use std::io::Read;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;

use rusqlite::{
    Connection,
    // Error as RError,
    // ErrorCode,
    OpenFlags,
    // Result as RResult,
    Transaction,
    TransactionBehavior,
    params,
};

use sequoia_openpgp as openpgp;
use openpgp::packet::signature::cache::SignatureVerificationCache;

use crate::Result;

/// Whether the cache was restored.  If we didn't finish restoring the
/// cache, we don't write out.
static RESTORED: AtomicBool = AtomicBool::new(false);

/// A handle to the signature cache.
///
/// When this handle is dropped, the cache is saved to disk.
pub struct SignatureCache {
}

const SQLITE: bool = true;
const SQLITE_FILENAME: &'static str = "/tmp/sig-cache.db";

/// We save a low precision (one day) time stamp to reduce the amount
/// of on-disk churn.
const TIME_GRANULARITY: u64 = 24 * 60 * 60;

/// We evict cache entries that haven't been accessed in this much
/// time.
const EVICTION_WINDOW: u64 = 30;

const FILE_ID: &'static str = "SEQUOIA SIGNATURE CACHE";
const VERSION: usize = 1;

impl SignatureCache {
    /// Returns a connection to the database.
    fn open() -> Result<Connection> {
        Ok(Connection::open_with_flags(
            SQLITE_FILENAME,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)?)
    }

    /// Ensures the database is initialized, and returns a transaction.
    fn init_db(conn: &Connection) -> Result<Transaction> {
        let tx = Transaction::new_unchecked(
            &conn, TransactionBehavior::Immediate)?;

        //let mut stmt = tx.prepare_cached(
        //    "SELECT (id, version) FROM version LIMIT 1")?;
        //
        // Check / fill in version table.

        tx.execute(
            "CREATE TABLE IF NOT EXISTS version (
                   id TEXT,
                   version INTEGER
                 )",
            ())?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS entries (
                   value BLOB PRIMARY KEY,
                   last_accessed INTEGER
                 ) WITHOUT ROWID",
            ())?;

        Ok(tx)
    }

    /// Loads the signature cache from disk.
    pub fn init() -> Result<Self> {
        if SQLITE {
            let conn = Self::open()?;
            let tx = Self::init_db(&conn)?;

            let mut stmt = tx.prepare("SELECT value FROM entries")?;
            let rows = stmt.query_map([], |row| {
                row.get(0)
            })?;

            let entries = rows.collect::<Vec<_>>();

            drop(stmt);
            drop(tx);
            drop(conn);

            SignatureVerificationCache::restore(
                entries.into_iter().filter_map(|e| {
                    e.ok()
                }),
                || RESTORED.store(true, Ordering::Relaxed));
        } else {
            const FILENAME: &str = "/tmp/sig-cache";
            let f = match std::fs::File::open(FILENAME) {
                Ok(f) => f,
                Err(_) => {
                    // There's nothing to restore or something is
                    // wrong.  We did the best we could.  We'll (try
                    // to) fix it when dumping that cache.
                    RESTORED.store(true, Ordering::Relaxed);
                    return Ok(SignatureCache {});
                }
            };

            let mut f = std::io::BufReader::new(f);

            let load_cache = std::iter::from_fn(move || {
                let mut len: [u8; 1] = [0];
                f.read_exact(&mut len).ok()?;

                let mut data = vec![ 0; len[0] as usize ];
                f.read_exact(&mut data).ok()?;

                Some(data)
            });
            SignatureVerificationCache::restore(
                load_cache,
                || RESTORED.store(true, Ordering::Relaxed));
        }

        Ok(SignatureCache {})
    }

    fn save() -> Result<()> {
        if SQLITE {
            let conn = Self::open()?;
            let tx = Self::init_db(&conn)?;

            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|t| t.as_secs())
                .unwrap_or(0) / TIME_GRANULARITY;

            // Add the list of entries that need to be updated to an
            // in-memory table, and then do a single insert.  Using an
            // INSERT per update takes about five times as longer.
            tx.execute("ATTACH ':memory:' as in_memory", ())?;

            tx.execute("CREATE TABLE in_memory.new \
                        (value BLOB PRIMARY KEY) \
                        WITHOUT ROWID",
                       ())?;
            let mut new_stmt = tx.prepare(
                "INSERT OR IGNORE INTO in_memory.new (value) VALUES (?1)")?;

            tx.execute("CREATE TABLE in_memory.accessed \
                        (value BLOB PRIMARY KEY) \
                        WITHOUT ROWID",
                       ())?;
            let mut accessed_stmt = tx.prepare(
                "INSERT OR IGNORE INTO in_memory.accessed (value) VALUES (?1)")?;

            let mut is_new = 0;
            let mut accessed = 0;
            time_it!("updating entries", {
                for entry in SignatureVerificationCache::dump() {
                    let entry_is_new = entry.is_new();
                    let entry_accessed = entry.accessed();
                    if entry_is_new || entry_accessed {
                        if entry_is_new {
                            is_new += 1;
                        } else if entry_accessed {
                            accessed += 1;
                        }
                    }

                    if entry_is_new {
                        new_stmt.execute(params!(entry.value()))?;
                    } else if entry_accessed {
                        accessed_stmt.execute(params!(entry.value()))?;
                    }
                }
            });

            if is_new > 0 || accessed > 0 {
                eprintln!("{} new entries, {} accessed",
                          is_new, accessed);

                // If we are confident that the entry already exists,
                // this takes about 2/3s as long as the statement
                // below, which checks for a conflict.
                time_it!("update last accessed", {
                tx.execute(
                    "UPDATE OR IGNORE entries \
                     SET last_accessed = ?1 \
                     WHERE entries.value in in_memory.accessed",
                    params!(now))?;
                });

                time_it!("update new accessed", {
                tx.execute(
                    "INSERT INTO entries \
                     SELECT value, ?1 FROM in_memory.new \
                     WHERE true \
                     ON CONFLICT DO UPDATE SET last_accessed = ?1",
                    params!(now))?;
                })
            }

            drop(new_stmt);
            drop(accessed_stmt);

            if now > EVICTION_WINDOW {
                time_it!("eviction", {
                let mut stmt = tx.prepare_cached(
                    "SELECT count(*) FROM entries")?;
                let precount = stmt.query([])?.mapped(|r| r.get(0)).next().unwrap_or(Ok(0))?;

                tx.execute(
                    "DELETE FROM entries WHERE last_accessed < ?1",
                    params!(now - EVICTION_WINDOW))?;

                let mut stmt = tx.prepare_cached(
                    "SELECT count(*) FROM entries")?;
                let postcount = stmt.query([])?.mapped(|r| r.get(0)).next().unwrap_or(Ok(0))?;

                eprintln!("Evicted {} entries", precount - postcount);
                })
            }

            time_it!("commit", {
                tx.commit()?;
            });

            eprintln!("{} new entries, {} entries accessed",
                      is_new, accessed);
        } else {
            if SignatureVerificationCache::insertions() == 0 {
                eprintln!("Not saving signature verification cache, \
                           nothing changed.");
                return Ok(());
            }

            let f = std::fs::File::create("/tmp/sig-cache")?;
            let mut f = std::io::BufWriter::new(f);
            for entry in SignatureVerificationCache::dump() {
                let len = entry.value().len();
                if len > u8::MAX as usize
                {
                    eprintln!("Skipping entry, which is too large for \
                               this file format ({} bytes)",
                              len);
                    continue;
                }

                let len: [u8; 1] = [len as u8; 1];
                f.write_all(&len)?;
                f.write_all(entry.value())?;
            }
        }

        Ok(())
    }
}

impl Drop for SignatureCache {
    fn drop(&mut self) {
        if RESTORED.load(Ordering::Relaxed) {
            time_it!("saving signature cache", {
                match SignatureCache::save() {
                    Ok(()) => {
                        eprintln!("Saved signature cache.");
                    }
                    Err(err) => {
                        eprintln!("Error saving signature cache: {}",
                                  crate::one_line_error_chain(err));
                    }
                }
            });
        } else {
            eprintln!("Not saving cache, it was never fully restored.");
        }
    }
}
