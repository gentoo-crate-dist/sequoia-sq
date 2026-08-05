//! A high-level API for Sequoia.
//!
//! This library implements a high-level API for [Sequoia].  The goal
//! is to provide an opinionated API for developers who want to use
//! [OpenPGP] in their applications, but don't want to understand the
//! details of OpenPGP or Sequoia.
//!
//! OpenPGP has a lot of data structures, and, as with all
//! security-related code, care has to be taken to use them correctly.
//! The Sequoia ecosystem includes about 20 crates and understanding
//! how they related to each other can take a while.  This library
//! hopes to alleviate this problem by providing a few functions that
//! are hard to use wrong and take care of most of the details.
//!
//! To achieve this, `sequoia` makes strong assumptions about what the
//! user wants.  But, if it turns out that some function's semantics
//! are not completely appropriate, it is often possible to tweak its
//! behavior.  When even that is not enough, it is possible to mix in
//! use of the low-level APIs.  This works, because the high-level
//! don't replace the low-level abstractions, but are built on and
//! reuse them.
//!
//! [Sequoia]: https://sequoia-pgp.org
//! [OpenPGP]: https://www.rfc-editor.org/rfc/rfc9580.html
//!
//! If you have used [`sq`], Sequoia's primary command line interface,
//! then the interfaces exposed by this library will seem very
//! familiar: [`sq`]'s interface was a primary inspiration for this
//! library, and it has largely been re-implemented in terms of this
//! library.  For instance, to verify a message using `sq`, you would
//! use `sq verify`.  Using this library, you would use
//! [`Sequoia::verify`], which is in the [`sequoia::verify`] module.
//!
//! [`sq`]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq.1.html
//!
//! # Getting Started
//!
//! The first thing that you will have to do is to create a
//! [`Sequoia`] context.  Upon instantiation, a `Sequoia` context
//! reads in the configuration unless it has been disabled using
//! [`SequoiaBuilder`].  A `Sequoia` context also holds global state,
//! like references to the certificate store, and the key store.
//!
//! To create a Sequoia context using the default home directory, you
//! can do:
//!
//! ```rust
//! use sequoia::Sequoia;
//!
//! # fn main() -> sequoia::Result<()> {
//! let sequoia = Sequoia::new()?;
//! # Ok(()) }
//! ```
//!
//! One of the most common operations is to verify a signature (see
//! [`sequoia::verify`]).  The following example verifies that a
//! signature over a file is valid, and that the signing certificate
//! can be authenticated.
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::openpgp::Cert;
//! use sequoia::openpgp::parse::Parse;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let sequoia = Sequoia::builder().ephemeral()?.build()?;
//! # let alice = sequoia
//! #   .key_generate()
//! #   .email("alice@example.org")
//! #   .without_password()
//! #   .generate(sequoia::prompt::Cancel::new())?;
//! #
//! # let file = b"I own you";
//! # let mut signature = Vec::new();
//! # sequoia.sign()
//! #   .detached()
//! #   .add_signer(alice.cert().clone())
//! #   .sign(
//! #       std::io::Cursor::new(file),
//! #       &mut signature,
//! #       sequoia::prompt::Cancel::new())?;
//! #
//! # if false {
//! let qubes_release_key = Cert::from_file("qubes-release-4.3-signing-key.asc")?;
//! let signature = std::fs::File::open("Qubes-R4.3.1-x86_64.iso.asc")?;
//! let file = std::fs::File::open("Qubes-R4.3.1-x86_64.iso")?;
//! # }
//! # let qubes_release_key = alice.into_cert();
//! # let signature = std::io::Cursor::new(signature);
//! # let file = std::io::Cursor::new(file);
//!
//! sequoia
//!     .verify()
//!     .add_designated_signer(qubes_release_key)
//!     .detached_signature(file, signature, std::io::empty())?;
//! # Ok(()) }
//! ```
//!
//! # Overview
//!
//! The following sections list the functionality exposed by this
//! library.  Each section contains one or more functions that fall
//! into the section's category.  The table links to the module, which
//! provides a detailed description of the function, and examples, the
//! method on the [`Sequoia`] context, and the related `sq` commands.
//!
//! ## Messages
//!
//! | Functionality | Module               | Function             | `sq` equivalent |
//! |---------------|----------------------|----------------------|-|
//! | Verify        | [`sequoia::verify`]  | [`Sequoia::verify`]  | [`sq verify`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-verify.1.html) |
//! | Sign          | [`sequoia::sign`]    | [`Sequoia::sign`]    | [`sq sign`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-sign.1.html) |
//! | Decryption    | [`sequoia::decrypt`] | [`Sequoia::decrypt`] | [`sq decrypt`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-decrypt.1.html) |
//! | Encryption    | [`sequoia::encrypt`] | [`Sequoia::encrypt`] | [`sq encrypt`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-encrypt.1.html) |
//!
//! ## Certificate Management
//!
//! | Functionality       | Module                    | Function                 | `sq` equivalent |
//! |---------------------|---------------------------|--------------------------|-|
//! | Import certificates | [`sequoia::cert::import`] | [`Sequoia::cert_import`] | [`sq cert import`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-cert-import.1.html) |
//! | List certificates   | [`sequoia::cert::list`]   | [`Sequoia::cert_list`]   | [`sq cert list`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-cert-list.1.html), [`sq pki authenticate`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-authenticate.1.html), [`sq pki lookup`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-lookup.1.html), [`sq pki identify`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-identify.1.html), and [`sq pki path`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-path.1.html) |
//! | Lookup a certificate | -                        | [`Sequoia::lookup`]      | - |
//!
//! ## PKI
//!
//! | Functionality                     | Module                    | Function                 | `sq` equivalent |
//! |-----------------------------------|---------------------------|--------------------------|-|
//! | Certify a user ID and certificate | [`sequoia::pki::certify`] | [`Sequoia::pki_certify`] | [`sq pki link add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-link-add.1.html), [`sq pki link authorize`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-link-authorize.1.html), [`sq pki vouch add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-vouch-add.1.html), and [`sq pki vouch authorize`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-vouch-authorize.1.html) |
//!
//! ## Network Search
//!
//! | Functionality                          | Module                       | Function                    | `sq` equivalent |
//! |----------------------------------------|------------------------------|-----------------------------|-|
//! | Search for certificates on the network | [`sequoia::network::search`] | [`Sequoia::network_search`] | [`sq network search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-search.1.html), [`sq network keyserver search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-keyserver-search.1.html), [`sq network wkd search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-wkd-search.1.html), [`sq network dane search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-dane-search.1.html) |
//!
//! ## Key Management
//!
//! | Functionality                          | Module                       | Function                    | `sq` equivalent |
//! |----------------------------------------|------------------------------|-----------------------------|-|
//! | Generate a key                         | [`sequoia::key::generate`]   | [`Sequoia::key_generate`]   | [`sq key generate`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-generate.1.html) |
//! | Import a key                           | [`sequoia::key::import`]     | [`Sequoia::key_import`]     | [`sq key import`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-import.1.html) |
//! | Modify a certificate's expiration      | [`sequoia::key::expire`]     | [`Sequoia::key_expire`]     | [`sq key expire`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-expire.1.html) |
//! | Revoke a certificate                   | [`sequoia::key::revoke`]     | [`Sequoia::key_revoke`]     | [`sq key revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-revoke.1.html) |
//!
//! ### User IDs
//!
//! | Functionality    | Module                           | Function                       | `sq` equivalent |
//! |------------------|----------------------------------|--------------------------------|-|
//! | Add a user ID    | [`sequoia::key::userid::add`]    | [`Sequoia::key_userid_add`]    | [`sq key userid add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-userid-add.1.html) |
//! | Revoke a user ID | [`sequoia::key::userid::revoke`] | [`Sequoia::key_userid_revoke`] | [`sq key userid revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-userid-revoke.1.html) |
//!
//! ### Subkeys
//!
//! | Functionality   | Module                           | Function                       | `sq` equivalent |
//! |-----------------|----------------------------------|--------------------------------|-|
//! | Add a subkey    | [`sequoia::key::subkey::add`]    | [`Sequoia::key_subkey_add`]    | [`sq key subkey add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-subkey-add.1.html) |
//! | Revoke a subkey | [`sequoia::key::subkey::revoke`] | [`Sequoia::key_subkey_revoke`] | [`sq key subkey revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-subkey-revoke.1.html) |
//!
//! ### Certification Approval Management
//!
//! The approval functionality allows an owner of a certificate to
//! indicate what certifications should be distributed with their
//! certificate.  Key servers that respect this attribute will strip
//! other third-party certifications.  This mechanism can help prevent
//! malicious third parties from blowing up the size of a certificate
//! by creating many third-party certifications.
//!
//! | Functionality    | Module                              | Function                          | `sq` equivalent |
//! |------------------|-------------------------------------|-----------------------------------|-|
//! | List approvals   | [`sequoia::key::approvals::list`]   | [`Sequoia::key_approvals_list`]   | [`sq key approvals list`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-approvals-list.1.html) |
//! | Update approvals | [`sequoia::key::approvals::update`] | [`Sequoia::key_approvals_update`] | [`sq key approvals update`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-approvals-update.1.html) |
//!
//! ## Analysis
//!
//! | Functionality                          | Module                       | Function                        | `sq` equivalent |
//! |----------------------------------------|------------------------------|---------------------------------|-|
//! | Inspect some data                      | [`sequoia::inspect`]         | [`sequoia::inspect::inspect`]   | [`sq inspect`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-inspect.1.html) |
//! | Dump OpenPGP data structures           | [`sequoia::packet::dump`]    | [`sequoia::packet::dump::dump`] | [`sq packet dump`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-packet-dump.1.html) |

// For the library document so that we can use `sequoia::...` instead
// of `crate::...`.
#[cfg(doc)]
use crate::{self as sequoia};

use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
    time::UNIX_EPOCH,
};

#[macro_use] mod log;
#[macro_use] mod macros;
#[macro_use] mod boilerplate;

use anyhow::Context;

// Re-exports.
pub use anyhow;
pub use sequoia_autocrypt as autocrypt;
pub use sequoia_cert_store as cert_store;
pub use sequoia_directories as directories;
pub use sequoia_keystore as key_store;
pub use sequoia_ipc as ipc;
pub use sequoia_net as net;
pub use sequoia_openpgp as openpgp;
pub use sequoia_policy_config as policy_config;
pub use sequoia_wot as wot;

use openpgp::Fingerprint;
use openpgp::cert::raw::RawCertParser;
use openpgp::crypto::Password;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;

use cert_store::StoreUpdate;

#[macro_use] mod transitional;
#[macro_use] mod destination;
#[macro_use] mod errors;
pub use errors::Error;
pub use errors::SystemError;

pub mod cert;
pub mod consts;
pub mod decrypt;
pub mod encrypt;
pub mod inspect;
pub mod key;
pub mod network;
pub mod pki;
pub mod provenance;
mod shadow_ca;
pub use shadow_ca::Ca;
pub mod sign;
pub mod types;
pub mod userid;
use types::StateDirectory;
mod writer;
pub use writer::OptionalWriter;
pub use writer::Writer;

mod best_userid;
mod builder;
pub use builder::SequoiaBuilder;
mod compat;
pub mod config;
use config::Config;
use config::ConfigFile;
mod keys;
pub use keys::GetKeysOptions;
pub use keys::KeyType;
pub mod lookup;
pub mod packet;
pub mod prompt;
mod password_cache;
mod time;
pub use time::Time;
mod utils;
pub mod verify;

// XXX transitional: Switch to our own Error type.
pub type Result<T, E=anyhow::Error> = anyhow::Result<T, E>;

static STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
static NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };
const TRACE: bool = false;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Sequoia {
    /// The home directory.
    ///
    /// If `None`, then the `Sequoia` instance should operate in
    /// stateless mode.
    home: Option<Cow<'static, sequoia_directories::Home>>,

    /// The configuration.
    config_file: ConfigFile,
    config: Config,

    /// The current time.
    time: Clock,

    /// Overrides the path to the cert store.
    cert_store_path: Option<types::StateDirectory>,

    /// This will be set if the cert store has not been disabled, OR
    /// --keyring is passed.
    ///
    /// The u64 is the policy time (in seconds since the UNIX epoch)
    /// of the WotStore.
    cert_store: Mutex<Option<(u64, Arc<WotStore>)>>,

    /// Additional keyrings to read.
    keyrings: Vec<PathBuf>,

    /// Map from key fingerprint to cert fingerprint and the key.
    keyring_tsks: OnceLock<BTreeMap<
            Fingerprint,
        (Fingerprint, Key<PublicParts, UnspecifiedRole>)>>,

    /// The local trust root, as set in the cert store.
    trust_root_local: OnceLock<Option<Fingerprint>>,

    /// Additional trust roots.
    trust_roots: Vec<Fingerprint>,

    /// The key store.
    key_store_path: Option<StateDirectory>,
    key_store: once_cell::sync::OnceCell<Mutex<key_store::Keystore>>,

    /// Path to our IPC servers.
    ipc_server_path: PathBuf,

    /// A password cache.  When encountering a locked key, we first
    /// consult the password cache.  The passwords are only tried if
    /// it is safe.  That is, the passwords are only tried if we are
    /// sure that the key is not protected by a retry counter.  If the
    /// password cache doesn't contain the correct password, or the
    /// key is protected by a retry counter, the user is prompted to
    /// unlock the key.  The correct password is added to the cache.
    password_cache: Mutex<Vec<Password>>,
}

impl Sequoia {
    /// Returns a new builder.
    pub fn builder() -> SequoiaBuilder {
        SequoiaBuilder::new()
    }

    /// Returns a new `Sequoia` instance using all the defaults.
    pub fn new() -> Result<Sequoia> {
        Sequoia::builder().build()
    }

    /// Returns the home directory.
    ///
    /// This returns `None` if this `Sequoia` instance is configured to
    /// operate in stateless mode.
    pub fn home(&self) -> Option<&sequoia_directories::Home> {
        self.home.as_deref()
    }

    /// Returns whether this `Sequoia` instance is operating in
    /// stateless mode.
    pub fn stateless(&self) -> bool {
        self.home.is_none()
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Returns a reference to the configuration file.
    pub fn config_file(&self) -> &ConfigFile {
        &self.config_file
    }

    /// Returns the OpenPGP policy.
    pub fn policy(&self) -> &openpgp::policy::StandardPolicy<'static> {
        self.config.policy()
    }

    /// Returns the configured time.
    pub fn time(&self) -> SystemTime {
        self.time.get()
    }

    /// Returns whether the configured time approximates the current
    /// time.
    pub fn time_is_now(&self) -> bool {
        self.time.is_now()
    }

    /// Returns whether the cert store is disabled.
    fn no_rw_cert_store(&self) -> bool {
        self.cert_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        let default = || if let Ok(path) = std::env::var("PGP_CERT_D") {
            Some(PathBuf::from(path))
        } else {
            self.home()
                .map(|h| h.data_dir(sequoia_directories::Component::CertD))
        };

        if let Some(state) = self.cert_store_path.as_ref() {
            match state {
                StateDirectory::Absolute(p) => Some(p.clone()),
                StateDirectory::Default => default(),
                StateDirectory::None => None,
            }
        } else {
            default()
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<Arc<WotStore>>, SystemError> {
        self.cert_store_()
            .map_err(|err| {
                SystemError::CertStoreError(err.into())
            })
    }

    fn cert_store_(&self) -> Result<Option<Arc<WotStore>>> {
        if self.no_rw_cert_store()
            && self.keyrings.is_empty()
        {
            // The cert store is disabled.
            return Ok(None);
        }

        let mut cert_store = self.cert_store.lock().unwrap();
        if let Some((current_secs, cs)) = cert_store.as_ref() {
            // If the WotStore is out of date, then re-initialize it.
            let now = self.time();
            let now_secs = now.duration_since(UNIX_EPOCH)
                .map(|t| t.as_secs())
                .unwrap_or(0);
            if now_secs == *current_secs {
                // The cert store is already initialized for the
                // current time, return it.
                return Ok(Some(Arc::clone(&cs)));
            } else {
                // Re-initialize it.
                let result = Arc::new(WotStore::from_store(
                    Arc::clone(cs.store()),
                    Box::new(self.policy().clone()) as Box::<dyn Policy>,
                    now));
                *cert_store = Some((now_secs, Arc::clone(&result)));
                return Ok(Some(result));
            }
        }

        let create_dirs = |path: &Path| -> Result<()> {
            use std::fs::DirBuilder;

            let mut b = DirBuilder::new();
            b.recursive(true);

            // Create the parent with the normal umask.
            if let Some(parent) = path.parent() {
                // Note: since recursive is turned on, it is not an
                // error if the directory exists, which is exactly
                // what we want.
                b.create(parent)
                    .with_context(|| {
                        format!("Creating the directory {:?}", parent)
                    })?;
            }

            // Create path with more restrictive permissions.
            platform!{
                unix => {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                },
                windows => {
                },
            }

            b.create(path)
                .with_context(|| {
                    format!("Creating the directory {:?}", path)
                })?;

            Ok(())
        };

        // We need to initialize the cert store.
        let mut cs = if ! self.no_rw_cert_store() {
            // Open the cert-d.

            let path = self.cert_store_base()
                .expect("just checked that it is configured");

            create_dirs(&path)
                .and_then(|_| cert_store::CertStore::open(&path))
                .with_context(|| {
                    format!("While opening the certificate store at {:?}",
                            &path)
                })?
        } else {
            cert_store::CertStore::empty()
        };

        let keyring = cert_store::store::Certs::empty();
        let mut tsks = BTreeMap::new();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        for key in cert.keys() {
                            if key.has_secret() {
                                tsks.insert(
                                    key.fingerprint(),
                                    (cert.fingerprint(), key.clone()));
                            }
                        }

                        keyring.update(Arc::new(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        self.keyring_tsks.set(tsks).expect("uninitialized");

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        cs.add_backend(
            Box::new(keyring),
            cert_store::AccessMode::Always);

        // Sync certs from GnuPG's state if we are using the user's
        // default home directory.
        if self.home().map(|h| h.is_default_location())
            .unwrap_or(false)
            && std::env::var("GNUPGHOME").is_err()
        {
            if let Err(e) = crate::compat::sync_from_gnupg(self, &cs) {
                self.warn(format_args!(
                    "Syncing state from GnuPG failed: {}", e));
            }
        }

        let now = self.time();
        let result = Arc::new(WotStore::from_store(
            Arc::new(cs), Box::new(self.policy().clone()) as Box::<dyn Policy>,
            now));

        let now_secs = now.duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs())
            .unwrap_or(0);

        *cert_store = Some((now_secs, Arc::clone(&result)));

        Ok(Some(result))
    }

    fn no_cert_store_err() -> SystemError {
        errors::SystemError::CertStoreDisabled
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else<'s>(&'s self) -> Result<Arc<WotStore>, SystemError> {
        self.cert_store()
            .and_then(|cert_store| {
                cert_store
                    .ok_or_else(|| {
                        Self::no_cert_store_err()
                    })
            })
    }

    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::NetworkBuilder<Arc<WotStore>>>
    {
        let cert_store = self.cert_store_or_else()?;
        let network = wot::NetworkBuilder::rooted(cert_store,
                                                  &*self.trust_roots());
        Ok(network)
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = self.trust_root_local.get_or_init(|| {
            let cert_store = self.cert_store_or_else().ok()?;
            let certd = cert_store.certd()?;

            let cert_bytes = match certd.certd().get(cert_store::store::openpgp_cert_d::TRUST_ROOT) {
                Ok(Some((_tag, cert_bytes))) => Some(cert_bytes),
                // Not found.
                Ok(None) => None,
                Err(err) => {
                    self.warn(format_args!(
                        "Error looking up local trust root: {}", err));
                    None
                }
            }?;

            let cert = match RawCertParser::from_bytes(&cert_bytes[..]) {
                Ok(mut parser) => {
                    match parser.next() {
                        Some(Ok(cert)) => Some(cert.fingerprint()),
                        Some(Err(err)) => {
                            self.warn(format_args!(
                                "Local trust root is corrupted: {}",
                                err));
                            None
                        }
                        None =>  {
                            self.warn(format_args!(
                                "Local trust root is corrupted: \
                                 no data"));
                            None
                        }
                    }
                }
                Err(err) => {
                    self.warn(format_args!(
                        "Error parsing local trust root: {}", err));
                    None
                }
            };

            cert
        });

        if let Some(trust_root_local) = trust_root_local {
            self.trust_roots.iter().cloned()
                .chain(std::iter::once(trust_root_local.clone()))
                .collect()
        } else {
            self.trust_roots.clone()
        }
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        let default = || {
            Ok(self.home()
               .map(|h| h.data_dir(directories::Component::Keystore)))
        };

        if let Some(dir) = self.key_store_path.as_ref() {
            match dir {
                StateDirectory::Absolute(p) => Ok(Some(p.clone())),
                StateDirectory::Default => default(),
                StateDirectory::None => Ok(None),
            }
        } else {
            default()
        }
    }

    /// Returns whether the key store is disabled.
    fn no_key_store(&self) -> bool {
        self.key_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    fn no_key_store_err() -> errors::Error {
        errors::Error::state_disabled("key store")
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        if self.no_key_store() {
            Err(Self::no_key_store_err().into())
        } else {
            self.key_store_path()?
                .ok_or_else(|| {
                    Self::no_key_store_err().into()
                })
        }
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self) -> Result<Option<&Mutex<key_store::Keystore>>> {
        if self.no_key_store() {
            return Ok(None);
        }

        self.key_store
            .get_or_try_init(|| {
                let c = key_store::Context::configure()
                    .home(self.key_store_path_or_else()?)
                    .lib(self.ipc_server_path())
                    .build()?;

                let ks = key_store::Keystore::connect(&c)
                    .context("Connecting to key store")?;

                Ok(Mutex::new(ks))
            })
            .map(Some)
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self) -> Result<&Mutex<key_store::Keystore>> {
        self.key_store().and_then(|key_store| key_store.ok_or_else(|| {
            Self::no_key_store_err().into()
        }))
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> Result<&BTreeMap<Fingerprint,
                            (Fingerprint, Key<PublicParts, UnspecifiedRole>)>>
    {
        if let Some(keyring_tsks) = self.keyring_tsks.get() {
            Ok(keyring_tsks)
        } else {
            // This also initializes keyring_tsks.
            self.cert_store()?;

            // If something went wrong, we just set it to an empty
            // map.
            Ok(self.keyring_tsks.get_or_init(|| BTreeMap::new()))
        }
    }

    /// Returns the path to the IPC servers.
    pub fn ipc_server_path(&self) -> &Path {
        &self.ipc_server_path
    }

    /// Emits a warning.
    pub(crate) fn warn(&self, msg: std::fmt::Arguments) {
        let _ = msg; // XXX
    }

    /// Emits a warning showing an error message.
    pub(crate) fn warn_err(&self, err: &anyhow::Error) {
        let _ = err; // XXX
    }
}

#[derive(Clone, Default)]
enum Clock {
    /// Always use the current time.
    ///
    /// This is the default, and good for long-running programs.
    #[default]
    Realtime,

    /// Freeze the time the Sequoia context is built.
    Frozen(SystemTime),

    /// Use the given time.
    Fix(SystemTime),
}

impl Clock {
    /// Returns the configured time.
    fn get(&self) -> SystemTime {
        match self {
            Clock::Realtime => SystemTime::now(),
            Clock::Frozen(t) => *t,
            Clock::Fix(t) => *t,
        }
    }

    /// Returns whether the configured time approximates the current
    /// time.
    fn is_now(&self) -> bool {
        ! matches!(self, Clock::Fix(_))
    }
}

/// A shorthand for our store type.
type WotStore
    = wot::store::CertStore<'static, 'static, Arc<cert_store::CertStore<'static>>>;

/// The creation time for the trust root and intermediate CAs.
///
/// We use a creation time in the past (Feb 2002) so that it is still
/// possible to use the CA when the reference time is in the past.
// XXX: This is copied from sequoia-cert-store.  It would be nice to
// import it, but it is private.
pub fn ca_creation_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::new(1014235320, 0)
}

/// `anyhow::Error` does not implement clone.
///
/// This does a best effort clone.
fn clone_anyhow(err: &anyhow::Error) -> anyhow::Error
{
    let mut chain = err.chain().rev().collect::<Vec<_>>().into_iter();
    let e = chain.next().expect("have an error");
    // Try to clone error.
    let mut e = if let Some(e) = e.downcast_ref::<openpgp::Error>() {
        e.clone().into()
    } else {
        // Best effort.
        anyhow::anyhow!(e.to_string())
    };

    for cause in chain {
        e = e.context(cause.to_string());
    }

    e
}

// `std::error::Error` does not implement clone.
//
// This does a best effort clone.
fn clone_error(err: &(dyn std::error::Error + 'static)) -> anyhow::Error
{
    let mut causes = Vec::new();
    let mut err = Some(err);
    while let Some(cause) = err {
        err = cause.source();
        causes.push(cause);
    }

    let root = causes.pop().expect("have one");
    // Try to clone error.
    let mut e = if let Some(e) = root.downcast_ref::<openpgp::Error>() {
        e.clone().into()
    } else {
        // Best effort.
        anyhow::anyhow!(root.to_string())
    };

    for cause in causes.into_iter().rev() {
        e = e.context(cause.to_string());
    }

    e
}
