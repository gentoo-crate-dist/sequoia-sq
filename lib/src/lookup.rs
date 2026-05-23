use std::time::SystemTime;

use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::store::StoreError;

use crate::Sequoia;
use crate::transitional::print_error_chain;
use crate::types::FileStdinOrKeyHandle;

impl Sequoia {
    /// Looks up an identifier.
    ///
    /// This matches on both the primary key and the subkeys.
    ///
    /// If `keyflags` is not `None`, then only returns certificates
    /// where the matching key has at least one of the specified key
    /// flags.  If `or_by_primary` is set, then certificates with the
    /// specified key handle and a subkey with the specified flags
    /// also match.
    ///
    /// If `allow_ambiguous` is true, then all matching certificates
    /// are returned.  Otherwise, if an identifier matches multiple
    /// certificates an error is returned.
    ///
    /// An error is also returned if any of the identifiers does not
    /// match at least one certificate.
    pub fn lookup<'a, I>(&self, handles: I,
                         keyflags: Option<KeyFlags>,
                         or_by_primary: bool,
                         allow_ambiguous: bool)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy(
            handles, keyflags, or_by_primary, allow_ambiguous,
            self.policy(), self.time())
    }

    /// Looks up an identifier.
    ///
    /// Like [`Sequoia::lookup`], but uses an alternate policy and an
    /// alternate reference time.
    pub fn lookup_with_policy<'a, I>(&self, handles: I,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     allow_ambiguous: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        let mut results = Vec::new();

        for handle in handles {
            let (kh, mut certs) = match handle.into() {
                FileStdinOrKeyHandle::FileOrStdin(file) => {
                    let br = file.open("an OpenPGP certificate")?;
                    let cert = Cert::from_buffered_reader(br)?;
                    (cert.key_handle(), vec![ cert ])
                }
                FileStdinOrKeyHandle::KeyHandle(kh) => {
                    let certs = self.cert_store_or_else()?
                        .lookup_by_cert_or_subkey(&kh)
                        .with_context(|| {
                            format!("Failed to load {} from certificate store", kh)
                        })?
                        .into_iter()
                        .filter_map(|cert| {
                            match cert.to_cert() {
                                Ok(cert) => Some(cert.clone()),
                                Err(err) => {
                                    let err = err.context(
                                        format!("Failed to parse {} as loaded \
                                                 from certificate store", kh));
                                    print_error_chain(&err);
                                    None
                                }
                            }
                        })
                        .collect::<Vec<Cert>>();

                    (kh.clone(), certs)
                }
            };

            if let Some(keyflags) = keyflags.as_ref() {
                certs.retain(|cert| {
                    let vc = match cert.with_policy(policy, time)
                    {
                        Ok(vc) => vc,
                        Err(err) => {
                            let err = err.context(
                                format!("{} is not valid according \
                                         to the current policy, ignoring",
                                        kh));
                            print_error_chain(&err);
                            return false;
                        }
                    };

                    let checked_id = or_by_primary
                        && vc.cert().key_handle().aliases(&kh);

                    for ka in vc.keys() {
                        if checked_id || ka.key().key_handle().aliases(&kh) {
                            if &ka.key_flags().unwrap_or(KeyFlags::empty())
                                & keyflags
                                != KeyFlags::empty()
                            {
                                return true;
                            }
                        }
                    }

                    if checked_id {
                        weprintln!("Error: {} does not have a key with \
                                    the required capabilities ({:?})",
                                   cert.keyid(), keyflags);
                    } else {
                        weprintln!("Error: The subkey {} (cert: {}) \
                                    does not have the required capabilities \
                                    ({:?})",
                                   kh, cert.keyid(), keyflags);
                    }
                    return false;
                })
            }

            if ! allow_ambiguous && certs.len() > 1 {
                return Err(anyhow::anyhow!(
                    "{} is ambiguous; it matches: {}",
                    kh,
                    certs.into_iter()
                        .map(|cert| cert.fingerprint().to_string())
                        .collect::<Vec<String>>()
                        .join(", ")));
            }

            if certs.len() == 0 {
                return Err(StoreError::NotFound(kh.clone()).into());
            }

            results.extend(certs);
        }

        Ok(results)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sequoia::lookup`], but looks up a certificate, which must be
    /// uniquely identified by `handle` and `keyflags`.
    pub fn lookup_one<H>(&self, handle: H,
                      keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_one_with_policy(handle, keyflags, or_by_primary,
                                    self.policy(), self.time())
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sequoia::lookup_one_with_policy`], but uses an alternate
    /// policy and an alternate reference time.
    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_with_policy(std::iter::once(handle.into()),
                                keyflags, or_by_primary, false,
                                policy, time)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }
}
