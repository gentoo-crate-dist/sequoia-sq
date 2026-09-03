//! Lookup certificates.
//!
//! Functionality for looking up certificates in the certificate store
//! or a keyring.
//!
//! To locate a certificate by user ID or email address, you should
//! use [`Sequoia::cert_list`].

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

const TRACE: bool = false;

impl Sequoia {
    /// Lookup a certificate.
    ///
    /// Looks up a certificate by fingerprint or key ID in the
    /// certificate store and any configured keyrings.
    pub fn lookup(&self) -> Builder<'_> {
        Builder {
            params: Params {
                sequoia: self,
                keyflags: None,
                or_by_primary: false,
            }
        }
    }
}

/// Look up certificates.
///
/// These parameters are used by [`lookup`](Sequoia::lookup).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    keyflags: Option<KeyFlags>,
    or_by_primary: bool,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the key flag restrictions.
    ///
    /// If `keyflags` is `Some`, then only returns certificates where
    /// the matching key has at least one of the specified key flags.
    pub fn keyflags(&self) -> Option<&KeyFlags> {
        self.keyflags.as_ref()
    }

    /// Returns whether to also consider the primary key when
    /// searching by key flags.
    ///
    /// By default, if `keyflags` is set, the specified key must have
    /// the specified key flags.  Setting this flag changes the
    /// behavior as follows: if the specified key is a primary key,
    /// then the certificate matches if it has any subkeys with the
    /// specified key flags.
    ///
    /// Consider a certificate 0x1111 that has an encryption-capable
    /// subkey 0x2222.  If this flag is unset, then searching for
    /// `0x1111 + encryption capable` will not match the certificate
    /// since 0x1111 is not encryption capable.  If `or_by_primary` is
    /// set, then 0x1111 matches, because it has a subkey with the
    /// specified key flags.
    pub fn or_by_primary(&self) -> bool {
        self.or_by_primary
    }
}

/// Look up certificates.
///
/// A builder providing control over how to lookup certificates.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the key flag restrictions.
    ///
    /// If `keyflags` is `Some`, then only returns certificates where
    /// the matching key has at least one of the specified key flags.
    pub fn keyflags<K>(mut self, keyflags: K) -> Self
    where
        K: Into<Option<KeyFlags>>
    {
        self.params.keyflags = keyflags.into();
        self
    }

    /// Sets whether to also consider the primary key when searching
    /// by key flags.
    ///
    /// By default, if `keyflags` is set, the specified key must have
    /// the specified key flags.  Setting this flag changes the
    /// behavior as follows: if the specified key is a primary key,
    /// then the certificate matches if it has any subkeys with the
    /// specified key flags.
    ///
    /// Consider a certificate 0x1111 that has an encryption-capable
    /// subkey 0x2222.  If this flag is unset, then searching for
    /// `0x1111 + encryption capable` will not match the certificate
    /// since 0x1111 is not encryption capable.  If `or_by_primary` is
    /// set, then 0x1111 matches, because it has a subkey with the
    /// specified key flags.
    pub fn or_by_primary(mut self, or_by_primary: bool) -> Self {
        self.params.or_by_primary = or_by_primary;
        self
    }

    /// Looks up certificates.
    ///
    /// Returns all matching certificates.
    ///
    /// An error is also returned if the identifier does not match at
    /// least one certificate.
    pub fn lookup<'a, H>(&self, handle: H)
        -> Result<Vec<Cert>>
    where
        H: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy_(
            handle.into(), true,
            self.params.sequoia.policy(), self.params.sequoia.time())
    }

    /// Looks up certificates.
    ///
    /// Like [`Builder::lookup`], but uses an alternate policy and an
    /// alternate reference time.
    pub fn lookup_with_policy<'a, H>(&self, handle: H,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Vec<Cert>>
    where
        H: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy_(handle.into(), true, policy, time)
    }

    fn lookup_with_policy_(&self, handle: FileStdinOrKeyHandle,
                           allow_ambiguous: bool,
                           policy: &dyn Policy,
                           time: SystemTime)
        -> Result<Vec<Cert>>
    {
        tracer!(TRACE, "lookup_with_policy");

        let &Builder {
            params: Params {
                sequoia,
                ref keyflags,
                or_by_primary,
            },
        } = self;

        let (kh, mut certs) = match handle.into() {
            FileStdinOrKeyHandle::FileOrStdin(file) => {
                t!("Reading file {}, keyflags: {:?}, or_by_primary: {}",
                   file, keyflags, or_by_primary);

                let br = file.open("an OpenPGP certificate")?;
                let cert = Cert::from_buffered_reader(br)?;
                (cert.key_handle(), vec![ cert ])
            }
            FileStdinOrKeyHandle::KeyHandle(kh) => {
                t!("Looking up {}, keyflags: {:?}, or_by_primary: {}",
                   kh, keyflags, or_by_primary);

                let certs = sequoia.cert_store_or_else()?
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

                t!("Found {} certificates matching {}: {}",
                   certs.len(), kh,
                   certs.iter().map(|c| c.fingerprint().to_string())
                       .collect::<Vec<String>>()
                       .join(", "));

                (kh.clone(), certs)
            }
        };

        if let Some(keyflags) = keyflags.as_ref() {
            t!("Checking key flags constraint: {:?}", keyflags);
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
                    let ka_keyflags = ka.key_flags().unwrap_or(KeyFlags::empty());
                    if checked_id || ka.key().key_handle().aliases(&kh) {
                        if ! (&ka_keyflags & keyflags).is_empty() {
                            t!("{} ({:?}) matches key flags constraint ({:?})",
                               ka.key().fingerprint(), ka_keyflags,
                               keyflags);
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
        } else {
            t!("No key flags constraint");
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

        Ok(certs)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Builder::lookup`], but looks up a certificate, which
    /// must be uniquely identified by `handle` and `keyflags`.
    pub fn lookup_one<H>(&self, handle: H)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_one_with_policy(
            handle, self.params.sequoia.policy(), self.params.sequoia.time())
    }

    /// Looks up a certificate.
    ///
    /// Like [`Builder::lookup_one_with_policy`], but uses an
    /// alternate policy and an alternate reference time.
    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_with_policy_(handle.into(), false,
                                 policy, time)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use openpgp::cert::amalgamation::key::PrimaryKey;

    use crate::prompt::Cancel;

    #[test]
    fn lookup() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let cert = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .can_authenticate(false)
            .generate(Cancel::new())
            .expect("can generate key")
            .into_cert();
        let vc = cert.with_policy(sq.policy(), sq.time())
            .expect("have a valid certificate");

        eprintln!("Certificate:");
        for k in vc.keys() {
            eprintln!("  {}: {:?}",
                      k.key().fingerprint(),
                      k.key_flags());
        }

        // Lookup by primary.
        let ret = sq.lookup()
            .lookup_one(cert.fingerprint())
            .expect("have certificate");

        assert_eq!(ret.fingerprint(), cert.fingerprint());

        // Lookup by subkey.
        for k in vc.keys().subkeys() {
            eprintln!("Considering {} (keyflags: {:?})",
                      k.key().fingerprint(),
                      k.key_flags());

            eprintln!("- Looking up {}", k.key().fingerprint());
            let ret = sq.lookup()
                .lookup_one(k.key().fingerprint())
                .expect("have certificate");

            assert_eq!(ret.fingerprint(), cert.fingerprint());
        }

        let keyflags = [
            (KeyFlags::for_certification as fn(&KeyFlags) -> bool, KeyFlags::certification(), true),
            (KeyFlags::for_signing as _, KeyFlags::signing(), true),
            (KeyFlags::for_transport_encryption as _, KeyFlags::transport_encryption(), true),
            (KeyFlags::for_storage_encryption as _, KeyFlags::storage_encryption(), true),
            (KeyFlags::for_authentication as _, KeyFlags::authentication(), false),
        ];

        // Lookup by key and key flags.
        //
        // This returns a certificate if the certificate contains a
        // key with the specified key handle and that key has the
        // specified flags.
        //
        // This does NOT match if the matched key is the primary key
        // and a subkey has the specified key flags.
        for k in vc.keys() {
            let k_key_flags = k.key_flags().expect("have key flags");

            eprintln!("Considering {} (keyflags: {:?})",
                      k.key().fingerprint(), k_key_flags);

            for (check, kf, _have_one) in keyflags.iter() {
                eprintln!("- Looking up {}, key flags: {:?}",
                          k.key().fingerprint(), kf);

                let ret = sq.lookup()
                    .keyflags(kf.clone())
                    .lookup_one(k.key().fingerprint());

                if check(&k_key_flags) {
                    eprintln!("  - Expecting a match.");
                    assert_eq!(ret.expect("have a certificate").fingerprint(),
                               cert.fingerprint());
                } else {
                    eprintln!("  - Expecting not found.");
                    assert!(ret.is_err());
                }
            }
        }

        // Lookup by key handle and key flags.  Also allow matches on
        // the certificate's key handle.
        //
        // This returns a certificate if the certificate contains a
        // key with the specified key handle and that key has the
        // specified flags.
        for k in vc.keys() {
            let k_key_flags = k.key_flags().expect("have key flags");

            eprintln!("Considering {} (keyflags: {:?})",
                      k.key().fingerprint(), k_key_flags);

            for (check, kf, have_one) in keyflags.iter() {
                eprintln!("- Looking up {}, key flags: {:?}, or_by_primary: true",
                          k.key().fingerprint(), kf);

                let ret = sq.lookup()
                    .keyflags(kf.clone())
                    .or_by_primary(true)
                    .lookup_one(k.key().fingerprint());

                if (k.primary() && *have_one) || check(&k_key_flags) {
                    eprintln!("  - Expecting a match.");
                    assert_eq!(ret.expect("have a certificate").fingerprint(),
                               cert.fingerprint());
                } else {
                    eprintln!("  - Expecting not found.");
                    assert!(ret.is_err());
                }
            }
        }
    }
}
