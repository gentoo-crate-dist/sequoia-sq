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
    ///
    /// By default, when given a key handle, this only matches on the
    /// certificate's key handle.  To also match on the subkeys, set
    /// [`Builder::subkeys`].
    pub fn lookup(&self) -> Builder<'_> {
        Builder {
            params: Params {
                sequoia: self,
                subkeys: false,
                key_capabilities: None,
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

    /// A key flags restriction.
    ///
    /// If the boolean is `true`, then the restriction applies to the
    /// whole cert.  If `false` it applies to the specified key.
    ///
    /// Consider a certificate with a signing-capable subkey.  If the
    /// caller designates the primary key and specifies signing,
    /// looking up the for a signing-capable key and specifying the
    /// primary key
    key_capabilities: Option<KeyFlags>,

    /// Whether to also match on subkeys.
    subkeys: bool,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns whether to match on subkeys.
    ///
    /// By default, `lookup` only matches on a certificate's
    /// fingerprint (i.e., the fingerprint of its primary key).  If
    /// the `subkeys` parameter is set, then subkeys are also
    /// considered.
    ///
    /// Note: a key can be bound to multiple certificates.  As such,
    /// matching on subkeys can unexpectedly result in multiple
    /// matches when searching by fingerprint.
    pub fn subkeys(&self) -> bool {
        self.subkeys
    }

    /// Returns the key capabilities restriction.
    ///
    /// If the key capabilities parameter is `Some`, then only returns
    /// a certificate if the designated key has at least one of the
    /// specified capabilities.
    ///
    /// Note: this restriction applies to the designated key.  Thus,
    /// if you specify a certificate's fingerprint (i.e., its primary
    /// key), and only a subkey has the specified key flags, then the
    /// certificate will be ignored.
    ///
    /// This function is useful when examining a signature, and
    /// looking up the issuer: you know the signing key's fingerprint
    /// (not the certificate's fingerprint), and you know that the
    /// subkey must be signing capable.
    ///
    /// Because key flags can only available with a [`ValidCert`],
    /// using this restriction means that only valid certificates will
    /// be considered.
    ///
    /// [`ValidCert`]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/cert/struct.ValidCert.html
    pub fn key_capabilities(&self) -> Option<&KeyFlags> {
        self.key_capabilities.as_ref()
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

    /// Sets whether to match on subkeys.
    ///
    /// By default, `lookup` only matches on a certificate's
    /// fingerprint (i.e., the fingerprint of its primary key).  If
    /// the `subkeys` parameter is set, then subkeys are also
    /// considered.
    ///
    /// Note: a key can be bound to multiple certificates.  As such,
    /// matching on subkeys can unexpectedly result in multiple
    /// matches when searching by fingerprint.
    pub fn subkeys(mut self, subkeys: bool) -> Self {
        self.params.subkeys = subkeys;
        self
    }

    /// Sets the key capability restriction.
    ///
    /// If `keyflags` is `Some`, then only returns a certificate if
    /// the designated key has at least one of the specified
    /// capabilities.
    ///
    /// By default `lookup` only matches on the certificate's
    /// fingerprint (i.e., its primary key's fingerprint) as such if
    /// you set this parameter, you probably also want to set
    /// [`Builder::subkeys`].
    ///
    /// Note: this restriction applies to the designated key.  Thus,
    /// if you specify a certificate's fingerprint (i.e., its primary
    /// key), and only a subkey has the specified key flags, then the
    /// certificate will be ignored.
    ///
    /// This function is useful when examining a signature, and
    /// looking up the issuer: you know the signing key's fingerprint
    /// (not the certificate's fingerprint), and you know that the
    /// subkey must be signing capable.
    ///
    /// Because key flags can only available with a [`ValidCert`],
    /// using this restriction means that only valid certificates will
    /// be considered.
    ///
    /// [`ValidCert`]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/cert/struct.ValidCert.html
    pub fn key_capabilities<K>(mut self, key_flags: K) -> Self
    where
        K: Into<Option<KeyFlags>>
    {
        self.params.key_capabilities = key_flags.into();
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
                subkeys,
                ref key_capabilities,
            },
        } = self;

        let (kh, mut certs) = match handle.into() {
            FileStdinOrKeyHandle::FileOrStdin(file) => {
                t!("Reading file {}, key_capabilities: {:?}",
                   file, key_capabilities);

                let br = file.open("an OpenPGP certificate")?;
                let cert = Cert::from_buffered_reader(br)?;
                (cert.key_handle(), vec![ cert ])
            }
            FileStdinOrKeyHandle::KeyHandle(kh) => {
                t!("Looking up {}, key_capabilities: {:?}",
                   kh, key_capabilities);

                let cert_store = sequoia.cert_store_or_else()?;
                let result = if subkeys {
                    cert_store.lookup_by_cert_or_subkey(&kh)
                } else {
                    cert_store.lookup_by_cert(&kh)
                };
                let certs = result
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

        if let Some(key_capabilities) = key_capabilities.as_ref() {
            t!("Checking key flags constraint: {:?}", key_capabilities);
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

                for ka in vc.keys() {
                    let ka_keyflags = ka.key_flags().unwrap_or(KeyFlags::empty());
                    if ka.key().key_handle().aliases(&kh) {
                        if ! (&ka_keyflags & key_capabilities).is_empty() {
                            t!("{} ({:?}) matches key flags constraint ({:?})",
                               ka.key().fingerprint(), ka_keyflags,
                               key_capabilities);
                            return true;
                        }
                    }

                    if ! subkeys {
                        // We're only considering the primary key.
                        break;
                    }
                }

                weprintln!("Error: The subkey {} (cert: {}) \
                            does not have the required capabilities \
                            ({:?})",
                           kh, cert.keyid(), key_capabilities);
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
                .subkeys(true)
                .lookup_one(k.key().fingerprint())
                .expect("have certificate");
            assert_eq!(ret.fingerprint(), cert.fingerprint());

            sq.lookup()
                .lookup_one(k.key().fingerprint())
                .expect_err("didn't specify matching by subkey");
        }

        let keyflags = [
            (KeyFlags::for_certification as fn(&KeyFlags) -> bool, KeyFlags::certification()),
            (KeyFlags::for_signing as _, KeyFlags::signing()),
            (KeyFlags::for_transport_encryption as _, KeyFlags::transport_encryption()),
            (KeyFlags::for_storage_encryption as _, KeyFlags::storage_encryption()),
            (KeyFlags::for_authentication as _, KeyFlags::authentication()),
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

            for (check, kf) in keyflags.iter() {
                eprintln!("- Looking up {}, subkeys: true, key flags: {:?}",
                          k.key().fingerprint(), kf);

                let ret = sq.lookup()
                    .subkeys(true)
                    .key_capabilities(kf.clone())
                    .lookup_one(k.key().fingerprint());

                if check(&k_key_flags) {
                    eprintln!("  - Expecting a match.");
                    assert_eq!(ret.expect("have a certificate").fingerprint(),
                               cert.fingerprint());
                } else {
                    eprintln!("  - Expecting not found.");
                    assert!(ret.is_err());
                }

                eprintln!("- Looking up {}, subkeys: false, key flags: {:?}",
                          k.key().fingerprint(), kf);

                // Don't consider subkeys.
                let ret = sq.lookup()
                    .key_capabilities(kf.clone())
                    .lookup_one(k.key().fingerprint());
                if k.key().fingerprint() == vc.fingerprint() && check(&k_key_flags) {
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
