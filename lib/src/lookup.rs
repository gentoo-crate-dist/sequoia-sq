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
    pub fn keyflags(mut self, keyflags: Option<KeyFlags>) -> Self {
        self.params.keyflags = keyflags;
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
        let &Builder {
            params: Params {
                sequoia,
                ref keyflags,
                or_by_primary,
            },
        } = self;

        let (kh, mut certs) = match handle.into() {
            FileStdinOrKeyHandle::FileOrStdin(file) => {
                let br = file.open("an OpenPGP certificate")?;
                let cert = Cert::from_buffered_reader(br)?;
                (cert.key_handle(), vec![ cert ])
            }
            FileStdinOrKeyHandle::KeyHandle(kh) => {
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
