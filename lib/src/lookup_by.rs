//! Lookup certificates by human meaningful identifiers.
//!
//! # Fingerprints
//!
//! Certificates are often designated using their so-called
//! fingerprint.  The fingerprint is a hash of the primary key.  Since
//! the primary key does not change, the fingerprint is stable even if
//! the certificate is modified.  The fingerprint is also self
//! authenticating: assuming the hash function is secure, the
//! fingerprint is sufficient to authenticate the primary key (which
//! can in turn be used to verify the certificate's other components).
//!
//! To lookup a certificate by its fingerprint (or one of its
//! subkeys), use [`Sequoia::lookup`](crate::lookup).
//!
//! # Identifiers
//!
//! The main issue with fingerprints is that they are hard to
//! remember: people are better at remembering names and addresses
//! than long strings of hexadecimal numbers.  Unfortunately, names do
//! not unambiguously identify certificates and they are not self
//! authenticating.
//!
//! To work around this, fingerprints are sometimes used to bootstrap
//! communication.  Then the association between the name and the
//! certificate is saved.  This can be done using certifications, see
//! [`Sequoia::pki_certify`](crate::pki::certify).
//!
//! This module will provides functionality to lookup up a certificate
//! by an authenticated email address.  Use [`Sequoia::lookup_by`] to
//! get a [`Builder`].
//!
//! An email address is convenient as a human memorable identifier as
//! it unambiguously identifies a person or entity.  Human names, in
//! contrast, are often shared.  If you want to find certificates
//! associated with a human name, use
//! [`Sequoia::cert_list`](crate::cert::list), but be aware that two
//! certificates that can be authenticated for the same name are not
//! necessarily controlled by the same person.
//!
//! # Examples
//!
//! The functionality in this module provides a convenient way to
//! lookup a certificate by email address.  The email address must
//! have already been authenticated for the corresponding certificate;
//! unauthenticated user IDs are ignored.
//!
//! If you want to encrypt an email to someone (e.g., using
//! [`Sequoia::encrypt`](crate::encrypt)), you'll want to find the
//! certificates corresponding to the email address.  You can do this
//! using [`Builder::lookup_all_by_email`] and
//! [`Builder::lookup_one_by_email`].  The latter will error out if
//! there are multiple matches.
//!
//! When you know that you want to use the certificate for, e.g.,
//! encryption, you can also specify that the matching certificate
//! should be encryption-capable using [`Builder::cert_capabilities`].
//! This filters out unusable certificates.
//!
//! ```
//! use sequoia::openpgp::types::KeyFlags;
//! # use sequoia::Sequoia;
//! # use sequoia::prompt::Cancel;
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .unwrap()
//! #     .into_cert();
//!
//! let certs = sq.lookup_by()
//!     .cert_capabilities(KeyFlags::storage_encryption()
//!                        .set_transport_encryption())
//!     .lookup_all_by_email("alice@example.org")?;
//! #
//! # let fprs = certs.iter().map(|c| c.fingerprint()).collect::<Vec<_>>();
//! # assert_eq!(fprs, vec![alice.fingerprint()]);
//! # Ok(()) }
//! ```
use std::borrow::Cow;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::cert::CertProblem;
use crate::cert::list::Query;
use crate::cert::problem::CertInvalid;
use crate::cert::problem::CertRevoked;
use crate::cert::problem::NoUsableKeys;
use crate::cert::problem::NotLive;
use crate::cert::problem::ParseError;
use crate::cert;
use crate::types::Safe;

const TRACE: bool = false;

/// Errors related to looking up certificates.
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
///
/// These errors are usually wrapped in an [`Error`].
pub mod error {
    use super::*;

    /// The argument is not a valid email address.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{:?} does not appear to be an email address", .email)]
    pub struct InvalidEmail {
        pub email: String,
    }

    /// The argument is not a valid domain name.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{:?} does not appear to be a domain name", .domain)]
    pub struct InvalidDomain {
        pub domain: String,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        InvalidEmail(InvalidEmail),

        #[error(transparent)]
        InvalidDomain(InvalidDomain),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// Cert parse error.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parsing certificate")]
    pub struct CertError {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// A certificate corresponding to the handle was not found.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{:?} does not match any certificates{}",
            .email,
            if .lints.is_empty() {
                Cow::Borrowed("")
            } else {
                Cow::Owned(
                    format!(" ({}{})",
                            .lints
                                .iter()
                                .take(5)
                                .map(|lint| {
                                    lint.to_string()
                                })
                                .collect::<Vec<_>>()
                                .join(", "),
                            if .lints.len() > 5 {
                                Cow::Owned(
                                    format!(", {} more lints",
                                            .lints.len() - 5))
                            } else {
                                Cow::Borrowed("")
                            }))
            }
    )]
    pub struct EmailNotFound {
        pub email: String,

        /// Reasons why candidate certificates were rejected.
        pub lints: Vec<CertProblem>,
    }

    /// The query was ambiguous.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} is ambiguous; it matches: {}",
            Safe(.email),
            .certs.into_iter()
                .map(|cert| cert.fingerprint().to_string())
                .collect::<Vec<String>>()
                .join(", "))]
    pub struct EmailAmbiguous {
        pub email: String,
        pub certs: Vec<Cert>,
    }

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum OperationalError {
        #[error(transparent)]
        CertError(CertError),

        #[error(transparent)]
        EmailNotFound(EmailNotFound),

        #[error(transparent)]
        EmailAmbiguous(EmailAmbiguous),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to looking up a certificate.
///
/// Errors are divided into categories and each category contains more
/// precise errors.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum Error {
    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    ArgumentError(#[from] error::ArgumentError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    #[error(transparent)]
    SystemError(#[from] SystemError),

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    #[error(transparent)]
    OperationalError(#[from] error::OperationalError),
}

impl From<crate::cert::list::Error> for Error {
    fn from(err: crate::cert::list::Error) -> Error {
        use crate::cert::list;

        match err {
            list::Error::ArgumentError(err) => {
                match err {
                    list::error::ArgumentError::InvalidEmail(
                        list::error::InvalidEmail {
                            email,
                        }) =>
                    {
                        Error::ArgumentError(
                            error::ArgumentError::InvalidEmail(
                                error::InvalidEmail {
                                    email,
                                }))
                    },
                    list::error::ArgumentError::InvalidDomain(
                        list::error::InvalidDomain {
                            domain,
                            error,
                        }) =>
                    {
                        Error::ArgumentError(
                            error::ArgumentError::InvalidDomain(
                                error::InvalidDomain {
                                    domain,
                                    error,
                                }))
                    },
                    list::error::ArgumentError::Other(err) =>
                    {
                        Error::ArgumentError(
                            error::ArgumentError::Other(err))
                    },
                }
            }
            list::Error::SystemError(err) => {
                Error::SystemError(err)
            }
            list::Error::OperationalError(err) => {
                match err {
                    list::error::OperationalError::Other(err) =>
                    {
                        Error::OperationalError(
                            error::OperationalError::Other(err))
                    },
                }
            }
            list::Error::StreamOutputError(_err) => {
                // Our use of cert::list doesn't return an error from
                // the output callback.
                unreachable!()
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

    allow_expired: bool,
    allow_revoked: bool,

    /// A key flags restriction.
    ///
    /// If the boolean is `true`, then the restriction applies to the
    /// whole cert.  If `false` it applies to the specified key.
    ///
    /// Consider a certificate with a signing-capable subkey.  If the
    /// caller designates the primary key and specifies signing,
    /// looking up the for a signing-capable key and specifying the
    /// primary key
    cert_capabilities: Option<KeyFlags>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns whether expired certificates should be considered.
    ///
    /// Expired certificates are ignored by default.
    pub fn allow_expired(&self) -> bool {
        self.allow_expired
    }

    /// Returns whether revoked certificates should be considered.
    ///
    /// Revoked certificates are ignored by default.
    pub fn allow_revoked(&self) -> bool {
        self.allow_revoked
    }

    /// Returns the certificate capabilities restriction.
    ///
    /// If the certificate capabilities parameter is `Some`, then this
    /// function only returns a certificate if the certificate has at
    /// least one of the specified capabilities.  A certificate is
    /// considered to have a capability if the primary key or one of
    /// its subkeys has the specified capabilities.  If expired keys
    /// ([`Builder::allow_expired`]) are not allowed, then expired
    /// subkeys are not considered.  Likewise, if revoked keys
    /// ([`Builder::allow_revoked`]) are not allowed, then revoked
    /// subkeys are not considered.
    ///
    /// This function is useful when you, e.g., want to encrypt or
    /// sign a message: this ignores any certificates that aren't
    /// encryption or signing capable, respectively.
    pub fn cert_capabilities(&self) -> Option<&KeyFlags> {
        self.cert_capabilities.as_ref()
    }
}

/// Look up certificates by an authenticated identifier.
///
/// A builder providing control over how to lookup certificates.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia)
        -> Builder<'sequoia>
    {
        Builder {
            params: Params {
                sequoia,
                allow_expired: false,
                allow_revoked: false,
                cert_capabilities: None,
            }
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets whether expired certificates should be considered.
    ///
    /// Expired certificates are ignored by default.
    pub fn allow_expired(mut self, allow_expired: bool) -> Self {
        self.params.allow_expired = allow_expired;
        self
    }

    /// Sets whether revoked certificates should be considered.
    ///
    /// Revoked certificates are ignored by default.
    pub fn allow_revoked(mut self, allow_revoked: bool) -> Self {
        self.params.allow_revoked = allow_revoked;
        self
    }

    /// Sets the certificate capabilities restriction.
    ///
    /// If the certificate capabilities parameter is `Some`, then this
    /// function only returns a certificate if the certificate has at
    /// least one of the specified capabilities.  A certificate is
    /// considered to have a capability if the primary key or one of
    /// its subkeys has the specified capabilities.  If expired keys
    /// ([`Builder::allow_expired`]) are not allowed, then expired
    /// subkeys are not considered.  Likewise, if revoked keys
    /// ([`Builder::allow_revoked`]) are not allowed, then revoked
    /// subkeys are not considered.
    ///
    /// This function is useful when you, e.g., want to encrypt or
    /// sign a message: this ignores any certificates that aren't
    /// encryption or signing capable, respectively.
    pub fn cert_capabilities<K>(mut self, key_flags: K) -> Self
    where
        K: Into<Option<KeyFlags>>
    {
        self.params.cert_capabilities = key_flags.into();
        self
    }

    /// Looks up certificates by email.
    ///
    /// Returns all matching certificates.
    ///
    /// An error is returned if the identifier does not match at least
    /// one certificate.
    pub fn lookup_all_by_email<S>(self, email: S)
        -> Result<Vec<Cert>, Error>
    where
        S: AsRef<str>,
    {
        self.lookup_all_by_email_(email.as_ref(), true)
    }

    /// Looks up certificates by email.
    ///
    /// Returns one matching certificates.
    ///
    /// An error is returned if the identifier does not match exactly
    /// one certificate.
    pub fn lookup_one_by_email<S>(self, email: S)
        -> Result<Cert, Error>
    where
        S: AsRef<str>,
    {
        self.lookup_all_by_email_(email.as_ref(), false)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().unwrap()
            })
    }

    fn lookup_all_by_email_(self, email: &str, allow_ambiguous: bool)
        -> Result<Vec<Cert>, Error>
    {
        tracer!(TRACE, "lookup_all_by_email");

        t!("Looking up {}", email);

        let Params {
            sequoia,
            allow_expired,
            allow_revoked,
            cert_capabilities,
        } = self.params;

        // Find a certificate for Bob.
        let mut output = Vec::new();
        sequoia.cert_list()
            .query(Query::email(email))
            .list(&mut output)?;

        let mut lints = Vec::new();
        let mut certs = Vec::new();

        for o in output.into_iter() {
            let cert::list::Output::Binding(binding) = o else {
                continue;
            };

            let cert = match binding.cert(sequoia) {
                Ok(cert) => cert,
                Err(err) => {
                    lints.push(
                        CertProblem::ParseError(
                            ParseError {
                                cert: binding.fingerprint,
                                error: Arc::new(err.into()),
                            }));
                    continue;
                }
            };

            t!("Potential match: {}", cert.fingerprint());

            let vc = match cert.with_policy(sequoia.policy(), sequoia.time())
            {
                Ok(cert) => cert,
                Err(err) => {
                    t!("Not valid");
                    lints.push(
                        CertProblem::CertInvalid(
                            CertInvalid {
                                cert: cert.fingerprint(),
                                error: Arc::new(err.context(
                                    format!("{} is not valid according \
                                             to the current policy, ignoring",
                                            cert.fingerprint()))),
                            }));
                    continue;
                }
            };

            if ! allow_expired {
                if let Err(err) = vc.alive() {
                    // Not live.
                    t!("Not live, but needs to be");
                    lints.push(
                        CertProblem::NotLive(
                            NotLive {
                                cert: cert.fingerprint(),
                                key: cert.fingerprint(),
                                creation_time: cert.primary_key().key().creation_time(),
                                expiration_time: vc.primary_key().key_expiration_time(),
                                reference_time: sequoia.time(),
                                error: Arc::new(err.context(
                                    format!("{} is not valid according \
                                             to the current policy, ignoring",
                                            cert.fingerprint()))),
                            }));
                    continue;
                } else {
                    t!("Certificate is live");
                }
            }

            if ! allow_revoked {
                if let RevocationStatus::Revoked(sigs) = vc.revocation_status() {
                    // Revoked.
                    t!("Revoked, but shouldn't be");
                    lints.push(
                        CertProblem::CertRevoked(
                            CertRevoked {
                                cert: cert.fingerprint(),
                                revocations: sigs.into_iter().cloned().collect(),
                            }));
                    continue;
                } else {
                    t!("Certificate is not revoked");
                }
            }


            if let Some(cert_capabilities) = cert_capabilities.as_ref() {
                t!("Checking cert capabilities constraint: {:?}",
                   cert_capabilities);

                let mut good = false;
                let mut unusable = 0;

                for ka in vc.keys() {
                    let ka_keyflags
                        = ka.key_flags().unwrap_or(KeyFlags::empty());
                    if ! (&ka_keyflags & cert_capabilities).is_empty() {
                        t!("{} ({:?}) matches key flags constraint ({:?})",
                           ka.key().fingerprint(), ka_keyflags,
                           cert_capabilities);
                        if ! allow_expired {
                            if ka.alive().is_err() {
                                // Key is not live, but that's not
                                // allowed.  Ignore it.
                                t!("... but it is not live");
                                unusable += 1;
                                continue;
                            }
                        }
                        if ! allow_revoked {
                            if let RevocationStatus::Revoked(_)
                                = ka.revocation_status()
                            {
                                // Key is revoked, but that's not
                                // allowed.  Ignore it.
                                t!("... but it is revoked");
                                unusable += 1;
                                continue;
                            }
                        }

                        good = true;
                        break;
                    }
                }

                if ! good {
                    t!("Cert capabilities unsatisified");
                    lints.push(
                        CertProblem::NoUsableKeys(
                            NoUsableKeys {
                                cert: cert.fingerprint(),
                                capabilities: cert_capabilities.clone(),
                                unusable,
                            }));
                    continue;
                }
            }

            t!("{} is a full match", cert.fingerprint());
            certs.push(cert.clone());

            if ! allow_ambiguous && certs.len() > 1 {
                return Err(Error::OperationalError(
                    error::OperationalError::EmailAmbiguous(
                        error::EmailAmbiguous {
                            email: email.to_string(),
                            certs,
                        })));
            }
        }

        if certs.is_empty() {
            t!("No matches: {}",
               lints.iter()
                   .map(|l| l.to_string())
                   .collect::<Vec<_>>()
                   .join("; "));
            Err(Error::OperationalError(
                error::OperationalError::EmailNotFound(
                    error::EmailNotFound {
                        email: email.to_string(),
                        lints,
                    })))
        } else {
            t!("{} matches", certs.len());
            Ok(certs)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use openpgp::Packet;
    use openpgp::cert::SubkeyBuilder;
    use openpgp::cert::SubkeyRevocationBuilder;
    use openpgp::cert::ValidCert;
    use openpgp::packet::Key;
    use openpgp::packet::key::Key4;
    use openpgp::types::Curve;
    use openpgp::types::ReasonForRevocation;

    use crate::prompt::Cancel;

    fn dump_cert(vc: &ValidCert) {
        let creation_time = vc.primary_key().key().creation_time();

        let caps = vc.keys().fold(
            KeyFlags::empty(),
            |flags, k| {
                &flags | &k.key_flags().unwrap_or(KeyFlags::empty())
            });

        eprintln!("Certificate: {}, {}, {:?}",
                  vc.fingerprint(),
                  chrono::DateTime::<chrono::offset::Utc>::from(creation_time),
                  caps);
        for ua in vc.userids() {
            eprintln!("  - {}",
                      String::from_utf8_lossy(ua.userid().value()));
        }
        for k in vc.keys() {
            eprintln!("  {}: {:?}, {} -> {}, {}",
                      k.key().fingerprint(),
                      k.key_flags(),
                      chrono::DateTime::<chrono::offset::Utc>::from(
                          k.key().creation_time()),
                      if let Some(e) = k.key_expiration_time() {
                          format!("{} ({} s)",
                                  chrono::DateTime::<chrono::offset::Utc>::from(e),
                                  e.duration_since(creation_time).expect("can diff time")
                                      .as_secs())
                      } else {
                          "infinity".into()
                      },
                      if let RevocationStatus::Revoked(_) = k.revocation_status() {
                          "REVOKED"
                      } else {
                          ""
                      });
        }
    }

    #[test]
    fn lookup_by() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Signing and encryption certificate.
        let alice_s_e = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .can_authenticate(false)
            .generate(Cancel::new())
            .expect("can generate key")
            .into_cert();
        let vc_alice_s_e = alice_s_e.with_policy(sq.policy(), sq.time())
            .expect("have a valid certificate");
        let alice_s_e_caps = vc_alice_s_e.keys().fold(
            KeyFlags::empty(),
            |flags, k| {
                &flags | &k.key_flags().unwrap_or(KeyFlags::empty())
            });
        dump_cert(&vc_alice_s_e);

        // Signing only certificate.
        let alice_s = sq.key_generate()
            .email("alice@example.org")
            .email("alice@company.example")
            .without_password()
            .can_authenticate(false)
            .can_encrypt(None)
            .generate(Cancel::new())
            .expect("can generate key")
            .into_cert();
        let vc_alice_s = alice_s.with_policy(sq.policy(), sq.time())
            .expect("have a valid certificate");
        let alice_s_caps = vc_alice_s.keys().fold(
            KeyFlags::empty(),
            |flags, k| {
                &flags | &k.key_flags().unwrap_or(KeyFlags::empty())
            });
        dump_cert(&vc_alice_s);

        let mut all = vec![ alice_s_e.fingerprint(), alice_s.fingerprint() ];
        all.sort();

        // Lookup alice@example.org.  We should get both certificates.
        let ret = sq.lookup_by()
            .lookup_all_by_email("alice@example.org")
            .expect("have certificate");
        let mut got = ret.iter().map(|c| c.fingerprint()).collect::<Vec<_>>();
        got.sort();
        assert_eq!(all, got);


        // Lookup alice@company.example.  We should get one certificate.
        let ret = sq.lookup_by()
            .lookup_all_by_email("alice@company.example")
            .expect("have certificate");
        let got = ret.iter().map(|c| c.fingerprint()).collect::<Vec<_>>();
        assert_eq!(vec![ alice_s.fingerprint() ], got);



        // Lookup by email and key flags.
        let keyflags = [
            (KeyFlags::for_certification as fn(&KeyFlags) -> bool, KeyFlags::certification()),
            (KeyFlags::for_signing as _, KeyFlags::signing()),
            (KeyFlags::for_transport_encryption as _, KeyFlags::transport_encryption()),
            (KeyFlags::for_storage_encryption as _, KeyFlags::storage_encryption()),
            (KeyFlags::for_authentication as _, KeyFlags::authentication()),
        ];

        let email = "alice@example.org";
        for (check, kf) in keyflags.iter() {
            eprintln!("- Looking up {}, key flags: {:?}",
                      email, kf);

            let ret = sq.lookup_by()
                .cert_capabilities(kf.clone())
                .lookup_all_by_email(email);
            let certs = ret.unwrap_or(vec![]);
            let fprs = certs.iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<_>>();

            if check(&alice_s_e_caps) {
                eprintln!("  - Expecting a match for alice_s_e.");
                assert!(fprs.contains(&alice_s_e.fingerprint()));
            } else {
                eprintln!("  - Expecting not found for alice_s_e..");
                assert!(! fprs.contains(&alice_s_e.fingerprint()));
            }

            if check(&alice_s_caps) {
                eprintln!("  - Expecting a match for alice_s.");
                assert!(fprs.contains(&alice_s.fingerprint()));
            } else {
                eprintln!("  - Expecting not found for alice_s..");
                assert!(! fprs.contains(&alice_s.fingerprint()));
            }
        }
    }

    #[test]
    fn lookup_by_expired_subkey() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
        eprintln!("sq time: {}",
                  chrono::DateTime::<chrono::offset::Utc>::from(sq.time()));

        // Encryption certificate.
        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .can_authenticate(false)
            .can_sign(false)
            .generate(Cancel::new())
            .expect("can generate key")
            .into_cert();

        let vc = alice
            .with_policy(sq.policy(), sq.time())
            .expect("valid cert");
        dump_cert(&vc);

        let mut k: Key<_, _> = Key4::generate_ecc(true, Curve::Ed25519)
            .expect("can generate key")
            .into();

        let now = sq.time();
        k.set_creation_time(now)
            .expect("can set creation time");

        // Attach a signing subkey that expires in 60 seconds.
        let cert_new = SubkeyBuilder::new(vc.clone(), k, KeyFlags::signing())
            .expect("can create a subkey builder")
            .set_signature_creation_time(now)
            .expect("can set signature creation time")
            .set_key_validity_period(std::time::Duration::from_secs(60))
            .expect("can adjust expiration")
            .attach_cert().expect("can attach to cert");

        let vc = cert_new
            .with_policy(sq.policy(), sq.time())
            .expect("valid cert");
        dump_cert(&vc);
        assert!(vc.keys().subkeys().for_signing().next().is_some(),
                "Attached signing subkey");

        sq.cert_import().import_cert(cert_new).expect("can import cert");

        // Lookup alice@example.org.
        let cert = sq.lookup_by()
            .lookup_one_by_email("alice@example.org")
            .expect("have certificate");
        assert_eq!(cert.fingerprint(), alice.fingerprint());

        // Dump the merged certificate.
        let vc = cert
            .with_policy(sq.policy(), sq.time())
            .expect("valid cert");
        dump_cert(&vc);
        assert!(vc.keys().subkeys().for_signing().next().is_some(),
                "Lookup should see attached signing subkey");

        // Create a new sq instance with a reference time after the
        // subkey expires.
        let sq2 = Sequoia::builder()
            .fix_time_at(sq.time() + std::time::Duration::from_secs(180))
            .home(sq.home().unwrap().clone())
            .build()
            .unwrap();
        eprintln!("sq2 time: {}",
                  chrono::DateTime::<chrono::offset::Utc>::from(sq2.time()));

        // Lookup alice@example.org.
        let cert = sq2.lookup_by()
            .lookup_one_by_email("alice@example.org")
            .expect("have certificate");
        assert_eq!(cert.fingerprint(), alice.fingerprint());

        let vc = cert
            .with_policy(sq.policy(), sq2.time())
            .expect("valid cert");
        dump_cert(&vc);
        assert!(vc.keys().subkeys().for_signing().next().is_some(),
                "New home should see attached signing subkey");

        // Lookup alice@example.org, it should be signing capable, but
        // allow expired signing keys.
        let cert = sq2.lookup_by()
            .allow_expired(true)
            .cert_capabilities(KeyFlags::signing())
            .lookup_one_by_email("alice@example.org")
            .expect("have certificate");
        assert_eq!(cert.fingerprint(), alice.fingerprint());

        // Lookup alice@example.org, it should be signing capable,
        // don't allow expired signing keys.
        sq2.lookup_by()
            .cert_capabilities(KeyFlags::signing())
            .lookup_one_by_email("alice@example.org")
            .expect_err("shouldn't returned expired subkeys");
    }


    #[test]
    fn lookup_by_revoked_subkey() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
        eprintln!("sq time: {}",
                  chrono::DateTime::<chrono::offset::Utc>::from(sq.time()));

        // Encryption certificate.
        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .can_authenticate(false)
            .generate(Cancel::new())
            .expect("can generate key")
            .into_cert();

        let vc = alice
            .with_policy(sq.policy(), sq.time())
            .expect("valid cert");
        dump_cert(&vc);

        let signing_subkey = vc.keys().subkeys().for_signing().next()
            .expect("have a signing capable subkey");

        let mut primary_signer = alice.primary_key().key().clone()
            .parts_into_secret()
            .expect("have secret key material")
            .into_keypair()
            .expect("can generate keypair");

        let rev = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                       b"Bah.")
            .expect("can set reason for revocation")
            .set_signature_creation_time(sq.time())
            .expect("can set creation time")
            .build(&mut primary_signer, &alice, signing_subkey.key(), None)
            .expect("can create revocation certificate");

        let cert_new = alice.clone().insert_packets(Packet::from(rev))
            .expect("can insert revocation certificate").0;

        sq.cert_import().import_cert(cert_new).expect("can import cert");

        // Lookup alice@example.org.
        let cert = sq.lookup_by()
            .lookup_one_by_email("alice@example.org")
            .expect("have certificate");
        assert_eq!(cert.fingerprint(), alice.fingerprint());

        // Dump the merged certificate.
        let vc = cert
            .with_policy(sq.policy(), sq.time())
            .expect("valid cert");
        dump_cert(&vc);

        // Lookup alice@example.org, it should be signing capable, but
        // allow revoked signing keys.
        let cert = sq.lookup_by()
            .allow_revoked(true)
            .cert_capabilities(KeyFlags::signing())
            .lookup_one_by_email("alice@example.org")
            .expect("have certificate");
        assert_eq!(cert.fingerprint(), alice.fingerprint());

        // Lookup alice@example.org, it should be signing capable,
        // don't allow expired signing keys.
        sq.lookup_by()
            .cert_capabilities(KeyFlags::signing())
            .lookup_one_by_email("alice@example.org")
            .expect_err("shouldn't returned revoked subkeys");
    }
}
