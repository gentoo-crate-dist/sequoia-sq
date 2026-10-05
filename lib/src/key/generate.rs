//! Generate keys.
//!
//! A key is a certificate with secret key material.  A certificate
//! consists of the public keys as well optional information about the
//! certificate holder like their name, and their email address.
//!
//! # Subkeys
//!
//! By default, this generate a certificate with a signing subkey, an
//! encryption subkey, and an authentication subkey.  You can
//! customize this using [`Builder::can_sign`],
//! [`Builder::can_encrypt`], and [`Builder::can_authenticate`].  You
//! can add additional subkeys using [`Builder::additional_keys`].
//! See [`KeyTemplate`] for more information.
//!
//! # Algorithms
//!
//! You can customize what public key algorithms to use using
//! [`Builder::cipher_suite`], [`Builder::encryption_algorithm`] and
//! [`Builder::signing_algorithm`].  `Builder::cipher_suite` selects a
//! pair of signing and encryption algorithms that work well together.
//! Not algorithms can be specified using a cipher suite.  For
//! instance, the SLH-DSA signing algorithm is not part of a cipher
//! suite.  It has a high-security margin, but is very slow.  This
//! makes it appropriate for software signing, but it should be
//! avoided when signing and encrypting messages.  To use SLH-DSA, you
//! can specify it using [`Builder::signing_algorithm`].  (In this
//! case, you probably want to not generate an encryption-capable
//! subkey, see [`Builder::can_encrypt`].)
//!
//! # User IDs
//!
//! If you don't call [`Builder::name`], [`Builder::email`], or
//! [`Builder::userid`] to add one or more user IDs, then the
//! generated certificate will not contain any user IDs.  This is
//! legal, but not usually what you want.
//!
//! The user IDs are linted and if they are not in canonical form,
//! they will be rejected.  You can force the use of non-canonical
//! user IDs by calling [`Builder::allow_non_canonical_userids`].
//!
//! # Authentication
//!
//! When a key is generated and imported into the key store, the user
//! IDs are certified.  If [`Builder::own_key`] is true (the default),
//! the user IDs are certified as trusted introducers by the local
//! trust root.  If it is false (meaning that the key will be shared
//! with someone else), they are just certified.
//!
//! If a certificate is considered a trusted introducer, that means
//! that any certificates that it certifies are considered
//! authenticated.
//!
//! # Password Protection
//!
//! By default, the key generate function will prompt the user for a
//! password.  You can override this by setting a password using
//! [`Builder::password`], or by configuring it to not set a password
//! using [`Builder::without_password`].
//!
//! # Examples
//!
//! Generate a key and import it to the key store:
//!
//! ```
//! # use sqz::Sequoia;
//! # fn main() -> sqz::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! let outcome = sq.key_generate()
//!     .name("Alice")
//!     .email("alice@example.org")
//!     .password("secr3t".into())
//!     // We already provided the password so we don't need a password prompt.
//!     .generate()?;
//!
//! println!("New certificate's fingerprint: {}",
//!          outcome.cert().fingerprint());
//! # Ok(()) }
//! ```
//!
//! Generate a key and write it and the revocation certificate to a `Write`r:
//!
//! ```
//! # use sqz::Sequoia;
//!
//! # fn main() -> sqz::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! let mut key = Vec::new();
//! let mut revocation = Vec::new();
//!
//! let outcome = sq.key_generate()
//!     .name("Alice")
//!     .email("alice@example.org")
//!     .password("secr3t".into())
//!     .to_writer((&mut key, &mut revocation))
//!     // We already provided the password so we don't need a password prompt.
//!     .generate()?;
//!
//! println!("New certificate's fingerprint: {}",
//!          outcome.cert().fingerprint());
//! # Ok(()) }
//! ```
use std::sync::Arc;

use chrono::DateTime;
use chrono::Utc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Profile;
use openpgp::armor;
use openpgp::armor::Kind;
use openpgp::cert::CertBuilder;
use openpgp::cert::CipherSuite;
use openpgp::crypto;
use openpgp::packet::UserID;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::PublicKeyAlgorithmSpecification;
use openpgp::types::SignatureType;

use sequoia_wot::FULLY_TRUSTED;

use crate::OptionalWriter;
use crate::Result;
use crate::Sequoia;
use crate::Writer;
use crate::SystemError;
use crate::config::DEFAULT_KEY_VALIDITY_DURATION;
use crate::config::Expiration;
use crate::destination::Destination;
use crate::destination::DestinationSummary;
use crate::key::PasswordPolicy;
use crate::key::certify_generated;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::types::EncryptPurpose;
use crate::types::PartFileWriter;
use crate::types::import_stats;
use crate::userid::UserIDLint;
use crate::userid::lint_email;
use crate::userid::lint_name;
use crate::userid::lint_userid;

/// Errors related to importing keys.
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
///
/// These errors are usually wrapped in an [`Error`].
pub mod error {
    use super::*;

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        /// A user ID is not in canonical form.
        ///
        /// Non-canonical user IDs can be accepted using
        /// [`Builder::allow_non_canonical_userids`].
        #[error(transparent)]
        InvalidUserIDs(#[from] InvalidUserIDs),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// Some user IDs are invalid or not in canonical form.
    ///
    /// Non-canonical user IDs can be accepted using
    /// [`Builder::allow_non_canonical_userids`].
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Invalid user IDs{}{}",
              if .lints.is_empty() {
                  ""
              } else {
                  ": "
              },
              .lints
                  .iter()
                  .map(|l| l.to_string())
                  .collect::<Vec<_>>()
                  .join("; "))]
    pub struct InvalidUserIDs {
        pub lints: Vec<UserIDLint>,
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
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to generating a certificate.
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

    /// Errors returned by the prompt.
    #[error(transparent)]
    PromptError(#[from] prompt::Error),
}

/// The key generate operation's outcome.
///
/// This is returned by [`Builder::generate`].  It contains
/// information about the outcome.
#[non_exhaustive]
#[derive(Clone)]
pub struct Outcome {
    pub cert: Cert,

    /// The key import status.
    ///
    /// This is `None` if the key was not imported to the key store.
    pub key_import_status: Option<Vec<(sequoia_openpgp::Fingerprint,
                                       import_stats::ImportStatus)>>,
}

impl Outcome {
    /// Returns a reference to the generated certificate.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    /// Returns the generated certificate.
    pub fn into_cert(self) -> Cert {
        self.cert
    }

    /// Returns the key import status.
    ///
    /// This is `None` if the key was not imported to the key store.
    pub fn key_import_status(&self) -> Option<&[(sequoia_openpgp::Fingerprint,
                                                 import_stats::ImportStatus)]> {
        self.key_import_status.as_deref()
    }
}

/// Key generation parameters.
///
/// These parameters are used by [`Builder::generate`].
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    profile: Profile,
    cipher_suite: CipherSuite,
    encryption_algorithm: Option<PublicKeyAlgorithmSpecification>,
    signing_algorithm: Option<PublicKeyAlgorithmSpecification>,
    password_policy: PasswordPolicy,
    expiration: Expiration,
    own_key: bool,
    can_sign: bool,
    can_authenticate: bool,
    can_encrypt: Option<EncryptPurpose>,
    additional_keys: Vec<KeyTemplate>,
    names: Vec<String>,
    emails: Vec<String>,
    userids: Vec<UserID>,
    allow_non_canonical_userids: bool,
    destination: DestinationSummary,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// The certificate's profile.
    ///
    /// The profile parameter selects the version of the OpenPGP
    /// standard the new certificate will conform to.  See
    /// [`openpgp::Profile`] for more details.
    pub fn profile(&self) -> Profile {
        self.profile.clone()
    }

    /// Returns the password policy.
    pub fn password_policy(&self) -> &PasswordPolicy {
        &self.password_policy
    }

    /// Returns the suite of ciphers that the certificate will use.
    ///
    /// The cipher suite is a group of algorithms that determine what
    /// algorithms will be considered when generating the keys.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite.clone()
    }

    /// Returns the encryption algorithm.
    ///
    /// If set, the encryption algorithm overrides the cipher suite.
    pub fn encryption_algorithm(&self)
        -> Option<PublicKeyAlgorithmSpecification>
    {
        self.encryption_algorithm.clone()
    }

    /// Returns the signing algorithm.
    ///
    /// If set, the signing algorithm overrides the cipher suite.
    pub fn signing_algorithm(&self)
        -> Option<PublicKeyAlgorithmSpecification>
    {
        self.signing_algorithm.clone()
    }

    /// When the certificate expires.
    pub fn expiration(&self) -> &Expiration {
        &self.expiration
    }

    /// Whether the certificate is for the creator, or will be shared
    /// with someone else.
    ///
    /// When the certificate is the creator's own key, it will be
    /// marked as a fully trusted introducer.
    pub fn own_key(&self) -> bool {
        self.own_key
    }

    /// Whether to create a signing subkey.
    pub fn can_sign(&self) -> bool {
        self.can_sign
    }

    /// Whether to create an authentication subkey.
    pub fn can_authenticate(&self) -> bool {
        self.can_authenticate
    }

    /// Whether to create an encryption-capable subkey and its usage.
    pub fn can_encrypt(&self) -> Option<&EncryptPurpose> {
        self.can_encrypt.as_ref()
    }

    /// The additional subkeys that will be generated.
    ///
    /// These are in addition to the sign, authenticate and encryption
    /// subkeys that will be added, if they are enabled.
    pub fn additional_keys(&self) -> impl Iterator<Item = &KeyTemplate> {
        self.additional_keys.iter()
    }

    /// Returns the names that will be added to the certificate.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        use std::ops::Deref;
        self.names.iter().map(|s| s.deref())
    }

    /// Returns the emails that will be added to the certificate.
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        use std::ops::Deref;
        self.emails.iter().map(|s| s.deref())
    }

    /// Returns the user IDs that will be added to the certificate.
    pub fn userids(&self) -> impl Iterator<Item = &UserID> {
        self.userids.iter().map(|u| u)
    }

    /// Returns whether key generation will allow non-canonical user
    /// IDs.
    pub fn allow_non_canonical_userids(&self) -> bool {
        self.allow_non_canonical_userids
    }

    destination_params_impl!("key");
}

/// Describes an additional key.
///
/// This is passed to [`Builder::additional_keys`].
#[derive(Clone, Debug)]
pub struct KeyTemplate {
    key_flags: KeyFlags,
    notations: Vec<(bool, NotationData)>,
}

impl KeyTemplate {
    /// Returns a key template that will generate a key with the
    /// specified algorithm, and the specified flags.
    pub fn new(key_flags: KeyFlags) -> Self {
        Self {
            key_flags,
            notations: Vec::new(),
        }
    }

    /// Adds a notation to the subkey's self signature.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(
        mut self, critical: bool, notation: NotationData)
        -> Self
    {
        self.notations.push((critical, notation));
        self
    }

    /// Adds notations to the subkey's self signature.
    ///
    /// The first value of the tuple is the notation's criticality.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notations(
        mut self,
        notations: impl IntoIterator<Item=(bool, NotationData)>)
        -> Self
    {
        self.notations.extend(notations.into_iter());
        self
    }

    /// Returns the configured notations.
    pub fn notations(&self)
        -> impl Iterator<Item=&(bool, NotationData)>
    {
        self.notations.iter()
    }
}

/// Owned parameters.
struct ParamsOnce<'writer, 'prompt> {
    destination: Destination<(Writer<'writer>, OptionalWriter<'writer>)>,
    prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>,
}

/// Generates keys.
///
/// A builder providing control over how to generate a new key.
pub struct Builder<'sequoia, 'writer, 'prompt> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'writer, 'prompt>,
}

impl<'sequoia, 'writer, 'prompt> Builder<'sequoia, 'writer, 'prompt>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Self {
        Builder {
            params: Params {
                sequoia,
                profile: Profile::RFC4880,
                cipher_suite: CipherSuite::default(),
                encryption_algorithm: None,
                signing_algorithm: None,
                password_policy: PasswordPolicy::Prompt,
                expiration: Expiration::from_duration(
                    DEFAULT_KEY_VALIDITY_DURATION),
                own_key: true,
                can_sign: true,
                can_authenticate: true,
                can_encrypt: Some(EncryptPurpose::Universal),
                additional_keys: Vec::new(),
                names: Vec::new(),
                emails: Vec::new(),
                userids: Vec::new(),
                allow_non_canonical_userids: false,
                destination: DestinationSummary::Store,
            },
            params_once: ParamsOnce {
                destination: Destination::Store,
                prompt: None,
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    destination_builder_to_store_impl!("key");

    /// Writes the key and optionally the revocation certificate to
    /// `Write`rs.
    ///
    /// If `writers` is `None`, then writes the key and the revocation
    /// certificate to the store.
    pub fn to_writer<'w, O, W1, W2>(self, writers: O)
        -> Builder<'sequoia, 'w, 'prompt>
    where
        O: Into<Option<(W1, W2)>>,
        W1: Into<crate::Writer<'w>>,
        W2: Into<crate::OptionalWriter<'w>>,
    {
        let writers = writers.into();

        // This is a bit more complicated than other setters as we
        // need to change self's lifetime from 'writer to 'w.
        if let Some((key_writer, rev_writer)) = writers {
            Builder {
                params: Params {
                    destination : DestinationSummary::Writer,
                    ..self.params
                },
                params_once: ParamsOnce {
                    destination: Destination::Writer(
                        (key_writer.into(), rev_writer.into())),
                    ..self.params_once
                },
            }
        } else {
            Builder {
                params: Params {
                    destination : DestinationSummary::Store,
                    ..self.params
                },
                params_once: ParamsOnce {
                    destination: Destination::Store,
                    ..self.params_once
                },
            }
        }
    }

    destination_builder_to_ephemeral_impl!("key");

    prompt_builder_impl!('writer; );

    /// Sets the certificate's profile.
    ///
    /// The profile parameter selects the version of the OpenPGP
    /// standard the new certificate will conform to.  See
    /// [`openpgp::Profile`] for more details.
    pub fn profile(mut self, profile: Profile) -> Self {
        self.params.profile = profile;
        self
    }

    /// Sets the suite of ciphers that the certificate may use.
    ///
    /// The cipher suite is a group of algorithms that will be
    /// considered when generating the keys.
    pub fn cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.params.cipher_suite = cipher_suite;
        self
    }

    /// Sets the encryption algorithm.
    ///
    /// If set, the encryption algorithm overrides the cipher suite.
    pub fn encryption_algorithm<A>(mut self, algo: A)
        -> Self
    where
        A: Into<Option<PublicKeyAlgorithmSpecification>>
    {
        self.params.encryption_algorithm = algo.into();
        self
    }

    /// Sets the signing algorithm.
    ///
    /// If set, the signing algorithm overrides the cipher suite.
    pub fn signing_algorithm<A>(mut self, algo: A)
        -> Self
    where
        A: Into<Option<PublicKeyAlgorithmSpecification>>
    {
        self.params.signing_algorithm = algo.into();
        self
    }

    /// Sets the password policy.
    ///
    /// See also [`Builder::password`] and
    /// [`Builder::without_password`].
    pub fn password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.params.password_policy = policy;
        self
    }

    /// Sets the password that will be used to protect the secret key
    /// material.
    ///
    /// See also [`Builder::password_policy`] and
    /// [`Builder::without_password`].
    pub fn password(mut self, password: crypto::Password) -> Self {
        self.params.password_policy = PasswordPolicy::Password(password);
        self
    }

    /// Sets that no password will be used to protect the secret key
    /// material.
    ///
    /// See also [`Builder::password_policy`] and
    /// [`Builder::password`].
    pub fn without_password(mut self) -> Self {
        self.params.password_policy = PasswordPolicy::None;
        self
    }

    /// When the certificate expires.
    pub fn expiration(mut self, expiration: Expiration) -> Self
    {
        self.params.expiration = expiration;
        self
    }

    /// Sets whether the certificate is for the creator, or is a
    /// shared key.
    ///
    /// When the certificate is saved to the key store, and is the
    /// creator's own key, it will be marked as a fully trusted
    /// introducer.  When the certificate is saved to the key store,
    /// and is not creator's own key, the user IDs will be marked as
    /// authenticated.
    pub fn own_key(mut self, own_key: bool) -> Self {
        self.params.own_key = own_key;
        self
    }

    /// Sets whether to create a signing subkey.
    pub fn can_sign(mut self, can_sign: bool) -> Self {
        self.params.can_sign = can_sign;
        self
    }

    /// Sets whether to create an authentication subkey.
    pub fn can_authenticate(mut self, can_authenticate: bool) -> Self {
        self.params.can_authenticate = can_authenticate;
        self
    }

    /// Sets whether to create an encryption-capable subkey and its
    /// usage.
    ///
    /// If `Some`, a subkey that can be used for the specified
    /// encryption purpose (transport encryption, storage encryption,
    /// or both) will be created.  To create a separate keys for
    /// transport encryption and storage encryptionkeys, use
    /// [`Builder::additional_keys`].
    ///
    /// If `None`, no encryption-capable subkey will be added.
    pub fn can_encrypt<E>(mut self, encrypt_purpose: E)
        -> Self
    where
        E: Into<Option<EncryptPurpose>>
    {
        self.params.can_encrypt = encrypt_purpose.into();
        self
    }

    /// The additional subkeys that will be generated.
    pub fn additional_keys<K>(mut self, key: K) -> Self
    where
        K: Into<KeyTemplate>
    {
        self.params.additional_keys.push(key.into());
        self
    }

    /// Adds the name to the certificate.
    pub fn name<S>(mut self, name: S) -> Self
    where
        S: Into<String>
    {
        self.params.names.push(name.into());
        self
    }

    /// Adds the names to the certificate.
    pub fn names<S>(mut self, names: impl IntoIterator<Item=S>) -> Self
    where
        S: Into<String>
    {
        self.params.names.extend(names.into_iter().map(|s| s.into()));
        self
    }

    /// Adds the email address to the certificate.
    pub fn email<S>(mut self, email: S) -> Self
    where
        S: Into<String>
    {
        self.params.emails.push(email.into());
        self
    }

    /// Adds the email addresses to the certificate.
    pub fn emails<S>(mut self, emails: impl IntoIterator<Item=S>) -> Self
    where
        S: Into<String>
    {
        self.params.emails.extend(emails.into_iter().map(|s| s.into()));
        self
    }

    /// Adds the user ID to the certificate.
    pub fn userid<U>(mut self, userid: U) -> Self
    where
        U: Into<UserID>
    {
        self.params.userids.push(userid.into());
        self
    }

    /// Adds the user IDs to the certificate.
    pub fn userids(mut self, userids: impl IntoIterator<Item=UserID>)
        -> Self
    {
        self.params.userids.extend(userids.into_iter().map(|s| s.into()));
        self
    }

    /// Sets whether key generation will allow non-canonical user IDs.
    pub fn allow_non_canonical_userids(
        mut self, allow_non_canonical_userids: bool)
        -> Self
    {
        self.params.allow_non_canonical_userids = allow_non_canonical_userids;
        self
    }

    /// Generates a key.
    ///
    /// By default, the key is saved to the key store.  Use
    /// [`Builder::to_writer`] or [`Builder::ephemeral`] to override
    /// it.
    ///
    /// When the certificate is saved to the certificate store, it is
    /// also certified by the local trust root (if [own
    /// key][Builder::own_key] is set, it is authorized to be a
    /// trusted introducer, otherwise the user IDs are simply marked
    /// as authenticated).  The certificate is also certified by the
    /// "Generated on $HOST" shadow CA.  These are opportunistic and
    /// if either fails, e.g., because the certificate is not usable,
    /// the error is silently ignored.
    pub fn generate(self) -> Result<Outcome, Error> {
        let Builder {
            params: Params {
                sequoia,
                profile,
                cipher_suite,
                encryption_algorithm,
                signing_algorithm,
                password_policy,
                expiration,
                own_key,
                can_sign,
                can_authenticate,
                can_encrypt,
                additional_keys,
                names,
                emails,
                mut userids,
                allow_non_canonical_userids,
                destination: _,
            },
            params_once: ParamsOnce {
                mut destination,
                prompt,
            }
        } = self;

        macro_rules! arg {
            () => {
                |err| {
                    Error::ArgumentError(
                        error::ArgumentError::Other(err.into()))
                }
            }
        }

        let to_keystore = destination.to_store();
        if to_keystore {
            // We're going to write to the key store and cert store.
            // Fail early if they are not available.
            sequoia.key_store_or_else()?;
            sequoia.cert_store_or_else()?;
        }

        let key_flags_template = if own_key {
            KeyFlags::empty()
        } else {
            KeyFlags::empty().set_group_key()
        };

        let mut builder = CertBuilder::new()
            .set_profile(profile.into()).map_err(arg!())?;

        // Names, email addresses, and user IDs.

        let mut lints = Vec::new();
        for n in names {
            if let Err(lint) = lint_name(&n) {
                lints.push(lint);
            } else if lints.is_empty() {
                userids.push(UserID::from(n.as_str()));
            }
        }

        for e in emails {
            match lint_email(&e) {
                Ok(userid) => {
                    userids.push(userid)
                }
                Err(lint) => {
                    lints.push(lint);
                }
            }
        }

        if ! userids.is_empty() {
            // Make sure the user IDs are in canonical form.  If not, and
            // `--allow-non-canonical-userids` is not set, error out.
            if ! allow_non_canonical_userids {
                for userid in userids.iter() {
                    if let Err(lint) = lint_userid(userid) {
                        lints.push(lint);
                    }
                }
            }

            if ! lints.is_empty() {
                return Err(Error::ArgumentError(
                    error::ArgumentError::InvalidUserIDs(
                        error::InvalidUserIDs {
                            lints
                        })));
            }

            for userid in userids.iter() {
                builder = builder.add_userid(userid.clone());
            }
        }

        // Creation time.
        builder = builder.set_creation_time(sequoia.time());

        // Expiration.
        builder = builder.set_validity_period(
            expiration
                .as_duration(DateTime::<Utc>::from(sequoia.time()))
                .map_err(arg!())?);

        // Cipher Suite
        builder = builder.set_cipher_suite(cipher_suite);

        if let Some(algo) = encryption_algorithm {
            builder = builder.set_encryption_algorithm(algo);
        }
        if let Some(algo) = signing_algorithm {
            builder = builder.set_signing_algorithm(algo);
        }

        // Primary key capabilities.
        builder = builder.set_primary_key_flags(
            key_flags_template.clone().set_certification());

        // Signing Capability
        if can_sign {
            builder = builder.add_subkey(
                key_flags_template.clone().set_signing(),
                None, None);
        }

        // Authentication Capability
        if can_authenticate {
            builder = builder.add_subkey(
                key_flags_template.clone().set_authentication(),
                None, None);
        }

        // Encryption Capability
        let encryption = match can_encrypt {
            Some(EncryptPurpose::Universal) => Some(
                key_flags_template.clone()
                    .set_transport_encryption()
                    .set_storage_encryption()),
            Some(EncryptPurpose::Storage) => Some(
                key_flags_template.clone()
                    .set_storage_encryption()),
            Some(EncryptPurpose::Transport) => Some(
                key_flags_template.clone()
                    .set_transport_encryption()),
            None => None,
        };
        if let Some(encryption) = encryption {
            builder = builder.add_subkey(encryption, None, None);
        }

        for k in additional_keys.into_iter() {
            let mut sig = SignatureBuilder::new(SignatureType::SubkeyBinding);
            for (critical, notation) in k.notations.into_iter() {
                sig = sig.set_notation(
                    notation.name(), notation.value(),
                    Some(notation.flags().clone()), critical)
                    .map_err(arg!())?;
            }

            builder = builder.add_subkey_with(
                &key_flags_template | &k.key_flags,
                None, None,
                sig)
                .map_err(arg!())?;
        }

        match password_policy {
            PasswordPolicy::None => (),
            PasswordPolicy::Password(password) => {
                builder = builder.set_password(Some(password));
            }
            PasswordPolicy::Prompt => {
                let mut checker = CheckNewPassword::optional();

                let mut context = prompt::ContextBuilder::password(
                    prompt::Reason::LockNewCert)
                    .sequoia(sequoia)
                    .build();

                let password = match prompt!(
                    sequoia, prompt, &mut context, &mut checker)
                    .map_err(|err| Error::PromptError(err))?
                {
                    prompt::Response::Password(password) => Some(password),
                    prompt::Response::NoPassword => None,
                };

                builder = builder.set_password(password);
            }
        }

        // Generate the key.
        //
        // This is a closure.  We want to generate the key as late as
        // possible so we detect any latent errors first.
        let gen = || {
            builder.generate().map_err(op!())
        };

        let (mut cert, rev);

        let mut rev_writer_;
        let (mut output_writer, rev_writer) = match &mut destination {
            Destination::Writer((ref mut output_writer, ref mut rev_writer)) => {
                (cert, rev) = gen()?;

                (Some(output_writer.writer()), rev_writer.writer())
            }
            Destination::Store => {
                if let Some(home) = sequoia.home() {
                    let dir = home.data_dir(crate::directories::Component::Other(
                        "revocation-certificates".into()));
                    std::fs::create_dir_all(&dir)
                        .with_context(|| {
                            format!("While creating {}", dir.display())
                        })
                        .map_err(sys!())?;

                    (cert, rev) = gen()?;

                    let rev_path = dir.join(
                        format!("{}-revocation.pgp", cert.fingerprint()));

                    rev_writer_ = PartFileWriter::create_with_restricted_permissions(
                        &rev_path, true)
                        .with_context(|| {
                            format!("Failed to create {}", rev_path.display())
                        })
                        .map_err(sys!())?;

                    (None, Some(&mut rev_writer_ as _))
                } else {
                    return Err(Error::SystemError(
                        SystemError::HomeDisabled));
                }
            }
            Destination::Ephemeral => {
                (cert, rev) = gen()?;

                (None, None)
            }
        };

        let headers = cert.armor_headers();

        // Write out the revocation certificate.
        if let Some(rev_writer) = rev_writer {
            let mut headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();
            headers.insert(0, ("Comment", "Revocation certificate for"));

            let mut w = armor::Writer::with_headers(
                rev_writer, Kind::PublicKey, headers)
                .map_err(op!())?;
            Packet::from(cert.primary_key().key().clone()).serialize(&mut w)
                .map_err(op!())?;
            Packet::Signature(rev).serialize(&mut w)
                .map_err(op!())?;
            w.finalize()
                .map_err(op!())?;
        }

        let mut key_import_status = None;

        // Write out the key.
        {
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            if let Some(output_writer) = output_writer.as_mut() {
                //// Write the key to a file or to stdout.
                let mut w = armor::Writer::with_headers(
                    output_writer, Kind::SecretKey, headers)
                    .map_err(op!())?;
                cert.as_tsk().serialize(&mut w).map_err(op!())?;
                w.finalize().map_err(op!())?;
            } else if to_keystore {
                // write the key to the key store

                // Certify the key with a per-host shadow CA if there
                // are any user IDs to certify.
                let have_userids = cert.userids().next().is_some();
                if have_userids {
                    if let Ok(c) = certify_generated(
                        &sequoia, &cert, prompt.clone())
                    {
                        cert = c;
                    }
                }

                let outcome = sequoia.key_import()
                    .import_key(cert.clone())
                    .map_err(op!())?;

                key_import_status = Some(
                    outcome
                        .imported
                        .into_iter()
                        .next()
                        .expect("imported key")
                        .key_import_status);

                let certify = || -> Result<(), anyhow::Error> {
                    // Now certify the user IDs, and if this is our own
                    // key, mark it as trusted introducer.
                    let trust_root = sequoia.local_trust_root()?
                        .into_cert();

                    if own_key && have_userids {
                        // Mark all user IDs as authenticated, and mark
                        // the key as a trusted introducer.
                        sequoia.pki_certify()
                            .prompt_(prompt.clone())
                            .recreate(false)
                            .trust_amount(FULLY_TRUSTED as u8)
                            .trust_depth(u8::MAX)
                            .expiration(Expiration::Never)
                            .exportable(false)
                            .certify(
                                &trust_root,
                                &cert,
                                &userids,
                            )?;
                    } else if ! own_key /* shared key */ && have_userids {
                        // Mark all user IDs as authenticated.
                        sequoia.pki_certify()
                            .prompt_(prompt.clone())
                            .recreate(false)
                            .trust_amount(FULLY_TRUSTED as u8)
                            // Not a trusted introducer.
                            .trust_depth(0)
                            .expiration(Expiration::Never)
                            .exportable(false)
                            .certify(
                                &trust_root,
                                &cert,
                                &userids)?;
                    }

                    Ok(())
                };

                // Don't fail if we can't certify the new certificate
                // using the trust root.
                let _ = certify();
            } else {
                // Must be ephemeral.
            }
        }

        Ok(Outcome {
            cert,
            key_import_status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::parse::Parse;

    use crate::cert::list::Output::Binding;
    use crate::cert::list::Query;

    fn check(sequoia: &Sequoia, cert: &Cert, imported: bool,
             authenticated: bool)
    {
        // Check if the cert was import into the cert store.
        let found = sequoia.lookup()
            .lookup_one(cert.key_handle());
        if imported {
            let found = found.expect("Can lookup certificate that was imported");
            assert_eq!(found.fingerprint(), cert.fingerprint());
        } else {
            assert!(found.is_err());
        }

        if imported {
            // Check for the secret key material.
            assert!(sequoia.have_secret_key(&cert.primary_key()),
                    "have secret key material for key that we just generated");
        } else {
            assert!(
                ! sequoia.have_secret_key(
                    &cert.clone().strip_secret_key_material().primary_key()),
                "shouldn't have secret key material");
        }

        // Make sure the user ID was marked as authenticated.
        let mut output = Vec::new();
        sequoia.cert_list()
            .query(Query::email("alice@example.org"))
            .list(&mut output)
            .expect("can list certificates");
        if authenticated {
            assert!(output.into_iter().any(|o| {
                if let Binding(binding) = o {
                    let c = binding.cert(&sequoia).expect("can read cert");
                    assert_eq!(c.fingerprint(), cert.fingerprint());
                    true
                } else {
                    false
                }
            }));
        } else {
            assert!(output.into_iter().all(|o| {
                ! matches!(o, Binding(_))
            }));
        }
    }

    #[test]
    fn key_generate_to_key_store() {
        let sequoia = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Generate key using the high-level API and directly import
        // it to the key store and the certificate store.
        let outcome = sequoia.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate()
            .expect("can generate key");

        assert!(outcome.key_import_status.is_some(),
                "key should have been imported");

        let cert = outcome.cert();

        check(&sequoia, &cert, true, true);
    }

    #[test]
    fn key_generate_to_writer() {
        let sequoia = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut cert_bytes = Vec::new();

        // Generate key using the high-level API and directly import
        // it to the key store and the certificate store.
        let outcome = sequoia.key_generate()
            .email("alice@example.org")
            .without_password()
            .to_writer((&mut cert_bytes, None))
            .generate()
            .expect("can generate key");

        assert!(outcome.key_import_status.is_none(),
                "key should not have been imported");

        let cert = outcome.cert();

        let from_writer = Cert::from_bytes(&cert_bytes)
            .expect("can parse certificate");
        assert_eq!(from_writer.fingerprint(), cert.fingerprint());

        check(&sequoia, &cert, false, false);

        // Import the key and make sure it was not certified by the
        // local trust root.
        sequoia.key_import()
            .import_key(cert.clone())
            .expect("imported");

        check(&sequoia, &cert, true, false);
    }

    #[test]
    fn key_generate_ephemeral() {
        let sequoia = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Generate key using the high-level API and directly import
        // it to the key store and the certificate store.
        let outcome = sequoia.key_generate()
            .email("alice@example.org")
            .without_password()
            .ephemeral()
            .generate()
            .expect("can generate key");

        assert!(outcome.key_import_status.is_none(),
                "key should not have been imported");

        let cert = outcome.cert();

        check(&sequoia, &cert, false, false);

        // Import the key and make sure it was not certified by the
        // local trust root.
        sequoia.key_import()
            .import_key(cert.clone())
            .expect("imported");

        check(&sequoia, &cert, true, false);
    }
}
