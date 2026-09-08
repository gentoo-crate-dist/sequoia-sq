//! Encrypt data.
//!
//! This module contains functionality related to encrypting and
//! optionally signing data.  For decrypting a mesasge, see
//! [`Sequoia::decrypt`](crate::decrypt).  To only sign a message, see
//! [`Sequoia::sign`](crate::sign).
//!
//! # Encryption
//!
//! Messages are encrypted with public keys (certificates), with
//! passwords, or a mix of the two.  For instance, to encrypt a
//! message for Alice and Bob, you could obtain Alice and Bob's
//! certificates and then pass them to [`Builder::add_recipient`].
//! They can then use their private keys to decrypt the message.  If
//! you don't have a certificate for Alice or Bob, you could instead
//! use a password ([`Builder::add_password`]).  The first challenge
//! is to securely share the password with them.  Long term, the
//! larger difficulty is managing the passwords, which is much more
//! complicated than managing certificates.  Nevertheless, there are a
//! few cases where using a password is the better option, because it,
//! unlike a key, can be memorized.
//!
//! Usually when encrypting a message, you'll also want to encrypt it
//! for the user so that they can decrypt it later.
//!
//! # Signing
//!
//! When someone decrypts a message, they usually want to know who it
//! was from.  Social clues, like a sign off, are not enough: anyone
//! can encrypt a message to any certificate.  This identification is
//! accomplished by having the sender sign the message using their own
//! certificate ([`Builder::add_signer`]).  The recipient can then
//! verify the signature and they know what certificate was used to
//! sign the message.  If the recipient has authenticated the
//! certificate (see [`Sequoia::pki_certify`](crate::pki::certify]),
//! then they know who sent the message.
//!
//! Although it is possible to send a message without a signature, it
//! is usually better to include a signature unless you have very
//! specific requirements.
//!
//! In OpenPGP, signing and encryption are separate operations.  As
//! such, it is possible to either sign first and then encrypt or vice
//! versa.  To protect the signer's identity, it is more common to
//! sign first, and then encrypt the signed message.  That is the only
//! option using this interface.
//!
//! # Examples
//!
//! The following example shows how Alice might sign and encrypt a
//! message for Bob.
//!
//! If you have a `Fingerprint` or `KeyID`, use
//! [`Sequoia::lookup`](crate::lookup) to find the corresponding
//! certificate.  If you have an email address, use
//! [`Sequoia::cert_list`](crate::cert::list) to find an authenticated
//! certificate.
//!
//! The encryption function looks for secret key material in the
//! certificate itself, in any [specified
//! keyrings](crate::SequoiaBuilder::add_keyring), and on the key
//! store.
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::cert::list::Query;
//! use sequoia::cert;
//! use sequoia::prompt::Cancel;
//! use sequoia::sign;
//!
//! use sequoia_openpgp as openpgp;
//! use openpgp::cert::amalgamation::ValidAmalgamation;
//! use openpgp::types::KeyFlags;
//! use openpgp::types::RevocationStatus;
//!
//! # fn main() -> anyhow::Result<()> {
//! // A stateless Sequoia instance.
//! let sequoia = Sequoia::builder().ephemeral()?.build()?;
//! #   // Since we create the certificates, they are marked as
//! #   // authenticated.
//! #   let alice = sequoia.key_generate()
//! #         .email("alice@example.org")
//! #         .without_password()
//! #         .generate(Cancel::new())
//! #         .expect("can generate certificate")
//! #         .into_cert();
//! #   let bob_priv = sequoia.key_generate()
//! #         .email("bob@example.org")
//! #         .without_password()
//! #         .generate(Cancel::new())
//! #         .expect("can generate certificate")
//! #         .into_cert();
//!
//! // The message to sign.
//! let message = b"I love you";
//!
//! // Find a certificate for Bob.
//! //
//! // If there are multiple certificates that we can authenticate for
//! // "bob@example.org" we take the first one (arbitrarily) that is valid
//! // (live, not revoked, has an encryption capable subkey).
//! let certs = sequoia.lookup_by()
//!     .cert_capabilities(KeyFlags::storage_encryption()
//!                        .set_transport_encryption())
//!     .lookup_all_by_email("alice@example.org")?;
//! let Some(bob) = certs.into_iter().next() else {
//!     panic!("Could not find an authenticated certificate for Bob");
//! };
//!
//! let mut ciphertext = Vec::new();
//! sequoia.encrypt()
//!     .add_signer(alice.clone())
//!     .add_recipient(bob.clone())
//!     .encrypt(
//!         std::io::Cursor::new(message),
//!         &mut ciphertext,
//!         // Fail if the signing key is password protected.
//!         sequoia::prompt::Cancel::new())?;
//! #
//! # let mut plaintext = Vec::new();
//! # sequoia.decrypt()
//! #     .add_designated_signer(alice)
//! #     .add_secret_key(bob_priv)
//! #     .decrypt(
//! #         std::io::Cursor::new(ciphertext),
//! #         &mut plaintext,
//! #         Cancel::new())
//! #     .expect("Valid signature");
//! # assert_eq!(&plaintext, message);
//! # Ok(()) }
//! ```
//!
//! To get more information about the encryption process, you can
//! provide an implementation of [`Stream`]:
//!
//! ```
//! use sequoia::Result;
//! use sequoia::Sequoia;
//! use sequoia::encrypt::Output;
//! use sequoia::encrypt::Params;
//! use sequoia::encrypt::Stream;
//! use sequoia::encrypt;
//! use sequoia::prompt::Cancel;
//! # use sequoia::openpgp::cert::CertBuilder;
//!
//! struct MyStream {
//! }
//!
//! impl Stream for MyStream {
//!    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
//!        match output {
//!            Output::Encrypting(encrypting) => {
//!                eprintln!("Will encrypt to {} recipients and sign with {} keys",
//!                          encrypting.recipients.len(), encrypting.signers.len());
//!            }
//!            _ => (),
//!        }
//!
//!        Ok(())
//!    }
//! }
//!
//! # fn main() -> anyhow::Result<()> {
//! # let (alice, _) =
//! #     CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! # let (bob, _) =
//! #     CertBuilder::general_purpose(Some("bob@example.org"))
//! #         .generate()?;
//! #
//! // A stateless Sequoia instance.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // The message to sign.
//! let message = b"I owe you";
//!
//! let mut stream = MyStream {};
//!
//! let mut ciphertext = Vec::new();
//! sequoia.encrypt()
//!     .stream(&mut stream)
//!     .add_signer(alice.clone())
//!     .add_recipient(bob.clone())
//!     .encrypt(
//!         std::io::Cursor::new(message),
//!         &mut ciphertext,
//!         // Fail if the signing key is password protected.
//!         sequoia::prompt::Cancel::new())?;
//! #
//! # let mut plaintext = Vec::new();
//! # sequoia.decrypt()
//! #     .add_designated_signer(alice)
//! #     .add_secret_key(bob)
//! #     .decrypt(
//! #         std::io::Cursor::new(ciphertext),
//! #         &mut plaintext,
//! #         Cancel::new())
//! #     .expect("Valid signature");
//! # assert_eq!(&plaintext, message);
//! # Ok(()) }
//! ```
use std::sync::Arc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::armor;
use openpgp::cert::ValidCert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::cert::amalgamation::key::ValidKeyAmalgamation;
use openpgp::crypto::Password;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::Compressor;
use openpgp::serialize::stream::Encryptor;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Signer;
use openpgp::serialize::stream::padding::Padder;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::Writer;
use crate::cert::CertError;
use crate::cert;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::types::CompressionMode;
use crate::types::EncryptPurpose;

// Stream trait.
stream!{}

/// Errors related to encryption.
///
/// Errors are divided into categories and each category contains more
/// precise errors.
///
/// These errors are usually wrapped in an [`Error`].
pub mod error {
    use super::*;

    /// Neither recipient nor password were given.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Neither recipient nor password given")]
    pub struct NoRecipientsOrPasswords {
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        NoRecipientsOrPasswords(NoRecipientsOrPasswords),
    }

    /// Signing failed.
    ///
    /// Provides some information about why signing was not
    /// possible.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{}",
            if let Some(err) = .unusable_certs.first() {
                err.to_string()
            } else {
                format!("Certificate can't be used for signing")
            })]
    pub struct SigningFailed {
        pub unusable_certs: Vec<CertError>,
    }

    /// Encryption failed.
    ///
    /// Provides some information about why encryption was not
    /// possible.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Encryption failed")]
    pub struct EncryptionFailed {
        pub unusable_certs: Vec<CertError>,
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
        PromptError(prompt::Error),

        #[error(transparent)]
        SigningFailed(SigningFailed),

        #[error(transparent)]
        EncryptionFailed(EncryptionFailed),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to encryption.
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

    /// If [`Stream::output`] returns an error, it is propagated here.
    StreamOutputError(anyhow::Error),
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// Information about how we're going to encrypt and sign the
    /// message before we do the actual encryption.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Encrypting {
        /// The recipients.
        pub recipients: Vec<(Cert, Vec<Fingerprint>)>,

        /// Set to true if the user may not be able to decrypt the
        /// message, because the secret key material is not available
        /// for any of the recipients.
        pub undecryptable: bool,

        /// The number of passwords that the message is encrypted to.
        pub passwords: Vec<Password>,

        /// The signers, if any.
        pub signers: Vec<(Cert, Fingerprint)>,
    }

    /// Emitted at the end.
    ///
    /// This is always emitted whether signing was successful or not.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
    }
}

/// The [`Stream`] output.
///
/// The variants of this enum are the different types of output that
/// [`encrypt`](Builder::encrypt) emits.  See [`Stream`].
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    /// An operational error occurred.
    ///
    /// This may be because the operation requires the certificate
    /// store, but it is disabled.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    OperationalError(error::OperationalError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    SystemError(SystemError),

    /// Errors related to incorrectly calling the function.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    ArgumentError(error::ArgumentError),

    /// Information about how we're going to encrypt and sign the
    /// message before we do the actual encryption.
    Encrypting(output::Encrypting),

    /// Emitted at the end.
    ///
    /// This is always emitted whether signing was successful or not.
    Report(output::Report),
}

/// The encryption operation's outcome.
///
/// This is returned by [`Builder::encrypt`].  It contains information
/// about the operation's outcome.  More detailed information is
/// available via the [`Stream`] interface.
#[non_exhaustive]
#[derive(Debug)]
pub struct Outcome {
}

impl Outcome {
    fn new() -> Self {
        Outcome {
        }
    }

    fn to_report(&self) -> output::Report {
        output::Report {
        }
    }
}

/// The encryption parameters.
///
/// These parameters are used by [`encrypt`](Builder::encrypt).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    signers: Vec<Cert>,
    notations: Vec<(bool, NotationData)>,

    prompt_for_passwords: usize,
    passwords: Vec<Password>,
    recipients: Vec<Cert>,

    /// If Some, ASCII-armor.  Otherwise, binary.
    armor_headers: Option<Vec<(String, String)>>,

    encryption_purpose: EncryptPurpose,
    compression_mode: CompressionMode,
    use_expired_encryption_keys: bool,

    filename: Vec<u8>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the configured signers.
    pub fn signers(&self) -> impl Iterator<Item=&Cert> {
        self.signers.iter()
    }

    /// Returns the configured notations.
    pub fn notations(&self) -> impl Iterator<Item=&(bool, NotationData)> {
        self.notations.iter()
    }

    /// Returns whether ASCII-armor is enabled.
    pub fn ascii_armor(&self) -> bool {
        self.armor_headers.is_some()
    }

    /// Returns the configured ASCII-armor headers.
    pub fn ascii_armor_headers(&self) -> impl Iterator<Item=&(String, String)> {
        static EMPTY: Vec<(String, String)> = Vec::new();

        if let Some(h) = self.armor_headers.as_ref() {
            h.iter()
        } else {
            EMPTY.iter()
        }
    }

    /// Returns the passwords that user will be prompted to enter.
    ///
    /// Each password will be used to encrypt the message.
    pub fn prompt_for_passwords(&self) -> usize {
        self.prompt_for_passwords
    }

    /// Returns the passwords that will be used to encrypt the message.
    pub fn passwords(&self) -> impl Iterator<Item=&Password> {
        self.passwords.iter()
    }

    /// Returns the recipient certificates.
    pub fn recipients(&self) -> impl Iterator<Item=&Cert> {
        self.recipients.iter()
    }

    /// Returns the encryption purpose.
    pub fn encryption_purpose(&self) -> EncryptPurpose {
        self.encryption_purpose.clone()
    }

    /// Returns the compression mode.
    pub fn compression_mode(&self) -> CompressionMode {
        self.compression_mode.clone()
    }

    /// Returns whether expired encryption keys will be used.
    pub fn use_expired_encryption_keys(&self) -> bool {
        self.use_expired_encryption_keys
    }

    /// Returns the filename that will be embedded in the literal data
    /// packet.
    pub fn unsafe_filename(&self) -> &[u8] {
        &self.filename
    }
}

/// Owned parameters.
struct ParamsOnce<'stream> {
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Encrypt messages.
///
/// This command builder is used to encrypt messages.
pub struct Builder<'sequoia, 'stream> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'stream>,
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream> {
    pub(crate) fn new(sequoia: &'sequoia Sequoia)
        -> Builder<'sequoia, 'stream>
    {
        Builder {
            params: Params {
                sequoia,
                signers: Vec::new(),
                notations: Vec::new(),

                prompt_for_passwords: 0,
                passwords: Vec::new(),
                recipients: Vec::new(),

                armor_headers: Some(Vec::new()),

                encryption_purpose: EncryptPurpose::Universal,
                compression_mode: CompressionMode::Pad,
                use_expired_encryption_keys: false,

                filename: Vec::new(),
            },
            params_once: ParamsOnce {
                stream: None,
            }
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    stream_builder_impl!();

    /// Signs the message with the specified certificate.
    ///
    /// This adds the certificate to the list of certificates that the
    /// message will be signed with.  It is possible to add multiple
    /// signatures to a message.
    ///
    /// The message will be signed with one valid (live, non-revoked)
    /// signing-capable key associated with the certificate for which
    /// the secret key material is available.  If the certificate has
    /// no valid signing-capable keys with secret key material, then
    /// an error will be returned.
    ///
    /// Messages should normally be signed by at least one
    /// certificate; it is strongly discouraged to send unsigned
    /// messages as the messages cannot be authenticated.
    pub fn add_signer(mut self, signer: Cert) -> Self {
        self.params.signers.push(signer);
        self
    }

    /// Signs the message with the specified certificates.
    ///
    /// See [`Builder::add_signer`] for details.
    pub fn add_signers(mut self, signers: impl IntoIterator<Item=Cert>)
        -> Self
    {
        self.params.signers.extend(signers.into_iter());
        self
    }

    /// Adds a notation to the signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(mut self, critical: bool, notation: NotationData) -> Self
    {
        self.params.notations.push((critical, notation));
        self
    }

    /// Adds notation to the signatures.
    ///
    /// The first value of the tuple is the notation's criticality.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notations(mut self,
                         notations: impl IntoIterator<Item=(bool, NotationData)>)
        -> Self
    {
        self.params.notations.extend(notations.into_iter());
        self
    }

    /// Encrypts the message with one or more passwords obtained from
    /// the user.
    ///
    /// The user is prompted for the passwords.  If the user cancels
    /// the prompt, the operation is aborted.
    ///
    /// By default, the user is not prompted for a password.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn prompt_for_passwords(mut self, count: usize) -> Self {
        self.params.prompt_for_passwords = count;
        self
    }

    /// Encrypts the message with the specified password.
    ///
    /// This adds the password to the list of passwords that will be
    /// used to encrypt the message.  It is possible to encrypt a
    /// message with multiple passwords.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn add_password(mut self, password: Password) -> Self {
        self.params.passwords.push(password);
        self
    }

    /// Encrypts the message with the specified passwords.
    ///
    /// This adds the passwords to the list of passwords that will be
    /// used to encrypt the message.  It is possible to encrypt a
    /// message with multiple passwords.
    ///
    /// A recipient only needs to know one of the passwords to decrypt
    /// the message.
    pub fn add_passwords(mut self, passwords: impl IntoIterator<Item=Password>)
        -> Self
    {
        self.params.passwords.extend(passwords.into_iter());
        self
    }

    /// Encrypts the message for the specified certificate.
    ///
    /// This adds the certificate to the list of certificates that the
    /// message will be encrypted for.  It is possible to encrypt a
    /// message for multiple certificates.
    ///
    /// The message will be encrypt for all valid (live, non-revoked)
    /// encryption-capable keys associated with the certificate and
    /// compatible with the encryption purpose (see
    /// [`Builder::encryption_purpose`]).  If the certificate has no
    /// valid encryption-capable keys, then an error will be returned.
    pub fn add_recipient(mut self, recipient: Cert) -> Self {
        self.params.recipients.push(recipient);
        self
    }

    /// Encrypts the message for the specified certificates.
    ///
    /// See [`Builder::add_recipient`] for details.
    pub fn add_recipients(mut self, recipients: impl IntoIterator<Item=Cert>)
        -> Self
    {
        self.params.recipients.extend(recipients.into_iter());
        self
    }

    /// Sets the encryption purpose.
    ///
    /// The default is [`EncryptPurpose::Universal`].
    pub fn encryption_purpose(mut self, encryption_purpose: EncryptPurpose)
        -> Self
    {
        self.params.encryption_purpose = encryption_purpose;
        self
    }

    /// Sets the compression mode.
    ///
    /// The default is [`CompressionMode::Pad`].
    pub fn compression_mode(mut self, compression_mode: CompressionMode)
        -> Self
    {
        self.params.compression_mode = compression_mode;
        self
    }

    /// Sets whether to use encryption keys that are expired.
    ///
    /// Occasionally, users let their certificates expire.  It can
    /// sometimes be better to encrypt a message to an expired
    /// certificate than to send it in cleartext.
    ///
    /// This is not enabled by default, and you should avoid using
    /// this unless the user explicitly opts in.
    pub fn use_expired_encryption_keys(mut self,
                                       use_expired_encryption_keys: bool)
        -> Self
    {
        self.params.use_expired_encryption_keys = use_expired_encryption_keys;
        self
    }

    /// Sets whether ASCII armor is used.
    ///
    /// If disabled, then the message is binary encoded.
    ///
    /// The default is to using ASCII armor and not add any headers.
    pub fn ascii_armor(mut self, use_ascii_armor: bool)
        -> Self
    {
        self.params.armor_headers = if use_ascii_armor {
            Some(Vec::new())
        } else {
            None
        };
        self
    }

    /// Enables ASCII armor and sets the ASCII-armor headers.
    ///
    /// This implicitly enables ASCII armor, and uses the specified
    /// headers.
    ///
    /// Note: the headers are informative and are neither encrypted
    /// nor protected by any signature.
    pub fn ascii_armor_headers<K, V>(mut self,
                                     headers: impl IntoIterator<Item=(K, V)>)
        -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.params.armor_headers = Some(
            headers
                .into_iter()
                .map(|(k, v)| {
                    (k.into(), v.into())
                })
                .collect());
        self
    }

    /// Sets the filename in the literal data packet.
    ///
    /// This is deprecated and should no longer be used.  This is
    /// available for backwards compatibility.
    ///
    /// Note: the filename is not protected by any signatures and
    /// could be manipulated by an attacker without detection.  If you
    /// need to encode a filename, you should use a container format
    /// like `pax` (tar's successor) or `zip`.
    ///
    ///   [`pax`]: https://en.wikipedia.org/wiki/Pax_(command)
    ///
    /// The filename is limited to 255 bytes.  An error is returned if
    /// `filename` contains more than 255 bytes.
    pub fn unsafe_filename<F>(mut self, filename: F)
        -> Result<Self>
    where
        F: AsRef<[u8]>
    {
        let filename = filename.as_ref();

        if filename.len() > 255 {
            Err(anyhow::anyhow!("Filename too long ({} bytes of 255 bytes)",
                                filename.len()))
        } else {
            self.params.filename = filename.to_vec();
            Ok(self)
        }
    }
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream> {
    /// Encrypts the specified message with the configured parameters.
    ///
    /// The encrypted data is written to `output`.  By default, the
    /// message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be encrypted.
    ///
    /// On failure some of the encrypted data may have been written to
    /// the output writer.  This should be ignored.
    pub fn encrypt<'w, 'p, I, O, P>(mut self, mut input: I, output: O, prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        O: Into<Writer<'w>>,
        P: prompt::PromptFactory<'p>,
    {
        let outcome = Outcome::new();

        let result = Self::encrypt_(
            &self.params, &mut self.params_once,
            &mut input, output.into(), &prompt);

        let mut stream = self.params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(())
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(&self.params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(&self.params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(&self.params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        // Emit the report.
        stream.output(
            &self.params,
            Output::Report(outcome.to_report()))
            .map_err(|err| Error::StreamOutputError(err))?;

        result.map(|_| outcome)
    }

    fn encrypt_<'w, 'p>(params: &Params, params_once: &mut ParamsOnce,
                        mut input: &mut (dyn std::io::Read + Send + Sync),
                        output: Writer<'w>,
                        prompt: &dyn prompt::PromptFactory<'p>)
        -> Result<(), Error>
    {
        let &Params {
            sequoia,
            ref signers,
            ref notations,

            prompt_for_passwords,
            ref passwords,
            ref recipients,

            ref encryption_purpose,
            ref compression_mode,
            use_expired_encryption_keys,

            ref armor_headers,

            ref filename,
        } = params;
        let ParamsOnce {
            stream,
        } = params_once;

        let mut signers = sequoia.get_signing_keys(&signers, None, &prompt)
            .map_err(|err| {
                Error::OperationalError(
                    error::OperationalError::SigningFailed(
                        error::SigningFailed {
                            unusable_certs: vec![ err ],
                        }))
            })?;

        let mut passwords = passwords.to_vec();
        for _ in 0..prompt_for_passwords {
            let mut checker = CheckNewPassword::required();

            let mut context = prompt::ContextBuilder::password(
                prompt::Reason::EncryptMessage)
                .sequoia(sequoia)
                .build();

            match prompt.prompt(&mut context, &mut checker)
                .map_err(|err| {
                    Error::OperationalError(
                        error::OperationalError::PromptError(err))
                })?
            {
                prompt::Response::Password(password) => {
                    passwords.push(password);
                }
                prompt::Response::NoPassword => {
                    // `CheckNewPasswordRequired` will not return
                    // `NoPassword`.
                    panic!("CheckNewPasswordRequired::required \
                            returned NoPassword");
                }
            }
        }

        if recipients.len() + passwords.len() == 0 {
            return Err(Error::ArgumentError(
                error::ArgumentError::NoRecipientsOrPasswords(
                    error::NoRecipientsOrPasswords {
                    })));
        }

        // Returns the encryption capable keys for the given
        // certificate.  If there are none, lint the certificate.
        fn get_encryption_keys<'a>(vc: &ValidCert<'a>,
                                   sequoia: &Sequoia,
                                   mode: &KeyFlags,
                                   use_expired_encryption_keys: bool)
            -> std::result::Result<
                (bool, Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>),
                Vec<cert::CertProblem>>
        {
            // XXX: In this block, instead of using sequoia.best_userid(&cert,
            // true), it'd be nice to use the cert designator that the
            // user used, instead or additionally.

            // This cert's subkeys we selected for encryption.
            let mut selected_keys = Vec::new();

            // As a fallback, we may consider expired keys.
            let mut expired_keys = Vec::new();

            let mut problems: Vec<cert::CertProblem> = Vec::new();

            let mut encryption_capable_keys = 0;
            for ka in vc.keys() {
                if let Some(key_flags) = ka.key_flags() {
                    if (&key_flags & mode).is_empty() {
                        // Not for encryption.
                        continue;
                    }
                } else {
                    // No key flags.  Not for encryption.
                    continue;
                }
                encryption_capable_keys += 1;

                let mut have_problem = false;
                if ! ka.key().pk_algo().is_supported() {
                    problems.push(cert::CertProblem::UnsupportedAlgorithm(
                        cert::problem::UnsupportedAlgorithm {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            algo: ka.key().pk_algo(),
                        }));
                    have_problem = true;
                }
                if let RevocationStatus::Revoked(sigs) = ka.revocation_status() {
                    problems.push(cert::CertProblem::KeyRevoked(
                        cert::problem::KeyRevoked {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            revocations: sigs.into_iter().cloned().collect(),
                        }));
                    have_problem = true;
                }
                if let Err(err) = ka.alive() {
                    let creation_time = ka.key().creation_time();
                    let expiration_time = ka.key_expiration_time();

                    problems.push(cert::CertProblem::NotLive(
                        cert::problem::NotLive {
                            cert: vc.fingerprint(),
                            key: ka.key().fingerprint(),
                            creation_time,
                            expiration_time,
                            reference_time: sequoia.time(),
                            error: err.into(),
                        }));

                    if ! have_problem {
                        if let Some(expiration_time) = expiration_time.as_ref() {
                            if *expiration_time < sequoia.time() {
                                // The only problem is that the key is expired.
                                expired_keys.push((ka, expiration_time.clone()));
                            }
                        }
                    }
                } else if ! have_problem {
                    selected_keys.push(ka);
                }
            }

            if selected_keys.is_empty() && use_expired_encryption_keys
                && ! expired_keys.is_empty()
            {
                expired_keys.sort_by_key(|(_key, t)| *t);

                if let Some((key, _expiration_time)) = expired_keys.pop() {
                    selected_keys.push(key);
                }
            }

            if selected_keys.is_empty() {
                // We didn't find any keys for this certificate.

                // See if there are encryption-capable subkeys that
                // are just invalid.
                for ka in vc.cert().keys() {
                    if let Err(err) = ka.with_policy(sequoia.policy(), sequoia.time()) {
                        problems.push(cert::CertProblem::KeyInvalid(
                            cert::problem::KeyInvalid {
                                cert: vc.fingerprint(),
                                key: ka.key().fingerprint(),
                                error: err.into(),
                            }));
                    }
                }

                if problems.is_empty() {
                    problems.push(cert::CertProblem::NoUsableKeys(
                        cert::problem::NoUsableKeys {
                            cert: vc.fingerprint(),
                            capabilities: mode.clone(),
                            unusable: encryption_capable_keys,
                        }));
                }

                Err(problems)
            } else {
                let mut have_one_secret = false;
                let mut recipient_subkeys = Vec::new();
                for ka in selected_keys {
                    have_one_secret |= sequoia.have_secret_key(ka.amalgamation());
                    recipient_subkeys.push(ka);
                }

                Ok((have_one_secret, recipient_subkeys))
            }
        }

        let mut unusable_certs = Vec::new();

        let mut vc = Vec::new();
        for cert in recipients.iter() {
            let revocation_status
                = cert.revocation_status(sequoia.policy(), sequoia.time());
            if let RevocationStatus::Revoked(sigs) = revocation_status {
                unusable_certs.push(cert::CertError {
                    cert: cert.clone(),
                    problems: vec![
                        cert::CertProblem::CertRevoked(
                            cert::problem::CertRevoked {
                                cert: cert.fingerprint(),
                                revocations: sigs.into_iter().cloned().collect(),
                            }),
                    ],
                });
            } else {
                match cert.with_policy(sequoia.policy(), sequoia.time()) {
                    Ok(vc_) => vc.push(vc_),
                    Err(err) => {
                        unusable_certs.push(cert::CertError {
                            cert: cert.clone(),
                            problems: vec![
                                cert::CertProblem::CertInvalid(
                                    cert::problem::CertInvalid {
                                        cert: cert.fingerprint(),
                                        error: err.into()
                                    }),
                            ],
                        });
                    }
                }
            }
        }

        let mode = KeyFlags::from(encryption_purpose);

        // Tracks whether we have a secret for at least one of the
        // encryption subkeys.
        let mut have_one_secret = false;

        let mut recipient_subkeys = Vec::new();
        for vc in vc {
            match get_encryption_keys(&vc, sequoia, &mode, use_expired_encryption_keys) {
                Ok((have_secret, keys)) => {
                    have_one_secret |= have_secret;
                    recipient_subkeys.extend(keys);
                }
                Err(problems) => {
                    unusable_certs.push(cert::CertError {
                        cert: vc.cert().clone(),
                        problems,
                    })
                }
            }
        }

        if ! unusable_certs.is_empty() {
            return Err(Error::OperationalError(
                error::OperationalError::EncryptionFailed(
                    error::EncryptionFailed {
                        unusable_certs
                    })));
        } else {
            let mut recipients = recipient_subkeys
                .iter()
                .map(|ka| {
                    (ka.cert(), vec![ ka.key().fingerprint() ])
                })
                .collect::<Vec<(&Cert, _)>>();
            recipients.dedup_by(|(cert_a, ref mut key_a), (cert_b, key_b)| {
                if cert_a.fingerprint() == cert_b.fingerprint() {
                    // A will be removed.
                    key_b.append(key_a);

                    true
                } else {
                    false
                }
            });
            let recipients = recipients
                .into_iter()
                .map(|(cert, keys)| {
                    (cert.clone(), keys)
                })
                .collect::<Vec<_>>();

            stream.output(
                params,
                Output::Encrypting(output::Encrypting {
                    recipients,
                    undecryptable: ! have_one_secret,
                    passwords: passwords.clone(),
                    signers: signers.iter()
                        .map(|(cert, signer)| {
                            (cert.clone(), signer.public().fingerprint())
                        })
                        .collect(),
                }))
                .map_err(|err| Error::StreamOutputError(err))?;
        }

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message).kind(armor::Kind::Message);
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build().map_err(op!())?;
        }

        // We want to encrypt a literal data packet.
        let encryptor =
            Encryptor::for_recipients(message, recipient_subkeys)
            .add_passwords(passwords);

        let mut sink = encryptor.build()
            .context("Failed to create encryptor")
            .map_err(op!())?;

        match compression_mode {
            CompressionMode::None => (),
            CompressionMode::Pad => {
                sink = Padder::new(sink).build().map_err(op!())?;
            }
            CompressionMode::Zip => {
                sink = Compressor::new(sink).algo(CompressionAlgorithm::Zip)
                    .build().map_err(op!())?;
            }
            CompressionMode::Zlib => {
                sink = Compressor::new(sink).algo(CompressionAlgorithm::Zlib)
                    .build().map_err(op!())?;
            }
            CompressionMode::Bzip2 => {
                sink = Compressor::new(sink).algo(CompressionAlgorithm::BZip2)
                    .build().map_err(op!())?;
            }
        }

        // Optionally sign message.
        if let Some(first) = signers.pop() {
            // Create a signature template.
            let mut builder = SignatureBuilder::new(SignatureType::Binary);
            for (critical, n) in notations.iter() {
                builder = builder.add_notation(
                    n.name(),
                    n.value(),
                    Some(n.flags().clone()),
                    *critical)
                    .map_err(op!())?;
            }

            let mut signer = Signer::with_template(sink, first.1, builder)
                .map_err(op!())?;

            for s in signers {
                signer = signer.add_signer(s.1)
                    .map_err(op!())?;
            }
            for r in recipients.iter() {
                signer = signer.add_intended_recipient(r);
            }
            sink = signer.build()
                .map_err(op!())?;
        }

        let literal_writer = LiteralWriter::new(sink).filename(filename)
            .map_err(op!())?;

        let mut writer_stack = literal_writer
            .build()
            .context("Failed to create literal writer")
            .map_err(op!())?;

        // Finally, copy stdin to our writer stack to encrypt the data.
        std::io::copy(&mut input, &mut writer_stack)
            .context("Failed to encrypt")
            .map_err(op!())?;

        writer_stack.finalize().context("Failed to encrypt")
            .map_err(op!())?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::prompt::Cancel;

    const MESSAGE: &[u8] = b"message";

    fn check(output: Vec<Output>, result: Result<Outcome, Error>,
             recipients: usize, signers: usize)
    {
        let mut saw_error = None;
        let mut saw_report = false;
        let mut saw_signing = false;

        eprintln!("Start: expecting {} signers, result: {:?}",
                  signers,
                  result.as_ref().map(|_| ()).map_err(|err| err.to_string()));
        for o in output.iter() {
            match o {
                Output::OperationalError(err) => {
                    eprintln!("- Operational Error: {}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }
                Output::SystemError(err) => {
                    eprintln!("- System Error: {}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }
                Output::ArgumentError(err) => {
                    eprintln!("- Argument Error: {}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }

                Output::Encrypting(encrypting) => {
                    eprintln!("- Encrypting");
                    assert!(! saw_report);
                    assert!(saw_error.is_none());
                    saw_signing = true;
                    assert_eq!(recipients, encrypting.recipients.len(),
                               "recipients: expected vs. got");
                    assert_eq!(signers, encrypting.signers.len(),
                               "signers: expected vs. got");
                }

                Output::Report(_report) => {
                    eprintln!("- Report");
                    assert!(! saw_report);
                    saw_report = true;
                }
            }
        }
        eprintln!("End");

        assert!(saw_report);

        match (result, saw_error) {
            (Ok(_), Some(err)) => {
                // Function returned success, but saw an error.
                panic!("Function returned success, but an error was \
                        propagated via the stream: {:?}",
                       err);
            }
            (Err(err), None) => {
                // Function returned an error, but we didn't see an error.
                panic!("Function return an error, but error was not \
                        propagated via the steam: {:?}",
                       err);
            }
            (Err(f_err), Some(s_err)) => {
                // Error does not implement Eq.  Instead convert the
                // error to a string.  Unless two different errors
                // have the same display output, this should is
                // enough.
                if f_err.to_string() != s_err {
                    panic!("Function returned a different error from the stream:\
                            \nFunction: {:?}\n  Stream: {:?}",
                           f_err, s_err);
                }
            }
            (Ok(_outcome), None) => {
                assert!(saw_signing);
            }
        }
    }

    #[test]
    fn encrypt() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Generate certificates and import them to the key store.
        let keystore1 = sq.key_generate()
            .email("keystore@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();
        let keystore2 = sq.key_generate()
            .email("keystore@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        // Generate certificates and don't import them to the key store.
        let ephemeral1 = sq.key_generate()
            .email("ephemeral@example.org")
            .without_password()
            .ephemeral()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();
        let ephemeral2 = sq.key_generate()
            .email("ephemeral@example.org")
            .without_password()
            .ephemeral()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        // The cert contains secret key material and the key
        // material is stored on the key store.
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_recipient(keystore1.clone())
            .add_signer(keystore2.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_ok(), "Failed: {}", result.unwrap_err());
        check(output, result, 1, 1);

        // The cert contains secret key material and the key
        // material is NOT stored on the key store.
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_recipient(ephemeral1.clone())
            .add_signer(ephemeral2.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_ok(), "Failed: {}", result.unwrap_err());
        check(output, result, 1, 1);

        // No secret key material.
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_recipient(ephemeral1.clone().strip_secret_key_material())
            .add_signer(ephemeral2.clone().strip_secret_key_material())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_err());
        check(output, result, 0, 0);

        // Multiple recipients and multiple signers.
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_recipient(ephemeral1.clone())
            .add_recipient(keystore1.clone())
            .add_signer(ephemeral1.clone())
            .add_signer(ephemeral2.clone())
            .add_signer(keystore2.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_ok(), "Failed: {}", result.unwrap_err());
        check(output, result, 2, 3);

        // No signer (good).
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_recipient(keystore1.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_ok(), "Failed: {}", result.unwrap_err());
        check(output, result, 1, 0);

        // Signer, but no recipient (bad).
        let mut output = Vec::new();
        let mut ciphertext = Vec::new();
        let result = sq.encrypt()
            .stream(&mut output)
            .add_signer(keystore1.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                crate::prompt::Cancel::new());

        assert!(result.is_err());
        check(output, result, 0, 0);
    }
}
