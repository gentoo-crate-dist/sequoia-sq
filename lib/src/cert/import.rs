//! Import certificates and revocation certificates.
//!
//! Certificates can be imported directly, from a keyring or from an
//! email's autocrypt headers.  Importing bare revocation certificates
//! is also supported, if the corresponding certificate is already
//! available in the certificate store or in one of the supplied
//! keyrings (see [`SequoiaBuilder::add_keyring`]).
//! [`Builder::import`] auto-detects the file's type.
//! [`Builder::import_keyring`], [`Builder::import_revocation`], and
//! [`Builder::import_autocrypt`] each handle a specific file type.
//!
//! [`SequoiaBuilder::add_keyring`]: crate::SequoiaBuilder::add_keyring
//!
//! If an imported certificate includes secret key material, the
//! secret key material is silently dropped.  To import secret key
//! material, use [`Sequoia::key_import`].
//!
//! # Examples
//!
//! Import certificates from a keyring, a bare revocation certificate,
//! or certificates from an email with autocrypt headers:
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let (alice, _alice_rev) = CertBuilder::new()
//! #     .add_userid("<alice@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! # let mut input = Vec::new();
//! # alice.serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! // The prompt is used to ask for a password to decrypt an
//! // Autocrypt message.  Here we suppress the prompt.
//! let prompt = Cancel::new();
//!
//! if let Err(err) = sq.cert_import().import(input, prompt) {
//!     eprintln!("Failed to import the file: {}", err);
//! }
//! # Ok(()) }
//! ```
//!
//! To get more information about what happened, we can pass an
//! implementation of the [`Stream`] trait.  Note: if you don't
//! require the information asynchronously, you can also pass a [`&mut
//! Vec<Output>`](Output) to collect the output and examine it after
//! the call returns.
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
//! use sequoia::cert::import::Output;
//! use sequoia::cert::import::output::*;
//! use sequoia::cert::import;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let (alice, _alice_rev) = CertBuilder::new()
//! #     .add_userid("<alice@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! # let mut input = Vec::new();
//! # alice.serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! pub struct Stream {
//!     // Local state.
//! }
//!
//! impl import::Stream for Stream {
//!     fn output(&mut self,
//!               _params: &import::Params,
//!               output: Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             Output::Imported(Imported { merged, .. }) => {
//!                 eprintln!("Imported {}", merged.fingerprint());
//!             }
//!             Output::ImportingFailed(err) => {
//!                 eprintln!("Failed to import: {}", err);
//!             }
//!             Output::Report(Report { stats, ..}) => {
//!                 eprintln!("New {}, updated: {}, unchanged: {}, errors: {}",
//!                           stats.certs.new_certs(),
//!                           stats.certs.updated_certs(),
//!                           stats.certs.unchanged_certs(),
//!                           stats.certs.errors());
//!                 # assert_eq!(stats.certs.new_certs(), 1);
//!                 # assert_eq!(stats.certs.errors(), 0);
//!             }
//!             _ => (),
//!         }
//!
//!         // Return an error to abort processing.
//!         Ok(())
//!     }
//! }
//!
//! // The prompt is used to ask for a password to decrypt an
//! // Autocrypt message.  Here we suppress the prompt.
//! let prompt = Cancel::new();
//!
//! let mut stream = Stream { };
//! if let Err(err) = sq.cert_import()
//!     .stream(&mut stream)
//!     .import(input, prompt)
//! {
//!     eprintln!("Failed to import at least one certificate: {}", err);
//! }
//! # Ok(()) }
//! ```

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use sequoia_openpgp::parse::buffered_reader;
use buffered_reader::BufferedReader;
use buffered_reader::Dup;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Packet;
use openpgp::cert::raw::RawCert;
use openpgp::cert::raw::RawCertParser;
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::parse::Cookie;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use sequoia_autocrypt as autocrypt;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::decrypt;
use crate::prompt;
use crate::provenance::certify_downloads;
use crate::types::SessionKey;
use crate::types::import_stats::ImportStats;

// Stream trait.
stream!{}

/// Data structures related to [`Error`].
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
pub mod error {
    use super::*;

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// Information about a broken certificate.
    ///
    /// If `cert` is `None`, then we expected a certificate and found
    /// junk.  If `cert` is `Some`, we were able to parse some bytes
    /// into something that resembles a certificate, but the
    /// certificate is corrupted.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parsing certificate {}{}",
            if .cert.is_some() {
                " "
            } else {
                ""
            },
            if let Some(cert) = .cert.as_ref() {
                Cow::Owned(cert.fingerprint().to_string())
            } else {
                Cow::Borrowed("")
            })]
    pub struct BrokenCert {
        pub cert: Option<RawCert<'static>>,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// Information about a broken revocation certificate.
    ///
    /// We were able to parse some bytes into an OpenPGP packet, but
    /// upon closer inspection, the certificate is broken.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parsing revocation certificate")]
    pub struct BrokenRevocation {
        pub packet: Packet,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// Information about an email that does not contain an autocrypt
    /// header.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parsing autocrypt message")]
    pub struct BrokenAutocrypt {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// An artifact is broken.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(transparent)]
    pub enum BrokenArtifact {
        /// The certificate is broken.
        BrokenCert(BrokenCert),

        /// The packet is not a revocation certificate.
        BrokenRevocation(BrokenRevocation),

        /// The email does not contain autocrypt headers.
        BrokenAutocrypt(BrokenAutocrypt),
    }


    /// Email does not contain any Autocrypt headers.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Email does not contain any Autocrypt headers")]
    pub struct NoAutocryptHeader {
    }

    /// An error occurred while importing the certificate into the
    /// certificate store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Importing {}", cert.fingerprint())]
    pub struct CertImportError {
        pub cert: Cert,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Importing revocation certificate{}",
            if let Some(issuer) = rev.get_issuers().into_iter().next() {
                Cow::Owned(format!(
                    " for {}",
                    issuer))
            } else {
                Cow::Borrowed("")
            })]
    pub struct RevocationImportError {
        pub rev: Signature,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Importing autocrypt message")]
    pub struct AutocryptImportError {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The autocrypt header's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Importing autocrypt gossip")]
    pub struct AutocryptGossipImportError {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// We tried to import an otherwise valid artifact into the
    /// certificate store, but failed.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(transparent)]
    pub enum ImportingError {
        CertImportError(CertImportError),
        RevocationImportError(RevocationImportError),
        AutocryptImportError(AutocryptImportError),
        AutocryptGossipImportError(AutocryptGossipImportError),
    }

    /// We failed to import something.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(transparent)]
    pub enum ImportError {
        /// An artifact is broken.
        BrokenArtifact(BrokenArtifact),

        /// No autocrypt header.
        ///
        /// The input appears to be an email, but it does not contain
        /// an autocrypt header.
        NoAutocryptHeader(NoAutocryptHeader),

        /// We tried to import an otherwise valid artifact into the
        /// certificate store, but failed.
        ImportingError(ImportingError),
    }

    /// We failed to parse the input.
    ///
    /// Note: If we were unable to parse an individual artifact, then
    /// we emit [`ImportError::BrokenArtifact`].
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parse error")]
    pub struct ParseError {
        #[source]
        pub error: Arc<anyhow::Error>,
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
        /// We failed to parse the input.
        ///
        /// Note: If we were unable to parse an individual artifact,
        /// then we emit [`ImportError::BrokenArtifact`].
        #[error(transparent)]
        ParseError(ParseError),

        #[error(transparent)]
        ImportError(ImportError),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to generating a searching the network for certificates.
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

    /// Information about a certificate.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Cert {
        pub cert: openpgp::Cert,
    }

    /// Information about an imported revocation certificate.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Revocation {
        pub rev: Signature,
    }

    /// Information about a certificate imported from an autocrypt
    /// message.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Autocrypt {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The autocrypt header's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
    }

    /// Information about a certificate imported from an autocrypt
    /// message.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct AutocryptGossip {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The sender header's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
        /// The certificate transported in the gossip header.
        pub gossip: Arc<openpgp::Cert>,
        /// The gossip header's attributes.
        pub gossip_attributes: Arc<Vec<autocrypt::Attribute>>,
    }

    /// A certificate, revocation, autocrypt, or an error.
    ///
    /// Used by [`Imported`].
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum Artifact {
        /// Information about a certificate.
        Cert(openpgp::Cert),

        /// Information about a revocation certificate.
        Revocation(Revocation),

        /// Information about a certificate from an autocrypt header.
        Autocrypt(Autocrypt),

        /// Information about a certificate from autocrypt gossip.
        AutocryptGossip(AutocryptGossip),
    }

    impl Artifact {
        /// If the artifact contains a `Cert`, returns it.
        ///
        /// This returns the certificate that is being merged into the
        /// certificate store.
        pub fn cert(&self) -> Option<&openpgp::Cert> {
            match self {
                Artifact::Cert(cert) => Some(cert),
                Artifact::Revocation(_rev) => None,
                Artifact::Autocrypt(ac) => Some(&ac.sender),
                Artifact::AutocryptGossip(ac) => Some(&ac.gossip),
            }
        }

        /// If this artifact is a revocation certificate, returns it.
        pub fn revocation(&self) -> Option<&Signature> {
            if let Artifact::Revocation(rev) = self {
                Some(&rev.rev)
            } else {
                None
            }
        }
    }

    /// We imported a certificate.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Imported {
        /// We imported the artifact.
        pub artifact: Artifact,

        /// The resulting certificate.
        ///
        /// The result after merging the artifact with any existing
        /// certificate in the certificate store.
        pub merged: openpgp::Cert,

        /// The certificate's provenance was recorded using the
        /// following intermediate CAs.
        pub recorded_provenance: Vec<Arc<openpgp::Cert>>,
    }

    /// Decryption status.
    ///
    /// This is only emitted when processing an autocrypt message.
    /// Autocrypt messages are encrypted.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct DecryptedAutocrypt {
        /// The sender.
        pub sender: Arc<openpgp::Cert>,
        /// The sender's attributes.
        pub sender_attributes: Arc<Vec<autocrypt::Attribute>>,
        /// The output of the decryption operation.
        pub decryption_output: Vec<decrypt::Output>,
        /// Whether the decryption was successful.
        pub decrypted: bool,
    }

    /// We failed to import a cert to the store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(transparent)]
    pub struct ImportingFailed {
        /// The related error.
        pub error: error::ImportError,
    }

    /// A report about the operation.
    ///
    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is imported or not.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Report {
        pub artifact_type: ArtifactType,

        /// Statistics.
        pub stats: ImportStats,
    }
}

/// The variants of this enum are the different types of output that
/// [`import`](Builder::import) emits.
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

    /// Emitted after the artifact being imported was successfully
    /// imported to the store.
    Imported(output::Imported),

    /// Emitted when a certificate can't be imported to the store.
    ///
    /// This is not considered an operational error, and processing is
    /// not normally aborted.
    ImportingFailed(output::ImportingFailed),

    /// Emitted after attempting to decrypt an autocrypt message.
    ///
    /// Autocrypt messages are encrypted.  To get at the autocrypt
    /// gossip, they need to be decrypted.
    ///
    /// This is emitted if decryption is successful or not.
    ///
    /// Any certifictes imported from the autocrypt message will also
    /// be reported via [`output::Imported`].  As such, you can
    /// usually ignore this.
    DecryptedAutocrypt(output::DecryptedAutocrypt),

    /// A report about the operation.
    ///
    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is imported or not.
    Report(output::Report),
}

/// The outcome of importing keys.
///
/// This is returned by [`Builder::import_keyring`],
/// [`Builder::import_certs`], [`Builder::import_cert`],
/// [`Builder::import_revocation`], and [`Builder::import_autocrypt`].
/// It contains information about the operation's outcome.  More
/// detailed information is available via the [`Stream`] interface.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Outcome {
    pub artifact_type: ArtifactType,

    /// Statistics.
    pub stats: ImportStats,

    /// The imported certificates.
    pub imported: Vec<output::Imported>,
    /// The import failures.
    pub importing_failed: Vec<output::ImportingFailed>,
}

impl Outcome {
    fn new(artifact_type: ArtifactType) -> Self {
        Outcome {
            artifact_type,
            imported: Vec::new(),
            importing_failed: Vec::new(),
            stats: Default::default(),
        }
    }

    fn to_report(&self) -> output::Report {
        output::Report {
            artifact_type: self.artifact_type.clone(),
            stats: self.stats.clone(),
        }
    }

    /// Returns whether all artifacts were imported.
    ///
    /// If one or more artifacts were not imported, returns one of the
    /// errors.
    ///
    /// For instance, when importing a keyring using
    /// [`Builder::import_keyring`], one of the certificates may be
    /// corrupted.  In this case, the other certificates are still
    /// imported, and `import_keyring` returns `Ok`.  This function
    /// allows you to determine if all certificates were imported.
    pub fn all_imported(&self) -> Result<()> {
        self.importing_failed
            .first()
            .map_or(Ok(()),
                    |failure| {
                        Err(failure.error.clone().into())
                    })
    }
}

/// The type of artifact that we imported (or tried to import).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactType {
    Keyring,
    Certs,
    Revocation,
    Autocrypt,
}

/// The certificate import parameters.
///
/// These parameters are used by [`import`](Builder::import).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    secret_keys: Vec<Cert>,
    session_keys: Vec<SessionKey>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the pre-loaded secret keys.
    ///
    /// See [`Builder::secret_keys`].
    pub fn secret_keys(&self) -> impl Iterator<Item=&Cert> {
        self.secret_keys.iter()
    }

    /// Returns the pre-loaded session keys.
    pub fn session_keys(&self) -> impl Iterator<Item=&SessionKey> {
        self.session_keys.iter()
    }
}

/// Owned parameters.
struct ParamsOnce<'stream> {
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Imports certificates.
///
/// A builder providing control over how to import certificates.
pub struct Builder<'sequoia, 'stream> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'stream>,
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia)
        -> Builder<'sequoia, 'stream>
    {
        Builder {
            params: Params {
                sequoia,
                secret_keys: Vec::new(),
                session_keys: Vec::new(),
            },
            params_once: ParamsOnce {
                stream: None,
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    stream_builder_impl!();

    /// Sets the secret keys to try when decrypting an autocrypt
    /// message.
    ///
    /// The secret keys are tried in addition to the key store, if it
    /// hasn't been disabled.
    ///
    /// Standards conformant autocrypt messages are always encrypted.
    /// To import certificates transported using [Autocrypt's gossip
    /// mechanism], it is necessary to decrypt the message.
    ///
    ///   [Autocrypt's gossip mechanism]: https://docs.autocrypt.org/level1.html#key-gossip
    ///
    /// Note: even if the autocrypt message can't be decrypted, any
    /// certificate found in the Autocrypt header is still imported.
    pub fn secret_keys(mut self, secret_keys: impl IntoIterator<Item=Cert>)
        -> Self
    {
        self.params.secret_keys = secret_keys.into_iter().collect();

        self
    }

    /// Sets session keys to try when decrypting an autocrypt message.
    ///
    /// The session keys are tried in addition to the key store, if
    /// it hasn't been disabled.
    ///
    /// Standards conformant autocrypt messages are always encrypted.
    /// To import certificates transported using [Autocrypt's gossip
    /// mechanism], it is necessary to decrypt the message.
    ///
    ///   [Autocrypt's gossip mechanism]: https://docs.autocrypt.org/level1.html#key-gossip
    ///
    /// Note: even if the autocrypt message can't be decrypted, any
    /// certificate found in the Autocrypt header is still imported.
    pub fn session_keys(mut self,
                        session_keys: impl IntoIterator<Item=SessionKey>)
        -> Self
    {
        self.params.session_keys = session_keys.into_iter().collect();

        self
    }

    /// Import certificates or revocation certificates.
    ///
    /// This function detects if `input` contains an OpenPGP keyring,
    /// a bare revocation certificate, or an email, and calls
    /// [`Builder::import_keyring`], [`Builder::import_revocation`], or
    /// [`Builder::import_autocrypt`], as appropriate.
    ///
    /// See those functions for a description of the return value.
    pub fn import<'a, P>(self,
                         input: impl std::io::Read + Send + Sync + 'a,
                         prompt: P)
        -> Result<Outcome, Error>
    where
        P: prompt::Prompt + 'a,
    {
        let Builder {
            params,
            mut params_once,
        } = self;

        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let mut input = buffered_reader::Generic::with_cookie(
            input, None, Cookie::default());

        if input.eof() {
            // Empty file.  Silently skip it.  Treat it like an empty
            // keyring.
            return Ok(Outcome::new(ArtifactType::Keyring));
        }

        enum Type {
            Signature,
            Keyring,
            Other,
        }

        // See if it is OpenPGP data.
        let dup = Dup::with_cookie(&mut input, Cookie::default());
        let mut typ = Type::Other;
        if let Ok(ppr) = PacketParser::from_buffered_reader(dup) {
            // See if it is a keyring, or a bare revocation
            // certificate.
            if let PacketParserResult::Some(ref pp) = ppr {
                if let Packet::Signature(sig) = &pp.packet {
                    typ = match sig.typ() {
                        SignatureType::KeyRevocation |
                        SignatureType::SubkeyRevocation |
                        SignatureType::CertificationRevocation =>
                        // Looks like a bare revocation.
                        Type::Signature,
                        _ => Type::Other,
                    };
                } else if pp.possible_keyring().is_ok() {
                    typ = Type::Keyring;
                } else {
                    // If we have a message, then it might
                    // actually be an email with autocrypt data.
                }
            }
        }

        let input = Box::new(input) as Box<dyn BufferedReader<Cookie> + 'a>;
        let (outcome, result) = match typ {
            Type::Keyring => {
                let mut outcome = Outcome::new(ArtifactType::Keyring);
                let result = Self::import_keyring_(
                    &params, &mut params_once, input, &mut outcome);
                (outcome, result)
            }
            Type::Signature => {
                let mut outcome = Outcome::new(ArtifactType::Revocation);
                let result = Self::import_revocation_(
                    &params, &mut params_once, input, &mut outcome);
                (outcome, result)
            }
            Type::Other => {
                let mut outcome = Outcome::new(ArtifactType::Autocrypt);
                let result = Self::import_autocrypt_(
                    &params, &mut params_once, input, &mut outcome, &prompt);
                (outcome, result)
            }
        };

        let mut stream = params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(())
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(&params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(&params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(&params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        stream.output(&params, Output::Report(outcome.to_report()))
            .map_err(|err| Error::StreamOutputError(err))?;

        result.map(|_| outcome)
    }

    /// Report that importing something failed.
    fn report_failure<'a>(params: &Params,
                          params_once: &mut ParamsOnce,
                          err: error::ImportError,
                          outcome: &mut Outcome)
        -> Result<(), Error>
    {
        let ParamsOnce {
            stream,
        } = params_once;

        outcome.importing_failed.push(output::ImportingFailed {
            error: err.clone(),
        });

        outcome.stats.certs.inc_errors();

        stream.output(
            params,
            Output::ImportingFailed(
                output::ImportingFailed {
                    error: err
                }))
            .map_err(|err| Error::StreamOutputError(err))?;

        Ok(())
    }

    /// Imports the certs and reports on the individual certs.
    fn import_and_report<'a>(params: &Params,
                             params_once: &mut ParamsOnce,
                             cert: openpgp::Cert,
                             artifact: output::Artifact,
                             provenance: Vec<Arc<Cert>>,
                             outcome: &mut Outcome)
        -> Result<bool, Error>
    {
        let Params {
            sequoia,
            secret_keys: _,
            session_keys: _,
        } = params;
        let ParamsOnce {
            stream,
        } = params_once;

        let cert_store = match sequoia.cert_store_or_else() {
            Ok(cert_store) => cert_store,
            Err(err) => {
                return Err(Error::SystemError(err));
            }
        };

        let cert = Arc::new(LazyCert::from(cert));
        match cert_store.update_by(cert.clone(), &mut outcome.stats) {
            Err(err) => {
                Self::report_failure(
                    params, params_once,
                    error::ImportError::ImportingError(
                        error::ImportingError::CertImportError(
                            error::CertImportError {
                                // Extract the cert that we just
                                // wrapped.
                                cert: Arc::unwrap_or_clone(cert)
                                    .into_cert()
                                    .expect("have a cert"),
                                error: err.into(),
                            })),
                    outcome)?;

                Ok(false)
            }
            Ok(merged) => {
                let merged = Arc::unwrap_or_clone(merged)
                    .into_cert().expect("is a cert");

                let imported = output::Imported {
                    artifact,
                    merged,
                    recorded_provenance: provenance
                        .iter()
                        .map(|ca| Arc::clone(&ca))
                        .collect(),
                };

                outcome.imported.push(imported.clone());

                stream.output(params, Output::Imported(imported))
                    .map_err(|err| Error::StreamOutputError(err))?;

                Ok(true)
            }
        }
    }

    /// Imports certificates from an OpenPGP keyring.
    ///
    /// This function imports certificates from an OpenPGP keyring.  A
    /// keyring consists of zero or more certificates.  It may be
    /// binary encoded or encoded using ASCII armor.
    ///
    /// This function returns an error if the certificate store is
    /// disabled.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring.  (Note: an empty file is consider a valid keyring.)
    ///
    /// Recoverable errors, such as failing to import a certificate
    /// into the certificate store, or a certificate being corrupted,
    /// do not cause this function to return an error.  These errors
    /// are reported using [`Output::ImportingFailed`].  Parsing is
    /// not aborted.  An example of a recoverable error is a keyring
    /// that contains two valid certificates and a corrupted
    /// certificate.  Unless the corrupted certificate is at the start
    /// of the file and is so corrupted that the input is not
    /// recognizable as a keyring, this function will not return an
    /// error; it will import the other two certificates, and emit
    /// [`Output::ImportingFailed`] for the corrupted certificate.
    ///
    /// This function does not return an error if the keyring is
    /// empty.
    pub fn import_keyring<'a>(mut self,
                              source: impl std::io::Read + Send + Sync + 'a)
        -> Result<Outcome, Error>
    {
        let Builder {
            ref params,
            ref mut params_once,
        } = self;

        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let mut outcome = Outcome::new(ArtifactType::Keyring);

        let result = Self::import_keyring_(
            params, params_once, source, &mut outcome);

        let report = outcome.to_report();

        let stream = &mut params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        stream.output(params, Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Imports certs encoded as OpenPGP keyring.
    fn import_keyring_<'a>(params: &Params,
                           params_once: &mut ParamsOnce,
                           source: Box<dyn BufferedReader<Cookie> + 'a>,
                           outcome: &mut Outcome)
        -> Result<(), Error>
    {
        let raw_certs = match RawCertParser::from_buffered_reader(source) {
            Ok(raw_certs) => raw_certs,
            Err(err) => {
                return Err(Error::OperationalError(
                    error::OperationalError::ParseError(
                        error::ParseError {
                            error: err.into(),
                        })));
            }
        };

        for raw_cert in raw_certs {
            let cert = match raw_cert {
                Err(err) => {
                    Self::report_failure(
                        params, params_once,
                        error::ImportError::BrokenArtifact(
                            error::BrokenArtifact::BrokenCert(
                                error::BrokenCert {
                                    cert: None,
                                    error: err.into(),
                                })),
                        outcome)?;
                    continue;
                }
                Ok(rawcert) => {
                    let lc = LazyCert::from(rawcert);
                    match lc.to_cert().cloned() {
                        Ok(cert) => cert,
                        Err(err) => {
                            Self::report_failure(
                                params, params_once,
                                error::ImportError::BrokenArtifact(
                                    error::BrokenArtifact::BrokenCert(
                                        error::BrokenCert {
                                            cert: Some(lc.into_raw_cert()
                                                .expect("have a rawcert")
                                                .into_owned()),
                                            error: err.into(),
                                        })),
                                outcome)?;
                            continue;
                        }
                    }
                }
            };

            Self::import_and_report(
                params, params_once,
                cert.clone(),
                output::Artifact::Cert(cert),
                Vec::new(), // No provenance.
                outcome)?;
        }

        Ok(())
    }

    /// Imports certificates.
    ///
    /// This function returns an error if the certificate store is
    /// disabled.
    ///
    /// Recoverable errors, such as failing to import a certificate
    /// into the certificate store, do not cause this function to
    /// return an error.  These errors are reported using
    /// [`Output::ImportingFailed`].  Parsing is not aborted.  Use
    /// [`Outcome::all_imported`] to check if all certificates were
    /// successfully imported.
    pub fn import_certs<I>(mut self, certs: I) -> Result<Outcome, Error>
    where
        I: IntoIterator<Item=Cert>,
    {
        let Builder {
            ref params,
            ref mut params_once,
        } = self;

        let mut certs = certs.into_iter();

        let mut outcome = Outcome::new(ArtifactType::Certs);

        let result = Self::import_certs_(
            params, params_once, &mut certs, &mut outcome);

        let report = outcome.to_report();

        let stream = &mut params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        stream.output(params, Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    fn import_certs_(params: &Params, params_once: &mut ParamsOnce,
                     certs: &mut dyn Iterator<Item=Cert>,
                     outcome: &mut Outcome)
        -> Result<(), Error>
    {
        for cert in certs.into_iter() {
            Self::import_and_report(
                params, params_once,
                cert.clone(),
                output::Artifact::Cert(cert),
                Vec::new(), // No provenance.
                outcome)?;
        }

        Ok(())
    }

    /// Imports a certificate.
    ///
    /// This is similar to [`Builder::import_certs`], but it only
    /// imports a single certificate, and it turns certificate import
    /// errors, which are only reported via the stream interface, into
    /// hard errors that are returned directly.
    pub fn import_cert(mut self, cert: Cert) -> Result<Outcome, Error>
    {
        let Builder {
            ref params,
            ref mut params_once,
        } = self;

        let mut outcome = Outcome::new(ArtifactType::Certs);

        let result = Self::import_and_report(
            params, params_once,
            cert.clone(),
            output::Artifact::Cert(cert),
            Vec::new(), // No provenance.
            &mut outcome);

        // Turn a soft error into a hard error.
        let result = match result {
            Ok(_) => {
                outcome.importing_failed
                    .first()
                    .map_or(Ok(()),
                            |failure| {
                                Err(Error::OperationalError(
                                    error::OperationalError::ImportError(
                                        failure.error.clone())))
                            })
            },
            Err(err) => Err(err),
        };

        let report = outcome.to_report();

        let stream = &mut params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        stream.output(params, Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Imports a bare revocation certificate.
    ///
    /// A bare revocation certificate is a certificate revocation that
    /// is not bundled with the certificate.  A bare revocation
    /// certificate can only be imported if the certificate is already
    /// present in the certificate store (or specified using
    /// [`SequoiaBuilder::add_keyring`](crate::SequoiaBuilder::add_keyring)
    /// in which case the certificate is also imported into the
    /// certificate store).
    ///
    /// This function emits [`error::ImportError`] and returns an
    /// error if the input does not contain exactly one valid
    /// revocation certificate.  This function also returns an error
    /// if the revoked certificate is not available.
    ///
    /// Note: if the input contains multiple ASCII-armored blocks,
    /// only the first one is considered.
    pub fn import_revocation(
        mut self,
        source: impl std::io::Read + Send + Sync)
        -> Result<Outcome, Error>
    {
        let Builder {
            ref params,
            ref mut params_once,
        } = self;

        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let mut outcome = Outcome::new(ArtifactType::Revocation);

        let result = Self::import_revocation_(
            params, params_once, source, &mut outcome);

        let report = outcome.to_report();

        let stream = &mut params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        params_once.stream.output(
            &params,
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Imports a bare revocation certificate.
    fn import_revocation_<'a>(
        params: &Params,
        params_once: &mut ParamsOnce,
        source: Box<dyn BufferedReader<Cookie> + 'a>,
        outcome: &mut Outcome)
        -> Result<(), Error>
    {
        let ppr = match PacketParser::from_buffered_reader(source) {
            Err(err) => {
                return Err(Error::OperationalError(
                    error::OperationalError::ParseError(
                        error::ParseError {
                            error: err.into(),
                        })));
            }
            Ok(ppr) => ppr,
        };
        let sig = if let PacketParserResult::Some(pp) = ppr {
            let (packet, next_ppr) = match pp.next() {
                Err(err) => {
                    return Err(Error::OperationalError(
                        error::OperationalError::ParseError(
                            error::ParseError {
                                error: err.into(),
                            })));
                }
                Ok(ppr) => ppr,
            };

            let sig = if let Packet::Signature(sig) = packet {
                sig
            } else {
                let err = error::ImportError::BrokenArtifact(
                    error::BrokenArtifact::BrokenRevocation(
                        error::BrokenRevocation {
                            packet: packet.clone(),
                            error: Arc::new(anyhow::anyhow!(
                                "Not a revocation certificate: got a {}",
                                packet.tag())),
                        }));

                Self::report_failure(
                    params, params_once, err.clone(), outcome)?;

                return Err(Error::OperationalError(
                    error::OperationalError::ImportError(err)));
            };

            if let PacketParserResult::Some(_) = next_ppr {
                let err = error::ImportError::BrokenArtifact(
                    error::BrokenArtifact::BrokenRevocation(
                        error::BrokenRevocation {
                            packet: sig.clone().into(),
                            error: Arc::new(anyhow::anyhow!(
                                "Not a revocation certificate: \
                                 got more than one packet")),
                        }));

                Self::report_failure(
                    params, params_once, err.clone(), outcome)?;

                return Err(Error::OperationalError(
                    error::OperationalError::ImportError(err)));
            }

            sig
        } else {
            return Err(Error::OperationalError(
                error::OperationalError::ParseError(
                    error::ParseError {
                        error: Arc::new(anyhow::anyhow!(
                            "Unnexpected end of file")),
                    })));
        };

        if sig.typ() != SignatureType::KeyRevocation {
            let typ = sig.typ();
            let err = error::ImportError::BrokenArtifact(
                error::BrokenArtifact::BrokenRevocation(
                    error::BrokenRevocation {
                        packet: sig.into(),
                        error: Arc::new(anyhow::anyhow!(
                            "Not a revocation certificate: got a {} signature",
                            typ)),
                    }));

            Self::report_failure(
                params, params_once, err.clone(), outcome)?;

            return Err(Error::OperationalError(
                error::OperationalError::ImportError(err)));
        }

        let issuers = sig.get_issuers();
        let mut missing = Vec::new();
        let mut bad = Vec::new();
        for issuer in issuers.iter() {
            let certs = if let Ok(certs) = params.sequoia.lookup()
                .lookup(issuer)
            {
                certs
            } else {
                missing.push(issuer);
                continue;
            };

            for cert in certs.into_iter() {
                if let Ok(_) = sig.clone().verify_primary_key_revocation(
                    cert.primary_key().key(),
                    cert.primary_key().key())
                {
                    let cert = cert.insert_packets(sig.clone())
                        // This should not fail.
                        .map_err(|err| {
                            Error::OperationalError(
                                error::OperationalError::ImportError(
                                    error::ImportError::BrokenArtifact(
                                        error::BrokenArtifact::BrokenRevocation(
                                            error::BrokenRevocation {
                                                packet: sig.clone().into(),
                                                error: Arc::new(err),
                                            }))))
                        })?.0;

                    let artifact = output::Artifact::Revocation(
                        output::Revocation {
                            rev: sig,
                        });

                    Self::import_and_report(
                        params, params_once,
                        cert,
                        artifact,
                        vec![], // No provenance.
                        outcome)?;

                    return Ok(());
                } else {
                    bad.push(issuer);
                }
            }
        }

        let err = if let Some(&bad) = bad.first() {
            let err = error::ImportError::ImportingError(
                error::ImportingError::RevocationImportError(
                    error::RevocationImportError {
                        rev: sig,
                        error: Arc::new(anyhow::anyhow!(
                            "Appears to be a revocation for {}, \
                             but the revocation certificate is not valid \
                             for that certificate",
                            bad)),
                    }));
            Self::report_failure(
                params, params_once, err.clone(), outcome)?;

            err
        } else if ! missing.is_empty() {
            // Dedup issuers.  If we have a key ID that aliases a
            // fingerprint, only keep the fingerprint.
            let (keyids, fingerprints): (Vec<_>, _)
                = missing.into_iter().partition(|kh| {
                    match kh {
                        KeyHandle::KeyID(_) => true,
                        KeyHandle::Fingerprint(_) => false,
                    }
                });

            let fingerprints_as_keyids: BTreeSet<KeyID>
                = BTreeSet::from_iter(fingerprints.iter().map(|fpr| {
                    KeyID::from(*fpr)
                }));

            let keyids: Vec<&KeyHandle> = keyids
                .into_iter()
                .filter(|keyid| {
                    ! fingerprints_as_keyids.contains(&KeyID::from(*keyid))
                })
                .collect();

            let missing = fingerprints.into_iter()
                .chain(keyids.into_iter())
                .collect::<Vec<&KeyHandle>>();

            let err = error::ImportError::ImportingError(
                error::ImportingError::RevocationImportError(
                    error::RevocationImportError {
                        rev: sig,
                        error: Arc::new(anyhow::anyhow!(
                            "Appears to be a revocation for {}, \
                             but no certificate is available",
                            missing.iter()
                                .map(|issuer| issuer.to_string())
                                .collect::<Vec<_>>()
                                .join(" or "))),
                    }));

            Self::report_failure(
                params, params_once, err.clone(), outcome)?;

            err
        } else {
            let err = error::ImportError::BrokenArtifact(
                error::BrokenArtifact::BrokenRevocation(
                    error::BrokenRevocation {
                        packet: sig.into(),
                        error: Arc::new(anyhow::anyhow!(
                            "Revocation is malformed, missing issuer \
                             packet")),
                    }));

            Self::report_failure(
                params, params_once, err.clone(), outcome)?;

            err
        };

        Err(Error::OperationalError(
            error::OperationalError::ImportError(err)))
    }

    /// Imports certificates from autocrypt headers.
    ///
    /// Autocrypt headers are email headers that a sender can set to
    /// communicate to the receiver what the sender's OpenPGP
    /// certificate is.  If the message is sent to multiple parties,
    /// the message may also include so-called gossip, which are the
    /// certificates that the sender allegedly` used for each of the
    /// recipients.
    ///
    /// This function imports certificates found in any autocrypt
    /// headers.  If the email headers include an autocrypt header,
    /// this function will also attempt to decrypt message body and
    /// verify the signature.  If the body was encrypted and the
    /// signature is valid, it will import any gossip headers.  Note:
    /// this function will not try to decrypt the message body if
    /// there are no autocrypt headers.
    ///
    /// This function processes a single email message.  If passed a
    /// mailbox, it will only process the first message.
    ///
    /// This function emits [`Output::ImportingFailed`] and returns an
    /// error if the input is not an email.  If the input is an email,
    /// and does not contain an autocrypt header, this function emits
    /// [`Output::ImportingFailed`], but it does not cause the
    /// function to return an error.  Similarly, if the message can't
    /// be decrypted or the signature can't be verified, the error is
    /// propagated using [`Output::DecryptedAutocrypt`], but it does
    /// not cause the function to return an error.
    pub fn import_autocrypt<'a, P>(
        mut self,
        source: impl std::io::Read + Send + Sync,
        prompt: P)
        -> Result<Outcome, Error>
    where
        P: prompt::Prompt + 'a,
    {
        let Builder {
            ref params,
            ref mut params_once,
        } = self;

        // XXX: There's a chance that input is already some
        // kind of BufferedReader.  We could try downcasting
        // to see if we could recover it.
        let source = buffered_reader::Generic::with_cookie(
            source, None, Cookie::default());
        let source = Box::new(source) as Box<dyn BufferedReader<Cookie>>;

        let mut outcome = Outcome::new(ArtifactType::Autocrypt);

        let result = Self::import_autocrypt_(
            params, params_once, source, &mut outcome, &prompt);

        let report = outcome.to_report();

        let stream = &mut params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        params_once.stream.output(&params, Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Imports certificates from autocrypt headers.
    fn import_autocrypt_<'a>(params: &Params,
                             params_once: &mut ParamsOnce,
                             mut source: Box<dyn BufferedReader<Cookie> + 'a>,
                             outcome: &mut Outcome,
                             prompt: &(dyn prompt::Prompt + 'a))
        -> Result<(), Error>
    {
        let Params {
            sequoia,
            ref secret_keys,
            ref session_keys,
        } = params;

        // First, get the Autocrypt headers from the outside.
        let mut ac = || -> Result<_> {
            let mut dup = Dup::with_cookie(&mut source, Cookie::default());
            let ac = autocrypt::AutocryptHeaders::from_reader(&mut dup)?;
            let from = UserID::from(
                ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
                    .as_str());
            let from_addr = from.email()?.ok_or(
                anyhow::anyhow!("no email address in From: header"))?
                .to_string();
            Ok((ac, from_addr))
        };
        let (ac, from_addr) = match ac() {
            Err(err) => {
                let err = error::ImportError::BrokenArtifact(
                    error::BrokenArtifact::BrokenAutocrypt(
                        error::BrokenAutocrypt {
                            error: Arc::new(err.context("Not an email")),
                        }));

                Self::report_failure(
                    params, params_once, err.clone(), outcome)?;
                return Err(Error::OperationalError(
                    error::OperationalError::ImportError(err)));
            }
            Ok((ac, from_addr)) => (ac, from_addr),
        };

        // Get the autocrypt shadow CA.  Be careful to do it at most
        // once.
        let mut autocrypt_ca: Option<Option<Arc<LazyCert>>> = None;
        let mut autocrypt_ca = || {
            if let Some(autocrypt_ca) = autocrypt_ca.as_ref() {
                if let Some(autocrypt_ca) = autocrypt_ca {
                    Some(Arc::clone(autocrypt_ca))
                } else {
                    None
                }
            } else {
                if let Ok(ca) = sequoia.shadow_ca_autocrypt()
                    .map(|ca| ca.into_cert())
                {
                    autocrypt_ca = Some(Some(Arc::clone(&ca)));
                    Some(ca)
                } else {
                    autocrypt_ca = Some(None);
                    None
                }
            }
        };

        use autocrypt::AutocryptHeaderType::*;
        let mut sender_attributes = None;

        for h in ac.headers.into_iter().filter(|h| h.header_type == Sender) {
            if let Some(addr) = h.attributes.iter()
                .find_map(|a| {
                    if &a.key == "addr"
                        && a.value.to_lowercase() == from_addr.to_lowercase()
                    {
                        Some(a.value.clone())
                    } else {
                        None
                    }
                })
            {
                if let Some(cert) = h.key {
                    let (cert, ca) = if let Some(ca) = autocrypt_ca() {
                        let cert = certify_downloads(
                            sequoia, false, ca.clone(),
                            vec![cert], Some(&addr[..]),
                            prompt);
                        (cert.into_iter().next().expect("have cert"),
                         Some(ca))
                    } else {
                        (cert, None)
                    };

                    let sender = Arc::new(cert.clone());
                    let attributes = Arc::new(h.attributes);
                    sender_attributes
                        = Some((Arc::clone(&sender),
                                Arc::clone(&attributes)));

                    Self::import_and_report(
                        params, params_once,
                        cert,
                        output::Artifact::Autocrypt(
                            output::Autocrypt {
                                sender,
                                sender_attributes: attributes,
                            }),
                        if let Some(ca) = ca {
                            if let Ok(ca)
                                = Arc::unwrap_or_clone(ca).into_cert()
                            {
                                vec![ Arc::new(ca) ]
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        },
                        outcome)?;
                }
            }
        }

        // If there is no Autocrypt header, don't bother looking for
        // gossip.
        let sender_attributes = if let Some((sender, attributes))
            = sender_attributes
        {
            (sender, attributes)
        } else {
            Self::report_failure(
                params, params_once,
                error::ImportError::NoAutocryptHeader(
                    error::NoAutocryptHeader {
                    }),
                outcome)?;
            return Ok(());
        };

        let dup = Dup::with_cookie(source, Cookie::default());

        let mut decryption_output = Vec::new();
        let mut plaintext = Vec::new();
        let decryption_result = sequoia.decrypt()
            .stream(&mut decryption_output)
            .add_designated_signer((*sender_attributes.0).clone())
            .add_secret_keys(secret_keys.clone())
            .add_session_keys(session_keys.clone())
            .signatures(1)
            .decrypt(
                dup,
                &mut plaintext,
                prompt);

        let decrypted = decryption_output.iter().any(|o| {
            matches!(o, decrypt::Output::Decrypted(_))
        });

        params_once.stream.output(
            params,
            Output::DecryptedAutocrypt(output::DecryptedAutocrypt {
                sender: Arc::clone(&sender_attributes.0),
                sender_attributes: Arc::clone(&sender_attributes.1),
                decryption_output,
                decrypted,
            }))
            .map_err(|err| Error::StreamOutputError(err))?;

        if let Err(_err) = decryption_result {
            // The decryption failed, but we imported the Autocrypt
            // header, which is fine.
            return Ok(());
        }

        let ac = match autocrypt::AutocryptHeaders::from_bytes(&plaintext) {
            Err(err) => {
                let err = error::ImportError::BrokenArtifact(
                    error::BrokenArtifact::BrokenAutocrypt(
                        error::BrokenAutocrypt {
                            error: Arc::new(err),
                        }));

                Self::report_failure(
                    params, params_once, err.clone(), outcome)?;

                return Err(Error::OperationalError(
                    error::OperationalError::ImportError(err)));
            }
            Ok(ac) => {
                ac
            }
        };

        // We know there has been one good signature from the sender.  Now
        // check that the message was encrypted.  Note: it doesn't have to
        // be encrypted for the purpose of the certification, but
        // Autocrypt requires messages to be signed and encrypted.
        if ! decrypted {
            return Ok(());
        }

        for h in ac.headers.into_iter().filter(|h| h.header_type == Gossip) {
            if let Some(_addr) = h.attributes.iter()
                .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
            {
                if let Some(cert) = h.key {
                    Self::import_and_report(
                        params, params_once,
                        cert.clone(),
                        output::Artifact::AutocryptGossip(
                            output::AutocryptGossip {
                                sender: Arc::clone(&sender_attributes.0),
                                sender_attributes:
                                    Arc::clone(&sender_attributes.1),
                                gossip: Arc::new(cert),
                                gossip_attributes: Arc::new(h.attributes),
                            }),
                        vec![], // No provenance information.
                        outcome)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use openpgp::cert::CertBuilder;
    use openpgp::serialize::Serialize;

    fn check(artifact_type: ArtifactType,
             output: Vec<Output>, result: Result<Outcome, Error>,
             imports_expected: usize, errors_expected: usize)
    {
        let mut saw_error = None;
        let mut saw_report = false;
        let mut imports_count = 0;
        let mut errors_count = 0;

        eprintln!("Start of import");
        for o in output.iter() {
            match o {
                Output::OperationalError(err) => {
                    eprintln!("- Operational Error: {:?}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }
                Output::SystemError(err) => {
                    eprintln!("- System Error: {:?}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }
                Output::ArgumentError(err) => {
                    eprintln!("- Argument Error: {:?}", err);
                    assert!(saw_error.is_none());
                    assert!(! saw_report);

                    saw_error = Some(err.to_string());
                }

                Output::Imported(_) => {
                    eprintln!("- Imported");
                    assert!(! saw_report);
                    assert!(saw_error.is_none());
                    imports_count += 1;
                }
                Output::ImportingFailed(
                    output::ImportingFailed {
                        error: failure
                    }) =>
                {
                    eprintln!("- ImportingFailed: {}", failure);
                    assert!(! saw_report);
                    assert!(saw_error.is_none());
                    errors_count += 1;
                }
                Output::DecryptedAutocrypt(_) => {
                    eprintln!("- DecryptedAutocrypt");
                    assert!(! saw_report);
                    assert!(saw_error.is_none());
                }
                Output::Report(report) => {
                    eprintln!("- Report");
                    assert!(! saw_report);
                    saw_report = true;

                    eprintln!("  Imported {}, updated {}, \
                               {} unchanged, {} errors.",
                              report.stats.certs.new_certs(),
                              report.stats.certs.updated_certs(),
                              report.stats.certs.unchanged_certs(),
                              report.stats.certs.errors());

                    let stats_imported = report.stats.certs.new_certs()
                        + report.stats.certs.unchanged_certs()
                        + report.stats.certs.updated_certs();
                    assert_eq!(stats_imported,
                               imports_count,
                               "imports: stats: {}; count: {}",
                               stats_imported, imports_count);
                    assert_eq!(report.stats.certs.errors(),
                               errors_count,
                               "errors: stats {}; count: {}",
                               report.stats.certs.errors(), errors_count);

                    if imports_expected != imports_count
                        || errors_expected != errors_count
                    {
                        panic!("Imported {}, expected {}; \
                                {} errors, expected: {}",
                               imports_count, imports_expected,
                               errors_count, errors_expected);
                    }
                }
            }
        }
        eprintln!("End of import");

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

                assert_eq!(imports_expected, 0, "expected imports vs returned");
                assert_eq!(imports_count, 0, "counted imports vs expected");
                if artifact_type == ArtifactType::Keyring
                    || artifact_type == ArtifactType::Certs
                {
                    assert_eq!(errors_expected, 0, "expected errors vs returned");
                    assert_eq!(errors_count, 0, "counted errors vs expected");
                }

            }
            (Ok(outcome), None) => {
                assert_eq!(imports_expected, outcome.imported.len(),
                           "imports expected vs outcome imported");
                assert_eq!(errors_expected, outcome.importing_failed.len(),
                           "errors expected vs outcome errors");

                assert_eq!(artifact_type, outcome.artifact_type);
            }
        }
    }

    #[test]
    fn keyring() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(b""));

        assert!(result.is_ok());
        check(ArtifactType::Keyring, output, result, 0, 0);

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input));

        assert!(result.is_err());
        check(ArtifactType::Keyring, output, result, 0, 0);

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        // Import Alice's certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Keyring, output, result, 1, 0);

        // Import Alice's and Bob's certificates.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        bob.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Keyring, output, result, 2, 0);

        // Add some junk in between and try again.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        write!(&mut input, "foobar").unwrap();
        bob.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Keyring, output, result, 2, 1);
    }

    #[test]
    fn import_keyring_no_cert_store() {
        // Disable the certificate store.
        let sq = Sequoia::builder()
            .ephemeral().unwrap()
            .cert_store_path(crate::StateDirectory::None)
            .build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();

        // Import Alice's key.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(ArtifactType::Keyring, output, result, 0, 0);
    }

    #[test]
    fn certs() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs(Vec::new());
        if let Err(err) = result.as_ref() {
            panic!("Can import zero certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 0, 0);

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs([]);
        if let Err(err) = result.as_ref() {
            panic!("Can import zero certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 0, 0);

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs(std::iter::empty());
        if let Err(err) = result.as_ref() {
            panic!("Can import zero certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 0, 0);

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs(vec![alice.clone(), bob.clone()]);
        if let Err(err) = result.as_ref() {
            panic!("Can import two certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 2, 0);

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs([alice.clone(), bob.clone()]);
        if let Err(err) = result.as_ref() {
            panic!("Can import two certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 2, 0);

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_certs([alice.clone(), bob.clone()].iter().cloned());
        if let Err(err) = result.as_ref() {
            panic!("Can import two certificates: {}", err);
        }
        check(ArtifactType::Certs, output, result, 2, 0);
    }

    #[test]
    fn cert() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_cert(alice.clone());
        if let Err(err) = result.as_ref() {
            panic!("Can import a certificate: {}", err);
        }
        check(ArtifactType::Certs, output, result, 1, 0);

        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_cert(bob.clone());
        if let Err(err) = result.as_ref() {
            panic!("Can import a certificate: {}", err);
        }
        check(ArtifactType::Certs, output, result, 1, 0);

        // Import Alice's certificate a second time.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_cert(alice.clone());
        if let Err(err) = result.as_ref() {
            panic!("Can import a certificate: {}", err);
        }
        check(ArtifactType::Certs, output, result, 1, 0);
    }

    #[test]
    fn revocation() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(b""));

        assert!(result.is_err());
        check(ArtifactType::Revocation, output, result, 0, 0);

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input));

        assert!(result.is_err());
        check(ArtifactType::Revocation, output, result, 0, 0);

        let (alice, alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let alice_rev = Packet::from(alice_rev);
        let (_bob, bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();
        let bob_rev = Packet::from(bob_rev);

        // Try to import a bare revocation certificate, but fail
        // because the certificate is not imported.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(ArtifactType::Revocation, output, result, 0, 1);

        // Try to import two bare revocation certificates, which is
        // not allowed.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        bob_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(ArtifactType::Revocation, output, result, 0, 1);

        // Import Alice's certificate as a revocation certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(ArtifactType::Revocation, output, result, 0, 1);

        // Import Alice's certificate.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Keyring, output, result, 1, 0);

        // Import Alice's bare revocation certificate.
        let mut input = Vec::new();
        alice_rev.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Revocation, output, result, 1, 0);

        // Import it a second time.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_revocation(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(ArtifactType::Revocation, output, result, 1, 0);
    }

    #[test]
    fn autocrypt() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_autocrypt(
                std::io::Cursor::new(b""),
                prompt::Cancel::new());

        assert!(result.is_err());
        check(ArtifactType::Autocrypt, output, result, 0, 1);

        // Not an email.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_autocrypt(
                std::io::Cursor::new(b"not an email"),
                prompt::Cancel::new());

        assert!(result.is_err());
        check(ArtifactType::Autocrypt, output, result, 0, 1);

        // Looks a bit like an email, but no autocrypt header.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_autocrypt(
                std::io::Cursor::new(b"\
From: Alice <alice@example.org>
To: Bob <bob@example.org>

Hi!
"),
                prompt::Cancel::new());

        if let Err(err) = result.as_ref() {
            panic!("Failed to import certificates: {:?}", err);
        }
        check(ArtifactType::Autocrypt, output, result, 0, 1);

        // Autocrypt header.
        let mut output = Vec::new();
        let result = sq.cert_import()
            .stream(&mut output)
            .import_autocrypt(
                std::io::Cursor::new(b"\
Date: Sat, 7 Dec 2024 12:38:37 +0100
From: Patrick Brunschwig <patrick@enigmail.net>
Autocrypt: addr=patrick@enigmail.net; prefer-encrypt=mutual; keydata=
 xjMEZmQU3RYJKwYBBAHaRw8BAQdA4/l57O4gUweBOgVW9S1yutfgMHF1iURviG1jcb+/3z7N
 KVBhdHJpY2sgQnJ1bnNjaHdpZyA8cGF0cmlja0BlbmlnbWFpbC5uZXQ+wpIEEBYKAEQFgmZk
 FN0FiQlmAYAECwkHCAmQoPyuK0NGVXYDFQgKBBYAAgECGQECmwMCHgEWIQRk9N12hm6miW5K
 hpug/K4rQ0ZVdgAAM+UA/1brtqyREKa65BRMYaxiySCYTPRObIkOWAWBKjUt/N/7APwNhkV4
 MzcNdCU1qGJWEJGPQCY8tF3xI7H+Bqg12UuRBM44BGZkFN0SCisGAQQBl1UBBQEBB0B1cnik
 tl07/9iRJLfy4AzCxM2sxByke0TXivmjKxodXQMBCAfCfgQYFgoAMAWCZmQU3QWJCWYBgAmQ
 oPyuK0NGVXYCmwwWIQRk9N12hm6miW5Khpug/K4rQ0ZVdgAAYksBAIUetCBOgiegbKKBPhah
 oONLAjAqbLlkGZZW54HaVTiUAQDbiHnmrXQ6dWpdMfjUeO9xvSgZ2b2Yup7vE4C4k/b7DA==

Hi!
"),
                prompt::Cancel::new());

        if let Err(err) = result.as_ref() {
            panic!("Failed to import certificates: {:?}", err);
        }
        check(ArtifactType::Autocrypt, output, result, 1, 0);
    }
}
