//! Functionality for creating digital signature over data.
//!
//! This module contains functionality related to creating digital
//! signatures.
//!
//! # Examples
//!
//! Create an inline-signed message:
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::sign;
//! # use sequoia::openpgp::cert::CertBuilder;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let (cert, _) =
//! #     CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! #
//! // A stateless Sequoia instance.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // The message to sign.
//! let message = b"I owe you";
//!
//! let mut signed_message = Vec::new();
//! sequoia.sign()
//!     // Create an inline-signed message where the signature and the
//!     // data are combined in the output.
//!     .inline()
//!     .add_signer(cert.clone())
//!     .sign(
//!         std::io::Cursor::new(message),
//!         &mut signed_message,
//!         // Fail if the signing key is password protected.
//!         sequoia::prompt::Cancel::new())?;
//! #
//! # sequoia.verify()
//! #     .add_designated_signers(vec![ cert ])
//! #     .inline_signature(
//! #         std::io::Cursor::new(signed_message),
//! #         std::io::empty())
//! #     .expect("Valid signature");
//! # Ok(()) }
//! ```
use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::armor;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::parse::buffered_reader::BufferedReader;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Signer;
use openpgp::types::SignatureType;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::Writer;
use crate::cert::CertError;
use crate::prompt;
use crate::types::HashMode;

// Stream trait.
stream!{}

pub mod error {
    use super::*;

    /// No signing keys were specified
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("No signing keys specified")]
    pub struct NoSigningKeysSpecified {
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        NoSigningKeysSpecified(NoSigningKeysSpecified),
    }

    /// The detached signature is invalid.
    ///
    /// If the reason is because an unexpected packet was encountered,
    /// then `unexpected_tag` contains the packet's tag.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Invalid detached signature{}",
            if let Some(tag) = .unexpected_tag {
                Cow::Owned(
                    format!(": {} in detached signature", tag))
            } else {
                Cow::Borrowed("")
            })]
    pub struct InvalidDetachedSignature {
        pub unexpected_tag: Option<Tag>
    }

    /// The OpenPGP message is malformed.
    ///
    /// Returned by [`Builder::append`] when the message is malformed,
    /// e.g., it encounters packets that do not belong in an [OpenPGP
    /// Message].
    ///
    ///   [OpenPGP Message]: https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Malformed OpenPGP message")]
    pub struct MalformedOpenPGPMessage {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// Can't append a signature to encrypted data.
    ///
    /// Returned by [`Builder::append`] when trying to append a
    /// signature to encrypted data.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Signing encrypted data is not implemented")]
    pub struct EncryptedData {
    }

    /// Can't append a signature to compressed data.
    ///
    /// Returned by [`Builder::append`] when trying to append a
    /// signature to compressed data.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Signing a compress-then-sign message is not implemented")]
    pub struct CompressedData {
    }

    /// Signing failed.
    ///
    /// Provides some information about why signing was not possible.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{}",
            if let Some(err) = .unusable_certs.first() {
                err.to_string()
            } else {
                format!("Certificate can't be used for signing")
            })]
    pub struct SigningFailed {
        /// The certificates that could not be used to generate a
        /// signature.
        ///
        /// This list is not necessarily exhaustive.  That is, if you
        /// want to sign with two certificates and both of them are
        /// problematic, the following is not guaranteed to mention
        /// both certificates.
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
        InvalidDetachedSignature(InvalidDetachedSignature),

        #[error(transparent)]
        MalformedOpenPGPMessage(MalformedOpenPGPMessage),

        #[error(transparent)]
        EncryptedData(EncryptedData),

        #[error(transparent)]
        CompressedData(CompressedData),

        #[error(transparent)]
        SigningFailed(SigningFailed),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to signing.
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

    /// Information about how we are going to sign the message before
    /// we create the actual signatures.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Signing {
        /// The signers.
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

/// The variants of this enum are the different types of output that
/// [`sign`](Builder::sign) and [`append`](Builder::append) emit.
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

    /// Information about how we are going to sign the message before
    /// we create the actual signatures.
    Signing(output::Signing),

    /// Emitted at the end.
    ///
    /// This is always emitted whether signing was successful or not.
    Report(output::Report),
}

/// The outcome.
///
/// This is returned by [`Builder::sign`] and [`Builder::append`].  It
/// contains information about the operation's outcome.  More detailed
/// information is available via the [`Stream`] interface.
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

/// The signing parameters.
///
/// These parameters are used by [`sign`](Builder::sign) and
/// [`append`](Builder::append).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    signers: Vec<Cert>,
    hash_mode: HashMode,
    /// Creating notarizations is currently unsupported.
    ///
    /// See
    /// <https://gitlab.com/sequoia-pgp/sequoia-sq/-/commit/993a719a7429f0afa87afd6cdc47e7d60645a1b4>
    /// and <https://gitlab.com/sequoia-pgp/sequoia/-/issues/1041>.
    notarize: bool,
    notations: Vec<(bool, NotationData)>,

    /// If Some, ASCII-armor.  Otherwise, binary.
    armor_headers: Option<Vec<(String, String)>>,
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

    /// Returns the hashing mode.
    pub fn hash_mode(&self) -> HashMode {
        self.hash_mode.clone()
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
}

/// Owned parameters.
struct ParamsOnce<'stream> {
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Sign messages.
///
/// A builder providing control over how to sign a message.
pub struct Builder<'sequoia, 'stream, T> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'stream>,
    t: std::marker::PhantomData<T>,
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream, builder::UnspecifiedSignatureType> {
    pub(crate) fn new(sequoia: &'sequoia Sequoia)
        -> Builder<'sequoia, 'stream, builder::UnspecifiedSignatureType>
    {
        Builder {
            params: Params {
                sequoia,
                signers: Vec::new(),
                hash_mode: HashMode::Binary,
                notarize: false,
                notations: Vec::new(),

                armor_headers: Some(Vec::new()),
            },
            params_once: ParamsOnce {
                stream: None,
            },
            t: std::marker::PhantomData,
        }
    }
}

/// Types related to [`Builder`].
pub mod builder {
    #[cfg(doc)]
    use super::Builder;

    mod private {
        pub trait Sealed {}
    }

    /// The signature type.
    pub trait SignatureType: private::Sealed {}

    /// Indicates that an extended set of parameters are applicable to
    /// the signature type.
    ///
    /// Detached and inline signatures are rich signature types.
    /// Cleartext signatures are more constrained.
    pub trait RichSignature: private::Sealed + SignatureType {}

    /// The base signature type.
    ///
    /// Before you create a signature, you must call
    /// [`Builder::detached`], [`Builder::inline`], or [`Builder::clear`],
    /// to specify the signature type.
    #[derive(Debug)]
    pub struct UnspecifiedSignatureType;
    impl private::Sealed for UnspecifiedSignatureType {}
    impl SignatureType for UnspecifiedSignatureType {}

    /// Designates a detached signature.
    ///
    /// A detached signature is stored separately from the signed data.
    #[derive(Debug)]
    pub struct DetachedSignature;
    impl private::Sealed for DetachedSignature {}
    impl SignatureType for DetachedSignature {}
    impl RichSignature for DetachedSignature {}

    /// Designates an inline-signed message.
    ///
    /// In an inline-signed message, the signature is stored with the
    /// signed data.
    #[derive(Debug)]
    pub struct InlineSignature;
    impl private::Sealed for InlineSignature {}
    impl SignatureType for InlineSignature {}
    impl RichSignature for InlineSignature {}

    /// Designates a cleartext signed message.
    ///
    /// A [cleartext-signed message] is an inline signed text message
    /// that has not been ASCII-armored.  The result is that the
    /// message remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    ///   [cleartext-signed message]: https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo
    #[derive(Debug)]
    pub struct CleartextSignature;
    impl private::Sealed for CleartextSignature {}
    impl SignatureType for CleartextSignature {}
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream, builder::UnspecifiedSignatureType>
{
    /// Sets that a detached signature should be created.
    ///
    /// When generating an inline-signed message, the data being
    /// signed is included with the signature.  When generated a
    /// [detached signature], only a signature is created.  This means
    /// that an inline-signed message is mostly self contained whereas
    /// someone who wants to use a detached signature needs a copy of
    /// the signed data.
    ///
    ///   [detached signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    pub fn detached(self) -> Builder<'sequoia, 'stream, builder::DetachedSignature>
    {
        Builder {
            params: self.params,
            params_once: self.params_once,
            t: std::marker::PhantomData,
        }
    }

    /// Sets that an inline-signed message should be created.
    ///
    /// When generating an inline-signed message, the data being
    /// signed is included with the signature.  When generated a
    /// [detached signature], only a signature is created.  This means
    /// that an inline-signed message is mostly self contained whereas
    /// someone who wants to use a detached signature needs a copy of
    /// the signed data.
    ///
    ///   [detached signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    pub fn inline(self) -> Builder<'sequoia, 'stream, builder::InlineSignature>
    {
        Builder {
            params: self.params,
            params_once: self.params_once,
            t: std::marker::PhantomData,
        }
    }

    /// Sets that a cleartext signed message should be created.
    ///
    /// A [cleartext-signed message] is an inline signed text message
    /// that has not been ASCII-armored.  The result is that the
    /// message remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    ///   [cleartext-signed message]: https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo
    pub fn clear(self) -> Builder<'sequoia, 'stream, builder::CleartextSignature>
    {
        Builder {
            params: self.params,
            params_once: self.params_once,
            t: std::marker::PhantomData,
        }
    }

}

impl<'sequoia, 'stream, T> Builder<'sequoia, 'stream, T>
where
    T: builder::SignatureType
{
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    stream_builder_impl!('sequoia; T);

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
    /// the signing operation will return an error.
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

    /// Adds a notation to each of the new signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(mut self, critical: bool, notation: NotationData)
                        -> Self
    {
        self.params.notations.push((critical, notation));
        self
    }

    /// Adds notations to each of the new signatures.
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
}

impl<'sequoia, 'stream, T> Builder<'sequoia, 'stream, T>
where
    T: builder::RichSignature
{
    /// Sets the hashing mode.
    ///
    /// The hashing mode determines how the data is hash.  By default
    /// the signature is generated in binary mode.  In binary mode,
    /// the signed content is hashed as-is.  In [text mode], line
    /// endings are normalized to `\n\r`.  If in doubt, you probably
    /// want binary mode.
    ///
    ///   [text mode]: https://www.rfc-editor.org/rfc/rfc9580.html#sigtype-text
    pub fn hash_mode(mut self, hash_mode: HashMode) -> Self {
        self.params.hash_mode = hash_mode;
        self
    }

    /// Sets whether ASCII armor is used.
    ///
    /// If disabled, then the message is binary encoded.
    ///
    /// The default is to using ASCII armor and not add any headers.
    pub fn ascii_armor(mut self, use_ascii_armor: bool) -> Self
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
}

impl<'sequoia, 'stream, T> Builder<'sequoia, 'stream, T>
where
    T: builder::SignatureType
{
    fn sign_<'a, 'w, 'p>(params: &Params, params_once: &mut ParamsOnce,
                         mut input: &mut (dyn std::io::Read + Send + Sync + 'a),
                         output: Writer<'w>,
                         prompt: &(dyn prompt::Prompt + 'p),
                         detached_signature: bool,
                         preexisting_signatures: Vec<Signature>)
        -> Result<(), Error>
    {
        let Params {
            sequoia,
            ref signers,
            ref hash_mode,
            notarize: _,
            ref notations,

            ref armor_headers,
        } = params;
        let ParamsOnce {
            stream
        } = params_once;

        if signers.is_empty() {
            return Err(Error::ArgumentError(
                error::ArgumentError::NoSigningKeysSpecified(
                    error::NoSigningKeysSpecified {
                    })));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                stream.output(
                    params,
                    Output::Signing(output::Signing {
                        signers: signers.iter()
                            .map(|(cert, signer)| {
                                (cert.clone(), signer.public().fingerprint())
                            })
                            .collect(),
                    }))
                    .map_err(|err| Error::StreamOutputError(err))?;

                signers
            }
            Err(err) => {
                return Err(Error::OperationalError(
                    error::OperationalError::SigningFailed(
                        error::SigningFailed {
                            unusable_certs: vec![ err.clone() ],
                        })));
            }
        };

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message).kind(
                if detached_signature {
                    armor::Kind::Signature
                } else {
                    armor::Kind::Message
                });
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build().map_err(op!())?;
        }

        // Prepend any existing signatures.
        if detached_signature {
            for sig in preexisting_signatures.into_iter() {
                Packet::Signature(sig).serialize(&mut message)
                    .map_err(op!())?;
            }
        } else if ! preexisting_signatures.is_empty() {
            panic!(
                "Internal error: Appending signatures to an inline-signed \
                 message is not supported by this function");
        }

        let mut builder = SignatureBuilder::new(hash_mode.into());
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)
                .map_err(op!())?;
        }

        let mut signer = Signer::with_template(
            message,
            signers.pop().unwrap().1,
            builder)
            .map_err(op!())?;
        signer = signer.creation_time(sequoia.time());
        for s in signers {
            signer = signer.add_signer(s.1).map_err(op!())?;
        }
        if detached_signature {
            signer = signer.detached();
        }
        let signer = signer.build().context("Failed to create signer")
            .map_err(op!())?;

        let mut writer = if detached_signature {
            // Detached signatures do not need a literal data packet, just
            // hash the data as is.
            signer
        } else {
            // We want to wrap the data in a literal data packet.
            LiteralWriter::new(signer).build()
                .context("Failed to create literal writer")
                .map_err(op!())?
        };

        // Finally, copy stdin to our writer stack to sign the data.
        std::io::copy(&mut input, &mut writer)
            .context("Failed to sign")
            .map_err(op!())?;

        writer.finalize()
            .context("Failed to sign")
            .map_err(op!())?;

        Ok(())
    }
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream, builder::DetachedSignature> {
    /// Signs a message and generates a detached signature.
    ///
    /// The detached signature is written to `output`.  By default,
    /// the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    pub fn sign<'w, I, O, P>(mut self, mut input: I, output: O, prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        O: Into<Writer<'w>>,
        P: prompt::Prompt,
    {
        let outcome = Outcome::new();

        let result = Self::sign_(
            &self.params, &mut self.params_once,
            &mut input, output.into(), &prompt,
            true, Vec::new());

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

    /// Adds signatures to a detached signature file.
    ///
    /// This function interprets `detached_signatures` as a detached
    /// signature file, and adds the new signatures to the existing
    /// signatures.  The pre-existing signatures are not checked for
    /// validity.
    ///
    /// The detached signatures are written to `output`.  By default,
    /// the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    pub fn append<'a, 'w, I, D, O, P>(
        mut self, mut input: I,
        detached_signatures: D,
        output: O,
        prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: Into<Writer<'w>>,
        P: prompt::Prompt,
    {
        let outcome = Outcome::new();

        let result = Self::append_(
            &self.params, &mut self.params_once,
            &mut input, Box::new(detached_signatures),
            output.into(), &prompt);

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

    // Note: we box `detached_signatures` instead of passing a
    // reference so that we can drop it.  This way if `output` is a
    // `PartFileWriter` referring to the same file, the file will not
    // exist when `PartFileWriter` persists it.  This is only relevant
    // on Windows where it is not possible to replace a file that is
    // open.
    fn append_<'a, 'w, 'p>(
        params: &Params, params_once: &mut ParamsOnce,
        mut input: &mut (dyn std::io::Read + Send + Sync),
        detached_signatures: Box<dyn std::io::Read + Send + Sync + 'a>,
        output: Writer<'w>,
        prompt: &(dyn prompt::Prompt + 'p))
        -> Result<(), Error>
    {
        // First, read the existing signatures.
        let mut sigs = Vec::new();
        let mut ppr =
            openpgp::parse::PacketParser::from_reader(detached_signatures)
            .map_err(op!())?;

        while let PacketParserResult::Some(pp) = ppr {
            let (packet, ppr_tmp) = pp.recurse()
                .map_err(op!())?;
            ppr = ppr_tmp;

            match packet {
                Packet::Signature(sig) => sigs.push(sig),
                p => return Err(Error::OperationalError(
                    error::OperationalError::InvalidDetachedSignature(
                        error::InvalidDetachedSignature {
                            unexpected_tag: Some(p.tag()),
                        }))),
            }
        }

        // Force detached_signatures to be dropped before output.
        // This way if output is a `PartFileWriter` referring to the
        // same file, the file will not exist when `PartFileWriter`
        // persists it.  This is only relevant on Windows where it is
        // not possible to replace a file that is open.
        drop(ppr);

        Self::sign_(params, params_once,
                    &mut input, output.into(), &prompt, true, sigs)
    }
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream, builder::InlineSignature> {
    /// Signs a message and generates an inline-signed message.
    ///
    /// The inlined-signed message is written to `output`.  By
    /// default, the message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    pub fn sign<'w, I, O, P>(mut self, mut input: I, output: O, prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        O: Into<Writer<'w>>,
        P: prompt::Prompt,
    {
        let outcome = Outcome::new();

        let result = Self::sign_(
            &self.params, &mut self.params_once,
            &mut input, output.into(), &prompt,
            false, Vec::new());

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

    /// Adds signatures to an inline signed message.
    ///
    /// Unlike [`Builder::sign`], this function interprets `input` as
    /// an inline signed message, and adds the new signatures to the
    /// existing signatures.
    ///
    /// If there are multiple signature layers (see [Section 10.3 of
    /// RFC
    /// 9580](https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3)
    /// or multiple groups (see [Section 5.4 of RFC
    /// 9580](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.4)),
    /// then this function adds the signatures to the outer-most layer
    /// and group.  (Adding it to an inner group or layer would break
    /// the signatures in outer groups, since they are over the data
    /// and the inner signature groups.)  Note: almost all signed
    /// messages only consist of a single signature layer and group.
    ///
    /// The signed data is written to `output`.  By default, the
    /// message is encoded using ASCII-armor.  Use
    /// [`Builder::ascii_armor`] to specify ASCII armor headers, or to
    /// disable ASCII-armor encoding and use a binary encoding.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    pub fn append<I, O, P>(mut self, input: I, mut output: O, prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        P: prompt::Prompt,
    {
        let outcome = Outcome::new();

        let result = Self::append_(
            &self.params, &mut self.params_once,
            Box::new(input), &mut output, &prompt);

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

    // Note: we box `input` instead of passing a reference so that we
    // can drop it.  This way if `output` is a `PartFileWriter`
    // referring to the same file, the file will not exist when
    // `PartFileWriter` persists it.  This is only relevant on Windows
    // where it is not possible to replace a file that is open.
    fn append_<'a, 'p>(params: &Params, params_once: &mut ParamsOnce,
                       input: Box<dyn std::io::Read + Send + Sync + 'a>,
                       output: &mut (dyn std::io::Write + Send + Sync),
                       prompt: &(dyn prompt::Prompt + 'p))
        -> Result<(), Error>
    {
        let Params {
            sequoia,
            ref signers,
            ref hash_mode,
            notarize,
            ref notations,

            ref armor_headers,
        } = params;
        let ParamsOnce {
            stream,
        } = params_once;

        if signers.is_empty() {
            return Err(Error::ArgumentError(
                error::ArgumentError::NoSigningKeysSpecified(
                    error::NoSigningKeysSpecified {
                    })));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                let (output, signers) = signers.into_iter()
                    .fold((Vec::new(), Vec::new()),
                          |(mut output, mut signers), (cert, signer)| {
                              output.push((cert, signer.public().fingerprint()));
                              signers.push(signer);

                              (output, signers)
                          });

                stream.output(
                    params,
                    Output::Signing(output::Signing {
                        signers: output,
                    }))
                    .map_err(|err| Error::StreamOutputError(err))?;

                signers
            }
            Err(err) => {
                return Err(Error::OperationalError(
                    error::OperationalError::SigningFailed(
                        error::SigningFailed {
                            unusable_certs: vec![ err.clone() ],
                        })));
            }
        };

        let mut message = Message::new(output);
        if let Some(armor_headers) = armor_headers {
            let mut armorer = Armorer::new(message)
                .kind(armor::Kind::Message);
            for (k, v) in armor_headers {
                armorer = armorer.add_header(k, v);
            }
            message = armorer.build().map_err(op!())?;
        }

        // Create a parser for the message to be notarized.
        let mut ppr
            = openpgp::parse::PacketParser::from_reader(input)
            .context("Failed to build parser")
            .map_err(op!())?;

        // Once we see a signature, we can no longer strip compression.
        let mut seen_signature = false;
        #[derive(PartialEq, Eq, Debug)]
        enum State {
            InFirstSigGroup,
            AfterFirstSigGroup,
            Signing {
                // Counts how many signatures are being notarized.  If
                // this drops to zero, we pop the signer from the stack.
                signature_count: isize,
            },
            Done,
        }
        let mut state =
            if ! notarize {
                State::InFirstSigGroup
            } else {
                // Pretend we have passed the first signature group so
                // that we put our signature first.
                State::AfterFirstSigGroup
            };

        while let PacketParserResult::Some(mut pp) = ppr {
            if let Err(err) = pp.possible_message() {
                return Err(Error::OperationalError(
                    error::OperationalError::MalformedOpenPGPMessage(
                        error::MalformedOpenPGPMessage {
                            error: err.into(),
                        })));
            }

            match pp.packet {
                Packet::PKESK(_) | Packet::SKESK(_) =>
                    return Err(Error::OperationalError(
                        error::OperationalError::EncryptedData(
                            error::EncryptedData {
                            }))),

                Packet::Literal(_) =>
                    if let State::InFirstSigGroup = state {
                        // Cope with messages that have no signatures, or
                        // with a ops packet without the last flag.
                        state = State::AfterFirstSigGroup;
                    },

                // To implement this, we'd need to stream the
                // compressed data packet inclusive framing, but
                // currently the partial body filter transparently
                // removes the framing.
                //
                // If you do implement this, there is a half-disabled test
                // in tests/sq-sign.rs.
                Packet::CompressedData(_) if seen_signature =>
                    return Err(Error::OperationalError(
                        error::OperationalError::CompressedData(
                            error::CompressedData {
                            }))),

                _ => (),
            }

            match state {
                State::AfterFirstSigGroup => {
                    // After the first signature group, we push the signer
                    // onto the writer stack.
                    let mut builder = SignatureBuilder::new(hash_mode.into());
                    for (critical, n) in notations.iter() {
                        builder = builder.add_notation(
                            n.name(),
                            n.value(),
                            Some(n.flags().clone()),
                            *critical)
                            .map_err(op!())?;
                    }

                    let mut signer = Signer::with_template(
                        message, signers.pop().unwrap(), builder)
                        .map_err(op!())?;
                    signer = signer.creation_time(sequoia.time());
                    for s in signers.drain(..) {
                        signer = signer.add_signer(s)
                            .map_err(op!())?;
                    }
                    message = signer.build().context("Failed to create signer")
                        .map_err(op!())?;
                    state = State::Signing { signature_count: 0, };
                },

                State::Signing { signature_count } if signature_count == 0 => {
                    // All signatures that are being notarized are
                    // written, pop the signer from the writer stack.
                    message = message.finalize_one()
                        .context("Failed to sign data")
                        .map_err(op!())?
                        .unwrap();
                    state = State::Done;
                },

                _ => (),
            }

            if let Packet::Literal(_) = pp.packet {
                let l = if let Packet::Literal(l) = pp.packet.clone() {
                    l
                } else {
                    unreachable!()
                };
                // Create a literal writer to wrap the data in a literal
                // message packet.
                let mut literal = LiteralWriter::new(message).format(l.format());
                if let Some(f) = l.filename() {
                    literal = literal.filename(f).map_err(op!())?;
                }
                if let Some(d) = l.date() {
                    literal = literal.date(d).map_err(op!())?;
                }

                let mut literal = literal.build()
                    .context("Failed to create literal writer").map_err(op!())?;

                // Finally, just copy all the data.
                pp.copy(&mut literal)
                    .context("Failed to sign data")
                    .map_err(op!())?;

                // Pop the literal writer.
                message = literal.finalize_one()
                    .context("Failed to sign data")
                    .map_err(op!())?
                    .unwrap();
            }

            let (packet, ppr_tmp) = if seen_signature {
                // Once we see a signature, we can no longer strip
                // compression.
                pp.next()
            } else {
                pp.recurse()
            }.context("Parsing failed").map_err(op!())?;
            ppr = ppr_tmp;

            match packet {
                Packet::OnePassSig(mut ops) => {
                    let was_last = ops.last();
                    match state {
                        State::InFirstSigGroup => {
                            // We want to append our signature here, hence
                            // we set last to false.
                            ops.set_last(false);

                            if was_last {
                                // The signature group ends here.
                                state = State::AfterFirstSigGroup;
                            }
                        },

                        State::Signing { ref mut signature_count } =>
                            *signature_count += 1,

                        _ => (),
                    }

                    Packet::OnePassSig(ops).serialize(&mut message)
                        .map_err(op!())?;
                    seen_signature = true;
                },

                Packet::Signature(sig) => {
                    Packet::Signature(sig).serialize(&mut message)
                        .context("Failed to serialize")
                        .map_err(op!())?;
                    if let State::Signing { ref mut signature_count } = state {
                        *signature_count -= 1;
                    }
                },
                _ => (),
            }
        }

        if let PacketParserResult::EOF(ref eof) = ppr {
            if let Err(err) = eof.is_message() {
                return Err(Error::OperationalError(
                    error::OperationalError::MalformedOpenPGPMessage(
                        error::MalformedOpenPGPMessage {
                            error: err.into(),
                        })));
            }
        } else {
            unreachable!()
        }

        // Force input to be dropped before output.  This way if
        // output is a `PartFileWriter` referring to the same file,
        // the file will not exist when `PartFileWriter` persists it.
        // This is only relevant on Windows where it is not possible
        // to replace a file that is open.
        drop(ppr);

        match state {
            State::Signing { signature_count } => {
                assert_eq!(signature_count, 0);
                message.finalize()
                    .context("Failed to sign data")
                    .map_err(op!())?;
            },
            State::Done => {
                message.finalize()
                    .context("Failed to sign data")
                    .map_err(op!())?;
            },
            _ => panic!("Unexpected state: {:?}", state),
        }

        Ok(())
    }
}

impl<'sequoia, 'stream> Builder<'sequoia, 'stream, builder::CleartextSignature> {
    /// Clear signs a message.
    ///
    /// A clear-signed message is an inline signed text message that
    /// has not been ASCII-armored.  The result is that the message
    /// remains readable.
    ///
    /// The cleartext signature framework normalizes line endings,
    /// trims trailing whitespace, and dash escapes lines starting
    /// with a dash.
    ///
    /// The signed data is written to `output`.
    ///
    /// Returns `Ok` if the message could be signed.
    ///
    /// On failure some of the signed data may have been written to
    /// the output writer.  This should be ignored.
    pub fn sign<I, O, P>(mut self, mut input: I, mut output: O, prompt: P)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        P: prompt::Prompt,
    {
        let outcome = Outcome::new();

        let result = Self::clear_sign_(
            &self.params, &mut self.params_once,
            &mut input, &mut output, &prompt);

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

    fn clear_sign_<'p>(
        params: &Params, params_once: &mut ParamsOnce,
        mut input: &mut (dyn std::io::Read + Send + Sync),
        mut output: &mut (dyn std::io::Write + Send + Sync),
        prompt: &(dyn prompt::Prompt + 'p))
        -> Result<(), Error>
    {
        let Params {
            sequoia,
            ref signers,
            hash_mode: _,
            notarize: _,
            ref notations,

            armor_headers: _,
        } = params;
        let ParamsOnce {
            stream
        } = params_once;

        if signers.is_empty() {
            return Err(Error::ArgumentError(
                error::ArgumentError::NoSigningKeysSpecified(
                    error::NoSigningKeysSpecified {
                    })));
        }

        let mut signers = match sequoia.get_signing_keys(
            &signers, None, &prompt)
        {
            Ok(signers) => {
                let (output, signers) = signers
                    .into_iter()
                    .fold((Vec::new(), Vec::new()),
                          |(mut output, mut signers), (cert, signer)| {
                              output.push((cert.clone(),
                                           signer.public().fingerprint()));
                              signers.push(signer);

                              (output, signers)
                          });

                stream.output(
                    params,
                    Output::Signing(output::Signing {
                        signers: output,
                    }))
                    .map_err(|err| Error::StreamOutputError(err))?;

                signers
            }
            Err(err) => {
                return Err(Error::OperationalError(
                    error::OperationalError::SigningFailed(
                        error::SigningFailed {
                            unusable_certs: vec![ err.clone() ],
                        })));
            }
        };

        // Prepare a signature template.
        let mut builder = SignatureBuilder::new(SignatureType::Text);
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)
                .map_err(op!())?
        }

        let message = Message::new(&mut output);
        let mut signer = Signer::with_template(
            message, signers.pop().unwrap(), builder)
            .map_err(op!())?
            .cleartext();
        signer = signer.creation_time(sequoia.time());
        for s in signers {
            signer = signer.add_signer(s)
                .map_err(op!())?
        }
        let mut message = signer.build().context("Failed to create signer")
            .map_err(op!())?;

        // Finally, copy stdin to our writer stack to sign the data.
        std::io::copy(&mut input, &mut message)
            .context("Failed to sign")
            .map_err(op!())?;

        message.finalize()
            .context("Failed to sign")
            .map_err(op!())?;

        Ok(())
    }
}
