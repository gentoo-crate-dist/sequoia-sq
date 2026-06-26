//! Signature verification.
//!
//! A digital signature can be used to verify the authenticity and
//! integrity of a message.  For instance, Alice may want to download
//! the latest release of [Qubes OS].  To ensure that an adversary has
//! not tampered with the release, she can check that the file that
//! she received was signed by the Qubes OS release team's
//! certificate.
//!
//! [Qubes OS]: https://www.qubes-os.org/
//!
//! Note that there are two steps to verify a signature: the signature
//! must authenticate the document, and the signing certificate must
//! be authenticated.  Checking that the signature authenticates the
//! document without also authenticating the certificate does not
//! prevent an attacker from modifying the data in transit.  If an
//! adversary gains control of the server that serves the file and the
//! signature, they can replace the file and the signature.  To detect
//! this type of tampering, the user must also authenticate the
//! certificate.
//!
//! There are several ways to authenticate a certificate.  You can
//! check it directly by checking the certificate's fingerprint.  The
//! most secure way to get the fingerprint is to ask the person who
//! controls the certificate in-person for the certificate's
//! fingerprint.  This has a lot of overhead, and is often
//! impractical.  As such, depending on the user's threat model, it
//! may be sufficient to check that multiple partially trusted
//! websites display the same fingerprint.  Alternatively, you can
//! check it indirectly by delegating the check to one or more
//! certification authorities (CAs), like [`keys.openpgp.org`].
//!
//! [`keys.openpgp.org`]: https://keys.openpgp.org
//!
//! # Examples
//!
//! Verify a message and just get the verified message or a succinct
//! error message; the structured output that includes information
//! about the signatures is discarded:
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::verify;
//!
//! # fn main() -> anyhow::Result<()> {
//! let message = b"-----BEGIN PGP MESSAGE-----
//!
//! xA0DAAoW0fHeyI2faiIAxA0DAAoWXBlCBA8F6L4BywpiAAAAAABmb28Kwr0EABYK
//! # AG8FgmjVMzYJEFwZQgQPBei+RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
//! # aWEtcGdwLm9yZ+1bBHsT0PK4Q2lkuDHQ5CTbOWeHYnKAw9RbOdsin32FFiEE6eay
//! # LiUrXUk+zRphXBlCBA8F6L4AAG4nAQDNliWncs/fB8lVnkjxFDmFCs9FZGgNwbyQ
//! # RtE0xafNdQD/a7Yy7OIV23HNmVAuNJfnKIqxkeASat/r9gdc5byB1wnCvQQAFgoA
//! # bwWCaNUzNgkQ0fHeyI2faiJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
//! # YS1wZ3Aub3JnbYs5xov77H9AAHQzFUoyI5qWFWUM0LHPXKQElGAUD1IWIQQiEsNi
//! # c1VLB0KxSYrR8d7IjZ9qIgAAJisBAPttuQBJJOVcqd0zV1bDX8I9LNgXt4mIXRM7
//! # ewZfwAjvAQC/LZc4j2tBqAxV5ORGXtArETa3r+ekLOD+hGLpo8j+Ag==
//! # =yiKW
//! # -----END PGP MESSAGE-----";
//! // ...";
//!
//! // Initialize Sequoia.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // Verify the message and store the verified data in output.
//! let mut output = Vec::new();
//! if let Err(err) = sequoia
//!     .verify()
//!     .inline_signature(
//!         std::io::Cursor::new(message),
//!         &mut output,
//!         // Discards the structured output.
//!         ())
//! {
//!     eprintln!("Failed to verify message: {}.", err);
//! } else {
//!     // The signed data is in `output`.
//!     eprintln!("Verified message.");
//! }
//! # Ok(()) }
//! ```
//!
//! Verify a message and examine the structured output.  This example
//! shows how to implement [`Stream`], and how to pick apart the
//! [`Output`] and [`output::MessageStructure`] structs to determine
//! the status of any [`output::Signature`]s.
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::verify;
//!
//! # fn main() -> anyhow::Result<()> {
//! struct VerifyOutputHandler<'a> {
//!     sequoia: &'a sequoia::Sequoia,
//! }
//!
//! impl verify::Stream for &mut VerifyOutputHandler<'_> {
//!     fn output(&mut self, _params: &verify::Params, output: verify::Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             verify::Output::MessageStructure(structure) => {
//!                 // Iterate over the message's layers.
//!                 for layer in structure.layers {
//!                     match layer {
//!                         // Examine the signatures.
//!                         verify::output::MessageLayer::Signature(
//!                             verify::output::message_layer::SignatureLayer {
//!                                 sigs,
//!                                 ..
//!                              }) =>
//!                         {
//!                             for sig in sigs {
//!                                 match sig.status {
//!                                     verify::output::SignatureStatus::Verified(
//!                                         verify::output::signature_status::Verified {
//!                                             cert,
//!                                             ..
//!                                         }) =>
//!                                      {
//!                                          eprintln!("Verified signature from {}, {}.",
//!                                                    cert.fingerprint(),
//!                                                    self.sequoia.best_userid(
//!                                                        &cert, true).display());
//!                                      }
//!                                      // Handle other signature statuses if you want.
//!                                      _ => (),
//!                                 }
//!                             }
//!                         }
//!                         // Ignore the non-signature layers.
//!                         _ => (),
//!                     }
//!                 }
//!            }
//!            verify::Output::Report(report) => {
//!                if report.authenticated {
//!                    eprintln!("Verified message");
//!                }
//!            }
//!            // Ignore other output.
//!            _ => (),
//!         }
//!
//!         // If we return an error, processing is aborted and the
//!         // error is immediately returned to the caller.
//!         Ok(())
//!     }
//! }
//!
//! let message = b"-----BEGIN PGP MESSAGE-----
//!
//! xA0DAAoW0fHeyI2faiIAxA0DAAoWXBlCBA8F6L4BywpiAAAAAABmb28Kwr0EABYK
//! # AG8FgmjVMzYJEFwZQgQPBei+RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv
//! # aWEtcGdwLm9yZ+1bBHsT0PK4Q2lkuDHQ5CTbOWeHYnKAw9RbOdsin32FFiEE6eay
//! # LiUrXUk+zRphXBlCBA8F6L4AAG4nAQDNliWncs/fB8lVnkjxFDmFCs9FZGgNwbyQ
//! # RtE0xafNdQD/a7Yy7OIV23HNmVAuNJfnKIqxkeASat/r9gdc5byB1wnCvQQAFgoA
//! # bwWCaNUzNgkQ0fHeyI2faiJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
//! # YS1wZ3Aub3JnbYs5xov77H9AAHQzFUoyI5qWFWUM0LHPXKQElGAUD1IWIQQiEsNi
//! # c1VLB0KxSYrR8d7IjZ9qIgAAJisBAPttuQBJJOVcqd0zV1bDX8I9LNgXt4mIXRM7
//! # ewZfwAjvAQC/LZc4j2tBqAxV5ORGXtArETa3r+ekLOD+hGLpo8j+Ag==
//! # =yiKW
//! # -----END PGP MESSAGE-----";
//! // ...";
//!
//! // Initialize Sequoia.
//! let sequoia = Sequoia::builder().stateless().build()?;
//!
//! // Verify the message and store the verified data in output.
//! let mut output = Vec::new();
//! let mut output_handler = VerifyOutputHandler {
//!     sequoia: &sequoia,
//! };
//! if let Err(err) = sequoia.verify()
//!     .inline_signature(
//!         std::io::Cursor::new(message),
//!         &mut output,
//!         &mut output_handler)
//! {
//!     eprintln!("Failed to verify message: {}.", err);
//! } else {
//!     // The signed data is in `output`.
//!     eprintln!("Verified message.");
//! }
//! # Ok(()) }
//! ```

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashSet, btree_map::{BTreeMap, Entry}};
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use sequoia_openpgp::parse::buffered_reader;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::packet::UserID;
use openpgp::packet;
use openpgp::parse::Parse;
use openpgp::parse::stream::DetachedVerifierBuilder;
use openpgp::parse::stream::VerificationError;
use openpgp::parse::stream::VerificationResult;
use openpgp::parse::stream::VerifierBuilder;
use openpgp::parse::stream;
use openpgp::types::AEADAlgorithm;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::SymmetricAlgorithm;

use sequoia_cert_store::Store;
use sequoia_wot::store::Store as _;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::decrypt;
use crate::inspect::Kind;

const TRACE: bool = false;

/// Turns an error into an `Error::OperationalError::Other` unless it
/// is already an `Error` in which case the `Error` is returned.
macro_rules! op {
    () => {
        |err| {
            match err.downcast::<Error>() {
                Ok(err) => {
                    // We already have an `Error`.  Just return it.
                    err
                },
                Err(err) => {
                    // Turn the err into an `Error::OperationalError`.
                    Error::OperationalError(
                        error::OperationalError::Other(
                            Arc::new(err.into())))
                }
            }
        }
    }
}

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`inline_signature`](Builder::inline_signature)
    /// and [`detached_signature`](Builder::detached_signature).
    fn output(&mut self, params: &Params, output: Output) -> Result<()>;
}

impl<T> Stream for Box<T>
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        self.as_mut().output(params, output)
    }
}

impl<T> Stream for &mut T
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        (*self).output(params, output)
    }
}

/// Collects the output in the specified vector.
impl Stream for &mut Vec<Output> {
    fn output(&mut self, _params: &Params, output: Output) -> Result<()> {
        self.push(output);
        Ok(())
    }
}

/// Discards the output.
impl Stream for () {
    fn output(&mut self, _params: &Params, _output: Output) -> Result<()> {
        Ok(())
    }
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// Web of Trust-specific authentication information.
    ///
    /// This is used by [`signature_status::GoodChecksum`] and
    /// [`signature_status::Verified`].
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct WebOfTrust {
        /// The maximum authentication level of any user ID.
        ///
        /// 120 means fully authenticated.
        pub authentication_level: usize,

        /// The authentication paths in the web of trust for each user
        /// ID.
        ///
        /// Self-signed user IDs that could not be authenticated
        /// (i.e., those for which there is no path from a trust root)
        /// are still included.
        pub authentication_paths: Vec<(UserID, sequoia_wot::Paths)>,
    }

    /// Direct authentication-specific authentication information.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Direct {
    }

    /// Data structures related to [`SignatureStatus`].
    pub mod signature_status {
        use super::*;

        /// A verified signature.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::add_designated_signer`]).
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct Verified {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// Web of trust authentication information.
            pub wot: Option<WebOfTrust>,

            /// Direct authentication information.
            ///
            /// See [`Builder::add_designated_signer`].
            pub direct: Option<Direct>,
        }

        /// A signature that could be mathemtically verified, but the
        /// signer's certificate could not be authenticated.
        ///
        /// This is called `GoodChecksum`, because a signature whose
        /// signer cannot be authenticated is no better than a
        /// checksum.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct GoodChecksum {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// Web of trust authentication information.
            pub wot: Option<WebOfTrust>,

            /// Direct authentication information.
            ///
            /// See [`Builder::add_designated_signer`].
            pub direct: Option<Direct>,
        }

        /// Missing key.
        ///
        /// A certificate that includes the alleged issuer's key is
        /// not available.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct MissingKey {
            /// The signature.
            pub sig: packet::Signature,
        }

        /// Unbound key.
        ///
        /// There is no valid binding signature at the time the
        /// signature was created under the given policy.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct UnboundKey {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The reason why the key is not bound.
            pub error: Arc<anyhow::Error>,
        }

        /// Bad key.
        ///
        /// We have a key, but it is not alive, etc.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct BadKey {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// The reason why the key is bad.
            pub error: Arc<anyhow::Error>,
        }

        /// Bad signature.
        ///
        /// We have a valid key, but the signature isn't valid.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct BadSignature {
            /// The signature.
            pub sig: packet::Signature,

            /// A certificate that includes the signing key.
            pub cert: Cert,

            /// The key that made the signature.
            pub key: Fingerprint,

            /// The reason why the signature isn't valid.
            pub error: Arc<anyhow::Error>,
        }

        /// Malformed signature.
        ///
        /// The signature is malformed.  This could be because it does
        /// not include a signature creation subpacket.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct MalformedSignature {
            /// The signature.
            pub sig: packet::Signature,

            /// The reason why the signature is malformed.
            pub error: Arc<anyhow::Error>,
        }

        /// A signature that we failed to parse.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct UnknownSignature {
            /// The signature parsed into an [`Unknown`] packet.
            ///
            /// You can get the parse error using [`Unknown::error`].
            ///
            /// [`Unknown`]: sequoia_openpgp::packet::Unknown
            /// [`Unknown::error`]: sequoia_openpgp::packet::Unknown::error
            pub sig: packet::Unknown,
        }

        /// An unknown error occurred.
        ///
        /// This may happen if your application is using a newer
        /// version of `sequoia_openpgp` than your code is prepared
        /// for.
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct Unknown {
            /// The unknown `VerificationResult` as an error.
            pub error: Arc<anyhow::Error>,
        }
    }

    /// A signature's verification status.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum SignatureStatus {
        Verified(signature_status::Verified),
        GoodChecksum(signature_status::GoodChecksum),
        MissingKey(signature_status::MissingKey),
        UnboundKey(signature_status::UnboundKey),
        BadKey(signature_status::BadKey),
        BadSignature(signature_status::BadSignature),
        MalformedSignature(signature_status::MalformedSignature),
        UnknownSignature(signature_status::UnknownSignature),
        Unknown(signature_status::Unknown),
    }

    impl SignatureStatus {
        /// Returns whether the signature could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::add_designated_signer`]).
        pub fn verified(&self) -> bool {
            matches!(self, SignatureStatus::Verified(_))
        }

        /// Returns the signature.
        ///
        /// Returns `None` for
        /// [`UnknownSignature`](SignatureStatus::UnknownSignature).
        /// It is still possible to get the raw signature data from an
        /// `UnknownSignature` by matching on the field.
        pub fn signature(&self) -> Option<&packet::Signature> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { sig, .. }) => Some(sig),
                SignatureStatus::GoodChecksum(GoodChecksum { sig, .. }) => Some(sig),
                SignatureStatus::MissingKey(MissingKey { sig, .. }) => Some(sig),
                SignatureStatus::UnboundKey(UnboundKey { sig, .. }) => Some(sig),
                SignatureStatus::BadKey(BadKey { sig, .. }) => Some(sig),
                SignatureStatus::BadSignature(BadSignature { sig, .. }) => Some(sig),
                SignatureStatus::MalformedSignature(MalformedSignature { sig, .. }) => Some(sig),
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns a certificate with the signing key that made the
        /// signature.
        ///
        /// Returns `None` if the certificate is not available.
        pub fn cert(&self) -> Option<&Cert> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { cert, .. }) => Some(cert),
                SignatureStatus::GoodChecksum(GoodChecksum { cert, .. }) => Some(cert),
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { cert, .. }) => Some(cert),
                SignatureStatus::BadKey(BadKey { cert, .. }) => Some(cert),
                SignatureStatus::BadSignature(BadSignature { cert, .. }) => Some(cert),
                SignatureStatus::MalformedSignature(MalformedSignature { .. }) => None,
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns the key that made the signature.
        ///
        /// Returns `None` if the key is not known.
        pub fn key(&self) -> Option<&Fingerprint> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { key, .. }) => Some(key),
                SignatureStatus::GoodChecksum(GoodChecksum { key, .. }) => Some(key),
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { .. }) => None,
                SignatureStatus::BadKey(BadKey { key, .. }) => Some(key),
                SignatureStatus::BadSignature(BadSignature { key, .. }) => Some(key),
                SignatureStatus::MalformedSignature(MalformedSignature { .. }) => None,
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { .. }) => None,
            }
        }

        /// Returns the related error.
        ///
        /// Returns `None` if no related error is available.  Note:
        /// even if there is no related error, that does not mean that
        /// the signature was verified.
        pub fn error(&self) -> Option<&anyhow::Error> {
            use signature_status::*;

            match self {
                SignatureStatus::Verified(Verified { .. }) => None,
                SignatureStatus::GoodChecksum(GoodChecksum { .. }) => None,
                SignatureStatus::MissingKey(MissingKey { .. }) => None,
                SignatureStatus::UnboundKey(UnboundKey { error, .. }) => Some(error),
                SignatureStatus::BadKey(BadKey { error, .. }) => Some(error),
                SignatureStatus::BadSignature(BadSignature { error, .. }) => Some(error),
                SignatureStatus::MalformedSignature(MalformedSignature { error, .. }) => Some(error),
                SignatureStatus::UnknownSignature(UnknownSignature { .. }) => None,
                SignatureStatus::Unknown(Unknown { error, .. }) => Some(error),
            }
        }
    }

    /// Miscellaneous information about a signature.
    ///
    /// The variants contain miscellaneous information about a
    /// signature.  This could be displayed under more information or
    /// as warnings.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum SignatureInfo {
        /// The signer's certificate can't be authenticated, because
        /// it has no user IDs.
        NoUserIDs,
    }

    /// A signature.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Signature {
        /// The signature's status.
        pub status: SignatureStatus,

        /// Miscellaneous information about the signature.
        pub info: Vec<SignatureInfo>,
    }

    impl Signature {
        /// Returns whether the signature could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::add_designated_signer`]).
        pub fn verified(&self) -> bool {
            self.status.verified()
        }

        /// Returns the signature.
        ///
        /// Returns `None` for
        /// [`UnknownSignature`](SignatureStatus::UnknownSignature).
        /// It is still possible to get the raw signature data from an
        /// `UnknownSignature` by matching on the field.
        pub fn signature(&self) -> Option<&packet::Signature> {
            self.status.signature()
        }

        /// Returns a certificate with the signing key that made the
        /// signature.
        ///
        /// Returns `None` if the certificate is not available.
        pub fn cert(&self) -> Option<&Cert> {
            self.status.cert()
        }

        /// Returns the key that made the signature.
        ///
        /// Returns `None` if the key is not known.
        pub fn key(&self) -> Option<&Fingerprint> {
            self.status.key()
        }

        /// Returns the related error.
        ///
        /// Returns `None` if no related error is available.  Note:
        /// even if there is no related error, that does not mean that
        /// the signature was verified.
        pub fn error(&self) -> Option<&anyhow::Error> {
            self.status.error()
        }
    }

    /// Data structures related to [`MessageLayer`].
    pub mod message_layer {
        use super::*;

        /// Information about a message's signature layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct SignatureLayer {
            pub sigs: Vec<Signature>,
        }

        /// Information about a message's compression layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct CompressionLayer {
            pub algo: CompressionAlgorithm,
        }

        /// Information about a message's encryption layer.
        ///
        /// See [`MessageLayer`].
        #[non_exhaustive]
        #[derive(Debug, Clone)]
        pub struct EncryptionLayer {
            pub sym_algo: SymmetricAlgorithm,
            pub aead_algo: Option<AEADAlgorithm>,
        }
    }

    /// The layers of an OpenPGP message.
    ///
    /// A valid OpenPGP message contains one literal data packet with
    /// optional encryption, signing, and compression layers freely
    /// combined on top.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum MessageLayer {
        Signature(message_layer::SignatureLayer),
        Compression(message_layer::CompressionLayer),
        Encryption(message_layer::EncryptionLayer),
    }

    /// Information about an OpenPGP message's structure.
    ///
    /// This data structure contains information about an OpenPGP
    /// message's structure; it does not include the message's
    /// content.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct MessageStructure {
        pub layers: Vec<MessageLayer>,
    }

    /// Information about the operation.
    ///
    /// This includes summary statistics.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Report {
        /// Whether enough signatures could be verified.
        ///
        /// A signature is considered verified if the signature is
        /// mathematically correct, and either at least one user ID
        /// (not necessarily a self-signed user ID) could be
        /// authenticated for the signer's certificate using the web
        /// of trust, or the certificate is considered authenticated
        /// (see [`Builder::add_designated_signer`]).
        pub authenticated: bool,

        /// The number of authenticated signatures.
        ///
        /// See [`SignatureStatus::Verified`].
        pub authenticated_signatures: usize,

        /// The number of mathematically correct signatures whose
        /// signer could not be authenticated.
        ///
        /// See [`SignatureStatus::GoodChecksum`].
        pub unauthenticated_signatures: usize,

        /// Signatures that could not be checked, because the key is
        /// missing.
        ///
        /// See [`SignatureStatus::MissingKey`].
        pub uncheckable_signatures: usize,

        /// The number of signatures that could not be checked,
        /// because the signature was bad.
        ///
        /// See [`SignatureStatus::UnknownSignature`] and
        /// [`SignatureStatus::BadSignature`].
        pub bad_signatures: usize,

        /// The number of signatures that could not be checked,
        /// because the key or certificate was bad.
        ///
        /// See [`SignatureStatus::UnboundKey`] and
        /// [`SignatureStatus::BadKey`].
        pub broken_keys: usize,

        /// The number of signatures that are broken.
        ///
        /// See [`SignatureStatus::MalformedSignature`].
        pub broken_signatures: usize,
    }

    impl Report {
        pub(crate) fn new() -> Self {
            Report {
                authenticated: false,
                authenticated_signatures: 0,
                unauthenticated_signatures: 0,
                uncheckable_signatures: 0,
                broken_keys: 0,
                bad_signatures: 0,
                broken_signatures: 0,
            }
        }
    }
}

/// The variants of this enum are the different types of output that
/// [`inline_signature`](Builder::inline_signature) and
/// [`detached_signature`](Builder::detached_signature) emit.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Output {
    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    ArgumentError(error::ArgumentError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    SystemError(SystemError),

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    OperationalError(error::OperationalError),

    /// The message's structure.
    ///
    /// A valid OpenPGP message contains one literal data packet with
    /// optional encryption, signing, and compression layers freely
    /// combined on top.
    ///
    /// This is emitted after the message has been parsed.
    MessageStructure(output::MessageStructure),

    /// Information about the decryption and verification.
    ///
    /// This data structure contains authentication information.
    ///
    /// This is always emitted at the end of the operation.
    Report(output::Report),
}

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

    /// Expected a detached signature, but got something else.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Input is not a detached signature")]
    pub struct NotADetachedSignature {
        /// The kind of detected data.
        ///
        /// Similar to `file(1)`, this is a best guess and not a
        /// guarantee.
        pub kind: Kind,
    }

    /// Can't authenticate the signature.
    ///
    /// The signature is mathematically correct, but we could not
    /// authenticate the signer according to the signing policy.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{}",
        if *.authenticated_signatures == 0 {
            "Verification failed: could not authenticate any signatures"
        } else {
            "Verification failed: could not authenticate enough signatures"
        })]
    pub struct Unauthenticated {
        /// The number of signatures from different authenticated
        /// signers that we need to authenticate the signature.
        pub need_signatures: usize,

        /// The number of signatures from different authenticated
        /// signers that we have.
        pub authenticated_signatures: usize,
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
        NotADetachedSignature(NotADetachedSignature),

        #[error(transparent)]
        Unauthenticated(Unauthenticated),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to verifying a message.
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

impl Sequoia {
    /// Returns a builder for verifying messages.
    ///
    /// See [`Builder`] for details.
    pub fn verify(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                signatures: 1,
                designated_signers: None,
            }
        }
    }
}

/// Parameters to the verify function.
///
/// The parameters passed to
/// [`inline_signature`](Builder::inline_signature) and
/// [`detached_signature`](Builder::detached_signature).
#[derive(Clone)]
pub struct Params<'sequoia> {
    pub(crate) sequoia: &'sequoia Sequoia,
    pub(crate) signatures: usize,
    pub(crate) designated_signers: Option<Vec<Cert>>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.sequoia
    }

    /// Returns the number of required authenticated signatures.
    ///
    /// By default there must be one authenticated signature.  Note: a
    /// mathematically correct signature is not considered
    /// authenticated; at least one of the user IDs on the signer's
    /// certificate must also be fully authenticated.
    pub fn signatures(&self) -> usize {
        self.signatures
    }

    /// Returns the designated signers.
    ///
    /// If not `None`, the specified designated signers (and no other
    /// certificates) are considered authenticated.
    ///
    /// By default, a certificate is authenticated using the web of
    /// trust using certificates from the certificate store (unless
    /// disabled with [`SequoiaBuilder::stateless`]) and any
    /// configured keyrings (see [`SequoiaBuiler::add_keyring`]).  If
    /// this parameter is `Some`, then the use of the web of trust is
    /// disabled, and verify only considers signatures by the
    /// specified certificates.
    ///
    ///   [`SequoiaBuilder::stateless`]: crate::SequoiaBuilder::stateless
    ///   [`SequoiaBuiler::add_keyring`]: crate::SequoiaBuilder::add_keyring
    pub fn designated_signers(&self) -> Option<&[Cert]> {
        self.designated_signers.as_deref()
    }

    // If you add any methods here, add forwarders in decrypt::Params.
}

/// Verify signatures.
///
/// This command builder is used to verify signatures.
#[derive(Clone)]
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia> {
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the number of required authenticated signatures.
    ///
    /// By default there must be one authenticated signature.  Note: a
    /// mathematically correct signature is not considered
    /// authenticated; at least one of the user IDs on the signer's
    /// certificate must also be fully authenticated.
    pub fn signatures(mut self, signatures: usize) -> Self {
        self.params.signatures = signatures;

        self
    }

    /// Adds a certificate to the list of designated signers.
    ///
    /// The specified designated signers (and no other certificates)
    /// are considered authenticated.
    ///
    /// By default, a certificate is authenticated using the web of
    /// trust using certificates from the certificate store (unless
    /// disabled with [`SequoiaBuilder::stateless`]) and any
    /// configured keyrings (see [`SequoiaBuiler::add_keyring`]).
    /// Setting this parameter disables the use of the web of trust
    /// and only considers signatures by the specified certificates.
    ///
    ///   [`SequoiaBuilder::stateless`]: crate::SequoiaBuilder::stateless
    ///   [`SequoiaBuiler::add_keyring`]: crate::SequoiaBuilder::add_keyring
    pub fn add_designated_signer(self, cert: Cert) -> Self
    {
        self.add_designated_signers(std::iter::once(cert))
    }

    /// Adds certificates to the list of designated signers.
    ///
    /// See [`Builder::add_designated_signer`] for details.
    ///
    /// If you specify an empty set of designated signers, then the
    /// web of trust will be disabled, and no signatures will be
    /// authenticated unless you explicitly add some.
    pub fn add_designated_signers(mut self, certs: impl IntoIterator<Item=Cert>)
        -> Self
    {
        if let Some(s) = self.params.designated_signers.as_mut() {
            s.extend(certs);
        } else {
            self.params.designated_signers
                = Some(certs.into_iter().collect())
        }

        self
    }

    /// Verifies an inline signed message.
    ///
    /// An inline-signed message is an OpenPGP message that includes
    /// one or more signatures and the signed data.  If the signatures
    /// and the data are stored separately, you have a detached
    /// signature, which you can verify using
    /// [`Builder::detached_signature`].
    ///
    /// Returns `Ok` if the message could be verified according to the
    /// policy.  (You can configure the signing policy using
    /// [`Builder::signatures`] and [`Builder::add_designated_signer`].)
    ///
    /// The verified data is written to `output`.  If you don't plan
    /// to consume the verified data, you can pass an instance of
    /// `std::io::Empty`, which is normally created by calling
    /// `std::io::empty`.  If you do plan to consume the verified
    /// data, you should not use the input, but save the output and
    /// use that.  This avoids [TOCTOU] errors, and, accidentally
    /// using the wrong data.
    ///
    /// [TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
    ///
    /// `stream` allows you to stream the status information.  If you
    /// don't want to stream the status information, you can pass a
    /// `&mut Vec<Output>` to collect the output.  If you don't care
    /// about the status information, you can pass `()`.
    pub fn inline_signature<I, O, S>(&self, input: I, output: O, stream: S)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,

    {
        self.execute(input, None::<std::io::Empty>, output, stream)
    }

    /// Verifies a detached signature.
    ///
    /// A detached signature is an OpenPGP signature that is stored
    /// separately from the signed data.  If the signature and the
    /// data are stored together, you have an inline signature, which
    /// you can verify using [`Builder::inline_signature`].
    ///
    /// Returns `Ok` if the message could be verified according to the
    /// policy.  (You can configure the signing policy using
    /// [`Builder::signatures`] and [`Builder::add_designated_signer`].)
    ///
    /// The verified data is written to `output`.  If you don't plan
    /// to consume the verified data, you can pass an instance of
    /// `std::io::Empty`, which is normally created by calling
    /// `std::io::empty`.  If you do plan to consume the verified
    /// data, you should not use the input, but save the output and
    /// use that.  This avoids [TOCTOU] errors, and, accidentally
    /// using the wrong data.
    ///
    /// [TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
    ///
    /// `stream` allows you to stream the status information.  If you
    /// don't want to stream the status information, you can pass a
    /// `&mut Vec<Output>` to collect the output.  If you don't care
    /// about the status information, you can pass `()`.
    pub fn detached_signature<I, D, O, S>(&self, input: I, detached: D,
                                          output: O, stream: S)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,

    {
        self.execute(input, Some(detached), output, stream)
    }

    /// Execute the verifier with the configured parameters.
    ///
    /// Returns `Ok` if the message could be verified.
    fn execute<I, D, O, S>(&self, input: I, detached: Option<D>,
                           output: O, mut stream: S)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,
    {
        let mut report = output::Report::new();
        let result = self.execute_(input, detached, output, &mut stream,
                                   &mut report);

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
                // Stop immediately.
                return Err(err);
            }
        };

        stream.output(
            self.params(),
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Execute the verifier with the configured parameters.
    ///
    /// Returns `Ok` if the message could be verified.
    fn execute_<I, D, O, S>(&self, input: I, detached: Option<D>,
                            mut output: O, stream: S,
                            report: &mut output::Report)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        D: std::io::Read + Send + Sync,
        O: std::io::Write + Send + Sync,
        S: Stream,
    {
        let &Builder {
            params: Params {
                sequoia,
                signatures,
                ref designated_signers,
            }
        } = self;

        let mut detached = if let Some(detached) = detached {
            Some(buffered_reader::Generic::with_cookie(
                detached, None, Default::default()))
        } else {
            None
        };

        let mut detached = if let Some(ref mut sig) = detached {
            let (kind, sig) = Kind::identify(sequoia, sig)
                .map_err(op!())?;
            if kind != Kind::DetachedSig {
                return Err(Error::OperationalError(
                    error::OperationalError::NotADetachedSignature(
                        error::NotADetachedSignature {
                            kind,
                        })));
            }

            Some(sig)
        } else {
            None
        };

        let proxy: Rc<RefCell<Box<dyn VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
            })));

        let mut helper = VerificationHelper::new(
            sequoia, signatures, designated_signers.clone(), report);
        helper.stream = Some((proxy, Cow::Borrowed(&self.params)));
        let helper = if let Some(ref mut dsig) = detached {
            let mut v = DetachedVerifierBuilder::from_reader(dsig)
                .map_err(op!())?
                .with_policy(sequoia.policy(), Some(sequoia.time()), helper)
                .map_err(op!())?;
            v.verify_reader(input)
                .map_err(op!())?;
            v.into_helper()
        } else {
            let mut v = VerifierBuilder::from_reader(input)
                .map_err(op!())?
                .with_policy(sequoia.policy(), Some(sequoia.time()), helper)
                .map_err(op!())?;
            io::copy(&mut v, &mut output)
                .map_err(op!())?;
            v.into_helper()
        };

        if helper.report.authenticated {
            Ok(())
        } else {
            Err(Error::OperationalError(
                error::OperationalError::Unauthenticated(
                    error::Unauthenticated {
                        need_signatures: signatures,
                        authenticated_signatures:
                            helper.report.authenticated_signatures,
                    })))
        }
    }
}

struct StreamProxy<'a> {
    stream: Box<dyn Stream + 'a>,
}

impl Stream for StreamProxy<'_>
{
    fn output(&mut self, params: &Params, output: Output)
        -> Result<()>
    {
        self.stream.output(params, output)
    }
}

impl decrypt::Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &decrypt::Params, _output: decrypt::Output)
        -> Result<()>
    {
        Ok(())
    }
}

/// A wrapper trait so that we can have a `Box<dyn verify::Stream +
/// decrypt::Stream>`.
pub(crate) trait VerifyDecryptStream: Stream + decrypt::Stream {
}

/// Implement the wrapper for everything that implements
/// verify::Stream and `Stream`.
impl<T: ?Sized> VerifyDecryptStream for T where T: Stream + decrypt::Stream {
}

pub(crate) struct VerificationHelper<'c>
{
    sequoia: &'c Sequoia,
    signatures: usize,

    pub(crate) stream: Option<(Rc<RefCell<Box<dyn VerifyDecryptStream + 'c>>>,
                               Cow<'c, Params<'c>>)>,

    /// Require signatures to be made by this set of certs.
    designated_signers: Option<Vec<Cert>>,

    trusted: HashSet<KeyID>,

    /// Tracks the inner-most encryption container encountered.
    pub sym_algo: Option<SymmetricAlgorithm>,

    /// Tracks the signatures encountered.
    report: &'c mut output::Report,
}

impl<'c> VerificationHelper<'c> {
    pub fn new(sequoia: &'c Sequoia, signatures: usize,
               designated_signers: Option<Vec<Cert>>,
               report: &'c mut output::Report)
               -> Self
    {
        VerificationHelper {
            sequoia,
            signatures,
            designated_signers,
            trusted: HashSet::new(),
            sym_algo: None,
            stream: None,
            report,
        }
    }

    /// Returns the Sequoia instance.
    pub fn sequoia(&self) -> &Sequoia {
        self.sequoia
    }
}

// We want the following functions to return an `Error`, but the
// `VerificationHelper` trait defines the function signatures, and
// says that they return an `anyhow::Error`.  We implement variants of
// the functions that return our error type and then convert that to
// an `anyhow::Error` in the actual trait implementation.  This flags
// any use of `anyhow::Error`.
impl VerificationHelper<'_> {
    fn get_certs_(&mut self, ids: &[openpgp::KeyHandle])
                  -> Result<Vec<Cert>, Error>
    {
        let mut certs = BTreeMap::new();

        let have_designated_signers = if let Some(designated_signers)
            = self.designated_signers.as_ref()
        {
            for c in designated_signers.iter().cloned() {
                match certs.entry(c.fingerprint()) {
                    Entry::Vacant(e) => {
                        e.insert(c);
                    },
                    Entry::Occupied(mut e) => {
                        // `Cert::merge_public` should only fail if
                        // the two certificates are not the same
                        // certificate.  As this should never happen,
                        // we don't do any special error handling like
                        // converting to a dedicated type.
                        let merged = e.get().clone().merge_public(c)
                            .map_err(op!())?;
                        e.insert(merged);
                    },
                }
            }

            // Get all keys.
            let seen: HashSet<_> = certs.values()
                .flat_map(|cert| {
                    cert.keys().map(|ka| ka.key().fingerprint().into())
                }).collect();

            // Explicitly provided keys are trusted.
            self.trusted = seen;

            true
        } else {
            false
        };

        // If we have any designated signers, we do not consider
        // certificates in the cert store: we require all signatures
        // to be made by the set of designated signers.
        if have_designated_signers {
            return Ok(certs.into_values().collect());
        }

        // Otherwise, look up the issuer IDs in the certificate store.

        // Avoid initializing the certificate store if we don't actually
        // need to.
        if ! ids.is_empty() {
            if let Some(cert_store) = self.sequoia.cert_store()? {
                for id in ids.iter() {
                    for c in cert_store.lookup_by_cert_or_subkey(id)
                        .unwrap_or_default()
                    {
                        // XXX: If we fail to parse a certificate, we
                        // completely abort processing even though a
                        // different certificate may be able to
                        // authenticate a certificate.  Is this really
                        // what we want?
                        let c = c.to_cert().map_err(op!())?
                            .clone();
                        match certs.entry(c.fingerprint()) {
                            Entry::Vacant(e) => {
                                e.insert(c);
                            },
                            Entry::Occupied(mut e) => {
                                // `Cert::merge_public` should only
                                // fail if the two certificates are
                                // not the same certificate.  As this
                                // should never happen, we don't do
                                // any special error handling like
                                // converting to a dedicated type.
                                let merged = e.get().clone().merge_public(c)
                                    .map_err(op!())?;
                                e.insert(merged);
                            },
                        }
                    }
                }
            }
        }

        Ok(certs.into_values().collect())
    }

    fn check_(&mut self, structure: stream::MessageStructure)
        -> Result<(), Error>
    {
        use output::message_layer::*;

        tracer!(TRACE, "VerificationHelper::check");

        let mut layers = Vec::new();

        for layer in structure {
            match layer {
                stream::MessageLayer::Compression { algo } => {
                    t!("Compression layer: {}", algo);
                    layers.push(output::MessageLayer::Compression(
                        CompressionLayer { algo }));
                },
                stream::MessageLayer::Encryption { sym_algo, aead_algo } => {
                    t!("Encryption layer: sym: {}, aead: {:?}",
                       sym_algo, aead_algo);
                    self.sym_algo = Some(sym_algo);
                    layers.push(output::MessageLayer::Encryption(
                        EncryptionLayer { sym_algo, aead_algo }));
                }
                stream::MessageLayer::SignatureGroup { results } => {
                    t!("Signature layer: {} signatures", results.len());

                    let mut sigs = Vec::new();
                    for result in results.into_iter() {
                        sigs.push(self.check_sig(result));
                    }
                    layers.push(output::MessageLayer::Signature(
                        SignatureLayer { sigs }));
                },
            }
        }

        let message_structure = output::MessageStructure { layers };

        self.report.authenticated =
            self.report.authenticated_signatures >= self.signatures;

        if let Some((stream, params)) = self.stream.as_ref() {
            use std::ops::DerefMut;

            let mut stream = stream.borrow_mut();
            let stream = stream.deref_mut();

            stream.output(params,
                          Output::MessageStructure(message_structure))
                .map_err(|err| Error::StreamOutputError(err))?;
        }

        if self.report.authenticated {
            Ok(())
        } else {
            Err(Error::OperationalError(
                error::OperationalError::Unauthenticated(
                    error::Unauthenticated {
                        need_signatures: self.signatures,
                        authenticated_signatures:
                            self.report.authenticated_signatures,
                    })))
        }
    }
}

impl<'c> stream::VerificationHelper for VerificationHelper<'c> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle])
        -> Result<Vec<Cert>>
    {
        self.get_certs_(ids).map_err(|err| anyhow::Error::from(err))
    }

    fn check(&mut self, structure: stream::MessageStructure)
             -> Result<()>
    {
        self.check_(structure).map_err(|err| anyhow::Error::from(err))
    }
}

impl<'c> VerificationHelper<'c> {
    /// Converts a `VerificationResult` into a `Signature`.
    fn check_sig(&mut self, result: VerificationResult) -> output::Signature {
        use output::signature_status::*;

        tracer!(TRACE, "VerificationHelper::check_sig");

        let (sig, ka) = match result {
            Ok(stream::GoodChecksum { sig, ka, .. }) => (sig, ka),
            Err(VerificationError::MissingKey { sig, .. }) => {
                t!("missing key");

                self.report.uncheckable_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::MissingKey(MissingKey {
                        sig: sig.clone(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::UnboundKey { sig, cert, error, .. }) => {
                t!("unbound key: {}", error);

                self.report.broken_keys += 1;
                return output::Signature {
                    status: output::SignatureStatus::UnboundKey(UnboundKey {
                        sig: sig.clone(),
                        cert: cert.clone(),
                        error: error.into(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::BadKey { sig, ka, error, .. }) => {
                t!("bad key: {}", error);

                self.report.broken_keys += 1;
                return output::Signature {
                    status: output::SignatureStatus::BadKey(BadKey {
                        sig: sig.clone(),
                        cert: ka.cert().clone(),
                        key: ka.key().fingerprint(),
                        error: error.into(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::BadSignature { sig, ka, error, .. }) => {
                t!("bad signature: {}", error);

                self.report.bad_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::BadSignature(BadSignature {
                        sig: sig.clone(),
                        cert: ka.cert().clone(),
                        key: ka.key().fingerprint(),
                        error: error.into(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::MalformedSignature { sig, error, .. }) => {
                t!("malformed signature: {}", error);

                self.report.broken_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::MalformedSignature(MalformedSignature {
                        sig: sig.clone(),
                        error: error.into(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(VerificationError::UnknownSignature { sig, .. }) => {
                t!("unknown signature: {}", sig.error());

                self.report.bad_signatures += 1;
                return output::Signature {
                    status: output::SignatureStatus::UnknownSignature(UnknownSignature {
                        sig: sig.clone(),
                    }),
                    info: Vec::new(),
                };
            }
            Err(ve) => {
                t!("unhandled signature");

                return output::Signature {
                    status: output::SignatureStatus::Unknown(Unknown {
                        error: Arc::new(openpgp::Error::from(ve).into()),
                    }),
                    info: Vec::new(),
                };
            }
        };

        t!("good signature (not yet authenticated)");

        // The signature is mathematically correct, but we still need
        // to authenticate it.
        let cert = ka.cert();
        let cert_fpr = cert.fingerprint();
        let issuer = ka.key().keyid();

        let mut direct = None;
        let mut wot = None;
        let mut authenticated = false;
        let mut info = Vec::new();

        if self.designated_signers.is_some() {
            // Direct trust.
            direct = Some(output::Direct {});
            authenticated = self.trusted.contains(&issuer);
        } else if ! self.sequoia.trust_roots().is_empty() {
            // Web of trust.

            let trust_roots = self.sequoia.trust_roots();
            if let Ok(Some(cert_store)) = self.sequoia.cert_store() {
                let mut authentication_paths = vec![];
                let mut authentication_level = 0;

                // Build the network.
                let cert_store = sequoia_wot::store::CertStore::from_store(
                    cert_store.as_ref(), self.sequoia.policy(), self.sequoia.time());

                let userids =
                    cert_store.certified_userids_of(&cert_fpr);

                if userids.is_empty() {
                    info.push(output::SignatureInfo::NoUserIDs);
                } else {
                    let n = sequoia_wot::NetworkBuilder::rooted(
                        &cert_store, &*trust_roots).build();

                    let authenticated_userids
                        = userids.into_iter().filter(|userid| {
                            let paths = n.authenticate(
                                userid, cert.fingerprint(),
                                // XXX: Make this user configurable.
                                sequoia_wot::FULLY_TRUSTED);

                            let amount = paths.amount();

                            // Return if the user ID could be at least
                            // partially authenticated.
                            authentication_paths.push(
                                (userid.clone(), paths));

                            authentication_level
                                = authentication_level.max(amount);

                            amount >= sequoia_wot::FULLY_TRUSTED
                        })
                        .collect::<Vec<UserID>>();

                    if ! authenticated_userids.is_empty() {
                        authenticated = true;
                    }

                    wot = Some(output::WebOfTrust {
                        authentication_level,
                        authentication_paths,
                    });
                }
            }
        }

        let status = if authenticated {
            self.report.authenticated_signatures += 1;
            output::SignatureStatus::Verified(Verified {
                sig: sig.clone(),
                cert: ka.cert().clone(),
                key: ka.key().fingerprint(),
                direct,
                wot,
            })
        } else {
            self.report.unauthenticated_signatures += 1;
            output::SignatureStatus::GoodChecksum(GoodChecksum {
                sig: sig.clone(),
                cert: ka.cert().clone(),
                key: ka.key().fingerprint(),
                direct,
                wot,
            })
        };

        output::Signature {
            status,
            info,
        }
    }
}
