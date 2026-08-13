//! Message decryption.
//!
//! Decrypts a message and optionally checks that the message is
//! signed.
//!
//! # Examples
//!
//! ```rust
//! use sequoia::Sequoia;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #         .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key")
//! #     .into_cert();
//! #
//! let message: &[u8] = b"hello, world!";
//!
//! # let mut ciphertext = Vec::new();
//! #
//! # sq.encrypt()
//! #     .add_recipient(alice.clone())
//! #     .add_signer(alice.clone())
//! #     .encrypt(
//! #         std::io::Cursor::new(message),
//! #         &mut ciphertext,
//! #         Cancel::new())
//! #     .expect("can encrypt");
//! # let ciphertext = std::io::Cursor::new(&ciphertext);
//!
//! let ciphertext = // Some Reader containing an encrypted message.
//! #   ciphertext;
//! let mut plaintext = Vec::new();
//!
//! // Information about the decryption operation.  If you don't want
//! // to examine the output, pass `()` below.
//!
//! let mut output = Vec::new();
//!
//! sq.decrypt()
//!     .stream(&mut output)
//!     .decrypt(
//!         ciphertext,
//!         &mut plaintext,
//!         Cancel::new())?;
//! // Examine output for more information about the decryption process.
//! assert_eq!(plaintext, message);
//! # Ok(()) }
//! ```
//!
//! To get additional information about the decryption process
//! including detailed information about the message structure, and
//! authentication status, you can either collect the [`Output`] and
//! examine it after the call completes, or implement [`Stream`] for a
//! data structure of your choice to examine the [`Output`]
//! asynchronously.  The latter approach, demonstrated below, is
//! better when the message is large as you can provide feedback to
//! the user before the decryption is completely decrypted.
//!
//! ```rust
//! use sequoia::Sequoia;
//! use sequoia::decrypt;
//! use sequoia::prompt::Cancel;
//!
//! struct Stream {
//! }
//!
//! impl decrypt::Stream for Stream {
//!     fn output(&mut self, params: &decrypt::Params, output: decrypt::Output)
//!         -> Result<(), anyhow::Error>
//!     {
//!         match output {
//!             decrypt::Output::Decrypted(
//!                 decrypt::output::Decrypted {
//!                     decryptor,
//!                     ..
//!                 }) =>
//!             {
//!                 use decrypt::output::Decryptor::*;
//!                 match decryptor {
//!                     Cert(cert, _key) => {
//!                         eprintln!("Decrypting using {}", cert.fingerprint());
//!                     }
//!                     Key(key) => {
//!                         eprintln!("Decrypting using {}", key.fingerprint());
//!                     }
//!                     SKESK(_skesk) => {
//!                         eprintln!("Decrypting using a password");
//!                     }
//!                     SessionKey(_session_key) => {
//!                         eprintln!("Decrypting using a provided session key");
//!                     }
//!                     // For future compatibility this and other data \
//!                     // structures are marked non-exhaustive.
//!                     _ => {
//!                         eprintln!("Decrypted some other way");
//!                     }
//!                 }
//!             }
//!             decrypt::Output::Report(
//!                 decrypt::output::Report { verification, .. }) =>
//!             {
//!                 eprintln!("Authenticated {} signatures",
//!                           verification.authenticated_signatures);
//!             }
//!             _ => {
//!                 // Ignore.
//!             }
//!         }
//!
//!         // Return an error to abort processing early.
//!         Ok(())
//!     }
//! }
//! # fn main() -> anyhow::Result<()> {
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key")
//! #     .into_cert();
//! #
//! let message: &[u8] = b"hello, world!";
//!
//! # let mut ciphertext = Vec::new();
//! #
//! # sq.encrypt()
//! #     .add_recipient(alice.clone())
//! #     .add_signer(alice.clone())
//! #     .encrypt(
//! #         std::io::Cursor::new(message),
//! #         &mut ciphertext,
//! #         Cancel::new())
//! #     .expect("can encrypt");
//! # let ciphertext = std::io::Cursor::new(&ciphertext);
//!
//! let ciphertext = // Some Reader containing an encrypted message.
//! #   ciphertext;
//! let mut plaintext = Vec::new();
//!
//! let mut output = Vec::new();
//!
//! sq.decrypt()
//!     .stream(&mut output)
//!     .decrypt(
//!         ciphertext,
//!         &mut plaintext,
//!         Cancel::new())?;
//! // Examine `output` for more information about the decryption process.
//! assert_eq!(plaintext, message);
//! # Ok(()) }
//! ```

use anyhow::Context as _;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::types::SymmetricAlgorithm;
use openpgp::KeyHandle;
use openpgp::crypto;
use openpgp::{Fingerprint, Cert, KeyID};
use openpgp::packet;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::stream::DecryptionHelper;
use openpgp::parse::stream::DecryptorBuilder;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::stream;
use openpgp::types::KeyFlags;

use sequoia_keystore as keystore;

use crate::OptionalWriter;
use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::prompt::Prompt as _;
use crate::prompt::check::CheckRemoteKey;
use crate::prompt::check::CheckSkesks;
use crate::prompt;
use crate::types::PreferredUserID;
use crate::types::SessionKey;
use crate::verify::VerificationHelper;
use crate::verify;

const TRACE: bool = false;

// Stream trait.
stream!{}

/// The decryption parameters.
///
/// These parameters are used by [`decrypt`](Builder::decrypt) and
/// [`decrypt_unwrap`](Builder::decrypt_unwrap).
#[derive(Clone)]
pub struct Params<'sequoia> {
    vparams: verify::Params<'sequoia>,
    secret_keys: Vec<Cert>,
    session_keys: Vec<SessionKey>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.vparams.sequoia()
    }

    /// Returns the number of signatures that have to be authenticated
    /// for the verification to succeed.
    ///
    /// See [`Builder::signatures`].
    pub fn signatures(&self) -> usize {
        self.vparams.signatures()
    }

    /// Returns the set of designated signers.
    ///
    /// See [`Builder::add_designated_signer`].
    pub fn designated_signers(&self) -> Option<&[Cert]> {
        self.vparams.designated_signers()
    }

    /// Returns the verification parameters.
    pub fn verify_params(&self) -> &verify::Params<'sequoia> {
        &self.vparams
    }

    /// Returns the pre-loaded secret keys.
    ///
    /// See [`Builder::add_secret_key`].
    pub fn secret_keys(&self) -> &[Cert] {
        &self.secret_keys[..]
    }

    /// Returns the pre-loaded session keys.
    pub fn session_keys(&self) -> &[SessionKey] {
        &self.session_keys[..]
    }
}

/// Owned parameters.
struct ParamsOnce<'stream> {
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Decrypt messages.
///
/// This command builder is used to decrypt messages.
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
                vparams: verify::Params {
                    sequoia,
                    signatures: 1,
                    designated_signers: None,
                },
                secret_keys: Vec::new(),
                session_keys: Vec::new(),
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

    /// Sets the number of required authenticated signatures.
    ///
    /// By default, one authenticated signature is required.
    ///
    /// Note: [`decrypt_unwrap`](Builder::decrypt_unwrap) does not
    /// apply a signing policy and silently ignores this parameter.
    pub fn signatures(mut self, signatures: usize) -> Self {
        self.params.vparams.signatures = signatures;

        self
    }

    /// Adds a certificate to the list of designated signers.
    ///
    /// The specified designated signers (and no other certificates)
    /// are considered authenticated.
    ///
    /// By default, signer certificates are authenticated using the
    /// web of trust using certificates from the certificate store
    /// (unless disabled with [`SequoiaBuilder::stateless`]) and any
    /// configured keyrings (see [`SequoiaBuiler::add_keyring`]).
    /// This disables the use of the web of trust and only considers
    /// signatures by the specified certificates.
    ///
    /// Note: [`decrypt_unwrap`](Builder::decrypt_unwrap) does not
    /// apply a signing policy and silently ignores this parameter.
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
    /// authenticated.
    pub fn add_designated_signers(mut self, certs: impl IntoIterator<Item=Cert>)
        -> Self
    {
        if let Some(s) = self.params.vparams.designated_signers.as_mut() {
            s.extend(certs);
        } else {
            self.params.vparams.designated_signers
                = Some(certs.into_iter().collect())
        }

        self
    }

    /// Adds the certificate to the list of secret keys to try.
    ///
    /// The secret keys are tried in addition to the key store, if it
    /// hasn't been disabled.
    pub fn add_secret_key(self, secret_key: Cert) -> Self {
        self.add_secret_keys(std::iter::once(secret_key))
    }

    /// Adds the certificates to the list of secret keys to try.
    ///
    /// The secret keys are tried in addition to the key store, if it
    /// hasn't been disabled.
    pub fn add_secret_keys(mut self, secret_keys: impl IntoIterator<Item=Cert>)
        -> Self
    {
        self.params.secret_keys.extend(secret_keys.into_iter());

        self
    }

    /// Adds a session keys to try.
    ///
    /// The session keys are tried in addition to the key store, if
    /// it hasn't been disabled.
    pub fn add_session_key(self, session_key: SessionKey) -> Self {
        self.add_session_keys(std::iter::once(session_key))
    }

    /// Adds session keys to try.
    ///
    /// The session keys are tried in addition to the key store, if
    /// it hasn't been disabled.
    pub fn add_session_keys(mut self,
                            session_keys: impl IntoIterator<Item=SessionKey>)
        -> Self
    {
        self.params.session_keys.extend(session_keys.into_iter());

        self
    }

    /// Decrypts the specified message with the configured parameters.
    ///
    /// Returns `Ok` if the message could be decrypted and verified.
    /// See [`verify::Builder`] for details.  By default, at least one
    /// signature needs to be authenticated.
    pub fn decrypt<'w, I, O, P>(self, input: I, output: O, prompt: P)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        O: Into<OptionalWriter<'w>>,
        P: prompt::Prompt,
    {
        let Builder {
            params,
            mut params_once,
        } = self;

        let mut report = verify::output::Report::new();
        let result = Self::decrypt_(
            &params, &mut params_once, input, output.into(), prompt,
            &mut report);

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
                // Stop immediately.
                return Err(err);
            }
        };

        stream.output(
            &params,
            Output::Report(output::Report {
                verification: report,
            }))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    fn decrypt_<'a, 'w, I, P>(params: &Params, params_once: &mut ParamsOnce,
                              input: I, mut output: OptionalWriter,
                              prompt: P, report: &mut verify::output::Report)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        P: prompt::Prompt,
    {
        let &Params {
            vparams: verify::Params {
                sequoia,
                signatures,
                ref designated_signers,
            },
            ref secret_keys,
            ref session_keys,
        } = params;
        let ParamsOnce {
            stream,
        } = params_once;

        let proxy: Rc<RefCell<Box<dyn verify::VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
                params: params,
            })));

        let mut helper = Helper::new(
            sequoia, signatures, designated_signers.clone(),
            secret_keys.clone(), session_keys.clone(), prompt,
            report);

        helper.stream = Some((Rc::clone(&proxy), params));
        helper.vhelper.stream = Some((proxy, Cow::Borrowed(&params.vparams)));

        DecryptorBuilder::from_reader(input)
            .map_err(op!())?
            .with_policy(sequoia.policy(), None, helper)
            .and_then(|mut decryptor| {
                io::copy(&mut decryptor, &mut output)?;
                Ok(())
            })
            .map_err(|err| {
                match err.downcast::<Error>() {
                    Ok(err) => {
                        err
                    }
                    Err(err) => {
                        Error::OperationalError(
                            error::OperationalError::Other(
                                Arc::new(err)))
                    }
                }
            })?;

        Ok(())
    }

    /// Decrypts the outer most encryption container with the
    /// configured parameters.
    ///
    /// Unlike [`Sequoia::decrypt`], this does not process the
    /// contents of the encryption container; it returns the content
    /// as is, which is often a signed message.
    ///
    /// Since this function does not process the content of the
    /// encryption container, it also does not verify the signatures.
    /// Thus, the signing policy parameters ([`Builder::signatures`]
    /// and [`Builder::add_designated_signer`]) are ignored.
    pub fn decrypt_unwrap<'w, I, O, P>(self,
                                       input: I, output: O,
                                       prompt: P)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        O: Into<OptionalWriter<'w>>,
        P: prompt::Prompt,
    {
        let Builder {
            params,
            mut params_once,
        } = self;

        let mut report = verify::output::Report::new();

        let result = Self::decrypt_unwrap_(
            &params, &mut params_once, input, output.into(), prompt,
            &mut report);

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
                // Stop immediately.
                return Err(err);
            }
        };

        stream.output(
            &params,
            Output::Report(output::Report {
                verification: report,
            }))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    fn decrypt_unwrap_<'w, I, P>(params: &Params, params_once: &mut ParamsOnce,
                                 input: I, mut output: OptionalWriter<'w>,
                                 prompt: P,
                                 report: &mut verify::output::Report)
        -> Result<(), Error>
    where
        I: std::io::Read + Send + Sync,
        P: prompt::Prompt,
    {
        let &Params {
            vparams: verify::Params {
                sequoia,
                signatures: _,
                designated_signers: _,
            },
            ref secret_keys,
            ref session_keys,
        } = params;
        let ParamsOnce {
            stream,
        } = params_once;

        let proxy: Rc<RefCell<Box<dyn verify::VerifyDecryptStream>>>
            = Rc::new(RefCell::new(Box::new(StreamProxy {
                stream: Box::new(stream),
                params: params,
            })));

        let mut helper = Helper::new(
            sequoia, 0, None,
            secret_keys.clone(), session_keys.clone(), prompt,
            report);

        helper.stream = Some((Rc::clone(&proxy), params));
        helper.vhelper.stream = Some((proxy, Cow::Borrowed(&params.vparams)));

        let mut ppr = PacketParser::from_reader(input).map_err(op!())?;

        let mut pkesks: Vec<packet::PKESK> = Vec::new();
        let mut skesks: Vec<packet::SKESK> = Vec::new();
        while let PacketParserResult::Some(mut pp) = ppr {
            let sym_algo_hint = match &pp.packet {
                Packet::SEIP(SEIP::V2(seip)) => Some(seip.symmetric_algo()),
                _ => None,
            };

            match pp.packet {
                Packet::SEIP(_) => {
                    {
                        let mut decrypt = |algo, secret: &crypto::SessionKey| {
                            pp.decrypt(algo, secret).is_ok()
                        };
                        helper.decrypt(&pkesks[..], &skesks[..], sym_algo_hint,
                                       &mut decrypt)
                            .map_err(|err| {
                                match err.downcast::<Error>() {
                                    Ok(err) => {
                                        err
                                    }
                                    Err(err) => {
                                        Error::OperationalError(
                                            error::OperationalError::Other(
                                                Arc::new(err)))
                                    }
                                }
                            })?;
                    }
                    if ! pp.processed() {
                        return Err(
                            Error::OperationalError(
                                error::OperationalError::InvalidSessionKey(
                                    error::InvalidSessionKey {
                                    })));
                    }

                    io::copy(&mut pp, &mut output).map_err(op!())?;
                    return Ok(());
                },
                #[allow(deprecated)]
                Packet::MDC(ref mdc) => if ! mdc.valid() {
                    return Err(
                        Error::OperationalError(
                            error::OperationalError::ManipulatedMessage(
                                error::ManipulatedMessage {
                                })));
                },
                _ => (),
            }

            let (p, ppr_tmp) = pp.recurse().map_err(op!())?;
            match p {
                Packet::PKESK(pkesk) => pkesks.push(pkesk),
                Packet::SKESK(skesk) => skesks.push(skesk),
                _ => (),
            }
            ppr = ppr_tmp;
        }

        Ok(())
    }
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// A key is locked, but not trying cached passwords, because the
    /// key may be protected by a retry counter.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct NotTryingCachedPasswords {
        pub key_handle: KeyHandle,
        pub userid: PreferredUserID,
        pub cert: Option<Cert>,
    }

    /// We decrypted a PKESK, but the session key was not able to
    /// decrypt the message.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct BadSessionKey {
        pub key_handle: KeyHandle,
        pub userid: PreferredUserID,
        pub cert: Option<Cert>,
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub struct KeyStoreUnreachable {
        pub error: anyhow::Error,
    }

    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum Info {
        /// A key is locked, but not trying cached passwords, because
        /// the key may be protected by a retry counter.
        #[error("{}, {} is locked, but not trying cached passwords, \
                 because the key may be protected by a retry counter.",
                .0.key_handle, .0.userid.display())]
        NotTryingCachedPasswords(NotTryingCachedPasswords),

        /// Decrypted a session key, but the session key was not able
        /// to decrypt the message.
        #[error("Unlocked {}, {}, but it failed to decrypt the message",
                .0.key_handle, .0.userid.display())]
        BadSessionKey(BadSessionKey),

        /// The key store is enabled, but we were unable to the
        /// connect to it.
        #[error("Warning: unable to connect to keystore: {}",
                .0.error)]
        KeyStoreUnreachable(KeyStoreUnreachable),
    }

    /// The certificate, SKESK, or session key that was used to decrypt
    /// the SEIPD packet.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub enum Decryptor {
        /// The certificate was used to decrypt the SEIPD packet.
        Cert(Cert, Key<key::PublicParts, key::UnspecifiedRole>),

        /// The key was used to decrypt the SEIPD packet.
        ///
        /// If the certificate is available, [`Decryptor::Cert`] will
        /// be returned.  However, it may happen that a key is on the
        /// key store, but the certificate is not in the certificate
        /// store.  In cases like this, this variant is returned.
        Key(Key<key::PublicParts, key::UnspecifiedRole>),

        /// The SKESK was used to decrypt the SEIPD packet.
        SKESK(SKESK),

        /// The preloaded-session key was used to decrypt the SEIPD
        /// packet.
        SessionKey(SessionKey),
    }

    /// The message was decrypted using the specified decryptor.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Decrypted {
        pub decryptor: Decryptor,
        pub session_key: crypto::SessionKey,
    }

    /// Information about the operation.
    ///
    /// This includes summary statistics.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        pub verification: verify::output::Report,
    }
}

/// The variants of this enum are the different types of output that
/// [`decrypt`](Builder::decrypt) and
/// [`decrypt_unwrap`](Builder::decrypt_unwrap) emit.
#[non_exhaustive]
#[derive(Debug)]
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

    /// Information emitted along the way.
    ///
    /// It may be possible to decrypt and authenticate a message, but
    /// there may still be diagnostics
    Info(output::Info),

    /// Emitted after the start of the message has been decrypted.
    ///
    /// This is emitted after the session key has been decrypted, and
    /// appears reasonable.  This is emitted before the content of the
    /// message is streamed.
    ///
    /// That this is emitted is not a guarantee that the operation
    /// will succeed.  In particular, if the message is truncated, the
    /// ciphertext is corrupted, or the authentication policy (as
    /// controlled by [`Builder::signatures`] and
    /// [`Builder::add_designated_signer`] isn't satisfied, this will be
    /// emitted and the operation will then fail.
    ///
    /// This will be emitted at most once.
    Decrypted(output::Decrypted),

    /// Information about an OpenPGP message's structure.
    ///
    /// This data structure contains information about an OpenPGP
    /// message's structure; it does not include the message's
    /// content.
    ///
    /// This will be emitted after the message has been decrypt, and
    /// if it contains a valid message.
    MessageStructure(verify::output::MessageStructure),

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
        VerificationArgumentError(verify::error::ArgumentError),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// The session key could not be decrypted, because we aren't able
    /// to decrypt one of the PKESKs or SKESKs.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(
        "Missing secret key material: {}",
        match (! .pkesks.is_empty(), ! .skesks.is_empty()) {
            (false, false) => {
                Cow::Borrowed(
                    "message does not contain any PKESKs or SKESKs")
            }
            (false, true) => {
                Cow::Borrowed("couldn't decrypt any of the SKESKs")
            },
            (true, skesks) => {
                Cow::Owned(format!(
                    "couldn't decrypt any of the PKESKs (recipients: {}){}",
                    .pkesks.iter()
                        .map(|pkesk| {
                            pkesk.recipient()
                                .map(|fpr| Cow::Owned(fpr.to_string()))
                                .unwrap_or_else(|| {
                                    Cow::Borrowed("anonymous recipient")
                                })
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    if skesks {
                        ",  or the SKESKs"
                    } else {
                        ""
                    }))
            },
        }
    )]
    pub struct MissingSecretKeyMaterial {
        pub pkesks: Vec<PKESK>,
        pub skesks: Vec<SKESK>,
    }

    /// Invalid session key.
    ///
    /// We got a session key by decrypting a PKESK or SKESK, but it
    /// failed to decrypt the encrypted packet.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Invalid session key")]
    pub struct InvalidSessionKey {
    }

    /// The message has been manipulated.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Message has been manipulated")]
    pub struct ManipulatedMessage {
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
        VerificationOperationalError(verify::error::OperationalError),

        #[error(transparent)]
        MissingSecretKeyMaterial(MissingSecretKeyMaterial),
        #[error(transparent)]
        InvalidSessionKey(InvalidSessionKey),
        #[error(transparent)]
        ManipulatedMessage(ManipulatedMessage),
        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to decrypting a message.
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

struct StreamProxy<'a> {
    stream: Box<dyn Stream + 'a>,
    params: &'a Params<'a>,
}

impl verify::Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &verify::Params, output: verify::Output)
        -> Result<()>
    {
        let output = match output {
            verify::Output::ArgumentError(err) => {
                Output::ArgumentError(
                    error::ArgumentError::VerificationArgumentError(
                        err))
            }
            verify::Output::OperationalError(err) => {
                Output::OperationalError(
                    error::OperationalError::VerificationOperationalError(
                        err))
            }
            verify::Output::SystemError(err) => {
                Output::SystemError(err)
            }
            verify::Output::Report(_) => {
                // The report is already saved in the Helper, and
                // we'll emit it later.
                return Ok(());
            },
            verify::Output::MessageStructure(s) => {
                Output::MessageStructure(s)
            },
        };
        Stream::output(&mut self.stream, self.params, output)
    }
}

impl Stream for StreamProxy<'_>
{
    fn output(&mut self, _params: &Params, output: Output) -> Result<()> {
        self.stream.output(self.params, output)
    }
}

pub(crate) struct Helper<'c>
{
    sequoia: &'c Sequoia,
    stream: Option<(Rc<RefCell<Box<dyn verify::VerifyDecryptStream + 'c>>>, &'c Params<'c>)>,
    vhelper: VerificationHelper<'c>,
    secret_keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>,
    key_identities: HashMap<KeyID, Arc<Cert>>,
    session_keys: Vec<SessionKey>,

    /// The fingerprint of the public key that we used to the decrypt
    /// the message.  If None and decryption was success then we
    /// decrypted it in some other way.
    decryptor: RefCell<Option<Fingerprint>>,

    prompt: Box<dyn prompt::Prompt + 'c>,
}

impl<'c> std::ops::Deref for Helper<'c> {
    type Target = VerificationHelper<'c>;

    fn deref(&self) -> &Self::Target {
        &self.vhelper
    }
}

impl<'c> std::ops::DerefMut for Helper<'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vhelper
    }
}

impl<'c> Helper<'c> {
    pub fn new<P>(sequoia: &'c Sequoia,
                  signatures: usize,
                  certs: Option<Vec<Cert>>,
                  secret_keys: Vec<Cert>,
                  session_keys: Vec<SessionKey>,
                  prompt: P,
                  report: &'c mut verify::output::Report)
        -> Self
    where
        P: prompt::Prompt + 'c
    {
        let mut keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>
            = HashMap::new();
        let mut identities: HashMap<KeyID, Arc<Cert>> = HashMap::new();
        for tsk in secret_keys {
            let cert = Arc::new(tsk.clone().strip_secret_key_material());
            for ka in tsk.keys().secret()
                // XXX: Should use the message's creation time that we do not know.
                .with_policy(sequoia.policy(), sequoia.time())
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                let key = ka.key();
                keys.insert(id.clone(), (tsk.clone(), key.clone()));
                identities.insert(id.clone(), cert.clone());
            }
        }

        Helper {
            sequoia: &sequoia,
            stream: None,
            vhelper: VerificationHelper::new(&sequoia, signatures, certs, report),
            secret_keys: keys,
            key_identities: identities,
            session_keys,
            decryptor: RefCell::new(None),
            prompt: Box::new(prompt),
        }
    }

    /// Emit some output.
    fn output(&self, output: Output) -> Result<()> {
        use std::ops::DerefMut;
        if let Some((stream, params)) = self.stream.as_ref() {
            let mut stream = stream.borrow_mut();
            Stream::output(stream.deref_mut().as_mut(), params, output)
        } else {
            Ok(())
        }
    }

    /// Checks if a session key can decrypt the packet parser using
    /// `decrypt`.
    fn try_session_key(&self, fpr: &Fingerprint,
                       algo: Option<SymmetricAlgorithm>, sk: &crypto::SessionKey,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                       -> Option<Option<Cert>>
    {
        if decrypt(algo, sk) {
            // XXX: make key identities map to certs, and failing that
            // look into the cert store.
            let cert = self.key_identities.get(&KeyID::from(fpr)).cloned();
            if let Some(cert) = &cert {
                // Prefer the reverse-mapped identity.
                self.decryptor.replace(Some(cert.fingerprint()));
            } else {
                // But fall back to the public key's fingerprint.
                self.decryptor.replace(Some(fpr.clone()));
            }

            Some(cert.map(|c| (*c).clone()))
        } else {
            None
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    ///
    /// The outer Result is the error returned by the output callback.
    fn try_decrypt(&self, pkesk: &PKESK,
                   sym_algo: Option<SymmetricAlgorithm>,
                   keypair: &mut dyn crypto::Decryptor,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
                   -> Result<Option<Option<Cert>>>
    {
        let fpr = keypair.public().fingerprint();
        let Some((sym_algo, sk)) = pkesk.decrypt(&mut *keypair, sym_algo) else {
            return Ok(None);
        };
        if let Some(decrypted) = self.try_session_key(&fpr, sym_algo, &sk, decrypt) {
            let output = if let Some(cert) = decrypted.as_ref() {
                Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::Cert(cert.clone(), keypair.public().clone()),
                    session_key: sk,
                })
            } else {
                Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::Key(keypair.public().clone()),
                    session_key: sk,
                })
            };
            self.output(output)?;

            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }
}

impl<'c> stream::VerificationHelper for Helper<'c> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'c> DecryptionHelper for Helper<'c> {
    fn decrypt(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &crypto::SessionKey) -> bool)
               -> openpgp::Result<Option<Cert>>
    {
        tracer!(TRACE, "DecryptionHelper::decrypt");
        t!("{} PKESKs, {} SKESKs", pkesks.len(), skesks.len());
        if pkesks.len() > 0 {
            t!("PKESKs: {}",
               pkesks
               .iter()
               .map(|pkesk| {
                   pkesk.recipient()
                       .map(|r| r.to_string())
                       .unwrap_or("wildcard".into())
               })
               .collect::<Vec<String>>()
               .join(", "));
        }

        // Before anything else, try the session keys
        t!("Trying the {} session keys", self.session_keys.len());
        for sk in &self.session_keys {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                decrypt(Some(sa), &sk.session_key)
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                (1u8..=19)
                    .map(SymmetricAlgorithm::from)
                    .any(|sa| decrypt(Some(sa), &sk.session_key))
            };
            if decrypted {
                self.output(Output::Decrypted(output::Decrypted {
                    decryptor: output::Decryptor::SessionKey(sk.clone()),
                    session_key: sk.session_key.clone(),
                }))?;
                return Ok(None);
            }
        }

        // Now, we try the secret keys that the user supplied on the
        // command line.

        // The outer Result is the error returned by the output callback.
        let mut decrypt_key = |slf: &Self, pkesk, cert, key: &Key<_, _>, may_prompt: bool| {
            let cancel_;
            let prompt: &Box<dyn prompt::Prompt> = if may_prompt {
                &slf.prompt
            } else {
                cancel_ = Box::new(prompt::Cancel::new()) as Box<dyn prompt::Prompt>;
                &cancel_
            };

            if let Ok(key) = slf.vhelper.sequoia()
                .decrypt_key(Some(cert), key.clone(), true, prompt)
            {
                let mut keypair = key.into_keypair()
                    .expect("decrypted secret key material");

                slf.try_decrypt(pkesk, sym_algo, &mut keypair, decrypt)
            } else {
                Ok(None)
            }
        };

        // First, we try those keys that we can use without prompting
        // for a password.
        t!("Trying the unencrypted PKESKs");
        for pkesk in pkesks {
            let keyid = pkesk.recipient().map(KeyID::from)
                .unwrap_or_else(KeyID::wildcard);
            if let Some((cert, key)) = self.secret_keys.get(&keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false)? {
                    return Ok(fp);
                }
            }
        }

        // Second, we try those keys that are encrypted.
        t!("Trying the encrypted PKESKs");
        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient().map(KeyID::from);
            if let Some((cert, key)) = keyid.as_ref()
                .and_then(|k| self.secret_keys.get(k))
            {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true)? {
                    return Ok(fp);
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        t!("Trying unencrypted PKESKs for wildcard recipient");
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false)? {
                    return Ok(fp);
                }
            }
        }

        // Fourth, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that are encrypted.
        t!("Trying encrypted PKESKs for wildcard recipient");
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true)? {
                    return Ok(fp);
                }
            }
        }

        // Try the key store.
        t!("Trying the key store");
        match self.vhelper.sequoia().key_store_or_else() {
            Ok(ks) => {
                t!("Connected to key store");

                let mut ks = ks.lock().unwrap();
                match ks.decrypt(&pkesks[..]) {
                    // Success!
                    Ok((_i, fpr, sym_algo, sk)) => {
                        t!("Key store unlocked session key using {}", fpr);

                        if let Some(fp) =
                            self.try_session_key(
                                &fpr, sym_algo, &sk, decrypt)
                        {
                            let keys = ks.find_key(KeyHandle::from(&fpr))
                                .with_context(|| {
                                    format!("Looking up {}", fpr)
                                })
                                .map_err(|err| {
                                    t!("Missing certificate for {}!", fpr);
                                    err
                                })?;
                            let Some(key) = keys.into_iter().next() else {
                                // find_key should never return an
                                // empty result.  Instead it should
                                // return an error.  But be tolerant,
                                // just in case.
                                return Err(anyhow::anyhow!("Key for {} not found", fpr));
                            };

                            t!("Decrypted session key");

                            self.output(
                                Output::Decrypted(output::Decrypted {
                                    decryptor: output::Decryptor::Key(
                                        key.public_key().clone()),
                                    session_key: sk,
                                }))?;

                            return Ok(fp);
                        }
                    }

                    Err(err) => {
                        match err.downcast() {
                            Ok(keystore::Error::InaccessibleDecryptionKey(keys)) => {
                                t!("Key store has {} locked keys.", keys.len());

                                // Get a reference to the softkeys backend.
                                let mut softkeys = if let Ok(backends) = ks.backends() {
                                    let mut softkeys = None;
                                    for mut backend in backends.into_iter() {
                                        if let Ok(id) = backend.id() {
                                            if id == "softkeys" {
                                                softkeys = Some(backend);
                                                break;
                                            }
                                        }
                                    }
                                    softkeys
                                } else {
                                    None
                                };

                                for key_status in keys.into_iter() {
                                    let pkesk = key_status.pkesk().clone();
                                    let mut key = key_status.into_key();
                                    let keyid = key.keyid();
                                    t!("{} is locked", keyid);
                                    let (userid, cert) = self.sequoia.best_userid_for(
                                        &KeyHandle::from(&keyid),
                                        KeyFlags::empty()
                                            .set_storage_encryption()
                                            .set_transport_encryption(),
                                        true);

                                    // If we have any cached
                                    // passwords, and the key is not
                                    // protected by a retry counter,
                                    // try the cached passwords.
                                    //
                                    // Right now, we only try the
                                    // password cache with keys
                                    // managed by the softkeys
                                    // backend, which we know are not
                                    // protected by a retry counter.
                                    // It would be better to query the
                                    // key, but the key store doesn't
                                    // expose that yet information yet
                                    // so we use this heuristic for
                                    // now.
                                    let password_cache = self.sequoia.cached_passwords()
                                        .collect::<Vec<_>>();
                                    if ! password_cache.is_empty() {
                                        // There's currently no way to
                                        // go from a key handle to the
                                        // backend.
                                        let mut on_softkeys = false;
                                        if let Some(softkeys) = softkeys.as_mut() {
                                            let devices = softkeys.devices();
                                            if let Ok(devices) = devices {
                                                for mut device in devices.into_iter() {
                                                    let keys = device.keys();
                                                    if let Ok(keys) = keys {
                                                        for mut a_key in keys.into_iter() {
                                                            if let Ok(a_id) = a_key.id() {
                                                                if key.id().ok() == Some(a_id) {
                                                                    // Same id.  We have a match.
                                                                    on_softkeys = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if on_softkeys {
                                            t!("{} is on the soft keys backend, \
                                                prompting user for the password",
                                               keyid);
                                            for password in password_cache.iter() {
                                                if let Ok(()) = key.unlock(password.clone()) {
                                                    if let Some(fp) = self.try_decrypt(
                                                        &pkesk, sym_algo, &mut key, decrypt)?
                                                    {
                                                        return Ok(fp);
                                                    }
                                                }
                                            }
                                        } else {
                                            t!("{} is NOT on the soft keys backend, \
                                                NOT prompting user for the password",
                                               keyid);

                                            self.output(Output::Info(output::Info::NotTryingCachedPasswords(
                                                output::NotTryingCachedPasswords {
                                                    key_handle: key.key_handle(),
                                                    userid: userid.clone(),
                                                    cert: cert.as_ref().ok().map(Clone::clone),
                                                })))?
                                        }
                                    }
                                    drop(password_cache);

                                    let mut context = prompt::ContextBuilder::password(
                                        prompt::Reason::UnlockKey)
                                        .sequoia(&self.vhelper.sequoia())
                                        .key(key.fingerprint());

                                    if let Ok(cert) = cert.as_ref() {
                                        context = context.cert(Cow::Borrowed(cert));
                                    }
                                    let mut context = context.build();

                                    let mut checker = CheckRemoteKey::optional(&mut key);

                                    match self.prompt.prompt(&mut context, &mut checker) {
                                        Ok(prompt::Response::Password(_)) => {
                                            t!("User entered a password for {}",
                                               keyid);
                                            if checker.unlocked() {
                                                if let Some(fp) = self.try_decrypt(
                                                    &pkesk, sym_algo, &mut key, decrypt)?
                                                {
                                                    t!("Key unlocked session key!");
                                                    return Ok(fp);
                                                } else {
                                                    t!("Key unlocked a BAD \
                                                        session key!");
                                                    self.output(Output::Info(output::Info::BadSessionKey(
                                                        output::BadSessionKey {
                                                            key_handle: key.key_handle(),
                                                            userid: userid.clone(),
                                                            cert: cert.as_ref().ok().map(Clone::clone),
                                                        })))?;
                                                }
                                            }
                                        }
                                        Ok(prompt::Response::NoPassword) => {
                                        }
                                        Err(prompt::Error::Cancelled(_)) => {
                                            t!("User cancelled the password prompt");
                                            // Skip.
                                        }
                                        Err(err) => {
                                            return Err(err).context(
                                                "Password prompt");
                                        }
                                    }

                                }
                            }
                            // Failed to decrypt using the keystore.
                            Ok(err) => {
                                t!("Failed to decrypt using key store: {}", err);
                            }
                            Err(err) => {
                                t!("Failed to decrypt using key store: {}", err);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                t!("Failed to connect to the key store: {}", err);
                self.output(Output::Info(output::Info::KeyStoreUnreachable(
                    output::KeyStoreUnreachable {
                        error: err.into(),
                    })))?;
            }
        }

        t!("Exhausted all decryption methods");

        if skesks.is_empty() {
            return Err(Error::OperationalError(
                error::OperationalError::MissingSecretKeyMaterial(
                    error::MissingSecretKeyMaterial {
                        pkesks: pkesks.to_vec(),
                        skesks: skesks.to_vec(),
                    })).into());
        }

        // Finally, try to decrypt using the SKESKs.  Before
        // prompting, try all passwords supplied on the cli.
        for password in self.sequoia.cached_passwords() {
            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    self.output(Output::Decrypted(output::Decrypted {
                        decryptor: output::Decryptor::SKESK(skesk.clone()),
                        session_key: sk,
                    }))?;
                    return Ok(None);
                }
            }
        }

        // Now prompt for passwords.
        let mut checker = CheckSkesks::new(skesks, decrypt);

        let mut context
            = prompt::ContextBuilder::password(
                prompt::Reason::DecryptMessage)
            .sequoia(&self.vhelper.sequoia())
            .build();
        let result = match self.prompt.prompt(&mut context, &mut checker) {
            Ok(prompt::Response::Password(p)) => {
                self.sequoia.cache_password(p);

                if let Some((i, sk)) = checker.resolve() {
                    self.output(Output::Decrypted(output::Decrypted {
                        decryptor: output::Decryptor::SKESK(skesks[i].clone()),
                        session_key: sk,
                    }))?;
                    Ok(None)
                } else {
                    // We shouldn't get here: if CheckSkesks returns a
                    // password, then it should also set sk.
                    Err(anyhow::anyhow!("Decryption failed."))
                }
            },
            Ok(prompt::Response::NoPassword)
                | Err(prompt::Error::Cancelled(_)) =>
            {
                return Err(error::OperationalError::MissingSecretKeyMaterial(
                    error::MissingSecretKeyMaterial {
                        pkesks: pkesks.to_vec(),
                        skesks: skesks.to_vec(),
                    }).into());
            }
            Err(err) => {
                Err(err).context("Password prompt")
            }
        };

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use crate::prompt::Cancel;

    // It's possible to decrypt, but then fail, if there are no valid
    // signatures.
    fn check(_sequoia: &Sequoia,
             output: &[Output],
             expect_decrypted: bool,
             expect_error: bool)
    {
        let mut saw_decrypted = false;
        let mut saw_message_structure = false;
        let mut saw_error = false;
        let mut saw_report = false;

        use Output::*;
        for output in output.into_iter() {
            match output {
                ArgumentError(err) => {
                    // No argument errors.
                    eprintln!("  - argument error: {}", err);
                    panic!("Argument error");
                }
                SystemError(err) => {
                    eprintln!("  - system error: {}", err);
                    // Currently system errors only happen at the
                    // beginning (although this is not part of the API
                    // contract).
                    assert!(! saw_error);
                    assert!(! saw_decrypted);
                    assert!(! saw_report);
                    saw_error = true;
                }
                OperationalError(err) => {
                    eprintln!("  - operational error: {}", err);
                    // An operational error can happen at any time.
                    assert!(! saw_error);
                    saw_error = true;
                }
                Info(info) => {
                    eprintln!("  - info: {:?}", info);
                    assert!(! saw_error);
                    assert!(! saw_report);
                }
                Decrypted(decrypted) => {
                    eprintln!("  - decrypted: {:?}", decrypted);
                    assert!(! saw_error);
                    assert!(! saw_decrypted);
                    assert!(! saw_message_structure);
                    assert!(! saw_report);
                    assert!(expect_decrypted);
                    saw_decrypted = true;
                }
                MessageStructure(structure) => {
                    eprintln!("  - message structure: {:?}", structure);
                    assert!(! saw_error);
                    assert!(saw_decrypted);
                    assert!(! saw_message_structure);
                    assert!(! saw_report);
                    assert!(saw_decrypted);

                    saw_message_structure = true;
                }
                Report(report) => {
                    eprintln!("  - report: {:?}", report);
                    assert!(! saw_report);
                    saw_report = true;
                }
            }
        }

        assert!((saw_decrypted && saw_message_structure)
                || saw_error);
        assert!(saw_report);

        assert_eq!(saw_decrypted, expect_decrypted);
        assert_eq!(saw_error, expect_error);
    }

    #[test]
    fn decrypt_no_signature() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let cert = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        const MESSAGE: &[u8] = b"message";

        let mut ciphertext = Vec::new();

        sq.encrypt()
            .add_recipient(cert.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                Cancel::new())
            .expect("can encrypt");

        let mut plaintext = Vec::new();
        let mut output = Vec::new();

        // Fail to decrypt, because, by default, we expect a valid
        // signature and the message is not signed.
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, true, true);

        // Successfully decrypt by not requiring a signature.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .signatures(0)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect("can decrypt");

        check(&sq, &output, true, false);
        assert_eq!(&plaintext, MESSAGE);
    }

    #[test]
    fn decrypt_unauthenticated_signer() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        // Bob will sign the message, but his certificate is not
        // authenticated.
        let bob = sq.key_generate()
            .email("bob@example.org")
            .without_password()
            .ephemeral()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        sq.key_import()
            .import_key(bob.clone())
            .expect("can import key");

        const MESSAGE: &[u8] = b"message";

        let mut ciphertext = Vec::new();

        sq.encrypt()
            .add_recipient(alice.clone())
            .add_signer(bob.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                Cancel::new())
            .expect("can encrypt");

        let mut plaintext = Vec::new();
        let mut output = Vec::new();

        // Fail to decrypt, because we expect a valid signature, but
        // the signer is not authenticated.
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, true, true);

        // Successfully decrypt by designating the signer.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .add_designated_signer(bob.clone())
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect("can decrypt");

        check(&sq, &output, true, false);
        assert_eq!(&plaintext, MESSAGE);
    }

    #[test]
    fn decrypt_authenticated_signer() {
        // This is the reverse the previous test: there, the signer is
        // not authenticated on the key store.  Here they are.

        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        let bob = sq.key_generate()
            .email("bob@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        const MESSAGE: &[u8] = b"message";

        let mut ciphertext = Vec::new();

        sq.encrypt()
            .add_recipient(alice.clone())
            .add_signer(bob.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                Cancel::new())
            .expect("can encrypt");

        let mut plaintext = Vec::new();
        let mut output = Vec::new();

        // Decrypt, because we expect a valid signature, and we can
        // authenticate it with an authenticated certificate in the
        // cert store.
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect("can decrypt");
        check(&sq, &output, true, false);
        assert_eq!(&plaintext, MESSAGE);

        // Fail to decrypt by designating the wrong signer.  If we
        // designate a signer then we don't use the certificate store.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .add_designated_signer(alice.clone())
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");

        // Fail to decrypt by designating the empty set of signers.
        // If we designate a signer then we don't use the certificate
        // store.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .add_designated_signers(std::iter::empty())
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");

        check(&sq, &output, true, true);
    }

    #[test]
    fn decrypt_no_cert() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        const MESSAGE: &str = "message";

        let mut ciphertext = Vec::new();

        sq.encrypt()
            .add_recipient(alice.clone())
            .encrypt(
                std::io::Cursor::new(MESSAGE),
                &mut ciphertext,
                Cancel::new())
            .expect("can encrypt");

        let mut plaintext = Vec::new();
        let mut output = Vec::new();

        // Fail to decrypt, because we expect a valid signature, but
        // there is none.
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, true, true);

        // Extract the session key.
        let session_key = output.into_iter()
            .find_map(|o| {
                if let Output::Decrypted(output::Decrypted { session_key, .. }) = o {
                    Some(session_key)
                } else {
                    None
                }
            })
            .expect("have session key");

        eprintln!("orig home: {:?}",
                  sq.home);

        // Create a new context so that we don't have the key.
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
        eprintln!("home: {:?}",
                  sq.home);

        // Without the key, we can't decrypt the message.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, false, true);

        // Unless we have the session key.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .add_session_key(session_key.into())
            .signatures(0)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect("can decrypt");
        check(&sq, &output, true, false);

        // But not if we have the WRONG session key.
        let session_key = SessionKey::from_str("001122334455667788001122334455667788")
            .expect("valid session key");

        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .add_session_key(session_key.into())
            .signatures(0)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, false, true);
    }

    #[test]
    fn decrypt_manipulated_message() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        // A big message.
        let message: Vec<u8> = vec![0x42; 10 * 1024 * 1024];

        let mut ciphertext = Vec::new();

        sq.encrypt()
            .add_recipient(alice.clone())
            .encrypt(
                std::io::Cursor::new(&message),
                &mut ciphertext,
                Cancel::new())
            .expect("can encrypt");

        // Make sure we can decrypt the message.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .signatures(0)
            .decrypt(
                std::io::Cursor::new(&ciphertext),
                &mut plaintext,
                Cancel::new())
            .expect("can decrypt");
        check(&sq, &output, true, false);
        assert_eq!(&message, &plaintext);

        // Corrupt the message towards the end so that Decrypted will
        // still be omitted.
        let mut corrupted = ciphertext.clone();
        let i = corrupted.len() * 95 / 100;
        corrupted[i] = corrupted[i].wrapping_add(1);

        // Decryption should now fail.
        let mut plaintext = Vec::new();
        let mut output = Vec::new();
        sq.decrypt()
            .stream(&mut output)
            .decrypt(
                std::io::Cursor::new(&corrupted),
                &mut plaintext,
                Cancel::new())
            .expect_err("fail to decrypt");
        check(&sq, &output, true, true);
    }
}
