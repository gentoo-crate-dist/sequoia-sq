//! Functionality for importing keys.
//!
//! A key is a certificate with secret key material.  When using
//! [`Sequoia::cert_import`] to import a certificate, any secret key
//! material is silently ignored.  The functionality here first
//! imports the secret key material into the key store, and then
//! imports the certificate into the certificate store.
//!
//! # Examples
//!
//! Import keys from an OpenPGP keyring using
//! [`Builder::import_keyring`].  Note: this function only returns an
//! error if the file is unreadable or the key store is not available.
//! To check if an error occurred while importing an individual key,
//! you need to examine the returned [`Outcome`] (shown here) or the
//! [`Stream`] output (see next example):
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
//! # alice.as_tsk().serialize(&mut input).unwrap();
//! #
//! # let mut input = std::io::Cursor::new(&input[..]);
//! #
//! match sq.key_import().import_keyring(input) {
//!     Err(err) => eprintln!("Importing keyring: {}", err),
//!     Ok(outcome) => {
//!         for failure in outcome.importing_failed {
//!             eprintln!("Importing key: {}", failure.error);
//!         }
//!     }
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
//! use sequoia::key::import::Output;
//! use sequoia::key::import::output::*;
//! use sequoia::key::import;
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
//! # alice.as_tsk().serialize(&mut input).unwrap();
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
//!               output: import::Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             Output::Imported(Imported { cert, .. }) => {
//!                 eprintln!("Imported {}", cert.fingerprint());
//!             }
//!             Output::ImportingFailed(ImportingFailed { error, .. }) => {
//!                 eprintln!("Importing key: {}", error);
//!             }
//!             Output::Report(Report { stats, ..}) => {
//!                 eprintln!("New {}, updated: {}, unchanged: {}, errors: {}",
//!                           stats.keys.new,
//!                           stats.keys.updated,
//!                           stats.keys.unchanged,
//!                           stats.keys.errors);
//!                 # assert_eq!(stats.keys.new, 1);
//!                 # assert_eq!(stats.keys.errors, 0);
//!             }
//!             _ => (),
//!         }
//!
//!         // Return an error to abort processing.
//!         Ok(())
//!     }
//! }
//!
//! let mut stream = Stream { };
//! if let Err(err) = sq.key_import()
//!     .stream(&mut stream)
//!     .import_keyring(input)
//! {
//!     eprintln!("Importing keyring: {}", err);
//! }
//! # Ok(()) }
//! ```

use std::borrow::Cow;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::cert::CertParser;
use openpgp::cert::raw::RawCert;
use openpgp::parse::Parse;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use sequoia_keystore as keystore;
use keystore::Backend;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::types::import_stats::ImportStats;
use crate::types::import_stats::ImportStatus;

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

    /// We failed to parse the input.
    ///
    /// Note: If we were unable to parse an individual artifact, then
    /// we emit [`ImportError::BrokenCert`].
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Parse error")]
    pub struct ParseError {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// Information about a broken certificate.
    ///
    /// If `cert` is `None`, then we expected a certificate and found
    /// junk.  If `cert` is `Some`, we were able to parse some bytes
    /// into something that resembles a certificate, but the
    /// certificate is corrupted.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{}",
            if let Some(cert) = .cert.as_ref() {
                Cow::Owned(format!(
                    "Parsing certificate {}", cert.fingerprint()))
            } else {
                Cow::Borrowed("Error parsing input")
            })]
    pub struct BrokenCert {
        pub cert: Option<RawCert<'static>>,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// The certificate does not contain any secret key material.
    ///
    /// If the certificate does not contain secret key material, then
    /// there is nothing to import.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{} does not contain any secret key material",
            .cert.fingerprint())]
    pub struct MissingSecretKeyMaterial {
        pub cert: Cert,
    }

    /// The certificate store is disabled.
    ///
    /// Note: we don't use [`SystemError::CertStoreDisabled`], because
    /// this is not a fatal error.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("No certificate store")]
    pub struct NoCertStore {
        pub cert: Cert,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// An error occurred while importing the certificate into the
    /// certificate store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Importing {}", cert.fingerprint())]
    pub struct ImportingCert {
        pub cert: Cert,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// We failed to import something.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error(transparent)]
    pub enum ImportError {
        /// We failed to parse the input.
        ///
        /// Note: If we were unable to parse an individual
        /// certificate, then we emit [`ImportError::BrokenCert`].
        ParseError(ParseError),

        /// An artifact is broken.
        BrokenCert(BrokenCert),

        /// The certificate does not contain any secret key material.
        MissingSecretKeyMaterial(MissingSecretKeyMaterial),

        /// The certificate store is disabled.
        NoCertStore(NoCertStore),

        /// We tried to import an otherwise valid certificate into the
        /// certificate store, but failed.
        ImportingCert(ImportingCert),
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
        ImportError(ImportError),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to importing keys.
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

    /// We imported a key.
    #[non_exhaustive]
    #[derive(Debug, Clone)]
    pub struct Imported {
        /// What we imported.
        pub cert: Cert,

        /// The merged certificate on the certificate store.
        ///
        /// This is the result after merging the certificate with any
        /// existing certificate in the certificate store.  Note:
        /// secret key material will have been stripped.
        ///
        /// If merging into the key store succeeds, but merging into
        /// the certificate store fails, we emit [`Imported`] and set
        /// this to the error.
        pub merged: Result<Cert, error::ImportError>,

        pub cert_import_status: ImportStatus,

        /// The keys and their import status.
        pub key_import_status: Vec<(Fingerprint, ImportStatus)>,
    }

    /// We failed to import a key.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
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
    #[derive(Debug)]
    pub struct Report {
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

    /// Emitted after the key being imported was successfully imported
    /// to the key store.
    Imported(output::Imported),

    /// Emitted when the key can't be imported to the key store.
    ImportingFailed(output::ImportingFailed),

    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is imported or not.
    Report(output::Report),
}

/// The outcome of importing keys.
///
/// This is returned by [`Builder::import_keyring`],
/// [`Builder::import_keys`], and [`Builder::import_key`].  It
/// contains information about the outcome.  More detailed information
/// is available via the [`Stream`] interface.
#[derive(Debug)]
pub struct Outcome {
    /// The imported keys.
    pub imported: Vec<output::Imported>,
    /// The import failures.
    pub importing_failed: Vec<output::ImportingFailed>,
    /// Statistics.
    pub stats: ImportStats,
}

impl Outcome {
    fn new() -> Self {
        Outcome {
            imported: Vec::new(),
            importing_failed: Vec::new(),
            stats: Default::default(),
        }
    }

    fn to_report(&self) -> output::Report {
        output::Report {
            stats: self.stats.clone(),
        }
    }

    /// Returns whether all keys were imported.
    ///
    /// If one or more keys were not imported, returns one of the
    /// errors.  This does not check if the certificates were also
    /// imported into the certificate store.
    pub fn all_imported(&self) -> Result<()> {
        self.importing_failed
            .first()
            .map_or(Ok(()),
                    |failure| {
                        Err(failure.error.clone().into())
                    })
    }
}

/// The key import parameters.
///
/// These parameters are used by [`key_import`](Builder::key_import).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }
}

/// Owned parameters.
struct ParamsOnce<'stream> {
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Imports keys.
///
/// A builder providing control over how to import keys.
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

    /// Report that importing something failed.
    ///
    /// This also increments the stats, if appropriate.
    fn report_failure<'a>(params: &Params,
                          params_once: &mut ParamsOnce,
                          error: error::ImportError,
                          outcome: &mut Outcome)
        -> Result<(), Error>
    {
        let ParamsOnce {
            stream,
        } = params_once;

        outcome.importing_failed.push(output::ImportingFailed {
            error: error.clone(),
        });

        if matches!(error,
                    error::ImportError::BrokenCert(_)
                    | error::ImportError::MissingSecretKeyMaterial(_)
                    | error::ImportError::ImportingCert(_))
        {
            outcome.stats.keys.errors += 1;
            outcome.stats.certs.inc_errors();
        }
        stream.output(
            params,
            Output::ImportingFailed(output::ImportingFailed {
                error,
            }))
            .map_err(|err| Error::StreamOutputError(err))?;

        Ok(())
    }

    /// Returns the soft keys backend.
    fn softkeys(params: &Params) -> Result<Backend, Error>
    {
        let sequoia = params.sequoia;

        let keystore = sequoia.key_store_or_else()
            .map_err(|err| Error::SystemError(err))?;

        let mut keystore = keystore.lock().unwrap();

        let softkeys = || {
            let mut softkeys = None;
            for mut backend in keystore.backends()?.into_iter() {
                if backend.id()? == "softkeys" {
                    softkeys = Some(backend);
                    break;
                }
            }

            drop(keystore);

            if let Some(softkeys) = softkeys {
                Ok(softkeys)
            } else {
                Err(anyhow::anyhow!("softkeys backend is not configured"))
            }
        };

        softkeys()
            .map_err(|err| {
                Error::SystemError(SystemError::KeyStoreError(Arc::new(err)))
            })
    }

    /// Imports keys from an OpenPGP keyring into the store.
    ///
    /// This function imports keys from an OpenPGP keyring into the
    /// key store.  If a key can be imported, then the certificate is
    /// also imported into the certificate store.  Whether the latter
    /// succeeds can be determined by examining the
    /// [`output::Imported::merged`](output::Imported) field.  If the
    /// key cannot be imported, e.g., because it does not contain any
    /// secret key material, the certificate is not imported into the
    /// certificate store.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring.  If the OpenPGP keyring contains recoverable errors,
    /// these are reported using [`Output::ImportingFailed`], but parsing
    /// is not aborted.
    ///
    /// This function returns an error if the input is not an OpenPGP
    /// keyring.  (Note: an empty file is consider a valid keyring.)
    ///
    /// Recoverable errors, such as failing to import a key into the
    /// store, a certificate being corrupted, or a certificate not
    /// containing any secret key material do not cause this function
    /// to return an error.  These errors are reported using
    /// [`Output::ImportingFailed`].  Parsing is not aborted.  An
    /// example of a recoverable error is a keyring that contains two
    /// valid certificates and a corrupted certificate.  Unless the
    /// corrupted certificate is at the start of the file and is so
    /// corrupted that the input is not recognizable as a keyring,
    /// this function will not return an error; it will import the
    /// other two certificates, and emit [`Output::ImportingFailed`]
    /// for the corrupted certificate.
    pub fn import_keyring<'a, I>(mut self, mut input: I)
        -> Result<Outcome, Error>
    where
        I: std::io::Read + Send + Sync + 'a,
    {
        let mut outcome = Outcome::new();

        let result = Self::import_keyring_(
            &self.params, &mut self.params_once, &mut input,
            &mut outcome);

        let report = outcome.to_report();

        let mut stream = self.params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
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
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    fn import_keyring_<'a>(params: &Params, params_once: &mut ParamsOnce,
                           input: &mut (dyn std::io::Read + Send + Sync + 'a),
                           outcome: &mut Outcome)
        -> Result<(), Error>
    {
        let parser = match CertParser::from_reader(input) {
            Ok(parser) => parser,
            Err(err) => {
                let err = error::ImportError::ParseError(
                    error::ParseError {
                        error: err.into(),
                    });

                Self::report_failure(
                    params, params_once, err.clone(), outcome)?;

                return Err(Error::OperationalError(
                    error::OperationalError::ImportError(err)));
            }
        };

        let mut softkeys = Self::softkeys(params)?;

        for r in parser {
            let cert = match r {
                Ok(cert) => cert,
                Err(err) => {
                    // Error parsing a key.
                    let err = error::ImportError::BrokenCert(
                        error::BrokenCert {
                            cert: None,
                            error: Arc::new(err),
                        });

                    Self::report_failure(
                        params, params_once, err, outcome)?;

                    continue;
                }
            };

            match Self::import_key_(params, params_once,
                                    &mut softkeys, cert, outcome)
            {
                Ok(imported) => {
                    // As long as we can import to the key store, we
                    // return Imported.

                    params_once.stream.output(
                        params,
                        Output::Imported(imported))
                        .map_err(|err| Error::StreamOutputError(err))?;
                }
                Err(_err) => {
                    // The error was already emitted.
                }
            }
        }

        Ok(())
    }

    /// Imports keys into the store.
    ///
    /// This function imports the specified keys into the key store.
    /// If a key can be imported, then the certificate is also
    /// imported into the certificate store.  Whether the latter
    /// succeeds can be determined by examining the
    /// [`output::Imported::merged`](output::Imported) field.  If the
    /// key cannot be imported, e.g., because it does not contain any
    /// secret key material, the certificate is not imported into the
    /// certificate store.
    ///
    /// If importing a key results in a recoverable error, that error
    /// is reported using [`Output::ImportingFailed`], but **importing
    /// is not aborted**, and the function does not return an error.
    /// If you need to check whether importing a key failed, use a
    /// [`Stream`](Builder::stream).
    ///
    /// **Note: these semantics are different from
    /// [`Builder::import_key`], which directly returns import
    /// errors.**
    pub fn import_keys<I>(mut self, certs: I)
        -> Result<Outcome, Error>
    where
        I: IntoIterator<Item=Cert>
    {
        let mut outcome = Outcome::new();

        let mut certs = certs.into_iter();

        let mut import_error = None;

        let result = Self::import_keys_(
            &self.params, &mut self.params_once, &mut certs, &mut outcome,
            &mut import_error);

        let report = outcome.to_report();

        let mut stream = self.params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(outcome)
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
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Imports a key into the store.
    ///
    /// This function imports the specified key into the key store.
    /// If the key can be imported, then the certificate is also
    /// imported into the certificate store.  Whether the latter
    /// succeeds can be determined by examining the
    /// [`output::Imported::merged`](output::Imported) field.  If the
    /// key cannot be imported, e.g., because it does not contain any
    /// secret key material, the certificate is not imported into the
    /// certificate store.
    ///
    /// If importing a key results in an error, that error is reported
    /// using [`Output::ImportingFailed`], and the function returns an
    /// error.  **Note: these semantics are different from
    /// [`Builder::import_keys`] and [`Builder::import_keyring`],
    /// which only return import errors via the stream interface.**
    pub fn import_key(mut self, cert: Cert)
        -> Result<Outcome, Error>
    {
        let mut outcome = Outcome::new();

        let mut certs = Some(cert).into_iter();

        let mut import_error = None;

        let result = Self::import_keys_(
            &self.params, &mut self.params_once, &mut certs,
            &mut outcome, &mut import_error);

        let report = outcome.to_report();

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
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result?;

        if let Some(err) = import_error {
            Err(err)
        } else {
            Ok(outcome)
        }
    }

    fn import_keys_(params: &Params, params_once: &mut ParamsOnce,
                    certs: &mut dyn Iterator<Item=Cert>,
                    outcome: &mut Outcome,
                    import_error: &mut Option<Error>)
        -> Result<(), Error>
    {
        let mut softkeys = Self::softkeys(params)?;

        for cert in certs.into_iter() {
            match Self::import_key_(params, params_once,
                                    &mut softkeys, cert, outcome)
            {
                Ok(imported) => {
                    // As long as we can import to the key store, we
                    // return Imported.
                    params_once.stream.output(
                        params,
                        Output::Imported(imported))
                        .map_err(|err| Error::StreamOutputError(err))?;
                }
                Err(err) => {
                    // Error importing the key.

                    if import_error.is_none() {
                        *import_error = Some(err);
                    }
                }
            }
        }

        Ok(())
    }

    fn import_key_(params: &Params, params_once: &mut ParamsOnce,
                   softkeys: &mut Backend, cert: Cert, outcome: &mut Outcome)
        -> Result<output::Imported, Error>
    {
        let Params {
            sequoia,
        } = params;

        if ! cert.is_tsk() {
            // No secret key material.
            let err = error::ImportError::MissingSecretKeyMaterial(
                error::MissingSecretKeyMaterial {
                    cert,
                });
            Self::report_failure(
                params, params_once, err.clone(), outcome)?;

            return Err(Error::OperationalError(
                error::OperationalError::ImportError(err)));
        }


        let result = match softkeys.import(&cert) {
            Ok(result) => result,
            Err(err) => {
                let err = Arc::new(err);

                return Err(Error::SystemError(
                    SystemError::KeyStoreError(err)));
            }
        };

        let mut key_import_status = Vec::with_capacity(result.len());
        let mut import_status = ImportStatus::Unchanged;
        for (s, key) in result.into_iter() {
            let s: ImportStatus = s.into();

            import_status = import_status.max(s.clone());

            key_import_status.push((key.fingerprint(), s));
        }

        match import_status {
            ImportStatus::New => outcome.stats.keys.new += 1,
            ImportStatus::Unchanged => outcome.stats.keys.unchanged += 1,
            ImportStatus::Updated => outcome.stats.keys.updated += 1,
        }

        // Also insert the certificate into the certificate store.
        // If we can't, we don't fail.  This allows, in
        // particular, `sq --cert-store=none key import` to work.
        let cert = cert.strip_secret_key_material();
        let cert = Arc::new(LazyCert::from(cert));

        let mut cert_import_status = ImportStatus::Unchanged;
        let merged = match sequoia.cert_store_or_else() {
            Ok(cert_store) => {
                let new_certs = outcome.stats.certs.new_certs();
                let updated_certs = outcome.stats.certs.updated_certs();

                match cert_store.update_by(Arc::clone(&cert), &outcome.stats) {
                    Ok(merged) => {
                        let merged = Arc::unwrap_or_clone(merged)
                            .into_cert().expect("is a cert");

                        if outcome.stats.certs.new_certs() > new_certs {
                            cert_import_status = ImportStatus::New;
                        } else if outcome.stats.certs.updated_certs() > updated_certs {
                            cert_import_status = ImportStatus::Updated;
                        }

                        Ok(merged)
                    }
                    Err(err) => {
                        let cert = Arc::unwrap_or_clone(cert.clone())
                            .into_cert().expect("is a cert");

                        let err = error::ImportError::ImportingCert(
                            error::ImportingCert {
                                cert,
                                error: err.into(),
                            });

                        // We do not call report_failure: the
                        // certificate import error is returned in the
                        // `Imported` event.

                        Err(err)
                    }
                }
            }
            Err(err) => {
                // No cert store.
                outcome.stats.certs.inc_errors();

                // We do not call report_failure: the certificate
                // import error is returned in the `Imported` event.

                let cert = Arc::unwrap_or_clone(cert.clone())
                    .into_cert().expect("is a cert");

                Err(error::ImportError::NoCertStore(
                    error::NoCertStore {
                        cert,
                        error: Arc::new(anyhow::Error::from(err)),
                    }))
            }
        };

        let output = output::Imported {
            cert: Arc::unwrap_or_clone(cert)
                .into_cert().expect("is a cert"),
            merged,
            key_import_status,
            cert_import_status,
        };

        outcome.imported.push(output.clone());

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use openpgp::cert::CertBuilder;
    use openpgp::serialize::Serialize;

    fn check(output: Vec<Output>, result: Result<Outcome, Error>,
             imports_expected: usize, errors_expected: usize)
    {
        let mut saw_error = None;
        let mut saw_report = false;
        let mut imports_count = 0;
        let mut errors_count = 0;

        eprintln!("Start of import");
        for o in output.iter() {
            match o {
                Output::ArgumentError(err) => {
                    // No argument errors.
                    eprintln!("  - argument error: {}", err);
                    assert!(saw_error.is_none());
                    saw_error = Some(err.to_string());
                    assert!(! saw_report);
                }
                Output::SystemError(err) => {
                    eprintln!("  - system error: {}", err);
                    assert!(saw_error.is_none());
                    saw_error = Some(err.to_string());
                    assert!(! saw_report);
                }
                Output::OperationalError(err) => {
                    eprintln!("  - operational error: {}", err);
                    // An operational error can happen at any time.
                    assert!(saw_error.is_none());
                    saw_error = Some(err.to_string());
                    assert!(! saw_report);
                }

                Output::Imported(_) => {
                    assert!(saw_error.is_none());
                    assert!(! saw_report);
                    eprintln!("- Imported");
                    imports_count += 1;
                }
                Output::ImportingFailed(failure) => {
                    assert!(saw_error.is_none());
                    assert!(! saw_report);
                    eprintln!("- ImportingFailed: {}", failure);
                    match failure.error {
                        error::ImportError::BrokenCert(_)
                            | error::ImportError::MissingSecretKeyMaterial(_)
                            | error::ImportError::ImportingCert(_)=>
                        {
                            errors_count += 1;
                        }
                        _ => (),
                    }
                }
                Output::Report(report) => {
                    eprintln!("- Report");
                    assert!(! saw_report);
                    saw_report = true;

                    eprintln!("  Imported {}, updated {}, \
                               {} unchanged, {} errors.",
                              report.stats.keys.new,
                              report.stats.keys.updated,
                              report.stats.keys.unchanged,
                              report.stats.keys.errors);

                    let stats_imported = report.stats.keys.new
                        + report.stats.keys.unchanged
                        + report.stats.keys.updated;
                    assert_eq!(stats_imported,
                               imports_count,
                               "imports: stats: {}; count: {}",
                               stats_imported, imports_count);
                    assert_eq!(report.stats.keys.errors,
                               errors_count,
                               "errors: stats {}; count: {}",
                               report.stats.keys.errors, errors_count);

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
                assert_eq!(errors_expected, 0, "expected errors vs returned");
                assert_eq!(errors_count, 0, "counted errors vs expected");

            }
            (Ok(outcome), None) => {
                assert_eq!(imports_expected, outcome.imported.len());
                assert_eq!(errors_expected, outcome.importing_failed.len());
            }
        }
    }

    #[test]
    fn import_keyring() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(b""));

        assert!(result.is_ok());
        check(output, result, 0, 0);

        // Junk.
        let input = vec![b'!'; 16 * 1024];
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input));

        assert!(result.is_err());
        check(output, result, 0, 0);

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        // Import Alice's certificate (not key!).
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 0, 1);

        // Import Alice's key.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 1, 0);

        // Import Alice's and Bob's keys.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 2, 0);

        // Import Alice's cert and Bob's key.
        let mut input = Vec::new();
        alice.serialize(&mut input).unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 1, 1);

        // Add some junk in between and try again.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        write!(&mut input, "foobar").unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream( &mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 2, 1);
    }

    #[test]
    fn import_keyring_no_cert_store() {
        // Disable the certificate store.  We should still be able to
        // import keys.
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
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_ok());
        check(output, result, 1, 0);
    }

    #[test]
    fn import_keyring_no_key_store() {
        // Disable the key store.  We shouldn't be able to import
        // keys.
        let sq = Sequoia::builder()
            .ephemeral().unwrap()
            .key_store_path(crate::StateDirectory::None)
            .build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        // Import Alice's key.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(output, result, 0, 0);

        // Import Alice's and Bob's keys.
        let mut input = Vec::new();
        alice.as_tsk().serialize(&mut input).unwrap();
        bob.as_tsk().serialize(&mut input).unwrap();
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keyring(std::io::Cursor::new(&input[..]));

        assert!(result.is_err());
        check(output, result, 0, 0);
    }

    #[test]
    fn import_keys() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Empty file.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([]);

        assert!(result.is_ok());
        check(output, result, 0, 0);

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let alice_pub = alice.clone().strip_secret_key_material();
        assert!(alice.is_tsk());
        assert!(! alice_pub.is_tsk());

        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();
        let bob_pub = bob.clone().strip_secret_key_material();
        assert!(bob.is_tsk());
        assert!(! bob_pub.is_tsk());

        // Import Alice's certificate (not key!).
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice_pub.clone() ]);

        assert!(result.is_ok());
        check(output, result, 0, 1);

        // Import Alice's key.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice.clone() ]);

        assert!(result.is_ok());
        check(output, result, 1, 0);

        // Import Alice's and Bob's keys.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice.clone(), bob.clone() ]);

        assert!(result.is_ok());
        check(output, result, 2, 0);

        // Import Alice's cert and Bob's key.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice_pub.clone(), bob.clone() ]);

        assert!(result.is_ok());
        check(output, result, 1, 1);
    }

    #[test]
    fn import_keys_no_cert_store() {
        // Disable the certificate store.  We should still be able to
        // import keys.
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
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice.clone() ]);

        assert!(result.is_ok());
        check(output, result, 1, 0);
    }

    #[test]
    fn import_keys_no_key_store() {
        // Disable the key store.  We shouldn't be able to import
        // keys.
        let sq = Sequoia::builder()
            .ephemeral().unwrap()
            .key_store_path(crate::StateDirectory::None)
            .build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let (bob, _bob_rev) = CertBuilder::new()
            .add_userid("<bob@example.org>")
            .generate()
            .unwrap();

        // Import Alice's key.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice.clone() ]);

        assert!(result.is_err());
        check(output, result, 0, 0);

        // Import Alice's and Bob's keys.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_keys([ alice.clone(), bob.clone() ]);

        assert!(result.is_err());
        check(output, result, 0, 0);
    }

    #[test]
    fn import_key() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();
        let alice_pub = alice.clone().strip_secret_key_material();
        assert!(alice.is_tsk());
        assert!(! alice_pub.is_tsk());

        // Import Alice's certificate (not key!).
        let mut output = Vec::new();
        let err = sq.key_import()
            .stream(&mut output)
            .import_key(alice_pub.clone())
            .expect_err("failure");

        // We need to fabricate an Outcome as unlike the other
        // functions `key_import` returns soft errors directly.

        let Error::OperationalError(error::OperationalError::ImportError(err))
            = err else {
                panic!("Expect an import error error, got: {:?}", err);
            };

        let mut outcome = Outcome {
            imported: Vec::new(),
            importing_failed: vec![ output::ImportingFailed { error: err } ],
            stats: Default::default(),
        };
        outcome.stats.keys.errors += 1;

        check(output, Ok(outcome), 0, 1);

        // Import Alice's key.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_key(alice.clone());

        assert!(result.is_ok());
        check(output, result, 1, 0);
    }

    #[test]
    fn import_key_no_cert_store() {
        // Disable the certificate store.  We should still be able to
        // import keys.
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
        let result = sq.key_import()
            .stream(&mut output)
            .import_key(alice.clone());

        assert!(result.is_ok());
        check(output, result, 1, 0);
    }

    #[test]
    fn import_key_no_key_store() {
        // Disable the key store.  We shouldn't be able to import
        // keys.
        let sq = Sequoia::builder()
            .ephemeral().unwrap()
            .key_store_path(crate::StateDirectory::None)
            .build().unwrap();

        let (alice, _alice_rev) = CertBuilder::new()
            .add_userid("<alice@example.org>")
            .generate()
            .unwrap();

        // Import Alice's key.
        let mut output = Vec::new();
        let result = sq.key_import()
            .stream(&mut output)
            .import_key(alice.clone());

        assert!(result.is_err());
        check(output, result, 0, 0);
    }
}
