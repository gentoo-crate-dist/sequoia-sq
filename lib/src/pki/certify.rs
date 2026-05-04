//! Functionality for certifying user IDs.
//!
//! After Alice convinces herself that a given certificate belongs to
//! Bob, she can create a certification that says as much.  Her
//! software can use this to find the right certificate for Bob in the
//! future.  If she decides, she can also share the certification with
//! other people.  If they are willing to rely on her, they can use
//! her certification to help them find the right certificate for Bob.
//!
//! A good starting point for understanding how to use this
//! functionality is to start with [`Sequoia::pki_certify`], and
//! [`Builder`].
//!
//! # Examples
//!
//! Alice certifies Bob's certificate:
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
//! # let (bob, _bob_rev) = CertBuilder::new()
//! #     .add_userid("<bob@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! if let Err(err) = sq
//!     .pki_certify()
//!     .certify(
//!         &alice,
//!         &bob,
//!         &["<bob@example.org>".into()],
//!         (),
//!         Cancel::new(),
//!         None)
//! {
//!     eprintln!("Failed to certify the user ID: {}", err);
//! }
//! # Ok(()) }
//! ```
//!
//! To get more information about what happened, we can implement
//! [`Stream`].  Note: if you don't require the information
//! asynchronously, you can also pass a [`&mut Vec<Output>`](Output)
//! to collect the output and examine it after the call returns.
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
//! use sequoia::pki::certify::Output;
//! use sequoia::pki::certify::output::*;
//! use sequoia::pki::certify;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let (alice, _alice_rev) = CertBuilder::new()
//! #     .add_userid("<alice@example.org>")
//! #     .generate()
//! #     .unwrap();
//! # let (bob, _bob_rev) = CertBuilder::new()
//! #     .add_userid("<bob@example.org>")
//! #     .generate()
//! #     .unwrap();
//! #
//! pub struct Stream {
//!     // Local state.
//! }
//!
//! impl certify::Stream for Stream {
//!     fn output(&mut self,
//!               _params: &certify::Params,
//!               output: certify::Output)
//!         -> sequoia::Result<()>
//!     {
//!         match output {
//!             Output::Report(Report { certifications, ..}) => {
//!                 eprintln!("Made {} certifications",
//!                           certifications.len());
//!                 # assert_eq!(certifications.len(), 1);
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
//! if let Err(err) = sq
//!     .pki_certify()
//!     .certify(
//!         &alice,
//!         &bob,
//!         &["<bob@example.org>".into()],
//!         &mut stream,
//!         Cancel::new(),
//!         None)
//! {
//!     eprintln!("Failed to certify the user ID: {}", err);
//! }
//! # Ok(()) }
//! ```

use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_wot as wot;
use wot::FULLY_TRUSTED;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::SignatureFields;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::clone_anyhow;
use crate::Result;
use crate::Sequoia;
use crate::config::Expiration;
use crate::consts::SECONDS_IN_YEAR;
use crate::prompt;
use crate::provenance::active_certification;
use crate::types::Safe;

/// The difference of two values, if any.
pub enum CertificationDiffValue<T>
where
    T: PartialEq + Eq
{
    /// The value is unchanged.
    Unchanged(T),
    /// The value changed.
    ///
    /// Old, new.
    Changed(T, T),
}

impl<T> Debug for CertificationDiffValue<T>
where
    T: PartialEq + Eq + Debug
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        match self {
            Self::Unchanged(value) => {
                write!(f,
                       "Unchanged({:?})",
                       value)
            }
            Self::Changed(old, new) => {
                write!(f,
                       "Changed({:?}, {:?})",
                       old, new)
            }
        }
    }
}

impl<T> CertificationDiffValue<T>
where
    T: PartialEq + Eq + Debug
{
    fn compute(old: T, new: T) -> Self {
        if old == new {
            CertificationDiffValue::Unchanged(old)
        } else {
            CertificationDiffValue::Changed(old, new)
        }
    }

    /// Whether the value is unchanged.
    fn unchanged(&self) -> bool {
        matches!(self, Self::Unchanged(_))
    }
}

/// A `diff` of important parameters in a `Certification`.
///
/// This `diff` does not intend to cover every possible different
/// between two certifications.  Instead, its purpose is to determine
/// whether a certification should be updated.  If the answer is yes,
/// this data structure can be used to conveniently summarize the
/// changes.
///
/// The following parameters are considered:
///
///   - (Absolute) expiration time
///   - Trust depth
///   - Trust amount
///   - Regular expressions
///   - Notations
///   - Exportable flag
#[derive(Debug)]
pub struct CertificationDiff {
    expiration: CertificationDiffValue<Option<SystemTime>>,
    trust_depth: CertificationDiffValue<u8>,
    trust_amount: CertificationDiffValue<u8>,
    regular_expressions: CertificationDiffValue<Vec<Vec<u8>>>,
    notations: CertificationDiffValue<Vec<String>>,
    exportable: CertificationDiffValue<bool>,
}

impl CertificationDiff {
    /// Returns whether the certification changed.
    ///
    /// Changes are normalized, and filtered to relevant changes.  For
    /// instance, regular expressions and notations are sorted and
    /// deduped, the salt notation is ignored, and a missing
    /// expiration is considered equivalent to an expiration that
    /// never expires.
    pub fn unchanged(&self) -> bool {
        self.expiration.unchanged()
            && self.trust_depth.unchanged()
            && self.trust_amount.unchanged()
            && self.regular_expressions.unchanged()
            && self.notations.unchanged()
            && self.exportable.unchanged()
    }

    /// Returns the change to the expiration value.
    pub fn expiration(&self) -> &CertificationDiffValue<Option<SystemTime>> {
        &self.expiration
    }

    /// Returns the change to the trust depth value.
    pub fn trust_depth(&self) -> &CertificationDiffValue<u8> {
        &self.trust_depth
    }

    /// Returns the change to the trust amount value.
    pub fn trust_amount(&self) -> &CertificationDiffValue<u8> {
        &self.trust_amount
    }

    /// Returns the change to the regular expressions.
    pub fn regular_expressions(&self) -> &CertificationDiffValue<Vec<Vec<u8>>> {
        &self.regular_expressions
    }

    /// Returns the change to the notations.
    pub fn notations(&self) -> &CertificationDiffValue<Vec<String>> {
        &self.notations
    }

    /// Returns the change to the exportable field.
    pub fn exportable(&self) -> &CertificationDiffValue<bool> {
        &self.exportable
    }

    /// Computes the difference between a certification and a
    /// signature builder.
    pub fn for_builder(old: &Signature,
                       new: &SignatureFields, new_ct: SystemTime)
        -> Self
    {
        let a_expiration = old.signature_expiration_time();
        let b_expiration = if let Some(vp) = new.signature_validity_period() {
            Some(new_ct + vp)
        } else {
            None
        };
        let expiration = CertificationDiffValue::compute(
            a_expiration, b_expiration);

        let (a_depth, a_amount) = old.trust_signature().unwrap_or((0, 120));
        let (b_depth, b_amount) = new.trust_signature().unwrap_or((0, 120));

        let trust_depth
            = CertificationDiffValue::compute(a_depth, b_depth);
        let trust_amount
            = CertificationDiffValue::compute(a_amount, b_amount);

        let mut a_regex: Vec<_> = old.regular_expressions()
            .map(|re| re.to_vec())
            .collect();
        a_regex.sort();
        a_regex.dedup();
        let mut b_regex: Vec<_> = new.regular_expressions()
            .map(|re| re.to_vec())
            .collect();
        b_regex.sort();
        b_regex.dedup();

        let regular_expressions
            = CertificationDiffValue::compute(a_regex, b_regex);

        let a_notations: Vec<_> = old.notation_data()
            .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
            .map(|n| n.to_string())
            .collect();
        let b_notations: Vec<_> = new.notation_data()
            .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
            .map(|n| n.to_string())
            .collect();

        let notations = CertificationDiffValue::compute(
            a_notations, b_notations);

        let a_exportable = old.exportable_certification().unwrap_or(true);
        let b_exportable = new.exportable_certification().unwrap_or(true);

        let exportable = CertificationDiffValue::compute(
            a_exportable, b_exportable);

        CertificationDiff {
            expiration,
            trust_depth,
            trust_amount,
            regular_expressions,
            notations,
            exportable,
        }
    }

    /// Computes the difference between an old certification and a new
    /// certification.
    pub fn diff(old: &Signature, new: &Signature)
        -> Self
    {
        Self::for_builder(old, &*new,
                          new.signature_creation_time().unwrap_or(UNIX_EPOCH))
    }

    /// Dumps the diff to the specified writer.
    ///
    /// The output is formatted as a markdown list with each line
    /// indicating the difference.
    pub fn dump(&self, output: &mut dyn std::io::Write)
    {
        if let CertificationDiffValue::Changed(a_expiration, b_expiration)
            = self.expiration()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating expiration time: {} -> {}",
                      if let Some(a_expiration) = a_expiration {
                          chrono::DateTime::<chrono::offset::Utc>::from(
                              *a_expiration).to_string()
                      } else {
                          "no expiration".to_string()
                      },
                      if let Some(b_expiration) = b_expiration {
                          chrono::DateTime::<chrono::offset::Utc>::from(
                              *b_expiration).to_string()
                      } else {
                          "no expiration".to_string()
                      });
        }

        if let CertificationDiffValue::Changed(a_amount, b_amount)
            = self.trust_amount()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating trust amount: {} -> {}",
                      a_amount, b_amount);
        }
        if let CertificationDiffValue::Changed(a_depth, b_depth)
            = self.trust_depth()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating trust depth: {} -> {}",
                      a_depth, b_depth);
        }

        if let CertificationDiffValue::Changed(a_regex, b_regex)
            = self.regular_expressions()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating regular expressions");

            wwriteln!(stream = output, initial_indent = "     - ",
                      "current certification");
            for (i, r) in a_regex.into_iter().enumerate() {
                wwriteln!(stream = output, initial_indent = "       - ",
                          "{}. {}", i + 1, Safe(r));
            }

            wwriteln!(stream = output, initial_indent = "     - ",
                      "new certification");
            for (i, r) in b_regex.into_iter().enumerate() {
                wwriteln!(stream = output, initial_indent = "       - ",
                          "{}. {}", i + 1, Safe(r));
            }
        }

        if let CertificationDiffValue::Changed(a_notations, b_notations)
            = self.notations()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating notations");

            wwriteln!(stream = output, initial_indent = "     - ",
                      "current certification");
            for (i, n) in a_notations.into_iter().enumerate() {
                wwriteln!(stream = output, initial_indent = "       - ",
                          "{}. {}", i + 1, Safe(n));
            }

            wwriteln!(stream = output, initial_indent = "     - ",
                      "updated certification");
            for (i, n) in b_notations.into_iter().enumerate() {
                wwriteln!(stream = output, initial_indent = "       - ",
                          "{}. {}", i + 1, Safe(n));
            }
        }

        if let CertificationDiffValue::Changed(a_exportable, b_exportable)
            = self.exportable()
        {
            wwriteln!(stream = output, initial_indent = "   - ",
                      "updating exportable flag: {} -> {}",
                      a_exportable, b_exportable);
        }
    }
}

/// The trait for collecting output.
pub trait Stream {
    /// Output from [`pki_certify`](Builder::certify).
    fn output(&mut self, params: &Params, output: Output) -> Result<()>;
}

impl<T> Stream for Box<T>
where
    T: Stream + ?Sized
{
    fn output(&mut self, params: &Params, output: Output) -> Result<()> {
        AsMut::as_mut(self).output(params, output)
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

/// Data structures related to [`Error`].
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
pub mod error {
    use super::*;

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    /// The [`Report`](output::Report) event is still emitted.
    ///
    /// An example of an operational error is that a key store is not
    /// available, but needed to complete the operation.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum OperationalError {
        #[error(transparent)]
        Other(anyhow::Error),
    }

    /// The certifier is the same as the certificate to certify.
    ///
    /// To create a third-party certifications, the certifier must be
    /// different from the certificate being certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("The certifier is the same as the certificate to certify")]
    pub struct CertifierSameAsCertificate {
        pub cert: Cert,
    }

    /// A regular expression was used with a certification with a
    /// trust depth of 0.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("A regex constraint only makes sense \
             if the trust depth is greater than 0")]
    pub struct NoRegularExpressions {
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.  The
    /// [`Report`](output::Report) event is still emitted.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum ArgumentError {
        #[error(transparent)]
        CertifierSameAsCertificate(CertifierSameAsCertificate),
        #[error(transparent)]
        NoRegularExpressions(NoRegularExpressions),
    }

    /// The certificate or the user ID is revoked and can't be
    /// certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("Can't certify {} for {}, it's revoked",
            .fingerprint, Safe(.userid))]
    pub struct Revoked {
        pub fingerprint: Fingerprint,
        pub userid: UserID,
        /// A reason for revocation.
        pub revocation: Signature,
    }

    /// An error related to making a certification.
    ///
    /// `CertificationError`s are considered hard errors and cause
    /// processing to stop.  You can turn `CertificationError`s into
    /// soft errors using [`Builder::ignore_certification_errors`].
    /// In that case, you can still reject certain certifications by
    /// catching them in your [`Stream`] implementation and returning
    /// an error.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum CertificationError {
        #[error(transparent)]
        Revoked(#[from] Revoked),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }

    /// The caller attempted to create a retraction, but there is
    /// nothing to retract.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("You never certified {} for {}, there is nothing to retract.",
            Safe(.userid), .fingerprint)]
    pub struct NothingToRetract {
        pub fingerprint: Fingerprint,
        pub userid: UserID,
    }

    /// The binding was previous certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    #[error("{}, {} is already certified with the same parameters",
            .fingerprint, Safe(.userid))]
    pub struct PreviouslyCertified {
        pub fingerprint: Fingerprint,
        pub userid: UserID,
        pub certification: Signature,
    }

    /// Reasons for skipping a certification.
    ///
    /// Skipping a certification is not considered an error.  It does
    /// not cause processing to stop; the user ID is simply skipped.
    /// You can turn this into an error by returning an error from
    /// your stream implementation.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug)]
    pub enum CertificationSkippedReason {
        #[error(transparent)]
        NothingToRetract(#[from] NothingToRetract),
        #[error(transparent)]
        PreviouslyCertified(#[from] PreviouslyCertified),
    }
}

/// Errors related to making certifications.
///
/// Errors are divided into categories and each category contains more
/// precise errors.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum Error {
    /// An operational-related error.
    ///
    /// This may be because the operation requires the certificate
    /// store, but it is disabled.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    #[error(transparent)]
    OperationalError(#[from] error::OperationalError),

    /// Errors related to incorrectly calling the function.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    ArgumentError(#[from] error::ArgumentError),

    /// Errors related to a certification.
    #[error(transparent)]
    CertificationError(#[from] error::CertificationError),

    /// If [`Stream::output`] returns an error, it is propagate here.
    StreamOutputError(anyhow::Error),
}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// We certified the specified binding.
    ///
    /// Note: the certification will only be written out (to the file
    /// or to the certificate store) at the end of the function.  Thus
    /// if a later certification fails, this certification may not
    /// actually be written out.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Certified {
        pub cert: Cert,
        pub userid: UserID,
        /// The certifications.
        ///
        /// The first certification is the primary certification, the
        /// second is the first additional certification, etc.
        pub certifications: Vec<Signature>,
        pub previous_certification: Option<Signature>,
        /// The diff relative to the active certification, if any.
        pub diff: Option<CertificationDiff>,
    }

    /// We didn't certify a binding, because it was unnecessary.
    ///
    /// This is emitted if the certification is the same as the active
    /// certification, if the certification is a retraction, but there
    /// is nothing to retract.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct CertificationSkipped {
        pub cert: Cert,
        pub userid: UserID,
        pub reason: error::CertificationSkippedReason,
    }

    /// We failed to certify the specified binding.
    ///
    /// `error` contains the reason.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct CertificationFailed {
        pub cert: Cert,
        pub userid: UserID,
        pub error: error::CertificationError,
    }

    /// A report about the operation.
    ///
    /// This is emitted once after attempting to create the
    /// certifications.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        /// The certifications.
        pub certifications: Vec<(UserID, Vec<Signature>)>,
    }
}

/// The variants of this enum are the different types of output that
/// [`pki_certify`](Builder::certify) emits.
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

    /// Errors related to incorrectly calling the function.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    ArgumentError(error::ArgumentError),

    /// Emitted after any certifications have been created and either
    /// exported or imported to the certificate store.
    Certified(output::Certified),

    /// Emitted when a certification is skipped.
    ///
    /// This is not an error.
    CertificationSkipped(output::CertificationSkipped),

    /// Emitted when the certification failed.
    ///
    /// This is an error.
    CertificationFailed(output::CertificationFailed),

    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is imported or not.
    Report(output::Report),
}

impl Sequoia {
    /// The default expiration of a third-party certification.
    const DEFAULT_CERTIFICATION_EXPIRATION: Expiration
        = Expiration::from_duration(Duration::from_secs(10 * SECONDS_IN_YEAR));

    /// Returns a builder providing control over how to import
    /// keys.
    ///
    /// See [`Builder`] for details.
    pub fn pki_certify(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,

                ignore_certification_errors: false,
                recreate: false,
                expiration: Self::DEFAULT_CERTIFICATION_EXPIRATION,
                trust_amount: FULLY_TRUSTED as u8,
                trust_depth: 0,
                domains: Vec::new(),
                regular_expressions: Vec::new(),
                exportable: true,
                revocable: false,
                notations: Vec::new(),
                additional_certifications: Vec::new(),
            },
        }
    }
}

/// A builder for a certification template.
///
/// A builder for specifying a certification's parameters.
///
/// This data structures contains some of the parameters for a
/// certification.  This data structure is only used to specify an
/// additional certification (see [`Builder::add_certification`]).
///
/// Parameters that are not set default to the values in [`Params`].
#[derive(Debug, Clone)]
pub struct CertificationTemplateBuilder {
    template: CertificationTemplate,
}

impl CertificationTemplateBuilder {
    /// Returns a new `CertificationTemplateBuilder` with no
    /// parameters set.
    ///
    /// The new `CertificationTemplateBuilder` has no parameters set.
    /// If used as is, it falls back to parameters specified in
    /// [`Params`].
    pub fn new() -> Self {
        CertificationTemplateBuilder {
            template: CertificationTemplate {
                trust_amount: None,
                trust_depth: None,
                expiration: None,
            }
        }
    }

    /// Sets the certification's trust amount.
    ///
    /// For details, see [`Builder::trust_amount`].
    ///
    /// If unset, it falls back to the value specified in [`Params`].
    pub fn trust_amount(mut self, trust_amount: u8) -> Self {
        self.template.trust_amount = Some(trust_amount);
        self
    }

    /// Sets the certification's trust depth.
    ///
    /// For details, see [`Builder::trust_depth`].
    ///
    /// If unset, it falls back to the value specified in [`Params`].
    pub fn trust_depth(mut self, trust_depth: u8) -> Self {
        self.template.trust_depth = Some(trust_depth);
        self
    }

    /// Sets the certification's expiration.
    ///
    /// For details, see [`Builder::expiration`].
    ///
    /// If unset, it falls back to the value specified in [`Params`].
    pub fn expiration(mut self, expiration: Expiration) -> Self {
        self.template.expiration = Some(expiration);
        self
    }

    /// Returns the `CertificationTemplate`.
    pub fn build(&self) -> CertificationTemplate {
        self.template.clone()
    }
}

impl From<CertificationTemplateBuilder> for CertificationTemplate {
    fn from(builder: CertificationTemplateBuilder) -> CertificationTemplate {
        builder.build()
    }
}

impl From<&mut CertificationTemplateBuilder> for CertificationTemplate {
    fn from(builder: &mut CertificationTemplateBuilder) -> CertificationTemplate {
        builder.build()
    }
}

/// A certification template.
///
/// This data structures contains some of the parameters for a
/// certification.  This data structure is only used to specify an
/// additional certification (see [`Builder::add_certification`]).
///
/// Parameters that are not set default to the corresponding values in
/// [`Params`].
#[derive(Debug, Clone)]
pub struct CertificationTemplate {
    trust_amount: Option<u8>,
    trust_depth: Option<u8>,
    expiration: Option<Expiration>,
}

impl CertificationTemplate {
    /// Returns the certification's trust amount.
    ///
    /// For details, see [`Params::trust_amount`].
    pub fn trust_amount(&self) -> Option<u8> {
        self.trust_amount.clone()
    }

    /// Returns the certification's trust depth.
    ///
    /// For details, see [`Params::trust_depth`].
    pub fn trust_depth(&self) -> Option<u8> {
        self.trust_depth.clone()
    }

    /// Returns the certification's expiration.
    ///
    /// For details, see [`Params::expiration`].
    pub fn expiration(&self) -> Option<Expiration> {
        self.expiration.clone()
    }
}

/// The certification parameters.
///
/// These parameters are used by [`certify`](Builder::certify).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,

    ignore_certification_errors: bool,
    recreate: bool,
    trust_amount: u8,
    trust_depth: u8,
    expiration: Expiration,
    domains: Vec<String>,
    regular_expressions: Vec<String>,
    exportable: bool,
    revocable: bool,
    notations: Vec<(bool, NotationData)>,
    additional_certifications: Vec<CertificationTemplate>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns whether certification errors are ignored.
    ///
    /// By default, [`CertificationError`](error::CertificationError)s
    /// are considered hard errors and cause processing to stop.  If
    /// this is set, it turns `CertificationError`s into soft errors.
    /// In that case, you can still reject certain certifications by
    /// catching them in your [`Stream`] implementation and returning
    /// an error.
    pub fn ignore_certification_errors(&self) -> bool {
        self.ignore_certification_errors
    }

    /// Returns whether this function will forcefully recreate the
    /// certification.
    ///
    /// By default, if the active certification has the same
    /// parameters as certification to be created, then a new
    /// certification will not be created, but the old certification
    /// will be reused.
    ///
    /// If this is set, then a new certification will always be
    /// created.
    pub fn recreate(&self) -> bool {
        self.recreate
    }

    /// Returns the certification's trust amount.
    ///
    /// The trust amount indicates the degree to which the certifier
    /// is confident that the user ID should be associated with the
    /// certificate.  It ranges from 0 to 120 where 0 is equivalent to
    /// no certification at all and 120 means the certifier is very
    /// confident that the user ID should be associated with the
    /// certificate.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.21
    pub fn trust_amount(&self) -> u8 {
        self.trust_amount
    }

    /// Returns the certification's trust depth.
    ///
    /// The trust depth indicates whether a certificate should be
    /// considered a trusted introducer and, if so, to what degree it
    /// can introduce other trusted introducers.  A trusted introducer
    /// is another name for a [certification authority (CA)].
    ///
    ///   [certification authority (CA)]: https://en.wikipedia.org/wiki/Certificate_authority
    ///
    /// By default, the trust depth is 0 and this means that the
    /// certification indicates that the certificate should be
    /// associated with the specified identity.  A trust depth of 1
    /// means that the certificate should also be considered a trusted
    /// introducer, but it cannot introduce other trusted introducers.
    /// A trust depth of 2 means that the certificate should be
    /// considered a trusted introducer, and it can introducer trusted
    /// introducers with a trust depth of 1.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.21
    pub fn trust_depth(&self) -> u8 {
        self.trust_depth
    }

    /// Returns when the certification expires.
    ///
    /// By default, the certification expires after 10 years.
    pub fn expiration(&self) -> Expiration {
        self.expiration.clone()
    }

    /// Returns any domain constraints.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Domain constraints are a way to limit
    /// that power.
    ///
    /// A domain constraint is converted to a regular expression
    /// constraint.  As it is easy to get regular expressions
    /// incorrect, you should use this function when constraining by
    /// domain.  See [`Builder::add_regular_expression_constraints`]
    /// for more information about constraints.
    pub fn domain_constraints(&self) -> impl Iterator<Item=&str> {
        self.domains.iter().map(|d| d.deref())
    }

    /// Returns any regular expression constraints.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Regular expression constraints are a
    /// way to limit that power.
    ///
    /// See [`Builder::add_regular_expression_constraint`] for a more
    /// detailed explanation.
    pub fn regular_expression_constraints(&self)
        -> impl Iterator<Item=&str>
    {
        self.regular_expressions.iter().map(|d| d.deref())
    }

    /// Returns whether the certification is exportable.
    ///
    /// By default, a certification is exportable.  If a certification
    /// is not marked as exportable, an OpenPGP implementation will
    /// strip it when exporting the certificate.  A non-exportable
    /// certification is also referred to as a local certification.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification
    pub fn exportable(&self) -> bool {
        self.exportable
    }

    /// Returns whether the certification is revocable.
    ///
    /// By default, a certifier is able to revoke a certification that
    /// they made.  A certifier can set this to indicate that they
    /// commit to never revoking the certification.  If a
    /// certification is marked non-revocable, any subsequent
    /// revocation will be ignored.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocable
    pub fn revocable(&self) -> bool {
        self.revocable
    }

    /// Returns any configured notations.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn notations(&self) -> impl Iterator<Item=&(bool, NotationData)> {
        self.notations.iter()
    }

    /// Returns any additional certifications that will be created.
    ///
    /// By default a single certificate is created.  It is possible to
    /// create multiple certifications at once.  This is useful to
    /// create a temporary fully authenticated certification, which
    /// expires after a short amount of time and then a minimally
    /// authenticated certification.
    ///
    /// Certifications are created as follows: the primary
    /// certification is created at the current time.  Additional
    /// certifications are created immediately *prior* to that
    /// certification with the first one being the oldest.  So if the
    /// current time is 12.00 and we are creating two additional
    /// certifications, the first additional certification will have a
    /// signature creation time of 11:59.58, the second at 11:59.59
    /// and the primary certification will be at 12:00.00.
    pub fn additional_certifications(&self)
        -> impl Iterator<Item=&CertificationTemplate>
    {
        self.additional_certifications.iter()
    }
}

/// Makes third-party certifications.
///
/// A builder providing control over how to make party-party
/// certifications.
///
/// A third party-certification is used to either indicate that an
/// identity should be associated with a certificate, or that an
/// identity should be associated with a certificate *and* the
/// certificate should be treated as a trusted introducer.
///
/// Consider Alice who has met Bob and Bob has told her his
/// certificate's fingerprint.  Alice can record that information
/// using a third-party certification.  This allows Alice's OpenPGP
/// implementation to automatically
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

    /// Sets whether certification errors are ignored.
    ///
    /// By default, [`CertificationError`](error::CertificationError)s
    /// are considered hard errors and cause processing to stop.  If
    /// this is set, it turns `CertificationError`s into soft errors.
    /// In that case, you can still reject certain certifications by
    /// catching them in your [`Stream`] implementation and returning
    /// an error.
    pub fn ignore_certification_errors(mut self, ignore: bool)
        -> Self
    {
        self.params.ignore_certification_errors = ignore;
        self
    }

    /// Sets whether this function will forcefully recreate the
    /// certification.
    ///
    /// By default, if the active certification has the same
    /// parameters as certification to be created, then a new
    /// certification will not be created, but the old certification
    /// will be reused.
    ///
    /// If this is set, then a new certification will always be
    /// created.
    pub fn recreate(mut self, recreate: bool) -> Self {
        self.params.recreate = recreate;
        self
    }

    /// Sets the certification's trust amount.
    ///
    /// The trust amount indicates the degree to which the certifier
    /// is confident that the user ID should be associated with the
    /// certificate.  It ranges from 0 to 120 where 0 is equivalent to
    /// no certification at all and 120 means the certifier is very
    /// confident that the user ID should be associated with the
    /// certificate.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.21
    pub fn trust_amount(mut self, trust_amount: u8) -> Self {
        self.params.trust_amount = trust_amount;
        self
    }

    /// Sets the certification's trust depth.
    ///
    /// The trust depth indicates whether a certificate should be
    /// considered a trusted introducer and, if so, to what degree it
    /// can introduce other trusted introducers.  A trusted introducer
    /// is another name for a [certification authority (CA)].
    ///
    ///   [certification authority (CA)]: https://en.wikipedia.org/wiki/Certificate_authority
    ///
    /// By default, the trust depth is 0 and this means that the
    /// certification indicates that the certificate should be
    /// associated with the specified identity.  A trust depth of 1
    /// means that the certificate should also be considered a trusted
    /// introducer, but it cannot introduce other trusted introducers.
    /// A trust depth of 2 means that the certificate should be
    /// considered a trusted introducer, and it can introducer trusted
    /// introducers with a trust depth of 1.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.21
    pub fn trust_depth(mut self, trust_depth: u8) -> Self {
        self.params.trust_depth = trust_depth;
        self
    }

    /// Sets certification's expiration time.
    ///
    /// By default, the certification expires after 10 years.
    pub fn expiration(mut self, expiration: Expiration) -> Self {
        self.params.expiration = expiration;
        self
    }

    /// Adds a domain constraint.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Domain constraints are a way to limit
    /// that power.
    ///
    /// A domain constraint is converted to a regular expression
    /// constraint.  As it is easy to get regular expressions
    /// incorrect, you should use this function when constraining by
    /// domain.  See [`Builder::add_regular_expression_constraints`]
    /// for more information about constraints.
    pub fn add_domain_constraint<S>(mut self, domain: S)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.domains.push(domain.as_ref().to_string());
        self
    }

    /// Adds domain constraints.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Domain constraints are a way to limit
    /// that power.
    ///
    /// A domain constraint is converted to a regular expression
    /// constraint.  As it is easy to get regular expressions
    /// incorrect, you should use this function when constraining by
    /// domain.  See [`Builder::add_regular_expression_constraints`]
    /// for more information about constraints.
    pub fn add_domain_constraints<S>(mut self, domains: impl Iterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.domains.extend(domains.map(|d| d.as_ref().to_string()));
        self
    }

    /// Adds a regular expression constraint.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Regular expression constraints are a
    /// way to limit that power.
    ///
    /// If a certification of a trusted introducer includes one or
    /// more regular expressions, then only certifications of user IDs
    /// that match at least one of the regular expressions are
    /// considered.  For example, say the user certifies the
    /// certificate for `<ca@bank.com>` as a trusted introducer so
    /// that they can authenticate all of their communication with
    /// their bank.  They can add a regular expression that says that
    /// that only certifications of user IDs that have an email
    /// address whose domain is `bank.com` should only be considered.
    /// Thus if the bank's CA certifies another bank's CA, the user
    /// will ignore that.  Consider:
    ///
    /// ```text
    ///            user
    ///              | trusted introducer, "<[^>]+[@.]bank\\.com>$"
    ///              v
    ///         ca@bank.com
    ///        /           \
    ///       v             v
    /// alice@bank.com  ca@banque.fr
    /// ```
    ///
    /// In the previous illustration, the user considers
    /// `alice@bank.com`'s certificate to be authenticated by the CA,
    /// but not `ca@bankque.fr`'s certificate, because `bank.com`
    /// matches the regular expression, but `banque.fr` does not.
    ///
    /// If you are adding a constraint for a domain, you should use
    /// domain constraints instead of regular expression constraints.
    /// (See [`Params::domain_constraints`].)  This library converts
    /// domain constraints into canonical regular expression
    /// constraints, which are tricky to write.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.22
    pub fn add_regular_expression_constraint<S>(mut self, regex: S)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.regular_expressions.push(regex.as_ref().to_string());
        self
    }

    /// Adds regular expression constraints.
    ///
    /// A certifier can indicate that they consider a certificate to
    /// be a trusted introducer by setting the trust depth to be
    /// greater than 0 using [`Builder::trust_depth`].  By default,
    /// all certifications made by a trusted introducer are used
    /// during authentication.  Regular expression constraints are a
    /// way to limit that power.
    ///
    /// See [`Builder::add_regular_expression_constraint`] for a more
    /// detailed explanation.
    pub fn add_regular_expression_constraints<S>(
        mut self, regexes: impl Iterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.regular_expressions.extend(regexes.map(|r| r.as_ref().to_string()));
        self
    }

    /// Sets whether the certification is exportable.
    ///
    /// By default, a certification is exportable.  If a certification
    /// is not marked as exportable, an OpenPGP implementation will
    /// strip it when exporting the certificate.  A non-exportable
    /// certification is also referred to as a local certification.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification
    pub fn exportable(mut self, exportable: bool) -> Self {
        self.params.exportable = exportable;
        self
    }

    /// Sets whether the certification is revocable.
    ///
    /// By default, a certifier is able to revoke a certification that
    /// they made.  A certifier can set this to indicate that they
    /// commit to never revoking the certification.  If a
    /// certification is marked non-revocable, any subsequent
    /// revocation will be ignored.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocable
    pub fn revocable(mut self, revocable: bool) -> Self {
        self.params.revocable = revocable;
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
                         notations: impl Iterator<Item=(bool, NotationData)>)
        -> Self
    {
        self.params.notations.extend(notations);
        self
    }

    /// Adds an additional certification template.
    ///
    /// By default a single certificate is created.  It is possible to
    /// create multiple certifications at once.  This is useful to
    /// create a temporary fully authenticated certification, which
    /// expires after a short amount of time and then a minimally
    /// authenticated certification.
    ///
    /// Certifications are created as follows: the primary
    /// certification is created at the current time.  Additional
    /// certifications are created immediately *prior* to that
    /// certification with the first one being the oldest.  So if the
    /// current time is 12.00 and we are creating two additional
    /// certifications, the first additional certification will have a
    /// signature creation time of 11:59.58, the second at 11:59.59
    /// and the primary certification will be at 12:00.00.
    pub fn add_certification<T>(mut self, template: T)
        -> Self
    where
        T: Into<CertificationTemplate>
    {
        self.params.additional_certifications.push(template.into());
        self
    }

    /// Adds additional certification templates.
    ///
    /// By default a single certificate is created.  It is possible to
    /// create multiple certifications at once.  This is useful to
    /// create a temporary fully authenticated certification, which
    /// expires after a short amount of time and then a minimally
    /// authenticated certification.
    ///
    /// Certifications are created as follows: the primary
    /// certification is created at the current time.  Additional
    /// certifications are created immediately *prior* to that
    /// certification with the first one being the oldest.  So if the
    /// current time is 12.00 and we are creating two additional
    /// certifications, the first additional certification will have a
    /// signature creation time of 11:59.58, the second at 11:59.59
    /// and the primary certification will be at 12:00.00.
    pub fn add_certifications<T>(mut self, templates: impl Iterator<Item=T>)
        -> Self
    where
        T: Into<CertificationTemplate>
    {
        self.params.additional_certifications.extend(templates.map(|t| t.into()));
        self
    }

    /// Generate or retract a certification.
    ///
    /// `certifier` is the certificate that will be used to generate
    /// the certification.  If the certificate does not include secret
    /// key material and the key store is not disabled, then the
    /// function will try to use the key store.
    ///
    /// `cert` and `userids` are the certificate and the user IDs that
    /// will be certified.  A certification will be generated for the
    /// certificate and each user ID (i.e., each binding).
    ///
    /// `cert` is not merged with any version on the certificate
    /// store.  If this is desired, the caller should do this first.
    ///
    /// If the trust amount is 0, the operation is interpreted as a
    /// retraction of any prior certifications by the certifier over
    /// the bindings.
    pub fn certify<'a, S, P>(&self,
                             certifier: &Cert,
                             cert: &Cert,
                             userids: &[UserID],
                             stream: S,
                             prompt: P,
                             output: Option<&mut dyn std::io::Write>)
        -> Result<(), Error>
    where
        S: Stream + 'a,
        P: prompt::Prompt,
    {
        let mut stream = Box::new(stream) as Box<dyn Stream>;
        let prompt = Box::new(prompt) as Box<dyn prompt::Prompt>;

        let result
            = self.certify_(certifier, cert, userids, &mut stream, prompt,
                            output);

        let (result, certifications) = match result {
            Ok(certifications) => (Ok(()), certifications),
            Err(err) => (Err(err), Vec::new()),
        };

        if let Err(Error::StreamOutputError(_)) = result.as_ref() {
        } else {
            // Emit the report.
            stream.output(
                self.params(),
                Output::Report(output::Report {
                    certifications,
                }))
                .map_err(|err| Error::StreamOutputError(err))?;
        }

        result
    }

    pub fn certify_<'a>(&self,
                        certifier: &Cert,
                        cert: &Cert,
                        userids: &[UserID],
                        stream: &mut Box<dyn Stream + 'a>,
                        prompt: Box<dyn prompt::Prompt + 'a>,
                        output: Option<&mut dyn std::io::Write>)
        -> Result<Vec<(UserID, Vec<Signature>)>, Error>
    {
        tracer!(false, "certify");

        let &Builder {
            params: Params {
                sequoia,

                ignore_certification_errors,
                recreate,
                ref expiration,
                trust_amount,
                trust_depth,
                ref domains,
                ref regular_expressions,
                exportable,
                revocable,
                ref notations,
                ref additional_certifications,
            },
        } = self;

        assert!(userids.len() > 0);

        macro_rules! op {
            () => {
                |err| {
                    let err = anyhow::Error::from(err);

                    if let Err(err) = stream.output(
                        self.params(),
                        Output::OperationalError(
                            error::OperationalError::Other(clone_anyhow(&err))))
                    {
                        Error::StreamOutputError(err)
                    } else {
                        Error::OperationalError(
                            error::OperationalError::Other(err))
                    }
                }
            }
        }

        if certifier.fingerprint() == cert.fingerprint() {
            stream.output(
                self.params(),
                Output::ArgumentError(
                    error::ArgumentError::CertifierSameAsCertificate(
                        error::CertifierSameAsCertificate {
                            cert: cert.clone(),
                        })))
                .map_err(|err| Error::StreamOutputError(err))?;

            return Err(Error::ArgumentError(
                error::ArgumentError::CertifierSameAsCertificate(
                    error::CertifierSameAsCertificate {
                        cert: cert.clone(),
                    })));
        }

        if trust_depth == 0 && !regular_expressions.is_empty() {
            stream.output(
                self.params(),
                Output::ArgumentError(
                    error::ArgumentError::NoRegularExpressions(
                        error::NoRegularExpressions {
                        })))
                .map_err(|err| Error::StreamOutputError(err))?;

            return Err(Error::ArgumentError(
                error::ArgumentError::NoRegularExpressions(
                    error::NoRegularExpressions {
                    })));
        }

        let prep = || {
            // Get the signer to certify with.
            let signer = sequoia.get_certification_key(
                certifier, None, prompt)?;

            let mut base
                = SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(sequoia.time())?;

            for domain in domains {
                if let Err(err) = UserIDQueryParams::is_domain(domain) {
                    return Err(err).context(format!(
                        "{:?} is not a valid domain", domain));
                }

                // Escape any control characters.
                const CONTROL: &[(&str, &str)] = &[
                    ("\\", "\\\\"),
                    (".", "\\."),
                    ("|", "\\|"),
                    ("(", "\\("),
                    (")", "\\)"),
                    ("*", "\\*"),
                    ("+", "\\+"),
                    ("?", "\\?"),
                    ("^", "\\^"),
                    ("$", "\\$"),
                    ("[", "\\["),
                    ("]", "\\]"),
                ];

                let mut domain = domain.to_string();
                for (c, e) in CONTROL.iter() {
                    domain = domain.replace(c, e);
                }

                base = base.add_regular_expression(format!("<[^>]+[@.]{}>$", domain))?;
            }
            for regex in regular_expressions {
                base = base.add_regular_expression(regex)?;
            }

            if ! exportable {
                base = base.set_exportable_certification(false)?;
            }

            if ! revocable {
                base = base.set_revocable(false)?;
            }

            for (critical, n) in notations {
                base = base.add_notation(
                    n.name(),
                    n.value(),
                    NotationDataFlags::empty().set_human_readable(),
                    *critical)?;
            };

            Ok((signer, base))
        };
        let (mut signer, base) = prep().map_err(op!())?;

        let mut retract = false;

        let mut builders
            = Vec::with_capacity(additional_certifications.len() + 1);
        for (i, certification)
            in additional_certifications
            .iter()
            .chain(std::iter::once(&CertificationTemplate {
                trust_amount: None,
                trust_depth: None,
                expiration: None,
            }))
            .enumerate()
        {
            let mut builder = base.clone();

            let trust_amount: u8 = certification
                .trust_amount
                .unwrap_or(trust_amount);
            if trust_amount == 0 {
                retract = true;
            }
            let trust_depth = certification
                .trust_depth
                .unwrap_or(trust_depth);
            if trust_depth != 0 || trust_amount != 120 {
                builder = builder.set_trust_signature(
                    trust_depth, trust_amount).map_err(op!())?;
            }

            // Creation time.
            //
            // If we should make two certifications, then the first one
            // should be at `sequoia.time() - 1`, and the second one at
            // `sequoia.time()`.  That is, the first one is a second earlier.
            let backdate = Duration::new((additional_certifications.len() - i) as u64, 0);
            let ct = sequoia.time() - backdate;
            builder = builder.set_signature_creation_time(ct).map_err(op!())?;

            // Expiration.
            let expiration = certification
                .expiration
                .as_ref()
                .unwrap_or(expiration);
            if let Some(validity) = expiration
                .as_duration(DateTime::<Utc>::from(sequoia.time()))
                .map_err(op!())?
            {
                builder = builder.set_signature_validity_period(validity)
                    .map_err(op!())?;
            }

            builders.push(builder);
        }

        // Get the active certification as of the reference time.
        let mut certifications = Vec::new();
        for (userid, active_certification) in
            active_certification(
                &sequoia, &cert, userids.iter(),
                certifier.primary_key().key().role_as_unspecified())
            .into_iter()
        {
            t!("Considering certification of {}: {:?}",
               String::from_utf8_lossy(userid.value()),
               active_certification);

            if let Some(ua) = cert.userids().find(|ua| ua.userid() == userid) {
                t!("  Known user ID");

                if retract {
                    // Check if we certified it.
                    if ! ua.certifications().any(|c| {
                        c.get_issuers().into_iter()
                            .any(|issuer| issuer.aliases(&certifier.key_handle()))
                    })
                    {
                        t!("  Should retract the active certification, \
                            but we never certified the user ID (1)");
                        stream.output(
                            self.params(),
                            Output::CertificationSkipped(
                                output::CertificationSkipped {
                                    cert: cert.clone(),
                                    userid: userid.clone(),
                                    reason: error::CertificationSkippedReason::NothingToRetract(
                                        error::NothingToRetract {
                                            fingerprint: cert.fingerprint(),
                                            userid: userid.clone(),
                                        }),
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;
                        certifications.push((userid.clone(), Vec::new()));
                        continue;
                    }
                } else {
                    if let RevocationStatus::Revoked(revs)
                        = ua.revocation_status(sequoia.policy(), sequoia.time())
                    {
                        t!("  Should certify the user ID, but it is revoked");
                        stream.output(
                            self.params(),
                            Output::CertificationFailed(
                                output::CertificationFailed {
                                    cert: cert.clone(),
                                    userid: userid.clone(),
                                    error: error::CertificationError::Revoked(
                                        error::Revoked {
                                            fingerprint: cert.fingerprint(),
                                            userid: userid.clone(),
                                            revocation: revs[0].clone(),
                                        })
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        if ! ignore_certification_errors {
                            return Err(Error::CertificationError(
                                error::CertificationError::Revoked(
                                    error::Revoked {
                                        fingerprint: cert.fingerprint(),
                                        userid: userid.clone(),
                                        revocation: revs[0].clone(),
                                    })));
                        }

                        // Return a signature packet to indicate that we
                        // processed something.  But don't return a
                        // signature.
                        certifications.push((userid.clone(), Vec::new()));
                        continue;
                    }
                }
            } else {
                t!("  Unknown user ID");
                if retract {
                    // Retracting an unknown user ID.
                    t!("  Should retract the active certification, \
                        but we never certified the user ID (2)");
                    stream.output(
                        self.params(),
                        Output::CertificationSkipped(
                            output::CertificationSkipped {
                                cert: cert.clone(),
                                userid: userid.clone(),
                                reason: error::CertificationSkippedReason::NothingToRetract(
                                    error::NothingToRetract {
                                        fingerprint: cert.fingerprint(),
                                        userid: userid.clone(),
                                    }),
                            }))
                        .map_err(|err| {
                            Error::StreamOutputError(err)
                        })?;

                    // Return a signature packet to indicate that we
                    // processed something.  But don't return a
                    // signature.
                    certifications.push((userid.clone(), Vec::new()));
                    continue;
                }
            }

            let diff = if let Some(active_certification)
                = active_certification.as_ref()
            {
                let diff = CertificationDiff::for_builder(
                    &active_certification,
                    &builders[0], sequoia.time());

                if diff.unchanged() && ! recreate {
                    stream.output(
                        self.params(),
                        Output::CertificationSkipped(
                            output::CertificationSkipped {
                                cert: cert.clone(),
                                userid: userid.clone(),
                                reason: error::CertificationSkippedReason::PreviouslyCertified(
                                    error::PreviouslyCertified {
                                        fingerprint: cert.fingerprint(),
                                        userid: userid.clone(),
                                        certification:
                                        active_certification.clone(),
                                    }),
                            }))
                        .map_err(|err| Error::StreamOutputError(err))?;

                    // Return a signature packet to indicate that we
                    // processed something.  But don't return a
                    // signature.
                    certifications.push((userid.clone(), Vec::new()));
                    continue;
                }

                Some(diff)
            } else {
                None
            };

            let result = builders.iter()
                .map(|builder| {
                    builder.clone().sign_userid_binding(
                        &mut signer,
                        cert.primary_key().key(),
                        userid)
                        .with_context(|| {
                            format!("Creating certification for {}",
                                    Safe(userid))
                        })
                })
                .collect::<Result<Vec<Signature>>>();

            let sigs = match result {
                Ok(sigs) => {
                    stream.output(
                        self.params(),
                        Output::Certified(
                            output::Certified {
                                cert: cert.clone(),
                                userid: userid.clone(),
                                certifications: sigs.clone(),
                                previous_certification: active_certification,
                                diff,
                            }))
                        .map_err(|err| Error::StreamOutputError(err))?;

                    sigs
                }
                Err(err) => {
                    let err_ = clone_anyhow(&err);
                    stream.output(
                        self.params(),
                        Output::CertificationFailed(
                            output::CertificationFailed {
                                cert: cert.clone(),
                                userid: userid.clone(),
                                error: error::CertificationError::Other(err),
                            }))
                        .map_err(|err| Error::StreamOutputError(err))?;

                    if ! ignore_certification_errors {
                        return Err(Error::CertificationError(
                            error::CertificationError::Other(err_)));
                    }

                    // Return a signature packet to indicate that we
                    // processed something.  But don't return a
                    // signature.
                    certifications.push((userid.clone(), Vec::new()));
                    continue;
                }
            };

            certifications.push((userid.clone(), sigs));
        }

        if certifications.iter().all(|(_u, s)| s.is_empty()) {
            // There are no signatures to insert.  We're done.
            return Ok(Vec::new());
        }

        let cert = cert.clone()
            .insert_packets(
                certifications.iter().flat_map(|(userid, sigs)| {
                    std::iter::once(Packet::from(userid.clone()))
                        .chain(sigs.iter().map(|sig| Packet::from(sig.clone())))
                }))
            .map(|(cert, _changed)| cert)
            .map_err(op!())?;

        if let Some(mut output) = output {
            cert.serialize(&mut output).map_err(op!())?;
        } else {
            // Import it.
            let cert_store = sequoia.cert_store_or_else().map_err(op!())?;

            if let Err(err) = cert_store.update(Arc::new(cert.into())) {
                return Err(err)
                    .context("Importing updated certificate")
                    .map_err(op!());
            }
        }

        Ok(certifications)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::PacketPile;
    use openpgp::parse::Parse;
    use openpgp::types::ReasonForRevocation;

    use crate::prompt::Cancel;

    fn check(output: Vec<Output>,
             expected_operational_errors: usize,
             expected_argument_errors: usize,
             expected_certifications: usize,
             expected_certifications_skipped: usize,
             expected_certifications_failed: usize)
    {
        let mut operational_errors = 0;
        let mut argument_errors = 0;
        let mut certifications = 0;
        let mut certifications_skipped = 0;
        let mut certifications_failed = 0;
        let mut saw_report = false;

        eprintln!("-----------------\nStart of certify");
        for o in output.iter() {
            match o {
                Output::OperationalError(err) => {
                    eprintln!("OperationError: {}", err);
                    assert!(! saw_report);
                    operational_errors += 1;
                }
                Output::ArgumentError(err) => {
                    eprintln!("ArguementError: {}", err);
                    assert!(! saw_report);
                    argument_errors += 1;
                }
                Output::Certified(
                    output::Certified {
                        diff,
                        ..
                    }) => {
                    eprintln!("Certified");
                    if let Some(diff) = diff {
                        eprintln!("  Changed from previous certification:");
                        diff.dump(&mut std::io::stderr());
                    } else {
                        eprintln!("  No previous certification.");
                    }
                    assert!(! saw_report);
                    certifications += 1;
                }
                Output::CertificationSkipped(
                    output::CertificationSkipped {
                        reason,
                        ..
                    }) => {
                    eprintln!("CertificationSkipped: {}", reason);
                    assert!(! saw_report);
                    certifications_skipped += 1;
                }
                Output::CertificationFailed(
                    output::CertificationFailed {
                        error,
                        ..
                    }) =>
                {
                    eprintln!("CertificationFailed: {}", error);
                    certifications_failed += 1;
                }
                Output::Report(report) => {
                    assert!(! saw_report);
                    saw_report = true;
                    assert_eq!(report.certifications.len(), certifications);
                }
            }
        }
        eprintln!("End of certify");

        eprintln!("
                     Expected     Got
Operational Errors:  {:8}{:8}
Argument Errors:     {:8}{:8}
Certifications:      {:8}{:8}
Skipped:             {:8}{:8}
Failed:              {:8}{:8}",
                  expected_operational_errors, operational_errors,
                  expected_argument_errors, argument_errors,
                  expected_certifications, certifications,
                  expected_certifications_skipped, certifications_skipped,
                  expected_certifications_failed, certifications_failed);

        assert!(saw_report);
        assert_eq!(expected_operational_errors, operational_errors,
                   "operation errors");
        assert_eq!(expected_argument_errors, argument_errors,
                   "argument errors");
        assert_eq!(expected_certifications, certifications,
                   "certifications");
        assert_eq!(expected_certifications_skipped, certifications_skipped,
                   "certifications skipped");
        assert_eq!(expected_certifications_failed, certifications_failed,
                   "certifications failed");
    }

    #[test]
    fn certify() {
        let sequoia = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut alice_key = Vec::new();
        let mut alice_rev = Vec::new();
        let alice = sequoia
            .key_generate()
            .name("alice")
            .without_password()
            .generate(
                prompt::Cancel::new(),
                Some((&mut alice_key, &mut alice_rev)))
            .expect("Can generate key")
            .into_cert();
        sequoia
            .key_import()
            .import_key(alice.clone(), &mut Default::default())
            .expect("Can import key");

        let mut bob_key = Vec::new();
        let mut bob_rev = Vec::new();
        let bob = sequoia
            .key_generate()
            .name("bob")
            .without_password()
            .generate(
                prompt::Cancel::new(),
                Some((&mut bob_key, &mut bob_rev)))
            .expect("Can generate key")
            .into_cert();
        sequoia.key_import()
            .import_key(bob.clone(), &mut Default::default())
            .expect("Can import key");

        // Not imported into the key store.
        let mut carol_key = Vec::new();
        let mut carol_rev = Vec::new();
        let carol = sequoia
            .key_generate()
            .name("carol")
            .without_password()
            .generate(
                prompt::Cancel::new(),
                Some((&mut carol_key, &mut carol_rev)))
            .expect("Can generate key")
            .into_cert();
        let mut dave_key = Vec::new();
        let mut dave_rev = Vec::new();
        let dave = sequoia
            .key_generate()
            .name("dave")
            .without_password()
            .generate(
                prompt::Cancel::new(),
                Some((&mut dave_key, &mut dave_rev)))
            .expect("Can generate key")
            .into_cert();

        // Make a correct and reasonable certification over a
        // self-signed user ID.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .certify(
                    &alice,
                    &bob,
                    &["bob".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .expect("Can certify");
            check(output, 0, 0, 1, 0, 0);
        }

        // Make a correct and reasonable certification over a
        // self-signed user ID and a user ID that is not self signed.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .certify(
                    &alice,
                    &bob,
                    &["bob".into(), "petname".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .expect("Can certify");
            check(output, 0, 0, 2, 0, 0);
        }

        // Argument error: we can't supply a regular expression if the
        // trust depth is 0.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .add_regular_expression_constraint("regex")
                .certify(
                    &alice,
                    &bob,
                    &["bob".into(), "petname".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .unwrap_err();
            check(output, 0, 1, 0, 0, 0);
        }

        // Argument error: a certificate can't certify itself.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .add_regular_expression_constraint("regex")
                .certify(
                    &bob,
                    &bob,
                    &["bob".into(), "petname".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .unwrap_err();
            check(output, 0, 1, 0, 0, 0);
        }

        // Operational error: the certifier can't actually generate a
        // signature.
        {
            let carol_pub = carol.clone().strip_secret_key_material();
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .certify(
                    &carol_pub,
                    &dave,
                    &["dave".into(), "petname".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .unwrap_err();
            check(output, 1, 0, 0, 0, 0);
        }

        // We can't certify a revoked user ID.
        {
            let mut output = Vec::new();
            sequoia.key_userid_revoke()
                .revoke(
                    None, // Revoker.
                    &carol,
                    &UserID::from("carol"),
                    ReasonForRevocation::UIDRetired,
                    "bye",
                    Some(&mut output),
                    Cancel::new())
                .expect("Can revoke");

            let packets = PacketPile::from_bytes(&output)
                .expect("Can read revocation certificate");
            let carol_revoked = carol
                .clone()
                .insert_packets(packets.into_children())
                .expect("can insert revocation certificate")
                .0;

            // Normally this results in `certify` returning an error.
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .certify(
                    &dave,
                    &carol_revoked,
                    &["carol".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .unwrap_err();
            check(output, 0, 0, 0, 0, 1);

            // If we say ignore_certification_errors, `certify` will
            // return `Ok` (but it will still say that the
            // certification failed).
            let mut output = Vec::new();
            sequoia
                .pki_certify()
                .ignore_certification_errors(true)
                .certify(
                    &dave,
                    &carol_revoked,
                    &["carol".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    Some(&mut certified))
                .unwrap();
            check(output, 0, 0, 0, 0, 1);
        }

        // If we make the same certification twice, the second one
        // should be skipped.
        {
            let mut output = Vec::new();
            sequoia
                .pki_certify()
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob,
                    &["bob".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    None)
                .expect("Can certify");
            check(output, 0, 0, 1, 0, 0);

            let bob2 = sequoia.lookup_one(bob.key_handle(), None, false)
                .expect("Certificate for bob is in cert store");

            let mut output = Vec::new();
            sequoia
                .pki_certify()
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob2,
                    &["bob".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    None)
                .expect("Can certify");
            check(output, 0, 0, 0, 1, 0);

            // Unless recreate is specified.
            let mut output = Vec::new();
            sequoia
                .pki_certify()
                .recreate(true)
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob2,
                    &["bob".into()],
                    &mut output,
                    prompt::Cancel::new(),
                    None)
                .expect("Can certify");
            check(output, 0, 0, 1, 0, 0);
        }
    }
}
