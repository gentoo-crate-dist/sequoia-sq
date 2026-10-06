//! Certify user IDs and certificates.
//!
//! # Certifications
//!
//! Let's say Alice wants to send an encrypted message to Bob, or she
//! has a signed message that she thinks is from Bob.  In both cases,
//! she needs Bob's certificate.  After figuring out what the right
//! certificate is, she should either memorize its fingerprint, or
//! record that the certificate belongs to Bob so that she doesn't
//! have to authenticate Bob's certificate again the next time she
//! needs it.  Memorizing fingerprints is impractical.  So it is
//! usually better to record the information.
//!
//! One way to record who a certificate belongs to, is to use a
//! certification.  A certification is a special signature over a
//! certificate and a user ID.  It says: the certifier is convinced
//! that this certificate is controlled by an entity identified by the
//! user ID.  Alice's software can use this certification to find the
//! right certificate for Bob in the future.  (See
//! [`Sequoia::cert_list`](crate::cert::list).)
//!
//! # Trusted Introducers
//!
//! If Alice decides to, she can share the certification with other
//! people.  If they are willing to rely on her, they can use her
//! certification to help them find the right certificate for Bob.
//! (And because the certification is a signature, they can check that
//! it is authentic.)  In these cases, those people consider Alice to
//! be a trusted introducer.  A trusted introducer is another word for
//! [certification authority] (CA).  This information can also be
//! recorded using a certification.  To do this, set the trust depth
//! to be greater than 0 using [`Builder::trust_depth`].
//!
//! [certification authority]: https://en.wikipedia.org/wiki/Certificate_authority
//!
//! In OpenPGP, certification authorities don't need to be all
//! powerful.  Instead, someone can indicate that Alice is only
//! partially trusted (see [`Builder::trust_amount`]).  This means
//! that they need corroborating evidence from other trusted
//! introducers.  Or, they can indicate that Alice should only be
//! relied upon for email addresses within a certain domain, e.g.,
//! `example.org` (see [`Builder::add_domain_constraint`]).  That is,
//! Alice is only authoritative for user IDs with an email address in
//! the `example.org` domain.
//!
//! # Social Graph
//!
//! Publishing a certification reveals the user's social graph.
//! Particularly for private individuals, this is not always
//! acceptable.  To prevent certifications from being accidentally
//! published, you can clear the exportable flag using
//! [`Builder::exportable`].  When OpenPGP software exports a
//! certificate, it normally strips any non-exportable certifications.
//! Similarly, well-behaving key servers strip non-exportable
//! certifications on import.
//!
//! # Local Trust Root
//!
//! Sequoia maintains a local trust root.  The local trust root is
//! user's default trust anchor.  It allows the user to create
//! certifications independent of their day-to-day certificates.  Then
//! if their day-to-day certificate expires, for instance, they don't
//! need to recreate all of the certifications.  In particular, if a
//! certification should not be exportable, you should probably use
//! the local trust root instead of a specific certificate to create
//! the certification.
//!
//! To get the local trust root, you can use
//! [`Sequoia::local_trust_root`].  If it doesn't exist, then it is
//! automatically created.
//!
//! Note: It is possible to add additional trust roots using
//! [`SequoiaBuilder::add_trust_root`](crate::SequoiaBuilder::add_trust_root).
//!
//! # Examples
//!
//! Alice certifies that a certificate is controlled by
//! `bob@example.org`.
//!
//! [`certify`](Builder::certify) takes two certificates: the
//! certifier's certificate and the certificate to be certified.  If
//! you have a `Fingerprint` or `KeyID`, use
//! [`Sequoia::lookup`](crate::lookup) to find the corresponding
//! certificate.  If you have an email address, use
//! [`Sequoia::lookup_by`](crate::lookup_by) to find an authenticated
//! certificate.
//!
//! Note: The certifier's certificate does not itself need to contain
//! the secret key material.  The certify function looks for secret
//! key material in the certificate itself, in any [specified
//! keyrings](crate::SequoiaBuilder::add_keyring), and on the key
//! store.
//!
//! ```
//! # use sequoia::openpgp;
//! # use openpgp::cert::CertBuilder;
//! # use openpgp::serialize::Serialize;
//! #
//! # use sequoia::Sequoia;
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
//!         &["<bob@example.org>".into()])
//! {
//!     eprintln!("Failed to certify the user ID: {}", err);
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
//! use sequoia::pki::certify::Output;
//! use sequoia::pki::certify::output::*;
//! use sequoia::pki::certify;
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
//! impl certify::Stream<'_> for Stream {
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
//!     .stream(&mut stream)
//!     .certify(
//!         &alice,
//!         &bob,
//!         &["<bob@example.org>".into()])
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

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::Writer;
use crate::config::Expiration;
use crate::consts::SECONDS_IN_YEAR;
use crate::destination::Destination;
use crate::destination::DestinationSummary;
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
/// This `diff` does not intend to cover every possible difference
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

    /// Computes the difference between two certifications.
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

// Stream trait.
stream!{}

/// Errors related to certifications.
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
///
/// These errors are usually wrapped in an [`Error`].
pub mod error {
    use super::*;

    /// The certificate or the user ID is revoked and can't be
    /// certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
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
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum CertificationError {
        #[error(transparent)]
        Revoked(#[from] Revoked),
        #[error(transparent)]
        Other(#[from] Arc<anyhow::Error>),
    }

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    /// The [`Report`](output::Report) event is still emitted.
    ///
    /// An example of an operational error is that a key store is not
    /// available, but needed to complete the operation.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum OperationalError {
        #[error(transparent)]
        CertificationError(CertificationError),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// The certifier is the same as the certificate to certify.
    ///
    /// To create a third-party certifications, the certifier must be
    /// different from the certificate being certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("The certifier is the same as the certificate to certify")]
    pub struct CertifierSameAsCertificate {
        pub cert: Cert,
    }

    /// A regular expression was used with a certification with a
    /// trust depth of 0.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("A regex constraint only makes sense \
             if the trust depth is greater than 0")]
    pub struct NoRegularExpressions {
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.  The
    /// [`Report`](output::Report) event is still emitted.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        CertifierSameAsCertificate(CertifierSameAsCertificate),
        #[error(transparent)]
        NoRegularExpressions(NoRegularExpressions),
    }

    /// The caller attempted to create a retraction, but there is
    /// nothing to retract.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("You never certified {} for {}, there is nothing to retract.",
            Safe(.userid), .fingerprint)]
    pub struct NothingToRetract {
        pub fingerprint: Fingerprint,
        pub userid: UserID,
    }

    /// The binding was previous certified.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
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
    #[derive(thiserror::Error, Debug, Clone)]
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

/// The [`Stream`] output.
///
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

    /// Emitted after any certifications have been created and either
    /// exported or imported to the certificate store.
    Certified(output::Certified),

    /// Emitted when a certification is skipped.
    ///
    /// This is not an error.
    CertificationSkipped(output::CertificationSkipped),

    /// Emitted when the certification failed.
    ///
    /// By default, this is a hard error.  Setting
    /// [`Builder::ignore_certification_errors`] turns it into a soft
    /// error.
    CertificationFailed(output::CertificationFailed),

    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is certified or not.
    Report(output::Report),
}

/// The certify operation's outcome.
///
/// Returned by [`Builder::certify`].  It contains information about
/// the operation's outcome.  More detailed information is available
/// via the [`Stream`] interface.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The updated certificate.
    pub cert: Cert,

    /// The generated certifications.
    pub certifications: Vec<(UserID, Vec<Signature>)>,
}

impl Outcome {
    fn new(cert: &Cert) -> Self {
        Outcome {
            cert: cert.clone(),
            certifications: Vec::new(),
        }
    }

    fn to_report(&self) -> output::Report {
        output::Report {
            certifications: self.certifications.clone(),
        }
    }

    /// Returns a reference to the updated certificate.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    /// Returns the updated certificate.
    pub fn into_cert(self) -> Cert {
        self.cert
    }

    /// Returns the generated certifications.
    pub fn certifications(&self)
        -> impl Iterator<Item=&(UserID, Vec<Signature>)>
    {
        self.certifications.iter()
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
    destination: DestinationSummary,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    destination_params_impl!("certificate", "is");

    /// Returns whether certification errors are ignored.
    ///
    /// By default, [`CertificationError`s](error::CertificationError)
    /// are considered hard errors and cause processing to stop.  If
    /// this is set, it turns `CertificationError`s into soft errors.
    /// In that case, you can still reject certain certifications by
    /// catching them in your [`Stream`] implementation and returning
    /// an error.
    ///
    /// If `ignore_certification_errors` is `false`, then an error
    /// will be emitted twice.  Once as
    /// [`Output::CertificationFailed`] and then as
    /// [`Output::OperationalError`].
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

/// Owned parameters.
struct ParamsOnce<'sequoia, 'writer, 'stream, 'prompt> {
    destination: Destination<Writer<'writer>>,
    stream: Option<Box<dyn Stream<'sequoia> + 'stream>>,
    prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>,
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
/// implementation to automatically determine the right certificate
/// for Bob in the future.
///
/// If Alice is also willing to rely on Bob to introduce her to other
/// people, then she could record that in the certification as well
/// using [`Builder::trust_depth`].  Depending on how much she trusts
/// Bob, she might want to constrain Bob to, for example, only allow
/// him to introduce people with an email address from a particular
/// domain using [`Builder::add_domain_constraint`].  Then if Bob were
/// to certify Carol's certificate, Alice would also find the right
/// certificate for Carol.
pub struct Builder<'sequoia, 'writer, 'stream, 'prompt> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'sequoia, 'writer, 'stream, 'prompt>,
}

impl<'sequoia, 'writer, 'stream, 'prompt>
    Builder<'sequoia, 'writer, 'stream, 'prompt>
{
    /// The default expiration of a third-party certification.
    const DEFAULT_CERTIFICATION_EXPIRATION: Expiration
        = Expiration::from_duration(Duration::from_secs(10 * SECONDS_IN_YEAR));

    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Self
    {
        Builder {
            params: Params {
                sequoia,

                ignore_certification_errors: false,
                recreate: false,
                expiration: Self::DEFAULT_CERTIFICATION_EXPIRATION,
                trust_amount: FULLY_TRUSTED as u8,
                trust_depth: 0,
                domains: Vec::new(),
                regular_expressions: Vec::new(),
                exportable: true,
                revocable: true,
                notations: Vec::new(),
                additional_certifications: Vec::new(),
                destination: DestinationSummary::Store,
            },
            params_once: ParamsOnce {
                destination: Destination::Store,
                stream: None,
                prompt: None,
            }
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    destination_builder_impl!('sequoia; 'stream, 'prompt; "certificate", "is");

    stream_builder_impl!('writer; 'prompt,);

    prompt_builder_impl!('writer, 'stream; );

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
    pub fn add_domain_constraints<S>(mut self,
                                     domains: impl IntoIterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.domains.extend(
            domains.into_iter().map(|d| d.as_ref().to_string()));
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
        mut self, regexes: impl IntoIterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.regular_expressions.extend(
            regexes.into_iter().map(|r| r.as_ref().to_string()));
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
                         notations: impl IntoIterator<Item=(bool, NotationData)>)
        -> Self
    {
        self.params.notations.extend(notations.into_iter());
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
    pub fn add_certifications<T>(mut self, templates: impl IntoIterator<Item=T>)
        -> Self
    where
        T: Into<CertificationTemplate>
    {
        self.params.additional_certifications.extend(
            templates.into_iter().map(|t| t.into()));
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
    pub fn certify(mut self,
                   certifier: &Cert,
                   cert: &Cert,
                   userids: &[UserID])
        -> Result<Outcome, Error>
    {
        let mut outcome = Outcome::new(cert);

        let result = Self::certify_(
            &self.params, &mut self.params_once,
            certifier, cert, userids, &mut outcome);

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

    fn certify_(
        params: &Params<'sequoia>,
        params_once: &mut ParamsOnce<'sequoia, 'writer, 'stream, 'prompt>,
        certifier: &Cert,
        cert: &Cert,
        userids: &[UserID],
        outcome: &mut Outcome)
        -> Result<(), Error>
    {
        tracer!(false, "certify");

        let &Params {
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
            destination: _,
        } = params;
        let ParamsOnce {
            destination,
            stream,
            prompt,
        } = params_once;

        assert!(userids.len() > 0);

        if certifier.fingerprint() == cert.fingerprint() {
            return Err(Error::ArgumentError(
                error::ArgumentError::CertifierSameAsCertificate(
                    error::CertifierSameAsCertificate {
                        cert: cert.clone(),
                    })));
        }

        if trust_depth == 0 && !regular_expressions.is_empty() {
            return Err(Error::ArgumentError(
                error::ArgumentError::NoRegularExpressions(
                    error::NoRegularExpressions {
                    })));
        }

        let prep = ||  -> Result<_, anyhow::Error> {
            // Get the signer to certify with.
            let signer = sequoia
                .signer()
                .prompt_(prompt.clone())
                .get_certification_key(certifier)?;

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
                            params,
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
                            params,
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
                            return Err(Error::OperationalError(
                                error::OperationalError::CertificationError(
                                    error::CertificationError::Revoked(
                                        error::Revoked {
                                            fingerprint: cert.fingerprint(),
                                            userid: userid.clone(),
                                            revocation: revs[0].clone(),
                                        }))));
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
                        params,
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
                        params,
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
                        params,
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
                    let err = Arc::new(err);
                    stream.output(
                        params,
                        Output::CertificationFailed(
                            output::CertificationFailed {
                                cert: cert.clone(),
                                userid: userid.clone(),
                                error: error::CertificationError::Other(
                                    Arc::clone(&err)),
                            }))
                        .map_err(|err| Error::StreamOutputError(err))?;

                    if ! ignore_certification_errors {
                        return Err(Error::OperationalError(
                            error::OperationalError::CertificationError(
                                error::CertificationError::Other(err))));
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
            return Ok(());
        }

        let cert = cert.clone()
            .insert_packets(
                certifications.iter().flat_map(|(userid, sigs)| {
                    std::iter::once(Packet::from(userid.clone()))
                        .chain(sigs.iter().map(|sig| Packet::from(sig.clone())))
                }))
            .map(|(cert, _changed)| cert)
            .map_err(op!())?;

        match destination {
            Destination::Writer(ref mut output) => {
                cert.serialize(output).map_err(op!())?;
            }
            Destination::Store => {
                // Import it.
                let cert_store = sequoia.cert_store_or_else().map_err(op!())?;

                if let Err(err) = cert_store.update(Arc::new(cert.clone().into())) {
                    return Err(err)
                        .context("Importing updated certificate")
                        .map_err(op!());
                }
            }
            Destination::Ephemeral => {
                // Do nothing.
            }
        }

        outcome.cert = cert;
        outcome.certifications = certifications;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::PacketPile;
    use openpgp::parse::Parse;
    use openpgp::types::ReasonForRevocation;

    fn check(output: Vec<Output>,
             outcome: impl Into<Option<Outcome>>,
             expected_operational_errors: usize,
             expected_argument_errors: usize,
             expected_certifications: usize,
             expected_certifications_skipped: usize,
             expected_certifications_failed: usize)
    {
        let outcome = outcome.into();

        let mut operational_errors = 0;
        let mut argument_errors = 0;
        let mut system_errors = 0;
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
                Output::SystemError(err) => {
                    eprintln!("SystemError: {}", err);
                    assert!(! saw_report);
                    system_errors += 1;
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
System Errors:       {:8}{:8}
Certifications:      {:8}{:8}
Skipped:             {:8}{:8}
Failed:              {:8}{:8}",
                  expected_operational_errors, operational_errors,
                  expected_argument_errors, argument_errors,
                  0, system_errors,
                  expected_certifications, certifications,
                  expected_certifications_skipped, certifications_skipped,
                  expected_certifications_failed, certifications_failed);

        assert!(saw_report);
        assert_eq!(system_errors, 0);
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

        assert_eq!(outcome.map(|a| a.certifications.len()).unwrap_or(0),
                   certifications);
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
            .to_writer((&mut alice_key, &mut alice_rev))
            .generate()
            .expect("Can generate key")
            .into_cert();
        sequoia
            .key_import()
            .import_key(alice.clone())
            .expect("Can import key");

        let mut bob_key = Vec::new();
        let mut bob_rev = Vec::new();
        let bob = sequoia
            .key_generate()
            .name("bob")
            .without_password()
            .to_writer((&mut bob_key, &mut bob_rev))
            .generate()
            .expect("Can generate key")
            .into_cert();
        sequoia.key_import()
            .import_key(bob.clone())
            .expect("Can import key");

        // Not imported into the key store.
        let mut carol_key = Vec::new();
        let mut carol_rev = Vec::new();
        let carol = sequoia
            .key_generate()
            .name("carol")
            .without_password()
            .to_writer((&mut carol_key, &mut carol_rev))
            .generate()
            .expect("Can generate key")
            .into_cert();
        let mut dave_key = Vec::new();
        let mut dave_rev = Vec::new();
        let dave = sequoia
            .key_generate()
            .name("dave")
            .without_password()
            .to_writer((&mut dave_key, &mut dave_rev))
            .generate()
            .expect("Can generate key")
            .into_cert();

        // Make a correct and reasonable certification over a
        // self-signed user ID.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .certify(
                    &alice,
                    &bob,
                    &["bob".into()])
                .expect("Can certify");
            check(output, outcome, 0, 0, 1, 0, 0);
        }

        // Make a correct and reasonable certification over a
        // self-signed user ID and a user ID that is not self signed.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .certify(
                    &alice,
                    &bob,
                    &["bob".into(), "petname".into()])
                .expect("Can certify");
            check(output, outcome, 0, 0, 2, 0, 0);
        }

        // Argument error: we can't supply a regular expression if the
        // trust depth is 0.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .add_regular_expression_constraint("regex")
                .certify(
                    &alice,
                    &bob,
                    &["bob".into(), "petname".into()])
                .unwrap_err();
            check(output, None, 0, 1, 0, 0, 0);
        }

        // Argument error: a certificate can't certify itself.
        {
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .add_regular_expression_constraint("regex")
                .certify(
                    &bob,
                    &bob,
                    &["bob".into(), "petname".into()])
                .unwrap_err();
            check(output, None, 0, 1, 0, 0, 0);
        }

        // Operational error: the certifier can't actually generate a
        // signature.
        {
            let carol_pub = carol.clone().strip_secret_key_material();
            let mut output = Vec::new();
            let mut certified = Vec::new();
            sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .certify(
                    &carol_pub,
                    &dave,
                    &["dave".into(), "petname".into()])
                .unwrap_err();
            check(output, None, 1, 0, 0, 0, 0);
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
                    Some(&mut output))
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
                .stream(&mut output)
                .to_writer(&mut certified)
                .certify(
                    &dave,
                    &carol_revoked,
                    &["carol".into()])
                .unwrap_err();
            check(output, None, 1, 0, 0, 0, 1);

            // If we say ignore_certification_errors, `certify` will
            // return `Ok` (but it will still say that the
            // certification failed).
            let mut output = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .to_writer(&mut certified)
                .ignore_certification_errors(true)
                .certify(
                    &dave,
                    &carol_revoked,
                    &["carol".into()])
                .unwrap();
            check(output, outcome, 0, 0, 0, 0, 1);
        }

        // If we make the same certification twice, the second one
        // should be skipped.
        {
            let mut output = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob,
                    &["bob".into()])
                .expect("Can certify");
            check(output, outcome, 0, 0, 1, 0, 0);

            let bob2 = sequoia
                .lookup()
                .lookup_one(bob.key_handle())
                .expect("Certificate for bob is in cert store");

            let mut output = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob2,
                    &["bob".into()])
                .expect("Can certify");
            check(output, outcome, 0, 0, 0, 1, 0);

            // Unless recreate is specified.
            let mut output = Vec::new();
            let outcome = sequoia
                .pki_certify()
                .stream(&mut output)
                .recreate(true)
                .expiration(Expiration::Never)
                .certify(
                    &alice,
                    &bob2,
                    &["bob".into()])
                .expect("Can certify");
            check(output, outcome, 0, 0, 1, 0, 0);
        }
    }
}
