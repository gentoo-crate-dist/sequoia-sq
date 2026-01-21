use std::sync::Arc;
use std::ops::Deref;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_wot as wot;
use wot::FULLY_TRUSTED;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::Sequoia;
use crate::config::Expiration;
use crate::consts::SECONDS_IN_YEAR;
use crate::prompt;
use crate::provenance::active_certification;
use crate::transitional::output::cert::emit_cert_userid;
use crate::types::Convert;
use crate::types::Safe;

// Returns whether two certifications have different parameters.
//
// Returns true if the parameters are different.  Returns false if
// they are the same.
//
// This does some normalization and only considers things that are
// relevant to certifications:
//
//   - Expiration time
//   - Trust depth
//   - Trust amount
//   - Regular expressions
//   - Notations
//   - Exportable
pub fn diff_certification(unless_quiet: &mut dyn std::io::Write,
                          old: &Signature, new: &SignatureBuilder,
                          new_ct: SystemTime)
    -> bool
{
    let mut changed = false;

    let a_expiration = old.signature_expiration_time();
    let b_expiration = if let Some(vp) = new.signature_validity_period() {
        Some(new_ct + vp)
    } else {
        None
    };
    if a_expiration != b_expiration {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
            "updating expiration time: {} -> {}",
            if let Some(a_expiration) = a_expiration {
                chrono::DateTime::<chrono::offset::Utc>::from(
                    a_expiration).to_string()
            } else {
                "no expiration".to_string()
            },
            if let Some(b_expiration) = b_expiration {
                chrono::DateTime::<chrono::offset::Utc>::from(
                    b_expiration).to_string()
            } else {
                "no expiration".to_string()
            });
    }

    let (a_depth, a_amount) = old.trust_signature().unwrap_or((0, 120));
    let (b_depth, b_amount) = new.trust_signature().unwrap_or((0, 120));

    if a_amount != b_amount {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                  "updating trust amount: {} -> {}",
                  a_amount, b_amount);
    }
    if a_depth != b_depth {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                  "updating trust depth: {} -> {}",
                  a_depth, b_depth);
    }

    let mut a_regex: Vec<_> = old.regular_expressions().collect();
    a_regex.sort();
    a_regex.dedup();
    let mut b_regex: Vec<_> = new.regular_expressions().collect();
    b_regex.sort();
    b_regex.dedup();

    if a_regex != b_regex {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                  "updating regular expressions");

        wwriteln!(stream = unless_quiet, initial_indent = "     - ",
                  "current certification");
        for (i, r) in a_regex.into_iter().enumerate() {
            wwriteln!(stream = unless_quiet, initial_indent = "       - ",
                      "{}. {}", i + 1, Safe(r));
        }

        wwriteln!(stream = unless_quiet, initial_indent = "     - ",
                  "new certification");
        for (i, r) in b_regex.into_iter().enumerate() {
            wwriteln!(stream = unless_quiet, initial_indent = "       - ",
                      "{}. {}", i + 1, Safe(r));
        }
    }

    let a_notations: Vec<_> = old.notation_data()
        .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
        .collect();
    let b_notations: Vec<_> = new.notation_data()
        .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
        .collect();
    if a_notations != b_notations {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                  "updating notations");

        wwriteln!(stream = unless_quiet, initial_indent = "     - ",
                  "current certification");
        for (i, n) in a_notations.into_iter().enumerate() {
            wwriteln!(stream = unless_quiet, initial_indent = "       - ",
                      "{}. {}", i + 1, Safe(n));
        }

        wwriteln!(stream = unless_quiet, initial_indent = "     - ",
                  "updated certification");
        for (i, n) in b_notations.into_iter().enumerate() {
            wwriteln!(stream = unless_quiet, initial_indent = "       - ",
                      "{}. {}", i + 1, Safe(n));
        }
    }

    let a_exportable = old.exportable_certification().unwrap_or(true);
    let b_exportable = new.exportable_certification().unwrap_or(true);
    if a_exportable != b_exportable {
        changed = true;
        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                  "updating exportable flag: {} -> {}",
                  a_exportable, b_exportable);
    }

    changed
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

                recreate: false,
                user_supplied_userids: false,
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
    pub fn trust_amount(&mut self, trust_amount: u8) -> &mut Self {
        self.template.trust_amount = Some(trust_amount);
        self
    }

    /// Sets the certification's trust depth.
    ///
    /// For details, see [`Builder::trust_depth`].
    ///
    /// If unset, it falls back to the value specified in [`Params`].
    pub fn trust_depth(&mut self, trust_depth: u8) -> &mut Self {
        self.template.trust_depth = Some(trust_depth);
        self
    }

    /// Sets the certification's expiration.
    ///
    /// For details, see [`Builder::expiration`].
    ///
    /// If unset, it falls back to the value specified in [`Params`].
    pub fn expiration(&mut self, expiration: Expiration) -> &mut Self {
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

    recreate: bool,
    user_supplied_userids: bool,
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

    /// Returns whether the user supplied the user IDs.
    pub fn user_supplied_userids(&self) -> bool {
        self.user_supplied_userids
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
    pub fn recreate(&mut self, recreate: bool) -> &mut Self {
        self.params.recreate = recreate;
        self
    }

    /// Sets whether the user supplied the user IDs.
    pub fn user_supplied_userids(&mut self, user_supplied_userids: bool)
        -> &mut Self
    {
        self.params.user_supplied_userids = user_supplied_userids;
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
    pub fn trust_amount(&mut self, trust_amount: u8) -> &mut Self {
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
    pub fn trust_depth(&mut self, trust_depth: u8) -> &mut Self {
        self.params.trust_depth = trust_depth;
        self
    }

    /// Sets certification's expiration time.
    ///
    /// By default, the certification expires after 10 years.
    pub fn expiration(&mut self, expiration: Expiration) -> &mut Self {
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
    pub fn add_domain_constraint<S>(&mut self, domain: S)
        -> &mut Self
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
    pub fn add_domain_constraints<S>(&mut self, domains: impl Iterator<Item=S>)
        -> &mut Self
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
    pub fn add_regular_expression_constraint<S>(&mut self, regex: S)
        -> &mut Self
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
        &mut self, regexes: impl Iterator<Item=S>)
        -> &mut Self
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
    pub fn exportable(&mut self, exportable: bool) -> &mut Self {
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
    pub fn revocable(&mut self, revocable: bool) -> &mut Self {
        self.params.revocable = revocable;
        self
    }

    /// Adds a notation to each of the new signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(&mut self, critical: bool, notation: NotationData)
        -> &mut Self
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
    pub fn add_notations(&mut self,
                         notations: impl Iterator<Item=(bool, NotationData)>)
        -> &mut Self
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
    pub fn add_certification<T>(&mut self, template: T)
        -> &mut Self
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
    pub fn add_certifications<T>(&mut self, templates: impl Iterator<Item=T>)
        -> &mut Self
    where
        T: Into<CertificationTemplate>
    {
        self.params.additional_certifications.extend(templates.map(|t| t.into()));
        self
    }

    /// Generate or retract a certification.
    ///
    /// `certifier` is the certificate that will be used to generate
    /// the certification.
    ///
    /// `cert` and `userids` are the certificate and the user IDs that
    /// will be certified.  A certification will be generated for the
    /// certificate and each user ID (i.e., each binding).
    ///
    /// If the trust amount is 0, the operation is interpreted as a
    /// retraction of any prior certifications by the certifier over
    /// the bindings.
    pub fn certify<P>(&self,
                      certifier: &Cert,
                      cert: &Cert,
                      userids: &[UserID],
                      output: Option<(Option<&Path>, &mut dyn std::io::Write)>,
                      o: &mut dyn std::io::Write,
                      prompt: P)
        -> Result<()>
    where
        P: prompt::Prompt
    {
        let &Builder {
            params: Params {
                sequoia,

                recreate,
                user_supplied_userids,
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

        let unless_quiet = if sequoia.config.quiet() {
            &mut std::io::sink()
        } else {
            o
        };


        if certifier.fingerprint() == cert.fingerprint() {
            sequoia.hint(
                format_args!("\
                    The certificate to certify is the same as the certificate being certified. \
                    If you are trying to add a user ID, try:"))
            .sq().arg("key").arg("userid").arg("add")
            .arg_value("--cert", cert.fingerprint())
            .arg_value("--userid", &userids[0])
            .done();

        return Err(
            anyhow::format_err!("\
The certifier is the same as the certificate to certify."));
        }

        if trust_depth == 0 && !regular_expressions.is_empty() {
            return Err(
                anyhow::format_err!("A regex constraint only makes sense \
                                     if the trust depth is greater than 0"));
        }

        // Get the signer to certify with.
        let mut signer = sequoia.get_certification_key(
            certifier, None, &prompt)?;

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
                    trust_depth, trust_amount)?;
            }

            // Creation time.
            //
            // If we should make two certifications, then the first one
            // should be at `sequoia.time() - 1`, and the second one at
            // `sequoia.time()`.  That is, the first one is a second earlier.
            let backdate = Duration::new((additional_certifications.len() - i) as u64, 0);
            let ct = sequoia.time() - backdate;
            builder = builder.set_signature_creation_time(ct)?;

            // Expiration.
            let expiration = certification
                .expiration
                .as_ref()
                .unwrap_or(expiration);
            if let Some(validity) = expiration
                .as_duration(DateTime::<Utc>::from(sequoia.time()))?
            {
                builder = builder.set_signature_validity_period(validity)?;
            }

            builders.push(builder);
        }

        // Get the active certification as of the reference time.
        let certifications = active_certification(
                &sequoia, &cert, userids.iter(),
                certifier.primary_key().key().role_as_unspecified())
            .into_iter()
            .map(|(userid, active_certification)| {
                if let Some(ua) = cert.userids().find(|ua| ua.userid() == userid) {
                    if retract {
                        // Check if we certified it.
                        if ! ua.certifications().any(|c| {
                            c.get_issuers().into_iter()
                                .any(|issuer| issuer.aliases(&certifier.key_handle()))
                        })
                        {
                            emit_cert_userid(unless_quiet, cert, userid)?;
                            wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                                      "this binding was never certified; \
                                       there is nothing to retract");

                            if user_supplied_userids {
                                return Err(anyhow::anyhow!(
                                    "You never certified {} for {}, \
                                     there is nothing to retract.",
                                    Safe(userid), cert.fingerprint()));
                            } else {
                                return Ok(vec![ Packet::from(userid.clone()) ]);
                            }
                        }
                    } else {
                        if let RevocationStatus::Revoked(_)
                            = ua.revocation_status(sequoia.policy(), sequoia.time())
                        {
                            // It's revoked.
                            if user_supplied_userids {
                                // It was explicitly mentioned.  Return an
                                // error.
                                return Err(anyhow::anyhow!(
                                    "Can't certify {} for {}, it's revoked",
                                    Safe(userid), cert.fingerprint()));
                            } else {
                                // We're just considering valid, self-signed
                                // user IDs.  Silently, skip it.
                                return Ok(vec![]);
                            }
                        }
                    }
                } else if retract {
                    emit_cert_userid(unless_quiet, cert, userid)?;
                    wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                              "this binding was never certified; \
                               there is nothing to retract");

                    if user_supplied_userids {
                        return Err(anyhow::anyhow!(
                            "You never certified {} for {}, \
                             there is nothing to retract.",
                            Safe(userid), cert.fingerprint()));
                    } else {
                        // The user passed --all.  Don't error out if some
                        // user IDs were not linked.  Instead, return a
                        // signature packet to indicate that we processed
                        // something; just don't return a signature.
                        return Ok(vec![ Packet::from(userid.clone()) ]);
                    }
                }

                if let Some(active_certification) = active_certification {
                    let active_certification_ct
                        = active_certification.signature_creation_time()
                        .expect("valid signature");

                    let retracted = matches!(active_certification.trust_signature(),
                                             Some((_depth, 0)));
                    if retracted {
                        emit_cert_userid(unless_quiet, cert, userid)?;
                        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                                  "a prior certification was retracted at {}",
                                  active_certification_ct.convert());
                    } else {
                        emit_cert_userid(unless_quiet, cert, userid)?;
                        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                                  "was previously certified at {}",
                                  active_certification_ct.convert());
                    }

                    let changed = diff_certification(
                        unless_quiet,
                        &active_certification,
                        &builders[0], sequoia.time());

                    if ! changed {
                        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                                  "certification parameters are unchanged; \
                                   there is nothing to do");

                        if ! recreate {
                            // Return a signature packet to indicate that we
                            // processed something.  But don't return a
                            // signature.
                            return Ok(vec![ Packet::from(userid.clone()) ]);
                        }
                    } else {
                        wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                                  "certification parameters changed, \
                                   creating a new certification");
                    }
                } else {
                    emit_cert_userid(unless_quiet, cert, userid)?;
                }

                if retract {
                    wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                              "certification retracted");
                } else {
                    wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                              "certification created");
                }

                let mut sigs = builders.iter()
                    .map(|builder| {
                        builder.clone().sign_userid_binding(
                            &mut signer,
                            cert.primary_key().key(),
                            userid)
                            .with_context(|| {
                                format!("Creating certification for {}",
                                        Safe(userid))
                            })
                            .map(Into::into)
                    })
                    .collect::<Result<Vec<Packet>>>()?;

                wwriteln!(stream = unless_quiet);

                let mut packets = vec![ Packet::from(userid.clone()) ];
                packets.append(&mut sigs);
                Ok(packets)
            })
            .collect::<Result<Vec<Vec<Packet>>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<Packet>>();

        if certifications.is_empty() {
            if retract {
                return Err(anyhow::anyhow!(
                    "Can't retract links for {}.  There is nothing to retract.",
                    cert.fingerprint()));
            } else {
                return Err(anyhow::anyhow!(
                    "Can't certify {}.  The certificate has no self-signed \
                     user IDs and you didn't specify any user IDs to certify.",
                    cert.fingerprint()));
            }
        }

        if certifications.iter().all(|p| matches!(p, Packet::UserID(_))) {
            // There are no signatures to insert.  We're done.
            return Ok(());
        }

        let cert = cert.clone().insert_packets(certifications)?.0;

        if let Some((path, mut output)) = output {
            cert.serialize(&mut output)?;

            if exportable {
                if let Some(path) = path {
                    sequoia.hint(format_args!(
                        "Updated certificate written to {}.  \
                         To make the update effective, it has to be published \
                         so that others can find it, for example using:",
                        path.display()))
                        .sq().arg("network").arg("keyserver").arg("publish")
                        .arg_value("--cert-file", path.display())
                        .done();
                } else {
                    sequoia.hint(format_args!(
                        "To make the update effective, it has to be published \
                         so that others can find it."));
                }
            }
        } else {
            // Import it.
            let cert_store = sequoia.cert_store_or_else()?;

            let fipr = cert.fingerprint();
            if let Err(err) = cert_store.update(Arc::new(cert.into())) {
                weprintln!("Error importing updated cert: {}", err);
                return Err(err);
            } else if exportable {
                sequoia.hint(format_args!(
                    "Imported updated cert into the cert store.  \
                     To make the update effective, it has to be published \
                     so that others can find it, for example using:"))
                    .sq().arg("network").arg("keyserver").arg("publish")
                    .arg_value("--cert", fipr)
                    .done();
            }
        }

        Ok(())
    }
}
