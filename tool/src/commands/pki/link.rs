use std::{
    time::Duration,
};

use anyhow::Result;

use sequoia::pki::certify::CertificationTemplateBuilder;
use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::common::NULL_POLICY;

use crate::cli::pki::link;
use crate::cli::types::Expiration;
use crate::common::password;
use crate::output::pki::certify::Stream;

mod list;

pub fn link(sq: Sq, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(sq, c)?,
        Authorize(c) => authorize(sq, c)?,
        Retract(c) => retract(sq, c)?,
        List(c) => list::list(sq, c)?,
    }
    Ok(())
}

pub fn add(sq: Sq, c: link::AddCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy(), Some(sq.time()))?;
    let userids = c.userids.resolve(&vc)?
        .into_iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();
    let user_supplied_userids = ! c.userids.all().unwrap_or(false);

    let notations = c.signature_notations.parse()?;

    let primary_expiration;
    let mut extra_certification = None;
    if c.temporary {
        // The first certification at t-1 is the long-term
        // certification.  It marks the binding as partially
        // authenticated and expires at the specified time.  The
        // primary certification at t is the temporary certification.
        // It will be valid for a week with the specified trust
        // amount.
        //
        // When the primary certification expires, then the older link
        // will come into effect.  If the user has fully linked the
        // binding in the meantime, then this won't override that,
        // which is exactly what we want.
        extra_certification = Some(
            CertificationTemplateBuilder::new()
                .trust_amount(40)
                .expiration(c.expiration.value())
                .build());

        primary_expiration = Expiration::from_duration(
            Duration::new(7 * 24 * 60 * 60, 0));
    } else {
        primary_expiration = c.expiration.value();
    };

    let mut output = std::io::stdout();
    let stream = Stream::new(
        &sq,
        &cert,
        &userids,
        user_supplied_userids,
        None, // Output file.
        &mut output);

    let prompt = password::Prompt::new(&sq, true);

    sq.sequoia.pki_certify()
        .stream(stream)
        .recreate(c.recreate)
        .ignore_certification_errors(true) // Filtered by stream.
        .trust_amount(c.amount.amount())
        // Not a trusted introducer.
        .trust_depth(0)
        .expiration(primary_expiration)
        .exportable(false)
        .add_notations(notations.into_iter())
        .add_certifications(extra_certification.into_iter())
        .certify(
            &trust_root,
            &cert,
            &userids,
            prompt)?;

    Ok(())
}

pub fn authorize(sq: Sq, c: link::AuthorizeCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy(), Some(sq.time()))?;
    let userids = c.userids.resolve(&vc)?
        .into_iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();
    let user_supplied_userids = ! c.userids.all().unwrap_or(false);

    let notations = c.signature_notations.parse()?;

    let mut output = std::io::stdout();
    let stream = Stream::new(
        &sq,
        &cert,
        &userids,
        user_supplied_userids,
        None, // Output file.
        &mut output);

    let prompt = password::Prompt::new(&sq, true);

    sq.sequoia.pki_certify()
        .stream(stream)
        .recreate(c.recreate)
        .ignore_certification_errors(true) // Filtered by stream.
        .trust_amount(c.amount.amount())
        .trust_depth(c.depth)
        .expiration(c.expiration.value())
        .exportable(false)
        .add_domain_constraints(c.domain.iter())
        .add_regular_expression_constraints(c.regex.iter())
        .add_notations(notations.into_iter())
        .certify(
            &trust_root,
            &cert,
            &userids,
            prompt)?;

    Ok(())
}

pub fn retract(sq: Sq, c: link::RetractCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(NULL_POLICY, Some(sq.time()))?;
    let userids = c.userids.resolve(&vc)?
        .into_iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();
    let user_supplied_userids = ! c.userids.all().unwrap_or(false);

    let notations = c.signature_notations.parse()?;

    let mut output = std::io::stdout();
    let stream = Stream::new(
        &sq,
        &cert,
        &userids,
        user_supplied_userids,
        None, // Output file.
        &mut output);

    let prompt = password::Prompt::new(&sq, true);

    sq.sequoia.pki_certify()
        .stream(stream)
        .recreate(c.recreate)
        .ignore_certification_errors(true) // Filtered by stream.
        .trust_amount(0)
        .expiration(Expiration::Never)
        .exportable(false)
        .add_notations(notations.into_iter())
        .certify(
            &trust_root,
            &cert,
            &userids,
            prompt)?;

    Ok(())
}
