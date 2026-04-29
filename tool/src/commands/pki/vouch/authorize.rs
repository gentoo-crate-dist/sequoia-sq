use sequoia::openpgp;
use openpgp::Result;

use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::cli::pki::vouch::authorize;
use crate::commands::FileOrStdout;
use crate::common::password;
use crate::output::pki::certify::Stream;

pub fn authorize(sq: Sq, mut c: authorize::Command)
    -> Result<()>
{
    let certifier =
        sq.resolve_cert(&c.certifier, TrustThreshold::Full)?.0;

    let (cert, source) = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;
    if source.is_file() {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let mut message_ = None;
    let path_;
    let output = if let Some(output) = c.output {
        // And export it.
        path_ = output.path().map(Clone::clone);
        let message = output.create_pgp_safe(
            &sq,
            false, // Binary.
            openpgp::armor::Kind::PublicKey,
            &[],
        )?;

        message_ = Some(message);
        Some((path_.as_deref(),
              message_.as_mut().unwrap() as &mut dyn std::io::Write))
    } else {
        None
    };

    let vc = cert.with_policy(sq.policy(), Some(sq.time()))?;
    let userids = c.userids.resolve(&vc)?
        .into_iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();
    let user_supplied_userids = ! c.userids.all().unwrap_or(false);

    let notations = c.signature_notations.parse()?;
    let expiration = sq.config()
        .resolve_pki_vouch_expiration(&c.expiration, c.expiration_source);

    let prompt = password::Prompt::new(&sq, true);

    let mut stderr = std::io::stderr();
    let stream = Stream::new(
        &sq,
        &cert,
        &userids,
        user_supplied_userids,
        output.as_ref().and_then(|(p, _)| p.clone()),
        &mut stderr);

    sq.sequoia.pki_certify()
        // Always recreate.
        .recreate(true)
        .ignore_certification_errors(true) // Filtered by stream.
        .trust_amount(c.amount.amount())
        .trust_depth(c.depth)
        .expiration(expiration)
        .exportable(! c.local)
        .revocable(! c.non_revocable)
        .add_domain_constraints(c.domain.iter())
        .add_regular_expression_constraints(c.regex.iter())
        .add_notations(notations.into_iter())
        .certify(
            &certifier,
            &cert,
            &userids,
            stream,
            prompt,
            output.map(|(_, f)| f),
        )?;

    if let Some(message) = message_ {
        message.finalize()?;
    }

    Ok(())
}
