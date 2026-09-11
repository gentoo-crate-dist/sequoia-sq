use anyhow::Context;

use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::cli::key::userid::RevokeCommand;
use crate::cli;
use crate::common::password;

pub fn dispatch(
    sq: Sq,
    command: cli::key::userid::Command,
) -> Result<()> {
    match command {
        cli::key::userid::Command::Add(c) => userid_add(sq, c)?,
        cli::key::userid::Command::Revoke(c) => userid_revoke(sq, c)?,
    }

    Ok(())
}

fn userid_add(
    sq: Sq,
    command: cli::key::userid::AddCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let mut output_;
    let output = if let Some(output_path) = command.output {
        // Don't import; save to a file.
        output_ = output_path.for_secrets().create_safe(&sq)?;
        Some(&mut output_ as &mut dyn std::io::Write)
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::PromptFactory::new(&sq, false);

    sq.sequoia.key_userid_add()
        .prompt(prompt)
        .names(&command.names)
        .emails(&command.emails)
        .userids(command.userid.into_iter())
        .allow_non_canonical_userids(command.allow_non_canonical_userids)
        .add(
            &cert,
            output)
}

/// Revoke a UserID of an existing primary key
///
/// ## Errors
///
/// Returns an error if reading of the [`Cert`] fails, if retrieval of
/// [`NotationData`] fails or if the eventual revocation fails.
pub fn userid_revoke(
    sq: Sq,
    command: RevokeCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    // To revoke a user ID, we require the certificate be valid under
    // the current policy.  Users can still revoke user IDs whose
    // binding signature relies on weak cryptography using
    // `--add-user`.
    let vcert = cert.with_policy(sq.policy(), sq.time())
        .with_context(|| {
            format!("The certificate is not valid under the current \
                     policy.  Consider revoking the whole certificate \
                     using `sq key revoke`, or fixing it using \
                     `sq cert lint` after verifying the certificate's \
                     integrity.")
        })?;
    let userids = command.userids.resolve(&vcert)?;
    assert_eq!(userids.len(), 1, "exactly one user ID enforced by clap");
    let userid = userids.into_iter().next().unwrap();

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, TrustThreshold::Full)?.0)
    };

    let notations = command.signature_notations.parse()?;

    let mut output_;
    let output = if let Some(output_path) = command.output {
        // Don't import; save to a file.
        output_ = output_path.for_secrets().create_safe(&sq)?;
        Some(&mut output_ as &mut dyn std::io::Write)
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::PromptFactory::new(&sq, false);

    sq.sequoia.key_userid_revoke()
        .prompt(prompt)
        .add_notations(notations.into_iter())
        .revoke(
            revoker.as_ref(),
            &cert,
            userid.userid(),
            command.reason.into(),
            &command.message,
            output)?;

    Ok(())
}
