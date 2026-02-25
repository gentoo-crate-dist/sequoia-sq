use sequoia::openpgp;
use openpgp::Result;

use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::cli::key::revoke::Command;
use crate::common::password;

/// Revoke a certificate
pub fn dispatch(
    sq: Sq,
    command: Command,
) -> Result<()> {
    let cert =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

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

    let prompt = password::Prompt::new(&sq, false);

    sq.sequoia.key_revoke()
        .add_notations(notations.into_iter())
        .revoke(
            revoker.as_ref(),
            &cert,
            command.reason.into(),
            &command.message,
            output,
            prompt)?;

    Ok(())
}
