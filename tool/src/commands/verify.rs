use anyhow::Context;

use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::Result;
use crate::cli;
use crate::output::verify::Stream;
use crate::output::verify::VerifyContext;

pub fn dispatch(sq: Sq, command: cli::verify::Command)
    -> Result<()>
{
    tracer!(TRACE, "verify::dispatch");

    let input = command.input.open("a signed message")?;
    let mut output = command.output.create_safe(&sq)?;
    let signatures = command.signatures;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    let mut verifier = sq.sequoia.verify()
        .signatures(signatures);
    if ! signers.is_empty() {
        verifier = verifier.add_designated_signers(signers);
    }

    let result = if let Some(signature_file) = command.detached.as_ref() {
        let stream = Stream::new(
            &sq, VerifyContext::Verify,
            // Detached signature argument.
            None, Some(signature_file.clone()));

        let signature_fp = std::fs::File::open(signature_file)
            .with_context(|| {
                format!("Opening {}", signature_file.display())
            })?;

        verifier.detached_signature(
            input, signature_fp,  &mut output, stream)
    } else {
        let stream = Stream::new(
            &sq, VerifyContext::Verify,
            // Detached signature argument.
            None, None);

        verifier.inline_signature(
            input,  &mut output, stream)
    }.map_err(|err| anyhow::Error::from(err));

    if result.is_err() {
        if let Some(path) = command.output.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Verification failed, failed to remove \
                            unverified output saved to {}: {}",
                           path.display(), err);
            }
        }
    }
    result
}
