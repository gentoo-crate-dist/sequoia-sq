use sequoia::openpgp;
use openpgp::Result;

use sequoia::types::TrustThreshold;

use crate::{
    Sq,
    cli,
    common::password,
    load_keys,
    output::decrypt::Stream,
    output::decrypt::DecryptContext,
};

pub fn dispatch(sq: Sq, command: cli::decrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let mut input = command.input.open("an encrypted message")?;
    let output_path = command.output.for_secrets();
    let mut output = output_path.create_safe(&sq)?;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    // Fancy default for --signatures.  If you change this,
    // also change the description in the CLI definition.
    let signatures = command.signatures.unwrap_or_else(|| {
        if signers.is_empty() {
            // No certs are given for verification, use 0 as
            // threshold so we handle only-encrypted messages
            // gracefully.
            0
        } else {
            // At least one cert given, expect at least one
            // valid signature.
            1
        }
    });
    let secret_keys =
        load_keys(command.secret_key_file.iter())?;
    let session_keys = command.session_key;
    let prompt = password::Prompt::new(&sq, true);
    let stream = Stream::new(
        &sq, DecryptContext::Decrypt, command.dump_session_key);
    let mut decryptor = sq.sequoia.decrypt()
        .stream(stream)
        .signatures(signatures)
        .add_secret_keys(secret_keys)
        .add_session_keys(session_keys);
    if ! signers.is_empty() {
        decryptor = decryptor.add_designated_signers(signers);
    }

    let result = decryptor.decrypt(&mut input, &mut output, prompt);

    if result.is_err() {
        if let Some(path) = output_path.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Decryption failed, failed to remove \
                            output saved to {}: {}",
                           path.display(), err);
            }
        }
    }

    result?;

    Ok(())
}
