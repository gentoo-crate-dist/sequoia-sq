//! Digital signatures over data.

use anyhow::Context as _;

use sequoia::openpgp;
use openpgp::armor;

use sequoia::types::FileOrStdin;
use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::password;

mod merge_signatures;
use merge_signatures::merge_signatures;

pub fn dispatch(sq: Sq, command: cli::sign::Command) -> Result<()> {
    tracer!(TRACE, "sign::dispatch");

    let mut input = command.input.open("the data to sign")?;
    let output = &command.output;
    let detached = &command.detached;
    let binary = command.binary;
    let append = command.append;
    let notarize = command.notarize;
    if notarize {
        return Err(anyhow::anyhow!("Notarizing messages is not supported."));
    }

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    let notations = command.signature_notations.parse()?;

    if let Some(merge) = command.merge {
        let output = output.create_pgp_safe(
            &sq,
            binary,
            armor::Kind::Message,
            &[],
        )?;
        let data: FileOrStdin = merge.into();
        let mut input2 = data.open("OpenPGP signatures")?;
        return merge_signatures(&mut input, &mut input2, output);
    }

    if signers.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
    }

    let output = detached.as_ref().unwrap_or(output);
    let output = output.create_safe_overwrite(&sq, append)?;

    let prompt = password::PromptFactory::new(&sq, true);

    let stream = crate::output::sign::Stream::new(&sq);

    let signer = sq.sequoia.sign()
        .add_signers(signers.into_iter())
        .add_notations(notations.into_iter());

    let result = if command.cleartext {
        signer.stream(stream).clear().sign(input, output, prompt)
    } else if append {
        if let Some(detached) = detached {
            let detached_signatures = if let Some(path) = detached.path() {
                Box::new(
                    std::fs::File::open(path)
                        .with_context(|| {
                            format!("Failed to open {}", path.display())
                        })?)
                    as Box<dyn std::io::Read + Send + Sync>
            } else {
                Box::new(std::io::stdin())
            };

            signer
                .detached()
                .stream(stream)
                .hash_mode(command.mode)
                .ascii_armor(! binary)
                .append(input, detached_signatures, output, prompt)
        } else {
            signer
                .inline()
                .stream(stream)
                .hash_mode(command.mode)
                .ascii_armor(! binary)
                .append(input, output, prompt)
        }
    } else {
        if detached.is_some() {
            signer
                .stream(stream)
                .detached()
                .hash_mode(command.mode)
                .ascii_armor(! binary)
                .sign(input, output, prompt)
        } else {
            signer
                .stream(stream)
                .inline()
                .hash_mode(command.mode)
                .ascii_armor(! binary)
                .sign(input, output, prompt)
        }
    };

    let _outcome = result?;
    Ok(())
}
