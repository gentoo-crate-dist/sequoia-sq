use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::common::password;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::expire::Command)
    -> Result<()>
{
    assert!(! command.keys.is_empty());

    let (cert, cert_handle)
        = sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy(), sq.time())?;

    let keys = sq.resolve_keys(&vc, &cert_handle, &command.keys, false)?;
    let keys = keys
        .into_iter()
        .map(|ka| ka.key().key_handle())
        .collect::<Vec<_>>();

    let mut output_;
    let output_path_;
    let output = if let Some(output_path) = command.output {
        // Don't import; save to a file.
        output_path_ = output_path.path().map(|p| p.clone());
        output_ = output_path.for_secrets().create_safe(&sq)?;
        Some((&mut output_ as &mut dyn std::io::Write,
              output_path_.as_ref().map(|p| p.as_path())))
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::Prompt::new(&sq, false);

    sequoia::key::expire::expire(
        &sq.sequoia,
        &cert,
        &keys,
        command.expiration.value(),
        output,
        false,
        prompt)
}
