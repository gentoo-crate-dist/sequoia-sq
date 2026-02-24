use anyhow::Context;

use sequoia::openpgp;
use openpgp::Cert;

use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::common::NULL_POLICY;
use crate::common::password;

/// Revoke a Subkey of an existing primary key
///
/// ## Errors
///
/// Returns an error if parsing of the [`KeyHandle`] fails, if reading of the
/// [`Cert`] fails, if retrieval of [`NotationData`] fails or if the eventual
/// revocation fails.
pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::revoke::Command)
    -> Result<()>
{
    let (cert, cert_source) =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    let vc = Cert::with_policy(&cert, NULL_POLICY, sq.time())
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     null policy.",
                    cert.fingerprint())
        })?;

    let keys = sq.resolve_keys(&vc, &cert_source, &command.keys, true)?;
    let keys = keys.into_iter().map(|ka| ka.key().key_handle()).collect::<Vec<_>>();

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

    sq.sequoia.key_subkey_revoke()
        .add_notations(notations.into_iter())
        .revoke(
            revoker.as_ref(),
            &cert,
            &keys,
            command.reason.into(),
            &command.message,
            output,
            prompt)
}
