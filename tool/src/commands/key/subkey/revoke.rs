use std::collections::BTreeSet;

use anyhow::Context;

use sequoia::openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::{Key, Signature, key};
use openpgp::types::ReasonForRevocation;

use sequoia::key::RevocationOutput;
use sequoia::key::get_secret_signer;
use sequoia::prompt;
use sequoia::types::TrustThreshold;

use crate::Result;
use crate::Sq;
use crate::common::NULL_POLICY;
use crate::common::password;

/// Handle the revocation of a subkey
struct SubkeyRevocation {
    cert: Cert,
    revoker: Cert,
    revocations: Vec<(Key<key::PublicParts, key::SubordinateRole>, Signature)>,
}

impl SubkeyRevocation {
    /// Create a new SubkeyRevocation
    pub fn new<P>(
        sq: &Sq,
        kas: &[ValidErasedKeyAmalgamation<key::PublicParts>],
        cert: &Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: P
    ) -> Result<Self>
    where
        P: prompt::Prompt
    {
        let (revoker, mut signer)
            = get_secret_signer(&sq.sequoia, &cert, revoker.as_ref(), prompt)?;

        let mut revocations = Vec::new();
        let mut revoked = BTreeSet::new();
        for ka in kas {
            // Did we already revoke it?
            if revoked.contains(&ka.key().fingerprint()) {
                continue;
            }
            revoked.insert(ka.key().fingerprint());

            let mut rev = SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(reason, message.as_bytes())?;
            rev = rev.set_signature_creation_time(sq.time())?;
            for (critical, notation) in notations {
                rev = rev.add_notation(
                    notation.name(),
                    notation.value(),
                    Some(notation.flags().clone()),
                    *critical,
                )?;
            }
            let key = ka.key().clone().role_into_subordinate();
            let rev = rev.build(&mut signer, &cert, &key, None)?;
            revocations.push((key, rev));
        }

        Ok(SubkeyRevocation {
            cert: cert.clone(),
            revoker,
            revocations,
        })
    }
}

impl RevocationOutput for SubkeyRevocation {
    fn cert(&self) -> Result<Cert> {
         Cert::from_packets(
            std::iter::once(
                Packet::from(self.cert.primary_key().key().clone()))
                .chain(self.revocations.iter().flat_map(
                    |(k, s)| [k.clone().into(), s.clone().into()].into_iter()))
        )
    }

    fn comment(&self) -> String {
        if self.revocations.len() == 1 {
            format!("This is a revocation certificate for \
                     the subkey {} of cert {}.",
                    self.revocations[0].0.fingerprint(),
                    self.cert.fingerprint())
        } else {
            let fingerprints: Vec<_> = self.revocations.iter()
                .map(|k| k.0.fingerprint().to_string()).collect();
            format!("This is a revocation certificate for \
                     the subkeys {} of cert {}.",
                    fingerprints.join(", "),
                    self.cert.fingerprint())
        }
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

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

    let revocation = SubkeyRevocation::new(
        &sq,
        &keys[..],
        &cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
        prompt,
    )?;
    revocation.write(&sq.sequoia, output, false)?;

    Ok(())
}
