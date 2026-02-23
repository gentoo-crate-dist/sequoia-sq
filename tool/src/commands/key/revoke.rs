use sequoia::openpgp;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use sequoia::key::RevocationOutput;
use sequoia::key::get_secret_signer;
use sequoia::prompt;
use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::cli::key::revoke::Command;
use crate::common::password;

/// Handle the revocation of a certificate
struct CertificateRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
}

impl CertificateRevocation {
    /// Create a new CertificateRevocation
    pub fn new<P>(
        sq: &Sq,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: P,
    ) -> Result<Self>
    where
        P: prompt::Prompt
    {
        let (revoker, mut signer) = get_secret_signer(
            &sq.sequoia,
            &cert,
            revoker.as_ref(),
            prompt,
        )?;

        let revocation_packet = {
            // Create a revocation for the certificate.
            let mut rev = CertRevocationBuilder::new()
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
            let rev = rev.build(&mut signer, &cert, None)?;
            Packet::Signature(rev)
        };

        Ok(CertificateRevocation {
            cert,
            revoker,
            revocation_packet,
        })
    }
}

impl RevocationOutput for CertificateRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        format!("This is a revocation certificate for the cert {}.",
                self.cert.fingerprint())
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

/// Revoke a certificate
pub fn certificate_revoke(
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

    let revocation = CertificateRevocation::new(
        &sq,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
        prompt,
    )?;
    revocation.write(&sq.sequoia, output, false)?;

    Ok(())
}
