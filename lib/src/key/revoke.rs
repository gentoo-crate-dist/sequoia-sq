use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::types::ReasonForRevocation;

use crate::Sequoia;
use crate::key::RevocationOutput;
use crate::key::get_secret_signer;
use crate::prompt;

/// Handle the revocation of a certificate
struct CertificateRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
}

impl CertificateRevocation {
    /// Create a new CertificateRevocation
    pub fn new<P>(
        sequoia: &Sequoia,
        cert: &Cert,
        revoker: Option<&Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: P,
    ) -> Result<Self>
    where
        P: prompt::Prompt
    {
        let (revoker, mut signer) = get_secret_signer(
            &sequoia,
            &cert,
            revoker,
            prompt,
        )?;

        let revocation_packet = {
            // Create a revocation for the certificate.
            let mut rev = CertRevocationBuilder::new()
                .set_reason_for_revocation(reason, message.as_bytes())?;
            rev = rev.set_signature_creation_time(sequoia.time())?;
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
            cert: cert.clone(),
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
pub fn revoke<P>(
    sequoia: &Sequoia,
    revoker: Option<&Cert>,
    cert: &Cert,
    reason: ReasonForRevocation,
    message: &str,
    signature_notations: &[(bool, NotationData)],
    output: Option<&mut dyn std::io::Write>,
    prompt: P)
    -> Result<()>
where
    P: prompt::Prompt
{
    let revocation = CertificateRevocation::new(
        &sequoia,
        cert,
        revoker,
        reason,
        message,
        signature_notations,
        prompt)?;
    revocation.write(sequoia, output, false)?;

    Ok(())
}
