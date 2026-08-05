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

/// Certificate revocation parameters.
///
/// These parameters are used by [`revoke`](Builder::revoke).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    notations: Vec<(bool, NotationData)>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the notations that will be added to the revocation
    /// certificate.
    pub fn notations(&self) -> impl Iterator<Item=&(bool, NotationData)> {
        self.notations.iter()
    }
}

/// Revokes certificates.
///
/// A builder providing control over how to revoke certificates.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Builder<'sequoia>
    {
        Builder {
            params: Params {
                sequoia,
                notations: Vec::new(),
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Adds a notation to the new revocation signatures.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notation(mut self, critical: bool, notation: NotationData)
                        -> Self
    {
        self.params.notations.push((critical, notation));
        self
    }

    /// Adds notations to the new revocation signatures.
    ///
    /// The first value of the tuple is the notation's criticality.
    ///
    /// See [RFC 9580 for details].
    ///
    ///   [RFC 9580 for details]: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
    pub fn add_notations(mut self,
                         notations: impl Iterator<Item=(bool, NotationData)>)
                         -> Self
    {
        self.params.notations.extend(notations);
        self
    }

    /// Revokes a certificate.
    pub fn revoke<P>(&self,
                     revoker: Option<&Cert>,
                     cert: &Cert,
                     reason: ReasonForRevocation,
                     message: &str,
                     output: Option<&mut dyn std::io::Write>,
                     prompt: P)
                     -> Result<()>
    where
        P: prompt::Prompt
    {
        let &Builder {
            params: Params {
                sequoia,
                ref notations,
            },
        } = self;

        let revocation = CertificateRevocation::new(
            &sequoia,
            cert,
            revoker,
            reason,
            message,
            notations,
            prompt)?;
        revocation.write(sequoia, output, false)?;

        Ok(())
    }
}
