use sequoia_openpgp as openpgp;
use openpgp::cert::UserIDRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::UserID;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use crate::Sequoia;
use crate::key::RevocationOutput;
use crate::key::get_secret_signer;
use crate::prompt;
use crate::types::Safe;

/// Handle the revocation of a User ID
struct UserIDRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
    userid: UserID,
}

impl UserIDRevocation {
    /// Create a new UserIDRevocation
    pub fn new<P>(
        sequoia: &Sequoia,
        revoker: Option<Cert>,
        cert: Cert,
        userid: &UserID,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: P
    ) -> Result<Self>
    where
        P: prompt::Prompt,
    {
        let (revoker, mut signer)
            = get_secret_signer(sequoia, &cert, revoker.as_ref(), prompt)?;

        let revocation_packet = {
            // Create a revocation for a User ID.
            let mut rev = UserIDRevocationBuilder::new()
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
            let rev = rev.build(
                &mut signer,
                &cert,
                userid,
                None,
            )?;
            Packet::Signature(rev)
        };

        Ok(UserIDRevocation {
            cert,
            revoker,
            revocation_packet,
            userid: userid.clone(),
        })
    }
}

impl RevocationOutput for UserIDRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.userid.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        format!("This is a revocation certificate for \
                 the User ID {} of cert {}.",
                Safe(&self.userid),
                self.cert.fingerprint())
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

/// Revoke UserIDs.
///
/// This function does not check that the user IDs are self-signed.
///
/// ## Errors
///
/// Returns an error if reading of the [`Cert`] fails, if retrieval of
/// [`NotationData`] fails or if the eventual revocation fails.
pub fn revoke<P>(
    sequoia: &Sequoia,
    revoker: Option<&Cert>,
    cert: &Cert,
    userid: &UserID,
    reason: ReasonForRevocation,
    message: &str,
    notations: &[(bool, NotationData)],
    output: Option<&mut dyn std::io::Write>,
    prompt: P)
    -> Result<()>
where
    P: prompt::Prompt
{
    let revocation = UserIDRevocation::new(
        &sequoia,
        revoker.map(|c| c.clone()),
        cert.clone(),
        userid,
        reason,
        message,
        &notations,
        prompt,
    )?;

    revocation.write(&sequoia, output, false)?;

    Ok(())
}
