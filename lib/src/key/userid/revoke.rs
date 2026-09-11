use std::sync::Arc;

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
    pub fn new<'sequoia, 'prompt>(
        sequoia: &'sequoia Sequoia,
        revoker: Option<Cert>,
        cert: Cert,
        userid: &UserID,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>,
    ) -> Result<Self>
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

/// User ID revocation parameters.
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

/// Owned parameters.
struct ParamsOnce<'prompt> {
    prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>,
}

/// Revokes user IDs.
///
/// A builder providing control over how to revoke user IDs.
pub struct Builder<'sequoia, 'prompt> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'prompt>,
}

impl<'sequoia, 'prompt> Builder<'sequoia, 'prompt>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Self
    {
        Builder {
            params: Params {
                sequoia,
                notations: Vec::new(),
            },
            params_once: ParamsOnce {
                prompt: None,
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    prompt_builder_impl!();

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

    /// Revoke a user ID.
    ///
    /// This function does not check that the user ID is
    /// self-signed.
    ///
    /// ## Errors
    ///
    /// Returns an error if reading of the [`Cert`] fails, if retrieval of
    /// [`NotationData`] fails or if the eventual revocation fails.
    pub fn revoke(
        self,
        revoker: Option<&Cert>,
        cert: &Cert,
        userid: &UserID,
        reason: ReasonForRevocation,
        message: &str,
        output: Option<&mut dyn std::io::Write>)
        -> Result<()>
    {
        let Builder {
            params: Params {
                sequoia,
                ref notations,
            },
            params_once: ParamsOnce {
                prompt,
            }
        } = self;

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

        revocation.write(sequoia, output, false)?;

        Ok(())
    }
}
