use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::{Key, Signature, key};
use openpgp::types::ReasonForRevocation;

use crate::NULL_POLICY;
use crate::Result;
use crate::Sequoia;
use crate::key::RevocationOutput;
use crate::key::get_secret_signer;
use crate::prompt;

/// Handle the revocation of a subkey
struct SubkeyRevocation {
    cert: Cert,
    revoker: Cert,
    revocations: Vec<(Key<key::PublicParts, key::SubordinateRole>, Signature)>,
}

impl SubkeyRevocation {
    /// Create a new SubkeyRevocation
    pub fn new<P>(
        sequoia: &Sequoia,
        kas: &[ValidErasedKeyAmalgamation<key::PublicParts>],
        cert: &Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
        prompt: P)
        -> Result<Self>
    where
        P: prompt::Prompt
    {
        let (revoker, mut signer)
            = get_secret_signer(sequoia, &cert, revoker.as_ref(), prompt)?;

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
            rev = rev.set_signature_creation_time(sequoia.time())?;
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

impl Sequoia {
    /// Returns a builder providing control over how to revoke
    /// subkeys.
    ///
    /// See [`Builder`] for details.
    pub fn key_subkey_revoke(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                notations: Vec::new(),
            },
        }
    }
}

/// Subkey revocation parameters.
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

/// Revokes subkeys.
///
/// A builder providing control over how to revoke subkeys.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
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

    /// Revoke a subkey.
    ///
    /// ## Errors
    ///
    /// Returns an error if parsing of the [`KeyHandle`] fails, if reading of the
    /// [`Cert`] fails, if retrieval of [`NotationData`] fails or if the eventual
    /// revocation fails.
    pub fn revoke<P>(&self,
                     revoker: Option<&Cert>,
                     cert: &Cert,
                     keys: &[KeyHandle],
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

        let vc = Cert::with_policy(&cert, NULL_POLICY, sequoia.time())
            .with_context(|| {
                format!("The certificate {} is not valid under the \
                         null policy.",
                        cert.fingerprint())
            })?;

        let mut fprs = BTreeMap::from_iter(
            keys
                .iter()
                .filter_map(|kh| {
                    match kh {
                        KeyHandle::Fingerprint(fpr) => Some((fpr.clone(), false)),
                        KeyHandle::KeyID(_keyid) => None,
                    }
                }));
        let mut keyids = BTreeMap::from_iter(
            keys
                .iter()
                .filter_map(|kh| {
                    match kh {
                        KeyHandle::Fingerprint(_fpr) => None,
                        KeyHandle::KeyID(keyid) => Some((keyid.clone(), false)),
                    }
                }));

        let mut kas = Vec::new();
        for ka in vc.keys() {
            // Don't short-circuit the or.
            let by_fpr = if let Some(saw) = fprs.get_mut(&ka.key().fingerprint()) {
                *saw = true;
                true
            } else {
                false
            };

            let by_keyid = if let Some(saw) = keyids.get_mut(&ka.key().keyid()) {
                *saw = true;
                true
            } else {
                false
            };

            if by_fpr || by_keyid {
                kas.push(ka);
            }
        }

        // Return an error if there are any unknown keys.
        let missed = fprs
            .into_iter()
            .filter_map(|(fpr, saw)| {
                if saw {
                    None
                } else {
                    Some(KeyHandle::from(fpr))
                }
            })
            .chain(keyids
                   .into_iter()
                   .filter_map(|(keyid, saw)| {
                       if saw {
                           None
                       } else {
                           Some(KeyHandle::from(keyid))
                       }
                   }))
            .collect::<Vec<_>>();

        if let Some(first) = missed.get(0) {
            if missed.len() == 1 {
                return Err(anyhow::anyhow!(
                    "{} is not part of the certificate",
                    first));
            } else {
                return Err(anyhow::anyhow!(
                    "{} are not part of the certificate",
                    missed.iter()
                        .map(|k| k.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")));
            }
        }

        if kas.is_empty() {
            return Err(anyhow::anyhow!("Nothing to revoke"));
        }

        let revocation = SubkeyRevocation::new(
            &sequoia,
            &kas[..],
            &cert,
            revoker.map(Clone::clone),
            reason.into(),
            &message,
            &notations,
            prompt)?;
        revocation.write(&sequoia, output, false)?;

        Ok(())
    }
}
