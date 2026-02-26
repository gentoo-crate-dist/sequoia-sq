use std::collections::BTreeMap;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::cert::ValidCert;
use openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use openpgp::packet::key::PublicParts;

use crate::Result;

/// Returns the specified key amalgamations.
///
/// An error is returned if a key cannot be found.  An error is
/// returned if `keys` is empty.
pub fn get_subkeys<'a>(vc: &ValidCert<'a>, keys: &[KeyHandle])
    -> Result<Vec<ValidErasedKeyAmalgamation<'a, PublicParts>>>
{
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

    Ok(kas)
}
