use std::collections::BTreeSet;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

use crate::Sequoia;
use crate::ca_creation_time;
use crate::cert_store::Store;
use crate::types::Safe;

pub fn list(
        sequoia: &Sequoia,
        vcert: &ValidCert,
        userids: Vec<UserID>,
        filter_pending: bool,
        o: &mut dyn std::io::Write)
    -> Result<()>
{
    let store = sequoia.cert_store_or_else()?;

    // resolve returns ResolvedUserIDs, which contain UserIDs, but we
    // need ValidUserIDAmalgamations.
    let all = userids.is_empty();
    let mut designated_userids = BTreeSet::from_iter(
        userids.into_iter());
    let mut pending = 0;
    for uid in vcert.userids() {
        if ! all && ! designated_userids.remove(uid.userid()) {
            continue;
        }

        wwriteln!(stream=o,
                  initial_indent = " - ", "{}",
                  Safe(uid.userid()));

        let approved =
            uid.approved_certifications().collect::<BTreeSet<_>>();

        let mut any = false;
        for c in uid.certifications() {
            // Ignore non-exportable certifications.
            if c.exportable().is_err() {
                sequoia.info(format_args!(
                    "Ignoring non-exportable certification from {} on {}.",
                    c.get_issuers()
                        .into_iter()
                        .next()
                        .map(|kh| kh.to_string())
                        .unwrap_or_else(|| "unknown certificate".to_string()),
                        Safe(uid.userid())));
                continue;
            }

            let approved = approved.contains(c);
            if ! approved {
                pending += 1;
            }

            if approved == filter_pending {
                // It's approved and we want pending, or it's pending
                // and we want approved.
                continue;
            }

            // Verify certifications by looking up the issuing cert.
            let mut issuer = None;
            let mut err = None;
            for i in c.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match c.verify_signature(&i.primary_key()) {
                    Ok(_) => issuer = Some(i),
                    Err(e) => err = Some(e),
                }
            }

            // If the certificate should not be exported, we don't
            // approve the certification.
            if let Some(Ok(i)) = issuer.as_ref().map(|i| i.to_cert()) {
                if ! i.exportable() {
                    sequoia.info(format_args!(
                        "Ignoring certification from non-exportable \
                         certificate {} on {}.",
                        i.fingerprint(), Safe(uid.userid())));
                    continue;
                }
                if i.primary_key().key().creation_time() == ca_creation_time() {
                    sequoia.info(format_args!(
                        "Ignoring certification from local shadow CA \
                         {} on {}.",
                        i.fingerprint(), Safe(uid.userid())));
                    continue;
                }
            }

            wwriteln!(stream=o,
                      initial_indent = "   - ", "{}{}: {}",
                      issuer.as_ref()
                      .map(|c| format!("{} ", c.fingerprint()))
                      .unwrap_or_else(|| "".into()),
                      issuer.as_ref()
                      .and_then(|i| Some(sequoia.best_userid(i.to_cert().ok()?, true)
                                         .display().to_string()))
                      .or(c.get_issuers().into_iter().next()
                          .map(|h| h.to_string()))
                      .unwrap_or_else(|| "no issuer information".into()),
                      if issuer.is_none() {
                          if let Some(e) = err {
                              e.to_string()
                          } else {
                              "issuer cert not found".into()
                          }
                      } else if approved {
                          "approved".into()
                      } else {
                          "unapproved".into()
                      });
            any = true;
        }

        if ! any {
            wwriteln!(stream=o,
                      initial_indent = "   - ", "no {} certifications",
                      if filter_pending {
                          "unapproved"
                      } else {
                          "approved"
                      });
        }
    }
    assert!(designated_userids.is_empty());

    if ! filter_pending && pending > 0 {
        wwriteln!(stream=o,
                  "{} certifications are pending approval.  Using `--pending` \
                   to see them.",
                  pending);
    }

    Ok(())
}
