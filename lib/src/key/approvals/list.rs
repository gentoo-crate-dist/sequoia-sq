use std::collections::BTreeSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

use crate::Sequoia;
use crate::ca_creation_time;
use crate::cert_store::Store;
use crate::types::Safe;

/// Parameters for the list of approvals.
///
/// These parameters are used by [`list`](Builder::list).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    userids: Vec<UserID>,
    pending: bool,
}

impl<'sequoia> Params<'sequoia> {
    /// Return the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.sequoia
    }

    /// Return the list of user IDs
    pub fn userids(&self) -> Vec<UserID> {
        self.userids.clone()
    }

    /// Return the type of listing created.
    ///
    /// If true, the list will contain pending approvals, otherwise
    /// approved certifications will be returned.
    pub fn pending(&self) -> bool {
        self.pending
    }
}

#[derive(Clone)]
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia> {
    pub(crate) fn new(sequoia: &Sequoia) -> Builder<'_> {
        Builder {
            params: Params {
                sequoia,
                userids: Vec::new(),
                pending: false,
            }
        }
    }

    /// Return the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the user IDs.
    ///
    /// List approvals only for these user IDs of the certificate.
    pub fn userids(mut self, userids: Vec<UserID>) -> Self {
        self.params.userids = userids;
        self
    }

    /// Sets pending.
    ///
    /// If true the produced list contains pending approvals, otherwise
    /// it would list existing ones.
    pub fn pending(mut self, pending: bool) -> Self {
        self.params.pending = pending;
        self
    }

    /// Lists approvals of `cert`.
    pub fn list(&self,
        cert: Cert,
        output: &mut dyn std::io::Write)
        -> Result<()> {

        let sequoia = self.params.sequoia;
        let vcert = cert.with_policy(sequoia.policy(), sequoia.time())?;

        list_internal(
            sequoia,
            &vcert,
            &self.params.userids,
            self.params.pending,
            output
        )
    }
}

// slightly modified version of the previous migration step.
pub fn list_internal(
        sequoia: &Sequoia,
        vcert: &ValidCert,
        userids: &Vec<UserID>,
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
