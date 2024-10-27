use std::collections::HashSet;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use crate::Result;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator::AddUserIDArg;
use crate::cli::types::userid_designator::UserIDDesignator;

impl<Arguments, Options> UserIDDesignators<Arguments, Options>
where
    Arguments: typenum::Unsigned,
{
    /// Resolve the user ID designators.
    ///
    /// If `--add-userid` is enabled, then this will return an error
    /// if a user ID that is not self-signed is designated.
    pub fn resolve(&self, vc: &ValidCert) -> Result<Vec<UserID>> {
        let arguments = Arguments::to_usize();
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;

        // Find the matching User ID.
        let mut userids = Vec::new();

        // Don't stop at the first error.
        let mut missing = false;

        if let Some(true) = self.all() {
            let all_userids = vc.userids()
                .filter_map(|ua| {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        None
                    } else {
                        Some(ua.userid().clone())
                    }
                })
                .collect::<Vec<_>>();

            if all_userids.is_empty() {
                return Err(anyhow::anyhow!(
                    "{} has no valid self-signed user IDs",
                    vc.fingerprint()));
            }

            userids.extend(all_userids);
        }

        for designator in self.iter() {
            let userid = match designator {
                UserIDDesignator::UserID(userid) => {
                    UserID::from(&userid[..])
                }
                UserIDDesignator::Email(email) => {
                    UserID::from(format!("<{}>", email))
                }
            };

            // If --add-userid is specified, we use the user ID as
            // is.  Otherwise, we make sure there is a matching
            // self-signed user ID.
            if ! add_userid_arg || self.add_userid().unwrap_or(false){
                userids.push(userid.clone());
            } else if let Some(_) = vc.userids()
                .find(|ua| {
                    ua.userid() == &userid
                })
            {
                userids.push(userid.clone());
            } else {
                wprintln!("{:?} is not a self-signed user ID.",
                          String::from_utf8_lossy(userid.value()));
                missing = true;
            }
        }

        if missing {
            wprintln!("{}'s self-signed user IDs:", vc.fingerprint());
            let mut have_valid = false;
            for ua in vc.userids() {
                if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                    have_valid = true;
                    wprintln!("  - {:?}", u);
                }
            }
            if ! have_valid {
                wprintln!("  - Certificate has no valid user IDs.");
            }
            wprintln!("Pass `--add-userid` to certify a user ID even if it \
                       isn't self signed.");
            return Err(anyhow::anyhow!("Not a self-signed user ID"));
        };

        // Dedup while preserving order.
        let mut seen = HashSet::new();
        userids.retain(|userid| seen.insert(userid.clone()));

        Ok(userids)
    }
}
