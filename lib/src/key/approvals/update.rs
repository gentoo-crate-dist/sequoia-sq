use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::ValidCert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::UserID;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;

use sequoia_wot as wot;
use sequoia_cert_store::LazyCert;
use sequoia_cert_store::StoreUpdate;
use sequoia_cert_store::store::MergePublicCollectStats;

use crate::Sequoia;
use crate::ca_creation_time;
use crate::cert_store::Store;
use crate::prompt::Prompt;
use crate::types::Safe;

// output must be created with .for_secrets().create_safe()
pub fn update<P>(
        sequoia: &Sequoia,
        vcert: &ValidCert,
        userids: Vec<UserID>,
        cmd_add_by: Vec<KeyHandle>,
        cmd_add_authenticated: bool,
        cmd_remove_all: bool,
        cmd_remove_by: Vec<KeyHandle>,
        cmd_add_all: bool,
        prompt: P,
        output: Option<(Box<dyn std::io::Write + Send + Sync>, Option<std::path::PathBuf>)>)
    -> Result<()>
where
    P: Prompt
{
    let key = vcert.cert().clone();

    let store = sequoia.cert_store_or_else()?;

    // Lookup any explicitly goodlisted certifiers.  We need these to
    // verify the certifications.
    let mut add_by = Vec::new();
    for i in &cmd_add_by {
        add_by.append(&mut store.lookup_by_cert(i)?);
    }

    // If we want to authenticate, prepare the authentication network.
    let network_threshold = cmd_add_authenticated.then_some(
        (wot::NetworkBuilder::rooted(store, &*sequoia.trust_roots()).build(),
         wot::FULLY_TRUSTED));

    // Get a signer.
    let mut pk_signer = sequoia.get_primary_key(&key, None, prompt)?;

    // Now, create new approval signatures.
    let mut approval_signatures = Vec::new();

    // resolve returns ResolvedUserIDs, which contain UserIDs, but we
    // need ValidUserIDAmalgamations.
    let all = userids.is_empty();
    let mut designated_userids = BTreeSet::from_iter(
        userids.into_iter());
    let mut removed = 0;
    let mut added = 0;
    for uid in vcert.userids() {
        if ! all && ! designated_userids.remove(uid.userid()) {
            continue;
        }

        // Skip revoked user IDs.
        match uid.revocation_status() {
            RevocationStatus::Revoked(_) => continue,
            _ => (),
        }

       weprintln!(initial_indent = " - ", "{}",
                   Safe(uid.userid()));

        let previously_approved =
            uid.approved_certifications().collect::<BTreeSet<_>>();

        // Start from scratch or from the current set?
        let mut next_approved = if cmd_remove_all {
            Default::default()
        } else {
            previously_approved.clone()
        };

        // Selectively remove approvals.
        next_approved.retain(|s| ! s.get_issuers().iter().any(
            // Quadratic, but how bad can it be...?
            |i| cmd_remove_by.iter().any(|j| i.aliases(j))));

        // Selectively add approvals.
        let next_approved_cloned = next_approved.clone();
        for sig in uid.certifications()
            // Don't consider those that we already approved.
            .filter(|s| ! next_approved_cloned.contains(s))
        {
            // Ignore non-exportable certifications.
            if sig.exportable().is_err() {
                sequoia.info(format_args!(
                    "Ignoring non-exportable certification from {} on {}.",
                    sig.get_issuers()
                        .into_iter()
                        .next()
                        .map(|kh| kh.to_string())
                        .unwrap_or_else(|| "unknown certificate".to_string()),
                    Safe(uid.userid())));
                continue;
            }

            // Try and get the issuer's certificate.
            let mut issuer = None;
            let mut err = None;
            for i in sig.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match sig.verify_signature(&i.primary_key()) {
                    Ok(_) => {
                        issuer = Some(i)
                    }
                    Err(e) => err = Some((i.fingerprint(), e)),
                }
            }

            if issuer.is_none() {
                if let Some((fpr, err)) = err {
                    // We have the alleged signer, but we couldn't
                    // verify the certification.  It's bad; silently
                    // ignore it.
                    sequoia.info(format_args!(
                        "Ignoring invalid certification from {}: {}",
                        fpr, err));
                    continue;
                }
            }

            // Convert it from a lazy cert to a cert.
            let issuer = if let Some(Ok(i))
                = issuer.as_ref().map(|i| i.to_cert())
            {
                Some(i)
            } else {
                None
            };

            // If the certificate should not be exported, we don't
            // approve the certification.
            if let Some(i) = issuer.as_ref() {
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

            // Skip if the issuer is in --remove-by.
            if let Some(issuer) = issuer.as_ref() {
                if cmd_remove_by.iter().any(|j| issuer.key_handle().aliases(j)) {
                    continue;
                }
            } else if ! sig.get_issuers().iter().any(
                // Quadratic, but how bad can it be...?
                |i| cmd_remove_by.iter().any(|j| i.aliases(j)))
            {
                continue;
            }

            // Add if --add-all is passed.
            if cmd_add_all {
                next_approved.insert(sig);
                continue;
            }

            // Add if the issuer is in --add-by.
            if let Some(issuer) = issuer.as_ref() {
                if cmd_add_by.iter().any(|j| issuer.key_handle().aliases(j)) {
                    next_approved.insert(sig);
                    continue;
                }
            } else if let Some(cert) = sig.get_issuers().iter().find_map(
                // Quadratic, but how bad can it be...?
                |i| add_by.iter().find_map(
                    |cert| i.aliases(cert.key_handle()).then_some(cert)))
            {
                if sig.verify_signature(&cert.primary_key()).is_ok() {
                    next_approved.insert(sig);
                }
                continue;
            }

            // Add authenticated certifiers.
            if let Some(issuer) = issuer.as_ref() {
                if let Some((ref network, threshold)) = network_threshold {
                    if issuer.userids().any(
                        |u| network.authenticate(u.userid(),
                                                 issuer.fingerprint(),
                                                 threshold)
                            .amount() >= threshold)
                    {
                        next_approved.insert(sig);
                        continue;
                    }
                }
            }
        }

        let mut any = false;
        for (prev, next, c) in uid.certifications()
            .map(|c| (previously_approved.contains(c),
                      next_approved.contains(c), c))
        {
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

            if ! prev && next {
                added += 1;
            }
            if prev && ! next {
                removed += 1;
            }

            weprintln!(initial_indent = "  ", "{} {}{}: {}",
                       match (prev, next) {
                           (false, false) => '.',
                           (true, false) => '-',
                           (false, true) => '+',
                           (true, true) => '=',
                       },
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
                       } else if next {
                           "approved".into()
                       } else if prev {
                           "previously approved".into()
                       } else {
                           "unapproved".into()
                       });
            any = true;
        }

        if ! any {
            weprintln!("    no certifications");
        }

        approval_signatures.append(&mut uid.approve_of_certifications(
            &mut pk_signer,
            next_approved.into_iter(),
        )?);
    }
    assert!(designated_userids.is_empty());

    match (added, removed) {
        (1, 1) => {
            weprintln!("1 new approval, 1 approval retracted");
        }
        (added, 1) => {
            weprintln!("{} new approvals, 1 approval retracted",
                       added);
        }
        (1, removed) => {
            weprintln!("1 new approval, {} approvals retracted",
                       removed);
        }
        (added, removed) => {
            weprintln!("{} new approvals, {} approvals retracted",
                       added, removed);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(approval_signatures)?.0;

    if let Some((mut output, path)) = output {
        if false {
            key.as_tsk().serialize(&mut output)?;
        } else {
            key.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            sequoia.hint(format_args!(
                "Updated key written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert-file", path.display())
                .done();
        } else {
            sequoia.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let fpr = key.fingerprint();
        let cert_store = sequoia.cert_store_or_else()?;

        let stats = MergePublicCollectStats::new();
        cert_store.update_by(Arc::new(LazyCert::from(key)), &stats)
            .with_context(|| {
                format!("Failed to import {} into the certificate store",
                        fpr)
            })
            .map_err(|err| {
                weprintln!("Error importing updated cert: {}", err);
                err
            })?;

        sequoia.hint(format_args!(
            "Imported updated cert into the cert store.  \
             To make the update effective, it has to be published \
             so that others can find it, for example using:"))
            .sq().arg("network").arg("keyserver").arg("publish")
            .arg_value("--cert", fpr)
            .done();
    }

    Ok(())
}
