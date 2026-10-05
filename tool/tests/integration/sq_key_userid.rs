use std::time::Duration;

use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Result;
use sqz::openpgp;

use super::common::NO_USERIDS;
use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::UserIDArg;
use super::common::compare_notations;
use super::common::time_as_string;

#[test]
fn sq_key_userid_revoke() -> Result<()> {
    let sq = Sq::new();
    let time = sq.now();

    let userids = &["alice <alice@example.org>", "alice <alice@other.org>"];
    // revoke the last userid
    let userid_revoke = userids.last().unwrap();

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (ReasonForRevocation::UIDRetired, "retired", &[][..], None),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", &[][..], None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
    ] {
        eprintln!("==========================");
        eprintln!("reason: {}, message: {}, notations: {:?}, time: {:?}",
                  reason, reason_str, notations, revocation_time);

        for keystore in [false, true].into_iter() {
            eprintln!("--------------------------");
            eprintln!("keystore: {}", keystore);

            let (cert, cert_path, _rev_path) = sq.key_generate(&[], userids);

            let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
            let fingerprint = valid_cert.fingerprint();

            let message = "message";

            let revocation = sq.scratch_file(Some(&*format!(
                "revocation_{}_{}_{}.rev",
                reason_str,
                if notations.is_empty() {
                    "no_notations"
                } else {
                    "notations"
                },
                if revocation_time.is_some() {
                    "time"
                } else {
                    "no_time"
                }
            )));

            if keystore {
                // When using the keystore, we need to import the key.
                sq.key_import(&cert_path);
            }

            let mut cmd = sq.command();
            cmd.args([
                "key",
                "userid",
                "revoke",
                "--userid", userid_revoke,
                "--reason", reason_str,
                "--message", message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.arg("--cert-file").arg(&cert_path)
                    .arg("--output").arg(&revocation);
            }

            for (k, v) in notations {
                cmd.args(["--signature-notation", k, v]);
            }
            if let Some(time) = revocation_time {
                cmd.args([
                    "--time",
                    &time_as_string(time.into()),
                ]);
            }
            let output = cmd.output()?;
            if !output.status.success() {
                panic!(
                    "sq exited with non-zero status code: {}",
                    String::from_utf8(output.stderr)?
                );
            }

            // read revocation cert
            let rev = if keystore {
                sq.cert_export(cert.key_handle())
            } else {
                Cert::from_file(&revocation)?
            };
            assert!(! rev.is_tsk());
            let cert = cert.clone().merge_public(rev)?;
            let valid_cert =
                cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

            // whether we found a revocation signature
            let mut found_revoked = false;

            valid_cert.userids().for_each(|x| {
                if x.userid().value() == userid_revoke.as_bytes() {
                    if let RevocationStatus::Revoked(sigs) = x.bundle()
                        .revocation_status(
                            STANDARD_POLICY,
                            revocation_time.map(Into::into),
                        )
                    {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a certification revocation
                        assert_eq!(
                            sig.typ(),
                            SignatureType::CertificationRevocation
                        );

                        // the issuer is the certificate owner
                        assert_eq!(
                            sig.get_issuers().into_iter().next().as_ref(),
                            Some(&fingerprint.clone().into())
                        );

                        // our reason for revocation and message matches
                        assert_eq!(
                            sig.reason_for_revocation(),
                            Some((reason, message.as_bytes()))
                        );

                        // the notations of the revocation match the ones
                        // we passed in
                        assert!(compare_notations(sig, notations).is_ok());

                        found_revoked = true;
                    }
                }
            });

            if !found_revoked {
                panic!("the revoked userid is not found in the revocation cert");
            }
        }
    }

    Ok(())
}

#[test]
fn sq_key_userid_revoke_third_party() -> Result<()> {
    let sq = Sq::new();
    let time = sq.now();

    let userids = &["alice <alice@example.org>", "alice <alice@other.org>"];
    // revoke the last userid
    let userid_revoke = userids.last().unwrap();

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (ReasonForRevocation::UIDRetired, "retired", &[][..], None),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", &[][..], None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
    ] {
        for keystore in [false, true].into_iter() {
            let (cert, cert_path, _rev_path) = sq.key_generate(&[], userids);
            let (third_party_cert, third_party_path, _rev_path)
                = sq.key_generate(&[], &["bob <bob@example.org>"]);
            let third_party_valid_cert = third_party_cert
                .with_policy(STANDARD_POLICY, Some(time.into()))?;
            let third_party_fingerprint = third_party_valid_cert.fingerprint();

            let message = "message";

            let revocation = sq.scratch_file(Some(&*format!(
                "revocation_{}_{}_{}.rev",
                reason_str,
                if notations.is_empty() {
                    "no_notations"
                } else {
                    "notations"
                },
                if revocation_time.is_some() {
                    "time"
                } else {
                    "no_time"
                }
            )));

            if keystore {
                // When using the keystore, we need to import the key.

                for path in &[ &cert_path, &third_party_path ] {
                    sq.key_import(path);
                }
            }

            let mut cmd = sq.command();
            cmd.args([
                "key",
                "userid",
                "revoke",
                "--userid", userid_revoke,
                "--reason", reason_str,
                "--message", message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                    "--revoker", &third_party_cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.arg("--output").arg(&revocation)
                    .arg("--cert-file").arg(&cert_path)
                    .arg("--revoker-file").arg(&third_party_path);
            }

            for (k, v) in notations {
                cmd.args(["--signature-notation", k, v]);
            }
            if let Some(time) = revocation_time {
                cmd.args([
                    "--time",
                    &time_as_string(time.into()),
                ]);
            }
            let output = cmd.output()?;
            if !output.status.success() {
                panic!(
                    "sq exited with non-zero status code: {}",
                    String::from_utf8(output.stderr)?
                );
            }

            // read revocation cert
            let rev = if keystore {
                sq.cert_export(cert.key_handle())
            } else {
                Cert::from_file(&revocation)?
            };
            assert!(! rev.is_tsk());
            let revocation_cert = cert.clone().merge_public(rev)?;
            let revocation_valid_cert = revocation_cert
                .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

            // whether we found a revocation signature
            let mut found_revoked = false;

            revocation_valid_cert.userids().for_each(|x| {
                if x.userid().value() == userid_revoke.as_bytes() {
                    if let RevocationStatus::CouldBe(sigs) = x.bundle()
                        .revocation_status(
                            STANDARD_POLICY,
                            revocation_time.map(Into::into),
                        )
                    {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a certification revocation
                        assert_eq!(
                            sig.typ(),
                            SignatureType::CertificationRevocation
                        );

                        // the issuer is a third party revoker
                        assert_eq!(
                            sig.get_issuers().into_iter().next().as_ref(),
                            Some(&third_party_fingerprint.clone().into())
                        );

                        // the revocation can be verified
                        if sig
                            .clone()
                            .verify_userid_revocation(
                                third_party_cert.primary_key().key(),
                                revocation_cert.primary_key().key(),
                                &UserID::from(*userid_revoke),
                            )
                            .is_err()
                        {
                            panic!("revocation is not valid")
                        }

                        // our reason for revocation and message matches
                        assert_eq!(
                            sig.reason_for_revocation(),
                            Some((reason, message.as_bytes()))
                        );

                        // the notations of the revocation match the ones
                        // we passed in
                        assert!(compare_notations(sig, notations).is_ok());

                        found_revoked = true;
                    }
                }
            });

            if !found_revoked {
                panic!("the revoked userid is not found in the revocation cert");
            }
        }
    }

    Ok(())
}

#[test]
fn sq_key_userid_add() -> Result<()> {
    let sq = Sq::new();
    let (key, _, _) = sq.key_generate(&[], NO_USERIDS);
    assert_eq!(key.userids().count(), 0);

    let key = sq.key_userid_add(
        &[],
        key,
        &[
            UserIDArg::Name("Joan Clarke"),
            UserIDArg::Name("Joan Clarke Murray"),
            UserIDArg::Email("joan@hut8.bletchley.park"),
        ])?;

    assert_eq!(key.userids().count(), 3);
    assert!(key.userids().any(|u| u.userid().value() == b"Joan Clarke"));
    assert!(key.userids().any(|u| u.userid().value() == b"Joan Clarke Murray"));
    assert!(
        key.userids().any(|u| u.userid().value() == b"<joan@hut8.bletchley.park>"));

    Ok(())
}

#[test]
fn sq_key_from_file_userid_add() -> Result<()> {
    use super::common::artifact;

    use openpgp::Fingerprint;
    use openpgp::KeyHandle;

    let sq = Sq::new();

    let alice_fpr = "5CCBBA0674EA5162615E36E980E5ADE943CA0DC3";
    let alice_handle: KeyHandle = Fingerprint::from_hex(alice_fpr)?.into();
    let alice_uid = "Alice Lovelace <alice@example.org>";
    let alice_path = artifact("keys")
        .join("alice-lovelace-encryption-subkey-signing-subkey-priv.pgp");
    let output_path = sq.scratch_file(None);

    // Import alice's key and link it.
    sq.key_import(&alice_path);

    sq.pki_link_add(&[],
        alice_handle.clone().into(),
        &[alice_uid]);

    // Add a new User ID to alice's key, but use the stateless interface
    // (no interaction with the cert store).
    let mut cmd = sq.command();
    cmd.args([
        "key",
        "userid",
        "add",
        "--home", "none",
        "--cert-file", alice_path.to_str().unwrap(),
        "--email", "alice@other.org",
        "--output", output_path.to_str().unwrap(),
    ]);
    let _output = sq.run(cmd, Some(true));

    // Import the result so that we can check the authentication of the 2
    // User IDs.
    sq.inspect(&output_path);
    sq.key_import(output_path);

    // The User ID which was linked should still be authenticated.
    assert!(sq.pki_authenticate(&[],
        alice_fpr,
        alice_uid).is_ok());

    // The added User ID should not be authenticated.
    assert!(sq.pki_authenticate(&[],
        alice_fpr,
        "<alice@other.org>").is_err());

    // Add new User IDs to alice's key, this time operate on the
    // cert store.
    let mut cmd = sq.command();
    cmd.args([
        "key",
        "userid",
        "add",
        "--cert", alice_fpr,
        "--email", "alice@this.org",
        "--email", "alice@that.org",
    ]);
    let _output = sq.run(cmd, Some(true));
    sq.inspect(&alice_handle);

    // The added user IDs should be authenticated.
    assert!(sq.pki_authenticate(&[],
        alice_fpr,
        "<alice@this.org>").is_ok());
    assert!(sq.pki_authenticate(&[],
        alice_fpr,
        "<alice@that.org>").is_ok());

    Ok(())
}
