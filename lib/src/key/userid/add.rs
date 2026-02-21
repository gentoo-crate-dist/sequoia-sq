use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use openpgp::packet::UserID;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sequoia;
use crate::prompt::Prompt;
use crate::types::Safe;
use crate::userid::lint_emails;
use crate::userid::lint_names;
use crate::userid::lint_userids;

pub fn add<'a, P>(
    sequoia: &Sequoia,
    cert: &Cert,
    names: &[String],
    emails: &[String],
    userids: impl Iterator<Item=UserID>,
    allow_non_canonical_userids: bool,
    prompt: P,
    output: Option<&mut dyn std::io::Write>)
    -> Result<()>
where
    P: Prompt
{
    let mut signer = sequoia.get_primary_key(cert, None, prompt)?;

    let mut userids = userids.collect::<Vec<_>>();
    // Make sure the user IDs are in canonical form.  If not, and
    // `--allow-non-canonical-userids` is not set, error out.
    if ! allow_non_canonical_userids {
        lint_userids(&userids)?;
    }

    // Names, email addresses, and user IDs.
    lint_names(&names)?;
    for n in names {
        userids.push(UserID::from(n.as_str()));
    }

    lint_emails(&emails)?;
    for n in emails {
        userids.push(UserID::from_address(None, None, n)?);
    }

    // Fail if any of the User IDs to add already exist in the ValidCert
    let cert_userids: Vec<_> =
        cert.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> = userids
        .iter()
        .filter(|s| cert_userids.contains(&s.value()))
        .collect();
    if !exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| Safe(*s).to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    let vcert = cert
        .with_policy(sequoia.policy(), sequoia.time())
        .with_context(|| {
            format!("Certificate {} is not valid", cert.fingerprint())
        })?;

    // Use the primary User ID or direct key signature as template for the
    // SignatureBuilder.
    //
    // XXX: Long term, this functionality belongs next to
    // openpgp/src/cert/builder/key.rs.
    let mut sb = if let Ok(primary_user_id) = vcert.primary_userid() {
        SignatureBuilder::from(primary_user_id.binding_signature().clone())
    } else if let Ok(direct_key_sig) = vcert.direct_key_signature() {
        SignatureBuilder::from(direct_key_sig.clone())
            .set_type(SignatureType::PositiveCertification)
    } else {
        // If there is neither a valid uid binding signature, nor a
        // valid direct key signature, we shouldn't have gotten a
        // ValidCert above.
        unreachable!("ValidCert has to have one of the above.")
    };

    // Remove bad algorithms from preferred algorithm subpackets,
    // and make sure preference lists contain at least one good algorithm.

    // - symmetric_algorithms
    let mut symmetric_algorithms: Vec<_> =
        sb.preferred_symmetric_algorithms().unwrap_or(&[]).to_vec();
    symmetric_algorithms
        .retain(|algo| sequoia.policy().symmetric_algorithm(*algo).is_ok());
    if symmetric_algorithms.is_empty() {
        symmetric_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_symmetric_algorithms(symmetric_algorithms)?;

    // - hash_algorithms
    let mut hash_algorithms: Vec<_> =
        sb.preferred_hash_algorithms().unwrap_or(&[]).to_vec();
    hash_algorithms.retain(|algo| {
        sequoia
            .policy()
            .hash_cutoff(*algo, HashAlgoSecurity::CollisionResistance)
            .map(|cutoff| cutoff.lt(&SystemTime::now()))
            .unwrap_or(true)
    });
    if hash_algorithms.is_empty() {
        hash_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_hash_algorithms(hash_algorithms)?;

    // Remove the following types of SubPacket, if they exist
    #[allow(deprecated)]
    const REMOVE_SUBPACKETS: &[SubpacketTag] = &[
        // The Signature should be exportable.
        // https://openpgp-wg.gitlab.io/rfc4880bis/#name-exportable-certification
        // "If this packet is not present, the certification is exportable;
        // it is equivalent to a flag containing a 1."
        SubpacketTag::ExportableCertification,
        // PreferredAEADAlgorithms has been removed by WG.
        // It was replaced by `39  Preferred AEAD Ciphersuites`,
        //  see https://openpgp-wg.gitlab.io/rfc4880bis/#section-5.2.3.5-7)
        SubpacketTag::PreferredAEADAlgorithms,
        // Strip the primary userid SubPacket
        // (don't implicitly make a User ID primary)
        SubpacketTag::PrimaryUserID,
        // Other SubPacket types that shouldn't be in use in this context
        SubpacketTag::TrustSignature,
        SubpacketTag::RegularExpression,
        SubpacketTag::SignersUserID,
        SubpacketTag::ReasonForRevocation,
        SubpacketTag::SignatureTarget,
        SubpacketTag::EmbeddedSignature,
        SubpacketTag::ApprovedCertifications,
    ];

    sb = sb.modify_hashed_area(|mut subpacket_area| {
        REMOVE_SUBPACKETS
            .iter()
            .for_each(|sp| subpacket_area.remove_all(*sp));

        Ok(subpacket_area)
    })?;

    // New User ID should only be made primary if explicitly specified by user.
    // xxx: add a parameter to set a new user id as primary?

    // Collect packets to add to the key (new User IDs and binding signatures)
    let mut add: Vec<Packet> = vec![];

    // Make new User IDs and binding signatures
    for uid in userids {
        let uid: UserID = uid.into();
        add.push(uid.clone().into());

        // Creation time.
        sb = sb.set_signature_creation_time(sequoia.time())?;

        let binding = uid.bind(&mut signer, &cert, sb.clone())?;
        add.push(binding.into());
    }

    // Merge the new User IDs into cert.
    let cert = cert.clone().insert_packets(add)?.0;

    if let Some(output) = output {
        if false {
            cert.as_tsk().serialize(output)?;
        } else {
            cert.as_tsk().armored().serialize(output)?;
        }
    } else {
        let cert_store = sequoia.cert_store_or_else()?;
        cert_store.update(Arc::new(cert.into()))?;
    }

    Ok(())
}
