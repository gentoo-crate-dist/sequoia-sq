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
use crate::config::Expiration;
use crate::prompt;
use crate::types::Safe;
use crate::types::TrustAmount;
use crate::userid::lint_emails;
use crate::userid::lint_names;
use crate::userid::lint_userids;

/// Parameters for adding a user ID to a certificate.
///
/// These parameters are used by [`add`](Builder::add).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    names: Vec<String>,
    emails: Vec<String>,
    userids: Vec<UserID>,
    allow_non_canonical_userids: bool,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the names that will be added to the certificate.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        use std::ops::Deref;
        self.names.iter().map(|s| s.deref())
    }

    /// Returns the email address that will be added to the certificate.
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        use std::ops::Deref;
        self.emails.iter().map(|s| s.deref())
    }

    /// Returns the user IDs that will be added to the certificate.
    pub fn userids(&self) -> impl Iterator<Item = &UserID> {
        self.userids.iter().map(|u| u)
    }

    /// Returns whether non-canonical user IDs are allowed.
    ///
    /// If disabled, [`Builder::add`] will fail if any user IDs are
    /// not in canonical form.
    pub fn allow_non_canonical_userids(&self) -> bool {
        self.allow_non_canonical_userids
    }
}

/// Adds user IDs to a certificate.
///
/// A builder providing control over how to add user IDs to a new
/// certificate.
pub struct Builder<'sequoia> {
    params: Params<'sequoia>,
}

impl<'sequoia> Builder<'sequoia>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Builder<'sequoia> {
        Builder {
            params: Params {
                sequoia,
                names: Vec::new(),
                emails: Vec::new(),
                userids: Vec::new(),
                allow_non_canonical_userids: false,
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Adds the specified name to the certificate.
    pub fn name<S>(mut self, name: S) -> Self
    where
        S: Into<String>
    {
        self.params.names.push(name.into());
        self
    }

    /// Adds the specified names to the certificate.
    pub fn names<S>(mut self, names: impl IntoIterator<Item=S>) -> Self
    where
        S: Into<String>
    {
        self.params.names.extend(names.into_iter().map(|s| s.into()));
        self
    }

    /// Adds the specified email address to the certificate.
    pub fn email<S>(mut self, email: S) -> Self
    where
        S: Into<String>
    {
        self.params.emails.push(email.into());
        self
    }

    /// Adds the specified email addresses to the certificate.
    pub fn emails<S>(mut self, emails: impl IntoIterator<Item=S>) -> Self
    where
        S: Into<String>
    {
        self.params.emails.extend(emails.into_iter().map(|s| s.into()));
        self
    }

    /// Adds the specified user ID to the certificate.
    pub fn userid<U>(mut self, userid: U) -> Self
    where
        U: Into<UserID>
    {
        self.params.userids.push(userid.into());
        self
    }

    /// Adds the specified user IDs to the certificate.
    pub fn userids(mut self, userids: impl IntoIterator<Item=UserID>)
                   -> Self
    {
        self.params.userids.extend(userids.into_iter().map(|s| s.into()));
        self
    }

    /// Sets whether non-canonical user IDs are allowed.
    ///
    /// If disabled, [`Builder::add`] will fail if any user IDs are
    /// not in canonical form.
    pub fn allow_non_canonical_userids(
        mut self, allow_non_canonical_userids: bool)
        -> Self
    {
        self.params.allow_non_canonical_userids = allow_non_canonical_userids;
        self
    }

    /// Adds a user ID to the specified certificate.
    ///
    /// If `output` is `None`, then the key is saved to the key store.
    /// If `output` is `Some`, the certificate with the user user ID
    /// is written to the specified writer.
    pub fn add<'a, P>(&self,
                      cert: &Cert,
                      prompt: P,
                      output: Option<&mut dyn std::io::Write>)
        -> Result<()>
    where
        P: prompt::Prompt + 'a,
    {
        let &Builder {
            params: Params {
                sequoia,
                ref names,
                ref emails,
                ref userids,
                allow_non_canonical_userids,
            },
        } = self;

        let mut signer = sequoia.get_primary_key(cert, None, &prompt)?;

        // Make sure the user IDs are in canonical form.  If not, and
        // `--allow-non-canonical-userids` is not set, error out.
        if ! allow_non_canonical_userids {
            lint_userids(&userids)?;
        }

        let mut userids = userids.to_vec();

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
        for uid in &userids {
            let uid: UserID = uid.clone().into();
            add.push(uid.clone().into());

            // Creation time.
            sb = sb.set_signature_creation_time(sequoia.time())?;

            let binding = uid.bind(&mut signer, &cert, sb.clone())?;
            add.push(binding.into());
        }

        // Mark the new user IDs as authenticated when saving the
        // certificate to the cert store (a local trust root is
        // available).
        if let Ok(trust_root) = sequoia.local_trust_root() {
            let trust_root = trust_root.to_cert()?;

            sequoia.pki_certify()
                .recreate(false)
                .trust_depth(0)
                .trust_amount(TrustAmount::Full.amount())
                .expiration(Expiration::Never)
                .exportable(false)
                .certify(
                    &trust_root,
                    &cert,
                    &userids,
                    &prompt)?;
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
}
