use anyhow::Context;

use sequoia::openpgp;
use openpgp::cert::UserIDRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::UserID;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::cli::key::userid::RevokeCommand;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::password;
use crate::common::ui;

/// Handle the revocation of a User ID
struct UserIDRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
    uid: UserID,
}

impl UserIDRevocation {
    /// Create a new UserIDRevocation
    pub fn new(
        sq: &Sq,
        uid: ResolvedUserID,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer)
            = get_secret_signer(sq, &cert, revoker.as_ref())?;

        let revocation_packet = {
            // Create a revocation for a User ID.
            let mut rev = UserIDRevocationBuilder::new()
                .set_reason_for_revocation(reason, message.as_bytes())?;
            rev = rev.set_signature_creation_time(sq.time())?;
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
                uid.userid(),
                None,
            )?;
            Packet::Signature(rev)
        };

        Ok(UserIDRevocation {
            cert,
            revoker,
            revocation_packet,
            uid: uid.userid().clone(),
        })
    }
}

impl RevocationOutput for UserIDRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.uid.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        format!("This is a revocation certificate for \
                 the User ID {} of cert {}.",
                ui::Safe(&self.uid),
                self.cert.fingerprint())
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

pub fn dispatch(
    sq: Sq,
    command: cli::key::userid::Command,
) -> Result<()> {
    match command {
        cli::key::userid::Command::Add(c) => userid_add(sq, c)?,
        cli::key::userid::Command::Revoke(c) => userid_revoke(sq, c)?,
    }

    Ok(())
}

fn userid_add(
    sq: Sq,
    command: cli::key::userid::AddCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let mut output_;
    let output = if let Some(output_path) = command.output {
        // Don't import; save to a file.
        output_ = output_path.for_secrets().create_safe(&sq)?;
        Some(&mut output_ as &mut dyn std::io::Write)
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::Prompt::new(&sq, false);

    sq.sequoia.key_userid_add()
        .names(&command.names)
        .emails(&command.emails)
        .userids(command.userid.into_iter())
        .allow_non_canonical_userids(command.allow_non_canonical_userids)
        .add(
            &cert,
            prompt,
            output)
}

/// Revoke a UserID of an existing primary key
///
/// ## Errors
///
/// Returns an error if reading of the [`Cert`] fails, if retrieval of
/// [`NotationData`] fails or if the eventual revocation fails.
pub fn userid_revoke(
    sq: Sq,
    command: RevokeCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    // To revoke a user ID, we require the certificate be valid under
    // the current policy.  Users can still revoke user IDs whose
    // binding signature relies on weak cryptography using
    // `--add-user`.
    let vcert = cert.with_policy(sq.policy(), sq.time())
        .with_context(|| {
            format!("The certificate is not valid under the current \
                     policy.  Consider revoking the whole certificate \
                     using `sq key revoke`, or fixing it using \
                     `sq cert lint` after verifying the certificate's \
                     integrity.")
        })?;
    let userids = command.userids.resolve(&vcert)?;
    assert_eq!(userids.len(), 1, "exactly one user ID enforced by clap");
    let userid = userids.into_iter().next().unwrap();

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, TrustThreshold::Full)?.0)
    };

    let notations = command.signature_notations.parse()?;

    let revocation = UserIDRevocation::new(
        &sq,
        userid,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;

    revocation.write(&sq, command.output, false)?;

    Ok(())
}
