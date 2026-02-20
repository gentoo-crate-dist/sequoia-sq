use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::cert::CipherSuite;
use openpgp::cert::KeyBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;

use crate::Sequoia;
use crate::config::Expiration;
use crate::key::PasswordPolicy;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::types::EncryptPurpose;
use crate::types::import_stats::ImportStats;

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
pub fn add<P>(sequoia: &Sequoia,
              cert: &Cert,
              cipher_suite: CipherSuite,
              expiration: Expiration,
              can_sign: bool,
              can_authenticate: bool,
              can_encrypt: Option<EncryptPurpose>,
              password: PasswordPolicy,
              prompt: P,
              output: Option<&mut dyn std::io::Write>)
    -> Result<()>
where
    P: prompt::Prompt,
{
    let valid_cert = cert.with_policy(sequoia.policy(), sequoia.time())?;

    let validity = expiration
        .as_duration(DateTime::<Utc>::from(sequoia.time()))?;

    let keyflags = KeyFlags::empty()
        .set_authentication_to(can_authenticate)
        .set_signing_to(can_sign)
        .set_storage_encryption_to(matches!(
            can_encrypt,
            Some(EncryptPurpose::Storage) | Some(EncryptPurpose::Universal)
        ))
        .set_transport_encryption_to(matches!(
            can_encrypt,
            Some(EncryptPurpose::Transport) | Some(EncryptPurpose::Universal)
        ));

    // If a password is needed to use the key, the user will be prompted.
    let (primary_key, password) =
        match sequoia.get_primary_key(cert, None, &prompt) {
            Ok(key) => {
                // Don't use a password, or prompt for one.
                match password {
                    PasswordPolicy::Password(password) => {
                        (key, Some(password))
                    }
                    PasswordPolicy::None => {
                        (key, None)
                    }
                    PasswordPolicy::Prompt => {
                        let mut checker = CheckNewPassword::optional();

                        let mut context = prompt::ContextBuilder::password(
                            prompt::Reason::LockNewKey)
                            .sequoia(sequoia)
                            .build();

                        let password = match prompt.prompt(
                            &mut context, &mut checker)?
                        {
                            prompt::Response::Password(password) => Some(password),
                            prompt::Response::NoPassword => None,
                        };
                        (key, password)
                    }
                }
            }
            Err(error) => {
                return Err(error.into())
            }
        };

    let new_cert = KeyBuilder::new(keyflags)
        .set_creation_time(sequoia.time())
        .set_cipher_suite(cipher_suite)
        .set_password(password)
        .subkey(valid_cert)?
        .set_key_validity_period(validity)?
        .set_primary_key_signer(primary_key)
        .attach_cert()?;

    if let Some(output_writer) = output {
        new_cert.as_tsk().armored().serialize(output_writer)?;
    } else {
        let mut stats = ImportStats::default();
        let result = sequoia.key_import()
            .import_key(new_cert, &mut stats)?;
        for (fpr, status) in result.key_import_status.iter() {
            sequoia.info(format_args!(
                "Importing {} into key store: {:?}",
                fpr, status));
        }
    }

    Ok(())
}
