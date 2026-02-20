use anyhow::Context;

use sequoia::openpgp;
use openpgp::Result;

use sequoia::key::PasswordPolicy;
use sequoia::types::EncryptPurpose;

use crate::Sq;
use crate::cli;
use crate::common::password;

pub fn generate(
    sq: Sq,
    command: cli::key::generate::Command,
) -> Result<()> {
    if command.output.as_ref().map(|s| s.is_stdout()).unwrap_or(false)
        && command.rev_cert.as_ref().map(|s| s.is_stdout()).unwrap_or(false)
    {
        return Err(anyhow::anyhow!(
            "--output and --rev-cert must not both be stdout"));
    }

    if command.output.is_none() {
        // We're going to save the output to the certificate store and
        // the key store.  Make sure they are enabled.
        sq.cert_store_or_else()?;
        sq.key_store_or_else()?;
    }

    let password_policy = if let Some(path) = command.new_password_file {
        let password = std::fs::read(&path)
             .with_context(|| {
                 format!("Reading {}", path.display())
             })?;
        PasswordPolicy::Password(password.into())
    } else if command.without_password {
        PasswordPolicy::None
    } else {
        PasswordPolicy::Prompt
    };

    let mut output_;
    let output_path_;
    let mut rev_;
    let output = if let (Some(output_path), Some(rev_path))
        = (command.output, command.rev_cert)
    {
        // Don't import; save to a file.
        output_ = output_path.clone().for_secrets().create_safe(&sq)?;
        output_path_ = output_path.clone();
        rev_ = rev_path.for_secrets().create_safe(&sq)?;
        Some((&mut output_ as &mut dyn std::io::Write,
              output_path_.path().map(|p| p.as_path()),
              &mut rev_ as &mut dyn std::io::Write))
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::Prompt::new(&sq, false);

    sq.sequoia.key_generate()
        .profile(command.profile.into())
        .cipher_suite(command.cipher_suite.into())
        .password_policy(password_policy)
        .expiration(command.expiration.value())
        .own_key(command.own_key)
        .can_sign(! command.cannot_sign)
        .can_authenticate(! command.cannot_authenticate)
        .can_encrypt(
            if command.cannot_encrypt {
                None
            } else {
                Some(command
                     .can_encrypt
                     .unwrap_or(EncryptPurpose::Universal))
            })
        .names(command.names)
        .emails(command.emails)
        .userids(command.userid)
        .allow_non_canonical_userids(command.allow_non_canonical_userids)
        .generate(prompt,
                  output)
}
