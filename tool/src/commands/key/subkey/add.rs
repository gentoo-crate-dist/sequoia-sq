use anyhow::Context;

use sqz::openpgp;
use openpgp::Result;
use sqz::key::PasswordPolicy;

use sqz::types::TrustThreshold;

use crate::Sq;
use crate::cli::key::subkey::add::Command;
use crate::common::password;

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    let cert =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let ciphersuite = sq.config().resolve_cipher_suite(
        &command.cipher_suite, command.cipher_suite_source)
        .as_ciphersuite();

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

    let prompt = password::PromptFactory::new(&sq, false);

    let mut output_;
    let output = if let Some(output_path) = command.output {
        // Don't import; save to a file.
        output_ = output_path.for_secrets().create_safe(&sq)?;
        Some(&mut output_ as &mut dyn std::io::Write)
    } else {
        // Save to the key store.
        None
    };

    sq.sequoia.key_subkey_add()
        .prompt(prompt)
        .password_policy(password_policy)
        .cipher_suite(ciphersuite)
        .expiration(command.expiration.value())
        .can_sign(command.can_sign)
        .can_authenticate(command.can_authenticate)
        .can_encrypt(command.can_encrypt)
        .add(
            &cert,
            output)
}
