use anyhow::Context;

use sequoia::openpgp;
use openpgp::Result;
use openpgp::parse::buffered_reader;
use openpgp::serialize::Serialize;

use sequoia::inspect::inspect;
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
    let mut output_path = None;
    let mut rev_;
    let output = if let (Some(output_path_arg), Some(rev_path_arg))
        = (command.output, command.rev_cert)
    {
        // Don't import; save to a file.
        output_ = output_path_arg.clone().for_secrets().create_safe(&sq)?;
        output_path_ = output_path_arg.clone();
        output_path = output_path_.path().map(|p| p.as_path());
        rev_ = rev_path_arg.for_secrets().create_safe(&sq)?;
        Some((&mut output_ as &mut dyn std::io::Write,
              &mut rev_ as &mut dyn std::io::Write))
    } else {
        // Save to the key store.
        None
    };

    let prompt = password::Prompt::new(&sq, false);

    if command.names.is_empty()
        && command.emails.is_empty()
        && command.userid.is_empty()
    {
        weprintln!("No user ID given, using direct key signature");
    }

    let own_key = command.own_key;
    let on_keystore = output.is_none();

    let result = sq.sequoia.key_generate()
        .profile(command.profile.into())
        .cipher_suite(command.cipher_suite.into())
        .password_policy(password_policy)
        .expiration(command.expiration.value())
        .own_key(own_key)
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
                  output)?;

    if let Some(key_import_status) = result.key_import_status() {
        for (fpr, status) in key_import_status.iter() {
            sq.info(format_args!(
                "Importing {} into key store: {:?}",
                fpr, status));
        }
    }

    let cert = result.cert();

    {
        let mut bytes = Vec::new();
        cert.as_tsk().serialize(&mut bytes)
            .expect("serializing to a vector is infallible");
        if let Err(err) = inspect(
            &sq.sequoia,
            buffered_reader::Memory::with_cookie(&bytes, Default::default()),
            output_path
                .as_ref()
                .and_then(|p| Some(p.display().to_string()))
                .as_deref(),
            &mut (Box::new(std::io::stderr()) as Box<dyn std::io::Write + Send + Sync>),
            false, false)
        {
            weprintln!("Failed to display key: {}", err);
            weprintln!("This is probably a bug in sq, please report it to \
                        https://gitlab.com/sequoia-pgp/sequoia-sq/-/issues/new .");
        }
    }

    // If we are writing to key store, provide some guidance.
    if on_keystore && own_key {
        sq.hint(format_args!("Because you supplied the `--own-key` \
                              flag, the user IDs on this key have \
                              been marked as authenticated, and \
                              this key has been marked as a fully \
                              trusted introducer.  If that was a \
                              mistake, you can undo that with:"))
            .sq().arg("pki").arg("link").arg("retract")
            .arg_value("--cert", cert.fingerprint())
            .arg("--all")
            .done();
    }
    if on_keystore && ! own_key {
        sq.hint(format_args!("The user IDs on the key have been marked \
                              as authenticated.  \
                              If that was a mistake, you can undo that \
                              with:"))
            .sq().arg("pki").arg("link").arg("retract")
            .arg_value("--cert", cert.fingerprint())
            .arg("--all")
            .done();
    }

    if on_keystore {
        sq.hint(format_args!("You can export your certificate as \
                              follows:"))
            .sq().arg("cert").arg("export")
            .arg_value("--cert", cert.fingerprint())
            .done();
        sq.hint(format_args!("Once you are happy you can upload \
                              it to public directories using:"))
            .sq().arg("network").arg("keyserver").arg("publish")
            .arg_value("--cert", cert.fingerprint())
            .done();
    } else {
        let mut shown = false;
        if let Some(ref output_path) = output_path {
            sq.hint(format_args!("You can extract the \
                                  certificate from the \
                                  generated key by running:"))
                .sq().arg("key").arg("delete")
                .arg_value("--cert-file", output_path.display())
                .arg_value("--output", output_path.with_extension("cert").display())
                .done();
            shown = true;
        }
        if ! shown {
            sq.hint(format_args!("You can extract the certificate from the \
                                  generated key using:"))
                .sq().arg("key").arg("delete").done();
        }
    }

    Ok(())
}
