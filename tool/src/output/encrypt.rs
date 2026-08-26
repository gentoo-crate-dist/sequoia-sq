use sequoia::cert;
use sequoia::config::Config;
use sequoia::encrypt;

use crate::Result;
use crate::Sq;
use crate::error_chain;
use crate::output::pluralize::Pluralize;

pub struct Stream<'a> {
    sq: &'a Sq,
}

impl<'a> Stream<'a> {
    pub fn new(sq: &'a Sq) -> Self {
        Self {
            sq,
        }
    }
}

impl encrypt::Stream for Stream<'_> {
    fn output(&mut self,
              _params: &encrypt::Params,
              output: encrypt::Output)
        -> Result<()>
    {
        make_qprintln!(self.sq.quiet());

        match output {
            encrypt::Output::EncryptionFailed(
                encrypt::output::EncryptionFailed {
                    unusable_certs,
                    ..
                }) =>
            {
                let unusable_cert = unusable_certs[0].clone();

                for unusable_cert in unusable_certs {
                    let cert::CertError {
                        cert,
                        problems,
                        ..
                    } = unusable_cert;

                    weprintln!("Cannot encrypt to {}, {}:",
                               cert.fingerprint(),
                               self.sq.best_userid(&cert, true).display());
                    let mut suggest_use_expired_subkey = false;
                    for problem in problems {
                        if let cert::CertProblem::NotLive(_)
                            = &problem
                        {
                            suggest_use_expired_subkey = true;
                        }

                        for (i, err)
                            in error_chain(&anyhow::Error::from(problem))
                                .into_iter()
                                .enumerate()
                        {
                            if i == 0 {
                                weprintln!(initial_indent="  - ",
                                           "{}", err);
                            } else {
                                weprintln!(initial_indent="    ",
                                           "because: {}", err);
                            }
                        }
                    }

                    if suggest_use_expired_subkey {
                        self.sq.hint(format_args!(
                            "To use an expired key anyway, pass \
                             --use-expired-subkey"));
                    }
                }

                let err = if let cert::CertProblem::CertInvalid(_)
                    = unusable_cert.problems[0]
                {
                    anyhow::anyhow!(
                        "{}, {} is not valid according to the current policy",
                        unusable_cert.cert.fingerprint(),
                        self.sq.sequoia.best_userid(&unusable_cert.cert, true).display())
                } else if let cert::CertProblem::CertRevoked(_)
                    = unusable_cert.problems[0]
                {
                    anyhow::anyhow!(
                        "Can't encrypt to {}, {}: it is revoked",
                        unusable_cert.cert.fingerprint(),
                        self.sq.sequoia.best_userid(&unusable_cert.cert, true).display())
                } else if unusable_cert.no_usable_keys()
                    .map(|p| p.unusable == 0)
                    .unwrap_or(false)
                {
                    anyhow::anyhow!(
                        "Cert {}, {} has no encryption-capable keys",
                        unusable_cert.cert.fingerprint(),
                        self.sq.sequoia.best_userid(&unusable_cert.cert, true).display())
                } else {
                    anyhow::anyhow!(
                        "Cert {}, {} has no suitable encryption key",
                        unusable_cert.cert.fingerprint(),
                        self.sq.sequoia.best_userid(&unusable_cert.cert, true).display())
                };

                return Err(err);
            }

            encrypt::Output::Encrypting(
                encrypt::output::Encrypting {
                    recipients,
                    undecryptable,
                    passwords,
                    signers,
                    ..
                }) =>
            {
                for (cert, _encryption_keys) in recipients {
                    qprintln!();
                    qprintln!(initial_indent = " - ", "encrypted for {}",
                              self.sq.best_userid(&cert, true).display());
                    qprintln!(initial_indent = "   - ", "using {}",
                              cert.fingerprint());
                }
                if ! passwords.is_empty() {
                    qprintln!();
                    qprintln!(initial_indent = " - ", "encrypted using {}",
                              passwords.len().of("password"));
                }
                if signers.is_empty() {
                    self.sq.hint(format_args!(
                        "The message will not be signed.  \
                         While the message integrity will be protected \
                         by the encryption, there will be no way for the \
                         recipient to tell whether the message is \
                         authentic.  Consider signing the message."));
                } else {
                    for (signer, _) in signers {
                        qprintln!();
                        qprintln!(initial_indent = " - ", "signed by {}",
                                  self.sq.best_userid(&signer, true).display());
                        qprintln!(initial_indent = "   - ", "using {}",
                                  signer.fingerprint());
                    }
                }

                if undecryptable {
                    if let Some(home) = self.sq.sequoia.home() {
                        self.sq.hint(format_args!(
                            "It looks like you won't be able to decrypt the message.  \
                             Consider adding yourself as recipient, for example by \
                             adding your cert to `{}` in the configuration file ({}), \
                             and using the `--for-self` argument.",
                            Config::encrypt_for_self_config_key(),
                            crate::config::ConfigFile::file_name(home).display()));
                    } else {
                        self.sq.hint(format_args!(
                            "It looks like you won't be able to decrypt the message.  \
                             Consider adding yourself as recipient."));
                    }
                }

                // A newline to make it look nice.
                qprintln!();
            }

            encrypt::Output::Encrypted(
                encrypt::output::Encrypted {
                    ..
                }) =>
            {
            }

            _output => {
                // eprintln!("Unknown output: {:?}", output);
            }
        }

        Ok(())
    }
}
