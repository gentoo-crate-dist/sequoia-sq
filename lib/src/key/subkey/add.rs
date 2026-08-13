use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::cert::CipherSuite;
use openpgp::cert::KeyBuilder;
use openpgp::crypto;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;

use crate::Sequoia;
use crate::config::DEFAULT_KEY_VALIDITY_DURATION;
use crate::config::Expiration;
use crate::key::PasswordPolicy;
use crate::prompt::check::CheckNewPassword;
use crate::prompt;
use crate::types::EncryptPurpose;

/// The key generation parameters.
///
/// These parameters are used by [`add`](Builder::add).
#[derive(Clone)]
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    cipher_suite: CipherSuite,
    password_policy: PasswordPolicy,
    expiration: Expiration,
    can_sign: bool,
    can_authenticate: bool,
    can_encrypt: Option<EncryptPurpose>,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns the password policy.
    pub fn password_policy(&self) -> &PasswordPolicy {
        &self.password_policy
    }

    /// Returns the suite of ciphers that the certificate will use.
    ///
    /// The cipher suite is a group of algorithms that determine what
    /// algorithms will be considered when generating the keys.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite.clone()
    }

    /// When the certificate expires.
    pub fn expiration(&self) -> &Expiration {
        &self.expiration
    }

    /// Returns whether the new key will be signing capable.
    pub fn can_sign(&self) -> bool {
        self.can_sign
    }

    /// Returns whether the new key will be authentication capable.
    pub fn can_authenticate(&self) -> bool {
        self.can_authenticate
    }

    /// Returns whether the new key will be encryption capable.
    pub fn can_encrypt(&self) -> Option<&EncryptPurpose> {
        self.can_encrypt.as_ref()
    }
}

/// Adds a subkey to a certificate.
///
/// A builder providing control over how to add a subkey to a
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
                cipher_suite: CipherSuite::default(),
                password_policy: PasswordPolicy::Prompt,
                expiration: Expiration::from_duration(
                    DEFAULT_KEY_VALIDITY_DURATION),
                can_sign: true,
                can_authenticate: true,
                can_encrypt: Some(EncryptPurpose::Universal),
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    /// Sets the suite of ciphers that the certificate may use.
    ///
    /// The cipher suite is a group of algorithms that will be
    /// considered when generating the keys.
    pub fn cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.params.cipher_suite = cipher_suite;
        self
    }

    /// Sets the password policy.
    ///
    /// See also [`Builder::password`] and
    /// [`Builder::without_password`].
    pub fn password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.params.password_policy = policy;
        self
    }

    /// Sets the password that will be used to protect the secret key
    /// material.
    ///
    /// See also [`Builder::password_policy`] and
    /// [`Builder::without_password`].
    pub fn password(mut self, password: crypto::Password) -> Self {
        self.params.password_policy = PasswordPolicy::Password(password);
        self
    }

    /// Sets that no password will be used to protect the secret key
    /// material.
    ///
    /// See also [`Builder::password_policy`] and
    /// [`Builder::password`].
    pub fn without_password(mut self) -> Self {
        self.params.password_policy = PasswordPolicy::None;
        self
    }

    /// When the certificate expires.
    pub fn expiration(mut self, expiration: Expiration) -> Self
    {
        self.params.expiration = expiration;
        self
    }

    /// Sets whether new key will be signing capable.
    ///
    /// Note: it is rarely advisable to create a subkey with multiple
    /// capabilities.  Further, most algorithms support either signing
    /// or encryption, but not both.
    pub fn can_sign(mut self, can_sign: bool) -> Self {
        self.params.can_sign = can_sign;
        self
    }

    /// Sets whether new key will be authentication capable.
    ///
    /// Note: it is rarely advisable to create a subkey with multiple
    /// capabilities.  Further, most algorithms support either signing
    /// or encryption, but not both.
    pub fn can_authenticate(mut self, can_authenticate: bool) -> Self {
        self.params.can_authenticate = can_authenticate;
        self
    }

    /// Sets whether new key will be encryption capable.
    ///
    /// Note: it is rarely advisable to create a subkey with multiple
    /// capabilities.  Further, most algorithms support either signing
    /// or encryption, but not both.
    pub fn can_encrypt<E>(mut self, encrypt_purpose: E)
        -> Self
    where
        E: Into<Option<EncryptPurpose>>
    {
        self.params.can_encrypt = encrypt_purpose.into();
        self
    }

    /// Adds a subkey to the specified certificate.
    ///
    /// If `output` is `None`, then the new key is saved to the key
    /// store.  If `output` is `Some`, the certificate with the new
    /// key is written to the specified writer.
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
                cipher_suite,
                ref password_policy,
                ref expiration,
                can_sign,
                can_authenticate,
                ref can_encrypt,
            },
        } = self;

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
                    match password_policy {
                        PasswordPolicy::Password(password) => {
                            (key, Some(password.clone()))
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
            let mut output = Vec::new();
            sequoia.key_import()
                .stream(&mut output)
                .import_keys(Some(new_cert))?;
            let key_import_status = output.into_iter()
                .find_map(|o| {
                    if let crate::key::import::Output::Imported(o) = o {
                        Some(o.key_import_status)
                    } else {
                        None
                    }
                })
                .expect("imported key");
            for (fpr, status) in key_import_status.into_iter() {
                sequoia.info(format_args!(
                    "Importing {} into key store: {:?}",
                    fpr, status));
            }
        }

        Ok(())
    }
}
