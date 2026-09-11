use std::borrow::Borrow;
use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context as _;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::prelude::*;
use openpgp::crypto;
use openpgp::packet::Key;
use openpgp::packet::key;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::NULL_POLICY;
use crate::Result;
use crate::Sequoia;
use crate::cert::CertError;
use crate::cert;
use crate::prompt::PromptFactory;
use crate::prompt::check::CheckRemoteKey;
use crate::prompt;

impl Sequoia {
    /// Gets a signer for the specified key.
    ///
    /// If `ka` includes secret key material, that is preferred.
    /// Otherwise, we look for the key on the key store.
    ///
    /// If the key is locked, we try to unlock it.  If the key isn't
    /// protected by a retry counter, then the password cache is
    /// tried.  Otherwise, or if that fails, the user is prompted to
    /// unlock the key.  The correct password is added to the password
    /// cache.
    pub fn get_signer<'sequoia, 'prompt, P1, R1, R2>(
        &'sequoia self,
        ka: &KeyAmalgamation<P1, R1, R2>,
        prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where P1: key::KeyParts + Clone,
          R1: key::KeyRole + Clone,
    {
        let try_tsk = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            if let Ok(key) = key.parts_as_secret() {
                let key = self.decrypt_key(
                    Some(cert), key.clone(), false, prompt.clone())?;
                let keypair = Box::new(key.into_keypair()
                    .expect("decrypted secret key material"));
                Ok(keypair)
            } else {
                Err(anyhow::anyhow!("No secret key material."))
            }
        };
        let try_keyrings = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            let keyring_tsks = self.keyring_tsks()?;
            if let Some((cert_fpr, key))
                = keyring_tsks.get(&key.fingerprint())
            {
                if cert_fpr == &cert.fingerprint() {
                    return try_tsk(cert, key);
                }
            }

            Err(anyhow::anyhow!("No secret key material."))
        };
        let try_keystore = |ka: &KeyAmalgamation<_, _, R2>|
            -> Result<_>
        {
            let ks = self.key_store_or_else()?;

            let mut ks = ks.lock().unwrap();

            let remote_keys = ks.find_key(ka.key().key_handle())?;

            // XXX: Be a bit smarter.  If there are multiple
            // keys, sort them so that we try the easiest one
            // first (available, no password).

            'key: for mut key in remote_keys.into_iter() {
                if let Protection::Password(hint) = key.locked()? {
                    if self.cached_passwords()
                        .find(|password| {
                            key.unlock(password.clone()).is_ok()
                        })
                        .is_some()
                    {
                        return Ok(Box::new(key));
                    } else {
                        if let Some(hint) = hint {
                            weprintln!("{}", hint);
                        }

                        let mut context
                            = prompt::ContextBuilder::password(
                                prompt::Reason::UnlockKey)
                            .sequoia(self)
                            .cert(Cow::Borrowed(ka.cert()))
                            .key(key.fingerprint())
                            .build();

                        let mut checker = CheckRemoteKey::optional(&mut key);

                        match prompt!(self, prompt, &mut context, &mut checker) {
                            Ok(prompt::Response::Password(p)) => {
                                assert!(checker.unlocked());
                                self.cache_password(p.clone());
                                return Ok(Box::new(key));
                            },
                            Ok(prompt::Response::NoPassword)
                                | Err(prompt::Error::Cancelled(_)) =>
                            {
                                continue 'key;
                            }
                            Err(err) => {
                                return Err(err)
                                    .context("Prompting password");
                            }
                        }
                    }
                } else {
                    // Not locked.
                    return Ok(Box::new(key));
                }
            }

            Err(anyhow::anyhow!("Key not managed by keystore."))
        };

        let key = ka.key().parts_as_public().role_as_unspecified();

        if let Ok(key) = try_tsk(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keyrings(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keystore(ka) {
            Ok(key)
        } else {
            Err(CertError {
                cert: ka.cert().clone(),
                problems: vec![
                    cert::CertProblem::MissingSecretKeyMaterial(
                        cert::problem::MissingSecretKeyMaterial {
                            cert: ka.cert().fingerprint(),
                            key: ka.key().fingerprint(),
                        })
                ]
            })
        }
    }
}

/// Flags for [`Builder::get_key`].
enum KeyType {
    /// Only consider the primary key.
    Primary,
    /// Only consider keys that have at least one of the specified
    /// capabilities.
    KeyFlags(KeyFlags),
}

/// Gets a signer for a certificate.
///
/// These parameters are used by [`signer`](Sequoia::signer).
#[derive(Clone)]
pub struct Params<'sequoia, 'policy> {
    sequoia: &'sequoia Sequoia,

    /// Whether to consider keys that are not alive.
    allow_not_alive: bool,
    /// Whether to consider keys that are revoked.
    allow_revoked: bool,

    /// An alternate policy.
    policy: Option<&'policy dyn Policy>,
}

impl<'sequoia, 'policy> Params<'sequoia, 'policy> {
    /// Returns the `Sequoia` instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        &self.sequoia
    }

    /// Returns whether to consider keys that are not alive.
    ///
    /// By default keys that are expired or created in the future are
    /// ignored.
    pub fn allow_not_alive(&self) -> bool {
        self.allow_not_alive
    }

    /// Returns whether to consider revoked certificates.
    ///
    /// Revoked certificates are ignored by default.
    pub fn allow_revoked(&self) -> bool {
        self.allow_revoked
    }

    /// Returns the alternate policy, if any.
    ///
    /// If set, the alternate policy is used instead of the configured
    /// policy.
    pub fn policy(&self) -> Option<&'policy dyn Policy> {
        self.policy.clone()
    }
}

/// Owned parameters.
struct ParamsOnce<'prompt> {
    prompt: Option<Arc<dyn prompt::PromptFactory<'prompt> + 'prompt>>,
}

/// Gets a signer for a certificate.
///
/// A builder providing control over how to get the signer.
pub struct Builder<'sequoia, 'policy, 'prompt> {
    params: Params<'sequoia, 'policy>,
    params_once: ParamsOnce<'prompt>,
}

impl<'sequoia, 'policy, 'prompt> Builder<'sequoia, 'policy, 'prompt>
{
    pub(crate) fn new(sequoia: &'sequoia Sequoia) -> Self {
        Builder {
            params: Params {
                sequoia,
                allow_not_alive: false,
                allow_revoked: false,
                policy: None,
            },
            params_once: ParamsOnce {
                prompt: None,
            },
        }
    }

    prompt_builder_impl!('policy; );

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia, 'policy> {
        &self.params
    }

    /// Sets whether to consider keys that are not alive.
    ///
    /// By default keys that are expired or created in the future are
    /// ignored.
    pub fn allow_not_alive(mut self, allow_not_alive: bool) -> Self {
        self.params.allow_not_alive = allow_not_alive;
        self
    }

    /// Sets whether to consider revoked certificates.
    ///
    /// Revoked certificates are ignored by default.
    pub fn allow_revoked(mut self, allow_revoked: bool) -> Self {
        self.params.allow_revoked = allow_revoked;
        self
    }

    /// Sets an alternate policy.
    ///
    /// If set, the alternate policy is used instead of the configured
    /// policy.
    pub fn policy<'p, P>(self, policy: P)
        -> Builder<'sequoia, 'p, 'prompt>
    where
        P: Into<Option<&'p dyn Policy>>
    {
        Builder {
            params: Params {
                policy: policy.into(),
                ..self.params
            },
            ..self
        }
    }

    /// Sets the alternate policy to the null policy.
    ///
    /// The null policy accepts all algorithms, even those that are
    /// known to be broken.
    ///
    /// See [`Builder::policy`].
    pub fn null_policy(self) -> Builder<'sequoia, 'static, 'prompt> {
        self.policy(Some(NULL_POLICY as &dyn Policy))
    }

    /// Returns a signer.
    ///
    /// If the certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    fn get_key<C>(&self, cert: &C, key_type: KeyType)
        -> Result<(Cert, Box<dyn crypto::Signer + Send + Sync>),
                  CertError>
    where C: Borrow<Cert>,
    {
        let &Params {
            sequoia,
            allow_not_alive,
            allow_revoked,
            policy,
        } = &self.params;
        let ParamsOnce {
            prompt,
        } = &self.params_once;

        let policy: &dyn Policy = if let Some(policy) = policy {
            policy
        } else {
            sequoia.policy() as _
        };

        let cert = cert.borrow();

        if ! allow_revoked {
            let revocation_status
                = cert.revocation_status(policy, sequoia.time());
            if let RevocationStatus::Revoked(sigs) = revocation_status {
                return Err(CertError {
                    cert: cert.clone(),
                    problems: vec![
                        cert::CertProblem::CertRevoked(
                            cert::problem::CertRevoked {
                                cert: cert.fingerprint(),
                                revocations: sigs.into_iter()
                                    .cloned()
                                    .collect(),
                            }),
                    ],
                });
            }
        }

        let vc = match cert.with_policy(policy, sequoia.time()) {
            Ok(vc) => vc,
            Err(error) => {
                return Err(CertError {
                    cert: cert.clone(),
                    problems: vec![
                        cert::CertProblem::CertInvalid(
                            cert::problem::CertInvalid {
                                cert: cert.fingerprint(),
                                error: error.into()
                            })
                    ]
                });
            }
        };

        let keyiter = match key_type {
            KeyType::Primary => {
                Box::new(
                    std::iter::once(
                        vc.keys()
                            .next()
                            .expect("a valid cert has a primary key")))
                    as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
            },
            KeyType::KeyFlags(ref flags) => {
                Box::new(vc.keys().key_flags(flags.clone()))
                    as Box<dyn Iterator<Item=_>>
            },
        };

        let mut problems = Vec::new();

        let mut key_count = 0;
        for ka in keyiter {
            key_count += 1;

            let problem_count = problems.len();

            if ! allow_not_alive {
                if let Err(err) = ka.alive() {
                    problems.push(cert::CertProblem::NotLive(
                        cert::problem::NotLive {
                            cert: cert.fingerprint(),
                            key: ka.key().fingerprint(),
                            creation_time: ka.key().creation_time(),
                            expiration_time: ka.key_expiration_time(),
                            reference_time: sequoia.time(),
                            error: err.into(),
                        }));
                }
            }

            if ! allow_revoked {
                if let RevocationStatus::Revoked(sigs)
                    = ka.revocation_status()
                {
                    problems.push(cert::CertProblem::KeyRevoked(
                        cert::problem::KeyRevoked {
                            cert: cert.fingerprint(),
                            key: ka.key().fingerprint(),
                            revocations: sigs.into_iter()
                                .map(|sig| sig.clone())
                                .collect(),
                        }));
                }
            }

            if ! ka.key().pk_algo().is_supported() {
                problems.push(cert::CertProblem::UnsupportedAlgorithm(
                    cert::problem::UnsupportedAlgorithm {
                        cert: cert.fingerprint(),
                        key: ka.key().fingerprint(),
                        algo: ka.key().pk_algo(),
                    }));
            }

            if problems.len() > problem_count {
                // This key has at least one problem.
                continue;
            }

            match sequoia.get_signer(ka.amalgamation(), prompt.clone()) {
                Ok(key) => {
                    return Ok((cert.clone(), key));
                }
                Err(err) => {
                    problems.extend(err.problems);
                    continue;
                }
            }
        }

        // We didn't get a key.  Return an error.
        if problems.is_empty() {
            let key_flags = match key_type {
                KeyType::Primary =>
                    unreachable!("All certificates have a primary key"),
                KeyType::KeyFlags(flags) => flags.clone(),
            };

            return Err(CertError {
                cert: cert.clone(),
                problems: vec![
                    cert::CertProblem::NoUsableKeys(
                        cert::problem::NoUsableKeys {
                            cert: cert.fingerprint(),
                            capabilities: key_flags,
                            unusable: key_count,
                        })
                ]
            });
        } else {
            return Err(CertError {
                cert: cert.clone(),
                problems,
            });
        }
    }

    /// Returns a signer for each certificate's primary key.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_keys<C>(self, certs: &[C])
        -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
    {
        certs.into_iter()
            .map(|cert| {
                self.get_key(cert, KeyType::Primary)
                    .map(|(_cert, signer)| signer)
            })
            .collect::<Result<_, _>>()
    }

    /// Returns a signer for the certificate's primary key.
    ///
    /// If the certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_key<C>(self, cert: C,)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
    {
        self.get_key(&cert, KeyType::Primary)
            .map(|(_cert, signer)| signer)
    }

    /// Returns a signer for a signing-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_keys<C>(self, certs: &[C])
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                  CertError>
    where
        C: Borrow<Cert>,
    {
        certs.into_iter()
            .map(|cert| {
                self.get_key(
                    cert,
                    KeyType::KeyFlags(KeyFlags::signing()))
            })
            .collect::<Result<_, _>>()
    }

    /// Returns a signer for a signing-capable key for the
    /// certificate.
    ///
    /// If a certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_key<C>(self, cert: C)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: Borrow<Cert>,
    {
        self.get_key(
            &cert,
            KeyType::KeyFlags(KeyFlags::signing()))
            .map(|(_cert, signer)| signer)
    }

    /// Returns a signer for a certification-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_keys<C>(self, certs: &[C])
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                  CertError>
    where
        C: std::borrow::Borrow<Cert>,
    {
        certs.into_iter()
            .map(|cert| {
                self.get_key(
                    cert,
                    KeyType::KeyFlags(KeyFlags::certification()))
            })
            .collect::<Result<_, _>>()
    }

    /// Returns a signer for a certification-capable key for the
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the specified key type (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by [`Builder::allow_not_alive`])
    /// - the key is not revoked (unless allowed by
    ///   [`Builder::allow_revoked`])
    /// - the key's algorithm is supported by the underlying
    ///   cryptographic backend.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_key<C>(self, cert: C)
        -> Result<Box<dyn crypto::Signer + Send + Sync>, CertError>
    where
        C: std::borrow::Borrow<Cert>,
    {
        self.get_key(
            &cert,
            KeyType::KeyFlags(KeyFlags::certification()))
            .map(|(_cert, signer)| signer)
    }
}

