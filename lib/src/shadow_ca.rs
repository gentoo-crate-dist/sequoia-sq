//! Routines for looking up shadow CAs.

use std::ops::Deref;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::Result;
use crate::Sequoia;

#[derive(Debug, Clone)]
pub struct Ca {
    cert: Arc<LazyCert<'static>>,
    created: bool,
}

impl Deref for Ca {
    type Target = Arc<LazyCert<'static>>;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

impl Ca {
    /// Returns the certificate.
    pub fn cert(&self) -> Arc<LazyCert<'static>> {
        Arc::clone(&self.cert)
    }

    /// Returns the certificate.
    pub fn into_cert(self) -> Arc<LazyCert<'static>> {
        self.cert
    }

    /// Returns whether the certificate was created when it was looked
    /// up.
    pub fn created(&self) -> bool {
        self.created
    }
}

const NO_CERTD_ERR: &str =
    "A local trust root and other special certificates are \
     only available when using an OpenPGP certificate \
     directory";

impl Sequoia {
    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.trust_root()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the "generated on $host" shadow CA, creating it
    /// if necessary.
    pub fn shadow_ca_generated_on(&self) -> Result<Ca> {
        let hostname =
            gethostname::gethostname().to_string_lossy().to_string();

        self.shadow_ca(
            &format!("generated_on_{}", hostname),
            true,
            format!("Generated on {}", hostname),
            1,
            &[])
    }

    /// Returns the WKD CA, creating it if necessary.
    pub fn shadow_ca_wkd(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_wkd()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the DANE shadow CA, creating it if necessary.
    pub fn shadow_ca_dane(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_dane()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the `autocrypt` shadow CA, creating it if necessary.
    pub fn shadow_ca_autocrypt(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_autocrypt()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the `proton.me` CA, creating it if necessary.
    pub fn shadow_ca_proton_me(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_proton_me()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the `keys.openpgp.org` shadow CA, creating it if necessary.
    pub fn shadow_ca_keys_openpgp_org(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_keys_openpgp_org()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the `keys.mailvelope.com` shadow CA, creating it if necessary.
    pub fn shadow_ca_keys_mailvelope_com(&self) -> Result<Ca> {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca_keys_mailvelope_com()?;

        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns a shadow CA for the specified key server, if the key
    /// server is known to be a verifying key server.
    ///
    /// If the shadow CA does not exist, then this creates it.
    pub fn shadow_ca_keyserver(&self, uri: &str)
        -> Result<Option<Ca>>
    {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        if let Some((cert, created)) = certd.shadow_ca_keyserver(uri)? {
            Ok(Some(Ca {
                cert,
                created,
            }))
        } else {
            // This key server is not known to be a verifying key
            // server.
            Ok(None)
        }
    }

    /// Returns a shadow CA for the URL.
    ///
    /// This only succeeds for URLs using HTTPS as the protocol.  The
    /// URL is normalized, any user name, password, or fragment is
    /// stripped.
    ///
    /// If the shadow CA does not exist, then this creates it.
    pub fn shadow_ca_for_url(&self, uri: &str)
        -> Result<Option<Ca>>
    {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        if let Some((cert, created)) = certd.shadow_ca_keyserver(uri)? {
            Ok(Some(Ca {
                cert,
                created,
            }))
        } else {
            // This key server is not known to be a verifying key
            // server.
            Ok(None)
        }
    }

    /// Returns the specified shadow CA, creating it if necessary.
    pub fn shadow_ca<U>(&self,
                        name: &str,
                        create: bool,
                        userid: U,
                        trust_amount: u8,
                        intermediaries: &[(&str, UserID, u8)])
        -> Result<Ca>
    where
        U: Into<UserID>,
    {
        let cert_store = self.cert_store_or_else()?;
        let certd = cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))?;

        let (cert, created) = certd.shadow_ca(
                    name, create, userid, trust_amount, intermediaries)?;

        Ok(Ca {
            cert,
            created,
        })
    }
}
