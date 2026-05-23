//! Routines for looking up shadow CAs.

use std::ops::Deref;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::Result;
use crate::Sequoia;

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

impl Sequoia {
    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Ca> {
        let (cert, created) = self.certd_or_else()?.trust_root()?;
        Ok(Ca {
            cert,
            created,
        })
    }

    /// Returns the WKD CA, creating it if necessary.
    pub fn shadow_ca_wkd(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_wkd()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }

    /// Returns the DANE shadow CA, creating it if necessary.
    pub fn shadow_ca_dane(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_dane()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }

    /// Returns the `autocrypt` shadow CA, creating it if necessary.
    pub fn shadow_ca_autocrypt(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_autocrypt()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }

    /// Returns the `proton.me` CA, creating it if necessary.
    pub fn shadow_ca_proton_me(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_proton_me()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }

    /// Returns the `keys.openpgp.org` shadow CA, creating it if necessary.
    pub fn shadow_ca_keys_openpgp_org(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_keys_openpgp_org()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }

    /// Returns the `keys.mailvelope.com` shadow CA, creating it if necessary.
    pub fn shadow_ca_keys_mailvelope_com(&self) -> Result<Ca> {
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca_keys_mailvelope_com()
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
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
        self.certd_or_else()
            .and_then(|certd| {
                certd.shadow_ca(
                    name, create, userid, trust_amount, intermediaries)
            })
            .map(|(cert, created)| {
                Ca {
                    cert,
                    created,
                }
            })
    }
}
