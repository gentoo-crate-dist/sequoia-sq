//! Routines for looking up shadow CAs.

use std::ops::Deref;
use std::sync::Arc;

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
}

