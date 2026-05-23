//! Routines for looking up shadow CAs.

use std::sync::Arc;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::Result;
use crate::Sequoia;

impl Sequoia {
    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Arc<LazyCert<'static>>> {
        self.certd_or_else()?.trust_root().map(|(cert, _created)| {
            cert
        })
    }
}

