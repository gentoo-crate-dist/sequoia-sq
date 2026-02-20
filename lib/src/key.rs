//! Manage secret key material.
use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::crypto;

use crate::Result;
use crate::Sequoia;
use crate::prompt;
use crate::provenance::certify_downloads;

pub mod import;
pub mod generate;

/// The password that will be used to protect the secret key material.
#[derive(Debug, Clone)]
pub enum PasswordPolicy {
    /// Don't use a password.
    None,
    /// Use the specified password.
    Password(crypto::Password),
    /// Prompt for a password.
    Prompt,
}

/// Certifies the newly created key with a per-host shadow CA that
/// marks the origin.
///
/// This also has the benefit that newly created keys also show up in
/// the cert listing.
///
/// XXX Transitional: make this private.
pub fn certify_generated<P>(sequoia: &Sequoia, cert: &Cert, prompt: P)
    -> Result<Cert>
where
    P: prompt::Prompt,
{
    let hostname =
        gethostname::gethostname().to_string_lossy().to_string();
    let certd = sequoia.certd_or_else()?;

    let (ca, _created) = certd.shadow_ca(
        &format!("generated_on_{}", hostname),
        true,
        format!("Generated on {}", hostname),
        1,
        &[])?;

    // let prompt = crate::common::password::Prompt::new(sequoia, true);

    Ok(certify_downloads(sequoia, false, ca, vec![cert.clone()], None,
                         prompt)
       .into_iter().next().expect("exactly one"))
}
