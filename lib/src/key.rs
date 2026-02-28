//! Manage secret key material.

use std::sync::Arc;

use anyhow::Context;

use chrono::offset::Utc;
use chrono::DateTime;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::crypto::Signer;
use openpgp::crypto;
use openpgp::serialize::Serialize;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::LazyCert;

use crate::GetKeysOptions;

use crate::Result;
use crate::Sequoia;
use crate::prompt;
use crate::provenance::certify_downloads;

pub mod expire;
pub mod generate;
pub mod import;
pub mod revoke;
pub mod subkey;
pub mod userid;

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

/// A trait for unifying the approach of writing a revocation to an output
trait RevocationOutput {
    /// Returns a minimal version of the certificate including the
    /// revocation certificate.
    fn cert(&self) -> Result<Cert>;

    /// Returns a comment, which will be used as a header in the
    /// ASCII-armor output.
    ///
    /// This should be of the form:
    ///
    /// ```text
    /// Includes a revocation certificate for User ID $userid
    /// ```
    fn comment(&self) -> String;

    /// Returns the revoker's certificate.
    fn revoker(&self) -> &Cert;

    /// Write out the revocation certificate.
    fn write(&self, sequoia: &Sequoia, output: Option<&mut dyn std::io::Write>, binary: bool)
        -> Result<()>
    {
        // Target width of comments.
        const COMMENT_WIDTH: usize = 70;

        if let Some(mut output) = output {
            // First, build a minimal revocation certificate containing
            // the primary key, the revoked component, and the revocation
            // signature.
            let cert = self.cert()?;

            if binary {
                cert.serialize(&mut output)
                    .context("serializing revocation certificate")?;
            } else {
                // Add some more helpful ASCII-armor comments.
                let mut more: Vec<String> = vec![];

                // First, the thing that is being revoked.
                textwrap::wrap(&self.comment(), COMMENT_WIDTH)
                    .into_iter().for_each(|line| more.push(line.into()));

                let revoker = self.revoker();

                let first_party_issuer = revoker.fingerprint() == cert.fingerprint();
                if ! first_party_issuer {
                    // Then if it was issued by a third-party.
                    more.push("".into());
                    more.push(format!("This revocation is issued \
                                       by the cert {} ({}).",
                                      revoker.fingerprint(),
                                      sequoia.best_userid(revoker, false).display()));
                }

                let headers: Vec<(&str, &str)> = more.iter()
                    .map(|value| ("Comment", value.as_str()))
                    .collect();

                let mut writer =
                    Writer::with_headers(&mut output, Kind::PublicKey, headers)?;
                cert.serialize(&mut writer)
                    .context("serializing revocation certificate")?;
                writer.finalize()?;
            }
        } else {
            let cert_store = sequoia.cert_store_or_else()?;
            let cert = self.cert()?;
            cert_store.update(Arc::new(LazyCert::from(cert)))
                .with_context(|| {
                    "Error importing the revocation certificate into cert store"
                })?;
        }

        Ok(())
    }
}

/// Get secret Cert and Signer from an optional secret Cert or a Cert
///
/// Returns a secret Cert and the corresponding Signer, derived from `secret`,
/// if `secret` is `Some`, else attempts to derive it from `cert`.
///
/// ## Errors
///
/// - Returns an `Error` if `secret` is `Some`, but no suitable certification key
/// can be derived from it.
/// - Returns an `Error` if `secret` is `None` and no suitable certification key
/// can be derived from `cert`.
fn get_secret_signer<'a, P>(
    sequoia: &'a Sequoia,
    cert: &'a Cert,
    secret: Option<&'a Cert>,
    prompt: P)
    -> Result<(Cert, Box<dyn Signer + Send + Sync>)>
where
    P: prompt::Prompt
{
    let flags = Some(&[
        GetKeysOptions::AllowRevoked,
        GetKeysOptions::AllowNotAlive,
        GetKeysOptions::NullPolicy,
    ][..]);

    if let Some(secret) = secret {
        match sequoia.get_primary_key(secret, flags, prompt) {
            Ok(key) => Ok((secret.clone(), key)),
            Err(err) => {
                let err = anyhow::Error::from(err);
                if ! sequoia.time_is_now() {
                    return Err(err.context(format!("\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material.  \
Perhaps this is because no certification keys are valid at the time \
you specified ({})",
                        DateTime::<Utc>::from(sequoia.time()))));
                } else {
                    return Err(err.context(format!("\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material")));
                }
            }
        }
    } else {
        match sequoia.get_primary_key(cert, flags, prompt) {
            Ok(key) => Ok((cert.clone(), key)),
            Err(err) => {
                let err = anyhow::Error::from(err);
                if ! sequoia.time_is_now() {
                    return Err(err.context(format!("\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material.  Perhaps this is because no certification keys are valid at
the time you specified ({})",
                        DateTime::<Utc>::from(sequoia.time()))));
                } else {
                    return Err(err.context(format!("\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material")));
                }
            }
        }
    }
}
