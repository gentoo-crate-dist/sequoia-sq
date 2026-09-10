use std::path::Path;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::packet::UserID;

use sequoia::pki::certify;
use sequoia::types::Convert;
use sequoia::types::Safe;

use certify::output::*;
use certify::error::*;
use certify::Output;

use crate::Result;
use crate::Sq;
use crate::common::ui::emit_cert_userid;

pub struct Stream<'sq, 'a> {
    sq: &'sq Sq,

    // The certificate that is being certified.
    cert: &'a Cert,

    // The user IDs that are being certified.
    userids: &'a [UserID],

    // Whether the user supplied the user IDs or whether all
    // self-signed user IDs were used.
    user_supplied_userids: bool,

    // The file the output is being exported to.
    //
    // If `None`, then the certifications are stored on the
    // certificate store.
    output_file: Option<&'a Path>,

    // Where to send the output.
    o: &'a mut dyn std::io::Write,
}

impl<'sq, 'a> Stream<'sq, 'a> {
    pub fn new(sq: &'sq Sq,
               cert: &'a Cert,
               userids: &'a [UserID],
               user_supplied_userids: bool,
               output_file: Option<&'a Path>,
               terminal_output: &'a mut dyn std::io::Write)
        -> Self
    {
        Self {
            sq,
            cert,
            userids,
            user_supplied_userids,
            output_file,
            o: terminal_output,
        }
    }
}

impl certify::Stream<'_> for Stream<'_, '_> {
    fn output(&mut self,
              params: &certify::Params,
              output: certify::Output)
        -> Result<()>
    {
        let unless_quiet = if self.sq.quiet() {
            &mut std::io::sink() as &mut dyn std::io::Write
        } else {
            &mut self.o
        };

        match output {
            Output::ArgumentError(err) => {
                // Argument errors are returned to the caller and will
                // be printed when `sq` exits.  There's no needd to
                // show them again.

                match err {
                    ArgumentError::CertifierSameAsCertificate(
                        CertifierSameAsCertificate {
                            cert,
                            ..
                        }) =>
                    {
                        self.sq.hint(
                            format_args!("\
                                The certificate to certify is the same as the \
                                certificate being certified. If you are trying \
                                to add a user ID, try:"))
                            .sq()
                            .arg("key").arg("userid").arg("add")
                            .arg_value("--cert", cert.fingerprint())
                            .arg_value("--userid",
                                       String::from_utf8_lossy(
                                           self.userids.get(0)
                                               .map(|u| u.value())
                                               .unwrap_or(b"<userid>")))
                            .done();
                    }
                    ArgumentError::NoRegularExpressions(
                        NoRegularExpressions {
                            ..
                        }) =>
                    {
                    }
                    _err => {
                    }
                }
            }

            Output::OperationalError(_err) => {
                // Operational errors are returned to the caller and
                // will be printed when `sq` exits.  There's no needd
                // to show them again.
            }

            Output::Certified(Certified {
                cert,
                userid,
                certifications,
                previous_certification,
                diff,
                ..
            }) => {
                emit_cert_userid(unless_quiet, &cert, &userid)?;

                if let Some(p) = previous_certification.as_ref() {
                    let was_retracted = previous_certification
                        .as_ref()
                        .map(|c| {
                            matches!(c.trust_signature(), Some((_depth, 0)))
                        })
                        .unwrap_or(false);

                    if was_retracted {
                        wwriteln!(stream = unless_quiet,
                                  initial_indent = "   - ",
                                  "a prior certification was retracted at {}",
                                  p.signature_creation_time()
                                  // To get this far, the signature
                                  // should have a creation time, but
                                  // just in case it doesn't we make
                                  // something up.
                                  .unwrap_or(std::time::UNIX_EPOCH)
                                  .convert());
                    } else {
                        wwriteln!(stream = unless_quiet,
                                  initial_indent = "   - ",
                                  "was previously certified at {}",
                                  p.signature_creation_time()
                                  // To get this far, the signature
                                  // should have a creation time, but
                                  // just in case it doesn't we make
                                  // something up.
                                  .unwrap_or(std::time::UNIX_EPOCH)
                                  .convert());
                    }

                    if let Some(diff) = diff {
                        if diff.unchanged() {
                            // The caller supplied recreate.
                            wwriteln!(stream = unless_quiet,
                                      initial_indent = "   - ",
                                      "certification parameters are unchanged; \
                                       there is nothing to do");
                        } else {
                            diff.dump(unless_quiet);
                            wwriteln!(stream = unless_quiet,
                                      initial_indent = "   - ",
                                      "certification parameters changed, \
                                       creating a new certification");
                        }
                    }
                }

                let retracted = certifications
                    .get(0)
                    .map(|c| {
                        matches!(c.trust_signature(), Some((_depth, 0)))
                    })
                    .unwrap_or(false);
                if retracted {
                    wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                              "certification retracted");
                } else {
                    wwriteln!(stream = unless_quiet, initial_indent = "   - ",
                              "certification created");
                }
                wwriteln!(stream = unless_quiet);
            }

            Output::CertificationSkipped(CertificationSkipped {
                cert,
                userid,
                reason,
                ..
            }) => {
                emit_cert_userid(unless_quiet, &cert, &userid)?;
                match reason {
                    CertificationSkippedReason::NothingToRetract(
                        NothingToRetract {
                            ..
                        }) =>
                    {
                        wwriteln!(stream = unless_quiet,
                                  initial_indent = "   - ",
                                  "this binding was never certified; \
                                   there is nothing to retract");

                        if self.user_supplied_userids {
                            return Err(reason.into());
                        }
                    }
                    CertificationSkippedReason::PreviouslyCertified(
                        PreviouslyCertified {
                            certification,
                            ..
                        }) =>
                    {
                        let retracted
                            = matches!(certification.trust_signature(),
                                       Some((_depth, 0)));

                        if let Some(t) = certification.signature_creation_time() {
                            if retracted {
                                wwriteln!(
                                    stream = unless_quiet,
                                    initial_indent = "   - ",
                                    "a prior certification was retracted at {}",
                                    t.convert());
                            } else {
                                wwriteln!(
                                    stream = unless_quiet,
                                    initial_indent = "   - ",
                                    "was previously certified at {}",
                                    t.convert());
                            }
                        }
                        wwriteln!(stream = unless_quiet,
                                  initial_indent = "   - ",
                                  "certification parameters are unchanged; \
                                   there is nothing to do");
                    }
                    _ => {
                        wwriteln!(stream = unless_quiet,
                                  initial_indent = "   - ",
                                  "certification skipped because: {}", reason);
                    }
                }
            }

            Output::CertificationFailed(CertificationFailed {
                cert,
                userid,
                error,
                ..
            }) => {
                match error {
                    CertificationError::Revoked(
                        Revoked {
                            fingerprint: _,
                            userid: _,
                            revocation: _,
                            ..
                        }) =>
                    {
                        // It's revoked.
                        if self.user_supplied_userids {
                            // It was explicitly mentioned.  Return an
                            // error.
                            return Err(anyhow::anyhow!(
                                "Can't certify {} for {}, it's revoked",
                                Safe(&userid), cert.fingerprint()));
                        }
                    }
                    err => {
                        return Err(err.into());
                    }
                }
            }
            Output::Report(Report {
                certifications,
                ..
            }) => {
                if ! certifications.is_empty() && params.exportable() {
                    if let Some(output_file) = self.output_file.as_ref() {
                        self.sq.hint(format_args!(
                            "Updated certificate written to {}.  \
                             To make the update effective, it has to be \
                             published so that others can find it, for \
                             example using:",
                            output_file.display()))
                            .sq().arg("network").arg("keyserver").arg("publish")
                            .arg_value("--cert-file", output_file.display())
                            .done();
                    } else {
                        self.sq.hint(format_args!(
                            "Imported updated cert into the cert store.  \
                             To make the update effective, it has to be \
                             published so that others can find it, for \
                             example using:"))
                                .sq().arg("network").arg("keyserver").arg("publish")
                                .arg_value("--cert", self.cert.fingerprint())
                                .done();
                    }
                }
            }

            _ => {
            }
        }
        Ok(())
    }
}
