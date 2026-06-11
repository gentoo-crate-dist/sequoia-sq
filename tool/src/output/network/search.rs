use std::error::Error;
use std::path::PathBuf;

use indicatif::ProgressBar;

use sequoia_openpgp as openpgp;
use openpgp::types::RevocationStatus;

use sequoia::network::search::Output;
use sequoia::network::search::output::*;
use sequoia::network::search;
use sequoia::network::search::Source;
use sequoia::network::search::Query;
use sequoia::types::Convert;

use crate::Result;
use crate::Sq;
use crate::common::ui::Safe;
use crate::output::pluralize::Pluralize;

pub struct Stream<'a> {
    sq: &'a Sq,
    silent_errors: bool,
    pb: ProgressBar,
    certs: Vec<CertResult>,
    cert_count: usize,
    request_errors: Vec<(Source, Query, search::Error)>,
    output_path: Option<Option<PathBuf>>,
}

impl<'a> Stream<'a> {
    // If `output_path`'s outer `Option` is `None`, then we're saving
    // to the certificate store.  If the inner `Option` is `None`, we
    // don't have a file name.
    pub fn new(sq: &'a Sq,
               silent_errors: bool,
               output_path: Option<Option<PathBuf>>)
        -> Self
    {
        let pb = if sq.config().verbose() || sq.batch {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(0)
        };

        Self {
            sq,
            silent_errors,
            pb,
            certs: Vec::new(),
            cert_count: 0,
            request_errors: Vec::new(),
            output_path,
        }
    }

    /// Returns the number of certificates that were found.
    pub fn certs(&self) -> usize {
        self.cert_count
    }
}

impl search::Stream for Stream<'_> {
    fn output(&mut self,
              _params: &search::Params,
              output: search::Output)
        -> Result<()>
    {
        make_qprintln!(self.sq.config().quiet());

        let &mut Stream {
            ref sq,
            silent_errors,
            ref mut pb,
            ref certs,
            ref mut cert_count,
            ref mut request_errors,
            ref output_path,
        } = self;

        match output {
            Output::RequestQueued(RequestQueued {
                request,
                ..
            }) => {
                pb.set_length(request as u64 + 1);
            }
            Output::Response(Response {
                source,
                query,
                request: _,
                results,
                ..
            }) => {
                pb.inc(1);

                match results {
                    Ok(results) => {
                        for result in results.into_iter() {
                            if let Err(err) = result {
                                if ! silent_errors || sq.config().verbose() {
                                    pb.suspend(|| {
                                        weprintln!("{}: {}: {}",
                                                   source, query, err);
                                        let mut e: Option<&dyn std::error::Error> = err.source();
                                        while let Some(e_) = e {
                                            eprintln!("  Because: {}", e_);
                                            e = e_.source();
                                        }
                                    });
                                } else {
                                    request_errors.push(
                                        (source.clone(), query.clone(), err));
                                }
                            }
                        }
                    }
                    Err(err) => {
                        if ! silent_errors || sq.config().verbose() {
                            pb.suspend(|| {
                                weprintln!("{}: {}: {}", source, query, err);
                                let mut e: Option<&dyn std::error::Error> = err.source();
                                while let Some(e_) = e {
                                    eprintln!("  Because: {}", e_);
                                    e = e_.source();
                                }
                            });
                        } else {
                            request_errors.push(
                                (source.clone(), query.clone(), err));
                        }
                    }
                }
            }

            Output::CertResult(result) => {
                *cert_count += 1;
                self.certs.push(result);
            }

            Output::EndOfResults => {
                pb.finish_and_clear();

                // If we didn't get any results, then print the
                // request errors.
                if certs.is_empty() {
                    for (source, query, err) in std::mem::replace(request_errors, Vec::new()).into_iter() {
                        weprintln!("{}: {}: {}", source, query, err);
                        let mut e: Option<&dyn std::error::Error> = err.source();
                        while let Some(e_) = e {
                            eprintln!("  Because: {}", e_);
                            e = e_.source();
                        }
                    }

                    return Err(anyhow::anyhow!("No certificates found"));
                }

                let mut certs = certs.iter().map(|result| {
                    for source in &result.sources {
                        match &source.ca {
                            Some(Ok(ca)) => {
                                if ca.created() {
                                    if sq.config().verbose() {
                                        weprintln!(
                                            "Created the local CA {} for certifying \
                                             certificates downloaded from this service.  \
                                             Use `sq pki link authorize --unconstrained --amount N {}` \
                                             to change how much it is trusted.  Or \
                                             `sq pki link retract {}` to disable it.",
                                            if let Ok(uid) = ca.to_cert()
                                                .and_then(|c| sq.best_userid(c, false).userid()
                                                          .map(ToString::to_string))
                                            {
                                                // We really want the self-signed, primary user
                                                // ID.
                                                uid
                                            } else {
                                                "invalid data".to_string()
                                            },
                                            ca.fingerprint(), ca.fingerprint());
                                    } else {
                                        use std::sync::Once;
                                        static MSG: Once = Once::new();
                                        MSG.call_once(|| {
                                            qprintln!("Note: Created a local CA to record \
                                                       provenance information.\n\
                                                       Note: See `sq pki link list --ca` \
                                                       and `sq pki link --help` for more \
                                                       information.");
                                        });
                                    }
                                }
                            }
                            Some(Err(err)) => {
                                let print_err = || {
                                    weprintln!(
                                        "Not recording provenance information: {}",
                                        err);
                                };

                                if sq.config().verbose() {
                                    print_err();
                                } else {
                                    use std::sync::Once;
                                    static MSG: Once = Once::new();
                                    MSG.call_once(print_err);
                                }
                            }
                            None => (),
                        }
                    }

                    (sq.sequoia.best_userid(&result.cert, true),
                     &result.cert,
                     &result.sources)
                }).collect::<Vec<_>>();

                qprintln!("\nFound {} related to the query:\n",
                          certs.len().of("certificate"));

                // Reverse sort, i.e., most authenticated first.
                certs.sort_unstable_by_key(|result| {
                    usize::MAX - result.0.trust_amount()
                });

                for (i, (userid, cert, sources)) in certs.iter().enumerate() {
                    if i > 0 {
                        qprintln!();
                    }

                    // Emit metadata.
                    qprintln!(initial_indent = " - ", "{}",
                              cert.fingerprint());
                    qprintln!(initial_indent = "   - ", "{}", userid.display());
                    qprintln!(initial_indent = "   - ", "created {}",
                              cert.primary_key().key().creation_time().convert());

                    match cert.with_policy(sq.policy(), sq.time()) {
                        Ok(vcert) => {
                            if let Err(e) = vcert.alive() {
                                qprintln!(initial_indent = "   - ", "not live: {}", e);
                            }
                            match vcert.revocation_status() {
                                RevocationStatus::Revoked(sigs) => for s in sigs {
                                    if let Some((reason, message)) =
                                        s.reason_for_revocation()
                                    {
                                        qprintln!(initial_indent = "   - ",
                                                  "revoked: {}, {}", reason,
                                                  Safe(message));
                                    } else {
                                        qprintln!(initial_indent = "   - ",
                                                  "revoked");
                                    }
                                },

                                RevocationStatus::CouldBe(sigs) => for s in sigs {
                                    if let Some((reason, message)) =
                                        s.reason_for_revocation()
                                    {
                                        qprintln!(initial_indent = "   - ",
                                                  "possibly revoked: {}, {}", reason,
                                                  Safe(message));
                                    } else {
                                        qprintln!(initial_indent = "   - ",
                                                  "possibly revoked");
                                    }

                                    match sq.sequoia.lookup()
                                        .keyflags(None)
                                        .or_by_primary(false)
                                        .lookup(s.get_issuers(), true)
                                    {
                                        Ok(issuers) => for issuer in issuers {
                                            qprintln!(initial_indent = "     - ",
                                                      "by {}, {}",
                                                      issuer.fingerprint(),
                                                      sq.sequoia.best_userid(&issuer, true)
                                                      .display());
                                        },
                                        Err(_) =>
                                            qprintln!(initial_indent = "     - ",
                                                      "by {}", s.get_issuers()[0]),
                                    }
                                },

                                RevocationStatus::NotAsFarAsWeKnow => (),
                            }
                        },
                        Err(e) =>
                            qprintln!(initial_indent = "   - ", "not valid: {}", e),
                    }

                    qprintln!(initial_indent = "   - ", "found via: {}",
                              sources.into_iter().map(|s| s.source.to_string())
                              .collect::<Vec<_>>().join(", "));
                }
            }
            Output::Report(Report {
                import_stats,
                ..
            }) => {
                if let Some(output_path) = output_path {
                    if certs.len() > 1 {
                        let mut hint = sq.hint(format_args!(
                            "To extract a particular certificate from {}, \
                             use any of:",
                            output_path.as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "the stream".into())));

                        let path = output_path.as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "...".into());
                        for result in certs.iter() {
                            hint = hint.sq()
                                .arg("cert").arg("export")
                                .arg_value("--keyring", &path)
                                .arg_value("--cert", result.cert.fingerprint())
                                .done();
                        }
                    }
                } else {
                    if ! certs.is_empty() {
                        let o = &mut std::io::stderr();
                        import_stats.print_summary(o, &sq.sequoia)?;
                    }

                    for vcert in certs.iter()
                        .filter_map(|result| {
                            result.cert.with_policy(sq.policy(), sq.time()).ok()
                        })
                        .filter(|vcert| vcert.alive().is_ok())
                    {
                        let mut hint = sq.hint(format_args!(
                            "After checking that the certificate {} really belongs to the \
                             stated owner, you can mark the certificate as authenticated.  \
                             Each stated user ID can be marked individually using:",
                            vcert.fingerprint()));

                        let mut count = 0;
                        for uid in vcert.userids()
                            .filter_map(|uid| std::str::from_utf8(uid.userid().value())
                                        .map(ToString::to_string).ok())
                        {
                            hint = hint
                                .sq().arg("pki").arg("link").arg("add")
                                .arg_value("--cert", vcert.fingerprint())
                                .arg_value("--userid", uid)
                                .done();

                            count += 1;
                        }

                        if count > 1 {
                            hint.hint(format_args!(
                                "Alternatively, all user IDs can be marked as authenticated \
                                 using:"))
                                .sq().arg("pki").arg("link").arg("add")
                                .arg_value("--cert", vcert.fingerprint())
                                .arg("--all")
                                .done();
                        }
                    }
                }
            }

            _ => (),
        }

        Ok(())
    }
}
