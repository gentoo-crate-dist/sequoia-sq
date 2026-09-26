use sequoia::cert_store::Store;

use sequoia::cert::list::QueryKind;
use sequoia::cert::list::required_trust_amount;
use sequoia::cert::list;

use crate::Result;
use crate::Sq;
use crate::cli::types::Query;
use crate::common::pki::output::ConciseHumanReadableOutputNetwork;
use crate::common::pki::output::OutputType;

/// The context in which authenticate is called.
///
/// This controls the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListContext {
    PKI,
    Download,
}

pub struct Stream<'sq, 'a> {
    sq: &'sq Sq,
    queries: Vec<Query>,
    context: ListContext,
    network: ConciseHumanReadableOutputNetwork<'sq, 'a>,
}

impl<'sq, 'a> Stream<'sq, 'a> {
    pub fn new(sq: &'sq Sq,
               queries: Vec<Query>,
               params: &list::Params,
               context: ListContext,
               show_paths: bool,
               output: &'a mut dyn std::io::Write)
        -> Self
    {
        let required_amount = required_trust_amount(
            params.trust_amount(), params.certification_network());

        let network = ConciseHumanReadableOutputNetwork::new(
            output, &sq, required_amount, show_paths);

        Self {
            sq,
            queries,
            context,
            network,
        }
    }
}

impl sequoia::cert::list::Stream<'_> for Stream<'_, '_> {
    fn output(&mut self,
              params: &list::Params,
              output: list::Output)
        -> Result<()>
    {
        use list::Output::*;

        make_qprintln!(params.sequoia().config().quiet());

        match output {
            StartOfBindings => (),
            Binding(list::output::Binding {
                fingerprint,
                userid,
                paths,
                aggregate_trust_amount,
                ..
            }) => {
                self.network.add_cert(&fingerprint)?;
                if let Some(userid) = userid {
                    self.network.add_paths(
                        paths.into_iter().collect(),
                        &fingerprint, &userid,
                        aggregate_trust_amount)?;
                }
            }
            EndOfBindings => self.network.finalize()?,

            Report(list::output::Report {
                missing_trust_roots,
                query_lints,
                matching_bindings,
                unsatisfied_queries,
                authenticated_bindings,
                unusable_bindings,
                unauthenticated_bindings: _,
                ..
            }) if self.context == ListContext::PKI => {
                if let Some((roots, missing)) = missing_trust_roots {
                    if ! params.gossip() {
                        let missing_count = missing.len();
                        for (fpr, err) in missing.into_iter() {
                            qprintln!("Looking up trust root ({}): {}.",
                                      fpr, err);
                        }
                        if roots.iter().count() == missing_count {
                            qprintln!("Warning: No trust roots found.");
                        }
                    }
                }

                for q in unsatisfied_queries.iter() {
                    // We do a linear search, which makes this is
                    // quadratic.  Use a generic message if we'd do
                    // too much work.
                    let arg: &str = if self.queries.len() * unsatisfied_queries.len() < 4096 {
                        self.queries.iter().find(|q2| {
                            q2.inner.identical(&q)
                        })
                    } else {
                        None
                    }
                    .and_then(|q| {
                        q.argument.as_deref()
                    })
                    .unwrap_or("the query");

                    if params.gossip() {
                        qprintln!("No valid bindings match {}.", arg)
                    } else {
                        qprintln!("No bindings matching {} could be \
                                   authenticated.", arg);
                    }
                }

                for (_query, lint) in query_lints.into_iter() {
                    qprintln!(initial_indent = "  - ",
                              "Warning: {}",
                              crate::one_line_error_chain(lint));
                }

                if matching_bindings == 0 {
                    // There are no matching bindings.

                    qprintln!("No valid bindings match the query.");

                    if params.queries().count() == 1 {
                        if let QueryKind::Pattern(pattern)
                            = &unsatisfied_queries[0].kind
                        {
                            // Tell the user about `sq network fetch`.
                            self.sq.hint(format_args!(
                                "Try searching public directories:"))
                                .sq().arg("network").arg("search")
                                .arg(pattern)
                                .done();
                        }
                    } else if params.sequoia().cert_store_or_else()?
                        .certs().next().is_none()
                    {
                        qprintln!("Warning: The certificate store does not \
                                   contain any certificates.");

                        let return_all = params.queries()
                            .any(|q| matches!(q.kind, QueryKind::All));
                        if return_all {
                            self.sq.hint(format_args!(
                                "Consider creating a key for yourself:"))
                                .sq().arg("key").arg("generate")
                                .arg_value("--name", "your-name")
                                .arg_value("--email", "your-email-address")
                                .arg("--own-key")
                                .done();

                            self.sq.hint(format_args!(
                                "Consider importing other peoples' \
                                 certificates:"))
                                .sq().arg("cert").arg("import")
                                .arg("a-cert-file.pgp")
                                .done();

                            self.sq.hint(format_args!(
                                "Try searching public directories for other \
                                 peoples' certificates:"))
                                        .sq().arg("network").arg("search")
                                        .arg("some-mail-address")
                                        .done();
                        }
                    }
                } else if params.gossip() {
                    // We are in gossip mode.  Mention `sq pki link`
                    // as a way to mark bindings as authenticated.
                    if authenticated_bindings > 0 {
                        qprintln!("After checking that a user ID really \
                                   belongs to a certificate, use \
                                   `sq pki link add` to mark the binding as \
                                   authenticated, or use \
                                   `sq network search FINGERPRINT|EMAIL` to \
                                   look for new certifications.");
                    } else {
                        qprintln!("No bindings are valid.");
                    }
                }

                if matching_bindings - authenticated_bindings > 0 {
                    // Some of the matching bindings were not shown.  Tell the
                    // user about the `--gossip` option.
                    assert!(matching_bindings > 0);
                    let bindings_not_authenticated
                        = matching_bindings - authenticated_bindings - unusable_bindings;

                    if matching_bindings == 1 {
                        qprintln!("1 binding found.");
                    } else {
                        qprintln!("{} bindings found.", matching_bindings);
                    }

                    if unusable_bindings == 1 {
                        qprintln!("Skipped 1 binding, which is unusable.");
                    } else if unusable_bindings > 1 {
                        qprintln!("Skipped {} bindings, which are unusable.",
                                  unusable_bindings);
                    }

                    if bindings_not_authenticated == 1 {
                        qprintln!("Skipped 1 binding, which could not be authenticated.");
                        qprintln!("Pass `--gossip` to see the unauthenticated binding.");
                    } else if bindings_not_authenticated > 1 {
                        qprintln!("Skipped {} bindings, which could not be authenticated.",
                                  bindings_not_authenticated);
                        qprintln!("Pass `--gossip` to see the unauthenticated bindings.");
                    }
                }


                let unsatisfied_count = unsatisfied_queries.len();
                if unsatisfied_count == 1 {
                    if params.gossip() {
                        if params.queries().count() == 1 {
                            Err(anyhow::anyhow!("No bindings match the query."))?;
                        } else {
                            Err(anyhow::anyhow!("No bindings match one of the queries."))?;
                        }
                    } else {
                        if params.queries().count() == 1 {
                            Err(anyhow::anyhow!(
                                "No bindings matching the query could be authenticated."))?;
                        } else {
                            Err(anyhow::anyhow!(
                                "No bindings matching one of the queries could be authenticated."))?;
                        }
                    }
                } else if unsatisfied_count > 1 {
                    if params.gossip() {
                        Err(anyhow::anyhow!("No bindings match {} of the queries.",
                                            unsatisfied_count))?;
                    } else {
                        Err(anyhow::anyhow!(
                            "No bindings matching {} of the queries could be authenticated.",
                            unsatisfied_count))?;
                    }
                }
            }

            // Unknown.  Ignore.
            _ => (),
        }

        Ok(())
    }
}

