use std::borrow::Cow;
use std::error::Error as _;
use std::path::Path;
use std::path::PathBuf;

use sequoia::key::import::error;
use sequoia::key::import;
use sequoia::types::PreferredUserID;
use sequoia::types::import_stats::ImportStatus;

use import::output::*;
use import::Output;

use sequoia::types::import_stats::ImportStats;

use crate::Result;
use crate::Sq;

pub struct Stream<'a> {
    sq: &'a Sq,
    source: Option<PathBuf>,
    output: Box<dyn std::io::Write + Send + Sync + 'a>,
    print_stats: bool,
    pub stats: Option<ImportStats>,
    saw_error: bool,
    pub import_error: Option<import::Error>,
}

impl<'a> Stream<'a> {
    /// `source` is the filename of the source.  This is only used for
    /// display purposes.
    ///
    /// `output` is where to write the human readable output.  This is
    /// normally `stdout` or `stderr`.
    ///
    /// `print_stats` controls whether the statistics are shown at the
    /// end.
    pub fn new(sq: &'a Sq,
               source: Option<&Path>,
               output: impl std::io::Write + Send + Sync + 'a,
               print_stats: bool)
        -> Self
    {
        Self {
            sq,
            source: source.map(|s| s.to_path_buf()),
            output: Box::new(output),
            print_stats,
            stats: None,
            saw_error: false,
            import_error: None,
        }
    }
}

impl import::Stream for Stream<'_> {
    fn output(&mut self,
              _params: &import::Params,
              output: import::Output)
        -> Result<()>
    {
        match output {
            Output::OperationalError(
                error @ error::OperationalError::ParseError(
                    error::ParseError {
                        error: _,
                        ..
                    })) =>
            {
                let input = if let Some(source) = self.source.as_ref() {
                    Cow::Owned(source.display().to_string())
                } else {
                    Cow::Borrowed("input")
                };

                return Err(anyhow::Error::from(error)
                           .context(format!("Reading {}", input)));
            }
            Output::SystemError(_)
                | Output::ArgumentError(_)
                | Output::OperationalError(_) =>
            {
                self.saw_error = true;
            }

            Output::Imported(
                Imported {
                    cert,
                    merged,
                    key_import_status,
                    cert_import_status,
                    ..
                }) =>
            {
                let fp = cert.fingerprint();
                let id = format!("{} {}",
                                 cert.fingerprint(),
                                 self.sq.best_userid(&cert, true).display());

                let key_import_status_max = key_import_status
                    .iter()
                    .map(|(_fpr, status)| status.clone())
                    .max()
                    .unwrap_or(ImportStatus::Unchanged);

                wwriteln!(&mut self.output,
                          "Imported {} from {}: {}",
                          id,
                          if let Some(filename) = self.source.as_ref() {
                              Cow::Owned(filename.display().to_string())
                          } else {
                              Cow::Borrowed("stdin")
                          },
                          if key_import_status_max == cert_import_status {
                              key_import_status_max.to_string()
                          } else {
                              format!("key {}, cert {}",
                                      key_import_status_max, cert_import_status)
                          });

                for (fpr, status) in key_import_status.iter() {
                    self.sq.info(format_args!(
                        "Importing {} into key store: {:?}",
                        fpr, status));
                }

                if let Err(err) = merged {
                    wwriteln!(&mut self.output,
                              "Warning: Imported the key into the key store, \
                               but failed to import the certificate into the \
                               certificate store: {}",
                              err);
                }

                self.sq.hint(format_args!("If this is your key, you should  \
                                           mark it as a fully trusted \
                                           introducer:"))
                    .sq().arg("pki").arg("link").arg("authorize")
                    .arg("--unconstrained")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();

                self.sq.hint(format_args!("Otherwise, consider marking it as \
                                           authenticated:"))
                    .sq().arg("pki").arg("link").arg("add")
                    .arg_value("--cert", &fp)
                    .arg("--all")
                    .done();
            }

            Output::ImportingFailed(
                ImportingFailed {
                    error,
                    ..
                }) =>
            {
                if self.import_error.is_none() {
                    self.import_error = Some(import::Error::OperationalError(
                        import::error::OperationalError::ImportError(error.clone())));
                }

                let input = if let Some(source) = self.source.as_ref() {
                    Cow::Owned(source.display().to_string())
                } else {
                    Cow::Borrowed("input")
                };

                match error {
                    error::ImportError::BrokenCert(
                        error::BrokenCert {
                            ref cert,
                            // error,
                            ..
                        }) =>
                    {
                        let id = cert
                            .as_ref()
                            .map(|cert| {
                                let userid = cert
                                    .clone()
                                    .try_into()
                                    .map(|cert| {
                                        self.sq.best_userid(&cert, true)
                                    })
                                    .unwrap_or_else(|_| {
                                        PreferredUserID::unknown()
                                    });

                                Cow::Owned(format!(
                                    "{} {}",
                                    cert.fingerprint(), userid.display()))
                            })
                            .unwrap_or(Cow::Borrowed("key"));

                        let mut chain = Vec::new();
                        chain.push(error.to_string());
                        let mut source = error.source();
                        while let Some(s) = source {
                            chain.push(s.to_string());
                            source = s.source();
                        }

                        wwriteln!(&mut self.output,
                                  "Error importing {} from {}:{}{}",
                                  id,
                                  input,
                                  if chain.len() == 1 {
                                      " "
                                  } else {
                                      ""
                                  },
                                  if chain.len() == 1 {
                                      Cow::Owned(error.to_string())
                                  } else {
                                      Cow::Borrowed("")
                                  });
                        if chain.len() > 1 {
                            for c in chain {
                                wwriteln!(stream = &mut self.output,
                                          indent = "    ",
                                          "{}", c);
                            }
                        }
                    }
                    error::ImportError::MissingSecretKeyMaterial(
                        error::MissingSecretKeyMaterial {
                            ref cert,
                            ..
                        }) =>
                    {
                        let userid = self.sq.best_userid(cert, true);
                        let id = format!("{} {}",
                                         cert.fingerprint(), userid.display());

                        let mut chain = Vec::new();
                        chain.push(error.to_string());
                        let mut source = error.source();
                        while let Some(s) = source {
                            chain.push(s.to_string());
                            source = s.source();
                        }

                        wwriteln!(&mut self.output,
                                  "Error importing {} from {}:{}{}",
                                  id,
                                  input,
                                  if chain.len() == 1 {
                                      " "
                                  } else {
                                      ""
                                  },
                                  if chain.len() == 1 {
                                      Cow::Owned(error.to_string())
                                  } else {
                                      Cow::Borrowed("")
                                  });
                        if chain.len() > 1 {
                            for c in chain {
                                wwriteln!(stream = &mut self.output,
                                          indent = "    ",
                                          "{}", c);
                            }
                        }

                        self.sq.hint(format_args!(
                            "To import certificates, do:"))
                            .sq().arg("cert").arg("import")
                            .arg(input)
                            .done();
                    }
                    // No special handling for these errors.
                    error => {
                        wwriteln!(&mut self.output,
                                  "Error importing key from {}: {}",
                                  input, error);
                    },
                }
            }

            Output::Report(
                Report {
                    stats,
                    ..
                }) =>
            {
                if ! self.saw_error
                    && stats.keys.new == 0
                    && stats.keys.unchanged == 0
                    && stats.keys.updated == 0
                    && stats.keys.errors == 0
                    && ! self.sq.quiet()
                {
                    let input = if let Some(source) = self.source.as_ref() {
                        Cow::Owned(source.display().to_string())
                    } else {
                        Cow::Borrowed("input")
                    };

                    wwriteln!(&mut self.output,
                              "Warning: {} does not contain any certificates",
                              input);
                }

                if self.print_stats {
                    wwriteln!(&mut self.output);
                    stats.print_summary(&mut self.output, &self.sq.sequoia)?;
                }
                self.stats = Some(stats);
            }

            _output => {
                // eprintln!("Unknown output: {:?}", output);
            }
        }

        Ok(())
    }
}
