//! A unified interface for specifying various destinations for
//! OpenPGP artifacts.

/// Where to write an artifact.
///
/// As this struct is consumed, this belongs in the `ParamsOnce`
/// struct.
pub enum Destination<T> {
    /// Write to the store.
    Store,

    /// Write to a `Write`r.
    Writer(T),

    /// Just return the artifact.
    Ephemeral,
}

impl<T> std::fmt::Debug for Destination<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dest = match self {
            Destination::Store => "Store",
            Destination::Writer(_) => "Writer",
            Destination::Ephemeral => "Ephemeral",
        };
        write!(f, "{}", dest)
    }
}

#[allow(unused)]
impl<T> Destination<T> {
    /// Whether we will write to the store.
    pub fn to_store(&self) -> bool {
        matches!(self, Destination::Store)
    }

    /// Whether we will write to a writer.
    pub fn to_writer(&self) -> bool {
        matches!(self, Destination::Writer(_))
    }

    /// Whether we will just return the artifact.
    ///
    /// In this case, the artifact is not written to the store or to a
    /// `Write`r.
    pub fn ephemeral(&self) -> bool {
        matches!(self, Destination::Ephemeral)
    }

    /// Converts this `Destination` to a `DestinationSummary`.
    pub fn to_summary(&self) -> DestinationSummary {
        match self {
            Destination::Store => DestinationSummary::Store,
            Destination::Writer(_) => DestinationSummary::Writer,
            Destination::Ephemeral => DestinationSummary::Ephemeral,
        }
    }
}

/// Where to store the artifacts.
///
/// This struct is not consumed, and can be added to the `Params`
/// struct.  It is important that it be kept synchronized with the
/// corresponding [`Destination`].
#[derive(Clone)]
pub enum DestinationSummary {
    /// Write to the store.
    Store,

    /// Write to a `Write`r.
    Writer,

    /// Just return the artifact.
    Ephemeral,
}

impl std::fmt::Debug for DestinationSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dest = match self {
            DestinationSummary::Store => "Store",
            DestinationSummary::Writer => "Writer",
            DestinationSummary::Ephemeral => "Ephemeral",
        };
        write!(f, "{}", dest)
    }
}

impl DestinationSummary {
    /// Whether we will write the artifact to the store.
    pub fn to_store(&self) -> bool {
        matches!(self, DestinationSummary::Store)
    }

    /// Whether we will write the artifact to a writer.
    pub fn to_writer(&self) -> bool {
        matches!(self, DestinationSummary::Writer)
    }

    /// Whether we will just return the artifact.
    ///
    /// In this case, the artifact is not written to the store or to a
    /// `Write`r.
    pub fn ephemeral(&self) -> bool {
        matches!(self, DestinationSummary::Ephemeral)
    }
}

/// Methods to add to the `Params` impl.
macro_rules! destination_params_impl {
    ($artifact:literal) => {
        destination_params_impl!($artifact, "is");
    };
    ($artifact:literal, $is:literal) => {
        /// Whether we will write the
        #[doc=$artifact]
        /// to the store.
        #[allow(unused)]
        pub fn to_store(&self) -> bool {
            self.destination.to_store()
        }

        /// Whether we will write the
        #[doc=$artifact]
        /// to a writer.
        #[allow(unused)]
        pub fn to_writer(&self) -> bool {
            self.destination.to_writer()
        }

        /// Whether we will just return the
        #[doc=$artifact]
        /// .
        ///
        /// In this case, the
        #[doc=$artifact]
        #[doc=$is]
        /// not written to the store or to a `Write`r.
        #[allow(unused)]
        pub fn ephemeral(&self) -> bool {
            self.destination.ephemeral()
        }
    }
}

/// Add `to_store` method to the `Builder` impl.
macro_rules! destination_builder_to_store_impl {
    ($artifact:literal) => {
        destination_builder_to_store_impl!($artifact, "is");
    };
    ($artifact:literal, $is:literal) => {
        /// Writes the
        #[doc=$artifact]
        /// to the store.
        ///
        /// This is the default.
        #[allow(unused)]
        pub fn to_store(mut self) -> Self {
            self.params.destination = DestinationSummary::Store;
            self.params_once.destination = Destination::Store;
            self
        }
    }
}

/// Add `to_writer` method to the `Builder` impl.
macro_rules! destination_builder_to_writer_impl {
    ($artifact:literal) => {
        destination_builder_to_writer_impl!($artifact, "is");
    };
    ($artifact:literal, $is:literal) => {
        /// Writes the
        #[doc=$artifact]
        /// to the `Write`r.
        #[allow(unused)]
        ///
        /// If `writer` is `None`, then writes the
        #[doc=$artifact]
        /// to the store.
        pub fn to_writer<'writer_new, W>(self, writer: W)
            -> Builder<'sequoia, 'writer_new>
        where
            W: Into<crate::OptionalWriter<'writer_new>>,
        {
            use crate::OptionalWriter;

            let writer = writer.into();

            // This is a bit more complicated than other setters as we
            // need to change self's lifetime from 'writer to 'w.
            match writer {
                OptionalWriter::Writer(writer) => {
                    Builder {
                        params: Params {
                            destination : DestinationSummary::Writer,
                            ..self.params
                        },
                        params_once: ParamsOnce {
                            destination: Destination::Writer(writer),
                            ..self.params_once
                        },
                    }
                }
                OptionalWriter::Discard => {
                    Builder {
                        params: Params {
                            destination : DestinationSummary::Store,
                            ..self.params
                        },
                        params_once: ParamsOnce {
                            destination: Destination::Store,
                            ..self.params_once
                        },
                    }
                }
            }
        }
    }
}

/// Add `ephemeral` method to the `Builder` impl.
macro_rules! destination_builder_to_ephemeral_impl {
    ($artifact:literal) => {
        destination_builder_to_ephemeral_impl!($artifact, "is");
    };
    ($artifact:literal, $is:literal) => {
        /// Doesn't save the
        #[doc=$artifact]
        ///
        /// In this case, the
        #[doc=$artifact]
        #[doc=$is]
        /// not written to the store or to a `Write`r.
        #[allow(unused)]
        pub fn ephemeral(mut self) -> Self {
            self.params.destination = DestinationSummary::Ephemeral;
            self.params_once.destination = Destination::Ephemeral;
            self
        }
    }
}

/// Methods to add to the `Builder` impl.
macro_rules! destination_builder_impl {
    ($artifact:literal) => {
        destination_builder_impl!($artifact, "is");
    };
    ($artifact:literal, $is:literal) => {
        destination_builder_to_store_impl!($artifact, $is);
        destination_builder_to_writer_impl!($artifact, $is);
        destination_builder_to_ephemeral_impl!($artifact, $is);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Sequoia;
    use crate::Writer;

    #[test]
    fn destination() {
        struct Params<'sequoia> {
            #[allow(unused)]
            sequoia: &'sequoia Sequoia,
            destination: DestinationSummary,
        }

        impl Params<'_> {
            destination_params_impl!("cert");
        }

        struct ParamsOnce<'writer> {
            destination: Destination<Writer<'writer>>,
        }

        struct Builder<'sequoia, 'writer> {
            params: Params<'sequoia>,
            params_once: ParamsOnce<'writer>,
        }

        impl<'sequoia, 'writer> Builder<'sequoia, 'writer> {
            destination_builder_impl!("cert");
        }

        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let builder = || -> Builder<'_, 'static> {
            Builder {
                params: Params {
                    sequoia: &sq,
                    destination: DestinationSummary::Store,
                },
                params_once: ParamsOnce {
                    destination: Destination::Store,
                }
            }
        };

        // To store.
        let b = builder().to_store();
        assert!(b.params.to_store());
        assert!(matches!(b.params_once.destination, Destination::Store));

        // To store.
        let b = builder().to_writer(None);
        assert!(b.params.to_store());
        assert!(matches!(b.params_once.destination, Destination::Store));

        // Ephmeral.
        let b = builder().ephemeral();
        assert!(b.params.ephemeral());
        assert!(matches!(b.params_once.destination, Destination::Ephemeral));

        // Write to a `&mut File`.
        let mut file: std::fs::File = tempfile::tempfile()
            .expect("can create a new temporary file");
        let b = builder().to_writer(&mut file);
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        // We need to cast to `&mut std::io::Write` (read the comment
        // for `impl<'w> From<Option<&'w mut dyn std::io::Write>> for
        // OptionalWriter<'w>`).  Likewise below.
        let b = builder().to_writer(Some(&mut file as _));
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        // Write to a `&mut &mut File`.
        let mut file_ref = &mut file;
        let b = builder().to_writer(&mut file_ref);
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        let b = builder().to_writer(Some(&mut file_ref as _));
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        // Write to a `&mut Vec<u8>`.
        let mut output: Vec<u8> = Vec::new();
        let b = builder().to_writer(&mut output);
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        let b = builder().to_writer(Some(&mut output as _));
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        // Write to a `Sink`.
        let mut writer = std::io::sink();
        let b = builder().to_writer(&mut writer);
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        let b = builder().to_writer(Some(&mut writer as _));
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        // Write to an (unsized) `&mut dyn std::io::Write`.
        let mut writer: Vec<u8> = Vec::new();
        let mut writer: &mut (dyn std::io::Write + Send + Sync) = &mut writer;
        let b = builder().to_writer(&mut writer);
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));

        let b = builder().to_writer(Some(&mut writer as _));
        assert!(b.params.to_writer());
        assert!(matches!(b.params_once.destination, Destination::Writer(_)));
    }
}
