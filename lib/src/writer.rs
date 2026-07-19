//! Thin convenience wrappers around `std::io::Write`.

/// A thin wrapper around a `std::io::Write`.
///
/// This struct implements a number of conversions that make
/// specifying a writer cleaner and easier.
#[non_exhaustive]
pub enum Writer<'w> {
    Mut(&'w mut (dyn std::io::Write + Send + Sync)),
    Owned(Box<dyn std::io::Write + Send + Sync>),
}

impl<'w> std::io::Write for Writer<'w> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Writer::Mut(w) => w.write(buf),
            Writer::Owned(ref mut w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Writer::Mut(w) => w.flush(),
            Writer::Owned(ref mut w) => w.flush(),
        }
    }
}

impl<'w> Writer<'w> {
    /// Returns a reference to the underlying writer.
    pub fn writer(&mut self) -> &mut dyn std::io::Write {
        match self {
            Writer::Mut(w) => w,
            Writer::Owned(w) => w.as_mut(),
        }
    }
}

impl<'w> From<&'w mut (dyn std::io::Write + Send + Sync)> for Writer<'w> {
    fn from(writer: &'w mut (dyn std::io::Write + Send + Sync)) -> Self {
        Writer::Mut(writer)
    }
}

impl<'w, W> From<&'w mut W> for Writer<'w>
where
    W: std::io::Write + Send + Sync,
{
    fn from(writer: &'w mut W) -> Self {
        Writer::Mut(writer)
    }
}

impl<'w> From<Box<dyn std::io::Write + Send + Sync>> for Writer<'w> {
    fn from(writer: Box<dyn std::io::Write + Send + Sync>) -> Self {
        Writer::Owned(writer)
    }
}

// We can't both `impl<'w, W> From<&'w mut W> for Writer<'w>` and
// `impl<'w, W> From<W> for Writer<'w>`, as they overlap.  We
// implement the former, which is by far the more common case, to
// avoid unnecessary boxing.  We handle the latter by implementing
// conversions for some common concrete types.

impl From<std::fs::File> for Writer<'_> {
    fn from(writer: std::fs::File) -> Self {
        Writer::Owned(Box::new(writer))
    }
}

impl From<std::io::Empty> for Writer<'_> {
    fn from(writer: std::io::Empty) -> Self {
        Writer::Owned(Box::new(writer))
    }
}

impl From<std::io::Sink> for Writer<'_> {
    fn from(writer: std::io::Sink) -> Self {
        Writer::Owned(Box::new(writer))
    }
}

impl From<std::io::Stdout> for Writer<'_> {
    fn from(writer: std::io::Stdout) -> Self {
        Writer::Owned(Box::new(writer))
    }
}

impl From<std::io::Stderr> for Writer<'_> {
    fn from(writer: std::io::Stderr) -> Self {
        Writer::Owned(Box::new(writer))
    }
}

/// A thin wrapper around a `std::io::Write`.
///
/// Unlike `std::io::Write`, this `Write` variant is optional.  It
/// also implements a number of conversions that make specifying an
/// optional writer cleaner and easier.
//
// We'd like to write:
//
// ```
// pub fn to_writer<'w, O>(self, writer: O)
//     -> Builder<'sequoia, 'w>
// where
//     O: Into<Option<&'w mut std::io::Write>>,
// ```
//
// But that won't accept a `&mut Vec<u8>` without an explicit cast.
// Likewise, we'd like to write:
//
// ```
// pub fn to_writer<'w, O, W>(self, writer: O)
//     -> Builder<'sequoia, 'w>
// where
//     O: Into<Option<&'w mut W>>,
//     W: std::io::Write + 'w,
// ```
//
// But that won't accept an unsized `Write`r.  Hence, this data
// structure.
#[non_exhaustive]
pub enum OptionalWriter<'w> {
    Writer(Writer<'w>),
    Discard,
}

impl<'w> std::io::Write for OptionalWriter<'w> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            OptionalWriter::Writer(w) => w.write(buf),
            OptionalWriter::Discard => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            OptionalWriter::Writer(w) => w.flush(),
            OptionalWriter::Discard => Ok(()),
        }
    }
}

impl<'w> OptionalWriter<'w> {
    /// Returns a reference to the underlying writer.
    pub fn writer(&mut self) -> Option<&mut dyn std::io::Write> {
        match self {
            OptionalWriter::Writer(w) => Some(w.writer()),
            OptionalWriter::Discard => None,
        }
    }
}

impl<'w> From<Writer<'w>> for OptionalWriter<'w> {
    fn from(writer: Writer<'w>) -> Self {
        OptionalWriter::Writer(writer)
    }
}

impl<'w> From<&'w mut (dyn std::io::Write + Send + Sync)> for OptionalWriter<'w> {
    fn from(writer: &'w mut (dyn std::io::Write + Send + Sync)) -> Self {
        OptionalWriter::Writer(Writer::Mut(writer))
    }
}

impl<'w, W> From<&'w mut W> for OptionalWriter<'w>
where
    W: std::io::Write + Send + Sync,
{
    fn from(writer: &'w mut W) -> Self {
        OptionalWriter::Writer(Writer::Mut(writer))
    }
}

impl<'w> From<Box<dyn std::io::Write + Send + Sync>> for OptionalWriter<'w> {
    fn from(writer: Box<dyn std::io::Write + Send + Sync>) -> Self {
        OptionalWriter::Writer(Writer::Owned(writer))
    }
}

// Note: this must be the only implementation of a `From<Option<...>>`
// for `OptionalWriter`.  If we have another, then the user won't be
// able to specify `None` without giving `None` an explicit type,
// which defeats the purpose of `None` short cut!  Similarly, the only
// implementation can't be `impl<'w, W> From<Option<&'w mut W>> for
// OptionalWriter<'w>`, as `W` has to be a concrete type.
//
// This means that if the user passes, e.g., `Some(&mut Vec<u8>)`,
// they'll get the error "the trait bound `OptionalWriter<'_>:
// From<Option<&mut Vec<u8>>>` is not satisfied."  In practice this is
// not so bad, as the user can just drop the `Some` and the conversion
// will work.
impl<'w> From<Option<&'w mut (dyn std::io::Write + Send + Sync)>>
    for OptionalWriter<'w>
{
    fn from(writer: Option<&'w mut (dyn std::io::Write + Send + Sync)>) -> Self {
        if let Some(writer) = writer {
            OptionalWriter::Writer(Writer::Mut(writer))
        } else {
            OptionalWriter::Discard
        }
    }
}

impl From<std::fs::File> for OptionalWriter<'_> {
    fn from(writer: std::fs::File) -> Self {
        OptionalWriter::Writer(Writer::Owned(Box::new(writer)))
    }
}

impl From<std::io::Empty> for OptionalWriter<'_> {
    fn from(writer: std::io::Empty) -> Self {
        OptionalWriter::Writer(Writer::Owned(Box::new(writer)))
    }
}

impl From<std::io::Sink> for OptionalWriter<'_> {
    fn from(writer: std::io::Sink) -> Self {
        OptionalWriter::Writer(Writer::Owned(Box::new(writer)))
    }
}

impl From<std::io::Stdout> for OptionalWriter<'_> {
    fn from(writer: std::io::Stdout) -> Self {
        OptionalWriter::Writer(Writer::Owned(Box::new(writer)))
    }
}

impl From<std::io::Stderr> for OptionalWriter<'_> {
    fn from(writer: std::io::Stderr) -> Self {
        OptionalWriter::Writer(Writer::Owned(Box::new(writer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Custom;

    impl std::io::Write for Custom {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_from() {
        // Write to a `&mut File`.
        let mut file: std::fs::File = tempfile::tempfile()
            .expect("can create a new temporary file");
        let _ = Writer::from(&mut file);

        // Write to a `&mut &mut File`.
        let mut file_ref = &mut file;
        let _ = Writer::from(&mut file_ref);

        // Write to a `File`.
        let _ = Writer::from(file);

        // Write to a `&mut Vec<u8>`.
        let mut output: Vec<u8> = Vec::new();
        let _ = Writer::from(&mut output);

        // Write to a `Box<dyn Write>`.
        let output: Box<dyn std::io::Write + Send + Sync>
            = Box::new(Vec::new());
        let _ = Writer::from(output);

        // Write to an `&mut Empty`.
        let mut empty = std::io::empty();
        let _ = Writer::from(&mut empty);

        // Write to an `Empty`.
        let _ = Writer::from(empty);

        // Write to an `&mut Sink`.
        let mut sink = std::io::sink();
        let _ = Writer::from(&mut sink);

        // Write to an `Sink`.
        let _ = Writer::from(sink);

        // Write to an `&mut Stdout`.
        let mut stdout = std::io::stdout();
        let _ = Writer::from(&mut stdout);

        // Write to an `Stdout`.
        let _ = Writer::from(stdout);

        // Write to an `&mut Stderr`.
        let mut stderr = std::io::stderr();
        let _ = Writer::from(&mut stderr);

        // Write to an `Stderr`.
        let _ = Writer::from(stderr);

        // Write to an (unsized) `&mut dyn std::io::Write`.
        let mut writer: Vec<u8> = Vec::new();
        let mut writer: &mut (dyn std::io::Write + Send + Sync) = &mut writer;
        let _ = Writer::from(&mut writer);

        // Write to a custom `std::io::Write` implementation.
        let mut output = Custom;
        let _ = Writer::from(&mut output);

        // We can't rely on the implicit conversion.  But we can
        // convert manually.
        let output: Vec<u8> = Vec::new();
        let _ = Writer::from(Writer::Owned(Box::new(output)));
    }

    #[test]
    fn optional_writer_from() {
        // Write to a `&mut File`.
        let mut file: std::fs::File = tempfile::tempfile()
            .expect("can create a new temporary file");
        let _ = OptionalWriter::from(&mut file);
        let _ = OptionalWriter::from(Some(&mut file as _));

        // Write to a `&mut &mut File`.
        let mut file_ref = &mut file;
        let _ = OptionalWriter::from(&mut file_ref);
        let _ = OptionalWriter::from(Some(&mut file_ref as _));

        // Write to a `File`.
        let _ = OptionalWriter::from(file);

        // No conversion for `Some(File)`
        //let mut file: std::fs::File = tempfile::tempfile()
        //    .expect("can create a new temporary file");
        //let _ = OptionalWriter::from(Some(Writer::from(file)));

        // Write to a `&mut Vec<u8>`.
        let mut output: Vec<u8> = Vec::new();
        let _ = OptionalWriter::from(&mut output);
        let _ = OptionalWriter::from(Some(&mut output as _));

        // Write to a `Box<dyn Write>`.
        let output: Box<dyn std::io::Write + Send + Sync>
            = Box::new(Vec::new());
        let _ = OptionalWriter::from(output);

        // Write to an `&mut Empty`.
        let mut empty = std::io::empty();
        let _ = OptionalWriter::from(&mut empty);
        let _ = OptionalWriter::from(Some(&mut empty as _));

        // Write to an `Empty`.
        let _ = OptionalWriter::from(empty);

        // No conversion for `Some(Empty)`
        //let mut empty = std::io::empty();
        //let _ = OptionalWriter::from(Some(empty as _));

        // Write to an `&mut Sink`.
        let mut sink = std::io::sink();
        let _ = OptionalWriter::from(&mut sink);
        let _ = OptionalWriter::from(Some(&mut sink as _));

        // Write to an `Sink`.
        let sink = std::io::sink();
        let _ = OptionalWriter::from(sink);

        // No conversion for `Some(Sink)`.
        //let mut sink = std::io::sink();
        //let _ = OptionalWriter::from(Some(sink as _));

        // Write to an `&mut Stdout`.
        let mut stdout = std::io::stdout();
        let _ = OptionalWriter::from(&mut stdout);
        let _ = OptionalWriter::from(Some(&mut stdout as _));

        // Write to an `Stdout`.
        let _ = OptionalWriter::from(stdout);

        // No conversion for `Some(Stdout)`.
        //let mut stdout = std::io::stdout();
        //let _ = OptionalWriter::from(Some(stdout as _));

        // Write to an `&mut Stderr`.
        let mut stderr = std::io::stderr();
        let _ = OptionalWriter::from(&mut stderr);
        let _ = OptionalWriter::from(Some(&mut stderr as _));

        // Write to an `Stderr`.
        let _ = OptionalWriter::from(stderr);

        // No conversion for `Some(Stderr)`.
        //let mut stderr = std::io::stderr();
        //let _ = OptionalWriter::from(Some(stderr as _));

        // Write to an (unsized) `&mut dyn std::io::Write`.
        let mut writer: Vec<u8> = Vec::new();
        let mut writer: &mut (dyn std::io::Write + Send + Sync) = &mut writer;
        let _ = OptionalWriter::from(&mut writer);
        let _ = OptionalWriter::from(Some(&mut writer as _));

        // Discard.
        let _ = OptionalWriter::from(None);

        // `Writer`.
        let output: Vec<u8> = Vec::new();
        let _ = OptionalWriter::from(Writer::Owned(Box::new(output)));

        // No conversion for `Some(Writer)`.
        //let _ = OptionalWriter::from(Some(Writer::Owned(Box::new(output))));
    }
}
