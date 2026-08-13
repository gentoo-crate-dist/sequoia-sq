use std::path::PathBuf;

use sequoia::types::FileOrStdin;
use sequoia::types::import_stats::ImportStats;

use crate::cli;
use crate::Sq;
use crate::Result;
use crate::output::key::import::Stream;

pub fn import(sq: Sq, command: cli::key::import::Command)
    -> Result<()>
{
    let inputs = if command.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        command.input
    };

    let mut output = std::io::stdout();

    let mut stats = ImportStats::default();

    let mut result = Ok(());
    for file in inputs {
        let input = FileOrStdin::from(file.clone());
        let input = input.open("OpenPGP keys")?;

        let mut stream = Stream::new(
            &sq, Some(file.as_path()), &mut output, false);

        let r = sq.sequoia.key_import()
            .stream(&mut stream)
            .import_keyring(input);

        if let Some(s) = stream.stats {
            stats += s;
        }

        // Save the first error.
        if result.is_ok() && r.is_err() {
            result = r;
        }
        if result.is_ok() {
            if let Some(err) = stream.import_error.take() {
                result = Err(err);
            }
        }
    }

    stats.print_summary(&mut output, &sq.sequoia)?;

    // Carefully turn result into an anyhow::Error.  Specifically, we
    // want to be able to downcast the result to a `SystemError`, but
    // to do this we need to strip the outer `Error`.
    let result = result.map_err(|e| {
        match e {
            sequoia::key::import::Error::SystemError(e) => anyhow::Error::from(e),
            e => anyhow::Error::from(e),
        }
    });

    result
}
