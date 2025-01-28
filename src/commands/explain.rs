use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::cli::explain;
use crate::Sq;

pub fn dispatch(_sq: Sq, c: explain::Command) -> Result<()> {
    Ok(())
}
