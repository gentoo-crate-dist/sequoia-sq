#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ResourceRecordType {
    #[default]
    #[clap(name = "openpgp")]
    OpenPGP,
    Generic,
}

