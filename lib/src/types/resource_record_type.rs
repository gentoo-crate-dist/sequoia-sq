#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ResourceRecordType {
    #[default]
    #[cfg_attr(feature = "clap", clap(name = "openpgp"))]
    OpenPGP,
    Generic,
}

