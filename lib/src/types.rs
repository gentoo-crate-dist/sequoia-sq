//! Types used in the interface.

use std::{
    path::PathBuf,
};

mod as_ref;
pub use as_ref::MyAsRef;
mod cert_designator;
pub use cert_designator::FileStdinOrKeyHandle;
pub use cert_designator::FileOrStdin;
mod compression_mode;
pub use compression_mode::CompressionMode;
mod convert;
pub use convert::Convert;
mod encrypt_purpose;
pub use encrypt_purpose::EncryptPurpose;
mod hash_mode;
pub use hash_mode::HashMode;
pub mod import_stats;
mod part_file_writer;
pub use part_file_writer::PartFileWriter;
mod preferred_userid;
pub use preferred_userid::PreferredUserID;
mod resource_record_type;
pub use resource_record_type::ResourceRecordType;
mod safe;
pub use safe::Safe;
mod session_key;
pub use session_key::SessionKey;

mod trust_amount;
pub use trust_amount::TrustAmount;
mod trust_threshold;
pub use trust_threshold::TrustThreshold;

/// Either an absolute path, or a default path.
///
/// Even though this type is homomorphic to [`Option<PathBuf>`], we
/// need a new type for this, because clap handles [`Option`]s
/// differently, and we cannot return [`Option<PathBuf>`] from
/// `TypedValueParser::parse_ref`.
#[derive(Clone, Debug)]
pub enum StateDirectory {
    /// An absolute path.
    Absolute(PathBuf),

    /// The default path.
    Default,

    /// Explicitly disable this state.
    None,
}

impl StateDirectory {
    /// Returns whether this state has been disabled.
    pub fn is_none(&self) -> bool {
        matches!(self, StateDirectory::None)
    }
}
