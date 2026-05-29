//! Error handling.

use std::sync::Arc;

/// Crate result specialization.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

/// Errors used in this crate.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The state has been explicitly disabled.
    #[error("the {state} has been explicitly disabled")]
    #[non_exhaustive]
    StateDisabled {
        state: &'static str,
    },
}

impl Error {
    /// Signals that the state has been explicitly disabled.
    pub(crate) fn state_disabled(state: &'static str) -> Self {
        Error::StateDisabled { state }
    }
}

/// A system error that prevents processing from continuing.
///
/// System errors are fatal and cause processing to abort.
///
/// System errors are related to the system.  An example of a
/// system error is that a key store is not available, but is
/// needed to complete the operation.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone)]
pub enum SystemError {
    #[error("Cert store disabled")]
    CertStoreDisabled,

    #[error("Error opening the cert store: {}", .0)]
    CertStoreError(Arc<anyhow::Error>),

    #[error("Home disabled: can't save certificate")]
    HomeDisabled,

    #[error(transparent)]
    Other(Arc<anyhow::Error>),
}

/// Converts an error to a SystemError::Other.
///
/// This can be used as follows.  Note: there must be an `Error` enum
/// in scope with a `Error::SystemError` variant.
///
/// ```text
/// sq.key_store_or_else().map_err(sys!())?;
/// ```
macro_rules! sys {
    () => {
        |err| {
            Error::SystemError(
                $crate::SystemError::Other(err.into()))
        }
    }
}
