use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use sequoia::types::Query as InnerQuery;
pub use sequoia::types::QueryKind;

#[derive(Debug, Clone)]
pub struct Query {
    /// The user-supplied command-line argument, e.g., `--cert
    /// FINGERPRINT`.
    pub argument: Option<String>,
    pub inner: InnerQuery,
}

impl Query {
    /// Returns a `Query` for the specified kind of query.
    ///
    /// `argument` is the user-supplied command-line argument, e.g.,
    /// `--cert FINGERPRINT`.
    pub fn for_kind(argument: Option<String>, kind: QueryKind)
        -> Query
    {
        Query {
            argument,
            inner: InnerQuery::for_kind(kind),
        }
    }

    /// Returns a `Query` that matches all bindings.
    pub fn all() -> Self {
        Self::for_kind(None, QueryKind::All)
    }

    /// Returns a `Query` for a key handle.
    ///
    /// `argument` is the user-supplied command-line argument, e.g.,
    /// `--cert FINGERPRINT`.
    pub fn for_key_handle(argument: Option<String>, kh: KeyHandle)
        -> Query
    {
        Self::for_kind(argument, QueryKind::Cert(kh))
    }

    /// Returns the inner Query.
    pub fn to_inner(&self) -> &InnerQuery {
        &self.inner
    }
}
