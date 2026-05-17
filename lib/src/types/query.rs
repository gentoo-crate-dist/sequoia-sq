use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

/// The different kinds of queries that we support.
#[derive(Debug, Clone)]
pub enum QueryKind {
    AuthenticatedCert(KeyHandle),
    Cert(KeyHandle),
    UserID(String),
    Email(String),
    UserIDBinding(KeyHandle, String),
    EmailBinding(KeyHandle, String),
    Domain(String),
    Pattern(String),
    All,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub kind: QueryKind,
}

impl Query {
    /// Returns a `Query` that matches all bindings.
    pub fn all() -> Self {
        Query {
            kind: QueryKind::All,
        }
    }

    /// Returns whether the two queries are identical.
    pub fn identical(&self, other: &Self) -> bool {
        use QueryKind::*;

        match (&self.kind, &other.kind) {
            (AuthenticatedCert(a), AuthenticatedCert(b)) => a == b,
            (Cert(a), Cert(b)) => a == b,
            (UserID(a), UserID(b)) => a == b,
            (Email(a), Email(b)) => a == b,
            (UserIDBinding(a1, a2), UserIDBinding(b1, b2)) => {
                a1 == b1 && a2 == b2
            }
            (EmailBinding(a1, a2), EmailBinding(b1, b2)) => {
                a1 == b1 && a2 == b2
            }
            (Domain(a), Domain(b)) => a == b,
            (Pattern(a), Pattern(b)) => a == b,
            (All, All) => true,
            (_, _) => false,
        }
    }
}
