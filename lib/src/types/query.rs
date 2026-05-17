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
    /// Returns a `Query` for the specified kind of query.
    pub fn for_kind(kind: QueryKind) -> Self {
        Query {
            kind,
        }
    }

    /// Returns a `Query` that matches all bindings.
    pub fn all() -> Self {
        Self::for_kind(QueryKind::All)
    }

    /// Returns a `Query` that matches a certificate.
    ///
    /// The certificate is considered authenticated by the designator.
    pub fn authenticated_cert(kh: KeyHandle) -> Self {
        Self::for_kind(QueryKind::AuthenticatedCert(kh))
    }

    /// Returns a `Query` that matches a certificate.
    ///
    /// The certificate must be authenticated via the web of trust.
    pub fn unauthenticated_cert(kh: KeyHandle) -> Self {
        Self::for_kind(QueryKind::Cert(kh))
    }

    /// Returns a `Query` that matches a user ID.
    pub fn userid<S>(userid: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::UserID(userid.into()))
    }

    /// Returns a `Query` that matches an email address.
    pub fn email<S>(email: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::Email(email.into()))
    }

    /// Returns a `Query` that matches a binding exactly.
    pub fn userid_binding<S>(kh: KeyHandle, userid: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::UserIDBinding(kh, userid.into()))
    }

    /// Returns a `Query` that matches on the specified certificate's
    /// bindings, which include the specified email address.
    pub fn email_binding<S>(kh: KeyHandle, email: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::EmailBinding(kh, email.into()))
    }

    /// Returns a `Query` that matches bindings that contain an email
    /// address in the specified domain.
    pub fn domain<S>(domain: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::Domain(domain.into()))
    }

    /// Returns a `Query` that matches bindings that contain the
    /// specified string.
    pub fn pattern<S>(pattern: S) -> Self
    where
        S: Into<String>
    {
        Self::for_kind(QueryKind::Pattern(pattern.into()))
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
