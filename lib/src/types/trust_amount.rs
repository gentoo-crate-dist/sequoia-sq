use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use crate::Result;

/// A trust amount.
///
/// Note that OpenPGP data structures only describe a u8, however,
/// this trust amount can be larger to accommodate expressing higher
/// trust requirements, like 360 for three fully-trusted, orthogonal
/// paths.
#[derive(Copy, Clone, Debug)]
pub enum TrustAmount<T> {
    /// No trust.
    None,

    /// Partial trust.
    Partial,

    /// Full trust.
    Full,

    /// Double trust.
    Double,

    /// Other trust amount.
    Other(T),
}

impl<T> PartialEq for TrustAmount<T>
where
    T: PartialEq + Copy + From<u8>
{
    fn eq(&self, other: &Self) -> bool {
        self.amount() == other.amount()
    }
}

impl<T> Eq for TrustAmount<T>
where
    T: PartialEq + Copy + From<u8>
{
}

impl<T: Copy + From<u8>> TrustAmount<T> {
    /// Returns the trust amount as numeric value.
    pub fn amount(&self) -> T {
        match self {
            TrustAmount::None => 0.into(),
            // See section 5.2.3.13. Trust Signature of RFC4880 for
            // the values of partial and full trust.
            TrustAmount::Partial => 60.into(),
            TrustAmount::Full => 120.into(),
            TrustAmount::Double => 240.into(),
            TrustAmount::Other(a) => *a,
        }
    }
}

impl<T> From<usize> for TrustAmount<T>
where
    T: From<usize>
{
    fn from(amount: usize) -> Self {
        match amount {
            0 => TrustAmount::None,
            // See section 5.2.3.13. Trust Signature of RFC4880 for
            // the values of partial and full trust.
            60 => TrustAmount::Partial,
            120 => TrustAmount::Full,
            240 => TrustAmount::Double,
            a => TrustAmount::Other(T::from(a)),
        }
    }
}

impl<T: Display + FromStr> FromStr for TrustAmount<T>
where
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<TrustAmount<T>> {
        if s.eq_ignore_ascii_case("none") {
            Ok(TrustAmount::None)
        } else if s.eq_ignore_ascii_case("partial") {
            Ok(TrustAmount::Partial)
        } else if s.eq_ignore_ascii_case("full") {
            Ok(TrustAmount::Full)
        } else if s.eq_ignore_ascii_case("double") {
            Ok(TrustAmount::Double)
        } else {
            Ok(TrustAmount::Other(s.parse()?))
        }
    }
}

impl<T: Display + FromStr> Display for TrustAmount<T> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            TrustAmount::None => f.write_str("none"),
            TrustAmount::Partial => f.write_str("partial"),
            TrustAmount::Full => f.write_str("full"),
            TrustAmount::Double => f.write_str("double"),
            TrustAmount::Other(a) => write!(f, "{}", a),
        }
    }
}
