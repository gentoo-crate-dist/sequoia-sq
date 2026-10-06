# A High-Level API for the Sequoia PGP Ecosystem

`sqz` is an easy-to-use, high-level library that abstracts away the
complex details of using the OpenPGP protocol and navigating the
Sequoia PGP ecosystem.

`sqz` provides a small number of highly opinionated interfaces, which
are nevertheless appropriate for many workflows.  While such an API
exposes less functionality than the lower-level libraries that it is
built on, it also requires less expertise from application developers.
Lowering the barrier to adopting strong cryptography improves privacy
and security.  Fewer concerns also means fewer possibilities for
errors.  And the reduced freedom imposed by a constrained API leads to
more consistent workflows between applications, which increases
operational security: familiar processes are easier for people to use
correctly and therefore more secure.

`sqz` provides an escape hatch in case its policies are inappropriate.
`sqz` carefully builds on and exposes lower-level types.  This means
that when the high-level API's decisions are unsuitable, you don't
have to abandon the library; you can drop down to the low-level API to
tweak its behavior.  Mixing the high-level and the low-level APIs is
explicitly supported.

`sqz` is short for squeeze.  The name comes from the idea that the
high-level library squeezes the Sequoia ecosystem together and serves
the juiciest bits as a full bodied, refreshing, and tasty API.

# Features

If you enable the `clap` feature then several types in the `config`
implement some `clap` traits.  For instance, `CipherSuite` and
`Profile` implement `clap::ValueEnum`, and `Expiration` implements
`clap::builder::IntoResettable`.  This allows these types to be
directly used with clap without having to wrap them, which would
otherwise be required due to Rust's orphan rule (a crate can only
implement a trait for a given struct or enum if the crate defines the
struct or enum, or the crate defines the trait).
