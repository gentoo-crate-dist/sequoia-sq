//! Functionality for listing certificates.
//!
//! A Sequoia context usually includes a certificate store.
//! [`Sequoia::cert_list`] enables the user to query the certificate
//! store by fingerprint or by user ID.  A query matches on a binding,
//! which is either a certificate and a user ID pair or a bare
//! certificate.
//!
//! In additional to returning any matching certificates,
//! [`Sequoia::cert_list`] also returns why a binding is considered
//! authenticated.  By default, [`Sequoia::cert_list`] only matches on
//! authenticated certificates.  However, setting the gossip flag
//! (using [`Builder::gossip`]) changes it to return any matching
//! bindings.
//!
//! If you are only looking up a certificate by its fingerprint, you
//! should use [`Sequoia::lookup`], which is lighter weight.
//!
//! # Examples
//!
//! List all bindings that have an authenticated user ID that contain
//! an email address with the specified domain.  (See [`Query`] for
//! other types of queries.)
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::types::Query;
//! use sequoia::cert::list::Output;
//! # use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # // Generate a key and import it into the certificate store.
//! # // This will marked it as a trusted introducer.
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key")
//! #     .into_cert();
//! #
//! let mut output = Vec::new();
//! sq.cert_list(Some(Query::domain("example.org")))
//!     .list(&mut output)?;
//! # let mut bindings = 0;
//! for o in output {
//!     if let Output::Binding(binding) = o {
//!         eprintln!("{}, {:?} matches",
//!                   binding.fingerprint,
//!                   binding.userid
//!                       .map(|u| {
//!                           String::from_utf8_lossy(u.value()).to_string()
//!                       })
//!                       .unwrap_or_else(|| "<bare certificate>".into()));
//! #       bindings += 1;
//!     }
//! }
//! # assert_eq!(bindings, 1);
//! # Ok(()) }
//! ```
//!
//! The above example waits for all of the results and then displays
//! them.  If the certificate store is very large, this can take a
//! noticeable amount of time.  To display the results as they are
//! returned, we can instead provide an implementation of [`Stream`],
//! which is called with each result.
//!
//! ```
//! use sequoia::Result;
//! use sequoia::Sequoia;
//! use sequoia::cert::list::Output;
//! use sequoia::cert::list::Params;
//! use sequoia::cert::list::Stream;
//! use sequoia::types::Query;
//! # use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! # let sq = Sequoia::builder().ephemeral()?.build()?;
//! #
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # // Generate a key and import it into the certificate store.
//! # // This will marked it as a trusted introducer.
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key")
//! #     .into_cert();
//! #
//! struct MyStream {
//! #   bindings: usize,
//! }
//!
//! impl Stream for MyStream {
//!     fn output(&mut self, params: &Params, output: Output) -> Result<()> {
//!         if let Output::Binding(binding) = output {
//!             eprintln!("{}, {:?} matches",
//!                       binding.fingerprint,
//!                       binding.userid
//!                           .map(|u| {
//!                               String::from_utf8_lossy(u.value()).to_string()
//!                           })
//!                           .unwrap_or_else(|| "<bare certificate>".into()));
//! #           self.bindings += 1;
//!         }
//!
//!         Ok(())
//!     }
//! }
//!
//! let mut my_stream = MyStream {
//! #   bindings: 0,
//! };
//!
//! sq.cert_list(Some(Query::domain("example.org")))
//!     .list(&mut my_stream)?;
//! # assert_eq!(my_stream.bindings, 1);
//! # Ok(()) }
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use sequoia_wot as wot;
use wot::store::Backend;
use wot::store::Store;
use wot::store::StoreError;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store as _;
use cert_store::store::UserIDQueryParams;

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::types::Query;
use crate::types::QueryKind;
use crate::types::Safe;
use crate::types::TrustAmount;

#[cfg(doc)]
use crate::SequoiaBuilder;

const TRACE: bool = false;

pub fn required_trust_amount(trust_amount: Option<TrustAmount<usize>>,
                             certification_network: bool)
                             -> usize
{
    let amount = if let Some(v) = &trust_amount {
        v.amount()
    } else {
        if certification_network {
            // Look for multiple paths.  Specifically, try to find 10
            // paths.
            10 * wot::FULLY_TRUSTED
        } else {
            wot::FULLY_TRUSTED
        }
    };

    amount
}

// Stream trait.
stream!{}

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// A matching binding.
    ///
    /// Note the binding is not necessarily authenticated.  You still
    /// need to check the aggregate trust amount.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Binding {
        /// The fingerprint.
        pub fingerprint: Fingerprint,

        /// The certificate.
        pub(crate) cert: OnceLock<Arc<LazyCert<'static>>>,

        /// The user ID.  This can be `None` when just authenticating a
        /// certificate.  This happens when listing all certificates and
        /// there is a certificate with no user IDs.
        pub userid: Option<UserID>,

        /// A set of paths that help authenticate the binding.
        ///
        /// If the set of paths are sufficient to authenticate the binding
        /// at the required confidence level, then the set of paths may
        /// not be exhaustive.
        pub paths: Vec<(wot::Path, usize)>,

        /// The aggregate trust amount across all paths.
        ///
        /// This excludes overlaps and as such may be less than simply
        /// summing the trust amount of each individual path.
        pub aggregate_trust_amount: usize,
    }

    impl Binding {
        /// Looks up the certificate from the certificate store.
        ///
        /// Note: this is often faster than looking it up manually
        /// using [`Sequoia::lookup`] as the certificate may be cached
        /// in the binding.
        pub fn cert(&self, sequoia: &Sequoia) -> Result<&Cert> {
            if let Some(cert) = self.cert.get() {
                cert.to_cert()
            } else {
                match sequoia.lookup().lookup_one(self.fingerprint.clone()) {
                    Ok(cert) => {
                        let _ = self.cert.set(Arc::new(LazyCert::from(cert)));
                        self.cert.get().expect("just set").to_cert()
                    }
                    Err(err) => {
                        Err(err)
                    }
                }
            }
        }
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        /// A certificate for each of the specified trust roots could not
        /// be found.
        ///
        /// This is only included in the report if at least one query did
        /// not match anything.
        ///
        /// Roots is a copy of the trust roots.
        pub missing_trust_roots:
            Option<(wot::Roots, Vec<(Fingerprint, anyhow::Error)>)>,

        /// Query lints.
        pub query_lints: Vec<(Query, anyhow::Error)>,

        /// The number of bindings that match the query.
        pub matching_bindings: usize,

        /// The queries that didn't match any bindings in the certificate
        /// store.
        pub unsatisfied_queries: Vec<Query>,

        /// The number of bindings that match the query and could be
        /// authenticated.
        pub authenticated_bindings: usize,

        /// The number of matching bindings that were not considered
        /// because they are unusable.
        ///
        /// See [`Builder::unusable`] for an explanation of
        /// unusable bindings.
        pub unusable_bindings: usize,

        /// The number of matching bindings that were not considered
        /// because they could not be authenticated at the specified
        /// level.
        ///
        /// When gossip mode is enabled, all bindings are considered
        /// authenticated at the specified level and this will be 0.
        pub unauthenticated_bindings: usize,
    }
}

/// The variants of this enum are the different types of output that
/// `Sequoia::list` emits.
#[non_exhaustive]
pub enum Output {
    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    ArgumentError(error::ArgumentError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    SystemError(SystemError),

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    OperationalError(error::OperationalError),

    /// We're about to emit the actual results.
    ///
    /// Note: this is emitted even if no bindings are emitted.
    StartOfBindings,

    /// A matching binding.
    ///
    /// Note the binding is not necessarily authenticated.  You still
    /// need to check the aggregate trust amount.
    Binding(output::Binding),

    /// All of the bindings that will be returned have been returned.
    ///
    /// Now's a good time to output any statistics.
    EndOfBindings,

    /// A report about the operation.
    ///
    /// The report includes lints and statistics that are collected
    /// during the operation.
    Report(output::Report),
}

impl Sequoia {
    /// List bindings.
    ///
    /// See [`Builder`] for details.
    pub fn cert_list<I>(&self, queries: I) -> Builder<'_>
    where
        I: IntoIterator<Item=Query>,
    {
        let queries: Vec<Query>
            = queries.into_iter().map(|q| q.into()).collect();

        Builder {
            params: Params {
                sequoia: self,
                queries,
                gossip: false,
                unusable: false,
                certification_network: false,
                trust_amount: None,
            }
        }
    }
}

/// Data structures related to [`Error`].
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
pub mod error {
    use super::*;

    /// The argument is not a valid email address.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{:?} does not appear to be an email address", .email)]
    pub struct InvalidEmail {
        pub email: String,
    }

    /// The argument is not a valid domain name.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("{:?} does not appear to be a domain name", .domain)]
    pub struct InvalidDomain {
        pub domain: String,
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
        #[error(transparent)]
        InvalidEmail(InvalidEmail),

        #[error(transparent)]
        InvalidDomain(InvalidDomain),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum OperationalError {
        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to generating a certificate.
///
/// Errors are divided into categories and each category contains more
/// precise errors.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum Error {
    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    ArgumentError(#[from] error::ArgumentError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    #[error(transparent)]
    SystemError(#[from] SystemError),

    /// An operational error that prevents processing from continuing.
    ///
    /// Operational errors are fatal and cause processing to abort.
    ///
    /// Operational errors are related to the operation.  An example
    /// of an operational error is that the operation needs to create
    /// a signature, but the secret key material is not available.
    #[error(transparent)]
    OperationalError(#[from] error::OperationalError),

    /// If [`Stream::output`] returns an error, it is propagated here.
    StreamOutputError(anyhow::Error),
}

/// Parameters to the list function.
///
/// The parameters passed to [`Sequoia::cert_list`].
pub struct Params<'a> {
    sequoia: &'a Sequoia,
    queries: Vec<Query>,
    gossip: bool,
    unusable: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
}

impl<'a> Params<'a> {
    /// Returns the sequoia instance.
    pub fn sequoia(&self) -> &'a Sequoia {
        self.sequoia
    }

    /// Returns the set of queries.
    pub fn queries(&self) -> &[Query] {
        &self.queries
    }

    /// Returns whether gossip mode is enabled.
    ///
    /// See [`Builder::gossip`] for more information.
    pub fn gossip(&self) -> bool {
        self.gossip
    }

    /// Returns whether unusable bindings are considered.
    ///
    /// See [`Builder::unusable`] for more information.
    pub fn unusable(&self) -> bool {
        self.unusable
    }

    /// Returns whether the network is viewed as a certification
    /// network.
    ///
    /// See [`Builder::certification_network`] for more
    /// information.
    pub fn certification_network(&self) -> bool {
        self.certification_network
    }

    /// Returns the threshold at which a binding is considered
    /// authenticated.
    ///
    /// See [`Builder::trust_amount`] for more
    /// information.
    pub fn trust_amount(&self) -> Option<TrustAmount<usize>> {
        self.trust_amount.clone()
    }
}

/// Lists bindings.
///
/// This command builder lists bindings.
///
/// By default, it returns all bindings that are fully authenticated.
pub struct Builder<'a> {
    params: Params<'a>,
}

impl<'a> Builder<'a> {
    /// Sets gossip mode.
    ///
    /// By default gossip mode is disabled.
    ///
    /// When gossip mode is enabled, this function returns all usable
    /// bindings (see [`Builder::unusable`]) and any
    /// unauthenticated paths to binding.  An unauthenticated path is
    /// one that doesn't include a trust root.
    ///
    /// Consider the following scenario: Alice has certified Bob's
    /// certificate and the caller wants to authenticate Bob's
    /// certificate.  If the caller does not consider Alice to be a
    /// trusted introducer (either directly as a trust root, or
    /// indirectly), then the path `Alice -> Bob` will not be
    /// returned.  When gossip mode is enabled, such paths are also
    /// returned.  The aggregate trust amount is still accurate.
    ///
    /// Gossip is useful to determine who certified a given binding
    /// even if the certified is not considered a trusted introducer.
    ///
    /// Note: Enabling gossip mode is not equivalent to setting the
    /// trust amount to 0 using [`Builder::trust_amount`].
    /// Setting the trust amount to 0 will return all valid bindings,
    /// but it will not return any unauthenticated paths.
    pub fn gossip(mut self, gossip: bool) -> Self {
        self.params.gossip = gossip;
        self
    }

    /// Sets whether unusable bindings should be returned.
    ///
    /// By default unusable bindings are not returned.  An unusable
    /// binding is one where the binding is not valid according to the
    /// current cryptographic policy, the certificate or user ID is
    /// revoked, or the binding is not live.  Setting this option
    /// causes these bindings to be returned.
    ///
    /// Note: the bindings still have to meet the trust threshold.  As
    /// such, this option is only meaningful if gossip mode is also
    /// enabled (see [`Builder::gossip`]).
    pub fn unusable(mut self, unusable: bool) -> Self {
        self.params.unusable = unusable;
        self
    }

    /// Sets whether the network should be viewed as a certification
    /// network.
    ///
    /// By default, `Sequoia::authenticate` treats the network as an
    /// authentication network.  That means if Alice certifies Bob's
    /// certificate and Bob certifies Carol's certificate, then
    /// relying on Alice is not enough to authenticate Carol's
    /// certificate: Alice only certified Bob's certificate; she did
    /// not indicate that he should be treated as a trusted
    /// introducer.  In a certification network, all certifications
    /// are treated as delegations.
    ///
    /// Certification networks are useful for understanding how well a
    /// group of people are connected.  They should not be use for
    /// authentication purposes.
    pub fn certification_network(mut self, certification_network: bool)
        -> Self
    {
        self.params.certification_network = certification_network;
        self
    }

    /// Sets the threshold at which a binding is considered
    /// authenticated.
    ///
    /// By default a binding is considered authenticated if the trust
    /// amount is at least `sequoia_wot::FULLY_TRUSTED` (120).
    ///
    /// If gossip mode is enabled, that mode takes precedence, and the
    /// trust amount is ignored.
    pub fn trust_amount<T>(mut self, trust_amount: T) -> Self
    where
        T: Into<Option<TrustAmount<usize>>>
    {
        self.params.trust_amount = trust_amount.into();
        self
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'_> {
        &self.params
    }

    /// List matching certificates.
    ///
    /// Unless `gossip` has been enabled, queries against user IDs
    /// only match authenticated user IDs.  That is, if you search for
    /// `alice@example.org`, a certificate with that user ID will only
    /// be returned if the user ID can be authenticated.
    ///
    /// Note: authenticated user IDs do not need to be self-signed; a
    /// user ID is considered authenticated if there is sufficient
    /// evidence that the user ID should be associated with the
    /// certificate.  This is computed using the web of trust.
    ///
    /// Returns an error if the cert store was disabled (see
    /// [`SequoiaBuilder::cert_store_path`]) and no keyrings were
    /// added (see [`SequoiaBuilder::add_keyring`]).
    pub fn list<S>(&self, mut stream: S) -> Result<(), Error>
    where
        S: Stream,
    {
        let result = self.list_(&mut stream);

        match result {
            Ok(report) => {
                stream.output(&self.params, Output::Report(report))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Ok(())
            }
            Err(err @ Error::StreamOutputError(_)) => {
                Err(err)
            }
            Err(Error::ArgumentError(err)) => {
                let err_ = err.clone();
                stream.output(&self.params, Output::ArgumentError(err))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err_))
            }
            Err(Error::SystemError(err)) => {
                let err_ = err.clone();
                stream.output(&self.params, Output::SystemError(err))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err_))
            }
            Err(Error::OperationalError(err)) => {
                let err_ = err.clone();
                stream.output(&self.params, Output::OperationalError(err))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err_))
            }
        }
    }

    pub fn list_(&self, stream: &mut dyn Stream) -> Result<output::Report, Error>
    {
        let &Params {
            sequoia,
            ref queries,
            gossip,
            unusable,
            certification_network,
            trust_amount,
        } = &self.params;

        tracer!(TRACE, "authenticate");

        let queries_;
        let queries = if queries.is_empty() {
            queries_ = vec![ Query::all() ];
            &queries_
        } else {
            queries
        };

        let return_all = queries.iter().any(|q| matches!(q.kind, QueryKind::All));

        // Build the network.
        let cert_store = sequoia.cert_store_or_else()?;
        if return_all {
            cert_store.precompute();
        }

        let mut n = wot::NetworkBuilder::rooted(
            cert_store.as_ref(), &*sequoia.trust_roots());
        if certification_network {
            n = n.certification_network();
        }
        let n = n.build();

        let required_amount =
            required_trust_amount(trust_amount, certification_network);
        t!("required amount: {} (gossip: {})", required_amount, gossip);

        // Map a key handle to the named certificates.
        let resolve_key_handle = |kh: &KeyHandle| -> Vec<Arc<LazyCert<'_>>> {
            match kh {
                KeyHandle::Fingerprint(fpr) => {
                    if let Ok(cert) = cert_store.lookup_by_cert_fpr(&fpr) {
                        vec![ cert ]
                    } else {
                        // We don't error out here: at the end of this
                        // function we check that all queries matched at
                        // least one certificate.
                        vec![]
                    }
                },
                KeyHandle::KeyID(_) => {
                    cert_store.lookup_by_cert(&kh)
                        // We don't error out here: at the end of this
                        // function we check that all queries matched at
                        // least one certificate.
                        .unwrap_or_default()
                }
            }
        };

        // Get the candidates.
        //
        // The `bool` means: always show the certificate, even if it can't
        // be authenticated.  The `Vec<usize>` are the queries that
        // resolve to that binding.
        let mut bindings: Vec<(Fingerprint, Option<Arc<LazyCert>>, Option<UserID>, bool, Vec<usize>)>
            = Vec::new();

        // Whether query #index matched something.
        let mut queries_satisfied = vec![false; queries.len()];

        for (i, query) in queries.iter().enumerate() {
            match &query.kind {
                QueryKind::AuthenticatedCert(kh) | QueryKind::Cert(kh) => {
                    t!("Authenticating {}", kh);

                    let cert_authenticated
                        = matches!(query.kind, QueryKind::AuthenticatedCert(_));

                    for cert in resolve_key_handle(kh) {
                        let count = bindings.len();
                        bindings.extend(
                            n.certified_userids_of(&cert.fingerprint())
                                .into_iter()
                                .map(|userid| {
                                    (cert.fingerprint(), Some(cert.clone()),
                                     Some(userid),
                                     cert_authenticated, vec![ i ])
                                }));

                        if bindings.len() == count {
                            // No user IDs.  Add the certificate.
                            bindings.push((cert.fingerprint(), Some(cert), None,
                                           cert_authenticated, vec![ i ]));
                        }
                    }
                }
                QueryKind::UserID(userid) => {
                    t!("Authenticating user ID: {:?}", userid);

                    bindings.extend(
                        n.lookup_by_userid(&UserID::from(&userid[..]))
                            .unwrap_or(Vec::new())
                            .into_iter()
                            .map(|cert| {
                                (cert.fingerprint(), Some(cert),
                                 Some(UserID::from(&userid[..])),
                                 false, vec![ i ])
                            }));
                }
                QueryKind::EmailBinding(_, email) | QueryKind::Email(email) =>
                {
                    let kh = if let QueryKind::EmailBinding(kh, _) = &query.kind {
                        t!("Authenticating binding: {}, {:?}", kh, email);
                        Some(kh)
                    } else {
                        t!("Authenticating email: {:?}", email);
                        None
                    };

                    let userid_check = UserID::from(format!("<{}>", email));
                    if let Ok(Some(email_check)) = userid_check.email() {
                        if email != email_check {
                            return Err(Error::ArgumentError(
                                error::ArgumentError::InvalidEmail(
                                    error::InvalidEmail {
                                        email: email.to_owned(),
                                    })));
                        }
                    } else {
                        return Err(Error::ArgumentError(
                            error::ArgumentError::InvalidEmail(
                                error::InvalidEmail {
                                    email: email.to_owned(),
                                })));
                    }

                    // Now, iterate over all of the certifications of the target,
                    // and select the bindings where the User ID matches the email
                    // address.
                    let b = if let Some(kh) = kh.as_ref() {
                        let certs = resolve_key_handle(kh);
                        certs.into_iter().flat_map(|cert| {
                            n.certified_userids_of(&cert.fingerprint())
                                .into_iter()
                                .map(|userid| {
                                    (cert.fingerprint(), Some(cert.clone()),
                                     Some(userid))
                                })
                                .collect::<Vec<_>>()
                                .into_iter()
                        }).collect::<Vec<_>>()
                    } else {
                        // XXX: We can't (easily) use lookup_by_email
                        // because we need the matched user ID, which
                        // `lookup_synopses_by_email` returns, but
                        // `lookup_by_email` doesn't.
                        n.lookup_synopses_by_email(&email)
                            .into_iter()
                            .map(|(fpr, userid)| (fpr, None, Some(userid)))
                            .collect()
                    };

                    let email_normalized = userid_check.email_normalized()
                        .expect("checked").expect("checked");
                    bindings.extend(
                        b.into_iter().filter_map(|(fingerprint, cert, userid_other)| {
                            if let Some(email_other_normalized)
                                = userid_other.as_ref()
                                .and_then(|u| u.email_normalized().ok())
                                .flatten()
                            {
                                if email_normalized == email_other_normalized {
                                    Some((fingerprint, cert, userid_other.clone(),
                                          false, vec![ i ]))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }));
                }
                QueryKind::UserIDBinding(kh, userid) => {
                    t!("Authenticating {}, {:?}", kh, userid);
                    for cert in resolve_key_handle(kh) {
                        bindings.push(
                            (cert.fingerprint(),
                             Some(cert), Some(UserID::from(&userid[..])),
                             false, vec![ i ]));
                    }
                }
                QueryKind::Domain(pattern) | QueryKind::Pattern(pattern) => {
                    let pattern_;
                    let (query_params, pattern)
                        = if let QueryKind::Domain(_) = query.kind
                    {
                        t!("Authenticating domain {}", pattern);

                        let domain = UserIDQueryParams::is_domain(pattern)
                            .map_err(|err| {
                                Error::ArgumentError(
                                    error::ArgumentError::InvalidDomain(
                                        error::InvalidDomain {
                                            domain: pattern.to_owned(),
                                            error: err.into(),
                                        }))
                            })?;
                        let mut query_params = UserIDQueryParams::new();
                        query_params.set_email(true)
                            .set_anchor_start(false);
                        pattern_ = format!("@{}", domain);

                        (query_params, &pattern_)
                    } else {
                        if pattern.is_empty() {
                            t!("Authenticating everything");
                        } else {
                            t!("Authenticating user IDs matching {:?}", pattern);
                        }

                        let mut query_params = UserIDQueryParams::new();
                        query_params
                            .set_email(false)
                            .set_anchor_start(false)
                            .set_anchor_end(false)
                            .set_ignore_case(true);

                        (query_params, pattern)
                    };

                    if ! pattern.is_empty() {
                        // If the pattern doesn't match anything, don't
                        // abort yet.  There might be other queries.
                        if let Ok(matches)
                            = cert_store.select_userid(&query_params, pattern)
                        {
                            bindings.extend(
                                matches
                                    .into_iter()
                                    .flat_map(|cert| {
                                        cert.userids()
                                            .filter(|userid| {
                                                t!("Checking {}, {}",
                                                   cert.fingerprint(),
                                                   String::from_utf8_lossy(userid.value()));

                                                query_params.check(&userid, pattern)
                                            })
                                            .map(|userid| {
                                                (cert.fingerprint(),
                                                 Some(cert.clone()),
                                                 Some(userid), false, vec![ i ])
                                            })
                                            .collect::<Vec<_>>()
                                            .into_iter()
                                    }));
                        }
                    } else {
                        bindings.extend(
                            n.certified_userids()
                                .into_iter()
                                .map(|(fp, userid)| {
                                    (fp, None, Some(userid), false, vec![ i ])
                                }));
                    }
                }
                QueryKind::All => {
                    // --all is always satisfied.
                    queries_satisfied[i] = true;

                    let mut certs = BTreeSet::new();
                    bindings.extend(
                        n.certified_userids()
                            .into_iter()
                            .map(|(fp, userid)| {
                                certs.insert(fp.clone());

                                (fp, None, Some(userid), false, vec![ i ])
                            }));

                    // Add certificates without user IDs.
                    let all_certs: BTreeSet<_> = n.iter_fingerprints().collect();
                    bindings.extend(
                        all_certs.difference(&certs).map(|fp| {
                            (fp.clone(), None, None, false, vec![ i ])
                        }));
                }
            }
        }

        // There may be multiple certifications of the same
        // User ID.  Dedup.
        bindings.sort_by(
            |(a_fpr, _, a_userid, _, _), (b_fpr, _, b_userid, _, _)|
            {
                a_fpr.cmp(b_fpr)
                    .then(a_userid.cmp(b_userid))
            });
        bindings.dedup_by(
            |(a_fpr, _, a_userid, a_show, a_idx), (b_fpr, _, b_userid, b_show, b_idx)|
            {
                if a_fpr == b_fpr && a_userid == b_userid {
                    // debup removes a, so we merge into b.
                    b_idx.extend_from_slice(&a_idx[..]);
                    *b_show |= *a_show;
                    true
                } else {
                    false
                }
            });
        t!("Checking {} bindings", bindings.len());

        // The number of matching bindings that we showed.
        let mut bindings_authenticated = 0;

        // The number of bindings that we skipped because the certificate
        // or user ID was invalid / unusable.
        let mut bindings_unusable = 0;

        // Look up the certificate, and return it if it is valid.
        let check_cert = |fpr: &Fingerprint| -> Result<Cert> {
            // Look up the certificate.
            let kh = KeyHandle::from(fpr);
            let lc = match cert_store.lookup_by_cert(&kh) {
                Ok(certs) => {
                    assert_eq!(certs.len(), 1, "there can be only one");
                    certs.into_iter().next().unwrap()
                }
                Err(err) => {
                    // See if it is a subkey.
                    if let Some(StoreError::NotFound(_)) = err.downcast_ref() {
                        if let Ok(certs)
                            = cert_store.lookup_by_cert_or_subkey(&kh)
                        {
                            return Err(anyhow::anyhow!(
                                "{} appears to be a subkey of {}",
                                fpr,
                                certs.iter()
                                    .map(|c| c.fingerprint().to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")));
                        }
                    }

                    return Err(err);
                }
            };

            let cert = lc.to_cert()
                .with_context(|| format!("{} is unusable", fpr))?;

            // Check if the certificate is valid according to the current
            // policy.
            let vc = cert.with_policy(sequoia.policy(), sequoia.time())
                .with_context(|| format!("{} is unusable", fpr))?;

            // Check if the certificate is live.
            let _ = vc.alive()
                .with_context(|| format!("{} is not live", fpr))?;

            // Check that it is not revoked.
            if let RevocationStatus::Revoked(sigs)
                = cert.revocation_status(sequoia.policy(), sequoia.time())
            {
                if let Some((reason, message))
                    = sigs[0].reason_for_revocation()
                {
                    return Err(anyhow::anyhow!(
                        "{} is revoked: {}{}.",
                        cert.fingerprint(),
                        reason,
                        Safe(message)));
                } else {
                    return Err(anyhow::anyhow!(
                        "{} is revoked: unspecified reason.",
                        cert.fingerprint()));
                }
            }

            Ok(cert.clone())
        };

        // Check that the user ID is valid.
        let check_userid = |cert: &Cert, userid: &UserID| -> Result<()> {
            if let Some(ua)
                = cert.userids().find(|ua| ua.userid() == userid)
            {
                if let RevocationStatus::Revoked(sigs)
                    = ua.revocation_status(sequoia.policy(), sequoia.time())
                {
                    if let Some((reason, message))
                        = sigs[0].reason_for_revocation()
                    {
                        return Err(anyhow::anyhow!(
                            "{}, {} is revoked: {}{}.",
                            cert.fingerprint(),
                            userid,
                            reason,
                            Safe(message)));
                    } else {
                        return Err(anyhow::anyhow!(
                            "{}, {} is revoked: unspecified reason.",
                            cert.fingerprint(), userid));
                    }
                }
            }

            Ok(())
        };

        // bool: true if the lint is for the certificate (not the user ID).
        let mut lints: Vec<(Option<anyhow::Error>, bool, &[usize])>
            = Vec::with_capacity(queries.len());

        stream.output(&self.params, Output::StartOfBindings)
            .map_err(|err| Error::StreamOutputError(err))?;

        for (fingerprint, cert, userid, cert_authenticated, i) in bindings.iter() {
            if let Some(userid) = userid {
                let paths = if gossip {
                    n.gossip(fingerprint, userid.clone())
                } else {
                    n.authenticate(
                        userid.clone(), fingerprint, required_amount)
                };

                let aggregated_amount = paths.amount();
                t!("{}, {:?}: {}", fingerprint, userid, aggregated_amount);
                let userid_authenticated = if aggregated_amount >= required_amount {
                    // We authenticated the binding!
                    true
                } else if gossip && (aggregated_amount > 0 || unusable) {
                    // We're in gossip mode, show all bindings...
                    true
                } else if gossip && aggregated_amount == 0 {
                    // ... as long as the certificate is valid...
                    let cert = match check_cert(&fingerprint) {
                        Err(err) => {
                            t!("Skipping {}: certificate not valid: {}",
                               fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((Some(err), true, &i));
                            continue;
                        }
                        Ok(cert) => cert
                    };

                    // ... and the user ID is not revoked.
                    if let Err(err) = check_userid(&cert, &userid)
                    {
                        t!("Skipping {}, {}: {}", fingerprint, userid, err);
                        if ! *cert_authenticated {
                            bindings_unusable += 1;
                            lints.push((Some(err), false, &i));
                            continue;
                        }
                        false
                    } else {
                        true
                    }
                } else if *cert_authenticated {
                    // The binding is not authenticated, but we should
                    // show the certificate if it is valid.
                    if let Err(err) = check_cert(&fingerprint) {
                        t!("Skipping {}: {}", fingerprint, err);
                        bindings_unusable += 1;
                        lints.push((Some(err), true, &i));
                        continue;
                    }

                    false
                } else {
                    // Don't show it.
                    t!("Failed to sufficiently authenticate the binding");

                    if aggregated_amount == 0 {
                        if let Err(err) = check_cert(&fingerprint) {
                            t!("{}: {}", fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((Some(err), true, &i));
                        } else {
                            if ! n.certified_userids_of(fingerprint)
                                .contains(userid)
                            {
                                lints.push((
                                    Some(anyhow::anyhow!(
                                        "{:?} was never certified for {}",
                                        String::from_utf8_lossy(userid.value()),
                                        fingerprint)),
                                    false, &i));
                            }
                        }
                    }

                    continue;
                };

                let paths = if userid_authenticated {
                    bindings_authenticated += 1;
                    paths.into_iter().collect::<Vec<(wot::Path, usize)>>()
                } else {
                    vec![]
                };
                stream.output(
                    &self.params, Output::Binding(output::Binding {
                        fingerprint: fingerprint.clone(),
                        cert: if let Some(cert) = cert {
                            OnceLock::from(cert.clone())
                        } else {
                            OnceLock::new()
                        },
                        userid: Some(userid.clone()),
                        paths: paths,
                        aggregate_trust_amount: aggregated_amount,
                    }))
                    .map_err(|err| Error::StreamOutputError(err))?;
            } else {
                // A certificate with no User ID bindings.
                if gossip || *cert_authenticated {
                    if ! unusable {
                        if let Err(err) = check_cert(fingerprint) {
                            t!("Skipping {}: {}", fingerprint, err);
                            bindings_unusable += 1;
                            lints.push((Some(err), true, &i));
                            continue;
                        }
                    }

                    stream.output(
                        &self.params, Output::Binding(output::Binding {
                            fingerprint: fingerprint.clone(),
                            cert: if let Some(cert) = cert {
                                OnceLock::from(cert.clone())
                            } else {
                                OnceLock::new()
                            },
                            userid: None,
                            paths: vec![],
                            aggregate_trust_amount: 0,
                        }))
                        .map_err(|err| Error::StreamOutputError(err))?;
                    bindings_authenticated += 1;
                } else {
                    t!("Skipping {}: no user IDs", fingerprint);
                    continue;
                }
            }

            for i in i.into_iter() {
                queries_satisfied[*i] = true;
            }
        }

        stream.output(&self.params, Output::EndOfBindings)
            .map_err(|err| Error::StreamOutputError(err))?;

        let mut unsatisfied = Vec::new();
        let mut unsatisfied_lints = Vec::new();
        for (i, satisfied) in queries_satisfied.into_iter().enumerate() {
            if satisfied {
                continue;
            }
            // We didn't show anything.  Try to figure out what was wrong.
            let query = &queries[i];

            unsatisfied.push(query.clone());
            t!("Query {:?} is unsatisified", query);

            for (ref mut lint, for_cert, is) in lints.iter_mut() {
                if ! gossip && *for_cert {
                    use QueryKind::*;
                    match queries[i].kind {
                        AuthenticatedCert(_) | Cert(_)
                            | UserIDBinding(_, _) | EmailBinding(_, _) | All =>
                        {
                            ()
                        }
                        UserID(_) | Email(_) | Domain(_) | Pattern(_) => {
                            // It's a certificate-specific lint, but we're
                            // matching on user IDs.  Skip it.
                            continue;
                        }
                    }
                }
                if is.contains(&i) {
                    if let Some(lint) = lint.take() {
                        unsatisfied_lints.push((query.clone(), lint));
                    }
                }
            }
        }

        // See if the trust roots exist.
        let mut missing_trust_roots = Vec::new();
        if ! unsatisfied.is_empty() {
            for r in n.roots().iter() {
                let fpr = r.fingerprint();
                if let Err(err) = n.lookup_synopsis_by_fpr(&fpr) {
                    missing_trust_roots.push((fpr.clone(), err));
                }
            }
        }

        let bindings_not_authenticated
            = bindings.len() - bindings_authenticated - bindings_unusable;

        let report = output::Report {
            missing_trust_roots: if ! unsatisfied.is_empty() {
                Some((n.roots().clone(), missing_trust_roots))
            } else {
                None
            },
            query_lints: unsatisfied_lints,
            matching_bindings: bindings.len(),
            unsatisfied_queries: unsatisfied.clone(),
            authenticated_bindings: bindings_authenticated,
            unusable_bindings: bindings_unusable,
            unauthenticated_bindings: bindings_not_authenticated
        };

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::prompt::Cancel;

    fn check(sequoia: &Sequoia,
             output: Vec<Output>,
             expected_certs: &[(Fingerprint, Option<&str>, usize)])
    {
        let local_trust_root = sequoia.local_trust_root()
            .expect("have local trust root")
            .fingerprint();
        let generated_cert = sequoia.shadow_ca_generated_on()
            .expect("have generate on")
            .fingerprint();

        let mut saw_start_of_bindings = false;
        let mut saw_end_of_bindings = false;
        let mut saw_report = false;

        let expected_certs = BTreeSet::from_iter(
            expected_certs
                .into_iter()
                .map(|(fingerprint, userid, trust_amount)| {
                    (fingerprint.clone(),
                     userid.as_ref().map(|u| UserID::from(*u)),
                     *trust_amount)
                }));
        let mut got_certs = BTreeSet::new();

        let mut binding_count = 0;

        eprintln!("Start of cert list");
        for o in output.iter() {
            match o {
                Output::StartOfBindings => {
                    eprintln!("- Start of bindings");
                    assert!(! saw_start_of_bindings);
                    assert!(! saw_end_of_bindings);
                    assert!(! saw_report);
                    saw_start_of_bindings = true;
                }
                Output::Binding(binding) => {
                    eprintln!("- Binding: {}, {}, {}",
                              binding.fingerprint,
                              binding.userid
                                  .as_ref()
                                  .map(|userid| {
                                      String::from_utf8_lossy(userid.value())
                                          .to_string()
                                  })
                                  .unwrap_or_else(|| "<none>".into()),
                              binding.aggregate_trust_amount);
                    assert!(saw_start_of_bindings);
                    assert!(! saw_end_of_bindings);
                    assert!(! saw_report);

                    if binding.fingerprint == local_trust_root {
                        eprintln!("  (local trust root; skipping)");
                    } else if binding.fingerprint == generated_cert {
                        eprintln!("  (generated cert; skipping)");
                    } else {
                        got_certs.insert(
                            (binding.fingerprint.clone(),
                             binding.userid.clone(),
                             binding.aggregate_trust_amount));
                    }

                    assert_eq!(
                        binding.fingerprint,
                        binding
                            .cert(sequoia)
                            .expect("can get certificate")
                            .fingerprint());

                    binding_count += 1;
                }
                Output::EndOfBindings => {
                    eprintln!("- End of bindings");
                    assert!(saw_start_of_bindings);
                    assert!(! saw_end_of_bindings);
                    assert!(! saw_report);
                    saw_end_of_bindings = true;
                }
                Output::Report(report) => {
                    eprintln!("- Report");
                    assert!(saw_start_of_bindings);
                    assert!(saw_end_of_bindings);
                    assert!(! saw_report);
                    saw_report = true;

                    // If gossip is true, then not all returned
                    // bindings will be authenticated.
                    assert!(report.authenticated_bindings <= binding_count);
                }
                Output::ArgumentError(err) => {
                    panic!("Argument error: {}", err);
                }
                Output::OperationalError(err) => {
                    panic!("Operational error: {}", err);
                }
                Output::SystemError(err) => {
                    panic!("System error: {}", err);
                }
            }
        }
        eprintln!("End of cert list");

        assert!(saw_start_of_bindings);
        assert!(saw_end_of_bindings);
        assert!(saw_report);

        let missing = expected_certs.difference(&got_certs)
            .collect::<Vec<_>>();
        if missing.len() > 0 {
            eprintln!("{} missing bindings:", missing.len());
            for (fingerprint, userid, aggregate_trust_amount) in missing.iter() {
                eprintln!("  - {}, {}, {}",
                          fingerprint,
                          userid
                              .as_ref()
                              .map(|userid| {
                                  String::from_utf8_lossy(userid.value())
                                      .to_string()
                              })
                              .unwrap_or_else(|| "<none>".into()),
                          aggregate_trust_amount);
            }
        }
        let unexpected = got_certs.difference(&expected_certs)
            .collect::<Vec<_>>();
        if unexpected.len() > 0 {
            eprintln!("{} unexpected bindings:", unexpected.len());
            for (fingerprint, userid, aggregate_trust_amount) in unexpected.iter() {
                eprintln!("  - {}, {}, {}",
                          fingerprint,
                          userid
                              .as_ref()
                              .map(|userid| {
                                  String::from_utf8_lossy(userid.value())
                                      .to_string()
                              })
                              .unwrap_or_else(|| "<none>".into()),
                          aggregate_trust_amount);
            }
        }
        assert_eq!(missing.len(), 0);
        assert_eq!(unexpected.len(), 0);
    }

    #[test]
    fn cert_list_empty() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .list(&mut output)
            .expect("ok");
        check(&sq, output, &[]);

        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .gossip(true)
            .list(&mut output)
            .expect("ok");
        check(&sq, output, &[]);
    }

    #[test]
    fn cert_list_generated() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        // Generate a key and import it into the certificate store.
        // This will marked it as a trusted introducer.
        let alice = sq.key_generate()
            .email("alice@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate a key")
            .into_cert();

        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .list(&mut output)
            .expect("ok");
        check(&sq, output,
              &[(alice.fingerprint(), Some("<alice@example.org>"), 120)]);

        // In gossip mode, we don't stop at 120.  It will also get 1
        // point of trust amount from the "Generated on host" shadow
        // CA.
        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .gossip(true)
            .list(&mut output)
            .expect("ok");
        check(&sq, output,
              &[(alice.fingerprint(), Some("<alice@example.org>"), 121)]);
    }


    #[test]
    fn cert_list_imported() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let local_trust_root = sq.local_trust_root()
            .expect("have local trust root")
            .to_cert()
            .expect("local trust root is valid")
            .clone();

        // Generate a key, manually import it into the certificate
        // store, and manually mark it as a trusted introducer.
        let gen = |email: &str, certifier: Option<(&Cert, u8, u8)>|
        {
            let cert = sq.key_generate()
                .email(email)
                .without_password()
                .ephemeral()
                .generate(Cancel::new())
                .expect("can generate a key")
                .into_cert();

            let mut stats = Default::default();
            sq.key_import()
                .import_key(cert.clone(), &mut stats)
                .expect("can import key");

            if let Some((certifier, trust_depth, trust_amount)) = certifier {
                sq.pki_certify()
                    .trust_depth(trust_depth)
                    .trust_amount(trust_amount)
                    .certify(&certifier,
                             &cert,
                             &[UserID::from(format!("<{}>", email))],
                             Cancel::new())
                    .expect("can certify");
            }

            cert
        };

        let alice = gen("alice@example.org", Some((&local_trust_root, 1, 120)));
        let alice_binding
            = (alice.fingerprint(), Some("<alice@example.org>"), 120);

        let bob = gen("bob@example.org", Some((&alice, 1, 120)));
        let bob_binding
            = (bob.fingerprint(), Some("<bob@example.org>"), 120);

        let carol = gen("carol@example.org", Some((&bob, 0, 120)));
        let carol_binding
            = (carol.fingerprint(), Some("<carol@example.org>"), 0);

        let dave = gen("dave@example.org", None);
        let dave_binding
            = (dave.fingerprint(), Some("<dave@example.org>"), 0);

        // List authenticated bindings.
        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .list(&mut output)
            .expect("ok");
        check(&sq, output,
              &[
                  alice_binding.clone(),
                  bob_binding.clone(),
              ]);

        // List all bindings.
        let mut output = Vec::new();
        sq.cert_list(std::iter::empty())
            .gossip(true)
            .list(&mut output)
            .expect("ok");
        check(&sq, output,
              &[
                  alice_binding.clone(),
                  bob_binding.clone(),
                  carol_binding.clone(),
                  dave_binding.clone(),
              ]);

        // List individual bindings in different ways.
        for binding in [
            &alice_binding,
            &bob_binding,
            &carol_binding,
            &dave_binding,
        ] {
            // By unauthenticated certificate.
            let mut output = Vec::new();
            sq.cert_list(
                Some(Query::unauthenticated_cert(binding.0.clone().into())))
                .list(&mut output)
                .expect("ok");
            if binding.2 >= 120 {
                check(&sq, output, &[ binding.clone(), ]);
            } else {
                check(&sq, output, &[ ]);
            }

            let mut output = Vec::new();
            sq.cert_list(
                Some(Query::unauthenticated_cert(binding.0.clone().into())))
                .gossip(true)
                .list(&mut output)
                .expect("ok");
            check(&sq, output, &[ binding.clone(), ]);

            // By authenticated certificate.
            let mut output = Vec::new();
            sq.cert_list(
                Some(Query::authenticated_cert(binding.0.clone().into())))
                .list(&mut output)
                .expect("ok");
            check(&sq, output, &[ binding.clone(), ]);

            let mut output = Vec::new();
            sq.cert_list(
                Some(Query::authenticated_cert(binding.0.clone().into())))
                .gossip(true)
                .list(&mut output)
                .expect("ok");
            check(&sq, output, &[ binding.clone(), ]);

            // By user ID.
            if let Some(userid) = binding.1 {
                let mut output = Vec::new();
                sq.cert_list(
                    Some(Query::userid(userid)))
                    .list(&mut output)
                    .expect("ok");
                if binding.2 >= 120 {
                    check(&sq, output, &[ binding.clone(), ]);
                } else {
                    check(&sq, output, &[ ]);
                }

                let mut output = Vec::new();
                sq.cert_list(
                    Some(Query::userid(userid)))
                    .gossip(true)
                    .list(&mut output)
                    .expect("ok");
                check(&sq, output, &[ binding.clone(), ]);
            }
        }

        // And queries that don't match anything.
        let mut output = Vec::new();
        sq.cert_list(
            Some(Query::unauthenticated_cert(
                "012345678901234567890123456789".parse().expect("valid"))))
            .list(&mut output)
            .expect("ok");
        check(&sq, output, &[ ]);

        let mut output = Vec::new();
        sq.cert_list(
            Some(Query::authenticated_cert(
                "012345678901234567890123456789".parse().expect("valid"))))
            .list(&mut output)
            .expect("ok");
        check(&sq, output, &[ ]);

        let mut output = Vec::new();
        sq.cert_list(
            Some(Query::userid("not present")))
            .list(&mut output)
            .expect("ok");
        check(&sq, output, &[ ]);
    }

    #[test]
    fn cert_list_bad_argument() {
        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut output = Vec::new();
        let result = sq.cert_list(Some(Query::email("invalid@email@domain.com")))
            .list(&mut output);

        // Check the function's return value.
        let Err(err) = result else {
            panic!("Failed to catch invalid argument");
        };
        let Error::ArgumentError(err) = err else {
            panic!("Failed to return ArgumentError");
        };
        let error::ArgumentError::InvalidEmail(_err) = err else {
            panic!("Failed to return InvalidEmail");
        };

        // Make sure the error was also reported via the stream interface.
        assert_eq!(output.len(), 1,
                   "Unexpected stream output");
        let output = output.into_iter().next().unwrap();
        let Output::ArgumentError(err) = output else {
            panic!("Stream didn't return invalid argument");
        };
        let error::ArgumentError::InvalidEmail(_err) = err else {
            panic!("Failed to return InvalidEmail");
        };
    }

    #[test]
    fn cert_list_no_home() {
        let sq = Sequoia::builder().ephemeral().unwrap().stateless().build().unwrap();

        let mut output = Vec::new();
        let result = sq.cert_list(Some(Query::email("email@domain.com")))
            .list(&mut output);

        // Check the function's return value.
        let Err(err) = result else {
            panic!("Failed to catch missing home error");
        };
        let Error::SystemError(err) = &err else {
            panic!("Failed to return SystemError, got: {:?}", err);
        };
        let SystemError::CertStoreDisabled = err else {
            panic!("Failed to return CertStoreDisabled, got: {:?}", err);
        };

        // Make sure the error was also reported via the stream interface.
        assert_eq!(output.len(), 1,
                   "Unexpected stream output");
        let output = output.into_iter().next().unwrap();
        let Output::SystemError(err) = output else {
            panic!("Stream didn't return CertStoreDisable");
        };
        let SystemError::CertStoreDisabled = err else {
            panic!("Failed to return CertStoreDisabled");
        };

    }
}
