//! Search for certificates on the network.
//!
//! Searches for certificates on key servers
//! ([`keys.openpgp.org`](https://keys.openpgp.org),
//! [`keys.mailvelope.com`](https://keys.mailvelope.com), [Proton's
//! key server](https://proton.me), [the SKS key server
//! network](https://spider.pgpkeys.eu/) and [Ubuntu's key
//! server](https://keyserver.ubuntu.com/)), in WKDs, using DANE, and
//! in web pages.
//!
//! By default, the search function checks all of these sources in
//! parallel, and uses the results to make additional queries.  For
//! instance, when searching by fingerprint, it is not possible to
//! search in WKDs or using DANE, because those can only be searched
//! by email address.  To work around this, after finding a
//! certificate on a key server, the search function makes additional
//! queries based on the self-signed user IDs.  By default, the
//! function will iterate up to three times.  This results in a more
//! complete view of the certificate.
//!
//! By checking multiple sources, the search function is more
//! resilient to an attacker who wants to withhold information: the
//! attacker needs to control many sources, not just one to trick the
//! victim.
//!
//! Note: this approach means that even when searching by fingerprint,
//! the search function may return other certificates.
//!
//! When certificates are downloaded from well-known authorities, like
//! a verifying key server, WKD or DANE, a so-called shadow CA (see
//! [`Ca`]) certify the returned bindings.  The shadow CAs are local
//! certificates, which are minimally trusted (although the user can
//! change this).  By default, this is not enough to authenticate a
//! binding, but it does provide the user some information, which they
//! can use to make a more informed decision.
//!
//! # Examples
//!
//! Search for certificates by email address ([`Query`]) and
//! automatically add the results to the certificate store:
//!
//! ```rust
//! use sequoia::Sequoia;
//! use sequoia::network::search::Query;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let rt = tokio::runtime::Runtime::new()
//! #   .expect("can create tokio run time");
//! #
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key");
//! #
//! # rt.block_on(async {
//! sq.network_search()
//! #   .clear_sources()
//! #   .query_cert_store(true)
//!     .search(
//!         vec![Query::Address("alice@example.org".to_string())],
//!         // If a shadow CA is password protected, don't prompt for
//!         // a password; ignore it;
//!         Cancel::new())
//!     .await?;
//! # Ok::<(), anyhow::Error>(())
//! # })?;
//! # Ok(()) }
//! ```
//!
//! As above, but display a progress bar, and show the certificates as
//! they are fetched by implementing [`Stream`] and matching on the
//! relevant [`Output`] variants:
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::network::search::Query;
//! use sequoia::network::search;
//! use sequoia::prompt::Cancel;
//!
//! struct Stream {
//!     requests: usize,
//!     responses: usize,
//! }
//!
//! impl search::Stream for Stream {
//!     fn output(&mut self, params: &search::Params, output: search::Output)
//!         -> Result<(), anyhow::Error>
//!     {
//!         match output {
//!             // Display a primitive progress bar.
//!             search::Output::RequestQueued(_) => {
//!                 self.requests += 1;
//!                 eprintln!("{}/{}", self.responses, self.requests);
//!             }
//!             search::Output::Response(_) => {
//!                 self.responses += 1;
//!                 eprintln!("{}/{}", self.responses, self.requests);
//!             }
//!
//!             search::Output::CertResult(result) => {
//!                 eprintln!("Got {}", result.cert.fingerprint());
//!             }
//!             _ => (),
//!         }
//!         // Return an error to abort; `Ok` to continue.
//!         Ok(())
//!     }
//! }
//!
//! # fn main() -> anyhow::Result<()> {
//! # let rt = tokio::runtime::Runtime::new()
//! #   .expect("can create tokio run time");
//! #
//! # let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();
//! #
//! # let alice = sq.key_generate()
//! #     .email("alice@example.org")
//! #     .without_password()
//! #     .generate(Cancel::new())
//! #     .expect("can generate a key");
//! #
//! # rt.block_on(async {
//! let mut stream = Stream {
//!     requests: 0,
//!     responses: 0,
//! };
//!
//! sq.network_search()
//!     .stream(&mut stream)
//! #   .clear_sources()
//! #   .query_cert_store(true)
//!     .search(
//!         vec![Query::Address("alice@example.org".to_string())],
//!         // If a shadow CA is password protected, don't prompt for
//!         // a password; ignore it;
//!         Cancel::new())
//!     .await?;
//! # Ok::<(), anyhow::Error>(())
//! # })?;
//! # Ok(()) }
//! ```
//!
//! Alternatively, you can pass `&mut Vec<Output>` to gather the
//! output and inspect it afterwards.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use tokio::task::JoinSet;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::armor;
use openpgp::cert::Cert;
use openpgp::cert::CertParser;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use sequoia_net as net;
use net::KeyServer;
use net::dane;
use net::reqwest::Url;
use net::wkd;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::Ca;
use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::Writer;
use crate::cert::cert_exportable;
use crate::config::DEFAULT_KEYSERVERS;
use crate::destination::Destination;
use crate::destination::DestinationSummary;
use crate::network::http_client;
use crate::prompt::Prompt;
use crate::provenance::certify_downloads;
use crate::types::import_stats::ImportStats;

/// The type of query.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Query {
    /// Search by key handle.
    Handle(KeyHandle),
    /// Search for an email address.
    Address(String),
    /// Fetch a URL.
    Url(Url),
}

impl From<Fingerprint> for Query {
    fn from(fp: Fingerprint) -> Query {
        Query::Handle(fp.into())
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Handle(h) => write!(f, "{}", h),
            Query::Address(a) => write!(f, "{}", a),
            Query::Url(u) => write!(f, "{}", u),
        }
    }
}

impl Query {
    /// Converts the search strings to queries.
    pub fn parse(args: &[String]) -> Result<Vec<Query>> {
        args.iter().map(
            |q| if let Ok(h) = q.parse::<KeyHandle>() {
                Ok(Query::Handle(h))
            } else if let Ok(Some(addr)) = UserID::from(q.as_str()).email() {
                Ok(Query::Address(addr.to_string()))
            } else if let Ok(url) = Url::parse(q.as_str()) {
                Ok(Query::Url(url))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     an http or https Url, or an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Parses strings to queries suitable for key servers.
    ///
    /// This detects fingerprints, key ID, and email addresses.
    /// Anything else results in an error.
    pub fn parse_keyserver_queries(args: &[String]) -> Result<Vec<Query>> {
        args.iter().map(
            |q| if let Ok(h) = q.parse::<KeyHandle>() {
                Ok(Query::Handle(h))
            } else if let Ok(Some(addr)) = UserID::from(q.as_str()).email() {
                Ok(Query::Address(addr.to_string()))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     or an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Returns all known addresses and fingerprints of exportable
    /// certificates as queries.
    pub fn all_certs(sequoia: &Sequoia) -> Result<Vec<Query>> {
        if let Some(store) = sequoia.cert_store()? {
            let mut fingerprints = HashSet::new();
            let mut addresses = HashSet::new();
            for cert in store.certs().filter(
                |c| c.to_cert().map(|c| cert_exportable(c)).unwrap_or(false))
            {
                fingerprints.insert(cert.fingerprint());
                for address in cert.userids().filter_map(
                    |uid| uid.email().ok().flatten().map(|s| s.to_string()))
                {
                    addresses.insert(address);
                }
            }

            Ok(fingerprints.into_iter().map(|fp| Query::Handle(fp.into()))
               .chain(addresses.into_iter().map(Query::Address))
               .collect())
        } else {
            Err(anyhow::anyhow!("no known certificates"))
        }
    }


    /// Returns all known addresses of exportable certificates as
    /// queries.
    pub fn all_addresses(sequoia: &Sequoia) -> Result<Vec<Query>> {
        if let Some(store) = sequoia.cert_store()? {
            let mut addresses = store.certs()
                .filter(
                    |c| c.to_cert().map(|c| cert_exportable(c)).unwrap_or(false))
                .flat_map(|cert| cert.userids().filter_map(
                    |uid| uid.email().ok().flatten().map(|s| s.to_string()))
                          .collect::<Vec<_>>())
                .collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            Ok(addresses.into_iter().map(Query::Address).collect())
        } else {
            Err(anyhow::anyhow!("no known certificates"))
        }
    }

    /// Converts email addresses to queries.
    ///
    /// Arguments that are not email addresses result in an error.
    pub fn parse_addresses(args: &[String]) -> Result<Vec<Query>> {
        args.iter().map(
            |q| if let Ok(Some(addr)) = UserID::from(q.as_str()).email() {
                Ok(Query::Address(addr.to_string()))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Returns the email address, if any.
    fn as_address(&self) -> Option<&str> {
        if let Query::Address(a) = self {
            Some(a)
        } else {
            None
        }
    }

    /// Returns the query if suitable for keyservers.
    fn as_keyserver_query(&self) -> Option<&Query> {
        match self {
            Query::Address(_) => Some(self),
            Query::Handle(_) => Some(self),
            _ => None,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if let Query::Address(email) = self {
            UserID::from(&format!("<{}>", email)[..]).email()
                .map_err(|err| {
                    Error::ArgumentError(
                        error::ArgumentError::MalformedQuery(
                            error::MalformedQuery {
                                query: self.clone(),
                                error: err.into(),
                            }))
                })?;
        }
        Ok(())
    }
}

/// The source of a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Source {
    KeyServer(String),
    WKD,
    DANE,
    Http(Url),
    CertStore,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::KeyServer(url) => write!(f, "{}", url),
            Source::WKD => write!(f, "WKD"),
            Source::DANE => write!(f, "DANE"),
            Source::Http(_) => write!(f, "http"),
            Source::CertStore => write!(f, "cert-store"),
        }
    }
}

impl Source {
    /// Returns the CA's certificate.
    ///
    /// Returns `Ok(None)` if the source does not have a shadow CA, or
    /// the certificate store is disabled.
    fn ca(&self, sequoia: &Sequoia)
        -> Result<Option<Ca>>
    {
        let Ok(cert_store) = sequoia.cert_store_or_else() else {
            return Ok(None);
        };
        let Some(_) = cert_store.certd() else {
            return Ok(None);
        };

        let result = match self {
            Source::KeyServer(url) => {
                sequoia.shadow_ca_keyserver(url)?
            }
            Source::WKD => Some(sequoia.shadow_ca_wkd()?),
            Source::DANE => Some(sequoia.shadow_ca_dane()?),
            Source::Http(url) =>
                if let Some(r) = sequoia.shadow_ca_for_url(url.as_ref())? {
                    Some(r)
                } else {
                    return Ok(None);
                },
            Source::CertStore => return Ok(None),
        };

        // Check that the data is a valid certificate.  If not,
        // bail sooner rather than later.
        if let Some(ca) = result.as_ref() {
            let _ = ca.cert().to_cert()?;
        }

        Ok(result)
    }
}

// Stream trait.
stream!{}

/// Data structures related to [`Error`].
///
/// The errors are divided into categories, and the categories contain
/// more precise errors.  In this way, if you match on a category, and
/// a new error is added you can still react.
pub mod error {
    use super::*;

    /// The query is invalid.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Malformed query: {:?}", .query)]
    pub struct MalformedQuery {
        pub query: Query,

        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// The specified key server is invalid.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Malformed keyserver URI: {:?}", .server)]
    pub struct MalformedKeyserverUri {
        pub server: String,

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
        MalformedQuery(MalformedQuery),

        #[error(transparent)]
        MalformedKeyserverUri(MalformedKeyserverUri),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }

    /// We failed to update a certificate on the certificate store.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Inserting {}", .cert.fingerprint())]
    pub struct UpdatingCert {
        /// The certificate being written to the certificate store.
        pub cert: Arc<LazyCert<'static>>,

        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// We failed to serialize the keyring.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Error serializing keyring")]
    pub struct SerializingKeyring {
        #[source]
        pub error: Arc<anyhow::Error>,
    }

    /// We failed to execute the query.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("Error executing query {} against {}",
            .query, .source)]
    pub struct ExecutingQuery {
        pub query: Query,
        pub source: Source,
        #[source]
        pub error: Arc<anyhow::Error>,
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
        UpdatingCert(UpdatingCert),

        #[error(transparent)]
        SerializingKeyring(SerializingKeyring),

        #[error(transparent)]
        ExecutingQuery(ExecutingQuery),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to searching the network for certificates.
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

/// Data structures related to [`Output`].
pub mod output {
    use super::*;

    /// A request has been queued.
    ///
    /// A query is turned into a request for each relevant source.
    /// For instance, a query for an email address will be sent to
    /// both the WKD and the DANE sources, if they are enabled.  As
    /// such, there may be multiple results corresponding to the same
    /// query.
    ///
    /// A query may also result in no requests if none of the enabled
    /// sources can handle it.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct RequestQueued {
        pub query: Query,
        pub source: Source,

        /// A mono-atomically increasing counter.
        ///
        /// This event can be paired with the [`Response`] event using
        /// this field.
        ///
        /// The first request has a request ID of 0.  So this counter
        /// also indicates the total number of requests that have been
        /// queued prior to this one.
        pub request: usize,
    }

    /// A response to a result.
    ///
    /// This is emitted when a request returns.  The certificates are
    /// the data as returned by the source; they have not yet been
    /// merged.
    ///
    /// A query is turned into a request for each relevant source.
    /// For instance, a query for an email address will be sent to
    /// both the WKD and the DANE sources, if they are enabled.  As
    /// such, there may be multiple results corresponding to the same
    /// query.
    ///
    /// If `results` is an error, the error is not fatal, but it can
    /// be helpful to display it when debugging.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Response {
        pub query: Query,
        pub source: Source,

        /// A mono-atomically increasing counter.
        ///
        /// This event can be paired with the [`RequestQueued`] event
        /// using this field.
        ///
        /// The first request has a request ID of 0.  So this counter
        /// also indicates the total number of requests that have been
        /// queued prior to this one.
        pub request: usize,

        /// The response.
        ///
        /// The outer `Result` indicates whether the request failed
        /// completely.  The inner `Result`s correspond to each of the
        /// returned results.  For instance, a key server may return
        /// multiple matching certificates, but one of those
        /// certificates may be so corrupted that it can't be parsed.
        /// In that case, the parse error will be stored instead of
        /// the certificate that couldn't be parsed.
        pub results: Result<Vec<Result<Cert, error::OperationalError>>,
                            error::OperationalError>,
    }

    /// Information related to a particular source and certificate.
    ///
    /// This data structure is part of [`CertResult`].  See it for
    /// details.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct SourceInfo {
        pub source: Source,

        /// The shadow CA for this source that certified the
        /// certificate on import.
        ///
        /// `None` means that there is no shadow CA associated with
        /// this source.  This is always `None` if the certificate
        /// store is disabled and shadow CAs are disabled.  But it is
        /// also `None` for sources that provide no authentication
        /// information.  For instance, a key server is only
        /// associated with a shadow CA if the key server is known to
        /// be a verifying key server.
        ///
        /// An error means that we were unable to get the shadow CA.
        /// This is usually a sign of corruption.
        ///
        /// Note: a CA may be returned here even if it didn't certify
        /// the certificate this time, but did in the past.
        pub ca: Option<Result<Ca, Arc<anyhow::Error>>>,
    }

    /// A final, merged certificate.
    ///
    /// This returns a merged certificate.  The certificate is the
    /// result of merging the intermediate results.
    ///
    /// Note: when this is emitted, the certificate has not yet been
    /// written out.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct CertResult {
        pub sources: Vec<SourceInfo>,
        pub cert: Cert,
    }

    /// A report about the operation.
    ///
    /// This is emitted once after attempting to create the
    /// certifications.
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct Report {
        /// Statistics about certificates imported into the
        /// certificate store.
        ///
        /// This is only updated when the certificates are imported
        /// into the certificate store.
        pub import_stats: ImportStats,
    }

    impl Report {
        pub(super) fn new() -> Self {
            Report {
                import_stats: ImportStats::default(),
            }
        }
    }
}

/// The variants of this enum are the different types of output that
/// [`network_search`](Builder::search) emits.
#[non_exhaustive]
#[derive(Debug)]
pub enum Output {
    /// An operational error occurred.
    ///
    /// This may be because the operation requires the certificate
    /// store, but it is disabled.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    OperationalError(error::OperationalError),

    /// A system error that prevents processing from continuing.
    ///
    /// System errors are fatal and cause processing to abort.
    ///
    /// System errors are related to the system.  An example of a
    /// system error is that a key store is not available, but is
    /// needed to complete the operation.
    SystemError(SystemError),

    /// Errors related to incorrectly calling the function.
    ///
    /// This error is unrecoverable, and the rest of the operation
    /// will be aborted.
    ArgumentError(error::ArgumentError),

    /// A request has been queued.
    ///
    /// A query is turned into a request for each relevant source.
    /// For instance, a query for an email address will be sent to
    /// both the WKD and the DANE sources, if they are enabled.  As
    /// such, there may be multiple results corresponding to the same
    /// query.
    ///
    /// A query may also result in no requests if none of the enabled
    /// sources can handle it.
    RequestQueued(output::RequestQueued),

    /// A response to a result.
    ///
    /// This is emitted when a request returns.  The certificates are
    /// the data as returned by the source; they have not yet been
    /// merged.
    ///
    /// A query is turned into a request for each relevant source.
    /// For instance, a query for an email address will be sent to
    /// both the WKD and the DANE sources, if they are enabled.  As
    /// such, there may be multiple results corresponding to the same
    /// query.
    ///
    /// If `results` is an error, the error is not fatal, but it can
    /// be helpful to display it when debugging.
    Response(output::Response),

    /// We're about to emit the results.
    ///
    /// Note: this is emitted even if there are no results.
    StartOfResults,

    /// A final, merged result.
    ///
    /// This returns a final result.  The certificate is the result of
    /// merging the intermediate results.
    ///
    /// Note: when this is emitted, the certificate has not yet been
    /// written out.
    CertResult(output::CertResult),

    /// All of the certificate that will be returned have been
    /// returned.
    ///
    /// Now's a good time to output any statistics.
    EndOfResults,

    /// Emitted at the end.
    ///
    /// This is always emitted whether anything is found or not.
    Report(output::Report),
}

/// Parameters to the network search function.
///
/// The parameters passed to [`Sequoia::network_search`].
pub struct Params<'sequoia> {
    sequoia: &'sequoia Sequoia,
    iterations: u8,
    servers: Vec<Cow<'static, str>>,
    query_key_servers: bool,
    query_wkd: bool,
    query_dane: bool,
    query_web: bool,
    query_cert_store: bool,
    destination: DestinationSummary,
}

impl<'sequoia> Params<'sequoia> {
    /// Returns the sequoia instance.
    pub fn sequoia(&self) -> &'sequoia Sequoia {
        self.sequoia
    }

    destination_params_impl!("certificates", "are");

    /// The number of times to iterate.
    ///
    /// The search function starts with one or more queries to
    /// execute, and then uses the results to derive related queries,
    /// which it then executes.  This parameter determines the maximum
    /// number of times the function will iterate.
    ///
    /// Consider searching for a certificate by fingerprint.  The
    /// search function can query key servers, but it cannot search in
    /// WKDs or using DANE, because they are keyed by email address,
    /// not fingerprint.  These sources may contain important
    /// information that is not available on the key servers either
    /// because it hasn't yet been propagate to them or it was
    /// stripped due to the server's policy or a bad actor.  To
    /// provide a more complete result, the search function generates
    /// queries based on the certificates that were found in the
    /// previous iteration, and then executes those queries in the
    /// next iteration.  In this case, it would generate a query for
    /// each self-signed user ID.  This approach is similar to how a
    /// web crawler works: after fetching a web page, it extracts the
    /// links, and then visits those web pages.
    ///
    /// By checking multiple sources, the search function is more
    /// resilient to an attacker who wants to withhold information:
    /// the attacker needs to control many sources, not just one.
    ///
    /// By default, the search function iterates three times or until
    /// an iteration does not result in a new queries, whichever
    /// happens first.
    pub fn iterations(&self) -> u8 {
        self.iterations
    }

    /// Returns the configured key servers.
    pub fn key_servers(&self) -> impl Iterator<Item=&str> {
        self.servers.iter().map(|s| &s[..])
    }

    /// Whether to query key servers.
    ///
    /// Key servers can be queried by address, and by fingerprint.
    ///
    /// See
    /// [draft-ietf-openpgp-hkp-01](https://datatracker.ietf.org/doc/draft-ietf-openpgp-hkp/)
    /// for more information.
    pub fn query_key_servers(&self) -> bool {
        self.query_key_servers
    }

    /// Whether to query WKD servers.
    ///
    /// WKD stands for web key directory.  A WKD directory can be
    /// queried by address for the domain that it manages.  A WKD is
    /// stored on a web server, and it only serves certificates for
    /// the same domain.  As such, it can be seen as a weak authority
    /// for the certificates that it serves.
    ///
    /// See
    /// [draft-koch-openpgp-webkey-service](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/)
    /// for more information.
    pub fn query_wkd(&self) -> bool {
        self.query_wkd
    }

    /// Whether to use DANE.
    ///
    /// DANE stands for DNS-Based Authentication of Named Entities.
    /// It defines a way to store OpenPGP certificates in DNS, and
    /// query them.  It is protected by DNSSEC.  As such, it can be
    /// seen as a weak authority for the certificates that it serves.
    ///
    /// See [RFC 7929](https://datatracker.ietf.org/doc/rfc7929/) for
    /// more information.
    pub fn query_dane(&self) -> bool {
        self.query_dane
    }

    /// Whether to query the web.
    ///
    /// Fetches a web page and extracts any certificates it finds.
    ///
    /// The web is the only backend that resolves URLs.
    pub fn query_web(&self) -> bool {
        self.query_web
    }

    /// Whether to query the local certificate store.
    ///
    /// When enabled, the local certificate store is queried.  This is
    /// useful to prime the query.  See [`Builder::iterations`] for
    /// why this is useful.
    pub fn query_cert_store(&self) -> bool {
        self.query_cert_store
    }
}

/// Owned parameters.
struct ParamsOnce<'writer, 'stream> {
    destination: Destination<Writer<'writer>>,
    stream: Option<Box<dyn Stream + 'stream>>,
}

/// Search for certificates on the network.
pub struct Builder<'sequoia, 'writer, 'stream> {
    params: Params<'sequoia>,
    params_once: ParamsOnce<'writer, 'stream>,
}

impl<'sequoia, 'writer, 'stream> Builder<'sequoia, 'writer, 'stream> {
    pub(crate) fn new(sequoia: &'sequoia Sequoia)
        -> Builder<'sequoia, 'writer, 'stream>
    {
        Builder {
            params: Params {
                sequoia,
                iterations: 3,
                servers: DEFAULT_KEYSERVERS
                    .iter()
                    .map(|s| Cow::Borrowed(*s))
                    .collect(),
                query_key_servers: true,
                query_wkd: true,
                query_dane: true,
                query_web: true,
                query_cert_store: true,
                destination: DestinationSummary::Store,
            },
            params_once: ParamsOnce {
                destination: Destination::Store,
                stream: None,
            },
        }
    }

    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'sequoia> {
        &self.params
    }

    destination_builder_impl!('sequoia; 'stream; "certificates", "are");

    stream_builder_impl!('sequoia, 'writer;);

    /// The number of times to iterate.
    ///
    /// The search function starts with one or more queries to
    /// execute, and then uses the results to derive related queries,
    /// which it then executes.  This parameter determines the maximum
    /// number of times the function will iterate.
    ///
    /// Consider searching for a certificate by fingerprint.  The
    /// search function can query key servers, but it cannot search in
    /// WKDs or using DANE, because they are keyed by email address,
    /// not fingerprint.  These sources may contain important
    /// information that is not available on the key servers either
    /// because it hasn't yet been propagate to them or it was
    /// stripped due to the server's policy or a bad actor.  To
    /// provide a more complete result, the search function generates
    /// queries based on the certificates that were found in the
    /// previous iteration, and then executes those queries in the
    /// next iteration.  In this case, it would generate a query for
    /// each self-signed user ID.  This approach is similar to how a
    /// web crawler works: after fetching a web page, it extracts the
    /// links, and then visits those web pages.
    ///
    /// By checking multiple sources, the search function is more
    /// resilient to an attacker who wants to withhold information:
    /// the attacker needs to control many sources, not just one.
    ///
    /// By default, the search function iterates three times or until
    /// an iteration does not result in a new queries, whichever
    /// happens first.
    pub fn iterations(mut self, iterations: u8) -> Self {
        self.params.iterations = iterations;
        self
    }

    /// Sets the set of key servers to query.
    ///
    /// This clears any key servers.  To add to the set of key
    /// servers, use [`Builder::add_key_servers`].
    pub fn set_key_servers<S>(mut self,
                              key_servers: impl IntoIterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.servers = key_servers
            .into_iter()
            .map(|s| Cow::Owned(s.as_ref().to_string()))
            .collect();
        self
    }

    /// Adds the key server to the set of key servers to query.
    pub fn add_key_server<S>(mut self, key_server: S) -> Self
    where
        S: AsRef<str>
    {
        self.params.servers.push(
            Cow::Owned(key_server.as_ref().to_string()));
        self
    }

    /// Adds the key servers to the set of key servers to query.
    pub fn add_key_servers<S>(mut self,
                              key_servers: impl IntoIterator<Item=S>)
        -> Self
    where
        S: AsRef<str>
    {
        self.params.servers.extend(
            key_servers.into_iter().map(|s| Cow::Owned(s.as_ref().to_string())));
        self
    }

    /// Clears the set of key servers to query.
    ///
    /// Normally, you'll use this to clear the default key servers and
    /// then follow up with a call to [`Builder::add_key_server`] or
    /// [`Builder::add_key_servers`] to configure the key servers that
    /// you want to use.
    ///
    /// If you only want to disable the use of key servers, then use
    /// [`Builder::query_key_servers`].
    pub fn clear_key_server(mut self) -> Self {
        self.params.servers = Vec::new();
        self
    }

    /// Clears the sources to query.
    ///
    /// By default, all sources are queried.  This clears all of the
    /// sources.  You should follow up by enabling the sources that
    /// you want to query, e.g., by calling
    /// [`Builder::query_key_servers`].
    ///
    /// It's better to use this function than to clear all sources
    /// manually in case a new source is added in the future.
    pub fn clear_sources(mut self) -> Self {
        self.params.query_key_servers = false;
        self.params.query_wkd = false;
        self.params.query_dane = false;
        self.params.query_web = false;
        self.params.query_cert_store = false;
        self
    }

    /// Whether to query key servers.
    ///
    /// Key servers can be queried by address, and by fingerprint.
    ///
    /// See
    /// [draft-ietf-openpgp-hkp-01](https://datatracker.ietf.org/doc/draft-ietf-openpgp-hkp/)
    /// for more information.
    pub fn query_key_servers(mut self, query_key_servers: bool) -> Self {
        self.params.query_key_servers = query_key_servers;
        self
    }

    /// Whether to query WKD servers.
    ///
    /// WKD stands for web key directory.  A WKD directory can be
    /// queried by address for the domain that it manages.  A WKD is
    /// stored on a web server, and it only serves certificates for
    /// the same domain.  As such, it can be seen as a weak authority
    /// for the certificates that it serves.
    /// See
    /// [draft-koch-openpgp-webkey-service](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/)
    /// for more information.
    pub fn query_wkd(mut self, query_wkd: bool) -> Self {
        self.params.query_wkd = query_wkd;
        self
    }

    /// Whether to use DANE.
    ///
    /// DANE stands for DNS-Based Authentication of Named Entities.
    /// It defines a way to store OpenPGP certificates in DNS, and
    /// query them.  It is protected by DNSSEC.  As such, it can be
    /// seen as a weak authority for the certificates that it serves.
    ///
    /// See [RFC 7929](https://datatracker.ietf.org/doc/rfc7929/) for
    /// more information.
    pub fn query_dane(mut self, query_dane: bool) -> Self {
        self.params.query_dane = query_dane;
        self
    }

    /// Whether to query the web.
    ///
    /// Fetches a web page and extracts any certificates it finds.
    ///
    /// The web is the only backend that resolves URLs.
    pub fn query_web(mut self, query_web: bool) -> Self {
        self.params.query_web = query_web;
        self
    }

    /// Whether to query the local certificate store.
    ///
    /// When enabled, the local certificate store is queried.  This is
    /// useful to prime the query.  See [`Builder::iterations`] for
    /// why this is useful.
    pub fn query_cert_store(mut self, query_cert_store: bool) -> Self {
        self.params.query_cert_store = query_cert_store;
        self
    }

    /// Search for certificates on the network.
    pub async fn search<P>(mut self, queries: Vec<Query>, prompt: P)
        -> Result<(), Error>
    where
        P: Prompt
    {
        let mut report = output::Report::new();

        let result = Self::search_(
            &self.params, &mut self.params_once,
            queries, prompt, &mut report).await;

        let mut stream = self.params_once.stream;

        let result = match result {
            Ok(()) => {
                Ok(())
            }
            Err(Error::ArgumentError(err)) => {
                stream.output(&self.params, Output::ArgumentError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::ArgumentError(err))
            }
            Err(Error::SystemError(err)) => {
                stream.output(&self.params, Output::SystemError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::SystemError(err))
            }
            Err(Error::OperationalError(err)) => {
                stream.output(&self.params, Output::OperationalError(err.clone()))
                    .map_err(|err| Error::StreamOutputError(err))?;
                Err(Error::OperationalError(err))
            }
            Err(err @ Error::StreamOutputError(_)) => {
                // Return immediately; don't emit the report.
                return Err(err);
            }
        };

        // Emit the report.
        stream.output(
            &self.params,
            Output::Report(report))
            .map_err(|err| Error::StreamOutputError(err))?;

        result
    }

    /// Search for certificates on the network.
    async fn search_<P>(params: &Params<'sequoia>,
                        params_once: &mut ParamsOnce<'writer, 'stream>,
                        mut queries: Vec<Query>,
                        prompt: P,
                        report: &mut output::Report)
        -> Result<(), Error>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
            iterations,
            ref servers,
            query_key_servers,
            query_wkd,
            query_dane,
            query_web,
            query_cert_store,
            destination: _,
        } = params;
        let ParamsOnce {
            destination,
            stream,
        } = params_once;

        for q in queries.iter() {
            q.check()?;
        }

        if params.to_store() {
            // We're going to save the output to the certificate store.
            // Make sure it is enabled.
            sequoia.cert_store_or_else()?;
        }

        // Certify with the shadown CAs if we're saving to the
        // certificate store.
        let certify = params.to_store();

        // Whether to output ASCII-armored keyrings or binary-encoded
        // keyrings.
        let binary = false;

        let http_client = http_client().map_err(op!())?;

        let mut request_count = 0;
        let mut seen_emails = HashSet::new();
        let mut seen_fps = HashSet::new();
        let mut seen_ids = HashSet::new();
        let mut seen_urls = HashSet::new();
        let mut certs = BTreeMap::new();

        let servers = if query_key_servers {
            servers
                .iter()
                .map(|s| {
                    let ks = KeyServer::with_client(s, http_client.clone())
                        .map_err(|err| {
                            Error::ArgumentError(
                                error::ArgumentError::MalformedKeyserverUri(
                                    error::MalformedKeyserverUri {
                                        server: s.to_string(),
                                        error: err.into(),
                                    }))
                        })?;
                    Ok(Arc::new(ks))
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            Vec::new()
        };

        for _ in 0..iterations {
            let cert_store = sequoia.cert_store()?;

            let mut requests = JoinSet::new();
            let mut converged = true;
            for query in std::mem::take(&mut queries).into_iter() {
                let new = match &query {
                    Query::Handle(KeyHandle::Fingerprint(fp)) =>
                        seen_fps.insert(fp.clone()),
                    Query::Handle(KeyHandle::KeyID(id)) =>
                        seen_ids.insert(id.clone()),
                    Query::Address(addr) =>
                        seen_emails.insert(addr.clone()),
                    Query::Url(url) =>
                        seen_urls.insert(url.clone()),
                };

                // Skip queries that we already did.
                if ! new {
                    continue;
                }
                converged = false;

                // Map anyhow::Error to Error.
                let massage_query_results = |results: Result<Vec<Result<Cert>>>,
                                             query: Query,
                                             source: Source|
                    -> Result<Vec<Result<Cert, error::OperationalError>>,
                              error::OperationalError>
                {
                    let results = match results {
                        Ok(results) => results,
                        Err(err) => {
                            return Err(error::OperationalError::ExecutingQuery(
                                    error::ExecutingQuery {
                                        query: query.clone(),
                                        source: source.clone(),
                                        error: err.into(),
                                    }));
                        }
                    };

                    let results = results
                        .into_iter()
                        .map(|result| {
                            match result {
                                Ok(result) => Ok(result),
                                Err(err) => {
                                    Err(error::OperationalError::ExecutingQuery(
                                            error::ExecutingQuery {
                                                query: query.clone(),
                                                source: source.clone(),
                                                error: err.into(),
                                            }))
                                }
                            }
                        })
                        .collect();
                    Ok(results)
                };

                if query_key_servers {
                    if let Some(query) = query.as_keyserver_query() {
                        #[expect(
                            clippy::unnecessary_to_owned,
                            reason = "false positive: needs to be cloned to be used in the spawned task"
                        )]
                        for ks in servers.iter().cloned() {
                            let query = query.clone();
                            let source = Source::KeyServer(
                                ks.url().as_str().to_string());

                            stream.output(
                                params,
                                Output::RequestQueued(
                                    output::RequestQueued {
                                        source: source.clone(),
                                        query: query.clone(),
                                        request: request_count,
                                    }))
                                .map_err(|err| Error::StreamOutputError(err))?;

                            requests.spawn(async move {
                                let results = match query.clone() {
                                    Query::Handle(h) => ks.get(h).await,
                                    Query::Address(a) => ks.search(a).await,
                                    Query::Url(_) => unreachable!(),
                                };
                                let results = massage_query_results(
                                    results, query.clone(), source.clone());
                                output::Response {
                                    query,
                                    source,
                                    request: request_count,
                                    results,
                                }
                            });
                            request_count += 1;
                        }
                    }
                }

                if query_wkd {
                    if let Some(address) = query.as_address() {
                        let query = query.clone();
                        let source = Source::WKD;

                        stream.output(
                            params,
                            Output::RequestQueued(
                                output::RequestQueued {
                                    query: query.clone(),
                                    source: source.clone(),
                                    request: request_count,
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        let a = address.to_string();
                        let http_client = http_client.clone();

                        requests.spawn(async move {
                            let results =
                                wkd::get(&http_client, &a).await;
                            let results = massage_query_results(
                                results, query.clone(), source.clone());

                            output::Response {
                                query,
                                source,
                                request: request_count,
                                results,
                            }
                        });
                        request_count += 1;
                    }
                }

                if query_dane {
                    if let Some(address) = query.as_address() {
                        let query = query.clone();
                        let source = Source::DANE;

                        stream.output(
                            params,
                            Output::RequestQueued(
                                output::RequestQueued {
                                    query: query.clone(),
                                    source: source.clone(),
                                    request: request_count,
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        let a = address.to_string();

                        requests.spawn(async move {
                            let results = dane::get(&a).await;
                            let results = massage_query_results(
                                results, query.clone(), source.clone());

                            output::Response {
                                query,
                                source,
                                request: request_count,
                                results,
                            }
                        });
                        request_count += 1;
                    }
                }

                if query_web {
                    if let Query::Url(url) = &query {
                        let query = query.clone();
                        let url = url.clone();
                        let source = Source::Http(url.clone());

                        stream.output(
                            params,
                            Output::RequestQueued(
                                output::RequestQueued {
                                    query: query.clone(),
                                    source: source.clone(),
                                    request: request_count,
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        let http_client = http_client.clone();

                        requests.spawn(async move {
                            let results = match http_client.get(
                                url.clone()).send().await
                            {
                                Ok(response) =>
                                    response.bytes().await
                                    .map_err(Into::into)
                                    .and_then(|b| CertParser::from_bytes(&b)
                                              .map(|cp| cp.collect())),
                                Err(e) => Err(e.into()),
                            };
                            let results = massage_query_results(
                                results, query.clone(), source.clone());

                            output::Response {
                                query,
                                source,
                                request: request_count,
                                results,
                            }
                        });
                        request_count += 1;
                    }
                }

                if query_cert_store {
                    // Finally, we also consult the certificate store
                    // to discover more identifiers.  This is sync,
                    // but we use the same mechanism to merge the
                    // result back in.
                    if let Some(store) = &cert_store {
                        let source = Source::CertStore;

                        stream.output(
                            params,
                            Output::RequestQueued(
                                output::RequestQueued {
                                    query: query.clone(),
                                    source: source.clone(),
                                    request: request_count,
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        let mut email_query = UserIDQueryParams::new();
                        email_query.set_email(true);
                        email_query.set_ignore_case(true);

                        let results = match &query {
                            Query::Handle(h) => store.lookup_by_cert(h),
                            Query::Address(a) => store.select_userid(&email_query, a),
                            Query::Url(_) => Ok(vec![]),
                        }.map(|r| r.into_iter().map(|c| c.to_cert().cloned()).collect());
                        let results = massage_query_results(
                            results, query.clone(), Source::CertStore);

                        requests.spawn(async move {
                            output::Response {
                                query,
                                source,
                                request: request_count,
                                results,
                            }
                        });
                        request_count += 1;
                    }
                }
            }

            if converged {
                break;
            }

            // Process the updates as they come in.

            let mut updated_certs = Vec::new();

            /// Merges `cert` into `acc`, adding its fingerprint to
            /// `updated_certs` if the cert is new, or there are new
            /// user IDs.
            fn merge(acc: &mut BTreeMap<Fingerprint,
                                        (Cert, BTreeMap<
                                                Source, Option<Result<Ca>>>)>,
                     updated_certs: &mut Vec<Fingerprint>,
                     source: Source,
                     ca: Result<Option<Ca>>,
                     cert: Cert)
                -> Result<(), Error>
            {
                use std::collections::btree_map::Entry;
                match acc.entry(cert.fingerprint()) {
                    Entry::Occupied(e) => {
                        let (e, m) = e.into_mut();
                        let n_uids = e.userids().count();
                        *e = e.clone().merge_public(cert).map_err(op!())?;
                        if e.userids().count() > n_uids {
                            updated_certs.push(e.fingerprint());
                        }
                        match m.entry(source) {
                            Entry::Occupied(_) => {
                                // XXX: the CA should be the same.
                                // This is possible race that the CA
                                // will be changed on disk.  That's
                                // such a weird corner case that we
                                // ignore it.
                            }
                            Entry::Vacant(s) => {
                                s.insert(ca.transpose());
                            }
                        }
                    },
                    Entry::Vacant(e) => {
                        updated_certs.push(cert.fingerprint());
                        e.insert((cert, std::iter::once((source, ca.transpose())).collect()));
                    },
                }
                Ok(())
            }

            let mut errors = Vec::new();
            while let Some(response) = requests.join_next().await {
                let response = response.map_err(op!())?;

                match response.results {
                    Ok(returned_certs) => {
                        for cert in returned_certs.iter() {
                            match cert {
                                Ok(cert) => {
                                    let cert = cert.clone();
                                    if ! certify {
                                        merge(
                                            &mut certs, &mut updated_certs,
                                            response.source.clone(), Ok(None),
                                            cert)?;
                                    } else {
                                        match response.source.ca(sequoia) {
                                            Ok(Some(ca)) => {
                                                let cert = certify_downloads(
                                                    &sequoia, true,
                                                    ca.cert(), vec![cert], None,
                                                    &prompt);
                                                // One cert in, one cert out.
                                                assert_eq!(cert.len(), 1);
                                                let cert = cert
                                                    .into_iter().next().unwrap();

                                                merge(
                                                    &mut certs,
                                                    &mut updated_certs,
                                                    response.source.clone(),
                                                    Ok(Some(ca)),
                                                    cert)?;
                                            }
                                            Ok(None) => {
                                                merge(
                                                    &mut certs,
                                                    &mut updated_certs,
                                                    response.source.clone(),
                                                    Ok(None),
                                                    cert)?;
                                            }
                                            Err(err) => {
                                                merge(
                                                    &mut certs,
                                                    &mut updated_certs,
                                                    response.source.clone(),
                                                    Err(err),
                                                    cert)?;
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    errors.push((response.source.clone(),
                                                 response.query.clone(),
                                                 err.clone()));
                                }
                            }
                        }
                        stream.output(
                            params,
                            Output::Response(
                                output::Response {
                                    source: response.source.clone(),
                                    query: response.query.clone(),
                                    request: response.request,
                                    results: Ok(returned_certs),
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                    }
                    Err(err) => {
                        stream.output(
                            params,
                            Output::Response(
                                output::Response {
                                    source: response.source.clone(),
                                    query: response.query.clone(),
                                    request: response.request,
                                    results: Err(err.clone()),
                                }))
                            .map_err(|err| Error::StreamOutputError(err))?;

                        errors.push((response.source.clone(),
                                     response.query.clone(),
                                     err.clone()));
                    }
                }
            }

            if certs.is_empty() {
                break;
            }

            // Expand certs to discover new identifiers to query.
            for (cert, _) in updated_certs.iter().filter_map(|fp| certs.get(fp)) {
                queries.push(Query::Handle(cert.key_handle()));

                for uid in cert.userids() {
                    if let Ok(Some(addr)) = uid.userid().email() {
                        queries.push(Query::Address(addr.into()));
                    }
                }
            }
        }

        // Write out a keyring or import the certs.

        stream.output(
            params,
            Output::StartOfResults)
            .map_err(|err| Error::StreamOutputError(err))?;

        let certs = certs.into_values()
            .map(|(cert, sources)| {
                stream.output(
                    params,
                    Output::CertResult(
                        output::CertResult {
                            sources: sources
                                .into_iter()
                                .map(|(source, ca)| {
                                    output::SourceInfo {
                                        source,
                                        ca: ca.map(|ca| ca.map_err(|err| Arc::new(err))),
                                    }
                                })
                                .collect(),
                            cert: cert.clone(),
                        }))
                    .map_err(|err| Error::StreamOutputError(err))?;

                Ok(cert)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        stream.output(
            params,
            Output::EndOfResults)
            .map_err(|err| Error::StreamOutputError(err))?;

        if let Destination::Writer(ref mut output) = destination {
            // Serializes a keyring, adding descriptive headers if armored.
            let doit = || {
                // Handle the easy options first.  No armor no cry:
                if binary {
                    for cert in certs {
                        cert.serialize(output)?;
                    }
                    return Ok(());
                }

                // Just one Cert?  Ez:
                if certs.len() == 1 {
                    return certs[0].armored().serialize(output.writer());
                }

                // Then, collect the headers.
                let mut headers = Vec::new();
                for (i, cert) in certs.iter().enumerate() {
                    headers.push(format!("Key #{}", i));
                    headers.append(&mut cert.armor_headers());
                }

                let headers: Vec<_> = headers.iter()
                    .map(|value| ("Comment", value.as_str()))
                    .collect();
                let mut output = armor::Writer::with_headers(
                    output, armor::Kind::PublicKey, headers)?;
                for cert in certs {
                    cert.serialize(&mut output)?;
                }
                output.finalize()?;

                Ok(())
            };

            // Convert anyhow::Error into Error.
            doit().map_err(|err| {
                Error::OperationalError(
                    error::OperationalError::SerializingKeyring(
                        error::SerializingKeyring {
                            error: Arc::new(err),
                        }))
            })?;
        } else {
            // Save the certificates to the cert store.
            if ! certs.is_empty() {
                let cert_store = sequoia.cert_store_or_else()?;

                for cert in certs.iter() {
                    let cert = Arc::new(cert.clone().into());
                    cert_store.update_by(Arc::clone(&cert), &mut report.import_stats)
                        .map_err(|err| {
                            Error::OperationalError(
                                error::OperationalError::UpdatingCert(
                                    error::UpdatingCert {
                                        cert,
                                        error: Arc::new(err),
                                    }))
                        })?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::prompt::Cancel;

    fn check(_sequoia: &Sequoia,
             output: &[Output],
             expect_success: bool,
             expected_requests: Option<usize>,
             expected_certs: &[Fingerprint])
    {
        let mut saw_error = false;
        let mut saw_report = false;
        let mut saw_requests: BTreeSet<usize> = BTreeSet::new();
        let mut saw_responses: BTreeSet<usize> = BTreeSet::new();
        let mut saw_start_of_results = false;
        let mut saw_certs: BTreeSet<Fingerprint> = BTreeSet::new();
        let mut saw_end_of_results = false;

        eprintln!("Checking output...");

        use Output::*;
        for output in output.into_iter() {
            match output {
                ArgumentError(err) => {
                    // No argument errors.
                    eprintln!("  - argument error: {}", err);
                    assert!(! saw_error);
                    saw_error = true;
                    assert!(! saw_report);
                }
                SystemError(err) => {
                    eprintln!("  - system error: {}", err);
                    // Currently system errors only happen at the
                    // beginning (although this is not part of the API
                    // contract).
                    assert!(! saw_error);
                    saw_error = true;
                    assert!(! saw_report);
                }
                OperationalError(err) => {
                    eprintln!("  - operational error: {}", err);
                    // An operational error can happen at any time.
                    assert!(! saw_error);
                    saw_error = true;
                    assert!(! saw_report);
                }
                RequestQueued(request) => {
                    eprintln!("  - request queued");
                    eprintln!("    - query: {}", request.query);
                    eprintln!("    - source: {}", request.source);
                    eprintln!("    - request: {}", request.request);
                    assert!(! saw_error);
                    assert!(saw_responses.len() <= saw_requests.len());
                    assert!(! saw_requests.contains(&request.request));
                    assert!(! saw_report);
                    saw_requests.insert(request.request);
                }
                Response(response) => {
                    eprintln!("  - response:");
                    eprintln!("    - query: {}", response.query);
                    eprintln!("    - source: {}", response.source);
                    eprintln!("    - request: {}", response.request);
                    eprintln!("    - cert results: {}",
                              match &response.results {
                                  Ok(certs) => {
                                      certs.iter()
                                          .map(|cert| {
                                              match cert {
                                                  Ok(c) => c.fingerprint().to_string(),
                                                  Err(err) => err.to_string()
                                              }
                                          })
                                          .collect::<Vec<String>>()
                                          .join("\n      ")
                                  }
                                  Err(err) => err.to_string(),
                              });
                    assert!(! saw_error);
                    assert!(saw_responses.len() <= saw_requests.len());
                    assert!(saw_requests.contains(&response.request));
                    assert!(! saw_report);
                    saw_responses.insert(response.request);
                    }
                StartOfResults => {
                    eprintln!("  - start of results");
                    assert!(! saw_error);
                    assert!(! saw_start_of_results);
                    assert!(! saw_end_of_results);
                    assert!(! saw_report);
                    saw_start_of_results = true;
                }
                CertResult(cert) => {
                    eprintln!("  - cert result: {}", cert.cert.fingerprint());
                    assert!(! saw_error);
                    assert!(saw_start_of_results);
                    assert!(! saw_end_of_results);
                    assert!(! saw_report);
                    let not_yet_seen = saw_certs.insert(cert.cert.fingerprint());
                    assert!(not_yet_seen);
                }
                EndOfResults => {
                    eprintln!("  - end of results");
                    assert!(! saw_error);
                    assert!(saw_start_of_results);
                    assert!(! saw_end_of_results);
                    assert!(! saw_report);
                    saw_end_of_results = true;
                }
                Report(report) => {
                    eprintln!("  - report: {:?}", report);
                    assert!(! saw_report);

                    saw_report = true;
                }
            }
        }

        if expect_success {
            assert!(! saw_error);
            assert!(saw_start_of_results);
            assert!(saw_end_of_results);
        } else {
            assert!(saw_error);
        }

        assert_eq!(saw_responses.len(), saw_requests.len());
        assert_eq!(saw_responses, saw_requests);

        if let Some(expected_requests) = expected_requests {
            assert_eq!(saw_requests.len(), expected_requests);
        }

        let expected_certs
            = BTreeSet::from_iter(expected_certs.into_iter().cloned());
        for c in expected_certs.difference(&saw_certs) {
            eprintln!("Didn't see {}", c);
        }
        for c in saw_certs.difference(&expected_certs) {
            eprintln!("Unexpectedly saw {}", c);
        }
        assert_eq!(saw_certs, expected_certs);

        assert!(saw_report);
    }

    #[test]
    fn no_results() {
        let rt = tokio::runtime::Runtime::new()
            .expect("can create tokio run time");

        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        check(&sq, &output, true, Some(1), &[]);

        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("invalid@alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect_err("should fail on invalid address");
        });
        check(&sq, &output, false, Some(0), &[]);
    }

    #[test]
    fn no_cert_store() {
        let rt = tokio::runtime::Runtime::new()
            .expect("can create tokio run time");

        // Stateless => no cert store.
        let sq = Sequoia::builder().stateless().build().unwrap();

        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect_err("should fail with no cert store");
        });
        check(&sq, &output, false, Some(0), &[]);
        // The error should be second to last and followed by the
        // report.
        assert!(matches!(
            output[output.len() - 2],
            Output::SystemError(
                SystemError::CertStoreDisabled)));
        assert!(matches!(
            output[output.len() - 1],
            Output::Report(_)));

        // Write to a file.
        let mut output = Vec::new();
        let mut keyring = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_writer(&mut keyring)
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        check(&sq, &output, true, Some(0), &[]);
    }

    #[test]
    fn spider() {
        let rt = tokio::runtime::Runtime::new()
            .expect("can create tokio run time");

        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        let alice1 = sq.key_generate()
            .email("alice@example.org")
            .email("alice@other.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate key");

        let _bob = sq.key_generate()
            .email("bob@example.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate key");

        // Search for alice@example.org.
        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        // Looking up alice@example.org generates queries for
        // alice@other.org and the fingerprint.
        check(&sq, &output, true, Some(3), &[ alice1.cert.fingerprint() ]);

        // Do the same, but only do a single iterations.
        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .iterations(1)
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        // Looking up alice@example.org shouldn't generate additional
        // queries as we don't iterate.
        check(&sq, &output, true, Some(1), &[ alice1.cert.fingerprint() ]);


        let alice2 = sq.key_generate()
            .email("alice@other.org")
            .without_password()
            .generate(Cancel::new())
            .expect("can generate key");

        // Search for alice@example.org.
        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        // Looking up alice@example.org generates queries for
        // alice@other.org and the fingerprint, and then
        // alice@other.org resolves to the second certificate, which
        // we also search for by fingerprint.
        check(&sq, &output, true, Some(4),
              &[
                  alice1.cert.fingerprint(),
                  alice2.cert.fingerprint(),
              ]);

        // Do the same, but only do a single iterations.
        let mut output = Vec::new();
        rt.block_on(async {
            sq.network_search()
                .stream(&mut output)
                .clear_sources()
                .iterations(1)
                .query_cert_store(true)
                .to_store()
                .search(
                    vec![Query::Address("alice@example.org".to_string())],
                    Cancel::new())
                .await
                .expect("should succeed");
        });
        // Looking up alice@example.org shouldn't generate additional
        // queries as we don't iterate.
        check(&sq, &output, true, Some(1), &[ alice1.cert.fingerprint() ]);
    }
}
