//! Network services.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use indicatif::ProgressBar;

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
use openpgp::types::RevocationStatus;

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

use crate::Result;
use crate::Sequoia;
use crate::SystemError;
use crate::cert::cert_exportable;
use crate::network::http_client;
use crate::prompt::Prompt;
use crate::provenance::certify_downloads;
use crate::transitional::output::pluralize::Pluralize;
use crate::types::Convert;
use crate::types::Safe;
use crate::types::import_stats::ImportStats;

/// Import the certificates into the local certificate store.
///
/// This does not certify the certificates.
fn import_certs(sequoia: &Sequoia, certs: Vec<Cert>) -> Result<(), Error> {
    if certs.is_empty() {
        // No need to do and say anything.
        return Ok(());
    }

    let cert_store = sequoia.cert_store_or_else()?;

    let mut stats = ImportStats::default();

    let o = &mut std::io::stderr();

    for cert in certs.iter() {
        let cert = Arc::new(cert.clone().into());
        cert_store.update_by(Arc::clone(&cert), &mut stats)
            .map_err(|err| {
                Error::OperationalError(
                    error::OperationalError::UpdatingCert(
                        error::UpdatingCert {
                            cert,
                            error: Arc::new(err),
                        }))
            })?;
    }

    stats.print_summary(o, &sequoia).map_err(op!())?;

    for vcert in certs.iter()
        .filter_map(|cert| cert.with_policy(sequoia.policy(), sequoia.time()).ok())
        .filter(|vcert| vcert.alive().is_ok())
    {
        let mut hint = sequoia.hint(format_args!(
            "After checking that the certificate {} really belongs to the \
             stated owner, you can mark the certificate as authenticated.  \
             Each stated user ID can be marked individually using:",
            vcert.fingerprint()));

        let mut count = 0;
        for uid in vcert.userids()
            .filter_map(|uid| std::str::from_utf8(uid.userid().value())
                        .map(ToString::to_string).ok())
        {
            hint = hint
                .sq().arg("pki").arg("link").arg("add")
                .arg_value("--cert", vcert.fingerprint())
                .arg_value("--userid", uid)
                .done();

            count += 1;
        }

        if count > 1 {
            hint.hint(format_args!(
                "Alternatively, all user IDs can be marked as authenticated \
                 using:"))
                .sq().arg("pki").arg("link").arg("add")
                .arg_value("--cert", vcert.fingerprint())
                .arg("--all")
                .done();
        }
    }

    Ok(())
}

/// Serializes a keyring, adding descriptive headers if armored.
fn serialize_keyring(sequoia: &Sequoia,
                     mut output: (&mut dyn std::io::Write, Option<&Path>),
                     certs: Vec<Cert>,
                     binary: bool)
    -> Result<(), Error>
{
    let doit = || {
        if certs.len() > 1 {
            let mut hint = sequoia.hint(format_args!(
                "To extract a particular certificate from {}, use any of:",
                output.1.map(|p| p.display().to_string())
                    .unwrap_or_else(|| "the stream".into())));

            let path = output.1.map(|p| p.display().to_string())
                .unwrap_or_else(|| "...".into());
            for cert in &certs {
                hint = hint.sq()
                    .arg("cert").arg("export")
                    .arg_value("--keyring", &path)
                    .arg_value("--cert", cert.fingerprint())
                    .done();
            }
        }

        // Handle the easy options first.  No armor no cry:
        if binary {
            for cert in certs {
                cert.serialize(&mut output.0)?;
            }
            return Ok(());
        }

        // Just one Cert?  Ez:
        if certs.len() == 1 {
            return certs[0].armored().serialize(&mut output.0);
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
        let mut output = armor::Writer::with_headers(&mut output.0,
                                                     armor::Kind::PublicKey,
                                                     headers)?;
        for cert in certs {
            cert.serialize(&mut output)?;
        }
        output.finalize()?;

        Ok(())
    };

    // Convert anyhow::Error into Error.
    doit()
        .map_err(|err| {
            Error::OperationalError(
                error::OperationalError::SerializingKeyring(
                    error::SerializingKeyring {
                        error: Arc::new(err),
                    }))
        })
}

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
    // Returns the CA's certificate.
    //
    // This doesn't return an error, because not all sources have
    // shadow CAs, and a missing CA is not a hard error.
    fn ca(&self, sequoia: &Sequoia)
        -> Option<Arc<LazyCert<'static>>>
    {
        make_qprintln!(sequoia.config.quiet());

        let ca = || -> Result<_> {
            let cert_store = sequoia.cert_store_or_else()?;
            let certd = cert_store.certd()
                .ok_or_else(|| anyhow::anyhow!(
                    "A local trust root and other special certificates are \
                     only available when using an OpenPGP certificate \
                     directory"))?;
            let (cert, created) = match self {
                Source::KeyServer(url) => {
                    let result = certd.shadow_ca_keyserver(url)?;

                    match result {
                        Some((cert, created)) => (cert, created),
                        None => {
                            if sequoia.config.verbose() {
                                weprintln!(
                                    "Not recording provenance information: \
                                     {} is not known to be a verifying \
                                     keyserver",
                                    url);
                            }
                            return Ok(None);
                        }
                    }
                }
                Source::WKD => certd.shadow_ca_wkd()?,
                Source::DANE => certd.shadow_ca_dane()?,
                Source::Http(url) =>
                    if let Some(r) = certd.shadow_ca_for_url(url.as_ref())? {
                        r
                    } else {
                        return Ok(None);
                    },
                Source::CertStore => return Ok(None),
            };

            // Check that the data is a valid certificate.  If not,
            // bail sooner rather than later.
            let _ = cert.to_cert()?;

            Ok(Some((cert, created)))
        };

        let (cert, created) = match ca() {
            Ok(Some((cert, created))) => (cert, created),
            Ok(None) => return None,
            Err(err) => {
                let print_err = || {
                    weprintln!(
                        "Not recording provenance information: {}",
                        err);
                };

                if sequoia.config.verbose() {
                    print_err();
                } else {
                    use std::sync::Once;
                    static MSG: Once = Once::new();
                    MSG.call_once(print_err);
                }

                return None;
            }
        };

        if ! created {
            // We didn't create it.
            return Some(cert);
        }

        if sequoia.config.verbose() {
            weprintln!(
                "Created the local CA {} for certifying \
                 certificates downloaded from this service.  \
                 Use `sq pki link authorize --unconstrained --amount N {}` \
                 to change how much it is trusted.  Or \
                 `sq pki link retract {}` to disable it.",
                if let Ok(uid) = cert.to_cert()
                    .and_then(|c| sequoia.best_userid(c, false).userid()
                              .map(ToString::to_string))
                {
                    // We really want the self-signed, primary user
                    // ID.
                    uid
                } else {
                    "invalid data".to_string()
                },
                cert.fingerprint(), cert.fingerprint());
        } else {
            use std::sync::Once;
            static MSG: Once = Once::new();
            MSG.call_once(|| {
                qprintln!("Note: Created a local CA to record \
                           provenance information.\n\
                           Note: See `sq pki link list --ca` \
                           and `sq pki link --help` for more \
                           information.");
            });
        }

        Some(cert)
    }
}

struct Response {
    query: Query,
    source: Source,
    results: Result<Vec<Result<Cert, Error>>, Error>,
}

impl Response {
    /// Creates a progress bar.
    fn progress_bar(sequoia: &Sequoia, batch: bool) -> ProgressBar {
        if sequoia.config.verbose() || batch {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(0)
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

    /// An error related to the arguments.
    ///
    /// Argument errors are fatal and cause processing to abort.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ArgumentError {
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

    /// The query did not match any certificates.
    #[non_exhaustive]
    #[derive(thiserror::Error, Debug, Clone)]
    #[error("No certificate found.")]
    pub struct NotFound {
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
        NotFound(NotFound),

        #[error(transparent)]
        Other(Arc<anyhow::Error>),
    }
}

/// Errors related to generating a searching the network for certificates.
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
}

impl Sequoia {
    /// Search for certificates on the network.
    ///
    /// By default, the search function will search all sources, and
    /// will iterate up to three times.  Each iteration uses the
    /// results of the previous iteration to generate related queries.
    ///
    /// See [`Builder`] for details.
    pub fn network_search(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
                batch: false,
                iterations: 3,
                default_servers: true,
                servers: Default::default(),
                query_key_servers: true,
                query_wkd: true,
                query_dane: true,
                query_web: true,
                query_cert_store: true,
            }
        }
    }
}

/// Parameters to the network search function.
///
/// The parameters passed to [`Sequoia::network_search`].
pub struct Params<'a> {
    sequoia: &'a Sequoia,
    batch: bool,
    iterations: u8,
    default_servers: bool,
    servers: Vec<Arc<KeyServer>>,
    query_key_servers: bool,
    query_wkd: bool,
    query_dane: bool,
    query_web: bool,
    query_cert_store: bool,
}

impl<'a> Params<'a> {
    /// Returns the sequoia instance.
    pub fn sequoia(&self) -> &'a Sequoia {
        self.sequoia
    }

    /// Transitional: whether we're operating in batch mode.
    pub fn batch(&self) -> bool {
        self.batch
    }

    /// Transitional: returns the default servers parameter.
    pub fn default_servers(&self) -> bool {
        self.default_servers
    }

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
    pub fn key_servers(&self) -> impl Iterator<Item=&Arc<KeyServer>> {
        self.servers.iter()
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

/// Search for certificates on the network.
pub struct Builder<'a> {
    params: Params<'a>,
}

impl<'a> Builder<'a> {
    /// Returns the parameters.
    ///
    /// This is useful for examining the builder's configuration.
    pub fn params(&self) -> &Params<'_> {
        &self.params
    }

    /// Transitional: whether we're operating in batch mode.
    pub fn batch(mut self, batch: bool) -> Self {
        self.params.batch = batch;
        self
    }

    /// Transitional: returns the default servers parameter.
    pub fn default_servers(mut self, default_servers: bool) -> Self {
        self.params.default_servers = default_servers;
        self
    }

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
    pub fn set_key_servers(mut self,
                           key_servers: impl IntoIterator<Item=Arc<KeyServer>>)
        -> Self
    {
        self.params.servers = key_servers.into_iter().collect();
        self
    }

    /// Adds the key server to the set of key servers to query.
    pub fn add_key_server(mut self, key_server: Arc<KeyServer>) -> Self {
        self.params.servers.extend(std::iter::once(key_server));
        self
    }

    /// Adds the key servers to the set of key servers to query.
    pub fn add_key_servers(mut self,
                           key_servers: impl IntoIterator<Item=Arc<KeyServer>>)
        -> Self
    {
        self.params.servers.extend(key_servers.into_iter());
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
    pub async fn search<P>(&self,
                           queries: Vec<Query>,
                           output: Option<(&mut dyn std::io::Write,
                                           Option<&Path>)>,
                           prompt: P)
        -> Result<(), Error>
    where
        P: Prompt
    {
        self.search_(queries, output, prompt).await?;

        Ok(())
    }

    /// Search for certificates on the network.
    async fn search_<P>(&self,
                        mut queries: Vec<Query>,
                        output: Option<(&mut dyn std::io::Write,
                                        Option<&Path>)>,
                        prompt: P)
        -> Result<(), Error>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
            batch,
            iterations,
            default_servers,
            ref servers,
            query_key_servers,
            query_wkd,
            query_dane,
            query_web,
            query_cert_store,
        } = &self.params;

        make_qprintln!(sequoia.config.quiet());

        if output.is_none() {
            // We're going to save the output to the certificate store.
            // Make sure it is enabled.
            sequoia.cert_store_or_else()?;
        }

        // Certify with the shadown CAs if we're saving to the
        // certificate store.
        let certify = output.is_none();
        let silent_errors = default_servers;

        // Whether to output ASCII-armored keyrings or binary-encoded
        // keyrings.
        let binary = false;

        let http_client = http_client().map_err(op!())?;

        let mut seen_emails = HashSet::new();
        let mut seen_fps = HashSet::new();
        let mut seen_ids = HashSet::new();
        let mut seen_urls = HashSet::new();
        let mut certs = BTreeMap::new();
        let pb = Response::progress_bar(sequoia, batch);

        for _ in 0..iterations {
            let cert_store = sequoia.cert_store()?;

            let mut requests = JoinSet::new();
            let mut converged = true;
            std::mem::take(&mut queries).into_iter().for_each(|query| {
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
                    return;
                }
                converged = false;

                // Map anyhow::Error to Error.
                let massage_query_results = |results: Result<Vec<Result<Cert>>>,
                                             query: Query,
                                             source: Source|
                    -> Result<Vec<Result<Cert, Error>>, Error>
                {
                    let results = match results {
                        Ok(results) => results,
                        Err(err) => {
                            return Err(Error::OperationalError(
                                error::OperationalError::ExecutingQuery(
                                    error::ExecutingQuery {
                                        query: query.clone(),
                                        source: source.clone(),
                                        error: err.into(),
                                    })));
                        }
                    };

                    let results = results
                        .into_iter()
                        .map(|result| {
                            match result {
                                Ok(result) => Ok(result),
                                Err(err) => {
                                    Err(Error::OperationalError(
                                        error::OperationalError::ExecutingQuery(
                                            error::ExecutingQuery {
                                                query: query.clone(),
                                                source: source.clone(),
                                                error: err.into(),
                                            })))
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
                            pb.inc_length(1);
                            requests.spawn(async move {
                                let results = match query.clone() {
                                    Query::Handle(h) => ks.get(h).await,
                                    Query::Address(a) => ks.search(a).await,
                                    Query::Url(_) => unreachable!(),
                                };
                                let results = massage_query_results(
                                    results, query.clone(), source.clone());
                                Response {
                                    query,
                                    results,
                                    source,
                                }
                            });
                        }
                    }
                }

                if query_wkd {
                    if let Some(address) = query.as_address() {
                        let query = query.clone();
                        let a = address.to_string();
                        let http_client = http_client.clone();
                        pb.inc_length(1);
                        requests.spawn(async move {
                            let results =
                                wkd::get(&http_client, &a).await;
                            let results = massage_query_results(
                                results, query.clone(), Source::WKD);

                            Response {
                                query,
                                results,
                                source: Source::WKD,
                            }
                        });
                    }
                }

                if query_dane {
                    if let Some(address) = query.as_address() {
                        let query = query.clone();
                        let a = address.to_string();
                        pb.inc_length(1);
                        requests.spawn(async move {
                            let results = dane::get(&a).await;
                            let results = massage_query_results(
                                results, query.clone(), Source::DANE);
                            Response {
                                query,
                                results,
                                source: Source::DANE,
                            }
                        });
                    }
                }

                if query_web {
                    if let Query::Url(url) = &query {
                        let query = query.clone();
                        let http_client = http_client.clone();
                        let url = url.clone();
                        pb.inc_length(1);
                        requests.spawn(async move {
                            let source = Source::Http(url.clone());

                            let results = match http_client.get(url.clone()).send().await
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
                            Response {
                                query,
                                results,
                                source,
                            }
                        });
                    }
                }

                if query_cert_store {
                    // Finally, we also consult the certificate store
                    // to discover more identifiers.  This is sync,
                    // but we use the same mechanism to merge the
                    // result back in.
                    if let Some(store) = &cert_store {
                        pb.inc_length(1);
                        let mut email_query = UserIDQueryParams::new();
                        email_query.set_email(true);
                        email_query.set_ignore_case(true);

                        let results = match &query {
                            Query::Handle(h) => store.lookup_by_cert(h),
                            Query::Address(a) => store.select_userid(&email_query, a),
                            Query::Url(_) => return,
                        }.map(|r| r.into_iter().map(|c| c.to_cert().cloned()).collect());
                        let results = massage_query_results(
                            results, query.clone(), Source::CertStore);
                        requests.spawn(async move {
                            Response {
                                query,
                                results,
                                source: Source::CertStore,
                            }
                        });
                    }
                }
            });

            if converged {
                return Result::Ok(());
            }

            // Process the updates as they come in.

            let mut updated_certs = Vec::new();

            /// Merges `cert` into `acc`, adding its fingerprint to `updated_certs`
            /// if the cert is new, or there are new user IDs.
            fn merge(acc: &mut BTreeMap<Fingerprint, (Cert, BTreeSet<Source>)>,
                     updated_certs: &mut Vec<Fingerprint>,
                     source: Source,
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
                        m.insert(source);
                    },
                    Entry::Vacant(e) => {
                        updated_certs.push(cert.fingerprint());
                        e.insert((cert, std::iter::once(source).collect()));
                    },
                }
                Ok(())
            }

            let mut errors = Vec::new();
            while let Some(request) = requests.join_next().await {
                pb.inc(1);
                let request = request.map_err(op!())?;
                match request.results {
                    Ok(returned_certs) => {
                        for cert in returned_certs {
                            match cert {
                                Ok(cert) => {
                                    if ! certify {
                                        merge(
                                            &mut certs, &mut updated_certs,
                                            request.source.clone(), cert)?;
                                    } else {
                                        pb.suspend(|| -> Result<(), Error> {
                                            if let Some(ca)
                                                = request.source.ca(sequoia)
                                            {
                                                for cert in certify_downloads(
                                                    &sequoia, true,
                                                    ca, vec![cert], None,
                                                    &prompt)
                                                {
                                                    merge(
                                                        &mut certs,
                                                        &mut updated_certs,
                                                        request.source.clone(),
                                                        cert)?;
                                                }
                                            } else {
                                                merge(
                                                    &mut certs,
                                                    &mut updated_certs,
                                                    request.source.clone(),
                                                    cert)?;
                                            }
                                            Ok(())
                                        })?
                                    }
                                }
                                Err(e) =>
                                    errors.push((request.source.clone(),
                                                 request.query.clone(), e)),
                            }
                        }
                    }
                    Err(e) =>
                        errors.push((request.source, request.query, e)),
                }
            }

            if ! silent_errors || sequoia.config.verbose() || certs.is_empty() {
                for (source, query, e) in errors {
                    pb.suspend(|| weprintln!("{}: {}: {}", source, query, e));
                }
            }

            if certs.is_empty() {
                return Err(Error::OperationalError(
                    error::OperationalError::NotFound(
                        error::NotFound {
                        })));
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

        drop(pb);

        // Write out a keyring or import the certs.

        qprintln!("\nFound {} related to the query:\n",
                  certs.len().of("certificate"));

        let mut certs = certs.into_values()
            .map(|(cert, sources)| {
                let userid = sequoia.best_userid(&cert, true);
                (userid, cert, sources)
            })
            .collect::<Vec<_>>();

        // Reverse sort, i.e., most authenticated first.
        certs.sort_unstable_by_key(|cert| usize::MAX - cert.0.trust_amount());

        for (i, (userid, cert, sources)) in certs.iter().enumerate() {
            if i > 0 {
                qprintln!();
            }

            // Emit metadata.
            qprintln!(initial_indent = " - ", "{}",
                      cert.fingerprint());
            qprintln!(initial_indent = "   - ", "{}", userid.display());
            qprintln!(initial_indent = "   - ", "created {}",
                      cert.primary_key().key().creation_time().convert());

            match cert.with_policy(sequoia.policy(), sequoia.time()) {
                Ok(vcert) => {
                    if let Err(e) = vcert.alive() {
                        qprintln!(initial_indent = "   - ", "not live: {}", e);
                    }
                    match vcert.revocation_status() {
                        RevocationStatus::Revoked(sigs) => for s in sigs {
                            if let Some((reason, message)) =
                                s.reason_for_revocation()
                            {
                                qprintln!(initial_indent = "   - ",
                                          "revoked: {}, {}", reason,
                                          Safe(message));
                            } else {
                                qprintln!(initial_indent = "   - ",
                                          "revoked");
                            }
                        },

                        RevocationStatus::CouldBe(sigs) => for s in sigs {
                            if let Some((reason, message)) =
                                s.reason_for_revocation()
                            {
                                qprintln!(initial_indent = "   - ",
                                          "possibly revoked: {}, {}", reason,
                                          Safe(message));
                            } else {
                                qprintln!(initial_indent = "   - ",
                                          "possibly revoked");
                            }

                            match sequoia.lookup()
                                .keyflags(None)
                                .or_by_primary(false)
                                .lookup(s.get_issuers(), true)
                            {
                                Ok(issuers) => for issuer in issuers {
                                    qprintln!(initial_indent = "     - ",
                                              "by {}, {}",
                                              issuer.fingerprint(),
                                              sequoia.best_userid(&issuer, true)
                                              .display());
                                },
                                Err(_) =>
                                    qprintln!(initial_indent = "     - ",
                                              "by {}", s.get_issuers()[0]),
                            }
                        },

                        RevocationStatus::NotAsFarAsWeKnow => (),
                    }
                },
                Err(e) =>
                    qprintln!(initial_indent = "   - ", "not valid: {}", e),
            }

            qprintln!(initial_indent = "   - ", "found via: {}",
                      sources.into_iter().map(|m| m.to_string())
                      .collect::<Vec<_>>().join(", "));
        }

        let certs = certs.into_iter().map(|(_, cert, _)| cert).collect();

        if let Some(output) = output {
            serialize_keyring(&sequoia, output, certs, binary)?;
        } else {
            import_certs(&sequoia, certs)?;
        }

        Ok(())
    }
}
