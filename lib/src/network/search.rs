//! Network services.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;

use indicatif::ProgressBar;

use tokio::task::JoinSet;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
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

use crate::Sequoia;
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
fn import_certs(sequoia: &Sequoia, certs: Vec<Cert>) -> Result<()> {
    if certs.is_empty() {
        // No need to do and say anything.
        return Ok(());
    }

    let cert_store = sequoia.cert_store_or_else()
        .context("Inserting results")?;

    let mut stats = ImportStats::default();

    let o = &mut std::io::stderr();

    for cert in certs.iter() {
        cert_store.update_by(Arc::new(cert.clone().into()), &mut stats)
            .with_context(|| {
                let sanitized_userid = sequoia.best_userid(&cert, true);

                format!("Inserting {}, {}",
                        cert.fingerprint(), sanitized_userid.display())
            })?;
    }

    stats.print_summary(o, &sequoia)?;

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
    -> openpgp::Result<()>
{
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
}

#[derive(Clone)]
enum Query {
    Handle(KeyHandle),
    Address(String),
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
    /// Parses command line arguments to queries.
    fn parse(args: &[String]) -> Result<Vec<Query>> {
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

    /// Parses command line arguments to queries suitable for key
    /// servers.
    fn parse_keyserver_queries(args: &[String]) -> Result<Vec<Query>> {
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
    fn all_certs(sequoia: &Sequoia) -> Result<Vec<Query>> {
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
    fn all_addresses(sequoia: &Sequoia) -> Result<Vec<Query>> {
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

    /// Parses command line arguments to queries that only contain
    /// email addresses.
    fn parse_addresses(args: &[String]) -> Result<Vec<Query>> {
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Method {
    KeyServer(String),
    WKD,
    DANE,
    Http(Url),
    CertStore,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::KeyServer(url) => write!(f, "{}", url),
            Method::WKD => write!(f, "WKD"),
            Method::DANE => write!(f, "DANE"),
            Method::Http(_) => write!(f, "http"),
            Method::CertStore => write!(f, "cert-store"),
        }
    }
}

impl Method {
    // Returns the CA's certificate.
    //
    // This doesn't return an error, because not all methods have
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
                Method::KeyServer(url) => {
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
                Method::WKD => certd.shadow_ca_wkd()?,
                Method::DANE => certd.shadow_ca_dane()?,
                Method::Http(url) =>
                    if let Some(r) = certd.shadow_ca_for_url(url.as_ref())? {
                        r
                    } else {
                        return Ok(None);
                    },
                Method::CertStore => return Ok(None),
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
    method: Method,
    results: Result<Vec<Result<Cert>>>,
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

    /// Collects the responses, and displays failures.
    ///
    /// Certs are collected into `certs`, and references to all newly
    /// discovered certs are returned.
    ///
    /// If `silent_errors` is given, then failure messages are
    /// suppressed unless --verbose is given, or there was not a
    /// single successful result.
    async fn collect<P>(
        sequoia: &Sequoia,
        mut responses: JoinSet<Response>,
        certs: &mut BTreeMap<Fingerprint, (Cert, BTreeSet<Method>)>,
        certify: bool,
        silent_errors: bool,
        pb: &mut ProgressBar,
        prompt: P,
    )
        -> Result<Vec<Fingerprint>>
    where
        P: Prompt
    {
        let mut new = Vec::new();

        /// Merges `cert` into `acc`, adding its fingerprint to `new`
        /// if the cert is new, or there are new user IDs.
        fn merge(acc: &mut BTreeMap<Fingerprint, (Cert, BTreeSet<Method>)>,
                 new: &mut Vec<Fingerprint>,
                 method: Method,
                 cert: Cert)
                 -> Result<()>
        {
            use std::collections::btree_map::Entry;
            match acc.entry(cert.fingerprint()) {
                Entry::Occupied(e) => {
                    let (e, m) = e.into_mut();
                    let n_uids = e.userids().count();
                    *e = e.clone().merge_public(cert)?;
                    if e.userids().count() > n_uids {
                        new.push(e.fingerprint());
                    }
                    m.insert(method);
                },
                Entry::Vacant(e) => {
                    new.push(cert.fingerprint());
                    e.insert((cert, std::iter::once(method).collect()));
                },
            }
            Ok(())
        }

        let mut errors = Vec::new();
        while let Some(response) = responses.join_next().await {
            pb.inc(1);
            let response = response?;
            match response.results {
                Ok(returned_certs) => for cert in returned_certs {
                    match cert {
                        Ok(cert) => if ! certify {
                            merge(certs, &mut new,
                                  response.method.clone(), cert)?;
                        } else { pb.suspend(|| -> Result<()> {
                            if let Some(ca) = response.method.ca(sequoia)
                            {
                                for cert in certify_downloads(
                                    &sequoia, true, ca, vec![cert], None,
                                    &prompt)
                                {
                                    merge(certs, &mut new,
                                          response.method.clone(), cert)?;
                                }
                            } else {
                                merge(certs, &mut new,
                                      response.method.clone(), cert)?;
                            }
                            Ok(())
                        })?},
                        Err(e) =>
                            errors.push((response.method.clone(),
                                         response.query.clone(), e)),
                    }
                },
                Err(e) =>
                    errors.push((response.method, response.query, e)),
            }
        }

        if ! silent_errors || sequoia.config.verbose() || certs.is_empty() {
            for (method, query, e) in errors {
                pb.suspend(|| weprintln!("{}: {}: {}", method, query, e));
            }
        }

        if certs.is_empty() {
            Err(anyhow::anyhow!("No cert found."))
        } else {
            Ok(new)
        }
    }

    /// Either writes out a keyring or imports the certs.
    fn import_or_emit(sequoia: &Sequoia,
                      output: Option<(&mut dyn std::io::Write, Option<&Path>)>,
                      binary: bool,
                      certs: BTreeMap<Fingerprint, (Cert, BTreeSet<Method>)>)
                      -> Result<()>
    {
        make_qprintln!(sequoia.config.quiet());

        qprintln!("\nFound {} related to the query:\n",
                  certs.len().of("certificate"));

        let mut certs = certs.into_values()
            .map(|(cert, methods)| {
                let userid = sequoia.best_userid(&cert, true);
                (userid, cert, methods)
            })
            .collect::<Vec<_>>();

        // Reverse sort, i.e., most authenticated first.
        certs.sort_unstable_by_key(|cert| usize::MAX - cert.0.trust_amount());

        for (i, (userid, cert, methods)) in certs.iter().enumerate() {
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
                      methods.into_iter().map(|m| m.to_string())
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

impl Sequoia {
    /// Search for certificates on the network.
    ///
    /// See [`Builder`] for details.
    pub fn network_search(&self) -> Builder<'_>
    {
        Builder {
            params: Params {
                sequoia: self,
            }
        }
    }
}

/// Parameters to the network search function.
///
/// The parameters passed to [`Sequoia::network_search`].
pub struct Params<'a> {
    sequoia: &'a Sequoia,
}

impl<'a> Params<'a> {
    /// Returns the sequoia instance.
    pub fn sequoia(&self) -> &'a Sequoia {
        self.sequoia
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

    /// Search for certificates on the network.
    pub async fn search<P>(&self,
                           batch: bool,
                           iterations: u8,
                           default_servers: bool,
                           servers: Vec<Arc<KeyServer>>,
                           query_wkd: bool,
                           query_dane: bool,
                           all: bool,
                           query: Vec<String>,
                           output: Option<(&mut dyn std::io::Write,
                                           Option<&Path>)>,
                           prompt: P)
        -> Result<()>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
        } = &self.params;

        let queries = if all {
            Query::all_certs(sequoia)?
        } else {
            Query::parse(&query)?
        };

        self.search_(batch, iterations, default_servers, servers,
                     true, // query_key_servers
                     query_wkd,
                     query_dane,
                     true, // query_web
                     true, // query_cert_store
                     queries, output, prompt).await?;

        Ok(())
    }

    /// Search for certificates on the network.
    async fn search_<P>(&self,
                        batch: bool,
                        iterations: u8,
                        default_servers: bool,
                        servers: Vec<Arc<KeyServer>>,
                        query_key_servers: bool,
                        query_wkd: bool,
                        query_dane: bool,
                        query_web: bool,
                        query_cert_store: bool,
                        mut queries: Vec<Query>,
                        output: Option<(&mut dyn std::io::Write,
                                        Option<&Path>)>,
                        prompt: P)
        -> Result<()>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
        } = &self.params;

        if output.is_none() {
            // We're going to save the output to the certificate store.
            // Make sure it is enabled.
            sequoia.cert_store_or_else()?;
        }

        let http_client = http_client()?;

        let mut seen_emails = HashSet::new();
        let mut seen_fps = HashSet::new();
        let mut seen_ids = HashSet::new();
        let mut seen_urls = HashSet::new();
        let mut results = Default::default();
        let mut pb = Response::progress_bar(sequoia, batch);

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

                if query_key_servers {
                    if let Some(query) = query.as_keyserver_query() {
                        #[expect(
                            clippy::unnecessary_to_owned,
                            reason = "false positive: needs to be cloned to be used in the spawned task"
                        )]
                        for ks in servers.iter().cloned() {
                            pb.inc_length(1);
                            let query = query.clone();
                            requests.spawn(async move {
                                let results = match query.clone() {
                                    Query::Handle(h) => ks.get(h).await,
                                    Query::Address(a) => ks.search(a).await,
                                    Query::Url(_) => unreachable!(),
                                };
                                Response {
                                    query,
                                    results,
                                    method: Method::KeyServer(
                                        ks.url().as_str().to_string()),
                                }
                            });
                        }
                    }
                }

                if query_wkd {
                    if let Some(address) = query.as_address() {
                        let a = address.to_string();
                        let http_client = http_client.clone();
                        pb.inc_length(1);
                        requests.spawn(async move {
                            let results =
                                wkd::get(&http_client, &a).await;
                            Response {
                                query: Query::Address(a),
                                results,
                                method: Method::WKD,
                            }
                        });
                    }
                }

                if query_dane {
                    if let Some(address) = query.as_address() {
                        let a = address.to_string();
                        pb.inc_length(1);
                        requests.spawn(async move {
                            let results = dane::get(&a).await;
                            Response {
                                query: Query::Address(a),
                                results,
                                method: Method::DANE,
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
                            Response {
                                query,
                                results: match http_client.get(url.clone()).send().await
                                {
                                    Ok(response) =>
                                        response.bytes().await
                                        .map_err(Into::into)
                                        .and_then(|b| CertParser::from_bytes(&b)
                                                  .map(|cp| cp.collect())),
                                    Err(e) => Err(e.into()),
                                },
                                method: Method::Http(url),
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
                        requests.spawn(async move {
                            Response {
                                query,
                                results,
                                method: Method::CertStore,
                            }
                        });
                    }
                }
            });

            if converged {
                return Result::Ok(());
            }

            let new = Response::collect(
                sequoia, requests, &mut results, output.is_none(),
                default_servers, &mut pb, &prompt).await?;

            // Expand certs to discover new identifiers to query.
            for (cert, _) in new.iter().filter_map(|fp| results.get(fp)) {
                queries.push(Query::Handle(cert.key_handle()));

                for uid in cert.userids() {
                    if let Ok(Some(addr)) = uid.userid().email() {
                        queries.push(Query::Address(addr.into()));
                    }
                }
            }
        }

        drop(pb);

        Response::import_or_emit(sequoia, output, false, results)?;
        Ok(())
    }

    pub async fn keyserver_search<P>(&self,
                                     batch: bool,
                                     default_servers: bool,
                                     servers: Vec<Arc<KeyServer>>,
                                     all: bool,
                                     query: Vec<String>,
                                     output: Option<(&mut dyn std::io::Write,
                                                     Option<&Path>)>,
                                     prompt: P)
        -> Result<()>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
        } = &self.params;

        let queries = if all {
            Query::all_certs(&sequoia)?
        } else {
            Query::parse_keyserver_queries(&query)?
        };

        self.search_(
            batch,
            1, // Iterations.
            default_servers,
            servers,
            true, // query_key_servers,
            false, // query_wkd,
            false, // query_dane,
            false, // query_web,
            false, // query_cert_store,
            queries,
            output,
            prompt).await
    }

    pub async fn wkd_search<P>(&self,
                               batch: bool,
                               all: bool,
                               addresses: Vec<String>,
                               output: Option<(&mut dyn std::io::Write,
                                               Option<&Path>)>,
                               prompt: P)
        -> Result<()>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
        } = &self.params;

        let queries = if all {
            Query::all_addresses(&sequoia)?
        } else {
            Query::parse_addresses(&addresses)?
        };

        self.search_(
            batch,
            1, // Iterations.
            false, // default_servers,
            Vec::new(), // servers,
            false, // query_key_servers,
            true, // query_wkd,
            false, // query_dane,
            false, // query_web,
            false, // query_cert_store,
            queries,
            output,
            prompt).await
    }

    pub async fn dane_search<P>(&self,
                                batch: bool,
                                all: bool,
                                addresses: Vec<String>,
                                output: Option<(&mut dyn std::io::Write,
                                                Option<&Path>)>,
                                prompt: P)
        -> Result<()>
    where
        P: Prompt
    {
        let &Params {
            sequoia,
        } = &self.params;

        let queries = if all {
            Query::all_addresses(&sequoia)?
        } else {
            Query::parse_addresses(&addresses)?
        };

        self.search_(
            batch,
            1, // Iterations.
            false, // default_servers,
            Vec::new(), // servers,
            false, // query_key_servers,
            false, // query_wkd,
            true, // query_dane,
            false, // query_web,
            false, // query_cert_store,
            queries,
            output,
            prompt).await
    }
}
