//! Network services.

use std::collections::BTreeMap;
use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::ArgMatches;

use sqz::openpgp;
use openpgp::{
    Result,
    cert::{
        Cert,
        CertParser,
    },
    parse::Parse,
    types::KeyFlags,
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
    dane,
    reqwest::StatusCode,
};

use sqz::cert_store;
use cert_store::Store;

use sqz::network::http_client;
use sqz::network::search::Query;
use sqz::types::TrustThreshold;

use crate::{
    output::pluralize::Pluralize,
    Sq,
    print_error_chain,
};
use crate::common::password;
use crate::cli;
use crate::output::network::search::Stream;

pub fn dispatch(sq: Sq, c: cli::network::Command, matches: &ArgMatches)
                -> Result<()>
{
    let matches = matches.subcommand().unwrap().1;
    use cli::network::Subcommands;
    match c.subcommand {
        Subcommands::Search(mut command) => {
            command.iterations_source = matches.value_source("iterations");
            command.servers_source = matches.value_source("servers");
            command.use_wkd_source = matches.value_source("use_wkd");
            command.use_dane_source = matches.value_source("use_dane");
            dispatch_search(sq, command)
        },

        Subcommands::Keyserver(command) =>
            dispatch_keyserver(sq, command, matches),

        Subcommands::Wkd(command) =>
            dispatch_wkd(sq, command),

        Subcommands::Dane(command) =>
            dispatch_dane(sq, command),
    }
}


pub fn dispatch_search(sq: Sq, c: cli::network::search::Command)
                      -> Result<()>
{
    if c.output.is_none() {
        // We're going to save the output to the certificate store.
        // Make sure it is enabled.
        sq.cert_store_or_else()?;
    }

    let default_servers =
        matches!(c.servers_source.unwrap(),
                 clap::parser::ValueSource::DefaultValue);

    let servers = sq.config()
        .resolve_key_servers(&c.servers, c.servers_source);

    let iterations =
        sq.config().resolve_network_search_iterations(
            c.iterations, c.iterations_source);
    let use_wkd =
        sq.config().resolve_network_search_use_wkd(
            c.use_wkd, c.use_wkd_source);
    let use_dane =
        sq.config().resolve_network_search_use_dane(
            c.use_dane, c.use_dane_source);

    let queries = if c.all {
        Query::all_certs(&sq.sequoia)?
    } else {
        Query::parse(&c.query)?
    };

    let mut output_;
    let (output, output_path) = if let Some(output) = c.output.as_ref() {
        output_ = output.create_safe(&sq)?;
        let output_path = output.path().map(|p| p.clone());
        (Some(&mut output_ as &mut _), Some(output_path))
    } else {
        (None, None)
    };

    let prompt = password::PromptFactory::new(&sq, true);

    let rt = tokio::runtime::Runtime::new()?;

    let mut stream = Stream::new(
        &sq,
        default_servers,
        output_path);

    rt.block_on(async {
        sq.sequoia.network_search()
            .stream(&mut stream)
            .prompt(prompt)
            .iterations(iterations)
            .set_key_servers(servers)
            .query_wkd(use_wkd)
            .query_dane(use_dane)
            .to_writer(output)
            .search(queries).await
    })?;

    Ok(())
}

pub fn dispatch_keyserver(
    sq: Sq,
    c: cli::network::keyserver::Command,
    matches: &ArgMatches,
) -> Result<()>
{
    let servers_source = matches.value_source("servers").unwrap();
    let default_servers =
        matches!(servers_source, clap::parser::ValueSource::DefaultValue);

    let servers = sq.config()
        .resolve_key_servers(&c.servers, Some(servers_source))
        .collect::<Vec<_>>();

    use crate::cli::network::keyserver::Subcommands::*;
    match c.subcommand {
        Search(c) => {
            let queries = if c.all {
                Query::all_certs(&sq.sequoia)?
            } else {
                Query::parse_keyserver_queries(&c.query)?
            };

            let mut output_;
            let (output, output_path) = if let Some(output) = c.output.as_ref() {
                output_ = output.create_safe(&sq)?;
                let output_path = output.path().map(|p| p.clone());
                (Some(&mut output_ as &mut _), Some(output_path))
            } else {
                (None, None)
            };

            let prompt = password::PromptFactory::new(&sq, true);

            let mut stream = Stream::new(
                &sq,
                default_servers,
                output_path);

            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                sq.sequoia.network_search()
                    .stream(&mut stream)
                    .prompt(prompt)
                    .iterations(1)
                    .set_key_servers(servers)
                    .clear_sources()
                    .query_key_servers(true)
                    .to_writer(output)
                    .search(queries).await
            })?;
        }
        Publish(c) => {
            let servers = servers
                .into_iter()
                .map(|uri| KeyServer::with_client(uri, http_client()?)
                     .with_context(|| format!("Malformed keyserver URI: {}", uri))
                     .map(Arc::new))
                .collect::<Result<Vec<_>>>()?;

            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                let o = &mut std::io::stdout();
                make_qprintln!(o, sq.quiet());

                let (certs, errors) = sq.resolve_certs(
                    &c.certs, TrustThreshold::Full)?;
                for error in errors.iter() {
                    print_error_chain(error);
                }
                if ! errors.is_empty() {
                    return Err(anyhow::anyhow!("Failed to resolve certificates"));
                }

                let mut requests = tokio::task::JoinSet::new();
                for ks in servers.iter() {
                    for cert in certs.iter().cloned() {
                        let ks = ks.clone();
                        requests.spawn(async move {
                            let response = ks.send(&cert).await;
                            (ks.url().to_string(), cert, response)
                        });
                    }
                }

                let mut result = Ok(());
                while let Some(response) = requests.join_next().await {
                    let (url, cert, response) = response?;
                    match response {
                        Ok(()) => {
                            qprintln!("{}: ok", url);
                        },
                        Err(e) if default_servers
                            && url == "hkps://mail-api.proton.me" =>
                        {
                            // Currently, the Proton keyserver is
                            // read-only, but may change to accept updates
                            // in the future.  We still send them updates
                            // by default, but we will not consider this
                            // an error, and only print the message in
                            // verbose mode.
                            if sq.verbose() {
                                wwriteln!(o, "{}: {}", url, e);
                            }
                        },
                        Err(e) => {
                            if url == "hkps://keys.mailvelope.com"
                                && matches!(e.downcast_ref(),
                                            Some(net::Error::HttpStatus(
                                                StatusCode::BAD_REQUEST)))
                                && cert.keys().with_policy(sq.policy(), sq.time())
                                .key_flags(KeyFlags::empty()
                                           .set_transport_encryption()
                                           .set_storage_encryption())
                                .next().is_none()
                            {
                                qprintln!(
                                    "Warning: The Mailvelope key server \
                                     rejects certificates that are not \
                                     encryption-capable.");
                            }

                            wwriteln!(o, "{}: {}", url, e);
                            if result.is_ok() {
                                result = Err((url, e));
                            }
                        },
                    }
                }

                result.map_err(|(_url, e)| e)
            })?;
        }
    }

    Ok(())
}

pub fn dispatch_wkd(sq: Sq, c: cli::network::wkd::Command)
    -> Result<()>
{
    use crate::cli::network::wkd::Subcommands::*;
    match c.subcommand {
        Search(c) => {
            let queries = if c.all {
                Query::all_addresses(&sq.sequoia)?
            } else {
                Query::parse_addresses(&c.addresses)?
            };

            let mut output_;
            let (output, output_path) = if let Some(output) = c.output.as_ref() {
                output_ = output.create_safe(&sq)?;
                let output_path = output.path().map(|p| p.clone());
                (Some(&mut output_ as &mut _), Some(output_path))
            } else {
                (None, None)
            };

            let prompt = password::PromptFactory::new(&sq, true);

            let mut stream = Stream::new(
                &sq,
                true,
                output_path);

            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                sq.sequoia.network_search()
                    .stream(&mut stream)
                    .prompt(prompt)
                    .iterations(1)
                    .clear_sources()
                    .query_wkd(true)
                    .to_writer(output)
                    .search(queries).await
            })?;
        }
        Publish(mut c) => {
            let o = &mut std::io::stdout();
            make_qprintln!(o, sq.quiet());

            use wkd::Variant;
            let cert_store = sq.cert_store()?;

            // Make `--all` implicitly select all certs with a user ID
            // matching `--domain` that can be authenticated.
            if c.all {
                use cli::types::cert_designator::CertDesignator;
                c.certs.push(CertDesignator::Domain(c.domain.clone()));
            }

            let (insert, errors) = sq.resolve_certs(
                &c.certs, TrustThreshold::Full)?;
            for error in errors.iter() {
                print_error_chain(error);
            }
            if ! errors.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve certificates"));
            }

            let mut skipping = Vec::new();
            let mut insert: BTreeMap<_, _> = insert.into_iter()
                .filter(|cert| {
                    if ! cert.with_policy(sq.policy(), sq.time())
                        .ok()
                        .map(|vc| vc.userids().any(
                            |u| u.userid().email().ok().flatten().map(
                                |a| a.ends_with(&c.domain))
                                .unwrap_or(false)))
                        .unwrap_or(false)
                    {
                        skipping.push(cert.fingerprint());
                        false // Drop.
                    } else {
                        true // Keep.
                    }
                })
                .map(|c| (c.fingerprint(), c))
                .collect();

            if ! skipping.is_empty() {
                qprintln!("Note: Skipping the following certificates because \
                           they don't have a valid self-signed user ID in \
                           {}:", c.domain);
                skipping.into_iter().for_each(|fipr| qprintln!(" - {}", fipr))
            }

            if c.create && insert.is_empty() {
                sq.hint(format_args!(
                    "You specified `--create`, but didn't specify any \
                     certificates to insert.  Try specifying `--all` to \
                     insert all certificates that have an authenticated \
                     user ID with an email address for {:?}.",
                    c.domain));
                return Err(anyhow::anyhow!(
                    "Cowardly refusing to create an empty WKD."));
            }

            // Make `--rsync-path` imply `--rsync`.
            let rsync = c.rsync_path.take()
                .or_else(|| c.rsync.then_some("rsync".into()));

            // Strategy: We transfer the WKD to a temporary directory,
            // read all the certs, update them from the local cert
            // store, re-create the WKD hierarchy, then transfer it
            // back.
            let wd = tempfile::TempDir::new()?;

            // First, fetch the WKD.
            let fetch = wd.path().join("fetch");
            fs::create_dir(&fetch)?;
            let r = transfer(&rsync,
                  &format!("{}/.well-known/openpgpkey", c.destination),
                  &fetch.display().to_string())
                .with_context(|| {
                    format!("failed to fetch the WKD from {}", c.destination)
                });
            if r.is_err() && ! c.create {
                return r;
            }

            // Detect the variant by locating the policy file.
            let fetch = fetch.join("openpgpkey");
            let direct_policy = fetch.join("policy");
            let advanced_policy = fetch.join(&c.domain).join("policy");

            if c.create && (direct_policy.exists()
                            || advanced_policy.exists())
            {
                return Err(anyhow::anyhow!(
                    "Cannot create WKD: {} already contains one",
                    c.destination));
            }

            let (variant, policy) = match (direct_policy.exists(),
                                           advanced_policy.exists())
            {
                (true, false) => (Variant::Direct, Some(direct_policy)),
                (false, true) => (Variant::Advanced, Some(advanced_policy)),
                (false, false) => if c.create {
                    (c.method.unwrap_or_default().into(), None)
                } else {
                    return Err(anyhow::anyhow!("No policy file found")
                               .context(format!(
                                   "{} does not appear to be a \
                                    WKD, consider specifying `--create`",
                                   c.destination)))
                },
                (true, true) =>
                    return Err(anyhow::anyhow!("Two policy files found")
                               .context("Invalid WKD: both direct and advanced \
                                         WKD detected")),
            };
            let hu = match variant {
                Variant::Direct => fetch.join("hu"),
                Variant::Advanced => fetch.join(&c.domain).join("hu"),
            };

            // Reports on certificate updates, or the lack thereof.
            let sq_ref = &sq;
            let mut printed_updating = false;
            let mut status = |cert: &Cert, msg: &str| {
                if ! printed_updating {
                    printed_updating = true;
                    qprintln!("Updating:");
                }

                qprintln!(initial_indent = " - ", "{}", cert.fingerprint());
                qprintln!(initial_indent = "   - ", "{}",
                          sq_ref.best_userid(&cert, false).display());
                qprintln!(initial_indent = "   - ", "{}", msg);
                qprintln!();
            };

            // Now re-create the WKD hierarchy while updating the certs.
            let push = wd.path().join("push");
            let push_wk = push.join(".well-known");
            let push_openpgpkey = push_wk.join("openpgpkey");
            fs::create_dir(&push)?;
            let insert_ref = &mut insert;
            let mut number_of_changes = 0;
            let number_of_changes_ref = &mut number_of_changes;
            visit_dirs(&hu, &mut |entry: &DirEntry| -> Result<()> {
                let p = entry.path();
                for cert in CertParser::from_reader(fs::File::open(p)?)? {
                    let mut cert = cert?;

                    let mut updated = false;
                    let mut unchanged = false;

                    // Here we look for updates from the cert store
                    // and merge them into any certificates in the
                    // WKD.  Below, we insert explicitly named
                    // certificates.  If a certificate exists in the
                    // WKD and is explicitly named, we'll overwrite it
                    // below.  As such, we also handle explicitly
                    // named certificates here.
                    if let Some(update) = insert_ref.remove(&cert.fingerprint()) {
                        let (cert_, updated_) = cert.insert_packets(
                            update.into_packets())?;
                        cert = cert_;
                        if updated_ {
                            updated = true;
                        } else {
                            unchanged = true;
                        }
                    }

                    // We still look for updates in the cert store:
                    // the designated certificate could have been from
                    // a file with updates that are not in the
                    // certificate store.
                    if let Some(update) = cert_store.as_ref().and_then(|cs| {
                        cs.lookup_by_cert_fpr(&cert.fingerprint()).ok()
                    }) {
                        let (cert_, updated_) = cert.insert_packets(
                            update.to_cert()?.clone().into_packets())?;
                        cert = cert_;
                        if updated_ {
                            updated = true;
                        } else {
                            unchanged = true;
                        }
                    }

                    if updated {
                        status(&cert, "updated");
                    } else if unchanged {
                        status(&cert, "unchanged");
                    } else {
                        status(&cert, "retained");
                    }

                    if updated {
                        wkd::insert(&push, &c.domain, variant, &cert)
                            .with_context(|| {
                                format!("Inserting {}, {}",
                                        cert.fingerprint(),
                                        sq.best_userid(&cert, true)
                                        .display())
                            })?;
                        *number_of_changes_ref += 1;
                    }
                }
                Ok(())
            })?;

            // Insert the new ones, if any.
            for (_fpr, cert) in insert.into_iter() {
                status(&cert, "inserted");
                wkd::insert(&push, &c.domain, variant, &cert)
                    .with_context(|| {
                        format!("Inserting {}, {}",
                                cert.fingerprint(),
                                sq.best_userid(&cert, true).display())
                    })?;
                number_of_changes += 1;
            }

            // Preserve the original policy file, if any.
            if let Some(policy) = policy {
                let path = match variant {
                    Variant::Direct => push_openpgpkey.join("policy"),
                    Variant::Advanced =>
                        push_openpgpkey.join(&c.domain).join("policy"),
                };

                fs::create_dir_all(
                    path.parent().expect("at least two components"))?;
                fs::copy(policy, &path)
                    .with_context(|| {
                        format!("Updating {}", path.display())
                    })?;
            }

            if number_of_changes == 0 {
                qprintln!("No updates.");
            } else {
                // Finally, transfer the WKD hierarchy back.
                transfer(&rsync, &push_wk.display().to_string(),
                         &format!("{}", c.destination))
                    .with_context(|| {
                        format!("failed to push updates to {}",
                                c.destination)
                    })?;
                qprintln!("{} applied.", number_of_changes.of("update"));
            }
        },
    }

    Ok(())
}

fn transfer(rsync_bin: &Option<PathBuf>, source: &str, destination: &str)
            -> Result<()>
{
    if let Some(r) = rsync_bin {
        rsync(r, source, destination)
    } else {
        copy(source, destination)
    }
}

fn copy(source: &str, destination: &str) -> Result<()> {
    let options = fs_extra::dir::CopyOptions::new()
        .overwrite(true);

    std::fs::create_dir_all(destination)?;
    fs_extra::dir::copy(source, destination, &options)?;
    Ok(())
}

fn rsync(rsync: &Path, source: &str, destination: &str) -> Result<()> {
    use std::process::Command;

    let status = Command::new(rsync)
        .arg("--recursive")
        .arg(source)
        .arg(destination)
        .spawn()?
        .wait()?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("rsync failed"))
    }
}

// one possible implementation of walking a directory only visiting files
fn visit_dirs(dir: &Path, cb: &mut dyn FnMut(&DirEntry) -> Result<()>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}

pub fn dispatch_dane(sq: Sq, c: cli::network::dane::Command)
                     -> Result<()> {
    use crate::cli::network::dane::Subcommands::*;
    match c.subcommand {
        Generate(mut c) => {
            // Make `--all` implicitly select all certs with a user ID
            // matching `--domain` that can be authenticated.
            if c.all {
                use cli::types::cert_designator::CertDesignator;
                c.certs.push(CertDesignator::Domain(c.domain.clone()));
            }

            let (certs, errors) = sq.resolve_certs(
                &c.certs, TrustThreshold::Full)?;
            for error in errors.iter() {
                print_error_chain(error);
            }
            if ! errors.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve certificates"));
            }

            for cert in certs {
                let vc = cert.with_policy(sq.policy(), sq.time())?;

                use sqz::types::ResourceRecordType;
                let records = match c.typ {
                    ResourceRecordType::OpenPGP =>
                        dane::generate(&vc, &c.domain, c.ttl, c.size_limit)?,
                    ResourceRecordType::Generic =>
                        dane::generate_generic(&vc, &c.domain, c.ttl,
                                               c.size_limit)?,
                };

                records.iter().for_each(|r| println!("{}", r));
            }
        },
        Search(c) => {
            let queries = if c.all {
                Query::all_addresses(&sq.sequoia)?
            } else {
                Query::parse_addresses(&c.addresses)?
            };

            let mut output_;
            let (output, output_path) = if let Some(output) = c.output.as_ref() {
                output_ = output.create_safe(&sq)?;
                let output_path = output.path().map(|p| p.clone());
                (Some(&mut output_ as &mut _), Some(output_path))
            } else {
                (None, None)
            };

            let prompt = password::PromptFactory::new(&sq, true);

            let mut stream = Stream::new(
                &sq,
                true,
                output_path);

            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                sq.sequoia.network_search()
                    .stream(&mut stream)
                    .prompt(prompt)
                    .iterations(1)
                    .clear_sources()
                    .query_dane(true)
                    .to_writer(output)
                    .search(queries).await
            })?;
        }
    }

    Ok(())
}
