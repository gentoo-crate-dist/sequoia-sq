//! A high-level API for Sequoia.
//!
//! This library implements a high-level API for [Sequoia].  The goal
//! is to provide an opinionated API for developers who want to use
//! [OpenPGP] in their applications, but don't want to understand the
//! details of OpenPGP or Sequoia.
//!
//! OpenPGP has a lot of data structures, and, as with all
//! security-related code, care has to be taken to use them correctly.
//! The Sequoia ecosystem includes about 20 crates and understanding
//! how they related to each other can take a while.  This library
//! hopes to alleviate this problem by providing a few functions that
//! are hard to use wrong and take care of most of the details.
//!
//! To achieve this, `sequoia` makes strong assumptions about what the
//! user wants.  But, if it turns out that some function's semantics
//! are not completely appropriate, it is often possible to tweak its
//! behavior.  When even that is not enough, it is possible to mix in
//! use of the low-level APIs.  This works, because the high-level
//! don't replace the low-level abstractions, but are built on and
//! reuse them.
//!
//! [Sequoia]: https://sequoia-pgp.org
//! [OpenPGP]: https://www.rfc-editor.org/rfc/rfc9580.html
//!
//! If you have used [`sq`], Sequoia's primary command line interface,
//! then the interfaces exposed by this library will seem very
//! familiar: [`sq`]'s interface was a primary inspiration for this
//! library, and it has largely been re-implemented in terms of this
//! library.  For instance, to verify a message using `sq`, you would
//! use `sq verify`.  Using this library, you would use
//! [`Sequoia::verify`], which is in the [`sequoia::verify`] module.
//!
//! [`sq`]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq.1.html
//!
//! # Getting Started
//!
//! The first thing that you will have to do is to create a
//! [`Sequoia`] context.  Upon instantiation, a `Sequoia` context
//! reads in the configuration unless it has been disabled using
//! [`SequoiaBuilder`].  A `Sequoia` context also holds global state,
//! like references to the certificate store, and the key store.
//!
//! To create a Sequoia context using the default home directory, you
//! can do:
//!
//! ```rust
//! use sequoia::Sequoia;
//! use sequoia::prompt::Cancel;
//!
//! # fn main() -> sequoia::Result<()> {
//! let sequoia = Sequoia::new(Cancel::new())?;
//! # Ok(()) }
//! ```
//!
//! We supply the [`Cancel`](crate::prompt::Cancel) implementation of
//! [`PromptFactory`](crate::prompt::PromptFactory`).  `PromptFactory`
//! returns objects that implement [`Prompt`](crate::prompt::Prompt`),
//! which is the mechanism that this library uses to prompt the user
//! for passwords (see the [`prompt`] module's documentation), to
//! insert a smartcard, etc.  `Cancel` simulates the user pressing
//! cancel at the prompt.  You should provide your own implementation
//! of `PromptFactory` and `Prompt`, which is appropriate for your
//! application.
//!
//! One of the most common operations is to verify a signature (see
//! [`sequoia::verify`]).  The following example verifies that a
//! signature over a file is valid, and that the signing certificate
//! can be authenticated.
//!
//! ```
//! use sequoia::Sequoia;
//! use sequoia::openpgp::Cert;
//! use sequoia::openpgp::parse::Parse;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let sequoia = Sequoia::builder().ephemeral()?.build()?;
//! # let alice = sequoia
//! #   .key_generate()
//! #   .email("alice@example.org")
//! #   .without_password()
//! #   .generate()?;
//! #
//! # let file = b"I own you";
//! # let mut signature = Vec::new();
//! # sequoia.sign()
//! #   .detached()
//! #   .add_signer(alice.cert().clone())
//! #   .sign(
//! #       std::io::Cursor::new(file),
//! #       &mut signature)?;
//! #
//! # if false {
//! let qubes_release_key = Cert::from_file("qubes-release-4.3-signing-key.asc")?;
//! let signature = std::fs::File::open("Qubes-R4.3.1-x86_64.iso.asc")?;
//! let file = std::fs::File::open("Qubes-R4.3.1-x86_64.iso")?;
//! # }
//! # let qubes_release_key = alice.into_cert();
//! # let signature = std::io::Cursor::new(signature);
//! # let file = std::io::Cursor::new(file);
//!
//! sequoia
//!     .verify()
//!     .add_designated_signer(qubes_release_key)
//!     .detached_signature(file, signature, std::io::empty())?;
//! # Ok(()) }
//! ```
//!
//! # Overview
//!
//! The following sections list the functionality exposed by this
//! library.  Each section contains one or more functions that fall
//! into the section's category.  The table links to the module, which
//! provides a detailed description of the function, and examples, the
//! method on the [`Sequoia`] context, and the related `sq` commands.
//!
//! ## Messages
//!
//! | Functionality | Module               | Function             | `sq` equivalent |
//! |---------------|----------------------|----------------------|-|
//! | Verify        | [`sequoia::verify`]  | [`Sequoia::verify`]  | [`sq verify`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-verify.1.html) |
//! | Sign          | [`sequoia::sign`]    | [`Sequoia::sign`]    | [`sq sign`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-sign.1.html) |
//! | Decryption    | [`sequoia::decrypt`] | [`Sequoia::decrypt`] | [`sq decrypt`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-decrypt.1.html) |
//! | Encryption    | [`sequoia::encrypt`] | [`Sequoia::encrypt`] | [`sq encrypt`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-encrypt.1.html) |
//!
//! ## Certificate Management
//!
//! | Functionality             | Module                    | Function                 | `sq` equivalent |
//! |---------------------      |---------------------------|--------------------------|-|
//! | Import certificates       | [`sequoia::cert::import`] | [`Sequoia::cert_import`] | [`sq cert import`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-cert-import.1.html) |
//! | List certificates         | [`sequoia::cert::list`]   | [`Sequoia::cert_list`]   | [`sq cert list`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-cert-list.1.html), [`sq pki authenticate`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-authenticate.1.html), [`sq pki lookup`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-lookup.1.html), [`sq pki identify`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-identify.1.html), and [`sq pki path`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-path.1.html) |
//! | Lookup a certificate...   |
//! | &nbsp;...by fingerprint   | [`sequoia::lookup`]      | [`Sequoia::lookup`] | - |
//! | &nbsp;...by email address | [`sequoia::lookup_by`] | [`Sequoia::lookup_by`] | - |
//!
//! ## PKI
//!
//! | Functionality                     | Module                    | Function                 | `sq` equivalent |
//! |-----------------------------------|---------------------------|--------------------------|-|
//! | Certify a user ID and certificate | [`sequoia::pki::certify`] | [`Sequoia::pki_certify`] | [`sq pki link add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-link-add.1.html), [`sq pki link authorize`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-link-authorize.1.html), [`sq pki vouch add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-vouch-add.1.html), and [`sq pki vouch authorize`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-pki-vouch-authorize.1.html) |
//!
//! ## Network Search
//!
//! | Functionality                          | Module                       | Function                    | `sq` equivalent |
//! |----------------------------------------|------------------------------|-----------------------------|-|
//! | Search for certificates on the network | [`sequoia::network::search`] | [`Sequoia::network_search`] | [`sq network search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-search.1.html), [`sq network keyserver search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-keyserver-search.1.html), [`sq network wkd search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-wkd-search.1.html), [`sq network dane search`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-dane-search.1.html) |
//!
//! ## Key Management
//!
//! | Functionality                          | Module                       | Function                    | `sq` equivalent |
//! |----------------------------------------|------------------------------|-----------------------------|-|
//! | Generate a key                         | [`sequoia::key::generate`]   | [`Sequoia::key_generate`]   | [`sq key generate`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-generate.1.html) |
//! | Import a key                           | [`sequoia::key::import`]     | [`Sequoia::key_import`]     | [`sq key import`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-import.1.html) |
//! | Modify a certificate's expiration      | [`sequoia::key::expire`]     | [`Sequoia::key_expire`]     | [`sq key expire`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-expire.1.html) |
//! | Revoke a certificate                   | [`sequoia::key::revoke`]     | [`Sequoia::key_revoke`]     | [`sq key revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-revoke.1.html) |
//!
//! ### User IDs
//!
//! | Functionality    | Module                           | Function                       | `sq` equivalent |
//! |------------------|----------------------------------|--------------------------------|-|
//! | Add a user ID    | [`sequoia::key::userid::add`]    | [`Sequoia::key_userid_add`]    | [`sq key userid add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-userid-add.1.html) |
//! | Revoke a user ID | [`sequoia::key::userid::revoke`] | [`Sequoia::key_userid_revoke`] | [`sq key userid revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-userid-revoke.1.html) |
//!
//! ### Subkeys
//!
//! | Functionality   | Module                           | Function                       | `sq` equivalent |
//! |-----------------|----------------------------------|--------------------------------|-|
//! | Add a subkey    | [`sequoia::key::subkey::add`]    | [`Sequoia::key_subkey_add`]    | [`sq key subkey add`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-subkey-add.1.html) |
//! | Revoke a subkey | [`sequoia::key::subkey::revoke`] | [`Sequoia::key_subkey_revoke`] | [`sq key subkey revoke`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-subkey-revoke.1.html) |
//!
//! ### Certification Approval Management
//!
//! The approval functionality allows an owner of a certificate to
//! indicate what certifications should be distributed with their
//! certificate.  Key servers that respect this attribute will strip
//! other third-party certifications.  This mechanism can help prevent
//! malicious third parties from blowing up the size of a certificate
//! by creating many third-party certifications.
//!
//! | Functionality    | Module                              | Function                          | `sq` equivalent |
//! |------------------|-------------------------------------|-----------------------------------|-|
//! | List approvals   | [`sequoia::key::approvals::list`]   | [`Sequoia::key_approvals_list`]   | [`sq key approvals list`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-approvals-list.1.html) |
//! | Update approvals | [`sequoia::key::approvals::update`] | [`Sequoia::key_approvals_update`] | [`sq key approvals update`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-key-approvals-update.1.html) |
//!
//! ## Analysis
//!
//! | Functionality                          | Module                       | Function                        | `sq` equivalent |
//! |----------------------------------------|------------------------------|---------------------------------|-|
//! | Inspect some data                      | [`sequoia::inspect`]         | [`sequoia::inspect::inspect`]   | [`sq inspect`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-inspect.1.html) |
//! | Dump OpenPGP data structures           | [`sequoia::packet::dump`]    | [`sequoia::packet::dump::dump`] | [`sq packet dump`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-packet-dump.1.html) |

// For the library document so that we can use `sequoia::...` instead
// of `crate::...`.
#[cfg(doc)]
use crate::{self as sequoia};

use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
    time::UNIX_EPOCH,
};

#[macro_use] mod log;
#[macro_use] mod macros;
#[macro_use] mod boilerplate;

use anyhow::Context;

// Re-exports.
pub use anyhow;
pub use sequoia_autocrypt as autocrypt;
pub use sequoia_cert_store as cert_store;
pub use sequoia_directories as directories;
pub use sequoia_keystore as key_store;
pub use sequoia_ipc as ipc;
#[cfg(feature = "net")]
pub use sequoia_net as net;
pub use sequoia_openpgp as openpgp;
pub use sequoia_policy_config as policy_config;
pub use sequoia_wot as wot;

use openpgp::Fingerprint;
use openpgp::cert::raw::RawCertParser;
use openpgp::crypto::Password;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;

use cert_store::StoreUpdate;
use cert_store::store::openpgp_cert_d;

#[macro_use] mod transitional;
#[macro_use] mod destination;
#[macro_use] mod errors;
pub use errors::SystemError;

pub mod cert;
pub mod consts;
pub mod decrypt;
mod decrypt_key;
pub mod encrypt;
pub mod inspect;
pub mod key;
#[cfg(feature = "net")]
pub mod network;
pub mod pki;
pub mod provenance;
mod shadow_ca;
pub use shadow_ca::Ca;
pub mod sign;
pub mod types;
pub mod userid;
use types::StateDirectory;
mod writer;
pub use writer::OptionalWriter;
pub use writer::Writer;

mod best_userid;
mod builder;
pub use builder::SequoiaBuilder;
mod compat;
pub mod config;
use config::Config;
use config::ConfigFile;
pub mod signer;
pub mod lookup;
pub mod lookup_by;
pub mod packet;
pub mod prompt;
mod password_cache;
mod time;
pub use time::Time;
mod utils;
pub mod verify;

// XXX transitional: Switch to our own Error type.
pub type Result<T, E=anyhow::Error> = anyhow::Result<T, E>;

static STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
static NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };
const TRACE: bool = false;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Sequoia {
    /// The home directory.
    ///
    /// If `None`, then the `Sequoia` instance should operate in
    /// stateless mode.
    home: Option<Cow<'static, sequoia_directories::Home>>,

    /// The configuration.
    config_file: ConfigFile,
    config: Config,

    /// The current time.
    time: Clock,

    /// The default prompt.
    prompt: Box<dyn prompt::PromptFactory<'static>>,

    /// Overrides the path to the cert store.
    cert_store_path: Option<types::StateDirectory>,

    /// This will be set if the cert store has not been disabled, OR
    /// --keyring is passed.
    ///
    /// The u64 is the policy time (in seconds since the UNIX epoch)
    /// of the WotStore.
    cert_store: Mutex<Option<(u64, Arc<WotStore>)>>,

    /// Additional keyrings to read.
    keyrings: Vec<PathBuf>,

    /// Map from key fingerprint to cert fingerprint and the key.
    keyring_tsks: OnceLock<BTreeMap<
            Fingerprint,
        (Fingerprint, Key<PublicParts, UnspecifiedRole>)>>,

    /// Additional trust roots.
    trust_roots: Vec<Fingerprint>,

    /// The key store.
    key_store_path: Option<StateDirectory>,
    key_store: once_cell::sync::OnceCell<Mutex<key_store::Keystore>>,

    /// Path to our IPC servers.
    ipc_server_path: PathBuf,

    /// A password cache.  When encountering a locked key, we first
    /// consult the password cache.  The passwords are only tried if
    /// it is safe.  That is, the passwords are only tried if we are
    /// sure that the key is not protected by a retry counter.  If the
    /// password cache doesn't contain the correct password, or the
    /// key is protected by a retry counter, the user is prompted to
    /// unlock the key.  The correct password is added to the cache.
    password_cache: Mutex<Vec<Password>>,
}

impl Sequoia {
    /// Returns a new builder.
    pub fn builder() -> SequoiaBuilder {
        SequoiaBuilder::new()
    }

    /// Returns a new `Sequoia` instance using all the defaults.
    pub fn new<P>(prompt: P) -> Result<Sequoia>
    where
        P: prompt::PromptFactory<'static> + 'static,
    {
        Sequoia::builder()
            .prompt(prompt)
            .build()
    }

    /// Returns a builder providing control over how to import
    /// certificates.
    ///
    /// See [`cert::import::Builder`] for details.
    pub fn cert_import<'sequoia, 'stream, 'prompt>(&'sequoia self)
        -> cert::import::Builder<'sequoia, 'stream, 'prompt>
    {
        cert::import::Builder::new(self)
    }

    /// List bindings.
    ///
    /// See [`cert::list::Builder`] for details.
    pub fn cert_list<'sequoia>(&'sequoia self)
        -> cert::list::Builder<'sequoia>
    {
        cert::list::Builder::new(self)
    }

    /// Lookup a certificate by a human-meaningful identifier.
    ///
    /// See [`lookup_by`] for details.
    pub fn lookup_by<'sequoia>(&'sequoia self)
        -> lookup_by::Builder<'sequoia>
    {
        lookup_by::Builder::new(self)
    }

    /// Returns a builder for decrypting and verifying messages.
    ///
    /// See [`decrypt::Builder`] for details.
    pub fn decrypt<'sequoia, 'stream, 'prompt>(&'sequoia self)
        -> decrypt::Builder<'sequoia, 'stream, 'prompt>
    {
        decrypt::Builder::new(self)
    }

    /// Returns a builder providing control over how to encrypt a message.
    ///
    /// See [`encrypt::Builder`] for details.
    pub fn encrypt<'sequoia, 'stream, 'prompt>(&'sequoia self)
        -> encrypt::Builder<'sequoia, 'stream, 'prompt>
    {
        encrypt::Builder::new(self)
    }

    pub fn key_approvals_list<'sequoia>(&'sequoia self)
        -> key::approvals::list::Builder<'sequoia>
    {
        key::approvals::list::Builder::new(self)
    }

    pub fn key_approvals_update<'sequoia, 'prompt>(&'sequoia self)
        -> key::approvals::update::Builder<'sequoia, 'prompt>
    {
        key::approvals::update::Builder::new(self)
    }

    /// Returns a builder providing control over how to change a
    /// certificate or a key's expiration.
    ///
    /// See [`key::expire::Builder`] for details.
    pub fn key_expire<'sequoia, 'prompt>(&'sequoia self)
        -> key::expire::Builder<'sequoia, 'prompt>
    {
        key::expire::Builder::new(self)
    }

    /// Returns a builder providing control over how to generate a
    /// certificate.
    ///
    /// By default, this creates a certificate with a signing, an
    /// authentication, and an encryption subkey.
    ///
    /// The default expiration is
    /// [`DEFAULT_KEY_VALIDITY_DURATION`](crate::config::DEFAULT_KEY_VALIDITY_DURATION).
    ///
    /// See [`key::generate::Builder`] for details.
    pub fn key_generate<'sequoia, 'writer, 'prompt>(&'sequoia self)
        -> key::generate::Builder<'sequoia, 'writer, 'prompt>
    {
        key::generate::Builder::new(self)
    }

    /// Returns a builder providing control over how to import
    /// keys.
    ///
    /// See [`key::import::Builder`] for details.
    pub fn key_import<'sequoia, 'stream>(&'sequoia self)
        -> key::import::Builder<'sequoia, 'stream>
    {
        key::import::Builder::new(self)
    }

    /// Returns a builder providing control over how to revoke
    /// a certificate.
    ///
    /// See [`key::revoke::Builder`] for details.
    pub fn key_revoke<'sequoia, 'prompt>(&'sequoia self)
        -> key::revoke::Builder<'sequoia, 'prompt>
    {
        key::revoke::Builder::new(self)
    }

    /// Returns a builder providing control over how to add a subkey
    /// to a certificate.
    ///
    /// The default expiration for the new subkey is
    /// [`DEFAULT_KEY_VALIDITY_DURATION`](crate::config::DEFAULT_KEY_VALIDITY_DURATION).
    ///
    /// See [`key::subkey::add::Builder`] for details.
    pub fn key_subkey_add<'sequoia, 'prompt>(&'sequoia self)
        -> key::subkey::add::Builder<'sequoia, 'prompt>
    {
        key::subkey::add::Builder::new(self)
    }

    /// Returns a builder providing control over how to revoke
    /// subkeys.
    ///
    /// See [`key::subkey::revoke::Builder`] for details.
    pub fn key_subkey_revoke<'sequoia, 'prompt>(&'sequoia self)
        -> key::subkey::revoke::Builder<'sequoia, 'prompt>
    {
        key::subkey::revoke::Builder::new(self)
    }

    /// Returns a builder providing control over how to add a user ID
    /// to a certificate.
    ///
    /// See [`key::userid::add::Builder`] for details.
    pub fn key_userid_add<'sequoia, 'prompt>(&'sequoia self)
        -> key::userid::add::Builder<'sequoia, 'prompt>
    {
        key::userid::add::Builder::new(self)
    }

    /// Returns a builder providing control over how to revoke
    /// user IDs.
    ///
    /// See [`key::userid::revoke::Builder`] for details.
    pub fn key_userid_revoke<'sequoia, 'prompt>(&'sequoia self)
        -> key::userid::revoke::Builder<'sequoia, 'prompt>
    {
        key::userid::revoke::Builder::new(self)
    }

    /// Search for certificates on the network.
    ///
    /// By default, the search function will search all sources, and
    /// will iterate up to three times.  Each iteration uses the
    /// results of the previous iteration to generate related queries.
    ///
    /// See [`network::search::Builder`] for details.
    #[cfg(feature = "net")]
    pub fn network_search<'sequoia, 'writer, 'stream, 'prompt>(&'sequoia self)
        -> network::search::Builder<'sequoia, 'writer, 'stream, 'prompt>
    {
        network::search::Builder::new(self)
    }

    /// Returns a builder providing control over how to import
    /// keys.
    ///
    /// See [`pki::certify::Builder`] for details.
    pub fn pki_certify<'sequoia, 'writer, 'stream, 'prompt>(&'sequoia self)
        -> pki::certify::Builder<'sequoia, 'writer, 'stream, 'prompt>
    {
        pki::certify::Builder::new(self)
    }

    /// Returns a builder providing control over how to generate a
    /// signature.
    ///
    /// See [`sign::Builder`] for details.
    pub fn sign<'sequoia, 'stream, 'prompt>(&'sequoia self)
        -> sign::Builder<'sequoia, 'stream, 'prompt,
                         sign::builder::UnspecifiedSignatureType>
    {
        sign::Builder::new(self)
    }

    /// Returns a signer for a given a certificate.
    ///
    /// See [`signer`] for details.
    pub fn signer<'sequoia, 'policy, 'prompt>(&'sequoia self)
        -> signer::Builder<'sequoia, 'policy, 'prompt>
    {
        signer::Builder::new(self)
    }

    /// Returns the home directory.
    ///
    /// This returns `None` if this `Sequoia` instance is configured to
    /// operate in stateless mode.
    pub fn home(&self) -> Option<&sequoia_directories::Home> {
        self.home.as_deref()
    }

    /// Returns whether this `Sequoia` instance is operating in
    /// stateless mode.
    pub fn stateless(&self) -> bool {
        self.home.is_none()
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Returns a reference to the configuration file.
    pub fn config_file(&self) -> &ConfigFile {
        &self.config_file
    }

    /// Returns the OpenPGP policy.
    pub fn policy(&self) -> &openpgp::policy::StandardPolicy<'static> {
        self.config.policy()
    }

    /// Returns the configured time.
    pub fn time(&self) -> SystemTime {
        self.time.get()
    }

    /// Returns whether the configured time approximates the current
    /// time.
    pub fn time_is_now(&self) -> bool {
        self.time.is_now()
    }

    /// Returns whether the cert store is disabled.
    fn no_rw_cert_store(&self) -> bool {
        self.cert_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        let default = || if let Ok(path) = std::env::var("PGP_CERT_D") {
            Some(PathBuf::from(path))
        } else {
            self.home()
                .map(|h| h.data_dir(sequoia_directories::Component::CertD))
        };

        if let Some(state) = self.cert_store_path.as_ref() {
            match state {
                StateDirectory::Absolute(p) => Some(p.clone()),
                StateDirectory::Default => default(),
                StateDirectory::None => None,
            }
        } else {
            default()
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<Arc<WotStore>>, SystemError> {
        self.cert_store_()
            .map_err(|err| {
                SystemError::CertStoreError(err.into())
            })
    }

    fn cert_store_(&self) -> Result<Option<Arc<WotStore>>> {
        if self.no_rw_cert_store()
            && self.keyrings.is_empty()
        {
            // The cert store is disabled.
            return Ok(None);
        }

        let mut cert_store = self.cert_store.lock().unwrap();
        if let Some((current_secs, cs)) = cert_store.as_ref() {
            // If the WotStore is out of date, then re-initialize it.
            let now = self.time();
            let now_secs = now.duration_since(UNIX_EPOCH)
                .map(|t| t.as_secs())
                .unwrap_or(0);
            if now_secs == *current_secs {
                // The cert store is already initialized for the
                // current time, return it.
                return Ok(Some(Arc::clone(&cs)));
            } else {
                // Re-initialize it.
                let result = Arc::new(WotStore::from_store(
                    Arc::clone(cs.store()),
                    Box::new(self.policy().clone()) as Box::<dyn Policy>,
                    now));
                *cert_store = Some((now_secs, Arc::clone(&result)));
                return Ok(Some(result));
            }
        }

        let create_dirs = |path: &Path| -> Result<()> {
            use std::fs::DirBuilder;

            let mut b = DirBuilder::new();
            b.recursive(true);

            // Create the parent with the normal umask.
            if let Some(parent) = path.parent() {
                // Note: since recursive is turned on, it is not an
                // error if the directory exists, which is exactly
                // what we want.
                b.create(parent)
                    .with_context(|| {
                        format!("Creating the directory {:?}", parent)
                    })?;
            }

            // Create path with more restrictive permissions.
            platform!{
                unix => {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                },
                windows => {
                },
            }

            b.create(path)
                .with_context(|| {
                    format!("Creating the directory {:?}", path)
                })?;

            Ok(())
        };

        // We need to initialize the cert store.
        let mut cs = if ! self.no_rw_cert_store() {
            // Open the cert-d.

            let path = self.cert_store_base()
                .expect("just checked that it is configured");

            create_dirs(&path)
                .and_then(|_| cert_store::CertStore::open(&path))
                .with_context(|| {
                    format!("While opening the certificate store at {:?}",
                            &path)
                })?
        } else {
            cert_store::CertStore::empty()
        };

        let keyring = cert_store::store::Certs::empty();
        let mut tsks = BTreeMap::new();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        for key in cert.keys() {
                            if key.has_secret() {
                                tsks.insert(
                                    key.fingerprint(),
                                    (cert.fingerprint(), key.clone()));
                            }
                        }

                        keyring.update(Arc::new(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        self.keyring_tsks.set(tsks).expect("uninitialized");

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        cs.add_backend(
            Box::new(keyring),
            cert_store::AccessMode::Always);

        // Sync certs from GnuPG's state if we are using the user's
        // default home directory.
        if self.home().map(|h| h.is_default_location())
            .unwrap_or(false)
            && std::env::var("GNUPGHOME").is_err()
        {
            if let Err(e) = crate::compat::sync_from_gnupg(self, &cs) {
                self.warn(format_args!(
                    "Syncing state from GnuPG failed: {}", e));
            }
        }

        let now = self.time();
        let result = Arc::new(WotStore::from_store(
            Arc::new(cs), Box::new(self.policy().clone()) as Box::<dyn Policy>,
            now));

        let now_secs = now.duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs())
            .unwrap_or(0);

        *cert_store = Some((now_secs, Arc::clone(&result)));

        Ok(Some(result))
    }

    fn no_cert_store_err() -> SystemError {
        errors::SystemError::CertStoreDisabled
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else<'s>(&'s self) -> Result<Arc<WotStore>, SystemError> {
        self.cert_store()
            .and_then(|cert_store| {
                cert_store
                    .ok_or_else(|| {
                        Self::no_cert_store_err()
                    })
            })
    }

    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::NetworkBuilder<Arc<WotStore>>>
    {
        let cert_store = self.cert_store_or_else()?;
        let network = wot::NetworkBuilder::rooted(cert_store,
                                                  &*self.trust_roots());
        Ok(network)
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = || -> Option<Fingerprint> {
            let cert_store = self.cert_store_or_else().ok()?;
            let certd = cert_store.certd()?;

            let path = certd.certd()
                .get_path(openpgp_cert_d::TRUST_ROOT)
                .ok()?;

            if path.exists() {
                Some(self.local_trust_root().ok()?.fingerprint())
            } else {
                None
            }
        };

        if let Some(trust_root_local) = trust_root_local() {
            self.trust_roots.iter().cloned()
                .chain(std::iter::once(trust_root_local.clone()))
                .collect()
        } else {
            self.trust_roots.clone()
        }
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        let default = || {
            Ok(self.home()
               .map(|h| h.data_dir(directories::Component::Keystore)))
        };

        if let Some(dir) = self.key_store_path.as_ref() {
            match dir {
                StateDirectory::Absolute(p) => Ok(Some(p.clone())),
                StateDirectory::Default => default(),
                StateDirectory::None => Ok(None),
            }
        } else {
            default()
        }
    }

    /// Returns whether the key store is disabled.
    fn no_key_store(&self) -> bool {
        self.key_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.stateless())
    }

    fn no_key_store_err() -> SystemError {
        errors::SystemError::KeyStoreDisabled
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        if self.no_key_store() {
            Err(Self::no_key_store_err().into())
        } else {
            self.key_store_path()?
                .ok_or_else(|| {
                    Self::no_key_store_err().into()
                })
        }
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self)
        -> Result<Option<&Mutex<key_store::Keystore>>, SystemError>
    {
        self.key_store_()
            .map_err(|err| {
                SystemError::KeyStoreError(err.into())
            })
    }

    fn key_store_(&self) -> Result<Option<&Mutex<key_store::Keystore>>> {
        if self.no_key_store() {
            return Ok(None);
        }

        self.key_store
            .get_or_try_init(|| {
                let c = key_store::Context::configure()
                    .home(self.key_store_path_or_else()?)
                    .lib(self.ipc_server_path())
                    .build()?;

                let ks = key_store::Keystore::connect(&c)
                    .context("Connecting to key store")?;

                Ok(Mutex::new(ks))
            })
            .map(Some)
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self)
        -> Result<&Mutex<key_store::Keystore>, SystemError>
    {
        self.key_store()
            .and_then(|key_store| {
                key_store
                    .ok_or_else(|| {
                        Self::no_key_store_err()
                    })
            })
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> Result<&BTreeMap<Fingerprint,
                            (Fingerprint, Key<PublicParts, UnspecifiedRole>)>>
    {
        if let Some(keyring_tsks) = self.keyring_tsks.get() {
            Ok(keyring_tsks)
        } else {
            // This also initializes keyring_tsks.
            self.cert_store()?;

            // If something went wrong, we just set it to an empty
            // map.
            Ok(self.keyring_tsks.get_or_init(|| BTreeMap::new()))
        }
    }

    /// Returns the path to the IPC servers.
    pub fn ipc_server_path(&self) -> &Path {
        &self.ipc_server_path
    }

    /// Emits a warning.
    pub(crate) fn warn(&self, msg: std::fmt::Arguments) {
        let _ = msg; // XXX
    }

    /// Emits a warning showing an error message.
    pub(crate) fn warn_err(&self, err: &anyhow::Error) {
        let _ = err; // XXX
    }
}

#[derive(Clone, Default)]
enum Clock {
    /// Always use the current time.
    ///
    /// This is the default, and good for long-running programs.
    #[default]
    Realtime,

    /// Freeze the time the Sequoia context is built.
    Frozen(SystemTime),

    /// Use the given time.
    Fix(SystemTime),
}

impl Clock {
    /// Returns the configured time.
    fn get(&self) -> SystemTime {
        match self {
            Clock::Realtime => SystemTime::now(),
            Clock::Frozen(t) => *t,
            Clock::Fix(t) => *t,
        }
    }

    /// Returns whether the configured time approximates the current
    /// time.
    fn is_now(&self) -> bool {
        ! matches!(self, Clock::Fix(_))
    }
}

/// A shorthand for our store type.
type WotStore
    = wot::store::CertStore<'static, 'static, Arc<cert_store::CertStore<'static>>>;

/// The creation time for the trust root and intermediate CAs.
///
/// We use a creation time in the past (Feb 2002) so that it is still
/// possible to use the CA when the reference time is in the past.
// XXX: This is copied from sequoia-cert-store.  It would be nice to
// import it, but it is private.
pub fn ca_creation_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::new(1014235320, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_trust_root() {
        // The local trust root is created and loaded on demand.  If
        // we call `Sequoia::trust_roots` and the local trust root
        // does not exist, it is not created.  Make sure that after we
        // create the local trust root, `Sequoia::trust_roots` returns
        // it.

        let sq = Sequoia::builder().ephemeral().unwrap().build().unwrap();

        assert!(sq.trust_roots().is_empty());

        let trust_root = sq.local_trust_root()
            .expect("Created trust root");

        assert_eq!(sq.trust_roots(), &[trust_root.fingerprint()]);
    }
}
