//! `oneiron hosted login --origin <url>` with no credential: this user signs
//! in to the hosted vault through the vault's own OAuth 2.1 server, as a
//! native app (RFC 8252; ruling L1-14-HOSTED-LOGIN = B, Engine Sat 14 Nov
//! 03:02).
//!
//! The command reads the vault's protected-resource document for the
//! resource and its issuer, listens on a loopback port, registers a public
//! client with that loopback redirect, and prints the authorize URL (PKCE
//! S256, a fresh `state`, the `read` scope, the `resource`) and opens it in a
//! browser. The vault's page shows a match code, and the owner allows the
//! request in his inbox, where the same code shows; the browser then comes
//! back to the loopback with the code. The command checks `state` and `iss`,
//! exchanges the code with its verifier, and writes the tokens to one
//! owner-only file ([`crate::commands::oauth_sign_in`]). Nothing here mints
//! authority: the hook then reaches the vault as an ordinary OAuth agent in
//! the owner's consent registry, at the tier he allowed.
//!
//! The continue step-up ([`SignInAsk::Continue`]) runs the same flow for
//! the vault's `/mcp` and `/git` in one sign-in at the `full` tier, as the
//! client the recall sign-in registered, so the owner's ask names the same
//! agent and says it asks to continue this session in his hosted vault
//! (lead rulings CONTINUE-PUSH-GIT-TIER = C, Sat 21 Nov 05:4x, and
//! CONTINUE-STEP-UP-MCP-WRITE = A, 06:1x). The recall sign-in stays `read`
//! at `/mcp` ([`super::hosted_continue_sign_in`]).
//!
//! The hand-over sign-in ([`SignInAsk::HandOver`]) runs it for the vault's
//! `/mcp` alone at `full`, as the same client, naming the purpose
//! `session_hand_over`, so the owner's ask says it asks to land this
//! machine's coding sessions in his hosted vault as each ends; only the
//! hooks' hand-over reads it (HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER = B, lead
//! 07:0x; [`super::hand_over_queue`]).
//!
//! An unattended sign-in ([`CodeDelivery::Unattended`], `hosted login
//! --hand-over --unattended`, which the hooks start themselves) opens no
//! browser: the command loads the consent page itself, which records the
//! request and the owner's inbox ask, and polls its answer with the page's
//! token, as the page's script does; the allow's redirect carries the code.

mod unattended;

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;

pub(super) use self::unattended::SignInEnded;
use self::unattended::polled_code;
use super::hosted_selection::{self, HostedAuthMode, HostedVault};
use crate::api::{
    AUTHORIZE_PATH, PROTECTED_RESOURCE_GIT_METADATA_PATH, PROTECTED_RESOURCE_MCP_METADATA_PATH,
    PURPOSE_PARAMETER, REGISTER_PATH, REVOKE_PATH, SignInPurpose, TOKEN_PATH,
};
use crate::commands::oauth_sign_in::{
    self, MAX_ANSWER_BYTES, OAuthSession, OAuthSignIn, SignInParty,
};

/// Where the browser comes back to on the loopback.
const CALLBACK_PATH: &str = "/oauth/callback";
/// The tier a recall sign-in asks for: a hook recalls, and writes nothing.
const RECALL_SCOPE: &str = "read";
/// The tier the continue step-up asks for: the import and the start are
/// Write rows, and every receive-pack needs `core:write`.
const CONTINUE_SCOPE: &str = "full";
/// The tier the hand-over sign-in asks for: the import is a Write row.
const HAND_OVER_SCOPE: &str = "full";
/// The name the owner's ask and consent registry show for the client.
const CLIENT_NAME: &str = "oneiron hosted login";
/// The most of a callback request read: its request line and headers.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
/// How long one loopback connection may take to send its request.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the loopback is checked for the browser's return.
const CALLBACK_POLL: Duration = Duration::from_millis(100);

/// The vault's protected-resource document (RFC 9728).
#[derive(Deserialize)]
struct ProtectedResource {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// A registration's answer (RFC 7591 §3.2.1): the one field read.
#[derive(Deserialize)]
struct Registered {
    client_id: String,
}

/// What one sign-in asks the vault for.
#[derive(Clone, Copy, Debug)]
pub(super) enum SignInAsk<'a> {
    /// `hosted login`: a client registered now, the `/mcp` resource, the
    /// `read` tier.
    Recall,
    /// The continue step-up: the client `client_id` (the recall sign-in's),
    /// the `/mcp` and `/git` resources, the `full` tier.
    Continue { client_id: &'a str },
    /// The hand-over sign-in: the client `client_id` (the recall sign-in's),
    /// the `/mcp` resource alone, the `full` tier, the purpose
    /// [`SignInPurpose::SessionHandOver`].
    HandOver { client_id: &'a str },
}

impl<'a> SignInAsk<'a> {
    /// The paths of the protected-resource documents of the resources
    /// asked, in the order the request names them: `/mcp` first, whose
    /// document names the issuer.
    const fn metadata_paths(self) -> &'static [&'static str] {
        match self {
            Self::Recall | Self::HandOver { .. } => &[PROTECTED_RESOURCE_MCP_METADATA_PATH],
            Self::Continue { .. } => &[
                PROTECTED_RESOURCE_MCP_METADATA_PATH,
                PROTECTED_RESOURCE_GIT_METADATA_PATH,
            ],
        }
    }

    /// The tier asked, as its scope.
    const fn scope(self) -> &'static str {
        match self {
            Self::Recall => RECALL_SCOPE,
            Self::Continue { .. } => CONTINUE_SCOPE,
            Self::HandOver { .. } => HAND_OVER_SCOPE,
        }
    }

    /// The purpose the request names, when it names one: the vault then
    /// says what the sign-in asks to do in its own words.
    const fn purpose(self) -> Option<SignInPurpose> {
        match self {
            Self::Recall | Self::Continue { .. } => None,
            Self::HandOver { .. } => Some(SignInPurpose::SessionHandOver),
        }
    }

    /// The client a step-up signs in as: the recall sign-in's. `None` for
    /// the recall sign-in, which registers its own.
    const fn client_id(self) -> Option<&'a str> {
        match self {
            Self::Recall => None,
            Self::Continue { client_id } | Self::HandOver { client_id } => Some(client_id),
        }
    }

    /// What the person is asked to sign in for, after "To ".
    const fn why(self) -> &'static str {
        match self {
            Self::Recall => "sign in to",
            Self::Continue { .. } => "let `oneiron continue --cloud` move this session to",
            Self::HandOver { .. } => "let this machine's session ends land their logs in",
        }
    }
}

/// How a sign-in's code comes back once the owner allows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CodeDelivery {
    /// The person's browser opens the consent page and comes back to a
    /// one-time listener on this machine's loopback.
    Browser,
    /// No browser: this command loads the consent page itself, which files
    /// the owner's inbox ask, and polls his answer ([`unattended`]).
    Unattended,
}

/// Signs this user in at the vault at `origin` for what `ask` names and
/// writes the sign-in to `token_file`, within `timeout` from the start to
/// the code's return by `delivery`. Runs on the blocking pool of the
/// command's runtime.
pub(super) fn sign_in(
    origin: &str,
    token_file: &Path,
    timeout: Duration,
    ask: SignInAsk<'_>,
    delivery: CodeDelivery,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("hosted login signs in on the command's runtime"))?;
    let deadline = Instant::now() + timeout;
    let client = oauth_sign_in::endpoint_client()?;
    let mut documents = Vec::with_capacity(ask.metadata_paths().len());
    for path in ask.metadata_paths() {
        let document: ProtectedResource =
            runtime.block_on(get_json(&client, &format!("{origin}{path}")))?;
        documents.push(document);
    }
    let issuer = documents
        .first()
        .and_then(|document| document.authorization_servers.first())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{origin} names no authorization server for its MCP"))?;
    anyhow::ensure!(
        documents
            .iter()
            .all(|document| document.authorization_servers.first() == Some(&issuer)),
        "{origin}'s protected resources name different authorization servers"
    );
    // The first resource, `/mcp`, is the one the code is traded for and the
    // tokens refresh for; the family reaches every one named.
    let resource = documents[0].resource.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| anyhow::anyhow!("listen on the loopback: {error}"))?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    // A loopback redirect matches the client's on any port (RFC 8252 §7.3),
    // so the step-up's client is the recall sign-in's own.
    let client_id = match ask.client_id() {
        Some(client_id) => client_id.to_owned(),
        None => runtime.block_on(register(&client, origin, &redirect_uri))?,
    };
    let verifier = random_text(32);
    let state = random_text(16);
    let challenge = oneiron::dispatch_byoa::pkce_s256_challenge(&verifier)
        .map_err(|error| anyhow::anyhow!("the PKCE challenge: {error}"))?;
    let mut authorize = reqwest::Url::parse(&format!("{origin}{AUTHORIZE_PATH}"))?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("scope", ask.scope());
    if let Some(purpose) = ask.purpose() {
        authorize
            .query_pairs_mut()
            .append_pair(PURPOSE_PARAMETER, purpose.name());
    }
    for document in &documents {
        authorize
            .query_pairs_mut()
            .append_pair("resource", &document.resource);
    }
    let code = match delivery {
        CodeDelivery::Browser => {
            say_open(ask, origin, &authorize, timeout);
            wait_for_code(&listener, &state, &issuer, deadline)?
        }
        CodeDelivery::Unattended => {
            runtime.block_on(polled_code(&client, &authorize, &state, &issuer, deadline))?
        }
    };
    let token_endpoint = format!("{origin}{TOKEN_PATH}");
    let answer = runtime.block_on(oauth_sign_in::token_call(
        &client,
        &token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
            ("resource", resource.as_str()),
        ],
    ))?;
    let party = SignInParty {
        token_endpoint,
        revocation_endpoint: format!("{origin}{REVOKE_PATH}"),
        client_id,
        resource,
    };
    OAuthSignIn::from_answer(party, answer, oauth_sign_in::now_ms())?.write(token_file)
}

/// Asks the person to open `authorize` in a browser on this machine, and
/// opens it there.
fn say_open(ask: SignInAsk<'_>, origin: &str, authorize: &reqwest::Url, timeout: Duration) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "To {} {origin}, open this page in a browser on this machine:\n  {authorize}\n\
         It shows a match code. Allow the request in your Oneiron inbox when its match code is \
         the same; this command waits up to {}s.",
        ask.why(),
        timeout.as_secs()
    );
    open_in_browser(authorize.as_str());
}

/// Where a new sign-in for `token_file` waits until its origin admits it
/// for the vault named: a file of its own beside `token_file`, named for
/// this process and the time, so two sign-ins at once never share one and
/// each revokes only its own on a failure.
pub(super) fn staged_file(token_file: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut name = token_file.as_os_str().to_owned();
    name.push(format!(".staged-{}-{nanos}", std::process::id()));
    PathBuf::from(name)
}

/// Puts the admitted sign-in at `staged` in `token_file`'s place, and
/// revokes the sign-in it replaced, best effort: no file holds that one now.
pub(super) fn take_place(staged: &Path, token_file: &Path) -> anyhow::Result<()> {
    if let Some(replaced) = OAuthSignIn::take_place(staged, token_file)? {
        revoke(&replaced);
    }
    Ok(())
}

/// A step-up of an OAuth selection's recall sign-in: a second sign-in as
/// the same client ([`SignInAsk::client_id`]) for more than recall, kept in
/// a file of its own beside the recall one ([`StepUp::file`]), which one
/// command alone reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StepUp {
    /// `oneiron continue --cloud`'s ([`SignInAsk::Continue`]).
    Continue,
    /// The hooks' hand-over's ([`SignInAsk::HandOver`]).
    HandOver,
}

impl StepUp {
    /// The ask it makes as the client `client_id`.
    const fn ask(self, client_id: &str) -> SignInAsk<'_> {
        match self {
            Self::Continue => SignInAsk::Continue { client_id },
            Self::HandOver => SignInAsk::HandOver { client_id },
        }
    }

    /// The file its sign-in for `origin` is kept in, beside the recall one.
    pub(super) fn file(self, origin: &str) -> Option<PathBuf> {
        match self {
            Self::Continue => hosted_selection::oauth_continue_sign_in_file(origin),
            Self::HandOver => hosted_selection::oauth_hand_over_sign_in_file(origin),
        }
    }

    /// The tier it asks for.
    const fn scope(self) -> &'static str {
        match self {
            Self::Continue => CONTINUE_SCOPE,
            Self::HandOver => HAND_OVER_SCOPE,
        }
    }

    /// What it lets happen, as a refusal names it.
    const fn what(self) -> &'static str {
        match self {
            Self::Continue => "moving a session",
            Self::HandOver => "landing a session's log at its end",
        }
    }

    /// Its sign-in kept for `vault`, read and never refreshed: the file,
    /// when it reads, holds the tier the step-up asks, was made at the vault
    /// and is the client of `vault`'s recall sign-in now, so a new `hosted
    /// login` that registered another client never goes on as the old one.
    /// The bridge that sends with it refreshes it when due, within its own
    /// deadline. `None` when there is none.
    pub(super) fn held(self, vault: &HostedVault) -> Option<PathBuf> {
        let file = self.file(&vault.origin)?;
        let held = OAuthSignIn::read(&file).ok()?;
        let recall = OAuthSignIn::read(&vault.credential_file).ok()?;
        let mcp = reqwest::Url::parse(&format!("{}/mcp", vault.origin)).ok()?;
        (held.scope == self.scope()
            && held.client_id == recall.client_id
            && held.made_at(&file, &mcp).is_ok())
        .then_some(file)
    }

    /// Its sign-in that stands for `vault`: one [`StepUp::held`] that
    /// yields a bearer at `/mcp` (refreshed when due). `None` when there is
    /// none, or it no longer refreshes. Runs on the blocking pool of the
    /// command's runtime.
    pub(super) fn standing(self, vault: &HostedVault) -> Option<PathBuf> {
        let file = self.held(vault)?;
        session(&file, &vault.origin, "/mcp")
            .is_ok_and(|open| open.bearer().is_ok())
            .then_some(file)
    }

    /// Runs the step-up for the OAuth selection `vault`, waiting up to
    /// `timeout` for the owner's answer by `delivery`, and keeps the sign-in
    /// it makes in its file in place of any earlier one, which is revoked.
    /// Refused for a
    /// selection signed in another way; when the owner allowed a tier other
    /// than the one asked; and when, by the time it is kept, `vault` is no
    /// longer recorded with that recall sign-in (a `hosted logout`, or a new
    /// `hosted login`, while the owner had not yet answered). Such a sign-in
    /// is signed out again and nothing is kept. The check and the keeping
    /// run under the file's refresh lock, which a sign-out takes too.
    pub(super) fn run(
        self,
        vault: &HostedVault,
        timeout: Duration,
        delivery: CodeDelivery,
    ) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            vault.auth_mode == HostedAuthMode::OAuth,
            "this step-up is an OAuth sign-in's, and {} is signed in another way",
            vault.origin
        );
        let recall = OAuthSignIn::read(&vault.credential_file)?;
        let file = self.file(&vault.origin).ok_or_else(|| {
            anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)")
        })?;
        hosted_selection::create_user_dir_for(&file)?;
        let staged = staged_file(&file);
        sign_in(
            &vault.origin,
            &staged,
            timeout,
            self.ask(&recall.client_id),
            delivery,
        )?;
        let made = OAuthSignIn::read(&staged)?;
        if made.scope != self.scope() {
            let _ = sign_out(&staged);
            anyhow::bail!(
                "the owner allowed this sign-in at the `{}` tier, and {} needs `{}`; it was \
                 signed out again",
                made.scope,
                self.what(),
                self.scope()
            );
        }
        let still_recorded = || {
            recorded_recall(vault).is_some_and(|recall_now| recall_now.client_id == made.client_id)
        };
        match OAuthSignIn::take_place_while(&staged, &file, still_recorded) {
            Ok(replaced) => {
                if let Some(replaced) = replaced {
                    revoke(&replaced);
                }
                Ok(file)
            }
            Err(error) => {
                let _ = sign_out(&staged);
                Err(error)
            }
        }
    }

    /// Signs out its sign-in kept for `origin`: revoked at the vault, best
    /// effort, and its file removed. It takes the file's refresh lock even
    /// when there is no file yet, so a step-up whose owner answers later
    /// finds its vault forgotten and keeps nothing ([`StepUp::run`]).
    pub(super) fn sign_out(self, origin: &str) -> anyhow::Result<()> {
        match self.file(origin) {
            Some(file) if file.parent().is_some_and(Path::is_dir) => sign_out(&file),
            _ => Ok(()),
        }
    }
}

/// The recall sign-in `vault` is recorded with now: its record in the
/// selection (the same origin, vault id, OAuth mode and file) and the
/// sign-in that file holds. `None` once a logout forgot it.
fn recorded_recall(vault: &HostedVault) -> Option<OAuthSignIn> {
    let selection = hosted_selection::read().ok()?;
    selection
        .vaults
        .iter()
        .find(|recorded| {
            recorded.origin == vault.origin
                && recorded.vault_id == vault.vault_id
                && recorded.auth_mode == HostedAuthMode::OAuth
                && recorded.credential_file == vault.credential_file
        })
        .and_then(|recorded| OAuthSignIn::read(&recorded.credential_file).ok())
}

/// A session on the sign-in in `file`, for requests to `door` under
/// `origin`, refreshed on the command's runtime when due.
pub(super) fn session(file: &Path, origin: &str, door: &str) -> anyhow::Result<OAuthSession> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("a hosted sign-in runs on the command's runtime"))?;
    OAuthSession::open(
        file,
        &reqwest::Url::parse(&format!("{origin}{door}"))?,
        runtime,
    )
}

/// Revokes the sign-in in `token_file` at its vault, best effort, and
/// removes the file, which `hosted login` wrote, under its refresh lock
/// ([`OAuthSignIn::remove`]). A vault that does not answer is named on
/// stderr; the file goes all the same.
pub(super) fn sign_out(token_file: &Path) -> anyhow::Result<()> {
    OAuthSignIn::remove(token_file, revoke)
}

/// Revokes `sign_in` at its vault, best effort. A vault that does not
/// answer is named on stderr.
fn revoke(sign_in: &OAuthSignIn) {
    let revoked = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("no runtime"))
        .and_then(|runtime| {
            let client = oauth_sign_in::endpoint_client()?;
            runtime.block_on(oauth_sign_in::revoke(&client, sign_in))
        });
    if let Err(error) = revoked {
        let _ = writeln!(
            std::io::stderr().lock(),
            "the vault did not confirm the sign-out ({error}); the owner can revoke it in his \
             consent registry"
        );
    }
}

/// GETs `url` and reads its JSON answer.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<T> {
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {url}: {}", error.without_url()))?;
    let status = response.status();
    anyhow::ensure!(
        status != reqwest::StatusCode::NOT_FOUND,
        "{url} is not served: this origin offers no OAuth sign-in. Sign in on the console or the \
         app instead, and pass the credential it wrote with --credential-file or \
         --owner-upgrade-headers-file"
    );
    anyhow::ensure!(
        status.is_success(),
        "{url} answered HTTP {}",
        status.as_u16()
    );
    let body = response
        .bytes()
        .await
        .map_err(|error| anyhow::anyhow!("{url}'s answer broke off: {}", error.without_url()))?;
    anyhow::ensure!(
        body.len() <= MAX_ANSWER_BYTES,
        "{url}'s answer is too large"
    );
    serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("{url} answered no such document"))
}

/// Registers a public client at the vault (RFC 7591) whose one redirect is
/// `redirect_uri`, and answers its id.
async fn register(
    client: &reqwest::Client,
    origin: &str,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    let endpoint = format!("{origin}{REGISTER_PATH}");
    let response = client
        .post(&endpoint)
        .json(&serde_json::json!({
            "redirect_uris": [redirect_uri],
            "client_name": CLIENT_NAME,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {endpoint}: {}", error.without_url()))?;
    let status = response.status();
    let body = response.bytes().await.map_err(|error| {
        anyhow::anyhow!("{endpoint}'s answer broke off: {}", error.without_url())
    })?;
    anyhow::ensure!(
        status.is_success() && body.len() <= MAX_ANSWER_BYTES,
        "{endpoint} did not register this client (HTTP {})",
        status.as_u16()
    );
    let registered: Registered = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("{endpoint} answered no client id"))?;
    Ok(registered.client_id)
}

/// `bytes` fresh random bytes, as unpadded base64url text.
fn random_text(bytes: usize) -> String {
    let mut held = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut held);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(held)
}

/// Opens `url` in the person's browser, best effort: the URL is printed
/// whether or not this works.
fn open_in_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    if let Ok(mut child) = std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

/// Waits on `listener` until `deadline` for the browser's return to the
/// callback with this sign-in's `state`, and answers its code. A request
/// for another path or with another `state` is answered and ignored. The
/// deadline holds whatever else comes to the loopback: it is checked before
/// each connection is taken, and no connection is read past it.
fn wait_for_code(
    listener: &TcpListener,
    state: &str,
    issuer: &str,
    deadline: Instant,
) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "the browser did not come back from the sign-in in time; nothing was recorded. \
             Run `oneiron hosted login --origin <url>` again"
        );
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(outcome) = callback(stream, state, issuer, deadline) {
                    return outcome;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(CALLBACK_POLL);
            }
            Err(error) => anyhow::bail!("the loopback listener failed: {error}"),
        }
    }
}

/// One loopback request, read until `deadline` at the latest: `None` when
/// it is not this sign-in's return, which is answered and ignored; else the
/// code, or why the sign-in ended.
fn callback(
    mut stream: TcpStream,
    state: &str,
    issuer: &str,
    deadline: Instant,
) -> Option<anyhow::Result<String>> {
    stream.set_nonblocking(false).ok()?;
    let until = deadline.min(Instant::now() + CALLBACK_READ_TIMEOUT);
    let target = request_target(&mut stream, until)?;
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", "Not found.");
        return None;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        respond(
            &mut stream,
            "400 Bad Request",
            "This is not the sign-in this command is waiting for.",
        );
        return None;
    }
    if param("iss").is_some_and(|iss| iss != issuer) {
        respond(
            &mut stream,
            "400 Bad Request",
            "The sign-in came from another vault.",
        );
        return Some(Err(anyhow::anyhow!(
            "the sign-in came back from an issuer other than {issuer}; nothing was recorded"
        )));
    }
    if let Some(error) = param("error") {
        respond(
            &mut stream,
            "200 OK",
            "The sign-in did not complete. You can close this tab.",
        );
        let error: String = error
            .chars()
            .filter(char::is_ascii_graphic)
            .take(64)
            .collect();
        return Some(Err(anyhow::anyhow!(
            "the vault ended the sign-in ({error}); nothing was recorded"
        )));
    }
    let Some(code) = param("code") else {
        respond(
            &mut stream,
            "400 Bad Request",
            "The sign-in brought no code.",
        );
        return None;
    };
    respond(
        &mut stream,
        "200 OK",
        "Signed in. You can close this tab and go back to the terminal.",
    );
    Some(Ok(code))
}

/// The request target of a GET on `stream`, from its request line, when
/// its head is in by `until`.
fn request_target(stream: &mut TcpStream, until: Instant) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let left = until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())?;
        stream.set_read_timeout(Some(left)).ok()?;
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return None;
        }
    }
    let line = std::str::from_utf8(&head).ok()?.lines().next()?.to_owned();
    let mut words = line.split(' ');
    let (Some("GET"), Some(target)) = (words.next(), words.next()) else {
        return None;
    };
    target.starts_with('/').then(|| target.to_owned())
}

/// Answers `stream` with `status` and a one-line page of `text`.
fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Oneiron sign-in</title><p>{text}</p>"
    );
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}
