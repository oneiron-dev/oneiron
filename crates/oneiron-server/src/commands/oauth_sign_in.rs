//! The OAuth sign-in `oneiron hosted login` makes at a hosted vault as a
//! native app (RFC 8252; ruling L1-14-HOSTED-LOGIN = B), held in one
//! owner-only file: the client it registered there, the resource its tokens
//! reach, and the access and refresh tokens `oneiron mcp --auth-mode oauth`
//! sends and refreshes.
//!
//! The vault rotates its refresh tokens, and a spent one sent again revokes
//! the whole sign-in (crates/oneiron/src/authority/oauth_server/tokens.rs
//! `refresh_oauth_token`). Every bridge and every hook recall reads the same
//! file, so a refresh runs under an exclusive lock on a file beside it, and
//! reads the token file again first: tokens another process already
//! refreshed are taken as they are, never refreshed a second time. No value
//! the file holds is printed or logged.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use super::credential_file;

/// An access token this close to its expiry is refreshed before it is sent.
const EXPIRY_MARGIN_MS: u64 = 60_000;
/// A sign-in file is a few KiB; a larger one is not one.
const MAX_READ_BYTES: u64 = 64 * 1024;
/// How long one call to a vault's token or revocation endpoint may take.
const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest answer read from a vault's OAuth endpoint.
pub(crate) const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// The sign-in file's body.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OAuthSignIn {
    /// The vault's token endpoint, where the tokens refresh.
    pub(crate) token_endpoint: String,
    /// The vault's revocation endpoint, where a sign-out revokes them.
    pub(crate) revocation_endpoint: String,
    /// The public client `hosted login` registered at the vault.
    pub(crate) client_id: String,
    /// The protected resource the tokens reach: the vault's `{origin}/mcp`.
    pub(crate) resource: String,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    /// When the access token expires, in ms since the Unix epoch.
    pub(crate) expires_at_ms: u64,
    /// The tier the vault granted, as its wire name (`read`, `propose`,
    /// `full`).
    pub(crate) scope: String,
}

/// A token endpoint's answer (RFC 6749 §5.1).
#[derive(Deserialize)]
pub(crate) struct TokenAnswer {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    #[serde(default)]
    scope: String,
}

/// Where a sign-in's tokens refresh and revoke, and whose they are.
pub(crate) struct SignInParty {
    pub(crate) token_endpoint: String,
    pub(crate) revocation_endpoint: String,
    pub(crate) client_id: String,
    pub(crate) resource: String,
}

impl OAuthSignIn {
    /// The sign-in `answer` makes for `party`, at `now_ms`.
    pub(crate) fn from_answer(
        party: SignInParty,
        answer: TokenAnswer,
        now_ms: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            answer.token_type.eq_ignore_ascii_case("bearer"),
            "the vault's token endpoint answered a {} token, not a bearer token",
            answer.token_type
        );
        for token in [&answer.access_token, &answer.refresh_token] {
            anyhow::ensure!(
                !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()),
                "the vault's token endpoint answered a token that is not one header value"
            );
        }
        Ok(Self {
            token_endpoint: party.token_endpoint,
            revocation_endpoint: party.revocation_endpoint,
            client_id: party.client_id,
            resource: party.resource,
            access_token: answer.access_token,
            refresh_token: answer.refresh_token,
            expires_at_ms: now_ms.saturating_add(answer.expires_in.saturating_mul(1000)),
            scope: answer.scope,
        })
    }

    /// The sign-in a refresh's `answer` leaves: the same client and
    /// resource, with the new pair.
    fn renewed(&self, answer: TokenAnswer, now_ms: u64) -> anyhow::Result<Self> {
        Self::from_answer(self.party(), answer, now_ms)
    }

    fn party(&self) -> SignInParty {
        SignInParty {
            token_endpoint: self.token_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            client_id: self.client_id.clone(),
            resource: self.resource.clone(),
        }
    }

    /// Whether the access token is still good to send at `now_ms`.
    fn fresh(&self, now_ms: u64) -> bool {
        now_ms.saturating_add(EXPIRY_MARGIN_MS) < self.expires_at_ms
    }

    /// Reads `path`: a file only its owner may read, by its mode and by any
    /// ACL, holding one sign-in. Every refusal names the file, never a value.
    pub(crate) fn read(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path).map_err(|error| {
            anyhow::anyhow!(
                "open {}: {error}; sign in with `oneiron hosted login --origin <url>`",
                path.display()
            )
        })?;
        credential_file::admit(path, &file)?;
        let mut body = Vec::new();
        file.take(MAX_READ_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
        anyhow::ensure!(
            body.len() as u64 <= MAX_READ_BYTES,
            "{} is too large to be an OAuth sign-in",
            path.display()
        );
        // Only where it failed: serde's own message can quote the text.
        serde_json::from_slice(&body).map_err(|error| {
            anyhow::anyhow!(
                "{} is not an OAuth sign-in (line {}, column {}); sign in again with \
                 `oneiron hosted login --origin <url>`",
                path.display(),
                error.line(),
                error.column()
            )
        })
    }

    /// Writes the sign-in to `path`, whole, owner-only and in one rename.
    pub(crate) fn write(&self, path: &Path) -> anyhow::Result<()> {
        credential_file::replace(path, &serde_json::to_vec_pretty(self)?)
    }
}

/// The HTTP client every call to a vault's OAuth endpoints goes through: no
/// proxy the environment names and no redirect, so neither a token nor a
/// code is handed anywhere but the endpoint named.
pub(crate) fn endpoint_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(ENDPOINT_TIMEOUT)
        .build()?)
}

/// Posts `form` to the token endpoint `endpoint` and reads its answer. An
/// OAuth error names its code alone (RFC 6749 §5.2), never a body.
pub(crate) async fn token_call(
    client: &reqwest::Client,
    endpoint: &str,
    form: &[(&str, &str)],
) -> anyhow::Result<TokenAnswer> {
    let response = client
        .post(endpoint)
        .form(form)
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {endpoint}: {}", error.without_url()))?;
    let status = response.status();
    let body = response.bytes().await.map_err(|error| {
        anyhow::anyhow!("{endpoint}'s answer broke off: {}", error.without_url())
    })?;
    anyhow::ensure!(
        body.len() <= MAX_ANSWER_BYTES,
        "{endpoint}'s answer is too large to be a token answer"
    );
    if !status.is_success() {
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|answer| answer.get("error")?.as_str().map(str::to_owned))
            .filter(|code| code.bytes().all(|byte| byte.is_ascii_graphic()))
            .unwrap_or_else(|| "no OAuth error code".to_owned());
        anyhow::bail!(
            "{endpoint} refused the request (HTTP {}, {code})",
            status.as_u16()
        );
    }
    serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("{endpoint} answered no token answer"))
}

/// Revokes `sign_in` at its vault (RFC 7009), which ends its whole family:
/// best effort, since a sign-out goes on whatever the vault answers.
pub(crate) async fn revoke(client: &reqwest::Client, sign_in: &OAuthSignIn) -> anyhow::Result<()> {
    let response = client
        .post(&sign_in.revocation_endpoint)
        .form(&[
            ("token", sign_in.refresh_token.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", sign_in.client_id.as_str()),
        ])
        .send()
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "could not reach {}: {}",
                sign_in.revocation_endpoint,
                error.without_url()
            )
        })?;
    anyhow::ensure!(
        response.status().is_success(),
        "{} answered HTTP {}",
        sign_in.revocation_endpoint,
        response.status().as_u16()
    );
    Ok(())
}

/// The sign-in one bridge holds: the file it reads, and the tokens it read
/// last. Locked only around a token lookup or a refresh.
pub(crate) struct OAuthSession {
    path: PathBuf,
    held: Mutex<OAuthSignIn>,
    client: reqwest::Client,
    runtime: Handle,
}

impl OAuthSession {
    /// The sign-in `path` holds, refreshed on `runtime` when it is due.
    pub(crate) fn open(path: &Path, runtime: Handle) -> anyhow::Result<Self> {
        Ok(Self {
            held: Mutex::new(OAuthSignIn::read(path)?),
            path: path.to_owned(),
            client: endpoint_client()?,
            runtime,
        })
    }

    /// The access token to send now: refreshed first when it is about to
    /// expire. Called from a plain thread, never from a runtime task.
    pub(crate) fn bearer(&self) -> Result<String, String> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if !held.fresh(now_ms()) {
            let stale = held.access_token.clone();
            self.refresh(&mut held, &stale)
                .map_err(|error| error.to_string())?;
        }
        Ok(held.access_token.clone())
    }

    /// A token to send again after the vault refused `refused`: the one
    /// another holder already refreshed to, or one refreshed now.
    pub(crate) fn renewed(&self, refused: &str) -> Result<String, String> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut held, refused)
            .map_err(|error| error.to_string())?;
        Ok(held.access_token.clone())
    }

    /// Replaces `held` with tokens newer than `stale`: the file's, when
    /// another holder refreshed it since and its token is fresh; otherwise
    /// the vault's answer to the file's own refresh token, written back.
    fn refresh(&self, held: &mut OAuthSignIn, stale: &str) -> anyhow::Result<()> {
        let _lock = RefreshLock::take(&self.path)?;
        let on_file = OAuthSignIn::read(&self.path)?;
        if on_file.access_token != stale && on_file.fresh(now_ms()) {
            *held = on_file;
            return Ok(());
        }
        let answer = self.runtime.block_on(token_call(
            &self.client,
            &on_file.token_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", on_file.refresh_token.as_str()),
                ("client_id", on_file.client_id.as_str()),
                ("resource", on_file.resource.as_str()),
            ],
        ));
        let answer = answer.map_err(|error| {
            anyhow::anyhow!(
                "the OAuth sign-in in {} did not refresh ({error}); sign in again with \
                 `oneiron hosted login --origin <url>`",
                self.path.display()
            )
        })?;
        let next = on_file.renewed(answer, now_ms())?;
        next.write(&self.path)?;
        *held = next;
        Ok(())
    }
}

/// An exclusive lock on the file beside a sign-in, held while it refreshes:
/// one refresh at a time across every process that reads it.
struct RefreshLock {
    _file: File,
}

impl RefreshLock {
    fn take(sign_in: &Path) -> anyhow::Result<Self> {
        let mut name = sign_in.as_os_str().to_owned();
        name.push(".lock");
        let path = PathBuf::from(name);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: flock on a descriptor this function owns and keeps
            // open in the guard; the lock ends when the guard closes it.
            let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            anyhow::ensure!(
                locked == 0,
                "lock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { _file: file })
    }
}

/// Now, in ms since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
