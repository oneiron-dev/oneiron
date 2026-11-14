//! The signing lens's session (ARCH-0064a §6 and [SGN-03], census L3-22).
//! The emailed link keeps its capability in the fragment, and the page
//! trades it once: `POST /sign/exchange` answers a single-use exchange, and
//! a top-level form POST to `/sign/session` consumes it at once. That answer
//! opens a session, sets its id in a Secure, HttpOnly, SameSite=Strict
//! cookie scoped to `/sign`, and redirects to the page. Every ceremony door
//! then reads only the cookie, and the vault still admits the link's
//! capability at each call, so its signing window, token cap and revocation
//! hold for the whole session.
//!
//! One pending exchange and one session per link: opening the link again
//! replaces both, which bounds what is held by the links in use, with no
//! count or rate refusal. Only the digests of exchanges and session ids are
//! kept, beside the capability they stand for, in this router's own
//! registry: a restart ends every session, and the signer reopens the
//! reusable emailed link. Ending a session never ends the link, and opening
//! one never extends the link's signing window.
use oneiron::blob_artifact::esign::EsignCapability;
use rand_core::{OsRng, RngCore as _};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The cookie a signing session's id rides in. Its path is `/sign`, so no
/// other route of the vault ever receives it.
pub(super) const SESSION_COOKIE: &str = "oneiron-sign-session";

/// The form field `POST /sign/session` reads its exchange from.
pub(super) const EXCHANGE_FIELD: &str = "exchange";

/// How long each lifetime row lets an exchange or a session live. An
/// absent session row sets no clock of its own: canon settles no number,
/// and the link's own window and cap still bound every call.
#[derive(Clone, Copy, Debug)]
pub(super) struct SessionLifetimes {
    pub(super) exchange: Duration,
    pub(super) idle: Option<Duration>,
    pub(super) absolute: Option<Duration>,
}

impl SessionLifetimes {
    pub(super) fn from_limits(limits: &crate::config::LimitsConfig) -> Self {
        Self {
            exchange: Duration::from_secs(limits.esign_exchange_seconds),
            idle: limits.esign_session_idle_seconds.map(Duration::from_secs),
            absolute: limits
                .esign_session_absolute_seconds
                .map(Duration::from_secs),
        }
    }
}

/// The public signing router's sessions, shared through an `Extension`.
#[derive(Clone, Default)]
pub(super) struct SigningSessions(Arc<Mutex<Registry>>);

#[derive(Default)]
struct Registry {
    /// Each link's pending exchange and open session, by the link's digest.
    links: HashMap<[u8; 32], LinkState>,
    /// The link each pending exchange's digest belongs to.
    exchanges: HashMap<[u8; 32], [u8; 32]>,
    /// The link each open session id's digest belongs to.
    sessions: HashMap<[u8; 32], [u8; 32]>,
}

/// One link's state: the capability it stands for, its pending exchange and
/// its open session.
struct LinkState {
    capability: String,
    exchange: Option<Pending>,
    session: Option<Open>,
}

struct Pending {
    digest: [u8; 32],
    minted: Instant,
}

struct Open {
    digest: [u8; 32],
    opened: Instant,
    used: Instant,
}

impl SigningSessions {
    /// Mints the single-use exchange for an admitted link, replacing any
    /// exchange the link had pending. Exchanges past their lifetime are
    /// reaped here.
    pub(super) fn mint_exchange(
        &self,
        capability: &EsignCapability,
        lifetimes: SessionLifetimes,
    ) -> String {
        let value = random_hex();
        let now = Instant::now();
        let link = digest(capability.expose_for_delivery().as_bytes());
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        registry.reap_exchanges(now, lifetimes.exchange);
        let pending = Pending {
            digest: digest(value.as_bytes()),
            minted: now,
        };
        registry.exchanges.insert(pending.digest, link);
        let state = registry.links.entry(link).or_insert_with(|| LinkState {
            capability: capability.expose_for_delivery().to_owned(),
            exchange: None,
            session: None,
        });
        let replaced = state.exchange.replace(pending).map(|old| old.digest);
        if let Some(old) = replaced {
            registry.exchanges.remove(&old);
        }
        value
    }

    /// Consumes a live exchange and opens its link's session, replacing any
    /// session the link had open. An unknown, used or expired exchange
    /// opens nothing.
    pub(super) fn open_session(
        &self,
        presented: &str,
        lifetimes: SessionLifetimes,
    ) -> Option<String> {
        if !is_token(presented) {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        let exchange = digest(presented.as_bytes());
        let link = registry.exchanges.remove(&exchange)?;
        let state = registry.links.get_mut(&link)?;
        let pending = state
            .exchange
            .take_if(|pending| pending.digest == exchange)?;
        if now.saturating_duration_since(pending.minted) >= lifetimes.exchange {
            registry.forget_if_idle(link);
            return None;
        }
        let id = random_hex();
        let open = Open {
            digest: digest(id.as_bytes()),
            opened: now,
            used: now,
        };
        let session = open.digest;
        let replaced = state.session.replace(open).map(|old| old.digest);
        if let Some(old) = replaced {
            registry.sessions.remove(&old);
        }
        registry.sessions.insert(session, link);
        Some(id)
    }

    /// The capability an open session stands for, when neither of its
    /// lifetimes has ended; the call counts as the session's latest use. A
    /// session past a lifetime is closed here and stands for nothing.
    pub(super) fn capability(
        &self,
        presented: &str,
        lifetimes: SessionLifetimes,
    ) -> Option<EsignCapability> {
        if !is_token(presented) {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        let session = digest(presented.as_bytes());
        let link = *registry.sessions.get(&session)?;
        let state = registry.links.get_mut(&link)?;
        let open = state
            .session
            .as_mut()
            .filter(|open| open.digest == session)?;
        let ended = lifetimes
            .absolute
            .is_some_and(|life| now.saturating_duration_since(open.opened) >= life)
            || lifetimes
                .idle
                .is_some_and(|life| now.saturating_duration_since(open.used) >= life);
        if ended {
            state.session = None;
            registry.sessions.remove(&session);
            registry.forget_if_idle(link);
            return None;
        }
        open.used = now;
        EsignCapability::parse(&state.capability).ok()
    }
}

#[cfg(oneiron_test_support)]
impl SigningSessions {
    /// How many links, pending exchanges and open sessions the registry
    /// holds: the test door's view.
    pub(super) fn held(&self) -> (usize, usize, usize) {
        let registry = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        (
            registry.links.len(),
            registry.exchanges.len(),
            registry.sessions.len(),
        )
    }
}

impl Registry {
    /// Drops every exchange past its lifetime, and each link left with
    /// neither an exchange nor a session.
    fn reap_exchanges(&mut self, now: Instant, life: Duration) {
        let mut expired = Vec::new();
        for (link, state) in &mut self.links {
            if let Some(pending) = state
                .exchange
                .take_if(|pending| now.saturating_duration_since(pending.minted) >= life)
            {
                expired.push((*link, pending.digest));
            }
        }
        for (link, exchange) in expired {
            self.exchanges.remove(&exchange);
            self.forget_if_idle(link);
        }
    }

    /// Forgets a link that holds neither an exchange nor a session.
    fn forget_if_idle(&mut self, link: [u8; 32]) {
        if self
            .links
            .get(&link)
            .is_some_and(|state| state.exchange.is_none() && state.session.is_none())
        {
            self.links.remove(&link);
        }
    }
}

/// The session id a request's `Cookie` headers carry, if any.
pub(super) fn session_cookie(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value)
}

/// The `Set-Cookie` value that opens a session in the signer's browser.
pub(super) fn session_set_cookie(id: &str) -> String {
    format!("{SESSION_COOKIE}={id}; Path=/sign; Secure; HttpOnly; SameSite=Strict")
}

/// An exchange or session id: 64 lowercase hex characters, 256 random bits.
fn is_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn random_hex() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(value: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(value).into()
}
