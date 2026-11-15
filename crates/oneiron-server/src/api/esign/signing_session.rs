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
//! Each ceremony has an id of its own, drawn from its link: the form's
//! answer redirects to `/sign?ceremony=<id>`, the cookie is named for it,
//! and every ceremony call names it in the `x-oneiron-sign-ceremony`
//! header. A door reads the cookie of that name and answers only when the
//! session it holds stands for that ceremony's link, so a page acts only on
//! the document it shows, however many invitations the browser opens after
//! it. The id stands for nothing on its own, and no capability can be read
//! back from it.
//!
//! One pending exchange and one session per link: opening the link again
//! replaces both, which bounds what is held by the links in use, with no
//! count or rate refusal. Every access first reaps what is over: each
//! exchange past its lifetime, each session past one of its own lifetimes or
//! past its link's end as the vault last admitted it, and each link left
//! holding neither. Only the digests of exchanges and session ids are kept,
//! beside the capability they stand for, in this router's own registry: a
//! restart ends every session, and the signer reopens the reusable emailed
//! link. Ending a session never ends the link, and opening one never extends
//! the link's signing window.
use oneiron::blob_artifact::esign::EsignCapability;
use rand_core::{OsRng, RngCore as _};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// What a signing session's cookie name starts with; the ceremony's id
/// ends it. Its path is `/sign`, so no other route of the vault ever
/// receives it.
pub(super) const SESSION_COOKIE_PREFIX: &str = "oneiron-sign-session-";

/// The header each ceremony call names its ceremony in.
pub(super) const CEREMONY_HEADER: &str = "x-oneiron-sign-ceremony";

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

    /// Whether `open` is past its idle or its absolute lifetime at `now`.
    fn ended(&self, open: &Open, now: Instant) -> bool {
        self.absolute
            .is_some_and(|life| now.saturating_duration_since(open.opened) >= life)
            || self
                .idle
                .is_some_and(|life| now.saturating_duration_since(open.used) >= life)
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

/// One link's state: the capability it stands for, when the vault stops
/// admitting it, its pending exchange and its open session.
struct LinkState {
    capability: String,
    /// The instant from which the clock alone refuses the link, as the
    /// exchange door last admitted it; `None` past any instant this host can
    /// hold.
    ends: Option<Instant>,
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

/// A session [`SigningSessions::open_session`] opened: its id, for the
/// cookie, and its ceremony's id, for the cookie's name and the page's
/// address.
pub(super) struct OpenedSession {
    pub(super) id: String,
    pub(super) ceremony: String,
}

impl SigningSessions {
    /// Mints the single-use exchange for an admitted link, replacing any
    /// exchange the link had pending. `link_ends` is when the vault's clock
    /// alone stops admitting the link.
    pub(super) fn mint_exchange(
        &self,
        capability: &EsignCapability,
        link_ends: Option<Instant>,
        lifetimes: SessionLifetimes,
    ) -> String {
        let value = random_hex();
        let now = Instant::now();
        let link = digest(capability.expose_for_delivery().as_bytes());
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        registry.reap(now, lifetimes);
        let pending = Pending {
            digest: digest(value.as_bytes()),
            minted: now,
        };
        registry.exchanges.insert(pending.digest, link);
        let state = registry.links.entry(link).or_insert_with(|| LinkState {
            capability: capability.expose_for_delivery().to_owned(),
            ends: link_ends,
            exchange: None,
            session: None,
        });
        state.ends = link_ends;
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
    ) -> Option<OpenedSession> {
        if !is_token(presented) {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        registry.reap(now, lifetimes);
        let exchange = digest(presented.as_bytes());
        let link = registry.exchanges.remove(&exchange)?;
        let state = registry.links.get_mut(&link)?;
        state
            .exchange
            .take_if(|pending| pending.digest == exchange)?;
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
        Some(OpenedSession {
            id,
            ceremony: ceremony_id(&link),
        })
    }

    /// The capability an open session stands for, when it is a session of
    /// `ceremony` and is not over; the call counts as the session's latest
    /// use. A session of another ceremony stands for nothing here.
    pub(super) fn capability(
        &self,
        presented: &str,
        ceremony: &str,
        lifetimes: SessionLifetimes,
    ) -> Option<EsignCapability> {
        if !is_token(presented) {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        registry.reap(now, lifetimes);
        let session = digest(presented.as_bytes());
        let link = *registry.sessions.get(&session)?;
        if ceremony_id(&link) != ceremony {
            return None;
        }
        let state = registry.links.get_mut(&link)?;
        let open = state
            .session
            .as_mut()
            .filter(|open| open.digest == session)?;
        open.used = now;
        EsignCapability::parse(&state.capability).ok()
    }

    /// How many links, pending exchanges and open sessions the registry
    /// holds: the test door's view.
    #[cfg(oneiron_test_support)]
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
    /// Drops every exchange past its lifetime, every session past one of its
    /// own lifetimes, both once their link's end has come, and each link
    /// left holding neither, with their digests in the reverse indexes.
    fn reap(&mut self, now: Instant, lifetimes: SessionLifetimes) {
        let mut exchanges = Vec::new();
        let mut sessions = Vec::new();
        self.links.retain(|_, state| {
            let link_ended = state.ends.is_some_and(|ends| now >= ends);
            if let Some(pending) = state.exchange.take_if(|pending| {
                link_ended || now.saturating_duration_since(pending.minted) >= lifetimes.exchange
            }) {
                exchanges.push(pending.digest);
            }
            if let Some(open) = state
                .session
                .take_if(|open| link_ended || lifetimes.ended(open, now))
            {
                sessions.push(open.digest);
            }
            state.exchange.is_some() || state.session.is_some()
        });
        for exchange in exchanges {
            self.exchanges.remove(&exchange);
        }
        for session in sessions {
            self.sessions.remove(&session);
        }
    }
}

/// The ceremony a request's `x-oneiron-sign-ceremony` header names, if it
/// is a ceremony id.
pub(super) fn requested_ceremony(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(CEREMONY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_ceremony(value))
}

/// The session id the `Cookie` headers carry for `ceremony`, if any.
pub(super) fn session_cookie<'a>(
    headers: &'a axum::http::HeaderMap,
    ceremony: &str,
) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| name.strip_prefix(SESSION_COOKIE_PREFIX) == Some(ceremony))
        .map(|(_, value)| value)
}

/// The `Set-Cookie` value that opens `ceremony`'s session in the signer's
/// browser.
pub(super) fn session_set_cookie(ceremony: &str, id: &str) -> String {
    format!("{SESSION_COOKIE_PREFIX}{ceremony}={id}; Path=/sign; Secure; HttpOnly; SameSite=Strict")
}

/// The page's address for `ceremony`, where the opened session lands.
pub(super) fn page_location(ceremony: &str) -> String {
    format!("/sign?ceremony={ceremony}")
}

/// A ceremony's id: 128 bits of a digest of its link's digest, as 32
/// lowercase hex characters. It names the ceremony in the page's address,
/// the session cookie's name and each ceremony call.
fn ceremony_id(link: &[u8; 32]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"oneiron-sign-ceremony\0");
    hasher.update(link);
    hex(&hasher.finalize()[..16])
}

/// A ceremony id: 32 lowercase hex characters.
fn is_ceremony(value: &str) -> bool {
    value.len() == 32 && is_lower_hex(value)
}

/// An exchange or session id: 64 lowercase hex characters, 256 random bits.
fn is_token(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn random_hex() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    hex(&secret)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(value: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(value).into()
}
