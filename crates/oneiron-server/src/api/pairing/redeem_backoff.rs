//! The pairing redeem door's failure backoff, per client address (FIX
//! 12477, Engine 11-06 08:17 = A). A typed code is 40 bits, and a wrong one
//! names no link, so no guess can be counted against the link it aims at:
//! the door counts each client address's redemptions instead.
//!
//! An address may make `limits.pairing_redeem_free_failures` redemptions
//! that no success answers. Each one past them makes the address wait,
//! twice as long as the wait before, from one second up to
//! `limits.pairing_redeem_wait_ceiling_ms`; while it waits, its redemptions
//! are refused before their code is read; a refused one adds no attempt
//! and no wait, but the address has not been quiet. A redemption counts as failed from the moment it is admitted,
//! so attempts sent at once wait their turns as attempts sent one by one
//! do. A success forgets the address, and so does
//! `limits.pairing_redeem_quiet_ms` with no redemption from it. Every
//! address counts alike, loopback, in-process and mesh peers too; no address
//! ever waits for another, so no stranger can block the owner's pairing. A
//! request that reaches this server through a socket carrying many callers
//! (the managed supervisor's socket, the relay) names no address of its
//! own, and is not counted: one count for all of them would let any one
//! block the rest. The managed edge in front bounds those. The record lives
//! in this process only: a restart forgets it.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::config::LimitsConfig;
use crate::server::SyncServer;

/// The address a redemption is counted under: its connection's own peer,
/// or the client a configured trusted proxy names behind it
/// ([`crate::auth::client_address`]). `None` for a request no socket peer
/// carries, which is not counted.
pub(crate) struct RedeemSource(pub(crate) Option<IpAddr>);

impl FromRequestParts<Arc<SyncServer>> for RedeemSource {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<ConnectInfo<SocketAddr>>().is_none() {
            return Ok(Self(None));
        }
        Ok(Self(crate::auth::client_address(
            &parts.headers,
            &parts.extensions,
            &server.config.trusted_proxies,
        )))
    }
}

/// The first wait past the free failures; each later one doubles.
const FIRST_WAIT: Duration = Duration::from_secs(1);

/// The wait set when a wait would pass the clock's range: an overflow
/// guard for a ceiling set past it, not a bound of its own.
const CLOCK_RANGE_WAIT: Duration = Duration::from_secs(86_400);

/// The `[limits]` rows one redemption is judged by.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RedeemBackoffRules {
    free_failures: u32,
    ceiling: Duration,
    quiet: Duration,
}

impl RedeemBackoffRules {
    pub(crate) fn of(limits: &LimitsConfig) -> Self {
        Self {
            free_failures: limits.pairing_redeem_free_failures,
            ceiling: Duration::from_millis(limits.pairing_redeem_wait_ceiling_ms),
            quiet: Duration::from_millis(limits.pairing_redeem_quiet_ms),
        }
    }

    /// The wait after the `past`-th redemption beyond the free failures,
    /// counted from one: one second, doubled for each one after, up to the
    /// ceiling.
    fn wait_after(&self, past: u32) -> Duration {
        let doublings = past.saturating_sub(1).min(31);
        FIRST_WAIT
            .saturating_mul(1_u32 << doublings)
            .min(self.ceiling)
    }
}

/// One address's redemptions since it last started over.
struct AddressRedemptions {
    /// Redemptions admitted that no success has answered.
    unanswered: u32,
    /// When it last made one, refused or admitted.
    last: Instant,
    /// Until then, its next redemption is refused unread.
    waits_until: Option<Instant>,
}

impl AddressRedemptions {
    fn fresh(now: Instant) -> Self {
        Self {
            unanswered: 0,
            last: now,
            waits_until: None,
        }
    }
}

#[derive(Default)]
struct Redemptions {
    by_address: HashMap<IpAddr, AddressRedemptions>,
    /// How many addresses the last forgetting pass kept.
    kept_at_prune: usize,
}

impl Redemptions {
    /// Forgets every address quiet for the quiet period, once the record
    /// has doubled since it last did, so each pass is paid for by as many
    /// new addresses.
    fn prune(&mut self, quiet: Duration, now: Instant) {
        if self.by_address.len() < self.kept_at_prune.saturating_mul(2).max(64) {
            return;
        }
        self.by_address
            .retain(|_, address| now.saturating_duration_since(address.last) < quiet);
        self.kept_at_prune = self.by_address.len();
    }
}

/// Every client address's unanswered pairing redemptions, for the server's
/// life.
#[derive(Default)]
pub(crate) struct PairingRedeemBackoff {
    redemptions: Mutex<Redemptions>,
}

impl PairingRedeemBackoff {
    /// Admits one redemption from `address` at `now`, or answers how long it
    /// still waits. An admitted redemption counts as failed until
    /// [`Self::succeeded`] forgets the address.
    pub(crate) fn admit(
        &self,
        address: IpAddr,
        rules: RedeemBackoffRules,
        now: Instant,
    ) -> Result<(), Duration> {
        let mut redemptions = self
            .redemptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        redemptions.prune(rules.quiet, now);
        let entry = redemptions
            .by_address
            .entry(address)
            .or_insert_with(|| AddressRedemptions::fresh(now));
        if now.saturating_duration_since(entry.last) >= rules.quiet {
            *entry = AddressRedemptions::fresh(now);
        }
        if let Some(until) = entry.waits_until
            && now < until
        {
            // A refused redemption adds no attempt and no wait, but it is a
            // redemption: the address is not quiet.
            entry.last = now;
            return Err(until - now);
        }
        entry.unanswered = entry.unanswered.saturating_add(1);
        entry.last = now;
        if entry.unanswered > rules.free_failures {
            let wait = rules.wait_after(entry.unanswered - rules.free_failures);
            entry.waits_until = now
                .checked_add(wait)
                .or_else(|| now.checked_add(CLOCK_RANGE_WAIT));
        }
        Ok(())
    }

    /// Forgets `address` once one of its redemptions succeeded: its next
    /// pairing starts over.
    pub(crate) fn succeeded(&self, address: IpAddr) {
        self.redemptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_address
            .remove(&address);
    }
}

/// `wait` as the whole seconds a `Retry-After` names: rounded up, at least
/// one.
pub(crate) fn retry_after_secs(wait: Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1)
}
