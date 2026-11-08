//! The engine's sweep of the OAuth server's lapsed rows, the housekeeping sweep `oauth_expiry`
//! (FIX 4902). A read drops a row it finds past its lifetime; this sweep drops the ones no read
//! comes back to, by the same judgement, so a vault no client calls again still sheds them:
//!
//! - an authorization request past its lifetime, answered or not, as `/oauth/authorize` drops
//!   every lapsed one before it counts the waiting ones. Its owner ask then offers no tap, as for
//!   one a read dropped: the ask's taps read the request (`oauth_authorization_tap_in`);
//! - an authorization code past its lifetime, redeemed or not, as the token endpoint drops one;
//! - an access or refresh token past its lifetime, and with an access token's row the slip it
//!   held, as a refresh or a revocation drops one. A standing family's live access token stays,
//!   so the refresh that retires it still revokes its slip (`take_live_access_in_txn`);
//! - a token family past its newest refresh token's lifetime, which no read drops: no token of it
//!   stands. Its live access token, lapsed long before, goes with it;
//! - a metadata-document client whose document is past [`super::OAUTH_CIMD_TTL_SECS`] and that
//!   no standing family or waiting request uses: its row is a copy the next authorize fetches
//!   again. A registered client has no lifetime; only the clients table's bound evicts one.
//!
//! Each page reads the lapsed rows in a snapshot and removes them in one short writer, which
//! judges each row again. Every lifetime is read at the earlier of the pass's clock and the wall
//! clock the server stamps the rows with, so the sweep never drops a row a read would still take.

use std::collections::BTreeSet;

use super::OAUTH_CLIENTS_MAX;
use super::rows::{CLIENTS, CODES, FAMILIES, REQUESTS, TOKENS};
use crate::Vault;
use crate::error::Result;
use crate::side_table::HexId;

/// The most lapsed rows one page removes, across the five tables, in one writer: the clients
/// table's bound, [`OAUTH_CLIENTS_MAX`], about as many rows as one eviction from that table already
/// reads in its writer. Not an engine call of its own.
const SWEEP_PAGE_ROWS: usize = OAUTH_CLIENTS_MAX;

/// What the sweep of the OAuth server's lapsed rows removed, by table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OAuthRowsSwept {
    /// Authorization requests, answered or not.
    pub(crate) requests: u64,
    /// Authorization codes, redeemed or not.
    pub(crate) codes: u64,
    /// Access and refresh tokens, each access token with the slip its row held.
    pub(crate) tokens: u64,
    /// Token families past their newest refresh token's lifetime.
    pub(crate) families: u64,
    /// Metadata-document clients whose document went stale, used by no sign-in.
    pub(crate) clients: u64,
}

impl OAuthRowsSwept {
    /// Every row counted.
    fn total(&self) -> u64 {
        self.requests + self.codes + self.tokens + self.families + self.clients
    }

    /// Adds `page`'s counts to these.
    fn add(&mut self, page: &Self) {
        self.requests += page.requests;
        self.codes += page.codes;
        self.tokens += page.tokens;
        self.families += page.families;
        self.clients += page.clients;
    }
}

/// The keys of the rows a snapshot found lapsed, at most [`SWEEP_PAGE_ROWS`] of them, for one
/// page's writer to judge again and remove.
#[derive(Default)]
struct LapsedRows {
    requests: Vec<HexId>,
    codes: Vec<String>,
    tokens: Vec<String>,
    families: Vec<HexId>,
    clients: Vec<String>,
    /// The snapshot found more lapsed rows than one page removes.
    more: bool,
}

impl LapsedRows {
    /// Whether the page holds another key, for a lapsed row just found; once the page is full,
    /// that row is left for the next page, and the page says rows are left.
    fn reserve_slot(&mut self) -> bool {
        let held = self.requests.len()
            + self.codes.len()
            + self.tokens.len()
            + self.families.len()
            + self.clients.len();
        let room = held < SWEEP_PAGE_ROWS;
        self.more |= !room;
        room
    }
}

impl Vault {
    /// Removes the OAuth server's rows lapsed at `now`, the pass's clock, a page at a time, until
    /// none is left, `stop` says so between pages, or a page removes nothing (the rows it read
    /// changed under it), and answers what went and whether none is left.
    ///
    /// # Errors
    /// A store failure reading or removing a page.
    pub(crate) fn sweep_lapsed_oauth_rows(
        &self,
        now: u64,
        stop: impl Fn() -> bool,
    ) -> Result<(OAuthRowsSwept, bool)> {
        let now = now.min(crate::unix_seconds_now());
        let mut swept = OAuthRowsSwept::default();
        loop {
            let lapsed = self.lapsed_oauth_rows(now)?;
            let more = lapsed.more;
            let page = self.remove_lapsed_oauth_rows(&lapsed, now)?;
            swept.add(&page);
            if !more {
                return Ok((swept, true));
            }
            if page.total() == 0 || stop() {
                return Ok((swept, false));
            }
        }
    }

    /// The keys of the rows lapsed at `now`, read in one snapshot, one page of them: requests
    /// first, since an owner ask waits on each, then codes, tokens, families and clients.
    fn lapsed_oauth_rows(&self, now: u64) -> Result<LapsedRows> {
        let txn = self.store.env.read_txn()?;
        let in_use = self.oauth_clients_in_use_in_txn(&txn, now)?;
        let families = FAMILIES.scan(&self.store, &txn)?;
        // The live access token of each family that still stands: kept for the refresh that
        // retires it and revokes its slip.
        let live_access: BTreeSet<String> = families
            .iter()
            .filter(|(_, family)| now < family.expires_at)
            .filter_map(|(_, family)| family.live_access.clone())
            .collect();
        let mut lapsed = LapsedRows::default();
        for (key, request) in REQUESTS.scan(&self.store, &txn)? {
            if now >= request.expires_at && lapsed.reserve_slot() {
                lapsed.requests.push(key);
            }
        }
        for row in CODES.iter_from(&self.store, &txn, &[])? {
            let (key, code) = row?;
            if now >= code.expires_at {
                if !lapsed.reserve_slot() {
                    break;
                }
                lapsed.codes.push(key);
            }
        }
        for row in TOKENS.iter_from(&self.store, &txn, &[])? {
            let (key, token) = row?;
            if now >= token.expires_at && !live_access.contains(&key) {
                if !lapsed.reserve_slot() {
                    break;
                }
                lapsed.tokens.push(key);
            }
        }
        for (key, family) in families {
            if now >= family.expires_at {
                if !lapsed.reserve_slot() {
                    break;
                }
                lapsed.families.push(key);
            }
        }
        for (key, client) in CLIENTS.scan(&self.store, &txn)? {
            if !client.is_fresh_at(now) && !in_use.contains(&client.client_id) {
                if !lapsed.reserve_slot() {
                    break;
                }
                lapsed.clients.push(key);
            }
        }
        Ok(lapsed)
    }

    /// Removes, in one writer, each row `lapsed` names that is still lapsed at `now`, and answers
    /// how many of each went. A family takes its live access token's row with it. A client goes
    /// only while no standing family or waiting request uses it, judged in this writer as the
    /// clients table's eviction judges it.
    fn remove_lapsed_oauth_rows(&self, lapsed: &LapsedRows, now: u64) -> Result<OAuthRowsSwept> {
        self.with_write_txn_grouped(|txn| {
            let mut swept = OAuthRowsSwept::default();
            for key in &lapsed.requests {
                if REQUESTS
                    .get(&self.store, txn, key)?
                    .is_some_and(|request| now >= request.expires_at)
                    && REQUESTS.delete(&self.store, txn, key)?
                {
                    swept.requests += 1;
                }
            }
            for key in &lapsed.codes {
                if CODES
                    .get(&self.store, txn, key)?
                    .is_some_and(|code| now >= code.expires_at)
                    && CODES.delete(&self.store, txn, key)?
                {
                    swept.codes += 1;
                }
            }
            // A lapsed token never becomes a family's live access token: a refresh names only
            // the token it has just minted.
            for key in &lapsed.tokens {
                if TOKENS
                    .get(&self.store, txn, key)?
                    .is_some_and(|token| now >= token.expires_at)
                    && TOKENS.delete(&self.store, txn, key)?
                {
                    swept.tokens += 1;
                }
            }
            // A refresh refuses a lapsed family, so none stands again.
            for key in &lapsed.families {
                let Some(family) = FAMILIES
                    .get(&self.store, txn, key)?
                    .filter(|family| now >= family.expires_at)
                else {
                    continue;
                };
                if let Some(access) = &family.live_access
                    && TOKENS.delete(&self.store, txn, access)?
                {
                    swept.tokens += 1;
                }
                if FAMILIES.delete(&self.store, txn, key)? {
                    swept.families += 1;
                }
            }
            if !lapsed.clients.is_empty() {
                let in_use = self.oauth_clients_in_use_in_txn(txn, now)?;
                for key in &lapsed.clients {
                    if CLIENTS.get(&self.store, txn, key)?.is_some_and(|client| {
                        !client.is_fresh_at(now) && !in_use.contains(&client.client_id)
                    }) && CLIENTS.delete(&self.store, txn, key)?
                    {
                        swept.clients += 1;
                    }
                }
            }
            Ok(swept)
        })
    }
}
