//! The engine's sweep of the OAuth server's lapsed rows, the housekeeping sweep `oauth_expiry`
//! (FIX 4902). A read drops a row it finds past its lifetime; this sweep drops the ones no read
//! comes back to, by the same judgement, so a vault no client calls again still sheds them:
//!
//! - an authorization request past its lifetime, answered or not, as `/oauth/authorize` drops
//!   every lapsed one before it counts the waiting ones. Its owner ask then offers no tap, as for
//!   one a read dropped: the ask's taps read the request (`oauth_authorization_tap_in`). An
//!   allowed one no page collected takes back the owner agent grant its allow minted (FIX
//!   22142, `withdraw_lapsed_oauth_grant_in_txn`);
//! - an authorization code past its lifetime, redeemed or not, as the token endpoint drops one.
//!   One no exchange redeemed takes its grant back too; a redeemed one's grant stays: its
//!   family's tokens stand on it, or its exchange took the grant back when the family's first
//!   slip did not stand (FIX 22193), or a pass's sign-in end takes it back (below);
//! - an access or refresh token past its lifetime, and with an access token's row the slip it
//!   held, as a refresh or a revocation drops one. A standing family's live access token stays,
//!   so the refresh that retires it still revokes its slip (`take_live_access_in_txn`);
//! - a token family past its newest refresh token's lifetime, which no read drops: no token of it
//!   stands. Its live access token, lapsed long before, goes with it. One whose sign-in end is
//!   still due (below) stays until a pass ends it;
//! - a metadata-document client whose document is past [`super::OAUTH_CIMD_TTL_SECS`] and that
//!   no standing family or waiting request uses: its row is a copy the next authorize fetches
//!   again. A registered client has no lifetime; only the clients table's bound evicts one.
//!
//! Before its pages, each pass retries the sign-in ends that failed (FIX 22226): a token family a
//! code's exchange opened whose first access slip never stood, which the failed end write left
//! with its opening pending, once its first access token has lapsed
//! ([`super::rows::FamilyOpening::end_due_at`]). One writer per family judges it again, revokes it
//! and takes its grant back unless another live family names it, as the failed write would have
//! (`retry_oauth_sign_in_end`), and marks its opening ended, so the next pass leaves it. A family
//! whose first slip stood is never ended here. A failure is logged and the next pass retries it;
//! the pass goes on to its pages.
//!
//! Each page reads the lapsed rows in a snapshot and removes them in one short writer, which
//! judges each row again. Every lifetime is read at the earlier of the pass's clock and the wall
//! clock the server stamps the rows with, so the sweep never drops a row a read would still take.
//! The host issuer that signs a grant's withdrawal is loaded from this install's keystore, outside
//! every writer, once a snapshot finds a sign-in end due, or a request or code that holds a grant
//! or may hold one when the writer reads it: an unredeemed code, an allowed request, or a pending
//! one, which an allow may settle between the snapshot and the writer (FIX 22188). With none, the
//! grant's withdrawal marker alone keeps it on the record (`withdraw_lapsed_oauth_grant_in_txn`).

use std::collections::BTreeSet;

use super::OAUTH_CLIENTS_MAX;
use super::rows::{AuthorizationDecision, CLIENTS, CODES, FAMILIES, REQUESTS, TOKENS};
use crate::authority::HostSlipIssuer;
use crate::error::Result;
use crate::side_table::HexId;
use crate::{EntityId, Vault};

/// The most lapsed rows one page removes, across the five tables, in one writer: the clients
/// table's bound, [`OAUTH_CLIENTS_MAX`], about as many rows as one eviction from that table already
/// reads in its writer. Not an engine call of its own.
const SWEEP_PAGE_ROWS: usize = OAUTH_CLIENTS_MAX;

/// What the sweep of the OAuth server's lapsed rows removed, by table, and the grants it took
/// back with them.
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
    /// Owner agent grants taken back with an allowed request no page collected, a code no
    /// exchange redeemed, or a sign-in whose family's first access slip never stood, ended
    /// after its own end write failed (FIX 22226).
    pub(crate) grants: u64,
}

impl OAuthRowsSwept {
    /// Every row counted.
    fn total(&self) -> u64 {
        self.requests + self.codes + self.tokens + self.families + self.clients + self.grants
    }

    /// Adds `page`'s counts to these.
    fn add(&mut self, page: &Self) {
        self.requests += page.requests;
        self.codes += page.codes;
        self.tokens += page.tokens;
        self.families += page.families;
        self.clients += page.clients;
        self.grants += page.grants;
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
    /// A request or code of the page holds a grant to take back, or may hold one when the
    /// page's writer reads it: an unredeemed code, or a request the owner did not deny.
    grants: bool,
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
    /// Ends the sign-ins whose end write failed, then removes the OAuth server's rows lapsed at
    /// `now`, the pass's clock, a page at a time, until none is left, `stop` says so between
    /// pages, or a page removes nothing (the rows it read changed under it), and answers what went
    /// and whether none is left.
    ///
    /// # Errors
    /// A store failure reading or removing a page, or a fold failure signing a grant's
    /// withdrawal. A sign-in end that fails is logged, not answered.
    pub(crate) fn sweep_lapsed_oauth_rows(
        &self,
        now: u64,
        stop: impl Fn() -> bool,
    ) -> Result<(OAuthRowsSwept, bool)> {
        let now = now.min(crate::unix_seconds_now());
        let mut swept = OAuthRowsSwept::default();
        // Loaded once, outside every writer, for the first sign-in end or page that holds a grant
        // to take back or may hold one by its writer, so the writer never takes one back unsigned
        // while this install holds the vault's host issuer.
        let mut issuer: Option<Option<HostSlipIssuer>> = None;
        swept.grants += self.retry_oauth_sign_in_ends(now, &mut issuer);
        loop {
            let lapsed = self.lapsed_oauth_rows(now)?;
            if lapsed.grants && issuer.is_none() {
                issuer = Some(self.load_withdrawal_issuer());
            }
            let more = lapsed.more;
            let page = self.remove_lapsed_oauth_rows(
                &lapsed,
                issuer.as_ref().and_then(Option::as_ref),
                now,
            )?;
            swept.add(&page);
            if !more {
                return Ok((swept, true));
            }
            if page.total() == 0 || stop() {
                return Ok((swept, false));
            }
        }
    }

    /// The host issuer that signs the withdrawal of the grants a pass takes back, from this
    /// install's keystore; `None`, logged, when it holds none: the withdrawals go unsigned, their
    /// markers alone keeping them on the record.
    fn load_withdrawal_issuer(&self) -> Option<HostSlipIssuer> {
        self.load_host_slip_issuer()
            .inspect_err(|error| {
                tracing::warn!(
                    %error,
                    "no host issuer signs the withdrawal of lapsed OAuth sign-ins' agent grants; \
                     they go unsigned"
                );
            })
            .ok()
    }

    /// Ends, each in its own writer, the sign-in of every token family whose end is due at `now`
    /// ([`super::rows::FamilyOpening::end_due_at`]): one a code's exchange opened whose first
    /// access slip never stood, left so by a failed end write (FIX 22226). `issuer` is the pass's
    /// host issuer, loaded here once an end is due. Answers how many grants went back. A failure
    /// reading the families or ending one is logged and retried on the next pass.
    fn retry_oauth_sign_in_ends(
        &self,
        now: u64,
        issuer: &mut Option<Option<HostSlipIssuer>>,
    ) -> u64 {
        let due = match self.oauth_sign_in_ends_due(now) {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "reading the OAuth token families whose sign-in end is due failed"
                );
                return 0;
            }
        };
        if due.is_empty() {
            return 0;
        }
        let issuer = issuer
            .get_or_insert_with(|| self.load_withdrawal_issuer())
            .as_ref();
        let mut withdrawn = 0;
        for family in due {
            match self.retry_oauth_sign_in_end(issuer, family, now) {
                Ok(true) => withdrawn += 1,
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    %error,
                    family = %family.to_hex(),
                    "ending an OAuth sign-in whose first access slip never stood failed; the \
                     next sweep retries it"
                ),
            }
        }
        withdrawn
    }

    /// The token families whose sign-in end is due at `now`, read in one snapshot.
    fn oauth_sign_in_ends_due(&self, now: u64) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(FAMILIES
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(_, family)| family.opening.end_due_at(now))
            .map(|(key, _)| key.0)
            .collect())
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
                // A pending request may be allowed before the writer reads it: only a deny is
                // final with no grant.
                lapsed.grants |= request.decision != AuthorizationDecision::Denied;
                lapsed.requests.push(key);
            }
        }
        for row in CODES.iter_from(&self.store, &txn, &[])? {
            let (key, code) = row?;
            if now >= code.expires_at {
                if !lapsed.reserve_slot() {
                    break;
                }
                lapsed.grants |= code.unredeemed_grant().is_some();
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
            if family.drop_due_at(now) {
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
    /// how many of each went. An allowed request no page collected, or a code no exchange
    /// redeemed, takes its grant with it, the host's withdrawal signed by `issuer` when it is the
    /// vault's live host. A family takes its live access token's row with it, and goes only once
    /// no sign-in end is due for it ([`super::rows::TokenFamily::drop_due_at`]). A client goes only
    /// while no standing family or waiting request uses it, judged in this writer as the clients
    /// table's eviction judges it.
    fn remove_lapsed_oauth_rows(
        &self,
        lapsed: &LapsedRows,
        issuer: Option<&HostSlipIssuer>,
        now: u64,
    ) -> Result<OAuthRowsSwept> {
        self.with_write_txn_grouped(|txn| {
            let mut swept = OAuthRowsSwept::default();
            for key in &lapsed.requests {
                let Some(request) = REQUESTS
                    .get(&self.store, txn, key)?
                    .filter(|request| now >= request.expires_at)
                else {
                    continue;
                };
                if let Some(grant) = request.uncollected_grant()
                    && self.withdraw_lapsed_oauth_grant_in_txn(txn, issuer, &grant)?
                {
                    swept.grants += 1;
                }
                if REQUESTS.delete(&self.store, txn, key)? {
                    swept.requests += 1;
                }
            }
            for key in &lapsed.codes {
                let Some(code) = CODES
                    .get(&self.store, txn, key)?
                    .filter(|code| now >= code.expires_at)
                else {
                    continue;
                };
                if let Some(grant) = code.unredeemed_grant()
                    && self.withdraw_lapsed_oauth_grant_in_txn(txn, issuer, &grant)?
                {
                    swept.grants += 1;
                }
                if CODES.delete(&self.store, txn, key)? {
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
                    .filter(|family| family.drop_due_at(now))
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
