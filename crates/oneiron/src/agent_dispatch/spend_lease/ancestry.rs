//! Spend-tree ancestry (FIX 9563, 9564). Every walk reads each scope once,
//! however many there are (rule 5): past its threshold row it asks whether
//! everything is okay, counted on every way out. A scope read twice is a
//! cycle, and a missing parent stays an error. A closed hard scope stays a
//! cap boundary for its subtree: what a late descendant draws through it is
//! no more than its room, and what that descendant settles is tallied there
//! as well as at the open ancestor that books it.

use std::collections::HashSet;

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::Result;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendScope, SpendScopeId, SpendState};
use super::super::widen_record::invalid;

/// The scope that books for a scope's parent, and the closed hard scopes
/// passed on the way up to it, lowest first.
pub(super) struct Host {
    pub(super) host: SpendScope,
    pub(super) boundaries: Vec<SpendScope>,
}

/// The scopes one walk read, counted against its row on every way out.
#[derive(Default)]
pub(super) struct ScopeWalk {
    rows: usize,
}

impl ScopeWalk {
    /// Raises the walk's check past its row, scoped to `from`. Evidence
    /// only: it never refuses and never fails the walk's caller.
    pub(super) fn finish(self, store: &Store, txn: &heed::RoTxn<'_>, from: &SpendScopeId) {
        observe(
            store,
            txn,
            EngineScan::SpendAncestorScopes,
            from.as_str().as_bytes(),
            self.rows,
        );
    }
}

/// Counts `rows` one walk of `scan` read from `scope`; a threshold row that
/// does not read asks at the count the walk once refused past.
pub(in crate::agent_dispatch) fn observe(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scan: EngineScan,
    scope: &[u8],
    rows: usize,
) {
    let old_cutoff = match scan {
        EngineScan::SpendRetryAttempts => 1024,
        _ => 256,
    };
    let mut count = ScanCount::start(store, txn, scan, scope)
        .unwrap_or_else(|_| ScanCount::start_at(scan, scope, old_cutoff));
    count.rows(rows);
    count.defer(store);
}

impl AgentDispatcher<'_> {
    /// `scope` and the root it spends under, in the caller's snapshot; `None`
    /// when no such scope exists. The root's payer is the only consent a tree
    /// carries (OF-531): a cap or an open scope is none.
    pub(crate) fn scope_with_root_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<Option<(SpendScope, SpendScope)>> {
        let store = &self.vault.store;
        let Some(row) = SCOPE.get(store, txn, &scope.0)? else {
            return Ok(None);
        };
        let mut walk = ScopeWalk::default();
        let root = root_in_walk(store, txn, &row, &mut walk);
        walk.finish(store, txn, &row.scope);
        Ok(Some((row, root?)))
    }

    /// The scope row `attempt` spends under, in the caller's snapshot: a
    /// retry's is the try it retries, however long its retry lineage (rule
    /// 5). `None`: unmetered.
    pub(in crate::agent_dispatch) fn scope_for_attempt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<SpendScopeId>> {
        let mut seen = HashSet::new();
        let found = self.retry_scope_in_txn(txn, attempt, &mut seen);
        observe(
            &self.vault.store,
            txn,
            EngineScan::SpendRetryAttempts,
            attempt.as_bytes(),
            seen.len(),
        );
        found
    }

    fn retry_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
        seen: &mut HashSet<AttemptId>,
    ) -> Result<Option<SpendScopeId>> {
        let queue = AttemptQueue::new(self.vault);
        let mut cursor = attempt;
        loop {
            if !seen.insert(cursor) {
                return Err(invalid("spend scope retry lineage cycle"));
            }
            let id = SpendScopeId::for_attempt(&cursor);
            if SCOPE.contains(&self.vault.store, txn, &id.0)? {
                return Ok(Some(id));
            }
            match queue.get_in_txn(txn, cursor)?.and_then(|row| row.retry_of) {
                Some(previous) => cursor = previous,
                None => return Ok(None),
            }
        }
    }

    /// The scope that books `scope`'s spend: itself when open, else its
    /// nearest open ancestor; when nothing above is open either, itself.
    pub(in crate::agent_dispatch) fn effective_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<SpendScope> {
        let store = &self.vault.store;
        let row = SCOPE
            .get(store, txn, &scope.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if row.state == SpendState::Open {
            return Ok(row);
        }
        let mut walk = ScopeWalk::default();
        let open = self.nearest_open_in_walk(txn, &row, &mut walk);
        walk.finish(store, txn, &row.scope);
        Ok(open?.map_or(row, |hop| hop.host))
    }

    /// The scope that books for `scope`'s parent: its nearest open ancestor;
    /// when every ancestor is closed, the direct parent keeps the books.
    pub(in crate::agent_dispatch) fn open_parent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<SpendScope> {
        Ok(self.host_in_txn(txn, scope)?.host)
    }

    /// [`Self::open_parent_in_txn`] with the closed hard scopes passed on
    /// the way up to it.
    pub(super) fn host_in_txn(&self, txn: &heed::RoTxn<'_>, scope: &SpendScope) -> Result<Host> {
        let mut walk = ScopeWalk::default();
        let host = self.host_in_walk(txn, scope, &mut walk);
        walk.finish(&self.vault.store, txn, &scope.scope);
        host
    }

    /// [`Self::host_in_txn`], counted in `walk`.
    pub(super) fn host_in_walk(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
        walk: &mut ScopeWalk,
    ) -> Result<Host> {
        if let Some(hop) = self.nearest_open_in_walk(txn, scope, walk)? {
            return Ok(hop);
        }
        let parent = scope
            .parent
            .as_ref()
            .ok_or_else(|| invalid("spend scope has no parent"))?;
        let host = SCOPE
            .get(&self.vault.store, txn, &parent.0)?
            .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
        Ok(Host {
            host,
            boundaries: Vec::new(),
        })
    }

    /// `scope`'s nearest open ancestor and the closed hard scopes below it;
    /// `None` when every ancestor is closed.
    fn nearest_open_in_walk(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
        walk: &mut ScopeWalk,
    ) -> Result<Option<Host>> {
        let mut seen = HashSet::from([scope.scope.clone()]);
        let mut boundaries = Vec::new();
        let mut cursor = scope.parent.clone();
        while let Some(id) = cursor {
            if !seen.insert(id.clone()) {
                return Err(invalid("spend scope ancestor cycle"));
            }
            walk.rows = walk.rows.saturating_add(1);
            let row = SCOPE
                .get(&self.vault.store, txn, &id.0)?
                .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
            if row.state == SpendState::Open {
                return Ok(Some(Host {
                    host: row,
                    boundaries,
                }));
            }
            cursor = row.parent.clone();
            if row.hard {
                boundaries.push(row);
            }
        }
        Ok(None)
    }

    /// The hops a soft `scope` tops up through, lowest first: each the host
    /// above the last, until a hard scope or the root.
    fn top_up_hops_in_walk(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
        walk: &mut ScopeWalk,
    ) -> Result<Vec<Host>> {
        let mut hosts = HashSet::from([scope.scope.clone()]);
        let mut hops = Vec::new();
        let mut current = scope.clone();
        while !current.hard && current.parent.is_some() {
            let hop = self.host_in_walk(txn, &current, walk)?;
            if !hosts.insert(hop.host.scope.clone()) {
                return Err(invalid("spend scope ancestor cycle"));
            }
            current = hop.host.clone();
            hops.push(hop);
        }
        Ok(hops)
    }

    /// What `scope` may spend: its own local units, plus, while it is soft,
    /// its open ancestors' up to and including the nearest hard one, no more
    /// through a closed hard scope than its room.
    pub(in crate::agent_dispatch) fn available_from_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<u64> {
        let mut walk = ScopeWalk::default();
        let hops = self.top_up_hops_in_walk(txn, scope, &mut walk);
        walk.finish(&self.vault.store, txn, &scope.scope);
        let mut through = 0u64;
        for hop in hops?.iter().rev() {
            through = hop.host.local_available().saturating_add(through);
            for boundary in &hop.boundaries {
                through = through.min(boundary.local_available());
            }
        }
        Ok(scope.local_available().saturating_add(through))
    }

    /// The hard scope whose cap binds `scope`: itself when hard, else the
    /// nearest hard scope above it on its top-up chain, a closed one
    /// included.
    pub(in crate::agent_dispatch) fn binding_cap_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<SpendScope> {
        let mut walk = ScopeWalk::default();
        let hops = self.top_up_hops_in_walk(txn, scope, &mut walk);
        walk.finish(&self.vault.store, txn, &scope.scope);
        for hop in hops? {
            if let Some(boundary) = hop.boundaries.into_iter().next() {
                return Ok(boundary);
            }
            if hop.host.hard || hop.host.parent.is_none() {
                return Ok(hop.host);
            }
        }
        Ok(scope.clone())
    }
}

/// The root `row` spends under, every parent read once in `walk`.
fn root_in_walk(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &SpendScope,
    walk: &mut ScopeWalk,
) -> Result<SpendScope> {
    let mut seen = HashSet::from([row.scope.clone()]);
    let mut root = row.clone();
    while let Some(parent) = root.parent.clone() {
        if !seen.insert(parent.clone()) {
            return Err(invalid("spend scope ancestor cycle"));
        }
        walk.rows = walk.rows.saturating_add(1);
        root = SCOPE
            .get(store, txn, &parent.0)?
            .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
    }
    Ok(root)
}
