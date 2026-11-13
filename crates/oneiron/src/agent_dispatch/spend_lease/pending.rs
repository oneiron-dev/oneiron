//! A live lease's staged spend ([RUN-STEP-CHARGE-LOST-ON-PROCESS-DEATH]).
//!
//! A host's live lease books a try's settled calls on its spend scope in
//! parts. Before this table, a part the lease had not yet booked lived only
//! in memory: a process that died, or a booking write that failed, between a
//! provider's answer and the booking lost that paid call's charge, and a step
//! whose answer was saved meanwhile replayed with no call and no booking.
//!
//! Now each part is first staged in its own commit, keyed by its scope and
//! its lease, before any answer it paid for is saved. A drain then books a
//! scope's staged rows through [`AgentDispatcher::record_guard_spend_in_txn`]
//! and deletes them in the same commit, so a row's units land on the scope
//! exactly once: a second drainer finds no row and books nothing (the key is
//! the row, as a free-time item's wake reservation is, FIX 4453). The lease
//! drains at each look and at its try's end; a saved answer read again
//! drains its scope before it answers; the server drains every row at its
//! start, for a lease whose process died. A row whose scope row is gone has
//! no one left to charge: its drain deletes it and logs its units (the
//! Engine, 12 Nov 19:40), so no dead row is retried forever.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendScopeId};
use super::super::widen_record::invalid;

/// Staged spend rows. Key: the scope id, 0x00, then id16(lease). Value: the
/// units staged, u64 big-endian. A scope id is printable ASCII, so the 0x00
/// ends it and one scope's prefix never reaches another's rows.
const PENDING: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::AGENT_DISPATCH_LEASE_PENDING_SPEND);

/// The bytes after a row's scope id: the 0x00 and the lease's id.
const LEASE_SUFFIX_LEN: usize = 1 + 16;

fn scope_prefix(scope: &SpendScopeId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(scope.as_str().len() + 1);
    prefix.extend_from_slice(scope.as_str().as_bytes());
    prefix.push(0);
    prefix
}

fn row_key(scope: &SpendScopeId, lease: EntityId) -> Vec<u8> {
    let mut key = scope_prefix(scope);
    key.extend_from_slice(lease.as_bytes());
    key
}

fn row_units(value: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| invalid("a staged lease spend row is not 8 bytes"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn row_scope(key: &[u8]) -> Result<SpendScopeId> {
    let end = key
        .len()
        .checked_sub(LEASE_SUFFIX_LEN)
        .filter(|end| *end > 0 && key[*end] == 0)
        .ok_or_else(|| invalid("a staged lease spend key has no scope"))?;
    let scope = std::str::from_utf8(&key[..end])
        .map_err(|_| invalid("a staged lease spend key's scope is not text"))?;
    Ok(SpendScopeId(scope.to_owned()))
}

impl AgentDispatcher<'_> {
    /// Stages `units` a live lease's meter spent on `scope`, in its own
    /// commit, added to what the lease staged before and no drain booked.
    /// Nothing is booked on the scope yet: [`Self::drain_lease_spend`] books
    /// it. A lease stages each unit once, before any answer it paid for is
    /// saved, so a process that dies after the stage loses nothing.
    pub fn stage_lease_spend(
        &self,
        scope: &SpendScopeId,
        lease: EntityId,
        units: u64,
    ) -> Result<()> {
        if units == 0 {
            return Ok(());
        }
        let mut txn = self.vault.store.env.write_txn()?;
        self.stage_lease_spend_in_txn(&mut txn, scope, lease, units)?;
        txn.commit()?;
        Ok(())
    }

    /// [`Self::stage_lease_spend`] in the caller's write transaction `txn`,
    /// so the stage commits with what else the caller writes there, or not
    /// at all: a scoped media job stages its end's part in the commit that
    /// writes its end row or its delete, so no restart takes up a job whose
    /// end is staged ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH]).
    #[doc(hidden)]
    pub fn stage_lease_spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScopeId,
        lease: EntityId,
        units: u64,
    ) -> Result<()> {
        if units == 0 {
            return Ok(());
        }
        let key = row_key(scope, lease);
        let staged = match PENDING.get(&self.vault.store, txn, &key)? {
            Some(value) => row_units(&value)?,
            None => 0,
        };
        let total = staged.saturating_add(units);
        PENDING.put(&self.vault.store, txn, &key, &total.to_be_bytes().to_vec())?;
        Ok(())
    }

    /// What every lease staged on `scope` and no drain booked yet.
    pub fn staged_lease_spend(&self, scope: &SpendScopeId) -> Result<u64> {
        let txn = self.vault.store.env.read_txn()?;
        let mut total = 0u64;
        for row in PENDING.iter_from(&self.vault.store, &txn, &scope_prefix(scope))? {
            let (_, value) = row?;
            total = total.saturating_add(row_units(&value)?);
        }
        Ok(total)
    }

    /// Books on `scope` every lease's staged spend and deletes those rows,
    /// in one commit, and answers the units it booked. Each row's units land
    /// once: the commit that books them deletes the row, so a later drain,
    /// here or at the server's start, finds none and books nothing. A scope
    /// with no staged row opens no write. When `scope`'s row is gone (an
    /// erase took it), nothing is booked: the rows are deleted in the same
    /// commit and their units logged, and the answer is 0.
    pub fn drain_lease_spend(&self, scope: &SpendScopeId) -> Result<u64> {
        if !self.has_staged_rows(scope)? {
            return Ok(0);
        }
        let prefix = scope_prefix(scope);
        let mut txn = self.vault.store.env.write_txn()?;
        let mut units = 0u64;
        let mut keys = Vec::new();
        for row in PENDING.iter_from(&self.vault.store, &txn, &prefix)? {
            let (key, value) = row?;
            units = units.saturating_add(row_units(&value)?);
            keys.push(key);
        }
        let gone = SCOPE.get(&self.vault.store, &txn, &scope.0)?.is_none();
        if gone {
            tracing::warn!(
                scope = scope.as_str(),
                units,
                "a staged lease spend was dropped: its spend scope is gone"
            );
        } else if units > 0 {
            self.record_guard_spend_in_txn(&mut txn, scope, units)?;
        }
        for key in &keys {
            PENDING.delete(&self.vault.store, &mut txn, key)?;
        }
        txn.commit()?;
        Ok(if gone { 0 } else { units })
    }

    /// [`Self::drain_lease_spend`] for every scope a staged row names, as
    /// the server runs it at its start for a lease whose process died. Each
    /// scope drains in its own commit, so a scope that cannot book keeps its
    /// rows and the others still drain; the first such error is answered
    /// after every scope was tried.
    pub fn drain_all_lease_spend(&self) -> Result<u64> {
        let scopes = {
            let txn = self.vault.store.env.read_txn()?;
            let mut scopes: Vec<SpendScopeId> = Vec::new();
            for key in PENDING.scan_keys(&self.vault.store, &txn, &[])? {
                let scope = row_scope(&key)?;
                if scopes.last() != Some(&scope) {
                    scopes.push(scope);
                }
            }
            scopes
        };
        let mut units = 0u64;
        let mut first_error = None;
        for scope in &scopes {
            match self.drain_lease_spend(scope) {
                Ok(drained) => units = units.saturating_add(drained),
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        scope = scope.as_str(),
                        "a scope's staged lease spend did not drain"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(units),
        }
    }

    /// Whether any staged row is on `scope`.
    fn has_staged_rows(&self, scope: &SpendScopeId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        let mut rows = PENDING.iter_from(&self.vault.store, &txn, &scope_prefix(scope))?;
        Ok(rows.next().transpose()?.is_some())
    }
}
