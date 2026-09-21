//! Node-local time-held symbol declarations and atomic queue ordering.

use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const PREFIX: &[u8] = b"tasks.symbol_lease.v1/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolLease {
    pub task_ref: String,
    pub holder_ref: String,
    pub symbols: BTreeSet<String>,
    pub expires_at: u64,
    pub held: bool,
    ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolLeaseOutcome {
    Granted(SymbolLease),
    Waiting {
        declaration: SymbolLease,
        blockers: Vec<EntityId>,
    },
}

fn key(task: EntityId) -> Vec<u8> {
    [PREFIX, task.as_bytes()].concat()
}
fn load(store: &Store, txn: &heed::RoTxn<'_>, task: EntityId) -> Result<Option<SymbolLease>> {
    store
        .vault_meta
        .get(txn, &key(task))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("symbol lease")))
        .transpose()
}
fn save(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    lease: &SymbolLease,
) -> Result<()> {
    let raw = serde_json::to_vec(lease)
        .map_err(|_| Error::InvariantViolation("symbol lease encoding"))?;
    store.vault_meta.put(txn, &key(task), &raw)?;
    Ok(())
}
fn blockers(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    wanted: &BTreeSet<String>,
    now: u64,
) -> Result<Vec<EntityId>> {
    let mut blocked = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, PREFIX)? {
        let (_, raw) = row?;
        let lease: SymbolLease =
            serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("symbol lease"))?;
        let other = EntityId::from_hex(&lease.task_ref)?;
        if other != task
            && lease.held
            && lease.expires_at > now
            && !lease.symbols.is_disjoint(wanted)
        {
            blocked.push(other);
        }
    }
    Ok(blocked)
}

impl Vault {
    /// Trusted scheduler door. The holder is bound to the declaration and must
    /// match on renew/release. An overlap queues the declaration; it is not refused.
    pub fn declare_symbols(
        &self,
        task: EntityId,
        holder: EntityId,
        symbols: BTreeSet<String>,
        ttl_seconds: u64,
        now: u64,
    ) -> Result<SymbolLeaseOutcome> {
        if ttl_seconds == 0
            || symbols.is_empty()
            || symbols.len() > 4096
            || symbols
                .iter()
                .any(|s| s.trim().is_empty() || s.len() > 1024)
        {
            return Err(Error::InvalidConfig(
                "invalid symbol declaration".to_owned(),
            ));
        }
        self.with_write_txn(|txn| {
            if self.get_entity_type_in_txn(txn, &task)? != Some(crate::registry::ENTITY_TYPE_TASK)
                || self.get_entity_type_in_txn(txn, &holder)?.is_none()
            {
                return Err(Error::EntityNotFound);
            }
            if let Some(prior) = load(&self.store, txn, task)?
                && prior.expires_at > now
                && (prior.holder_ref != holder.to_hex() || (prior.held && prior.symbols != symbols))
            {
                return Err(Error::ConcurrentWrite(
                    "live symbol declaration cannot be replaced",
                ));
            }
            let blockers = blockers(&self.store, txn, task, &symbols, now)?;
            let lease = SymbolLease {
                task_ref: task.to_hex(),
                holder_ref: holder.to_hex(),
                symbols,
                expires_at: now
                    .checked_add(ttl_seconds)
                    .ok_or(Error::ArithmeticOverflow("symbol lease expiry"))?,
                held: blockers.is_empty(),
                ttl_seconds,
            };
            save(&self.store, txn, task, &lease)?;
            Ok(if blockers.is_empty() {
                SymbolLeaseOutcome::Granted(lease)
            } else {
                SymbolLeaseOutcome::Waiting {
                    declaration: lease,
                    blockers,
                }
            })
        })
    }

    pub fn renew_symbols(&self, task: EntityId, holder: EntityId, now: u64) -> Result<SymbolLease> {
        self.with_write_txn(|txn| {
            let mut lease = load(&self.store, txn, task)?.ok_or(Error::EntityNotFound)?;
            if lease.holder_ref != holder.to_hex() || !lease.held || lease.expires_at <= now {
                return Err(Error::InvalidConfig(
                    "symbol lease is not live for holder".to_owned(),
                ));
            }
            lease.expires_at = now
                .checked_add(lease.ttl_seconds)
                .ok_or(Error::ArithmeticOverflow("symbol lease expiry"))?;
            save(&self.store, txn, task, &lease)?;
            Ok(lease)
        })
    }

    pub fn release_symbols(&self, task: EntityId, holder: EntityId) -> Result<bool> {
        self.with_write_txn(|txn| {
            let Some(lease) = load(&self.store, txn, task)? else {
                return Ok(false);
            };
            if lease.holder_ref != holder.to_hex() {
                return Err(Error::InvalidConfig(
                    "symbol lease holder mismatch".to_owned(),
                ));
            }
            self.store.vault_meta.delete(txn, &key(task))
        })
    }

    /// Expiry clears the hold, not its declared symbol set. A later dispatch
    /// must reacquire the declaration before it can run.
    pub fn expire_symbol_leases(&self, now: u64) -> Result<Vec<EntityId>> {
        self.with_write_txn(|txn| {
            let mut expired = Vec::new();
            let rows = self
                .store
                .vault_meta
                .prefix_iter(txn, PREFIX)?
                .map(|row| row.map(|(_, raw)| raw.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for raw in rows {
                let mut lease: SymbolLease = serde_json::from_slice(&raw)
                    .map_err(|_| Error::CorruptedIndex("symbol lease"))?;
                if lease.held && lease.expires_at <= now {
                    let task = EntityId::from_hex(&lease.task_ref)?;
                    lease.held = false;
                    save(&self.store, txn, task, &lease)?;
                    expired.push(task);
                }
            }
            Ok(expired)
        })
    }
}

pub(crate) fn symbols_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    now: u64,
) -> Result<bool> {
    let Some(lease) = load(store, txn, task)? else {
        return Ok(true);
    };
    Ok(blockers(store, txn, task, &lease.symbols, now)?.is_empty())
}

pub(crate) fn acquire_symbols(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    now: u64,
) -> Result<()> {
    if let Some(mut lease) = load(store, txn, task)? {
        if !blockers(store, txn, task, &lease.symbols, now)?.is_empty() {
            return Err(Error::ConcurrentWrite("overlapping symbol lease"));
        }
        if !lease.held || lease.expires_at <= now {
            lease.held = true;
            lease.expires_at = now
                .checked_add(lease.ttl_seconds)
                .ok_or(Error::ArithmeticOverflow("symbol lease expiry"))?;
            save(store, txn, task, &lease)?;
        }
    }
    Ok(())
}

pub(crate) fn forget_symbols(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    store.vault_meta.delete(txn, &key(task))?;
    Ok(())
}
