//! Replies to parked code runs: a run whose step parked on a durable wait
//! resumes from the reply delivered to it. The rows are where the run's rows
//! are: base, or its off-record room's overlay, through the route it
//! captured at entry. Nothing here knows what kind of wait it carries; a
//! wait's settler delivers, and the run's host re-enters the run.
//!
//! A parked run registers as a waiter on its wait id; a settler records the
//! wait's reply once and delivers it to every waiter it finds. Put-if-absent
//! is the consumption of one generation of one run's wait: a second delivery
//! is a no-op, and a park after the settle finds the reply already there, so
//! no wakeup is lost either way round. A canonical host may bind a C9 trap to
//! a parked wait, which the delivering commit wakes; a room binds none, and
//! its host re-enters by running the run again.

use std::cell::Cell;

use serde::{Deserialize, Serialize};

use super::routing::SessionBinding;
use crate::code_run::ExecutorStorage;
use crate::llm::{DreamerTrapKind, TrapRef};
use crate::off_record::OffRecordSession;
use crate::side_table::{self, CodecError, Raw, RawValue, SideCodec, SideKey, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// One parked wait of one run. `generation` counts how many times the run
/// already resumed from `wait_id`, so it is 0 for a wait that parks once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WaitKey {
    pub run: EntityId,
    pub wait_id: EntityId,
    pub generation: u64,
}

impl WaitKey {
    fn row(&self) -> (EntityId, EntityId, u64) {
        (self.run, self.wait_id, self.generation)
    }

    fn waiter(&self) -> ([u8; 1], EntityId, EntityId) {
        (WAITER_TAG, self.wait_id, self.run)
    }
}

/// The reply one wait was answered with, and when it was delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitDelivery {
    /// The reply as JSON text.
    pub reply: String,
    pub delivered_at_ms: u64,
}

impl RawValue for WaitDelivery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run wait delivery").into())
    }
}

/// A bound trap as its row spells it: anchor id, step hash, then the kind's
/// stable name.
impl RawValue for TrapRef {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(16 + 32 + 16);
        out.extend_from_slice(self.trap_claim_id.as_bytes());
        out.extend_from_slice(&self.step_hash);
        out.extend_from_slice(self.kind.as_str().as_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let undecodable = || CodecError::from(Error::CorruptedIndex("code-run wait trap"));
        let (id, rest) = bytes.split_at_checked(16).ok_or_else(undecodable)?;
        let (hash, kind) = rest.split_at_checked(32).ok_or_else(undecodable)?;
        Ok(Self {
            trap_claim_id: id
                .try_into()
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok())
                .ok_or_else(undecodable)?,
            kind: std::str::from_utf8(kind)
                .ok()
                .and_then(DreamerTrapKind::parse)
                .ok_or_else(undecodable)?,
            step_hash: hash.try_into().map_err(|_| undecodable())?,
        })
    }
}

/// Leads a parked waiter's index row: `p` + wait + run → generation.
const WAITER_TAG: [u8; 1] = *b"p";

/// Leads a wait's settled row: `s` + wait → the reply it settled with.
const SETTLED_TAG: [u8; 1] = *b"s";

const DELIVERIES: SideTable<(EntityId, EntityId, u64), WaitDelivery, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_DELIVERY);

const WAITERS: SideTable<([u8; 1], EntityId, EntityId), u64, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_INDEX);

/// The wait's first reply, kept as the delivery every later waiter gets.
const SETTLED: SideTable<([u8; 1], EntityId), WaitDelivery, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_INDEX);

const TRAPS: SideTable<(EntityId, EntityId, u64), TrapRef, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_TRAP);

fn reply_text(reply: &serde_json::Value) -> Result<String> {
    serde_json::to_string(reply)
        .map_err(|_| Error::InvalidConfig("a code-run wait reply is not JSON".to_owned()))
}

fn waiter_prefix(wait_id: EntityId) -> Vec<u8> {
    let mut prefix = WAITER_TAG.to_vec();
    prefix.extend_from_slice(wait_id.as_bytes());
    prefix
}

/// Settles `wait_id` with `reply` in the caller's transaction: records the
/// reply unless the wait already settled, then delivers the settled reply to
/// every run parked on it that has none, waking each one's bound trap in the
/// same commit. Returns how many runs this call delivered to.
pub(crate) fn deliver_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reply: &serde_json::Value,
    now_ms: u64,
) -> Result<usize> {
    let settled = match SETTLED.get(&vault.store, txn, &(SETTLED_TAG, wait_id))? {
        Some(settled) => settled,
        None => {
            let settled = WaitDelivery {
                reply: reply_text(reply)?,
                delivered_at_ms: now_ms,
            };
            SETTLED.put(&vault.store, txn, &(SETTLED_TAG, wait_id), &settled)?;
            settled
        }
    };
    let mut delivered = 0;
    for ((_, _, run), generation) in
        WAITERS.scan_from(&vault.store, txn, &waiter_prefix(wait_id))?
    {
        let key = WaitKey {
            run,
            wait_id,
            generation,
        };
        if deliver_in_txn(vault, txn, &key, &settled)? {
            delivered += 1;
        }
    }
    Ok(delivered)
}

/// Writes one waiter's delivery unless it has one, and wakes the trap bound
/// to it in the same transaction; `true` when this call delivered.
fn deliver_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
    settled: &WaitDelivery,
) -> Result<bool> {
    if DELIVERIES.contains(&vault.store, txn, &key.row())? {
        return Ok(false);
    }
    DELIVERIES.put(&vault.store, txn, &key.row(), settled)?;
    if let Some(trap) = TRAPS.get(&vault.store, txn, &key.row())? {
        crate::llm::wake_trap_in_txn(vault, txn, &trap, settled.delivered_at_ms)?;
    }
    Ok(true)
}

/// Binds a canonical run's C9 trap to its parked wait, in one transaction:
/// the delivering commit wakes it, and a reply already delivered wakes it
/// here. `true` when it woke. The host parks the run's attempt under the
/// trap before binding it, so a wake always finds the park.
pub fn bind_wait_trap(vault: &Vault, key: &WaitKey, trap: &TrapRef, now_ms: u64) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        TRAPS.put(&vault.store, txn, &key.row(), trap)?;
        if !DELIVERIES.contains(&vault.store, txn, &key.row())? {
            return Ok(false);
        }
        crate::llm::wake_trap_in_txn(vault, txn, trap, now_ms)?;
        Ok(true)
    })
}

/// Puts `value` at `key` along the run's route unless the composed view
/// holds a row there; `true` when this call wrote it. The comparison runs in
/// the transaction that writes.
fn put_if_absent_routed<K: SideKey, V, C: SideCodec<V>>(
    binding: &SessionBinding<'_>,
    table: &SideTable<K, V, C>,
    key: &K,
    value: &V,
) -> Result<bool> {
    let held = Cell::new(false);
    let put = binding.session.side_table_compare_and_put_routed(
        &binding.route,
        table,
        key,
        value,
        |current| match current {
            Some(_) => {
                held.set(true);
                Err(Error::InvariantViolation("the code-run wait row is held"))
            }
            None => Ok(()),
        },
    );
    match put {
        Ok(()) => Ok(true),
        Err(_) if held.get() => Ok(false),
        Err(error) => Err(error),
    }
}

impl ExecutorStorage<'_> {
    /// [`deliver_wait_in_txn`] where the run's rows are. A room's rows ride
    /// its route one at a time, each written only where it is absent, and
    /// bind no trap.
    pub(crate) fn deliver_wait(
        &self,
        wait_id: EntityId,
        reply: &serde_json::Value,
        now_ms: u64,
    ) -> Result<usize> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                deliver_wait_in_txn(vault, txn, wait_id, reply, now_ms)
            }),
            Self::Session(binding) => binding.answered(|| {
                let fresh = WaitDelivery {
                    reply: reply_text(reply)?,
                    delivered_at_ms: now_ms,
                };
                put_if_absent_routed(binding, &SETTLED, &(SETTLED_TAG, wait_id), &fresh)?;
                let settled = binding
                    .session
                    .side_table_get(&SETTLED, &(SETTLED_TAG, wait_id))?
                    .ok_or(Error::InvariantViolation(
                        "a settled code-run wait has no row",
                    ))?;
                let waiters = {
                    let view = binding.session.read_view()?;
                    let txn = view.read().base().env.read_txn()?;
                    WAITERS.scan_from(&view, &txn, &waiter_prefix(wait_id))?
                };
                let mut delivered = 0;
                for ((_, _, run), generation) in waiters {
                    let key = WaitKey {
                        run,
                        wait_id,
                        generation,
                    };
                    if put_if_absent_routed(binding, &DELIVERIES, &key.row(), &settled)? {
                        delivered += 1;
                    }
                }
                Ok(delivered)
            }),
        }
    }

    /// Registers the run as parked on `key`'s wait. When the wait already
    /// settled, it delivers the settled reply in the same step and answers
    /// `true`: a settle before the park left its reply, and a settle after
    /// it finds the waiter.
    pub(crate) fn park_wait(&self, key: &WaitKey) -> Result<bool> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                WAITERS.put(&vault.store, txn, &key.waiter(), &key.generation)?;
                let Some(settled) = SETTLED.get(&vault.store, txn, &(SETTLED_TAG, key.wait_id))?
                else {
                    return Ok(false);
                };
                deliver_in_txn(vault, txn, key, &settled)?;
                Ok(true)
            }),
            // The waiter is written before the settled row is read, and a
            // settler writes the settled row before it reads the waiters, so
            // one of the two always sees the other.
            Self::Session(binding) => binding.answered(|| {
                binding.session.side_table_put_routed(
                    &binding.route,
                    &WAITERS,
                    &key.waiter(),
                    &key.generation,
                )?;
                let Some(settled) = binding
                    .session
                    .side_table_get(&SETTLED, &(SETTLED_TAG, key.wait_id))?
                else {
                    return Ok(false);
                };
                put_if_absent_routed(binding, &DELIVERIES, &key.row(), &settled)?;
                Ok(true)
            }),
        }
    }

    /// The reply delivered to `key`'s wait, if one was.
    pub(crate) fn wait_delivery(&self, key: &WaitKey) -> Result<Option<WaitDelivery>> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                DELIVERIES.get(&vault.store, &txn, &key.row())
            }
            Self::Session(binding) => {
                binding.answered(|| binding.session.side_table_get(&DELIVERIES, &key.row()))
            }
        }
    }

    /// Retires `key`'s waiter, delivery and trap rows once the resumed record
    /// committed; idempotent. A room's rows stay until the room goes: its
    /// route writes and never deletes, and the resumed record already names
    /// the next generation, so nothing reads them again.
    pub(crate) fn clear_wait(&self, key: &WaitKey) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                if WAITERS.get(&vault.store, txn, &key.waiter())? == Some(key.generation) {
                    WAITERS.delete(&vault.store, txn, &key.waiter())?;
                }
                DELIVERIES.delete(&vault.store, txn, &key.row())?;
                TRAPS.delete(&vault.store, txn, &key.row())?;
                Ok(())
            }),
            Self::Session(_) => Ok(()),
        }
    }
}

/// Parked code runs' deliveries, for a host that re-enters its runs and a
/// settler that answers their waits: the canonical vault's, or one room's
/// as a participant stands in it.
pub struct WaitDeliveries<'a> {
    storage: ExecutorStorage<'a>,
}

impl<'a> WaitDeliveries<'a> {
    #[must_use]
    pub fn canonical(vault: &'a Vault) -> Self {
        Self {
            storage: ExecutorStorage::Canonical(vault),
        }
    }

    /// The room's deliveries as `participant` stands in it, along the route
    /// captured here.
    pub fn for_session(session: &OffRecordSession<'a>, participant: EntityId) -> Result<Self> {
        Ok(Self {
            storage: ExecutorStorage::for_session(session, participant)?,
        })
    }

    /// Settles `wait_id` with `reply` and delivers it to every run parked on
    /// it; returns how many runs this call delivered to.
    pub fn deliver(
        &self,
        wait_id: EntityId,
        reply: &serde_json::Value,
        now_ms: u64,
    ) -> Result<usize> {
        self.storage.deliver_wait(wait_id, reply, now_ms)
    }

    /// Registers a run as parked on `key`'s wait; `true` when its reply is
    /// already delivered.
    pub fn park(&self, key: &WaitKey) -> Result<bool> {
        self.storage.park_wait(key)
    }

    pub fn delivery(&self, key: &WaitKey) -> Result<Option<WaitDelivery>> {
        self.storage.wait_delivery(key)
    }

    pub fn clear(&self, key: &WaitKey) -> Result<()> {
        self.storage.clear_wait(key)
    }
}
