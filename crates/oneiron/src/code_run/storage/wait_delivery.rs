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
//!
//! Each run a reply is delivered to joins the wait's holders
//! (`wait_holders`, FIX 5718): once an erase of its actor took its replies,
//! it is delivered the reply's erased form, parks on nothing and reads a
//! typed unavailable, while every other holder reads the reply as before.

use std::cell::Cell;

use serde::{Deserialize, Serialize};

use super::replay_bodies::response_erased_error;
use super::routing::SessionBinding;
use super::wait_holders::{hold_settled_for_caller_in_txn, holder_erased_in_txn, join_wait_in_txn};
use crate::code_run::ExecutorStorage;
use crate::llm::{DreamerTrapKind, TrapRef};
use crate::off_record::OffRecordSession;
use crate::side_table::{
    self, CodecError, Erased, ErasedForm, Raw, RawValue, SideCodec, SideKey, SideTable,
};
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
    /// The rows the reply was derived from, as its settler listed them
    /// (FIX 5455): the rows a connector call's passes picked. `None` when
    /// its settler listed none: the reply then adds no row to its run's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
    /// Whether an erase of its holder's actor took the reply (FIX 5718):
    /// its text is gone, and when it came and its rows stay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erased: bool,
}

/// A delivery's erased form (FIX 5718): when it came and the rows its reply
/// was derived from stay, its reply goes. An erase writes it past the
/// side-row wall.
impl ErasedForm for WaitDelivery {
    fn into_erased(self) -> Result<Self> {
        Ok(Self {
            reply: String::new(),
            erased: true,
            ..self
        })
    }
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
pub(super) const SETTLED_TAG: [u8; 1] = *b"s";

pub(super) const DELIVERIES: SideTable<(EntityId, EntityId, u64), WaitDelivery, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_DELIVERY);

const WAITERS: SideTable<([u8; 1], EntityId, EntityId), u64, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_INDEX);

/// The wait's first reply, kept as the delivery every later waiter gets.
pub(super) const SETTLED: SideTable<([u8; 1], EntityId), WaitDelivery, Raw> =
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
    deliver_wait_listing_in_txn(vault, txn, wait_id, reply, None, now_ms)
}

/// [`deliver_wait_in_txn`], `reply` kept beside `rows`, the rows its settler
/// listed it derived from (FIX 5455), when it lists them.
pub(crate) fn deliver_wait_listing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reply: &serde_json::Value,
    rows: Option<&[EntityId]>,
    now_ms: u64,
) -> Result<usize> {
    let settled = match SETTLED.get(&vault.store, txn, &(SETTLED_TAG, wait_id))? {
        Some(settled) => settled,
        None => {
            let mut settled = WaitDelivery {
                reply: reply_text(reply)?,
                delivered_at_ms: now_ms,
                source_rows: rows.map(<[EntityId]>::to_vec),
                erased: false,
            };
            SETTLED.admit(vault, txn, &(SETTLED_TAG, wait_id), &mut settled)?;
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

/// The reply `wait_id` settled with, read in the caller's transaction, as the
/// side-row wall stored it and as every waiter parked on it is delivered it.
/// One an erase took is a typed unavailable, never a digest's input.
pub(crate) fn settled_wait_reply_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
) -> Result<Option<String>> {
    match SETTLED.get(&vault.store, txn, &(SETTLED_TAG, wait_id))? {
        Some(settled) if settled.erased => Err(response_erased_error("a wait's settled reply")),
        settled => Ok(settled.map(|settled| settled.reply)),
    }
}

/// Whether `key`'s wait has a reply at `txn`'s revision: delivered to it, or
/// settled for every waiter on it. A held turn program resumes on this alone
/// (DOOR-141 PR3b). A reply an erase took still came (FIX 5718): the resumed
/// entry meets the erase, typed, and the wait never reads as unsettled.
pub(crate) fn wait_delivered_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
) -> Result<bool> {
    Ok(DELIVERIES.contains(&vault.store, txn, &key.row())?
        || SETTLED.contains(&vault.store, txn, &(SETTLED_TAG, key.wait_id))?)
}

/// Writes one waiter's delivery unless it has one, and wakes the trap bound
/// to it in the same transaction; `true` when this call delivered. The run
/// joins the wait's holders (FIX 5718); one an erase of its actor took the
/// replies of is delivered the reply's erased form, which it never reads.
fn deliver_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
    settled: &WaitDelivery,
) -> Result<bool> {
    if DELIVERIES.contains(&vault.store, txn, &key.row())? {
        return Ok(false);
    }
    if join_wait_in_txn(vault, txn, key)?.erased() || settled.erased {
        let erased = Erased::of(settled.clone())?;
        DELIVERIES.put_erased(&vault.store, txn, &key.row(), erased)?;
    } else {
        DELIVERIES.put(&vault.store, txn, &key.row(), settled)?;
    }
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

/// Parks a canonical run's attempt under its C9 trap and binds the trap to
/// the run's parked wait, in one commit (OF-533): [`bind_wait_trap`] with the
/// park beside it, so no crash can leave a park that no delivery wakes. A
/// reply already delivered wakes the trap here; `true` when it woke.
pub fn park_and_bind_wait_trap(
    vault: &Vault,
    park: crate::dreamer_runner::ParkDreamerAttempt,
    key: &WaitKey,
    trap: &TrapRef,
    now_ms: u64,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        crate::DreamerRunnerStore::new(vault).park_attempt_in_txn(txn, park)?;
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
        rows: Option<&[EntityId]>,
        now_ms: u64,
    ) -> Result<usize> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                deliver_wait_listing_in_txn(vault, txn, wait_id, reply, rows, now_ms)
            }),
            Self::Session(binding) => binding.answered(|| {
                let fresh = WaitDelivery {
                    reply: reply_text(reply)?,
                    delivered_at_ms: now_ms,
                    source_rows: rows.map(<[EntityId]>::to_vec),
                    erased: false,
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
    /// it finds the waiter. A canonical park also takes, in that step, the
    /// result of a delegated TASK that already finished, the change of an
    /// ask voided since the run last looked (OF-533) and a world-privacy
    /// request's terminal state (FIX 4706), and answers `true` whenever a
    /// reply is delivered to `key`. A canonical run an erase of its actor
    /// took the replies of parks on nothing: a typed unavailable, never a
    /// park that waits again (FIX 5718).
    pub(crate) fn park_wait(&self, key: &WaitKey) -> Result<bool> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                if holder_erased_in_txn(vault, txn, key)? {
                    return Err(response_erased_error("a parked wait's reply"));
                }
                WAITERS.put(&vault.store, txn, &key.waiter(), &key.generation)?;
                crate::task_verb::deliver_task_result_in_txn(vault, txn, key.wait_id)?;
                crate::task_verb::deliver_ask_change_in_txn(vault, txn, key.wait_id)?;
                crate::task_verb::deliver_world_privacy_wait_for_in_txn(vault, txn, key.wait_id)?;
                if let Some(settled) =
                    SETTLED.get(&vault.store, txn, &(SETTLED_TAG, key.wait_id))?
                {
                    deliver_in_txn(vault, txn, key, &settled)?;
                }
                DELIVERIES.contains(&vault.store, txn, &key.row())
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

    /// The reply delivered to `key`'s wait, if one was. Once an erase of a
    /// canonical run's actor took its replies, a typed unavailable (FIX
    /// 5718): never the reply, never none.
    pub(crate) fn wait_delivery(&self, key: &WaitKey) -> Result<Option<WaitDelivery>> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                if holder_erased_in_txn(vault, &txn, key)? {
                    return Err(response_erased_error("a wait's delivered reply"));
                }
                match DELIVERIES.get(&vault.store, &txn, &key.row())? {
                    Some(delivery) if delivery.erased => {
                        Err(response_erased_error("a wait's delivered reply"))
                    }
                    delivery => Ok(delivery),
                }
            }
            Self::Session(binding) => {
                binding.answered(|| binding.session.side_table_get(&DELIVERIES, &key.row()))
            }
        }
    }

    /// Retires `key`'s waiter, delivery and trap rows once the resumed record
    /// committed; idempotent. It is cleanup, never a consumer: a code
    /// consent wait's consumption was committed with the record, in its own
    /// row, which this never touches. A room's rows stay until the room goes:
    /// its route writes and never deletes, and the resumed record already
    /// names the next generation, so nothing reads them again.
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
        self.deliver_listing(wait_id, reply, None, now_ms)
    }

    /// [`Self::deliver`], `reply` kept beside `rows`, the rows its settler
    /// listed it derived from (FIX 5455): the resumed run counts them among
    /// its own, and `connector.call_status` lists them. A canonical wait
    /// that is a connector call's, by its ref, holds its settled reply for
    /// the call's caller in the same commit (FIX 5718 part 3): that
    /// caller's erase reaches the copy `connector.call_status` reads.
    pub fn deliver_listing(
        &self,
        wait_id: EntityId,
        reply: &serde_json::Value,
        rows: Option<&[EntityId]>,
        now_ms: u64,
    ) -> Result<usize> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return self.storage.deliver_wait(wait_id, reply, rows, now_ms);
        };
        let Some(caller) = connector_call_caller(vault, wait_id)? else {
            return self.storage.deliver_wait(wait_id, reply, rows, now_ms);
        };
        vault.with_write_txn_grouped(|txn| {
            let delivered = deliver_wait_listing_in_txn(vault, txn, wait_id, reply, rows, now_ms)?;
            hold_settled_for_caller_in_txn(vault, txn, wait_id, caller)?;
            Ok(delivered)
        })
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

impl WaitDeliveries<'_> {
    /// The reply `wait_id` settled with, whether or not a run was ever
    /// parked on it: what a caller with no parked run reads of a wait a
    /// settler answered (FIX 2279). A room's settled rows ride its route; the
    /// connector settler answers canonical waits only, so a room reads none.
    /// A settled row an erase took is a typed unavailable (FIX 5718).
    pub fn settled(&self, wait_id: EntityId) -> Result<Option<WaitDelivery>> {
        match &self.storage {
            ExecutorStorage::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                match SETTLED.get(&vault.store, &txn, &(SETTLED_TAG, wait_id))? {
                    Some(settled) if settled.erased => {
                        Err(response_erased_error("a wait's settled reply"))
                    }
                    settled => Ok(settled),
                }
            }
            ExecutorStorage::Session(_) => Ok(None),
        }
    }
}

/// The actor whose connector call `wait_id` is, by the call's ref, when its
/// caller is an actor (FIX 5718 part 3): `connector.call_status` reads the
/// wait's settled reply for that caller. `None` for any other wait.
fn connector_call_caller(vault: &Vault, wait_id: EntityId) -> Result<Option<EntityId>> {
    let state = vault
        .connector_call_state(&wait_id)
        .map_err(|error| Error::InvalidConfig(format!("connector call state: {error}")))?;
    Ok(state.and_then(|state| EntityId::from_hex(&state.principal_ref).ok()))
}

/// Leads a run's seen-change row: `c` + wait + run → the highest option-void
/// generation of the ask the run has seen while it waits on it (OF-533). It
/// is one run's cursor: never a reply, and never the group's acknowledgement.
const OBSERVED_TAG: [u8; 1] = *b"c";

const OBSERVED_CHANGES: SideTable<([u8; 1], EntityId, EntityId), u64, Raw> =
    SideTable::new(&side_table::CODE_RUN_WAIT_INDEX);

/// The waits some canonical run is parked on with no reply delivered yet,
/// for a sweep that settles what is due on them.
pub(crate) fn canonical_wait_ids(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::BTreeSet<EntityId>> {
    let mut waits = std::collections::BTreeSet::new();
    for ((_, wait_id, run), generation) in WAITERS.scan_from(&vault.store, txn, &WAITER_TAG)? {
        let key = WaitKey {
            run,
            wait_id,
            generation,
        };
        if !DELIVERIES.contains(&vault.store, txn, &key.row())? {
            waits.insert(wait_id);
        }
    }
    Ok(waits)
}

/// Whether some canonical run is parked on `wait_id`.
pub(crate) fn has_parked_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
) -> Result<bool> {
    Ok(WAITERS
        .iter_from(&vault.store, txn, &waiter_prefix(wait_id))?
        .next()
        .transpose()?
        .is_some())
}

fn observed_change_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    wait_id: EntityId,
) -> Result<u64> {
    Ok(OBSERVED_CHANGES
        .get(&vault.store, txn, &(OBSERVED_TAG, wait_id, run))?
        .unwrap_or(0))
}

/// Raises `run`'s seen-change cursor on `wait_id` to `generation`; returns
/// the cursor as it stands after.
fn raise_observed_change_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: EntityId,
    wait_id: EntityId,
    generation: u64,
) -> Result<u64> {
    let held = observed_change_in(vault, txn, run, wait_id)?;
    if generation <= held {
        return Ok(held);
    }
    OBSERVED_CHANGES.put(
        &vault.store,
        txn,
        &(OBSERVED_TAG, wait_id, run),
        &generation,
    )?;
    Ok(generation)
}

/// The highest option-void generation `run` has seen on `wait_id`: its
/// cursor, raised to `durably_observed`, which only the run's own committed
/// bridge receipts may supply. A `tasks.wait` reads it before it chooses
/// between Changed and a park, so no change the run saw is delivered again.
pub(crate) fn observe_wait_change(
    vault: &Vault,
    run: EntityId,
    wait_id: EntityId,
    durably_observed: u64,
) -> Result<u64> {
    vault.with_write_txn_grouped(|txn| {
        raise_observed_change_in(vault, txn, run, wait_id, durably_observed)
    })
}

/// Delivers an ask's Changed status, at option-void `generation`, to every
/// run parked on `wait_id` that has not seen that generation, in the
/// caller's transaction, waking each one's bound trap. The reply goes to
/// each waiter's own key and never into the settled row, so a run that
/// parks later reads the wait afresh; a settled wait takes none, as its
/// final reply wins. A waiter already holding a reply keeps it, so repeated
/// voids coalesce. Returns how many runs this call delivered to.
pub(crate) fn deliver_changed_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    generation: u64,
    reply: &serde_json::Value,
    now_ms: u64,
) -> Result<usize> {
    if SETTLED.contains(&vault.store, txn, &(SETTLED_TAG, wait_id))? {
        return Ok(0);
    }
    let changed = WaitDelivery {
        reply: reply_text(reply)?,
        delivered_at_ms: now_ms,
        source_rows: None,
        erased: false,
    };
    let mut delivered = 0;
    for ((_, _, run), parked) in WAITERS.scan_from(&vault.store, txn, &waiter_prefix(wait_id))? {
        if observed_change_in(vault, txn, run, wait_id)? >= generation {
            continue;
        }
        let key = WaitKey {
            run,
            wait_id,
            generation: parked,
        };
        if deliver_in_txn(vault, txn, &key, &changed)? {
            delivered += 1;
        }
    }
    Ok(delivered)
}

impl ExecutorStorage<'_> {
    /// Commits the replay record of a run resumed from `key`'s reply, the
    /// result of its parked step `step_seq` at `resumed_path`. When that
    /// reply is an ask's Changed status, the run's seen-change cursor rises
    /// in the same transaction, so a failed append acknowledges nothing. A
    /// bound code consent wait's settlement is consumed in it (DOOR-079 1b):
    /// its reply must be delivered and verify, or the record does not
    /// commit. Retiring the wait's rows afterwards consumes nothing and
    /// deletes no consumption. Once an erase of the run's actor took its
    /// replies, nothing commits and nothing is consumed: a typed unavailable
    /// (FIX 5718). A room's record commits as any other append does.
    pub(crate) fn put_code_run_wait_resume_record(
        &self,
        record: &crate::code_run::CodeRunReplayRecord,
        expected: Option<crate::code_run::CodeRunReplayGeneration>,
        key: &WaitKey,
        step_seq: u64,
        resumed_path: &str,
    ) -> Result<crate::code_run::CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_with_heal_and(
                record,
                expected,
                None,
                |txn| {
                    if holder_erased_in_txn(vault, txn, key)? {
                        return Err(response_erased_error("a resumed wait's reply"));
                    }
                    let delivery = DELIVERIES.get(&vault.store, txn, &key.row())?;
                    if delivery.as_ref().is_some_and(|delivery| delivery.erased) {
                        return Err(response_erased_error("a resumed wait's reply"));
                    }
                    let resume = crate::code_run::CodeConsentResume {
                        record,
                        key: *key,
                        step_seq,
                        resumed_path,
                    };
                    let delivered = delivery.as_ref().map(|delivery| delivery.reply.as_str());
                    if crate::code_run::consume_code_consent_wait_in_txn(
                        vault, txn, &resume, delivered,
                    )? {
                        return Ok(());
                    }
                    let Some(delivery) = delivery else {
                        return Ok(());
                    };
                    if let Ok(crate::task_verb::TaskAskStatus::Changed { generation, .. }) =
                        serde_json::from_str::<crate::task_verb::TaskAskStatus>(&delivery.reply)
                    {
                        raise_observed_change_in(vault, txn, key.run, key.wait_id, generation)?;
                    }
                    Ok(())
                },
            ),
            Self::Session(_) => {
                self.put_code_run_replay_record_if_generation_with_heal(record, expected, None)
            }
        }
    }
}
