//! Machine-claim history this machine is owed (FIX 3820, FIX 4293).
//!
//! A receiver may hold a target's handoff packet without its ancestors: sync
//! windows partition by learned_at month, so packet N can land while N-1 sits
//! in a month this machine has not fetched. The target's history then does
//! not resolve. A row it gates is refused (`RemoteMachineHistoryPending`), the
//! own-receive exchange stays `Pending`, or an opened machine's thin touch
//! caches a row that needs it (FIX 4385), and each one writes an owed record
//! for the target in the transaction that saw it. Only those do: no other
//! pending dependency and no wrong chain owes a fetch.
//!
//! The connection's upkeep fetches each owed target's whole history from the
//! home ([`crate::sync::client::fetch_owed_machine_history`]), runs the
//! exchange again and drains the windows holding the target's rows
//! ([`release`]). The record clears once the history resolves under the
//! target's pin and the exchange waits on nothing. No pin is set here: the
//! exchange derives every pin itself (FIX 3821).
//!
//! A debt no fetch settles retires instead ([`retires`], FIX 4384). Each
//! place that takes a debt on asks first, so a home, which runs no upkeep,
//! keeps no such record either; the upkeep asks again each round.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::history_store::MachineHistoryKind;
use crate::claim::{ClaimSubject, PinExchangeOutcome};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::sync::manager::WindowManager;
use crate::sync::types::WindowKey;
use crate::vault::Vault;

/// One owed target's record, keyed by the target.
const OWED: SideTable<HexId, OwedHistory, Named> =
    SideTable::new(&side_table::SYNC_MACHINE_HISTORY_OWED);

/// What this machine owes one target's history.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::sync) struct OwedHistory {
    /// The windows the target's rows came in by: a row held there waits on
    /// the history, and the home is asked only when it reads their worlds.
    pub(in crate::sync) windows: BTreeSet<String>,
    /// Where the home's paging of the history stopped; the next round
    /// resumes there.
    pub(in crate::sync) cursor: Option<String>,
    /// What the last try found.
    pub(in crate::sync) status: OwedStatus,
    /// Whether a row refused for this history waits in one of the windows:
    /// the record then clears only once the upkeep has drained them.
    pub(in crate::sync) held: bool,
    /// Whether the home served its whole copy of the history since a row of
    /// it last landed here: the one proof that the history is another
    /// vault's (FIX 4901), as the home serves every control of this vault's.
    pub(in crate::sync) home_whole: bool,
}

/// What the last try at an owed history found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::sync) enum OwedStatus {
    /// Owed, and not settled by the last round.
    #[default]
    Owed,
    /// A row the target waits on landed here since: its held rows are tried
    /// again.
    Landed,
    /// The home's own copy of the history does not resolve whole yet.
    HomePending,
    /// The home refused the read, or may not read the target's world.
    HomeRefused,
}

thread_local! {
    /// The vaults an import on this thread landed rows in that an owed
    /// history waits on, by store path.
    static LANDED: RefCell<BTreeSet<PathBuf>> = const { RefCell::new(BTreeSet::new()) };
}

fn mark_landed(vault: &Vault) {
    LANDED.with(|landed| {
        landed
            .borrow_mut()
            .insert(vault.store.env.path().to_path_buf());
    });
}

/// Whether an import on this thread landed a row an owed history in `vault`
/// waits on since the last call: the upkeep then runs a round.
pub(in crate::sync) fn take_landed(vault: &Vault) -> bool {
    LANDED.with(|landed| landed.borrow_mut().remove(vault.store.env.path()))
}

/// The target a machine-history control names as its subject; `None` for any
/// other row.
fn control_target(blob: &[u8]) -> Option<EntityId> {
    let header = EntityMetadataHeader::parse(blob)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let body =
        crate::claim::decode_claim_body(blob.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()?;
    crate::claim::history_store::machine_history_kind(&body.predicate)?;
    match body.subject {
        ClaimSubject::Entity(target) => Some(target),
        ClaimSubject::Edge { .. } => None,
    }
}

/// Whether `blob` is a machine-history control of `target`.
pub(in crate::sync) fn is_history_of(blob: &[u8], target: EntityId) -> bool {
    control_target(blob) == Some(target)
}

/// Owes `target` a fetch for a row of `window_key`, `held` there when a
/// refusal holds it.
fn owe_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    window_key: &str,
    status: Option<OwedStatus>,
    held: bool,
) -> Result<()> {
    let key = HexId(target);
    let mut record = OWED.get(&vault.store, wtxn, &key)?.unwrap_or_default();
    record.windows.insert(window_key.to_owned());
    record.held |= held;
    // A landing may be what the home's copy lacked: it is read whole again.
    record.home_whole = false;
    if let Some(status) = status {
        record.status = status;
    }
    OWED.put(&vault.store, wtxn, &key, &record)
}

/// Whether `target`'s history resolves under its pin and the exchange's
/// `outcome` waits on nothing.
fn resolves(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    outcome: PinExchangeOutcome,
) -> bool {
    !matches!(outcome, PinExchangeOutcome::Pending(_))
        && crate::claim::history_advance::machine_history_rows_carried(&vault.store, txn, target)
            .is_ok()
}

/// The vault a signed control of `target` in `blob` names: a handoff
/// packet's or a birth's. `None` for any other row, and for a transition,
/// which names none.
fn named_vault(blob: &[u8], target: EntityId) -> Option<[u8; 32]> {
    let header = EntityMetadataHeader::parse(blob)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let body =
        crate::claim::decode_claim_body(blob.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()?;
    let Value::Binary(bytes) = &body.value else {
        return None;
    };
    match crate::claim::history_store::machine_history_kind(&body.predicate)? {
        MachineHistoryKind::Handoff => {
            let packet = crate::claim::ClaimHistoryHandoff::decode(bytes).ok()?;
            (matches!(packet.births.as_slice(), [birth] if birth.id == target)
                && crate::claim::history_projection::verify_handoff_signature(&packet))
            .then_some(packet.vault_id)
        }
        MachineHistoryKind::Birth => {
            let birth = crate::claim::SignedClaimBirth::decode(bytes).ok()?;
            (birth.target == target).then_some(birth.vault_id)
        }
        MachineHistoryKind::Transition => None,
    }
}

/// Whether `target`'s history is proven another vault's: the target is not
/// pinned here, the home's whole copy of its history landed since its last
/// row did, this vault's id is folded, and each signed control of `target`
/// in view that names a vault, `blob` (the row in hand) and every resident
/// one, names another, at least one of them. The exchange adopts only this
/// vault's packets, so no fetch settles such a history.
///
/// A control's vault id is its own signer's word, and any tier that may
/// write a window can land one, so the controls alone prove nothing: an
/// unpinned target of this vault whose own controls have not landed here
/// would retire on one naming another vault (FIX 4901). The home serves
/// every control of this vault's, so its whole copy holding none is the
/// proof; until it is fetched the debt stays owed.
fn foreign_history(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    blob: &[u8],
) -> Result<bool> {
    let home_whole = OWED
        .get(&vault.store, txn, &HexId(target))?
        .is_some_and(|record| record.home_whole);
    let pinned = vault
        .store
        .vault_meta
        .get(txn, &crate::claim::history_projection::pin_key(target))?
        .is_some();
    if !home_whole || pinned {
        return Ok(false);
    }
    let mut named: Vec<[u8; 32]> = named_vault(blob, target).into_iter().collect();
    for id in
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, txn, target)?
    {
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? {
            named.extend(named_vault(&raw, target));
        }
    }
    if named.is_empty() {
        return Ok(false);
    }
    let Some(own) = vault.authority_fold_readonly_in_txn(txn)?.vault_id else {
        return Ok(false);
    };
    Ok(named.iter().all(|vault_id| *vault_id != own))
}

/// Whether a debt for `target` retires rather than stays owed (FIX 4384,
/// CALLS "FIX 4384 machine-history debt retirement"), given the exchange's
/// `outcome` and `blob`, the row in hand: the history does not resolve and
/// the exchange ended `Conflict` (a signed fork, or a pin off the tip's
/// chain) or `Refused` (a chain that does not verify), or the history is
/// proven another vault's ([`foreign_history`]). No fetch settles either:
/// the home serves the same signed rows, and the exchange adopts only this
/// vault's. An incomplete history of this vault stays owed, and so does one
/// the home refused or holds incomplete itself. No time retires a debt.
fn retires(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    outcome: PinExchangeOutcome,
    blob: &[u8],
) -> Result<bool> {
    match outcome {
        PinExchangeOutcome::Conflict(_) | PinExchangeOutcome::Refused(_) => {
            Ok(!resolves(vault, txn, target, outcome))
        }
        PinExchangeOutcome::Pending(_) => foreign_history(vault, txn, target, blob),
        PinExchangeOutcome::NotMachineHistory
        | PinExchangeOutcome::Unchanged(_)
        | PinExchangeOutcome::Adopted(_) => Ok(false),
    }
}

/// Takes on a debt for `target` from `blob`, a row of `window_key`, `held`
/// there when a refusal holds it. The exchange runs first: a debt that
/// retires is dropped and not taken on ([`retires`]), and a row no refusal
/// holds owes nothing once its history resolves.
fn admit_debt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    window_key: &str,
    blob: &[u8],
    held: bool,
) -> Result<()> {
    let outcome = vault.advance_own_machine_history_in_txn(wtxn, target)?;
    if retires(vault, wtxn, target, outcome, blob)? {
        OWED.delete(&vault.store, wtxn, &HexId(target))?;
        return Ok(());
    }
    if !held && resolves(vault, wtxn, target, outcome) {
        return Ok(());
    }
    owe_in_txn(vault, wtxn, target, window_key, None, held)
}

/// A row of `window_key` refused because its machine history is not here
/// (`RemoteMachineHistoryPending`) owes its target a fetch, in the parent
/// transaction that keeps its quarantine, unless the debt retires (FIX
/// 4384). A refused control's target is its subject; any other refused row
/// is the target itself.
pub(in crate::sync) fn owe_refused_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: Option<EntityId>,
    err: &Error,
    blob: &[u8],
) -> Result<()> {
    let Some(id) = id.filter(|_| err.kind() == ErrorKind::RemoteMachineHistoryPending) else {
        return Ok(());
    };
    let target = control_target(blob).unwrap_or(id);
    admit_debt_in_txn(vault, wtxn, target, window_key, blob, true)
}

/// Whether `blob`, the row at `id`, is a CLAIM with a machine history to
/// resolve: its body needs one, or the target index names it.
fn needs_history(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId, blob: &[u8]) -> Result<bool> {
    let Some(body) = EntityMetadataHeader::parse(blob)
        .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        .and_then(|_| blob.get(ENTITY_METADATA_HEADER_LEN..))
        .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
    else {
        return Ok(false);
    };
    Ok(
        crate::authority::machine_claim_needs_history(&vault.store, txn, &body)?
            || crate::claim::history_store::machine_history_indexed(&vault.store, txn, id)?,
    )
}

/// A row an opened machine's thin touch caches read-only for `window_key`
/// owes its machine history a fetch when this vault lacks it (FIX 4385), in
/// the transaction that caches it: nothing is refused in the thin cache, so
/// no refusal owes it. The target is a control's subject, or the row at `id`
/// itself when it needs a history. The existing home fetch lands only the
/// history; the cached row stays read-only and no promotion is forged.
pub(in crate::sync) fn owe_touched_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: EntityId,
    blob: &[u8],
) -> Result<()> {
    let target = match control_target(blob) {
        Some(target) => target,
        None if needs_history(vault, wtxn, id, blob)? => id,
        None => return Ok(()),
    };
    admit_debt_in_txn(vault, wtxn, target, window_key, blob, false)
}

/// What the history owed here makes of a row `window_key` landed, in the
/// savepoint that landed it, given the exchange's `outcome` for it. An
/// exchange still `Pending` owes its target a fetch (FIX 4293). An owed
/// target no held row waits on clears once its history resolves, and a debt
/// that retires is dropped or never taken on (FIX 4384). Any other row of an
/// owed target, and any authority row while a target is owed, marks it
/// landed and wakes the upkeep, which runs the exchange again and drains
/// what it holds.
pub(in crate::sync) fn note_landed_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    outcome: PinExchangeOutcome,
    blob: &[u8],
) -> Result<()> {
    let Some(target) = outcome.target() else {
        if crate::sync::ingest::is_authority_row(blob)
            && OWED.iter_from(&vault.store, wtxn, &[])?.next().is_some()
        {
            mark_landed(vault);
        }
        return Ok(());
    };
    let key = HexId(target);
    let record = OWED.get(&vault.store, wtxn, &key)?;
    if (record.is_some() || matches!(outcome, PinExchangeOutcome::Pending(_)))
        && retires(vault, wtxn, target, outcome, blob)?
    {
        OWED.delete(&vault.store, wtxn, &key)?;
        return Ok(());
    }
    let status = match record {
        Some(record) if !record.held && resolves(vault, wtxn, target, outcome) => {
            OWED.delete(&vault.store, wtxn, &key)?;
            return Ok(());
        }
        Some(_) => {
            mark_landed(vault);
            OwedStatus::Landed
        }
        None if matches!(outcome, PinExchangeOutcome::Pending(_)) => OwedStatus::Owed,
        None => return Ok(()),
    };
    owe_in_txn(vault, wtxn, target, window_key, Some(status), false)
}

/// Every owed target and its record.
pub(in crate::sync) fn owed_targets(vault: &Vault) -> Result<Vec<(EntityId, OwedHistory)>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(OWED
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(HexId(target), record)| (target, record))
        .collect())
}

/// Changes `target`'s record, if it is still owed.
fn update(vault: &Vault, target: EntityId, change: impl FnOnce(&mut OwedHistory)) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let key = HexId(target);
        if let Some(mut record) = OWED.get(&vault.store, txn, &key)? {
            change(&mut record);
            OWED.put(&vault.store, txn, &key, &record)?;
        }
        Ok(())
    })
}

/// Keeps `cursor`, where the home's paging of `target`'s history stopped.
pub(in crate::sync) fn keep_cursor(vault: &Vault, target: EntityId, cursor: &str) -> Result<()> {
    update(vault, target, |record| {
        record.cursor = Some(cursor.to_owned());
    })
}

/// Records that the home served `target`'s whole history and each row of it
/// this machine lacked landed (FIX 4901).
pub(in crate::sync) fn note_home_whole(vault: &Vault, target: EntityId) -> Result<()> {
    update(vault, target, |record| record.home_whole = true)
}

/// Records what the home answered for `target`. A landing marked since
/// stands.
pub(in crate::sync) fn note_home(
    vault: &Vault,
    target: EntityId,
    status: OwedStatus,
) -> Result<()> {
    update(vault, target, |record| {
        if record.status != OwedStatus::Landed {
            record.status = status;
        }
    })
}

/// Runs the exchange again for each of `targets` and, where rows it waits on
/// landed (`true` beside it when a round landed some, or a landing an import
/// marked) or its history resolves now, drains the windows its refused rows
/// wait in, each window once. A record clears once its target's history
/// resolves under its pin and the exchange waits on nothing, or once its
/// debt retires ([`retires`]); otherwise it stays, with its cursor. Returns
/// the targets still owed.
pub(in crate::sync) fn release(
    manager: &WindowManager,
    targets: &[(EntityId, bool)],
) -> Result<Vec<EntityId>> {
    let vault = manager.vault();
    let mut windows = BTreeSet::new();
    for &(target, landed) in targets {
        if let Some((held, retry)) = advance(vault, target)?
            && (landed || retry)
        {
            windows.extend(held);
        }
    }
    for window in windows.iter().filter_map(WindowKey::try_new) {
        drain_held(manager, &window)?;
    }
    let mut owed = Vec::new();
    for &(target, _) in targets {
        if !settle(vault, target, &windows)? {
            owed.push(target);
        }
    }
    Ok(owed)
}

/// The exchange for an owed `target`, first: a pin it adopts is what a held
/// row needs to land. Returns the windows a refused row of it waits in and
/// whether they are tried again, or `None` once the target is not owed or
/// its debt retires, before the home is asked.
fn advance(vault: &Vault, target: EntityId) -> Result<Option<(BTreeSet<String>, bool)>> {
    vault.with_write_txn_grouped(|txn| {
        let key = HexId(target);
        let Some(mut record) = OWED.get(&vault.store, txn, &key)? else {
            return Ok(None);
        };
        let outcome = vault.advance_own_machine_history_in_txn(txn, target)?;
        if retires(vault, txn, target, outcome, &[])? {
            OWED.delete(&vault.store, txn, &key)?;
            return Ok(None);
        }
        let marked = record.status == OwedStatus::Landed;
        if marked {
            record.status = OwedStatus::Owed;
            OWED.put(&vault.store, txn, &key, &record)?;
        }
        // A held row is tried again before its record can clear.
        let retry = marked || resolves(vault, txn, target, outcome);
        let held = if record.held {
            record.windows
        } else {
            BTreeSet::new()
        };
        Ok(Some((held, retry)))
    })
}

/// Judges an owed `target` after the drain, which may have landed history
/// too: the exchange runs again, and the record clears once the history
/// resolves and the exchange waits on nothing, but a held row's windows must
/// have been `drained` first; a record that resolves before they were waits
/// for the next round, marked. A debt that retires is dropped. `true` when
/// it is cleared.
fn settle(vault: &Vault, target: EntityId, drained: &BTreeSet<String>) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let key = HexId(target);
        let Some(mut record) = OWED.get(&vault.store, txn, &key)? else {
            return Ok(true);
        };
        let outcome = vault.advance_own_machine_history_in_txn(txn, target)?;
        if retires(vault, txn, target, outcome, &[])? {
            OWED.delete(&vault.store, txn, &key)?;
            return Ok(true);
        }
        if !resolves(vault, txn, target, outcome) {
            return Ok(false);
        }
        if record.held && !record.windows.is_subset(drained) {
            record.status = OwedStatus::Landed;
            OWED.put(&vault.store, txn, &key, &record)?;
            return Ok(false);
        }
        OWED.delete(&vault.store, txn, &key)?;
        Ok(true)
    })
}

/// Tries `window`'s held rows again while each pass lands some: a row one
/// pass lands may be what another waits on. No count bounds the passes; each
/// one that goes on has cleared a marker.
fn drain_held(manager: &WindowManager, window: &WindowKey) -> Result<()> {
    let held = || {
        crate::sync::quarantine::pending_remat_entities(manager.vault(), window.as_str())
            .map(|entities| entities.len())
    };
    let mut left = held()?;
    while left > 0 {
        manager.retry_held_rows(window)?;
        let now = held()?;
        if now >= left {
            break;
        }
        left = now;
    }
    Ok(())
}
