//! Machine-claim history this machine is owed (FIX 3820, FIX 4293).
//!
//! A receiver may hold a target's handoff packet without its ancestors: sync
//! windows partition by learned_at month, so packet N can land while N-1 sits
//! in a month this machine has not fetched. The target's history then does
//! not resolve. Either a row it gates is refused (`RemoteMachineHistoryPending`)
//! or the own-receive exchange stays `Pending`, and either one writes an owed
//! record for the target in the transaction that saw it. Only those two do:
//! no other pending dependency and no wrong chain owes a fetch.
//!
//! The connection's upkeep fetches each owed target's whole history from the
//! home ([`crate::sync::client::fetch_owed_machine_history`]), runs the
//! exchange again and drains the windows holding the target's rows
//! ([`release`]). The record clears once the history resolves under the
//! target's pin and the exchange waits on nothing. No pin is set here: the
//! exchange derives every pin itself (FIX 3821).

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
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

/// Owes `target` a fetch for a row of `window_key` and wakes the upkeep.
fn owe_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    window_key: &str,
    status: Option<OwedStatus>,
) -> Result<()> {
    let key = HexId(target);
    let mut record = OWED.get(&vault.store, wtxn, &key)?.unwrap_or_default();
    record.windows.insert(window_key.to_owned());
    if let Some(status) = status {
        record.status = status;
    }
    OWED.put(&vault.store, wtxn, &key, &record)?;
    mark_landed(vault);
    Ok(())
}

/// A row of `window_key` refused because its machine history is not here
/// (`RemoteMachineHistoryPending`) owes its target a fetch, in the parent
/// transaction that keeps its quarantine. A refused control's target is its
/// subject; any other refused row is the target itself.
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
    owe_in_txn(
        vault,
        wtxn,
        control_target(blob).unwrap_or(id),
        window_key,
        None,
    )
}

/// What the history owed here makes of a row `window_key` landed, in the
/// savepoint that landed it, given the exchange's `outcome` for it. An
/// exchange still `Pending` owes its target a fetch (FIX 4293). Any row of an
/// owed target, and any authority row while a target is owed, marks the
/// target landed and wakes the upkeep, which runs the exchange again.
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
    let status = if OWED.contains(&vault.store, wtxn, &HexId(target))? {
        OwedStatus::Landed
    } else if matches!(outcome, PinExchangeOutcome::Pending(_)) {
        OwedStatus::Owed
    } else {
        return Ok(());
    };
    owe_in_txn(vault, wtxn, target, window_key, Some(status))
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
/// landed (`true` beside it when a round landed some, a landing an import
/// marked, or a pin the exchange just adopted), drains the windows holding
/// its rows, each window once. A record clears once its target's history
/// resolves under its pin and the exchange waits on nothing; otherwise it
/// stays, with its cursor. Returns the targets still owed.
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
        if !settle(vault, target)? {
            owed.push(target);
        }
    }
    Ok(owed)
}

/// The exchange for an owed `target`, first: a pin it adopts is what a held
/// row needs to land. Returns the record's windows and whether they are
/// tried again, or `None` once the target is not owed.
fn advance(vault: &Vault, target: EntityId) -> Result<Option<(BTreeSet<String>, bool)>> {
    vault.with_write_txn_grouped(|txn| {
        let key = HexId(target);
        let Some(mut record) = OWED.get(&vault.store, txn, &key)? else {
            return Ok(None);
        };
        let outcome = vault.advance_own_machine_history_in_txn(txn, target)?;
        let marked = record.status == OwedStatus::Landed;
        if marked {
            record.status = OwedStatus::Owed;
            OWED.put(&vault.store, txn, &key, &record)?;
        }
        let adopted = matches!(outcome, PinExchangeOutcome::Adopted(_));
        Ok(Some((record.windows, marked || adopted)))
    })
}

/// Judges an owed `target` after the drain, which may have landed history
/// too: the exchange runs again, and the record clears once the history
/// resolves and the exchange waits on nothing. `true` when it is cleared.
fn settle(vault: &Vault, target: EntityId) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let key = HexId(target);
        if !OWED.contains(&vault.store, txn, &key)? {
            return Ok(true);
        }
        let outcome = vault.advance_own_machine_history_in_txn(txn, target)?;
        let resolved = !matches!(outcome, PinExchangeOutcome::Pending(_))
            && crate::claim::history_projection::machine_history_rows(&vault.store, txn, target)
                .is_ok();
        if resolved {
            OWED.delete(&vault.store, txn, &key)?;
        }
        Ok(resolved)
    })
}

/// Tries `window`'s held rows again while each pass lands some: a row one
/// pass lands may be what another waits on. No count bounds the passes; each
/// one that goes on has cleared a marker.
fn drain_held(manager: &WindowManager, window: &WindowKey) -> Result<()> {
    let held = || {
        crate::sync::quarantine::pending_remat_entities(manager.vault(), window.as_str())
            .map(Vec::len)
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
