//! The machine-claim history this machine is owed, from the home (FIX 3820).
//! A machine that holds a handoff packet without its ancestors, or has
//! thin-touched a machine claim whose history it lacks (FIX 4385), asks the
//! home for the target's whole history by target
//! (`residence.machine-history`), a page at a time on one connection per
//! round, and resumes where the last round's paging stopped. Each row lands
//! through the explicit replay door under this machine's own tier, never
//! into the thin read caches and never by a forged promotion, and that door
//! checks it as window ingest would. Only a machine-history control of the
//! asked target is taken. Nothing the home asserts is trusted beyond the
//! signed bytes, and no pin comes from them: the own-receive exchange derives
//! its pin itself (FIX 3821). The round then runs the exchange again and
//! drains the windows holding the target's rows
//! ([`crate::sync::machine_history`]).
//!
//! A home that may not read a target's world is not asked for it (FIX 922
//! item 11).

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::super::base::home_reads_window;
use super::{ResidenceRpc, refused, residence_budgets};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::MachineHistoryFreshnessResponse;
use crate::sync::client::{ImportTier, SyncClientConfig};
use crate::sync::machine_history::{
    OwedHistory, OwedStatus, is_history_of, keep_cursor, note_home, note_home_whole, owed_targets,
    release,
};
use crate::sync::manager::WindowManager;
use crate::sync::replay::{ReplicatedEntity, replay_entity};
use crate::sync::residence::MACHINE_HISTORY_PAGE_ROWS;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::{EntityId, TimeRange, Vault};

/// One page of a target's history.
#[derive(Deserialize)]
struct MachineHistoryReply {
    target: String,
    /// The home's own copy of the history does not resolve whole.
    pending: bool,
    rows: Vec<MachineHistoryRow>,
    /// Where the next page starts; absent when pending.
    #[serde(default)]
    cursor: Option<String>,
    /// Whether rows are left after this page.
    #[serde(default)]
    more: bool,
}

/// One row of the history: its id in hex and its raw envelope in base64.
#[derive(Deserialize)]
struct MachineHistoryRow {
    id: String,
    raw: String,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// One round over every target this machine owes a history (FIX 3820). It
/// first runs the exchange again for each, which settles a target whose rows
/// landed meanwhile and retires a debt no fetch settles (FIX 4384); then it
/// fetches what is still owed from the home, on one connection, and releases
/// the targets it fetched, those it landed rows for with their held rows
/// tried again. Own residence only: a federation peer does not answer it.
/// Returns how many rows landed.
pub(crate) async fn fetch_owed_machine_history(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    if config.federation_peer.is_some() {
        return Ok(0);
    }
    let vault = manager.vault();
    let owed = owed_targets(vault).map_err(storage)?;
    if owed.is_empty() {
        return Ok(0);
    }
    let local = owed.iter().map(|(target, _)| (*target, false)).collect();
    let still: BTreeSet<EntityId> = release_targets(manager, local).await?.into_iter().collect();
    let asked: Vec<_> = owed
        .into_iter()
        .filter(|(target, _)| still.contains(target))
        .collect();
    if asked.is_empty() {
        return Ok(0);
    }
    let selector = config.residence_selector.as_ref().ok_or_else(refused)?;
    let selector = base64::engine::general_purpose::STANDARD
        .encode(encode_sync_selector(selector).map_err(|_| refused())?);
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::Storage("home node offline".into()));
    };
    let mut landed = 0;
    let mut fetched = Vec::new();
    let mut failed = None;
    for (target, record) in asked {
        if !home_reads(vault, &rpc, &record) {
            note_home(vault, target, OwedStatus::HomeRefused).map_err(storage)?;
            continue;
        }
        match fetch_target(vault, &mut rpc, &selector, target, record.cursor).await {
            Ok(rows) => {
                landed += rows;
                fetched.push((target, rows > 0));
            }
            // What landed before the round broke is released all the same.
            Err(error) => {
                fetched.push((target, true));
                failed = Some(error);
                break;
            }
        }
    }
    let owed: BTreeSet<EntityId> = release_targets(manager, fetched.clone())
        .await?
        .into_iter()
        .collect();
    // FIX 4294: each history this round settled asks the home to prove its
    // pin here the latest, unless no row landed for it and its pin is
    // already proven the latest (L03 07:0x): a quiet round costs no call.
    if failed.is_none() {
        for (target, moved) in fetched.iter().filter(|(target, _)| !owed.contains(target)) {
            let proven = matches!(
                vault.machine_history_pin_freshness(*target),
                Ok(crate::claim::MachineHistoryPinFreshness::Latest { .. })
            );
            if *moved || !proven {
                prove_freshness(vault, &mut rpc, &selector, *target).await;
            }
        }
    }
    failed.map_or(Ok(landed), Err)
}

/// Asks the home to prove `target`'s pin here the latest (FIX 4294): this
/// machine's fresh challenge out (`residence.machine-history.freshness`), the
/// home's signed answer in. A home that cannot answer, or an answer that
/// does not verify, leaves the pin's freshness unproven; the round goes on.
async fn prove_freshness(vault: &Vault, rpc: &mut ResidenceRpc, selector: &str, target: EntityId) {
    let Ok(Some(challenge)) = vault.issue_machine_history_freshness_challenge(target) else {
        return;
    };
    let params = json!({
        "selector": selector,
        "challenge": base64::engine::general_purpose::STANDARD.encode(challenge.encode()),
    });
    let Ok(Ok(reply)) = rpc
        .call("residence.machine-history.freshness", params)
        .await
    else {
        return;
    };
    let Some(response) = reply
        .get("response")
        .and_then(serde_json::Value::as_str)
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .and_then(|bytes| MachineHistoryFreshnessResponse::decode(&bytes))
    else {
        return;
    };
    if let Err(error) = vault.accept_machine_history_freshness(&response) {
        tracing::debug!(%error, target = %target.to_hex(), "machine history freshness not kept");
    }
}

/// [`release`] off the async worker: its drain rematerializes whole windows.
async fn release_targets(
    manager: &Arc<WindowManager>,
    targets: Vec<(EntityId, bool)>,
) -> Result<Vec<EntityId>, TransportError> {
    let manager = Arc::clone(manager);
    tokio::task::spawn_blocking(move || release(&manager, &targets))
        .await
        .map_err(|error| TransportError::Storage(error.to_string()))?
        .map_err(storage)
}

/// Whether the home may read the world of every window `record` names, so
/// it may be asked for the target. A record that names none is not asked
/// for.
fn home_reads(vault: &Vault, rpc: &ResidenceRpc, record: &OwedHistory) -> bool {
    !record.windows.is_empty()
        && record.windows.iter().all(|window| {
            WindowKey::try_new(window.as_str())
                .is_some_and(|window| home_reads_window(vault, rpc.home, &window))
        })
}

/// Pages `target`'s history from the home from `cursor` on and lands each
/// row this machine lacks. Each page's cursor is kept, so the next round
/// resumes there; once the home's tip moves, it starts over. Returns how many
/// rows landed.
async fn fetch_target(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    selector: &str,
    target: EntityId,
    mut cursor: Option<String>,
) -> Result<usize, TransportError> {
    let mut landed = 0;
    loop {
        let params = json!({ "selector": selector, "target": target.to_hex(), "cursor": cursor });
        let Ok(reply) = rpc.call("residence.machine-history", params).await? else {
            // The home does not serve this target to this machine.
            note_home(vault, target, OwedStatus::HomeRefused).map_err(storage)?;
            return Ok(landed);
        };
        let reply: MachineHistoryReply = serde_json::from_value(reply).map_err(|_| refused())?;
        if reply.target != target.to_hex() || reply.rows.len() > MACHINE_HISTORY_PAGE_ROWS {
            return Err(refused());
        }
        if reply.pending {
            note_home(vault, target, OwedStatus::HomePending).map_err(storage)?;
            return Ok(landed);
        }
        for row in &reply.rows {
            if land_row(vault, target, row)? {
                landed += 1;
            }
        }
        let next = reply.cursor.ok_or_else(refused)?;
        keep_cursor(vault, target, &next).map_err(storage)?;
        if !reply.more {
            note_home_whole(vault, target).map_err(storage)?;
            return Ok(landed);
        }
        // A page that moves no further is refused, so no home holds a round
        // here.
        if reply.rows.is_empty() || cursor.as_deref() == Some(next.as_str()) {
            return Err(refused());
        }
        cursor = Some(next);
    }
}

/// Whether this machine holds a row at `id`.
fn holds(vault: &Vault, id: &EntityId) -> crate::Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    crate::ports::EntityStoreRead::port_entity_present(&vault.store, &rtxn, id)
}

/// Lands one row of `target`'s history unless this machine holds it. Only a
/// machine-history control of `target` is taken; any other row refuses the
/// page. The replay door judges it under this machine's own tier, and a row
/// it refuses is passed over: the history stays owed. `true` when it landed.
fn land_row(
    vault: &Vault,
    target: EntityId,
    row: &MachineHistoryRow,
) -> Result<bool, TransportError> {
    let id = EntityId::from_hex(&row.id).map_err(|_| refused())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&row.raw)
        .map_err(|_| refused())?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(refused)?;
    if !is_history_of(&raw, target) {
        return Err(refused());
    }
    if holds(vault, &id).map_err(storage)? {
        return Ok(false);
    }
    let replayed = replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: header.entity_type,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            body: &raw[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::OwnDevice,
    );
    match replayed {
        Ok(()) => Ok(true),
        Err(error) => {
            tracing::debug!(%error, row = %id.to_hex(), "machine history row refused");
            Ok(false)
        }
    }
}
