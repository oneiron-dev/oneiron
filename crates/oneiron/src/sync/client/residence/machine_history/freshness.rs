//! Freshness for local pins whose history is no longer owed.

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine;

use super::{ResidenceRpc, home_reads_window, prove_freshness, residence_budgets};
use crate::authority::PeerMachine;
use crate::batch::EntityMetadataHeader;
use crate::claim::MachineHistoryPinFreshness;
use crate::ports::EntityStoreRead;
use crate::sync::client::SyncClientConfig;
use crate::sync::machine_history::is_history_of;
use crate::sync::manager::WindowManager;
use crate::sync::selector::encode_sync_selector;
use crate::{EntityId, Vault};

/// Uses the existing history round and its quiet-Latest rule. Optional work
/// never changes the empty history round's result or its error behavior.
pub(super) async fn refresh_unproven_pins(manager: &Arc<WindowManager>, config: &SyncClientConfig) {
    let vault = manager.vault();
    let Ok(mut targets) = vault.machine_history_pinned_targets() else {
        return;
    };
    targets.retain(
        |target| match vault.machine_history_pin_freshness(*target) {
            Ok(MachineHistoryPinFreshness::Latest { .. }) | Err(_) => false,
            Ok(_) => true,
        },
    );
    if targets.is_empty() {
        return;
    }
    let Some(selector) = config.residence_selector.as_ref() else {
        return;
    };
    let Ok(encoded) = encode_sync_selector(selector) else {
        return;
    };
    let selector = base64::engine::general_purpose::STANDARD.encode(encoded);
    let Ok(budgets) = residence_budgets(vault) else {
        return;
    };
    let Ok(Some(mut rpc)) = ResidenceRpc::connect(vault, config, budgets).await else {
        return;
    };
    for target in targets {
        if matches!(home_reads_target(vault, rpc.home, target), Ok(true)) {
            prove_freshness(vault, &mut rpc, &selector, target).await;
        }
    }
}

/// Local rows supply window addresses only. The same home authorization as
/// owed-history fetches judges every window before any target id is sent.
fn home_reads_target(vault: &Vault, home: PeerMachine, target: EntityId) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let mut ids =
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, target)?;
    ids.push(target);
    let mut windows = HashSet::new();
    for id in ids {
        let window = vault.store.port_entity_with_raw(&txn, &id, |raw| {
            if !EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
                || (id != target && !is_history_of(raw, target))
            {
                return Ok(None);
            }
            // The general residence mapper quarantines malformed world
            // metadata in base. An optional request must not use that fallback.
            crate::sync::types::entity_world(raw)?;
            crate::sync::residence::residence_window_for_blob(raw).map(Some)
        })?;
        let Some(Some(window)) = window else {
            return Ok(false);
        };
        windows.insert(window);
    }
    drop(txn);
    Ok(!windows.is_empty()
        && windows
            .iter()
            .all(|window| home_reads_window(vault, home, window)))
}
