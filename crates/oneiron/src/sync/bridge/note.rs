//! Live NOTE replay for document-only changes, retaining the existing entity observer.
use crate::Vault;
use crate::sync::{bridge::Materializer, types::WindowKey};
use loro::LoroDoc;
use std::sync::Arc;

pub(super) fn subscribe(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    window: &str,
    entity_subscription: loro::Subscription,
) -> loro::Subscription {
    let current = doc.clone();
    let vault = Arc::clone(vault);
    let materializer = Arc::clone(materializer);
    let window = window.to_owned();
    doc.subscribe_root(Arc::new(move |event| {
        // Holding this handle preserves the legacy entity callback and its tee.
        let _keep_entity_observer = &entity_subscription;
        if event.origin == crate::sync::bridge::BRIDGE_ORIGIN
            || event.origin == crate::sync::bridge::DELETION_TOMBSTONE_ORIGIN
            || !crate::note::sync::is_native(&current)
        { return; }
        let Some(key) = WindowKey::try_new(&window) else { return; };
        if let Err(error) = crate::sync::window::forward_rematerialize(&vault, &current, &materializer, &key) {
            let marked = vault.with_write_txn(|txn| {
                let mut notes = Vec::new();
                crate::sync::loro_support::map_for_each_value_bytes(&current.get_map("entities"), |key, raw| {
                    if raw.and_then(crate::batch::EntityMetadataHeader::parse).is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_NOTE)
                        && let Ok(id) = crate::EntityId::from_hex(key) {
                        notes.push(id);
                    }
                });
                for note in notes {
                    crate::sync::quarantine::set_replay_remat_marker_in_txn(&vault, txn, &window, &note)?;
                }
                Ok(())
            });
            tracing::error!(window, %error, marker_error = ?marked.err(), "NOTE window replay failed; retry remains pending");
        }
    }))
}
