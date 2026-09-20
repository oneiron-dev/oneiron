//! Live NOTE replay for document-only changes on the existing entity observer.
use crate::Vault;
use crate::sync::{bridge::Materializer, types::WindowKey};
use loro::LoroDoc;

pub(super) fn materialize(
    doc: &LoroDoc,
    vault: &Vault,
    materializer: &Materializer,
    window: &str,
) -> bool {
    let Some(key) = WindowKey::try_new(window) else {
        return false;
    };
    if let Err(error) = crate::sync::window::forward_rematerialize(vault, doc, materializer, &key) {
        let marked = vault.with_write_txn(|txn| {
            let mut notes = Vec::new();
            crate::sync::loro_support::map_for_each_value_bytes(
                &doc.get_map("entities"),
                |key, raw| {
                    if raw
                        .and_then(crate::batch::EntityMetadataHeader::parse)
                        .is_some_and(|header| {
                            header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                        })
                        && let Ok(id) = crate::EntityId::from_hex(key)
                    {
                        notes.push(id);
                    }
                },
            );
            for note in notes {
                crate::sync::quarantine::set_replay_remat_marker_in_txn(vault, txn, window, &note)?;
            }
            Ok(())
        });
        tracing::error!(window, %error, marker_error = ?marked.err(), "NOTE window replay failed; retry remains pending");
        false
    } else {
        true
    }
}
