//! Positive MESSAGE-linked secret marks, admitted in one room read snapshot.

use std::collections::{BTreeMap, BTreeSet};

use super::{RESULT_SECRETS, not_in_room, visible};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::MessageResultAttachment;
use crate::off_record::OffRecordSession;
use crate::ports::TombstoneStoreRead;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::session_overlay::{JournalRole, OverlayKeyspace, OverlaySnapshot};
use crate::store::SessionStoreView;
use crate::store::result_manifest::ResultOccurrence;

impl OffRecordSession<'_> {
    /// Returns exact mark keys and reasons, never a clearance or a body.
    /// The journal supplies candidates; the snapshot's current live rows
    /// supply the reference, so an old journal put cannot revive a result.
    pub(crate) fn code_run_room_secret_marks_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        room: EntityId,
    ) -> Result<Vec<(String, String)>> {
        self.read_composed_in_vault(|vault, view, txn| {
            let actor = owner.revalidate_in_txn(vault, txn)?;
            if self.room()? != Some(room) || self.participant() != Some(actor) {
                return Err(not_in_room(&self.session_ref, actor));
            }
            let windows = self.sight_in_txn(txn, room, actor, None)?;
            let snapshot = view
                .vault_meta
                .overlay_snapshot()
                .ok_or(Error::InvariantViolation(
                    "room read has no overlay snapshot",
                ))?;
            // Promotion publishes this membership before retiring TURN rows.
            let saved: BTreeSet<[u8; 16]> =
                super::super::registry::session_entry_state(&self.entry)?
                    .record
                    .promoted_turns
                    .iter()
                    .copied()
                    .collect();
            let mut turns = BTreeSet::new();
            let mut messages = BTreeMap::new();
            for entry in snapshot.journal_entries() {
                let BatchOp::Put {
                    id, entity_type, ..
                } = &entry.op
                else {
                    continue;
                };
                match entry.role {
                    JournalRole::TurnPut
                        if *entity_type == ENTITY_TYPE_TURN && *id == entry.scope.turn() =>
                    {
                        turns.insert(*id);
                    }
                    JournalRole::MessagePartOf if *entity_type == ENTITY_TYPE_MESSAGE => {
                        messages.insert(*id, (entry.scope.turn(), entry.occurred.start));
                    }
                    _ => {}
                }
            }
            let mut proposals = BTreeMap::new();
            for (message, (turn, at)) in messages {
                let unsaved = turns.contains(&turn);
                if (!unsaved && !saved.contains(turn.as_bytes())) || !visible(Some(&windows), at) {
                    continue;
                }
                let saved_turn_body = if unsaved {
                    None
                } else {
                    match crate::vault::live_entity_row_in_txn(&view.read(), txn, &turn)? {
                        crate::vault::LiveEntityRow::Live { entity_type, body }
                            if entity_type == ENTITY_TYPE_TURN =>
                        {
                            Some(body)
                        }
                        _ => None,
                    }
                };
                let turn_body = if unsaved {
                    let Some((body, _)) =
                        live_overlay_body(snapshot, view, txn, turn, ENTITY_TYPE_TURN)?
                    else {
                        continue;
                    };
                    body
                } else {
                    let Some(body) = saved_turn_body.as_deref() else {
                        continue;
                    };
                    body
                };
                // thread_binding's None also means malformed/non-map.
                // Only a complete actual TURN map proves the trunk case.
                let mut bytes = turn_body;
                if !matches!(
                    rmpv::decode::read_value(&mut bytes),
                    Ok(rmpv::Value::Map(_))
                ) || !bytes.is_empty()
                {
                    continue;
                }
                if let Some(binding) = crate::workspace_roster::thread_binding(turn_body)?
                    && !crate::workspace_roster::thread_turn_readable_with_read_in(
                        vault,
                        &view.read(),
                        txn,
                        binding.root,
                        turn,
                        &[actor],
                    )?
                {
                    continue;
                }
                let Some((body, current_at)) =
                    live_overlay_body(snapshot, view, txn, message, ENTITY_TYPE_MESSAGE)?
                else {
                    continue;
                };
                if current_at != at {
                    continue;
                }
                let Some((source, handle)) = MessageResultAttachment::reference_from_message(body)
                else {
                    continue;
                };
                // Overlay MESSAGEs use their room-held producer body, while
                // retained MESSAGEs can also carry their own occurrence mark.
                // Both keys are reached only through this admitted reference.
                for owner in [message, source.run_id] {
                    let key = ResultOccurrence::owned(owner, &source.path)?.mark_key(&handle);
                    if let Some(reason) = snapshot
                        .staged_value(OverlayKeyspace::VaultMeta, &RESULT_SECRETS.key_bytes(&key))
                    {
                        proposals.insert(key, RESULT_SECRETS.decode_value(reason)?);
                    }
                }
            }
            Ok(proposals.into_iter().collect())
        })
    }
}

/// A current overlay row, not a saved journal body or a base fallback.
/// The ordinary deletion/stale check is retained, including pending deletes.
fn live_overlay_body<'a>(
    snapshot: &'a OverlaySnapshot,
    view: &SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    entity_type: u8,
) -> Result<Option<(&'a [u8], u64)>> {
    let Some(raw) = snapshot.staged_value(OverlayKeyspace::Entities, id.as_bytes()) else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("room proposal entity header"))?;
    if header.entity_type != entity_type {
        return Ok(None);
    }
    let state = view.port_deletion_state(txn, &id)?;
    if state.deleted || state.stale {
        return Ok(None);
    }
    Ok(Some((
        &raw[ENTITY_METADATA_HEADER_LEN..],
        header.occurred_start,
    )))
}
