//! A saved result MESSAGE's hold on its body (FIX 365): the body comes out
//! of the room it was said in, and the hold lands with the MESSAGE.
//!
//! A body that holds a room handle the room keeps a value under
//! (ROOM-LOCAL-CUSTODY) is carried (ROOM-CUSTODY-REPLY-BODIES): in the save's
//! transaction the value moves into the vault's custody, the carried bytes,
//! holding its base handle, become a body of their own in base, and the
//! saved MESSAGE's attachment names that body, with its length and lines.
//! A body the room spilled to a file takes a body instance reserved before
//! that transaction opens, should its carried copy spill too (KS-2A).

use std::collections::BTreeMap;
use std::sync::PoisonError;

use heed::RwTxn;

use super::FloorWrites;
use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MESSAGE_RESULT_METADATA_KEY, MessageResultAttachment};
use crate::result_body::ResultBodyPin;
#[cfg(unix)]
use crate::session_overlay::PromotePlan;
use crate::store::result_manifest::StagedSinks;

/// What one save carries of its room's result bodies
/// (ROOM-CUSTODY-REPLY-BODIES).
#[derive(Default)]
pub(super) struct CarriedBodies {
    /// The body instances reserved before the save's transaction, one for
    /// each result body the room spilled to a file.
    staged: Option<StagedSinks>,
    /// The pins on each carried body file the save wrote, held for its
    /// discard once its transaction has ended (FIX 3633).
    pins: Vec<ResultBodyPin>,
}

/// Each MESSAGE `ops` puts whose metadata decodes a result attachment, with
/// it (FIX 365). The witness door refused every other writer of the key, so
/// one that does not decode names no body.
pub(super) fn message_results(ops: &[BatchOp]) -> Vec<(EntityId, MessageResultAttachment)> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE => {
                message_attachment(data).map(|attachment| (*id, attachment))
            }
            _ => None,
        })
        .collect()
}

/// The result attachment a MESSAGE body's metadata holds, if it decodes.
fn message_attachment(body: &[u8]) -> Option<MessageResultAttachment> {
    let metadata = message_metadata(body)?;
    MessageResultAttachment::from_metadata(Some(&metadata))
        .ok()
        .flatten()
}

/// A MESSAGE body's metadata, as JSON. The body is read in place, so its
/// words are not copied out of the plan that scrubs them.
fn message_metadata(body: &[u8]) -> Option<serde_json::Value> {
    let mut cursor = body;
    let Ok(rmpv::ValueRef::Map(fields)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return None;
    };
    fields.into_iter().find_map(|(key, value)| match key {
        rmpv::ValueRef::String(key) if key.as_str() == Some("metadata") => {
            Some(crate::serialize::msgpack_value_to_json(&value.to_owned()))
        }
        _ => None,
    })
}

/// `body`, a MESSAGE body, with the result attachment in its metadata
/// naming the body `saved` names: its handle, length and lines
/// (ROOM-CUSTODY-REPLY-BODIES). Every other byte stays as written, so the
/// body is still its canonical envelope.
fn with_saved_body(body: &[u8], saved: &MessageResultAttachment) -> Result<Vec<u8>> {
    let corrupt = || Error::CorruptedIndex("saved message result attachment");
    let mut cursor = body;
    let mut tree = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt())?;
    if !cursor.is_empty() {
        return Err(corrupt());
    }
    let result = field_mut(&mut tree, "metadata")
        .and_then(|metadata| field_mut(metadata, MESSAGE_RESULT_METADATA_KEY))
        .ok_or_else(corrupt)?;
    for (name, value) in [
        ("handle", rmpv::Value::from(saved.handle.as_str())),
        ("bytes", rmpv::Value::from(saved.bytes)),
        ("lines", rmpv::Value::from(saved.lines)),
    ] {
        *field_mut(result, name).ok_or_else(corrupt)? = value;
    }
    let mut carried = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut carried, &tree).map_err(|_| corrupt())?;
    Ok(carried)
}

/// The member `name` of the MessagePack map `value`.
fn field_mut<'a>(value: &'a mut rmpv::Value, name: &str) -> Option<&'a mut rmpv::Value> {
    let rmpv::Value::Map(fields) = value else {
        return None;
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

impl FloorWrites<'_> {
    /// The writer's selected result MESSAGE sources must be covered by the
    /// preview whose files were imported before this writer opened. A changed
    /// dependency stays staged for a fresh save; no half-save can commit.
    #[cfg(unix)]
    pub(in crate::off_record) fn require_preimported_selected_results(
        &self,
        imported: &[PromotePlan],
        selected: &[PromotePlan],
    ) -> Result<()> {
        let sources: std::collections::BTreeMap<_, _> = imported
            .iter()
            .flat_map(|plan| plan.ops.iter())
            .filter_map(|op| match op {
                BatchOp::Put {
                    id,
                    entity_type,
                    data,
                    ..
                } if *entity_type == crate::registry::ENTITY_TYPE_MESSAGE => {
                    Some((*id, data.as_slice()))
                }
                _ => None,
            })
            .collect();
        for plan in selected {
            for (id, _) in message_results(&plan.ops) {
                for op in &plan.ops {
                    if let BatchOp::Put {
                        id: source, data, ..
                    } = op
                        && *source == id
                        && sources.get(&id).copied() != Some(data.as_slice())
                    {
                        return Err(crate::Error::InvariantViolation(
                            "selected result MESSAGE changed before save",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Before a save's transaction (FIX 365): each result body a MESSAGE of
    /// `plans` holds that the room spilled to a file comes into the vault's
    /// `bodies/`, unnamed until that transaction commits, and every such
    /// body is pinned, so the caller holds the pins across the commit. A
    /// copy the save then leaves unnamed, refused or skipping its MESSAGE,
    /// goes through [`Vault::discard_unnamed_promoted_bodies`] (FIX 3633).
    /// In a room that keeps a secret, each spilled body also takes a body
    /// instance, reserved now, for its carried copy (see the module notes).
    #[cfg(unix)]
    pub(crate) fn import_result_bodies(
        &self,
        vault: &Vault,
        session_ref: &str,
        plans: &[PromotePlan],
    ) -> Result<Vec<ResultBodyPin>> {
        let results: Vec<_> = plans
            .iter()
            .flat_map(|plan| message_results(&plan.ops))
            .collect();
        if results.is_empty() {
            return Ok(Vec::new());
        }
        let overlay = self.room()?;
        let room = self.store.session_view(overlay.clone())?;
        if overlay.room_secret_count()? > 0 {
            let spilled = {
                let rtxn = self.store.env.read_txn()?;
                let mut spilled = 0;
                for (_, attachment) in &results {
                    let row = crate::store::result_body_rows::RAW_OUTPUTS.get(
                        &room,
                        &rtxn,
                        &attachment.output()?.handle,
                    )?;
                    if matches!(
                        row,
                        Some(crate::store::result_body_rows::StoredBody::File { .. })
                    ) {
                        spilled += 1;
                    }
                }
                spilled
            };
            if spilled > 0 {
                let staged = vault.staged_result_sinks(spilled)?;
                self.carried
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .staged = Some(staged);
            }
        }
        results
            .iter()
            .map(|(_, attachment)| {
                vault.promote_off_record_message_result_body(session_ref, &room, attachment)
            })
            .collect()
    }

    /// `ops`, a save's writes, with the body each fresh result MESSAGE of
    /// them names carried out of the room, in `wtxn` (see the module notes),
    /// and the attachment each carried MESSAGE now carries. A MESSAGE base
    /// holds already keeps its bytes, as the save's replay compares them; a
    /// floor that saves out of no room, or out of one that keeps no secret,
    /// writes `ops` as given.
    ///
    /// # Errors
    ///
    /// Custody, storage and filesystem errors, and a body the room holds no
    /// row or file of.
    pub(super) fn carry_message_results_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        session_ref: &str,
        mut ops: Vec<BatchOp>,
    ) -> Result<(Vec<BatchOp>, BTreeMap<EntityId, MessageResultAttachment>)> {
        let mut carried = BTreeMap::new();
        let Some(overlay) = &self.room else {
            return Ok((ops, carried));
        };
        let Some(mut carry) = crate::batch::secret_scan::RoomCarry::of(overlay)? else {
            return Ok((ops, carried));
        };
        let room = self.store.session_view(overlay.clone())?;
        let mut held = self.carried.lock().unwrap_or_else(PoisonError::into_inner);
        for op in &mut ops {
            let BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } = op
            else {
                continue;
            };
            if *entity_type != crate::registry::ENTITY_TYPE_MESSAGE
                || crate::ports::EntityStoreRead::port_entity_present(self.store, wtxn, id)?
            {
                continue;
            }
            let Some(said) = message_attachment(data) else {
                continue;
            };
            let message = *id;
            let Some((saved, pin)) = vault.carry_saved_message_result_in_txn(
                wtxn,
                (&room, session_ref),
                &said,
                held.staged.as_ref(),
                |wtxn, body| carry.body_in_txn(vault, wtxn, message, body),
            )?
            else {
                continue;
            };
            *data = with_saved_body(data, &saved)?;
            held.pins.extend(pin);
            carried.insert(message, saved);
        }
        Ok((ops, carried))
    }

    /// The pins on the result body files this floor's save carried into
    /// base, for the save's discard once its transaction has ended (FIX
    /// 3633): a copy no committed row names goes then.
    pub(crate) fn carried_body_pins(&self) -> Vec<ResultBodyPin> {
        std::mem::take(
            &mut self
                .carried
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pins,
        )
    }

    /// Each result MESSAGE of `results` keeps its hold on the body in base,
    /// in the transaction that writes it (FIX 365): the run that made the
    /// body ran in the room, so the body's row and marks and the run's
    /// replay are read there. A MESSAGE `carried` names holds the body the
    /// save carried for it ([`Self::carry_message_results_in_txn`]).
    pub(super) fn keep_message_results_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        results: &[(EntityId, MessageResultAttachment)],
        carried: &BTreeMap<EntityId, MessageResultAttachment>,
    ) -> Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        let room = self.store.session_view(self.room()?)?;
        for (message, said) in results {
            let saved = carried.get(message).unwrap_or(said);
            vault.retain_saved_message_result_in_txn(wtxn, &room, *message, (said, saved))?;
        }
        Ok(())
    }
}
