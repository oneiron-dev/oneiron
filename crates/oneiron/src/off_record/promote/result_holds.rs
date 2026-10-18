//! A saved result MESSAGE's hold on its body (FIX 365): the body comes out
//! of the room it was said in, and the hold lands with the MESSAGE.

use heed::RwTxn;

use super::FloorWrites;
use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::MessageResultAttachment;
#[cfg(unix)]
use crate::session_overlay::PromotePlan;

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
                let metadata = message_metadata(data)?;
                MessageResultAttachment::from_metadata(Some(&metadata))
                    .ok()
                    .flatten()
                    .map(|attachment| (*id, attachment))
            }
            _ => None,
        })
        .collect()
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

impl FloorWrites<'_> {
    /// Before a save's transaction (FIX 365): each result body a MESSAGE of
    /// `plans` holds that the room spilled to a file comes into the vault's
    /// `bodies/`, unnamed until that transaction commits, and every such
    /// body is pinned, so the caller holds the pins across the commit. A
    /// MESSAGE the save then leaves in the room leaves its copy to the
    /// collector.
    #[cfg(unix)]
    pub(crate) fn import_result_bodies(
        &self,
        vault: &Vault,
        session_ref: &str,
        plans: &[PromotePlan],
    ) -> Result<Vec<crate::result_body::ResultBodyPin>> {
        let results: Vec<_> = plans
            .iter()
            .flat_map(|plan| message_results(&plan.ops))
            .collect();
        if results.is_empty() {
            return Ok(Vec::new());
        }
        let room = self.store.session_view(self.room()?)?;
        results
            .iter()
            .map(|(message, attachment)| {
                vault.promote_off_record_message_result_body(
                    session_ref,
                    &room,
                    *message,
                    attachment,
                )
            })
            .collect()
    }

    /// Each result MESSAGE of `results` keeps its hold on the body in base,
    /// in the transaction that writes it (FIX 365): the run that made the
    /// body ran in the room, so the body's row and marks and the run's
    /// replay are read there.
    pub(super) fn keep_message_results_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        results: &[(EntityId, MessageResultAttachment)],
    ) -> Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        let room = self.store.session_view(self.room()?)?;
        for (message, attachment) in results {
            vault.retain_saved_message_result_in_txn(wtxn, &room, *message, attachment)?;
        }
        Ok(())
    }
}
