//! A phone thread's read gate (VOICE-PHONE-AGENT-REACH R1): a marked thread's
//! rows read to a non-owner only under a live grant naming its conversation.

use super::*;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

impl ScopedRead<'_> {
    /// The marked phone-thread CONVERSATIONs the row `id` sits in, on this
    /// read's content: the row itself for a CONVERSATION, its `ChildOf`
    /// targets for a TURN, its TURNs' conversations for a MESSAGE (found as
    /// `conversation_message_granted_in` finds them). Every other kind: none.
    /// A conversation whose row does not read or whose body has no
    /// `phone_line_agent` mark is not a phone thread.
    pub(super) fn phone_threads_of_row_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(Vec::new());
        };
        let conversations = match row.entity_type {
            crate::registry::ENTITY_TYPE_CONVERSATION => vec![*id],
            crate::registry::ENTITY_TYPE_TURN => self.edge_targets_in(
                txn,
                id,
                EdgeKind::ChildOf,
                crate::registry::ENTITY_TYPE_CONVERSATION,
            ),
            crate::registry::ENTITY_TYPE_MESSAGE => self
                .edge_targets_in(txn, id, EdgeKind::PartOf, crate::registry::ENTITY_TYPE_TURN)
                .iter()
                .flat_map(|turn| {
                    self.edge_targets_in(
                        txn,
                        turn,
                        EdgeKind::ChildOf,
                        crate::registry::ENTITY_TYPE_CONVERSATION,
                    )
                })
                .collect(),
            _ => return Ok(Vec::new()),
        };
        let mut marked = Vec::new();
        for conversation in conversations {
            let Some(row) = self.entity_record_in(txn, &conversation)? else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
                continue;
            }
            if crate::voice_call::phone_thread_agent(&row.body).is_some() {
                marked.push(conversation);
            }
        }
        Ok(marked)
    }

    /// Whether the phone-thread gate admits the revision `raw` of `id` in
    /// `txn`: true for unmarked rows and for the vault owner's read; any
    /// other reader needs a live `ConversationMessages` grant over EACH
    /// marked conversation the row sits in, whose authority admits the row's
    /// record Scope. This conjunct only ever removes rows. Fail closed: an
    /// error in the grant read refuses the row. Only the three transcript
    /// kinds pay the walk, and only on a non-owner read.
    pub(super) fn phone_threads_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &super::access_gate::HeldAuthority,
    ) -> Result<bool> {
        if self.actor_key.reads_as_vault_owner() {
            return Ok(true);
        }
        let header = crate::batch::EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if !matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_CONVERSATION
                | crate::registry::ENTITY_TYPE_TURN
                | crate::registry::ENTITY_TYPE_MESSAGE
        ) {
            return Ok(true);
        }
        let threads = self.phone_threads_of_row_in(txn, id)?;
        if threads.is_empty() {
            return Ok(true);
        }
        let record = match self.session_view {
            Some(view) => crate::federation::record_scope::scope_for_blob(view, txn, *id, raw)?,
            None => {
                crate::federation::record_scope::scope_for_blob(&self.vault.store, txn, *id, raw)?
            }
        };
        let Some(record) = record else {
            return Ok(false);
        };
        let allowed = authority.relationship_allows_in(
            self.vault,
            txn,
            self.actor_key.principal_ref,
            |context| {
                threads.iter().all(|conversation| {
                    context.allows_conversation_message_at_snapshot(*conversation, &record)
                })
            },
        );
        Ok(allowed.unwrap_or(false))
    }
}
