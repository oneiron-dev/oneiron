//! A phone thread's read gate (VOICE-PHONE-AGENT-REACH R1): a marked thread's
//! rows, and every row written from them (READ-LINEAGE L1, the row's floor),
//! read to a non-owner only under a live grant naming its conversation.

use super::*;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

impl ScopedRead<'_> {
    /// The marked phone-thread CONVERSATIONs the row `id` sits in, on this
    /// read's content, judged by the row's OWN stamp alone (R1 fix, no edge
    /// walk): the row itself for a CONVERSATION whose body carries
    /// `phone_line_agent`, its own `phone_thread` stamp for a TURN, MESSAGE
    /// or SESSION. Every other kind, and a row with no stamp of its own, is
    /// not a phone row. A CONVERSATION deleted or emptied alone leaves every
    /// TURN/MESSAGE still stamped and still gated.
    pub(super) fn phone_threads_of_row_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(Vec::new());
        };
        match row.entity_type {
            crate::registry::ENTITY_TYPE_CONVERSATION => {
                if crate::voice_call::phone_thread_agent(&row.body).is_some() {
                    Ok(vec![*id])
                } else {
                    Ok(Vec::new())
                }
            }
            crate::registry::ENTITY_TYPE_TURN
            | crate::registry::ENTITY_TYPE_MESSAGE
            | crate::registry::ENTITY_TYPE_SESSION => {
                if let Some(thread) = crate::voice_call::phone_thread_stamp(&row.body) {
                    Ok(vec![thread])
                } else {
                    Ok(Vec::new())
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Whether the phone-thread gate admits the revision `raw` of `id` in
    /// `txn`: its own threads (the row's own stamp) and the threads on its
    /// stored floor (READ-LINEAGE L1: a row written from a thread's rows,
    /// such as a CLAIM whose birth names a kept TURN as evidence). The vault
    /// owner reads every thread; any other reader needs a live
    /// `ConversationMessages` grant over EACH thread, whose authority admits
    /// the row's record Scope. A floor with an id that names no source reads
    /// to no one, the owner's read included (READ-LINEAGE-L3 = A); the
    /// policies on a floor are the source-audience walk's. This conjunct only
    /// ever removes rows. Fail closed: an error in the grant read refuses the
    /// row. Every read pays one floor read; only the three transcript kinds
    /// and the thread SESSION pay the stamp read, and only on a non-owner
    /// read.
    pub(super) fn phone_threads_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &super::access_gate::HeldAuthority,
    ) -> Result<bool> {
        let Some(mut threads) = crate::source_audience::floor_threads_in(self.vault, txn, id)?
        else {
            return Ok(false);
        };
        if self.actor_key.reads_as_vault_owner() {
            return Ok(true);
        }
        let header = crate::batch::EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_CONVERSATION
                | crate::registry::ENTITY_TYPE_TURN
                | crate::registry::ENTITY_TYPE_MESSAGE
                | crate::registry::ENTITY_TYPE_SESSION
        ) {
            threads.extend(self.phone_threads_of_row_in(txn, id)?);
        }
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
