//! Who reads a conversation's DAG records (FIX 8153, ARCH-0006a rule 2,
//! Engine 10-22).
//!
//! The record listing releases a conversation's HEAD, root and main line,
//! topology no row-by-row read bounds, so the conversation itself is
//! admitted first, under the caller's own credential-bound read: the lane
//! must read the conversation's row, and the reader must see it as its own
//! conversation list sees it. A group, channel or mirror shows only to a
//! member or on a live grant that opens its relationship; absent from the
//! reader's list is absent here. The vault owner reads every room.

use crate::claim::ScopedRead;
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

impl Vault {
    /// Whether `read`'s caller may read `conversation`'s DAG records: the
    /// lane reads its row, and its key is the vault owner's, or a narrower
    /// owner credential while he is still the bound owner, or its reader
    /// sees the conversation in its own list. An id that names no
    /// conversation is left to the listing, which refuses it as it does
    /// today.
    ///
    /// # Errors
    ///
    /// Storage errors, and the list's owner check that does not resolve
    /// (a broken authority root), as the read lane reports it.
    pub fn dag_records_admitted(
        &self,
        read: &ScopedRead<'_>,
        conversation: &EntityId,
    ) -> Result<bool> {
        // The lane's read takes its own snapshot, before this one opens.
        if !read.is_entity_readable(conversation)? {
            return Ok(false);
        }
        let txn = self.store.env.read_txn()?;
        if !matches!(
            live_entity_row_in_txn(&self.store, &txn, conversation)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_CONVERSATION,
                ..
            }
        ) {
            return Ok(true);
        }
        let key = read.actor_key();
        if key.reads_as_vault_owner() || key.facets_owner_exempt_in(self, &txn)? {
            return Ok(true);
        }
        let reader = key
            .authenticated_person()
            .zip(reader_class(key.actor_class()));
        self.conversation_list_sees_in(&txn, *conversation, reader)
            .map_err(|refusal| Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal))))
    }
}

/// The class a read key's caller reads as, as the server binds a
/// credential's: one that declares none is a person's.
fn reader_class(class: Option<&str>) -> Option<EdgeActorClass> {
    match class {
        None | Some("human") => Some(EdgeActorClass::Human),
        Some("agent") => Some(EdgeActorClass::Agent),
        Some("system") => Some(EdgeActorClass::System),
        Some(_) => None,
    }
}
