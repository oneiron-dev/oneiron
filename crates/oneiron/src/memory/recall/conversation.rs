//! Conversation and PERSON narrowing for one recall selection.
//!
//! These are relevance filters inside the reader's credential. A PERSON names
//! the conversations where they authored at least one live MESSAGE; mentions
//! and addressed rooms never enter the selection (Meta lead 20:27, FIX 11841).

use std::collections::BTreeSet;

use heed::RoTxn;

use super::RecallScope;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::pipeline::{CandidateGate, SnapshotCandidateFilter};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::scope_summary::{WordSources, word_sources_through_in};
use crate::store::StoreRead;

impl Memory<'_> {
    /// The explicit conversation set met with the selected PERSON's authored
    /// conversations. Empty refs and an unset PERSON add no narrowing.
    pub(super) fn selected_conversations(
        &self,
        scope: &RecallScope,
    ) -> MemoryResult<Option<BTreeSet<EntityId>>> {
        let mut explicit = BTreeSet::new();
        for reference in &scope.conversation_refs {
            let id = self.resolve_ref(reference)?;
            self.expect_scope_kind(id, ENTITY_TYPE_CONVERSATION, "conversation_refs")?;
            explicit.insert(id);
        }
        let explicit = (!scope.conversation_refs.is_empty()).then_some(explicit);
        let person = scope
            .person_ref
            .as_deref()
            .map(|reference| {
                let person = self.resolve_ref(reference)?;
                self.expect_scope_kind(person, ENTITY_TYPE_PERSON, "person_ref")?;
                self.person_conversations(person)
            })
            .transpose()?;
        Ok(match (explicit, person) {
            (None, None) => None,
            (Some(conversations), None) | (None, Some(conversations)) => Some(conversations),
            (Some(mut left), Some(right)) => {
                left.retain(|conversation| right.contains(conversation));
                Some(left)
            }
        })
    }

    /// A scope ref names its declared row kind, never merely an existing id.
    fn expect_scope_kind(&self, id: EntityId, expected: u8, field: &str) -> MemoryResult<()> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let actual = self
            .vault
            .store
            .port_entity_record(&txn, &id)?
            .map(|row| row.entity_type);
        if actual == Some(expected) {
            return Ok(());
        }
        let wanted = match expected {
            ENTITY_TYPE_CONVERSATION => "a CONVERSATION",
            ENTITY_TYPE_PERSON => "a PERSON",
            _ => "the requested kind",
        };
        Err(MemoryError::bad_request(format!(
            "scope.{field} must name {wanted} row"
        )))
    }

    /// Every conversation with a live MESSAGE `AuthoredBy` this PERSON. The
    /// whole adjacency is read: no page bound may silently drop a matching
    /// room, and no mention or address edge participates.
    fn person_conversations(&self, person: EntityId) -> MemoryResult<BTreeSet<EntityId>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let mut conversations = BTreeSet::new();
        for edge in self.vault.store.port_edges(
            &txn,
            &person,
            EdgeDirection::In,
            Some(EdgeKind::AuthoredBy),
            None,
        )? {
            let message = edge?.target;
            let Some(record) = self.vault.store.port_entity_record(&txn, &message)? else {
                continue;
            };
            if record.entity_type != ENTITY_TYPE_MESSAGE {
                continue;
            }
            let deletion = self.vault.store.port_deletion_state(&txn, &message)?;
            if deletion.archived || deletion.deleted || deletion.stale {
                continue;
            }
            for link in self.vault.store.port_edges(
                &txn,
                &message,
                EdgeDirection::Out,
                Some(EdgeKind::BelongsTo),
                None,
            )? {
                let conversation = link?.target;
                if self
                    .vault
                    .store
                    .port_entity_record(&txn, &conversation)?
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_CONVERSATION)
                {
                    conversations.insert(conversation);
                }
            }
        }
        Ok(conversations)
    }
}

/// The recall authority gate followed by conversation/PERSON narrowing. The
/// provenance readers run only for a candidate the credential already admits.
pub(super) struct ConversationGate<'a> {
    inner: &'a dyn CandidateGate,
    vault: &'a crate::Vault,
    selected: &'a Option<BTreeSet<EntityId>>,
}

impl<'a> ConversationGate<'a> {
    pub(super) fn new(
        inner: &'a dyn CandidateGate,
        vault: &'a crate::Vault,
        selected: &'a Option<BTreeSet<EntityId>>,
    ) -> Self {
        Self {
            inner,
            vault,
            selected,
        }
    }
}

impl CandidateGate for ConversationGate<'_> {
    fn in_txn<'t>(&'t self, txn: &'t RoTxn<'t>) -> Box<SnapshotCandidateFilter<'t>> {
        let admitted = self.inner.in_txn(txn);
        Box::new(move |store, txn, id| {
            if !admitted(store, txn, id)? {
                return Ok(false);
            }
            conversation_candidate_admits(self.vault, store, txn, id, self.selected)
        })
    }
}

/// Whether an admitted row belongs to a selected conversation directly or
/// through claim/summary source provenance. Every traversal is cycle-safe;
/// an absent or unresolvable source adds nothing and never drops the filter.
pub(crate) fn conversation_candidate_admits(
    vault: &crate::Vault,
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
    selected: &Option<BTreeSet<EntityId>>,
) -> crate::Result<bool> {
    let Some(selected) = selected else {
        return Ok(true);
    };
    if selected.is_empty() {
        return Ok(false);
    }
    let mut pending = vec![*id];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(raw) = store.port_entity_raw(txn, &current)? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if !direct_conversations(store, txn, &current, header.entity_type)?.is_disjoint(selected) {
            return Ok(true);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM
            && !crate::provenance::claim_conversation_sources_in(store, txn, &current)?
                .is_disjoint(selected)
        {
            return Ok(true);
        }
        if matches!(
            header.entity_type,
            ENTITY_TYPE_CLAIM | ENTITY_TYPE_SUMMARY | ENTITY_TYPE_TURN
        ) {
            match word_sources_through_in(vault, store, txn, &current, &raw)? {
                WordSources::From(sources) => pending.extend(sources),
                WordSources::Own | WordSources::Unresolved => {}
            }
        }
    }
    Ok(false)
}

/// The conversation ids a row itself names, without following derivation.
fn direct_conversations(
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> crate::Result<BTreeSet<EntityId>> {
    if entity_type == ENTITY_TYPE_CONVERSATION {
        return Ok(BTreeSet::from([*id]));
    }
    let edge = match entity_type {
        ENTITY_TYPE_TURN => Some(EdgeKind::ChildOf),
        ENTITY_TYPE_MESSAGE => Some(EdgeKind::BelongsTo),
        _ => None,
    };
    let mut conversations = BTreeSet::new();
    let Some(kind) = edge else {
        return Ok(conversations);
    };
    for edge in store.port_edges(txn, id, EdgeDirection::Out, Some(kind), None)? {
        let target = edge?.target;
        if store
            .port_entity_record(txn, &target)?
            .is_some_and(|row| row.entity_type == ENTITY_TYPE_CONVERSATION)
        {
            conversations.insert(target);
        }
    }
    Ok(conversations)
}
