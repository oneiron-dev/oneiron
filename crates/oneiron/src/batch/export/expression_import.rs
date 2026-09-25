//! Dependency scheduling for the owning expression-preference archive adapter.
use std::collections::{BTreeMap, BTreeSet};

use super::document_import::parse_id;
use super::{ExportEntity, WholeVaultDocument};
use crate::claim::{
    ArchivedExpressionPreference, ClaimSubject, ExpressionPreferenceArchive, decode_claim_body,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(super) fn is_expression(row: &ExportEntity) -> bool {
    row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && row
            .body
            .to_bytes()
            .ok()
            .and_then(|bytes| decode_claim_body(&bytes, false).ok())
            .is_some_and(|body| crate::claim::is_expression_preference_predicate(&body.predicate))
}

pub(super) struct ExpressionImports {
    pub(super) ids: BTreeSet<EntityId>,
    pending: BTreeMap<EntityId, ExpressionPreferenceArchive>,
}

impl ExpressionImports {
    pub(super) fn new(
        doc: &WholeVaultDocument,
        models: &BTreeMap<EntityId, EntityId>,
    ) -> Result<Self> {
        let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for row in doc.entities().filter(|row| is_expression(row)) {
            let body = decode_claim_body(&row.body.to_bytes()?, false)?;
            let ClaimSubject::Entity(original_subject) = body.subject else {
                return Err(invalid("expression subject is not an entity"));
            };
            let subject = models
                .get(&original_subject)
                .copied()
                .unwrap_or(original_subject);
            groups
                .entry((subject, body.predicate.clone()))
                .or_default()
                .push(ArchivedExpressionPreference {
                    id: parse_id(&row.id)?,
                    body,
                    subject,
                    occurred: TimeRange {
                        start: row.occurred_start,
                        end: row.occurred_end,
                    },
                    learned_at: row.learned_at,
                });
        }
        let mut pending = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let mut expected_edges = BTreeMap::new();
        for rows in groups.into_values() {
            let history = ExpressionPreferenceArchive::new(rows)?;
            let key = history
                .ids()
                .next()
                .ok_or_else(|| invalid("empty history"))?;
            ids.extend(history.ids());
            for (new, old, at) in history.supersessions() {
                expected_edges.insert((new, old), at);
            }
            pending.insert(key, history);
        }
        // A missing edge is missing history, not permission to invent a link.
        // Cross-family, reversed, branching or externally targeted links refuse.
        for edge in &doc.evidence_ledger.edges {
            if edge.kind != EdgeKind::Supersedes as u8 {
                continue;
            }
            let source = parse_id(&edge.source)?;
            let target = parse_id(&edge.target)?;
            if !ids.contains(&source) && !ids.contains(&target) {
                continue;
            }
            let at = expected_edges
                .remove(&(source, target))
                .ok_or_else(|| invalid("ambiguous supersedes edge"))?;
            if edge.created_at != at
                || Some(edge.weight) != EdgeKind::Supersedes.default_weight()
                || edge.vad.is_some_and(|vad| vad != [0.0, 0.0, 0.0])
                || edge.provenance.is_some()
            {
                return Err(invalid("supersedes edge differs from native history"));
            }
        }
        if !expected_edges.is_empty() {
            return Err(invalid("supersedes edge missing from history"));
        }
        Ok(Self { ids, pending })
    }

    pub(super) fn pending_ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.pending
            .values()
            .flat_map(ExpressionPreferenceArchive::ids)
    }

    pub(super) fn ready(&self, blocked: &BTreeSet<EntityId>) -> Vec<EntityId> {
        self.pending
            .iter()
            .filter_map(|(id, history)| (!blocked.contains(&history.subject())).then_some(*id))
            .collect()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn restore(
        &mut self,
        id: EntityId,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: &WriteActor,
    ) -> Result<(BTreeSet<EntityId>, usize)> {
        let history = self.pending.remove(&id).ok_or(Error::InvariantViolation(
            "expression import queue lost history",
        ))?;
        let (inserted, unchanged) = history.restore_in_txn(vault, txn, actor)?;
        let inserted_ids = if inserted == 0 {
            BTreeSet::new()
        } else {
            history.ids().collect()
        };
        Ok((inserted_ids, unchanged))
    }
}

/// Resolve the HOST-SUPPLIED actor before importing anything. An archive row
/// with the same id cannot create the local actor that authorizes this request.
pub(super) fn validate_local_actor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &WriteActor,
) -> Result<()> {
    if vault
        .store
        .off_record_sessions
        .contains_entity(&actor.entity_ref())?
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor.entity_ref())?.is_live()
    {
        return Err(Error::EntityNotFound);
    }
    let raw = vault
        .get_raw_in(txn, &actor.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("import actor header"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
    if vault.entity_lifecycle_state_in_txn(txn, &actor.entity_ref())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(invalid("import actor is not locally active"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("expression preference import: {reason}"))
}
