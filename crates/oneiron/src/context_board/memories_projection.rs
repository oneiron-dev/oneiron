//! MEMORIES projection with source labels, world fences, and one shared render budget.

use super::memories::{
    CompanionAssembly, MEMORIES_SECTION_VERSION_V4, MemoriesBudget, MemoriesSection, MemoryRow,
    MemorySlot, MemorySource, MemoryTier,
};
use crate::context_pack::{ContextEntity, ContextPack};
use crate::disclosure::DisclosureAssembly;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};

/// Builds the MEMORIES section from an already assembled pack.
///
/// Rows are sorted by slot, source, descending score, and entity id before slot
/// budgets are applied. That order is independent of `HashMap` iteration and
/// remains stable when retrieval returns equal-score rows.
///
/// The HTTP board uses this same projection and shared frame renderer.
#[must_use]
pub fn project_memories_section(
    pack: &ContextPack,
    budget: MemoriesBudget,
    companion: Option<CompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> MemoriesSection {
    let mut rows = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
    rows.extend(
        pack.results
            .iter()
            .filter(|entity| {
                !matches!(
                    entity.entity_type,
                    crate::registry::ENTITY_TYPE_SKILL | crate::registry::ENTITY_TYPE_AGENT_DEF
                )
            })
            .map(|entity| memory_row(entity, MemorySource::Result)),
    );
    rows.extend(
        pack.neighbors
            .iter()
            .filter(|entity| {
                !matches!(
                    entity.entity_type,
                    crate::registry::ENTITY_TYPE_SKILL | crate::registry::ENTITY_TYPE_AGENT_DEF
                )
            })
            .map(|entity| memory_row(entity, MemorySource::Neighbor)),
    );

    finish_projection(rows, budget, companion, disclosure)
}

pub(super) fn finish_projection(
    mut rows: Vec<MemoryRow>,
    budget: MemoriesBudget,
    companion: Option<CompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> MemoriesSection {
    rows.sort_by(memory_row_order);
    clamp_held_pairs(&mut rows);

    let mut used = MemoriesBudget::default();
    let mut filtered = Vec::with_capacity(rows.len());
    for mut row in rows {
        if row.tier != MemoryTier::Pinned
            && (used.get(row.slot) >= budget.get(row.slot)
                || budget.shared_total.is_some_and(|cap| filtered.len() >= cap))
        {
            continue;
        }
        used.increment(row.slot);
        row.row_index = filtered.len();
        filtered.push(row);
    }

    filtered.sort_by(|a, b| {
        foreign_row(a)
            .cmp(&foreign_row(b))
            .then_with(|| a.world.cmp(&b.world))
            .then_with(|| memory_row_order(a, b))
    });
    clamp_held_pairs(&mut filtered);
    for (index, row) in filtered.iter_mut().enumerate() {
        row.row_index = index;
    }
    MemoriesSection {
        version: MEMORIES_SECTION_VERSION_V4.to_owned(),
        budget,
        rows: filtered,
        companion,
        disclosure,
    }
}

/// OF-023 hold-both: an observed claim row never sits above a stated row of
/// its question (ARCH-0003), whichever section found it, so the slot budget
/// never keeps the observed mate over the stated one. A pinned row keeps
/// its pin, and every other row its place.
fn clamp_held_pairs(rows: &mut Vec<MemoryRow>) {
    let clamped =
        crate::context_pack::source_ranking::clamp_order_by(rows, &Default::default(), |row| {
            if row.tier == MemoryTier::Pinned {
                return None;
            }
            Some((row.claim_source?, row.question?))
        });
    if let Err(error) = clamped {
        tracing::warn!(%error, "the MEMORIES hold-both clamp did not run");
    }
}

fn memory_row(entity: &ContextEntity, source: MemorySource) -> MemoryRow {
    MemoryRow {
        row_index: 0,
        slot: memory_slot(entity.entity_type),
        source,
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        asset_ref: memory_asset_ref(entity.entity_type, &entity.short_id, entity.content_hash),
        score: entity.score,
        claim_source: (entity.entity_type == ENTITY_TYPE_CLAIM)
            .then(|| {
                entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("src"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(crate::claim::ClaimSource::parse)
            })
            .flatten(),
        world: (entity.entity_type == ENTITY_TYPE_CLAIM)
            .then(|| {
                entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("world"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .flatten()
            .or_else(|| {
                entity.edges.as_ref().and_then(|edges| {
                    edges
                        .iter()
                        .find(|edge| edge.kind == crate::edge::EdgeKind::InWorld)
                        .map(|edge| edge.target.to_hex())
                })
            }),
        tier: MemoryTier::Snippet,
        snippet: None,
        hook: None,
        source_revision: entity.source_revision_ref.map(crate::vault::RevisionRef),
        question: None,
    }
}

pub(super) fn memory_asset_ref(
    entity_type: u8,
    short_id: &str,
    content_hash: u8,
) -> Option<String> {
    matches!(entity_type, ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT)
        .then(|| format!("{short_id}:{content_hash:02x}"))
}

pub(super) fn memory_slot(entity_type: u8) -> MemorySlot {
    match entity_type {
        ENTITY_TYPE_CLAIM => MemorySlot::Claims,
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE => MemorySlot::Turns,
        ENTITY_TYPE_SUMMARY => MemorySlot::Summaries,
        ENTITY_TYPE_FACET => MemorySlot::Facets,
        _ => MemorySlot::Other,
    }
}

fn memory_row_order(left: &MemoryRow, right: &MemoryRow) -> std::cmp::Ordering {
    (left.tier != MemoryTier::Pinned)
        .cmp(&(right.tier != MemoryTier::Pinned))
        .then_with(|| left.slot.sort_rank().cmp(&right.slot.sort_rank()))
        .then_with(|| left.source.sort_rank().cmp(&right.source.sort_rank()))
        .then_with(|| right.score.total_cmp(&left.score))
        .then_with(|| left.id.cmp(&right.id))
}

pub(super) fn foreign_row(row: &MemoryRow) -> bool {
    row.world
        .as_deref()
        .and_then(|world| crate::EntityId::from_hex(world).ok())
        .is_some_and(crate::entity_id::is_foreign_world_id_range)
}

impl crate::Vault {
    /// Hydrates provenance for already-authorized retrieval results. Pinned
    /// inputs must also come from the caller's authorized read projection.
    pub fn project_memories_section(
        &self,
        pack: &ContextPack,
        budget: MemoriesBudget,
        companion: Option<CompanionAssembly>,
        disclosure: Option<DisclosureAssembly>,
        pinned: &std::collections::BTreeSet<crate::EntityId>,
    ) -> crate::error::Result<MemoriesSection> {
        let mut rows = Vec::new();
        // A claim's question only orders its row; its bytes and labels stay
        // the snapshot's.
        let rtxn = self.store.env.read_txn()?;
        for (entities, source) in [
            (&pack.results, MemorySource::Result),
            (&pack.neighbors, MemorySource::Neighbor),
        ] {
            for entity in entities {
                let mut row = memory_row(entity, source);
                if entity.entity_type == ENTITY_TYPE_CLAIM {
                    row.question = self
                        .get_claim_in_txn(&rtxn, &entity.id)
                        .ok()
                        .flatten()
                        .as_ref()
                        .and_then(crate::context_pack::source_ranking::question_key);
                }
                // These bytes and labels belong to the already-authorized
                // snapshot and its engine-issued ref. A new vault read could
                // substitute a changed private claim after the read gate.
                if entity.entity_type == ENTITY_TYPE_CLAIM
                    && let Some(value) = entity.fields.as_ref().and_then(|fields| fields.get("val"))
                {
                    let mut value = value.clone();
                    crate::batch::export::redact_credentials(&mut value);
                    row.snippet = Some(value.to_string());
                }
                row.tier = if pinned.contains(&entity.id) {
                    MemoryTier::Pinned
                } else if foreign_row(&row) {
                    MemoryTier::IndexOnly
                } else {
                    MemoryTier::Snippet
                };
                if foreign_row(&row) {
                    row.snippet = None;
                }
                rows.push(row);
            }
        }
        Ok(finish_projection(rows, budget, companion, disclosure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimeRange;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, PointRead,
        ScopedReadActorKey,
    };
    use crate::context_pack::FieldProfile;
    #[test]
    fn opaque_entity_fields_cannot_claim_provenance_or_foreign_authority() {
        let fields = std::collections::HashMap::from([
            ("src".into(), serde_json::json!("user_stated")),
            (
                "world".into(),
                serde_json::json!(crate::test_util::entity(0xF1).to_hex()),
            ),
        ]);
        let entity = ContextEntity {
            id: crate::test_util::entity(0x61),
            short_id: "pe1".into(),
            content_hash: 0,
            source_revision_ref: None,
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            critical: false,
            score: 1.0,
            fields: Some(fields),
            edges: None,
            vector: None,
        };
        let row = memory_row(&entity, MemorySource::Result);
        assert_eq!(row.claim_source, None);
        assert_eq!(row.world, None);
    }
    #[test]
    fn board_keeps_authorized_claim_bytes_and_issued_hash_after_private_rewrite()
    -> crate::Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let claim = crate::test_util::entity(0x71);
        let subject = crate::test_util::entity(0x72);
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )?;
        let mut body = ClaimBody::new(
            "profile.likes",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("authorized snapshot"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::UserStated);
        body.scope = Some(rmpv::Value::Map(vec![(
            "sensitivity".into(),
            "private".into(),
        )]));
        vault.put_claim(&claim, &body, TimeRange { start: 10, end: 10 }, 10)?;
        crate::test_util::authorize_readers(&vault, &["viewer"]);
        let read = vault.scoped_read(ScopedReadActorKey::new("viewer").unwrap());
        let mut pack = vault
            .context_pack()
            .search_temporal(10, 10, 8)
            .filter_types(&[ENTITY_TYPE_CLAIM])
            .field_profile(FieldProfile::Full)
            .run()?;
        read.filter_context_pack(&mut pack)?;
        let served = pack
            .results
            .iter()
            .find(|row| row.id == claim)
            .expect("authorized claim");
        let issued_hash = served.content_hash;
        let issued_short_id = served.short_id.clone();
        assert!(
            read.read(&[PointRead::short(&issued_short_id, issued_hash)], None)?
                .single()
                .value
                .is_some()
        );
        body.value = rmpv::Value::from("private rewrite must not appear on the board");
        body.approval = ClaimApprovalStatus::Proposed;
        body.scope = Some(rmpv::Value::Map(vec![(
            "sensitivity".into(),
            "private".into(),
        )]));
        vault.put_claim(&claim, &body, TimeRange { start: 11, end: 11 }, 11)?;
        assert_eq!(
            vault.get_claim(&claim)?.unwrap().value.as_str(),
            Some("private rewrite must not appear on the board")
        );
        assert!(
            read.read(&[PointRead::id(claim)], None)?
                .single()
                .value
                .is_none()
        );
        let section = vault.project_memories_section(
            &pack,
            MemoriesBudget::new(1, 0, 0, 0, 0, 0),
            None,
            None,
            &std::collections::BTreeSet::new(),
        )?;
        let row = section
            .rows
            .iter()
            .find(|row| row.id == claim.to_hex())
            .unwrap();
        assert_eq!(row.short_id, issued_short_id);
        assert_eq!(row.content_hash, format!("{issued_hash:02x}"));
        assert_eq!(row.claim_source, Some(ClaimSource::UserStated));
        assert_eq!(row.snippet.as_deref(), Some("\"authorized snapshot\""));
        Ok(())
    }
}
