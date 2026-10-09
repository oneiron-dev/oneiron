//! Acceptance laws exercise the existing put/index/read engines, not a side store.
use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

fn body(text: &str) -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({"content": text})).unwrap()
}

fn put(vault: &Vault, id: &EntityId, text: &str) {
    let is_birth = vault.get(id).unwrap().is_none();
    let batch = vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_ASSET_TEXT,
            TimeRange { start: 1, end: 1 },
            1,
            &body(text),
        )
        .text(id, &[("content", text)]);
    let batch = if is_birth {
        batch.vector(id, &[1.0, 0.0, 0.0, 0.0])
    } else {
        batch
    };
    batch.commit().unwrap();
}

struct Embed {
    expected: RevisionRef,
    expected_body: Vec<u8>,
}
impl IndexedRevisionEmbedder for Embed {
    fn embed_revision(&self, input: &IndexedRevisionInput) -> Result<Vec<f32>> {
        assert_eq!(input.source_revision_ref, self.expected);
        assert_eq!(input.body, self.expected_body);
        Ok(vec![0.0, 1.0, 0.0, 0.0])
    }
}

#[test]
fn live_indexed_pinned_and_pack_switch_only_at_manifest_debounced_idle() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    assert!(matches!(
        vault.refresh_staged_indexed_at_idle(0),
        Err(crate::error::Error::InvalidConfig(_))
    ));
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "alpha zebra");
    let citation = vault.cite_entity_text(&id, "content", 0, 5).unwrap();
    let mut forged = citation.clone();
    forged.short_ref = "pr999999:00".into();
    assert!(matches!(
        vault.resolve_citation(&forged),
        Err(crate::Error::InvalidKey)
    ));
    let original = vault
        .get_raw_with_mode(&id, ReadMode::Live)
        .unwrap()
        .unwrap();
    put(&vault, &id, "beta yak");
    let changed = vault
        .get_raw_with_mode(&id, ReadMode::Live)
        .unwrap()
        .unwrap();
    let next = vault.pin_entity_revision(&id).unwrap();
    assert_ne!(original, changed);
    assert_eq!(
        vault
            .get_raw_with_mode(&id, ReadMode::Indexed)
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(
        vault
            .get_raw_with_mode(&id, ReadMode::Pinned(citation.source_revision_ref))
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(
        vault
            .resolve_pinned_entity_reference(&citation.short_ref, citation.source_revision_ref)
            .unwrap(),
        Some(id)
    );
    let pack = vault.context_pack().search_text("alpha", 10).run().unwrap();
    assert_eq!(pack.results.len(), 1);
    assert_eq!(
        pack.results[0].fields.as_ref().unwrap().get("content"),
        Some(&serde_json::json!("alpha zebra"))
    );
    assert!(vault.search_text("beta", 10).unwrap().is_empty());
    let embedder = Embed {
        expected: next,
        expected_body: body("beta yak"),
    };
    vault.set_indexed_idle_delay_ms(u64::MAX).unwrap();
    assert!(
        vault
            .refresh_indexed_at_idle(0, &embedder)
            .unwrap()
            .refreshed
            .is_empty()
    );
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let receipt = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert_eq!(receipt.refreshed, vec![(id, next)]);
    assert_eq!(
        vault
            .get_raw_with_mode(&id, ReadMode::Indexed)
            .unwrap()
            .unwrap(),
        changed
    );
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![0.0, 1.0, 0.0, 0.0]
    );
    assert!(vault.search_text("alpha", 10).unwrap().is_empty());
    assert_eq!(vault.search_text("beta", 10).unwrap()[0].id, id);
    assert_eq!(
        vault
            .get_raw_with_mode(&id, ReadMode::Pinned(citation.source_revision_ref))
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(
        vault.resolve_citation(&citation).unwrap(),
        ResolvedCitation {
            quote: "alpha".into(),
            drifted: true
        }
    );
    // Facade reads verify the bound actor row, so the reader is a stored person.
    let reader = EntityId::now();
    vault
        .put_entity(
            &reader,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )
        .unwrap();
    let memory = vault.memory(reader, crate::EdgeActorClass::Human);
    assert_eq!(
        memory
            .get_entity_with_mode(
                &citation.short_ref,
                ReadMode::Pinned(citation.source_revision_ref)
            )
            .unwrap()
            .value
            .unwrap()
            .body,
        Some(serde_json::json!({"content": "alpha zebra"}))
    );
    assert_eq!(
        memory.hydrate(&[citation.reference()]).unwrap()[0].body,
        Some(serde_json::json!({"content": "alpha zebra"}))
    );
    assert_eq!(original[ENTITY_METADATA_HEADER_LEN..], body("alpha zebra"));
}

struct EditingEmbedder<'a> {
    vault: &'a Vault,
    id: EntityId,
}
impl IndexedRevisionEmbedder for EditingEmbedder<'_> {
    fn embed_revision(&self, input: &IndexedRevisionInput) -> Result<Vec<f32>> {
        assert_eq!(input.body, body("beta yak"));
        put(self.vault, &self.id, "gamma fox");
        Ok(vec![0.0, 1.0, 0.0, 0.0])
    }
}

#[test]
fn scoped_asset_text_indexed_read_survives_live_body_restamp() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::authorize_readers(&vault, &["reader"]);
    let id = EntityId::now();
    put(&vault, &id, "indexed scope old");
    let indexed = vault.pin_entity_revision(&id).unwrap();
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").unwrap());
    assert!(
        reader
            .get_entity_parts_with_mode_with_receipt(&id, ReadMode::Indexed, None)
            .unwrap()
            .value
            .is_some()
    );
    put(&vault, &id, "indexed scope live");
    let retained = reader
        .get_entity_parts_with_mode_with_receipt(&id, ReadMode::Pinned(indexed), None)
        .unwrap()
        .value
        .unwrap();
    assert_eq!(retained.2, body("indexed scope old"));
    assert_eq!(
        reader
            .get_entity_parts_with_mode_with_receipt(&id, ReadMode::Indexed, None)
            .unwrap()
            .value
            .unwrap()
            .2,
        body("indexed scope old")
    );
}

#[test]
fn concurrent_edit_discards_embedding_without_advancing_indexed_frontier() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "alpha zebra");
    let first = vault.indexed_revision(&id).unwrap();
    put(&vault, &id, "beta yak");
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let receipt = vault
        .refresh_indexed_at_idle(u64::MAX, &EditingEmbedder { vault: &vault, id })
        .unwrap();
    assert!(receipt.refreshed.is_empty());
    assert_eq!(receipt.superseded, vec![id]);
    assert_eq!(vault.indexed_revision(&id).unwrap(), first);
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![1.0, 0.0, 0.0, 0.0]
    );
}

#[test]
fn each_index_commit_is_published_before_a_later_provider_failure() {
    struct FailsSecond(EntityId);
    impl IndexedRevisionEmbedder for FailsSecond {
        fn embed_revision(&self, input: &IndexedRevisionInput) -> Result<Vec<f32>> {
            if input.entity == self.0 {
                Err(crate::Error::UpstreamToolFailure {
                    tool: "indexed test provider",
                    code: "unavailable".into(),
                })
            } else {
                Ok(vec![0.0, 1.0, 0.0, 0.0])
            }
        }
    }
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let a = EntityId::from_bytes([0xD4; 16]).unwrap();
    let b = EntityId::from_bytes([0xD5; 16]).unwrap();
    put(&vault, &a, "first old");
    put(&vault, &b, "second old");
    let indexed_a = vault.indexed_revision(&a).unwrap().unwrap();
    let indexed_b = vault.indexed_revision(&b).unwrap();
    put(&vault, &a, "first new");
    put(&vault, &b, "second new");
    let live_a = vault.pin_entity_revision(&a).unwrap();
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let mut published: Vec<crate::memory::IndexedPublication> = Vec::new();
    let error =
        vault.refresh_indexed_at_idle_with_publication(u64::MAX, &FailsSecond(b), |publication| {
            published.push(publication);
        });
    assert!(matches!(
        error,
        Err(crate::Error::UpstreamToolFailure { .. })
    ));
    assert_eq!(
        published,
        vec![crate::memory::IndexedPublication {
            entity: a,
            previous_indexed: indexed_a,
            indexed: live_a,
        }]
    );
    assert_eq!(vault.indexed_revision(&a).unwrap(), Some(live_a));
    assert_eq!(vault.indexed_revision(&b).unwrap(), indexed_b);
}

#[test]
fn old_citation_survives_reopen_but_delete_cannot_resurrect_document() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let id = EntityId::now();
    put(&vault, &id, "alpha zebra");
    let citation = vault.cite_entity_text(&id, "content", 0, 5).unwrap();
    let mut forged = citation.clone();
    forged.short_ref = "pr999999:00".into();
    assert!(matches!(
        vault.resolve_citation(&forged),
        Err(crate::Error::InvalidKey)
    ));
    put(&vault, &id, "beta yak");
    put(&vault, &id, "alpha zebra");
    assert_ne!(
        vault.pin_entity_revision(&id).unwrap(),
        citation.source_revision_ref
    );
    drop(vault);
    let vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    assert_eq!(vault.resolve_citation(&citation).unwrap().quote, "alpha");
    vault.batch().delete(&id).commit().unwrap();
    assert!(
        vault
            .get_raw_with_mode(&id, ReadMode::Pinned(citation.source_revision_ref))
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        vault.resolve_citation(&citation),
        Err(crate::Error::EntityNotFound)
    ));
    let mut forged = citation;
    forged.quote = "text never present in the deleted entity".into();
    forged.quote_hash = *blake3::hash(forged.quote.as_bytes()).as_bytes();
    assert!(matches!(
        vault.resolve_citation(&forged),
        Err(crate::Error::EntityNotFound)
    ));
}

#[test]
fn pinned_claim_does_not_bypass_current_scoped_admission() {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        ScopedReadActorKey,
    };
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let subject = EntityId::now();
    put(&vault, &subject, "subject");
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "core.fact",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("original"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.source = Some(ClaimSource::Observed);
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let pin = vault.pin_entity_revision(&claim).unwrap();
    crate::test_util::authorize_readers(&vault, &["reader"]);
    let scoped = vault.scoped_read(ScopedReadActorKey::new("reader").unwrap());
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = scoped
        .read(
            &[crate::claim::PointRead::id(claim).at(ReadMode::Pinned(pin))],
            None,
        )
        .unwrap()
        .single();
    assert!(value.is_some());
    vault.retract_claim(&claim, 2).unwrap();
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = scoped
        .read(
            &[crate::claim::PointRead::id(claim).at(ReadMode::Pinned(pin))],
            None,
        )
        .unwrap()
        .single();
    assert!(value.is_none());
}

#[test]
fn phonetic_codes_advance_with_the_idle_indexed_revision() {
    struct Embed;
    impl IndexedRevisionEmbedder for Embed {
        fn embed_revision(&self, _: &IndexedRevisionInput) -> Result<Vec<f32>> {
            Ok(vec![1.0, 0.0, 0.0, 0.0])
        }
    }

    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let id = EntityId::now();
    put(&vault, &id, "first name");
    vault.batch().phonetic(&id, &["OLD"]).commit().unwrap();
    put(&vault, &id, "second name");
    vault.batch().phonetic(&id, &["NEW"]).commit().unwrap();
    let search = |code: &str| {
        vault
            .query()
            .search_phonetic(&[code])
            .run()
            .unwrap()
            .iter()
            .map(|row| row.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(search("OLD"), vec![id]);
    assert!(search("NEW").is_empty());
    vault.set_indexed_idle_delay_ms(0).unwrap();
    vault.refresh_indexed_at_idle(u64::MAX, &Embed).unwrap();
    assert!(search("OLD").is_empty());
    assert_eq!(search("NEW"), vec![id]);
}

#[test]
fn habit_derived_rewrite_retains_the_indexed_body_for_default_pack() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let habit = EntityId::now();
    let raw = rmp_serde::to_vec_named(&serde_json::json!({
        "title": "habitreading", "role": crate::habit::TaskRole::Habit.role_byte()
    }))
    .unwrap();
    vault
        .batch()
        .put(
            &habit,
            crate::registry::ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            1,
            &raw,
        )
        .text(&habit, &[("title", "habitreading")])
        .commit()
        .unwrap();
    let original = vault
        .get_raw_with_mode(&habit, ReadMode::Indexed)
        .unwrap()
        .unwrap();
    let revision = vault.indexed_revision(&habit).unwrap().unwrap();
    let checkin = rmp_serde::to_vec_named(&serde_json::json!({
        "role": crate::habit::TaskRole::HabitCheckin.role_byte()
    }))
    .unwrap();
    vault
        .put_habit_checkin(
            &habit,
            &EntityId::now(),
            TimeRange { start: 2, end: 2 },
            2,
            &checkin,
        )
        .unwrap();
    assert_ne!(vault.get_raw(&habit).unwrap().unwrap(), original);
    assert_eq!(
        vault
            .get_raw_with_mode(&habit, ReadMode::Indexed)
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(vault.indexed_revision(&habit).unwrap(), Some(revision));
    let pack = vault
        .context_pack()
        .search_text("habitreading", 10)
        .run()
        .unwrap();
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, habit);
}

#[test]
fn staged_text_and_vector_survive_reopen_and_publish_without_embedder() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "alpha");
    put(&vault, &id, "beta");
    let revision = vault.pin_entity_revision(&id).unwrap();
    vault
        .batch()
        .text(&id, &[("content", "callerindex")])
        .vector(&id, &[0.0, 0.0, 1.0, 0.0])
        .commit()
        .unwrap();
    assert!(vault.search_text("callerindex", 10).unwrap().is_empty());
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![1.0, 0.0, 0.0, 0.0]
    );
    drop(vault);
    let vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let report = vault.refresh_staged_indexed_at_idle(u64::MAX).unwrap();
    assert_eq!(report.refreshed, vec![(id, revision)]);
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![0.0, 0.0, 1.0, 0.0]
    );
    assert_eq!(vault.search_text("callerindex", 10).unwrap()[0].id, id);
    assert!(vault.search_text("alpha", 10).unwrap().is_empty());
    assert_eq!(
        vault.get_raw_with_mode(&id, ReadMode::Indexed).unwrap(),
        vault.get_raw(&id).unwrap()
    );
}

/// A vector staged for an unpublished revision carries no record of the model
/// that made it, and idle publication prefers it over the embedder. The
/// embedding-space swap drops it and keeps the staged text, so the idle pass
/// embeds that revision with the new model and never publishes the old vector.
#[test]
fn an_embedding_space_swap_drops_staged_vectors_and_keeps_staged_text() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "alpha");
    put(&vault, &id, "beta");
    let revision = vault.pin_entity_revision(&id).unwrap();
    // The old model's vector for the new revision, staged without a token.
    vault
        .batch()
        .text(&id, &[("content", "callerindex")])
        .vector(&id, &[0.0, 0.0, 1.0, 0.0])
        .commit()
        .unwrap();
    drop(vault);

    let mut vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    vault.begin_embedding_migration("test/new@v2").unwrap();
    vault.set_indexed_idle_delay_ms(0).unwrap();
    let report = vault
        .refresh_indexed_at_idle(
            u64::MAX,
            &Embed {
                expected: revision,
                expected_body: body("beta"),
            },
        )
        .unwrap();
    assert_eq!(report.refreshed, vec![(id, revision)]);
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![0.0, 1.0, 0.0, 0.0],
        "the new model's vector, not the staged one"
    );
    assert_eq!(vault.search_text("callerindex", 10).unwrap()[0].id, id);
}

#[test]
fn invalid_deferred_vector_is_refused_before_durable_staging() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "initial");
    put(&vault, &id, "changed");
    assert!(matches!(
        vault.put_vector(&id, &[1.0]),
        Err(crate::Error::DimensionMismatch { .. })
    ));
    assert!(vault.put_vector(&id, &[f32::NAN, 0.0, 0.0, 0.0]).is_err());
    vault.set_indexed_idle_delay_ms(0).unwrap();
    // Neither refused input may supply a vector to the model-free drain.
    let report = vault.refresh_staged_indexed_at_idle(u64::MAX).unwrap();
    assert!(report.refreshed.is_empty());
    assert_eq!(
        report.failed,
        vec![(
            id,
            vault.pin_entity_revision(&id).unwrap(),
            crate::error::ErrorKind::InvalidConfig
        )]
    );
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![1.0, 0.0, 0.0, 0.0]
    );
}

#[test]
fn pack_level_pin_selects_its_entity_from_multiple_hits_and_neighbors() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let a = EntityId::now();
    let b = EntityId::now();
    put(&vault, &a, "shared alpha");
    put(&vault, &b, "shared beta");
    vault
        .put_edge(&a, crate::EdgeKind::Mentions, &b, 1.0)
        .unwrap();
    let pin = vault.pin_entity_revision(&a).unwrap();
    put(&vault, &a, "changed alpha");
    assert_eq!(
        vault
            .context_pack()
            .search_text("shared", 10)
            .run()
            .unwrap()
            .results
            .len(),
        2
    );
    let pack = vault
        .context_pack()
        .search_text("shared", 10)
        .read_mode(ReadMode::Pinned(pin))
        .include_edges(true)
        .edge_hop(1)
        .run()
        .unwrap();
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, a);
    assert_eq!(pack.results[0].source_revision_ref, Some(pin.0));
    assert_eq!(
        pack.results[0].fields.as_ref().unwrap()["content"],
        serde_json::json!("shared alpha")
    );
    assert!(pack.neighbors.iter().all(|entity| entity.id == a));
}

#[test]
fn metadata_only_put_advances_indexed_without_embedding_and_preserves_pins() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    for pin_first in [false, true] {
        let id = EntityId::now();
        put(&vault, &id, "unchanged body");
        let old = vault
            .get_raw_with_mode(&id, ReadMode::Indexed)
            .unwrap()
            .unwrap();
        let original = vault.indexed_revision(&id).unwrap().unwrap();
        if pin_first {
            assert_eq!(vault.pin_entity_revision(&id).unwrap(), original);
        }
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_ASSET_TEXT,
                TimeRange { start: 20, end: 30 },
                40,
                &body("unchanged body"),
            )
            .commit()
            .unwrap();
        let latest = vault.pin_entity_revision(&id).unwrap();
        assert_ne!(latest, original);
        assert_eq!(vault.indexed_revision(&id).unwrap(), Some(latest));
        assert_eq!(
            vault.get_raw_with_mode(&id, ReadMode::Indexed).unwrap(),
            vault.get_raw(&id).unwrap()
        );
        assert_eq!(
            vault
                .get_raw_with_mode(&id, ReadMode::Pinned(original))
                .unwrap(),
            Some(old)
        );
        assert_eq!(
            vault.get_vector(&id).unwrap().unwrap(),
            vec![1.0, 0.0, 0.0, 0.0]
        );
        assert!(
            vault
                .refresh_staged_indexed_at_idle(u64::MAX)
                .unwrap()
                .refreshed
                .is_empty()
        );
        assert!(
            vault
                .search_text("unchanged", 10)
                .unwrap()
                .iter()
                .any(|row| row.id == id)
        );
    }
}

#[test]
fn metadata_only_put_keeps_pending_content_and_staged_inputs_together() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "original body");
    let indexed = vault.indexed_revision(&id).unwrap().unwrap();
    put(&vault, &id, "pending body");
    let before_metadata = vault.pin_entity_revision(&id).unwrap();
    let pending_raw = vault.get_raw(&id).unwrap().unwrap();
    vault
        .batch()
        .text(&id, &[("content", "stagedword")])
        .vector(&id, &[0.0, 1.0, 0.0, 0.0])
        .phonetic(&id, &["NEXT"])
        .commit()
        .unwrap();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_ASSET_TEXT,
            TimeRange { start: 20, end: 30 },
            40,
            &body("pending body"),
        )
        .commit()
        .unwrap();
    let latest = vault.pin_entity_revision(&id).unwrap();
    assert_ne!(latest, before_metadata);
    assert_eq!(vault.indexed_revision(&id).unwrap(), Some(indexed));
    assert!(vault.search_text("stagedword", 10).unwrap().is_empty());
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![1.0, 0.0, 0.0, 0.0]
    );
    assert_eq!(
        vault
            .get_raw_with_mode(&id, ReadMode::Pinned(before_metadata))
            .unwrap(),
        Some(pending_raw)
    );
    vault.set_indexed_idle_delay_ms(0).unwrap();
    assert_eq!(
        vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .unwrap()
            .refreshed,
        vec![(id, latest)]
    );
    assert_eq!(
        vault.get_vector(&id).unwrap().unwrap(),
        vec![0.0, 1.0, 0.0, 0.0]
    );
    assert_eq!(vault.search_text("stagedword", 10).unwrap()[0].id, id);
    assert_eq!(
        vault.query().search_phonetic(&["NEXT"]).run().unwrap()[0].id,
        id
    );
    assert_eq!(
        vault.get_raw_with_mode(&id, ReadMode::Indexed).unwrap(),
        vault.get_raw(&id).unwrap()
    );
}

/// An embedding-space swap drops every vector. A published record no edit is
/// waiting on gets its vector back at idle, embedded by the new model from
/// its published revision; that revision, its text and its citations stay as
/// they were. The same-pin refill does the same.
#[test]
fn a_swap_refills_a_published_record_at_idle_without_a_new_revision() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    put(&vault, &id, "alpha");
    put(&vault, &id, "beta prose");
    let revision = vault.pin_entity_revision(&id).unwrap();
    let embedder = Embed {
        expected: revision,
        expected_body: body("beta prose"),
    };
    let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert_eq!(report.refreshed, vec![(id, revision)]);
    let citation = vault.cite_entity_text(&id, "content", 0, 4).unwrap();
    drop(vault);

    let mut vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    for swap in ["migration", "refill"] {
        if swap == "migration" {
            vault.begin_embedding_migration("test/new@v2").unwrap();
        } else {
            vault.refill_embedding_space().unwrap();
        }
        assert_eq!(vault.get_vector(&id).unwrap(), None, "{swap}");
        let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
        assert_eq!(report.refreshed, vec![(id, revision)], "{swap}");
        assert_eq!(
            vault.get_vector(&id).unwrap(),
            Some(vec![0.0, 1.0, 0.0, 0.0]),
            "{swap}"
        );
        assert_eq!(vault.indexed_revision(&id).unwrap(), Some(revision));
        assert_eq!(vault.pin_entity_revision(&id).unwrap(), revision);
        let resolved = vault.resolve_citation(&citation).unwrap();
        assert_eq!((resolved.quote.as_str(), resolved.drifted), ("beta", false));
        assert_eq!(vault.search_text("beta", 10).unwrap()[0].id, id);
        assert!(
            vault
                .refresh_indexed_at_idle(u64::MAX, &embedder)
                .unwrap()
                .refreshed
                .is_empty(),
            "nothing is left to refill"
        );
    }
}

/// Runs a same-pin refill swap the first time it is asked to embed, as
/// another process may while the provider runs, and returns the vector the
/// space before the swap would have got.
struct SwapsMidEmbed<'a> {
    vault: &'a Vault,
    swapped: std::cell::Cell<bool>,
}
impl IndexedRevisionEmbedder for SwapsMidEmbed<'_> {
    fn embed_revision(&self, _input: &IndexedRevisionInput) -> Result<Vec<f32>> {
        if !self.swapped.replace(true) {
            let model = self.vault.config.embedding_model.clone().unwrap();
            self.vault.with_write_txn(|wtxn| {
                self.vault
                    .swap_embedding_space_in_txn(wtxn, &model, None, true)
                    .map(drop)
            })?;
        }
        Ok(vec![0.0, 0.0, 1.0, 0.0])
    }
}

fn refill_marked(vault: &Vault, id: &EntityId) -> bool {
    let rtxn = vault.store.env.read_txn().unwrap();
    super::vector_refill::REFILL
        .contains(&vault.store, &rtxn, id)
        .unwrap()
}

/// A swap while the provider runs makes its vector one from the space
/// before: it is not written, neither by a publication nor by a refill. The
/// publication's revision stays dirty and the refill's marker stays, so the
/// next pass embeds both in the new space.
#[test]
fn a_swap_while_the_provider_runs_drops_the_old_spaces_vector() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let refilled = EntityId::now();
    put(&vault, &refilled, "alpha");
    put(&vault, &refilled, "beta prose");
    let refilled_revision = vault.pin_entity_revision(&refilled).unwrap();
    let embedder = Embed {
        expected: refilled_revision,
        expected_body: body("beta prose"),
    };
    vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    drop(vault);

    // The vector-only refill.
    let mut vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    vault.refill_embedding_space().unwrap();
    let report = vault
        .refresh_indexed_at_idle(
            u64::MAX,
            &SwapsMidEmbed {
                vault: &vault,
                swapped: std::cell::Cell::new(false),
            },
        )
        .unwrap();
    assert_eq!(report.superseded, vec![refilled]);
    assert!(report.refreshed.is_empty());
    assert_eq!(vault.get_vector(&refilled).unwrap(), None);
    assert!(refill_marked(&vault, &refilled), "the new space's refill");
    let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert_eq!(report.refreshed, vec![(refilled, refilled_revision)]);
    assert_eq!(
        vault.get_vector(&refilled).unwrap(),
        Some(vec![0.0, 1.0, 0.0, 0.0])
    );
    assert!(!refill_marked(&vault, &refilled));

    // The dirty publication.
    let published = EntityId::now();
    put(&vault, &published, "gamma");
    let before = vault.indexed_revision(&published).unwrap();
    put(&vault, &published, "delta prose");
    let revision = vault.pin_entity_revision(&published).unwrap();
    let report = vault
        .refresh_indexed_at_idle(
            u64::MAX,
            &SwapsMidEmbed {
                vault: &vault,
                swapped: std::cell::Cell::new(false),
            },
        )
        .unwrap();
    assert_eq!(report.superseded, vec![published]);
    assert_eq!(vault.indexed_revision(&published).unwrap(), before);
    assert_eq!(vault.get_vector(&published).unwrap(), None);
    assert!(refill_marked(&vault, &published), "the new space's refill");
    let report = vault
        .refresh_indexed_at_idle(
            u64::MAX,
            &Embed {
                expected: revision,
                expected_body: body("delta prose"),
            },
        )
        .unwrap();
    assert!(report.refreshed.contains(&(published, revision)));
    assert_eq!(
        vault.get_vector(&published).unwrap(),
        Some(vec![0.0, 1.0, 0.0, 0.0])
    );
    assert!(!refill_marked(&vault, &published));
}

/// Archiving a record hides it and keeps its body and indexes for a
/// restore. A swap while it is archived leaves it a refill that waits for
/// the restore rather than being dropped as gone; restored, it gets the new
/// space's vector, and its revision and citations are as they were.
#[test]
fn an_archived_record_keeps_its_refill_until_it_is_restored() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::publish_seeded_revisions(&vault);
    let span = TimeRange { start: 1, end: 1 };
    let summary = |text: &str| rmp_serde::to_vec_named(&serde_json::json!({"text": text})).unwrap();
    let id = EntityId::now();
    for text in ["alpha", "beta summary"] {
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_SUMMARY,
                span,
                1,
                &summary(text),
            )
            .commit()
            .unwrap();
    }
    let revision = vault.pin_entity_revision(&id).unwrap();
    let embedder = Embed {
        expected: revision,
        expected_body: summary("beta summary"),
    };
    let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert_eq!(report.refreshed, vec![(id, revision)]);
    assert!(vault.get_vector(&id).unwrap().is_some());
    let citation = vault.cite_entity_text(&id, "text", 0, 4).unwrap();
    assert!(
        vault
            .with_write_txn(|txn| {
                vault.archive_cleanup_candidate_in_txn(
                    txn,
                    &id,
                    &crate::deletion::TombstoneValueV2 {
                        reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
                        deleted_at: 2,
                        request_id: uuid::Uuid::now_v7().into_bytes(),
                    },
                )
            })
            .unwrap(),
        "archived"
    );
    drop(vault);

    let mut vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    vault.begin_embedding_migration("test/new@v2").unwrap();
    let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert!(report.refreshed.is_empty());
    assert!(refill_marked(&vault, &id), "kept while archived");

    vault.restore_archived(&id).unwrap();
    let report = vault.refresh_indexed_at_idle(u64::MAX, &embedder).unwrap();
    assert_eq!(report.refreshed, vec![(id, revision)]);
    assert_eq!(
        vault.get_vector(&id).unwrap(),
        Some(vec![0.0, 1.0, 0.0, 0.0])
    );
    assert_eq!(vault.indexed_revision(&id).unwrap(), Some(revision));
    assert_eq!(vault.pin_entity_revision(&id).unwrap(), revision);
    let resolved = vault.resolve_citation(&citation).unwrap();
    assert_eq!((resolved.quote.as_str(), resolved.drifted), ("beta", false));
    assert!(!refill_marked(&vault, &id));
}
