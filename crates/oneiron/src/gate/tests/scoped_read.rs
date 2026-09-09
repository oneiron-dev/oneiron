//! Scoped read and retrieval filtering: core-read grants, context-pack scrubbing, and facet edges.

use super::*;

#[test]
fn scoped_read_actor_key_rejects_unkeyed_bulk_bypass() {
    assert!(ScopedReadActorKey::new("").is_none());
    assert!(ScopedReadActorKey::new("   ").is_none());
    assert_eq!(
        ScopedReadActorKey::new(" reader ")
            .expect("trimmed actor key")
            .actor_ref(),
        "reader"
    );
}

#[test]
fn scoped_read_core_read_world_scope_contains_actor_readable_claims() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x31);
    let other_world = test_id(0x32);
    let data = encode_policy_manifest(vec![core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x61), &data)?;
    let policy = resolve(&vault)?;
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert_eq!(policy.scoped_grants().len(), 1);
    assert_eq!(
        policy.scoped_grants()[0].actor_ref.as_deref(),
        Some("reader")
    );
    assert_eq!(
        policy.scoped_grants()[0].effector,
        SCOPED_READ_EFFECTOR_CORE_READ
    );
    assert!(scoped_read_entity_id_from_value(&Value::from(world.to_hex())).is_some());

    let base_id = test_id(0xA0);
    let allowed_id = test_id(0x5A);
    let denied_id = test_id(0x5C);

    let base = source_trust_claim(ClaimSource::UserStated);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(other_world);
    put_claim_body(&vault, &base_id, &base)?;
    put_claim_body(&vault, &allowed_id, &allowed)?;
    put_claim_body(&vault, &denied_id, &denied)?;

    assert!(scoped_read_claim_allowed(&policy, &actor_key, &base, &[]));
    assert!(scoped_read_claim_allowed(
        &policy,
        &actor_key,
        &allowed,
        &[]
    ));
    assert!(!scoped_read_claim_allowed(
        &policy,
        &actor_key,
        &denied,
        &[]
    ));

    let scoped_read = vault.scoped_read(actor_key);
    let ids: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: base_id,
                score: 1.0,
            },
            ScoredEntity {
                id: allowed_id,
                score: 0.9,
            },
            ScoredEntity {
                id: denied_id,
                score: 0.8,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(ids, vec![base_id, allowed_id]);

    let other_actor =
        vault.scoped_read(ScopedReadActorKey::new("other-reader").expect("actor key"));
    assert!(
        other_actor
            .filter_scored_entities(vec![ScoredEntity {
                id: allowed_id,
                score: 1.0,
            }])?
            .is_empty(),
        "a core:read grant for one actor must not create a vault-wide read lane"
    );

    Ok(())
}

#[test]
fn scoped_read_receipt_required_core_grants_fail_closed_without_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x33);
    let data = encode_policy_manifest(vec![receipt_required_core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x6C), &data)?;

    let id = test_id(0x34);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.world = Some(world);
    put_claim_body(&vault, &id, &body)?;

    let policy = resolve(&vault)?;
    assert_eq!(policy.scoped_grants().len(), 1);
    assert!(policy.scoped_grants()[0].receipt_required);
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert!(
        !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
        "ScopedReadActorKey does not carry a consent receipt, so receipt-required grants must fail closed"
    );

    let scoped_read = vault.scoped_read(actor_key);
    assert!(scoped_read.get(&id)?.is_none());
    Ok(())
}

#[test]
fn scoped_read_budgeted_core_grants_fail_closed_without_budget_enforcer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x3A);
    let data = encode_policy_manifest(vec![budgeted_core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, test_id(0x3B), &data)?;

    let id = test_id(0x3C);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.world = Some(world);
    put_claim_body(&vault, &id, &body)?;

    let policy = resolve(&vault)?;
    assert_eq!(policy.scoped_grants().len(), 1);
    assert!(policy.scoped_grants()[0].budget.is_some());
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert!(
        !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
        "ScopedRead has no read-budget counter or receipt state, so budgeted grants must fail closed"
    );

    let scoped_read = vault.scoped_read(actor_key);
    assert!(scoped_read.get(&id)?.is_none());
    Ok(())
}

#[test]
fn scoped_read_without_core_grants_preserves_claim_surfaceable_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x62), &encode_policy_manifest(vec![]))?;

    let live_id = test_id(0xB0);
    let proposed_id = test_id(0xB1);
    let stale_id = test_id(0xB2);

    let live = source_trust_claim(ClaimSource::UserStated);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let mut stale = source_trust_claim(ClaimSource::UserStated);
    stale.stale = true;

    assert!(crate::claim::claim_surfaceable(&live));
    assert!(!crate::claim::claim_surfaceable(&proposed));
    assert!(!crate::claim::claim_surfaceable(&stale));

    put_claim_body(&vault, &live_id, &live)?;
    put_claim_body(&vault, &proposed_id, &proposed)?;
    put_claim_body(&vault, &stale_id, &stale)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(scoped_read.get(&live_id)?.is_some());
    assert!(scoped_read.get(&proposed_id)?.is_none());
    assert!(scoped_read.get(&stale_id)?.is_none());

    let visible: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: live_id,
                score: 1.0,
            },
            ScoredEntity {
                id: proposed_id,
                score: 0.9,
            },
            ScoredEntity {
                id: stale_id,
                score: 0.8,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(visible, vec![live_id]);
    Ok(())
}

#[test]
fn scoped_read_hybrid_candidate_limit_uses_text_vector_union() -> Result<()> {
    let _tmp = tempfile::tempdir().expect("temp dir");
    let mut config = crate::config::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("scoped/read@test-model".to_owned());
    let vault = crate::Vault::open(_tmp.path(), config)?;
    let world = test_id(0x39);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3D),
        &core_read_world_grant_manifest("reader", world),
    )?;
    for seed in [0x3E, 0x3F] {
        put_text_entity(
            &vault,
            &test_id(seed),
            crate::registry::ENTITY_TYPE_PERSON,
            "hybrid-union",
            serde_json::json!({"name": format!("text-{seed}")}),
        )?;
    }
    for (seed, vector) in [
        (0x40, [1.0_f32, 0.0, 0.0, 0.0]),
        (0x41, [0.0_f32, 1.0, 0.0, 0.0]),
        (0x43, [0.0_f32, 0.0, 1.0, 0.0]),
    ] {
        put_vector_entity(&vault, &test_id(seed), &vector)?;
    }

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert_eq!(scoped_read.search_candidate_limit(1, true, false)?, 2);
    assert_eq!(scoped_read.search_candidate_limit(1, false, true)?, 3);
    assert_eq!(
        scoped_read.search_candidate_limit(1, true, true)?,
        5,
        "hybrid scoped search must fetch the possible text/vector union before actor filtering"
    );
    Ok(())
}

#[test]
fn scoped_read_core_grant_preserves_claim_surfaceable_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0xC0);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x63),
        &core_read_world_grant_manifest("reader", world),
    )?;

    let live_id = test_id(0xC1);
    let proposed_id = test_id(0xC2);
    let mut live = source_trust_claim(ClaimSource::UserStated);
    live.world = Some(world);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.world = Some(world);
    proposed.approval = ClaimApprovalStatus::Proposed;
    put_claim_body(&vault, &live_id, &live)?;
    put_claim_body(&vault, &proposed_id, &proposed)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(scoped_read.get(&live_id)?.is_some());
    assert!(
        scoped_read.get(&proposed_id)?.is_none(),
        "matching scoped grant must still preserve claim_surfaceable"
    );
    let visible: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: proposed_id,
                score: 1.0,
            },
            ScoredEntity {
                id: live_id,
                score: 0.9,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(visible, vec![live_id]);
    Ok(())
}

#[test]
fn scoped_read_search_filters_before_limit_truncation() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xC3);
    let denied_world = test_id(0xC4);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x64),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let denied_ids = [
        test_id(0xC5),
        test_id(0xC6),
        test_id(0xC7),
        test_id(0xC8),
        test_id(0xC9),
    ];
    for (index, id) in denied_ids.iter().enumerate() {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.world = Some(denied_world);
        let text = std::iter::repeat_n("scopedslots", 10 - index)
            .collect::<Vec<_>>()
            .join(" ");
        put_claim_text_body(&vault, id, &text, &body)?;
    }

    let allowed_id = test_id(0xCA);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    put_claim_text_body(&vault, &allowed_id, "scopedslots", &allowed)?;

    let unscoped_top = vault.search_text("scopedslots", denied_ids.len())?;
    assert!(
        !unscoped_top.iter().any(|hit| hit.id == allowed_id),
        "test setup must place denied hits ahead of the allowed claim"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let visible: Vec<_> = scoped_read
        .search_text("scopedslots", 1, None)?
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(visible, vec![allowed_id]);
    Ok(())
}

#[test]
fn scoped_read_hydrate_preserves_dangling_short_id_result() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x65), &encode_policy_manifest(vec![]))?;

    let missing_id = test_id(0xCB);
    put_dangling_short_id(&vault, "cldangling", 0x5A, &missing_id)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let hydrated = scoped_read
        .hydrate_short_id("cldangling", 0x5A)?
        .expect("dangling short id should surface deletion metadata");
    assert_eq!(hydrated.id, missing_id);
    assert!(hydrated.body.is_none());
    assert_eq!(
        hydrated
            .deletion
            .expect("dangling short id deletion")
            .source,
        crate::deletion::HydratedShortIdDeletionSource::DanglingShortId
    );
    Ok(())
}

#[test]
fn scoped_read_hydrate_preserves_deleted_claim_short_id_metadata() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x6F), &encode_policy_manifest(vec![]))?;

    let claim_id = test_id(0xD0);
    put_claim_body(
        &vault,
        &claim_id,
        &source_trust_claim(ClaimSource::UserStated),
    )?;
    let short_id = "cldeleted";
    let content_hash = 0x5B;
    put_dangling_short_id(&vault, short_id, content_hash, &claim_id)?;

    let outcome =
        vault.delete_entity_with_reason(&claim_id, crate::deletion::DeleteReason::UserDelete)?;
    assert!(outcome.existed);

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let hydrated = scoped_read
        .hydrate_short_id(short_id, content_hash)?
        .expect("deleted claim short id should preserve deletion metadata");
    assert_eq!(hydrated.id, claim_id);
    assert_eq!(hydrated.entity_type, crate::registry::ENTITY_TYPE_CLAIM);
    assert!(hydrated.body.is_none());
    let deletion = hydrated.deletion.expect("deleted claim metadata");
    assert!(matches!(
        deletion.source,
        crate::deletion::HydratedShortIdDeletionSource::Tombstone
            | crate::deletion::HydratedShortIdDeletionSource::PendingTombstone
    ));
    assert_eq!(
        deletion.reason,
        Some(crate::deletion::HydratedShortIdDeletionReason::UserDelete)
    );
    assert!(!deletion.hard);
    Ok(())
}

#[test]
fn scoped_read_context_pack_scrubs_edges_to_denied_claims() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xCC);
    let denied_world = test_id(0xCD);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x66),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let source = test_id(0xCE);
    let denied_claim = test_id(0xCF);
    let claim_subject = test_id(0x21);
    put_text_entity(
        &vault,
        &source,
        crate::registry::ENTITY_TYPE_TURN,
        "edgevisible",
        serde_json::json!({"text": "edgevisible"}),
    )?;
    put_text_entity(
        &vault,
        &claim_subject,
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &denied_claim, &denied)?;
    vault.put_edge(&source, EdgeKind::Supports, &denied_claim, 0.7)?;

    let mut pack = vault
        .context_pack()
        .search_text("edgevisible", 10)
        .include_edges(true)
        .run()?;
    assert!(
        pack.results
            .iter()
            .flat_map(|entity| entity.edges.iter().flatten())
            .any(|edge| edge.target == denied_claim),
        "test setup should hydrate the denied target edge before scoped filtering"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    let leaked = pack
        .results
        .iter()
        .chain(pack.neighbors.iter())
        .flat_map(|entity| entity.edges.iter().flatten())
        .any(|edge| edge.target == denied_claim);
    assert!(
        !leaked,
        "scoped context-pack edges must not reveal denied claims"
    );
    Ok(())
}

/// One CLAIM, one FACET, and a `core:read` grant scoped to that facet. No
/// `FacetOf` edge yet, so the grant does not reach the claim.
fn facet_scoped_read_fixture(vault: &crate::Vault) -> Result<(EntityId, EntityId)> {
    let facet = test_id(0x7A);
    let claim = test_id(0x7B);
    put_policy_manifest_bytes(
        vault,
        test_id(0x7C),
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;
    put_text_entity(
        vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;
    put_text_entity(
        vault,
        &test_id(0x21),
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    put_claim_body(vault, &claim, &source_trust_claim(ClaimSource::UserStated))?;
    Ok((claim, facet))
}

/// The `edges_out` key one `FacetOf` edge occupies, and a well-formed value
/// for it. The facet scan reads the KEY only, so the value just has to be a
/// parseable edge record.
fn facet_edge_row(claim: EntityId, facet: EntityId) -> (Vec<u8>, [u8; 12]) {
    let mut key = crate::vault::edge_kind_prefix(&claim, EdgeKind::FacetOf).to_vec();
    key.extend_from_slice(facet.as_bytes());
    let mut value = [0_u8; 12];
    value[0..4].copy_from_slice(&0.7_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    (key, value)
}

#[test]
fn a_session_staged_facet_edge_authorizes_a_facet_scoped_read() -> Result<()> {
    // A facet-scoped grant matches on the facets a claim carries, so those
    // facets are the grant's subject matter. A scoped read opened in a session
    // composes overlay over base for every other edge scan it does; reading
    // the facets from base alone would decide the session's own permissions
    // against a graph the session cannot see.
    let (_tmp, vault) = temp_vault();
    let (claim, facet) = facet_scoped_read_fixture(&vault)?;
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");

    // No `FacetOf` edge anywhere yet: the grant reaches nothing.
    assert!(
        vault.scoped_read(actor_key.clone()).get(&claim)?.is_none(),
        "a facet-scoped grant must not read a claim carrying no facet"
    );

    let (key, value) = facet_edge_row(claim, facet);
    let overlay = crate::session_overlay::SessionOverlay::new(64 * 1024);
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::EdgesOut,
        &key,
        &value,
    )?;
    segment.commit()?;

    let view = vault.store.session_view(overlay)?;
    assert!(
        vault
            .scoped_read_in_session(actor_key.clone(), &view)
            .get(&claim)?
            .is_some(),
        "a `FacetOf` edge staged in the room authorizes in the room"
    );
    assert!(
        vault.scoped_read(actor_key).get(&claim)?.is_none(),
        "and nowhere else: the canonical handle still reads base only"
    );
    Ok(())
}

#[test]
fn a_session_tombstoned_facet_edge_stops_authorizing() -> Result<()> {
    // The other direction. A room that retracted the `FacetOf` edge has
    // retracted what the grant was matching on, so the read it authorized must
    // stop — while the canonical handle, which never saw the retraction, goes
    // on reading exactly as before.
    let (_tmp, vault) = temp_vault();
    let (claim, facet) = facet_scoped_read_fixture(&vault)?;
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    vault.put_edge(&claim, EdgeKind::FacetOf, &facet, 0.7)?;
    assert!(
        vault.scoped_read(actor_key.clone()).get(&claim)?.is_some(),
        "the base facet edge authorizes the base read"
    );

    let (key, _) = facet_edge_row(claim, facet);
    let overlay = crate::session_overlay::SessionOverlay::new(64 * 1024);
    let segment = overlay.install_txn_segment()?;
    overlay.delete_with_base_backing(
        crate::session_overlay::OverlayKeyspace::EdgesOut,
        &key,
        true,
    )?;
    segment.commit()?;

    let view = vault.store.session_view(overlay)?;
    assert!(
        vault
            .scoped_read_in_session(actor_key.clone(), &view)
            .get(&claim)?
            .is_none(),
        "a facet the room tombstoned must stop authorizing inside the room"
    );
    assert!(
        vault.scoped_read(actor_key).get(&claim)?.is_some(),
        "and the canonical handle is untouched"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_drops_neighbors_reached_only_from_filtered_results() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x6E);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;

    let denied_seed = test_id(0x71);
    let readable_neighbor = test_id(0x72);
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;
    put_text_entity(
        &vault,
        &test_id(0x21),
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    let denied = source_trust_claim(ClaimSource::UserStated);
    put_claim_text_body(&vault, &denied_seed, "neighborleak", &denied)?;
    put_text_entity(
        &vault,
        &readable_neighbor,
        crate::registry::ENTITY_TYPE_PERSON,
        "neighbor target",
        serde_json::json!({"name": "neighbor"}),
    )?;
    vault.put_edge(&denied_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

    let mut pack = vault
        .context_pack()
        .search_text("neighborleak", 10)
        .edge_hop(1)
        .max_neighbors(10)
        .run()?;
    assert!(
        pack.results.iter().any(|entity| entity.id == denied_seed),
        "test setup should surface the denied primary result before scoped filtering"
    );
    assert!(
        pack.neighbors
            .iter()
            .any(|entity| entity.id == readable_neighbor),
        "test setup should expand to the readable neighbor before scoped filtering"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    assert!(
        pack.results.is_empty(),
        "the denied primary seed should be removed"
    );
    assert!(
        pack.neighbors.is_empty(),
        "neighbors reached only through a denied primary seed must not remain visible"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_retains_neighbors_reached_from_kept_results_without_edges() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0x73);
    let denied_world = test_id(0x74);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x75),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let kept_seed = test_id(0x76);
    let denied_seed = test_id(0x77);
    let readable_neighbor = test_id(0x78);
    put_text_entity(
        &vault,
        &kept_seed,
        crate::registry::ENTITY_TYPE_TURN,
        "kept seed",
        serde_json::json!({"text": "kept seed"}),
    )?;
    put_text_entity(
        &vault,
        &readable_neighbor,
        crate::registry::ENTITY_TYPE_PERSON,
        "readable neighbor",
        serde_json::json!({"name": "readable neighbor"}),
    )?;
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &denied_seed, &denied)?;
    vault.put_edge(&kept_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

    let entity = |id: EntityId, entity_type: u8, score: f32| ContextEntity {
        id,
        short_id: id.to_hex(),
        content_hash: 0,
        entity_type,
        score,
        fields: None,
        edges: None,
        vector: None,
    };
    let mut pack = ContextPack {
        retrieval_quality: Default::default(),
        results: vec![
            entity(kept_seed, crate::registry::ENTITY_TYPE_TURN, 1.0),
            entity(denied_seed, crate::registry::ENTITY_TYPE_CLAIM, 0.9),
        ],
        neighbors: vec![entity(
            readable_neighbor,
            crate::registry::ENTITY_TYPE_PERSON,
            0.0,
        )],
        stats: PackStats {
            candidates_considered: 2,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 2,
            neighbors_hydrated: 1,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: PackTokenStats::default(),
            items_truncated: PackItemAccounting::item_budget(),
            items_dropped: PackItemAccounting::token_budget(),
        },
        empty: None,
    };

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    assert_eq!(
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![kept_seed]
    );
    assert_eq!(
        pack.neighbors
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![readable_neighbor],
        "omitted serialized edges must not cause readable neighbors from kept seeds to be pruned"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_filters_before_response_limit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x5E);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x6B),
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;
    put_text_entity(
        &vault,
        &test_id(0x21),
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;

    let denied_ids = [test_id(0xE3), test_id(0xE4), test_id(0xE5), test_id(0xE6)];
    for (index, id) in denied_ids.iter().enumerate() {
        let body = source_trust_claim(ClaimSource::UserStated);
        let text = std::iter::repeat_n("packslots", 8 - index)
            .collect::<Vec<_>>()
            .join(" ");
        put_claim_text_body(&vault, id, &text, &body)?;
    }

    let allowed_id = test_id(0xE7);
    let allowed = source_trust_claim(ClaimSource::UserStated);
    put_claim_text_body(&vault, &allowed_id, "packslots", &allowed)?;
    vault.put_edge(&allowed_id, EdgeKind::FacetOf, &facet, 0.7)?;

    let unscoped_top = vault
        .context_pack()
        .limit(denied_ids.len())
        .search_text("packslots", denied_ids.len())
        .run()?;
    assert!(
        !unscoped_top
            .results
            .iter()
            .any(|entity| entity.id == allowed_id),
        "test setup must place denied pack results ahead of the allowed claim"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let candidate_limit = scoped_read.search_candidate_limit(1, true, false)?;
    let mut pack = vault
        .context_pack()
        .limit(candidate_limit)
        .retrieval_budget(crate::context_pack::ContextPackRetrievalBudget::new(
            candidate_limit,
            candidate_limit,
            candidate_limit,
            candidate_limit,
            candidate_limit,
            crate::context_pack::DEFAULT_MAX_NEIGHBORS,
        ))
        .search_text("packslots", candidate_limit)
        .run()?;
    scoped_read.filter_context_pack(&mut pack)?;
    pack.results.truncate(1);
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, allowed_id);
    Ok(())
}

#[test]
fn scoped_read_memory_timeline_prunes_links_to_filtered_records() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xD0);
    let denied_world = test_id(0xD1);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x67),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let old = test_id(0xD2);
    let new = test_id(0xD3);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    put_claim_body(&vault, &old, &denied)?;
    put_claim_body(&vault, &new, &allowed)?;
    vault.put_edge(&new, EdgeKind::Supersedes, &old, 0.3)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let timeline = scoped_read.memory_timeline(&new)?;
    assert_eq!(timeline.records.len(), 1);
    let record = &timeline.records[0];
    assert_eq!(record.id, new);
    assert!(record.supersedes.is_empty());
    assert!(record.superseded_by.is_empty());
    Ok(())
}

#[test]
fn scoped_read_memory_timeline_rejects_unreadable_anchor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0x5D);
    let denied_world = test_id(0xD8);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x69),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let old = test_id(0xD9);
    let denied_anchor = test_id(0xDA);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &old, &allowed)?;
    put_claim_body(&vault, &denied_anchor, &denied)?;
    vault.put_edge(&denied_anchor, EdgeKind::Supersedes, &old, 0.3)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let timeline = scoped_read.memory_timeline(&denied_anchor)?;
    assert!(
        timeline.records.is_empty(),
        "unreadable anchors must not reveal readable chain neighbors"
    );
    Ok(())
}

#[test]
fn scoped_read_edges_out_scrubs_denied_sources_and_targets() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xDB);
    let denied_world = test_id(0xDC);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x6A),
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let source = test_id(0xDD);
    let allowed_claim = test_id(0xDE);
    let denied_claim = test_id(0xDF);
    put_text_entity(
        &vault,
        &source,
        crate::registry::ENTITY_TYPE_TURN,
        "source",
        serde_json::json!({"text": "source"}),
    )?;
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &allowed_claim, &allowed)?;
    put_claim_body(&vault, &denied_claim, &denied)?;
    vault.put_edge(&source, EdgeKind::Supports, &allowed_claim, 0.7)?;
    vault.put_edge(&source, EdgeKind::Opposes, &denied_claim, 0.7)?;

    let denied_source = test_id(0xE0);
    put_claim_body(&vault, &denied_source, &denied)?;
    vault.put_edge(&denied_source, EdgeKind::Supports, &allowed_claim, 0.7)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let edges = scoped_read
        .edges_out(&source)?
        .expect("readable source should return scoped edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].target, allowed_claim);
    assert!(
        scoped_read.edges_out(&denied_source)?.is_none(),
        "denied edge sources must not reveal outgoing relationships"
    );
    Ok(())
}

#[test]
fn scoped_read_facet_grants_match_facet_of_edges() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xD4);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x68),
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;

    let faceted_claim = test_id(0xD5);
    let unfaceted_claim = test_id(0xD6);
    let body = source_trust_claim(ClaimSource::UserStated);
    put_claim_body(&vault, &faceted_claim, &body)?;
    put_claim_body(&vault, &unfaceted_claim, &body)?;
    vault.put_edge(&faceted_claim, EdgeKind::FacetOf, &facet, 0.7)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(
        scoped_read.get(&faceted_claim)?.is_some(),
        "facet grant must match the claim's outgoing FacetOf edge"
    );
    assert!(
        scoped_read.get(&unfaceted_claim)?.is_none(),
        "facet grant must not fall through to unfaceted claims"
    );
    Ok(())
}
