// A caller off this device is answered alike whatever a device-local world
// holds (DEC-0005), on every recall route.

/// Sol R18 on this branch, after #1425: a facet-scoped recall built its
/// pipeline without its caller's locality. The rows a device-local world
/// keeps entered its lists, and the read lane dropped them only after
/// fusion, so they still scaled the scores of the rows a caller off this
/// device reads. Hidden phonetic hits in such a world turned the order of
/// its answer. Here 39 hits, with the one visible hit, fill half the
/// phonetic list's 80 places: the visible hit falls from z 8.9 to 1, below
/// the row with the strongest vector.
#[test]
fn a_device_local_world_moves_no_row_an_off_device_facet_recall_returns() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let put = |id: &EntityId, entity_type: u8, body: &[u8]| {
        vault
            .put_entity(
                id,
                entity_type,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .expect("put a row");
    };
    let facet = crate::test_util::entity(0x64);
    put(
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        &rmp_serde::to_vec_named(&serde_json::json!({"name": "facet"})).expect("facet body"),
    );
    let world = crate::test_util::entity(0x61);
    put(&world, crate::registry::ENTITY_TYPE_WORLD, b"world");
    vault
        .set_world_device_only(world, true)
        .expect("flag the world");
    // A claim whose words match nothing the recall asks, with a vector and
    // the phonetic code it asks for, if any.
    let claim = |id: EntityId, world: Option<EntityId>, vector: Option<[f32; 4]>, code: bool| {
        remember_claim(&vault, owner, id, world, "a quiet harbour note");
        let mut batch = vault.batch();
        if let Some(vector) = vector {
            batch = batch.vector(&id, &vector);
        }
        if code {
            batch = batch.phonetic(&id, &["LNTRN"]);
        }
        batch.commit().expect("index the claim");
    };
    let index = || {
        vault.set_indexed_idle_delay_ms(0).expect("idle delay");
        vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .expect("publish the index");
    };
    // The one phonetic hit has the weakest vector, another row the strongest
    // and six more sit between: vector z -2, +2 and 0.
    claim(
        crate::test_util::entity(0x70),
        None,
        Some([0.0, 1.0, 0.0, 0.0]),
        true,
    );
    claim(
        crate::test_util::entity(0x71),
        None,
        Some([1.0, 0.0, 0.0, 0.0]),
        false,
    );
    for byte in 0x72..0x78 {
        claim(crate::test_util::entity(byte), None, Some([0.5; 4]), false);
    }
    index();
    let answer = || -> Vec<String> {
        facade_for(&vault, owner)
            .at(crate::claim::CallerLocality::OffDevice)
            .recall_with_execution(
                "lantern",
                Effort::Light,
                &crate::memory::RecallScope {
                    facet: Some(facet.to_hex()),
                    world_ref: Some(world.to_hex()),
                    ..Default::default()
                },
                3,
                None,
                None,
                &crate::retrieval_depth::RecallExecution {
                    embedding: Some(&[1.0, 0.0, 0.0, 0.0]),
                    phonetic_codes: &["LNTRN"],
                    ..Default::default()
                },
            )
            .expect("recall")
            .items
            .into_iter()
            .map(|item| item.short_id)
            .collect()
    };

    let alone = answer();
    for _ in 0..39 {
        claim(EntityId::now(), Some(world), None, true);
    }
    index();
    let beside_hidden_hits = answer();

    assert_eq!(alone.len(), 3, "{alone:?}");
    assert_eq!(alone, beside_hidden_hits);
}
