/// The Node SDK count-limits fixture: the embedded owner witnesses one
/// conversation with one turn "window seat" and claims on the turn. The store
/// clock ticks in whole seconds, so the first compared recall lands in the
/// tick the fixture was written and the second one tick later. The TURN and
/// the CONVERSATION tie on every blend column but recency, and both recalls
/// must rank them the same way. A first recall fills the PPR cache, as the
/// Node test's earlier recalls do, so the compared packs differ in nothing
/// but what the clock could move.
#[test]
fn identical_recalls_return_the_same_pack_across_a_clock_tick() {
    // The seconds are held still while ids stay time-ordered, as they are
    // under the system clock the SDK runs on.
    struct TimeOrderedIds;
    impl crate::ports::IdGen for TimeOrderedIds {
        fn ulid(&self) -> [u8; 16] {
            uuid::Uuid::now_v7().into_bytes()
        }
    }
    let written = crate::unix_seconds_now();
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = crate::ports::ManualClock::new(written);
    let config = crate::config::VaultConfig {
        store_clock: crate::ports::StoreClock::new(
            clock.clone(),
            std::sync::Arc::new(TimeOrderedIds),
        ),
        ..crate::config::VaultConfig::default()
    };
    let vault = crate::Vault::open(dir.path(), config).expect("open vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let facade = facade_for(&vault, actor);
    let witnessed = facade
        .witness(&WitnessTurn {
            conversation_ref: "11111111111111111111111111111111".to_owned(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "window seat")],
            occurred_at: written,
        })
        .expect("witness");
    facade
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "preference.travel.seat".to_owned(),
            subject_ref: witnessed.turn_short_id,
            value: serde_json::json!({ "seat": "window" }),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("claim");

    // The turn and conversation come back only when the scope names them.
    let scope = RecallScope {
        kinds: Some(
            ["CLAIM", "MESSAGE", "TURN", "CONVERSATION"]
                .map(str::to_owned)
                .to_vec(),
        ),
        ..RecallScope::default()
    };
    let recall = || {
        facade
            .recall("window seat", Effort::Medium, &scope, 10, None, None)
            .expect("recall")
    };
    recall();
    let in_the_written_tick = recall();
    clock.set(written + 1);
    let one_tick_later = recall();

    let kinds: Vec<&str> = in_the_written_tick
        .items
        .iter()
        .map(|item| item.kind.as_str())
        .collect();
    assert!(
        ["CLAIM", "TURN", "CONVERSATION"]
            .iter()
            .all(|kind| kinds.contains(kind)),
        "the fixture recalls the claim and the tied TURN and CONVERSATION: {kinds:?}"
    );
    assert_eq!(in_the_written_tick, one_tick_later);
}

#[test]
fn world_scoped_last_week_recall_keeps_eligible_hit_at_limit_one() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xE1);
    let facade = facade_for(&vault, actor);
    let now = crate::unix_seconds_now();
    let eligible_world = EntityId::from_bytes([0xE2; 16]).unwrap();
    let other_world = EntityId::from_bytes([0xE3; 16]).unwrap();
    let scope = RecallScope {
        world_ref: Some(eligible_world.to_hex()),
        facet: None,
        kinds: None,
    };
    for (seed, world, days) in [(0xE4, eligible_world, 60), (0xE5, other_world, 3)] {
        let subject = put_person(&vault, seed);
        let mut claim = claim_input(
            "preference.color",
            &subject,
            "user_stated",
            serde_json::json!("amber"),
        );
        claim.world_ref = Some(world.to_hex());
        claim.occurred_at = Some(now - 3 * 86_400);
        claim.learned_at = Some(now - days * 86_400);
        assert_eq!(facade.claim_upsert(&claim).unwrap().approval, "auto");
    }
    let wide = facade
        .recall("last week", Effort::Light, &scope, 10, None, None)
        .unwrap();
    assert_eq!(wide.items.len(), 1);
    let narrow = facade
        .recall("last week", Effort::Light, &scope, 1, None, None)
        .unwrap();
    assert_eq!(narrow.items.len(), 1);
    assert_eq!(
        narrow.items[0].world.as_deref(),
        Some(eligible_world.to_hex().as_str())
    );
}
