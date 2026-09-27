fn witness_query_window_pair(facade: &Memory<'_>, now: u64) -> [String; 2] {
    let mut refs = Vec::new();
    for (seed, days_ago) in [(0x67, 40), (0x68, 3)] {
        let receipt = facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([seed; 16]).unwrap().to_hex(),
                turn_ref: None,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::User,
                    "I prefer a window seat when I fly.",
                )],
                occurred_at: now - days_ago * 86_400,
            })
            .expect("witness");
        refs.push(receipt.message_short_ids[0].clone());
    }
    refs.try_into().expect("two messages")
}

#[test]
fn recall_default_effort_reads_last_week_from_the_query() {
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0x69));
    let [older, newer] = witness_query_window_pair(&facade, crate::unix_seconds_now());

    let pack = facade
        .recall(
            "window seat last week",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .map(|item| item.short_id.split('@').next().unwrap_or_default())
        .collect();
    assert!(
        refs.contains(&newer.as_str()),
        "last-week message: {refs:?}"
    );
    assert!(!refs.contains(&older.as_str()), "outside window: {refs:?}");

    for query in [
        "window seat next week",
        "window seat next 2 weeks",
        "window seat last weekend",
        "window seat next weekend",
        "window seat this weekend",
    ] {
        assert!(
            matches!(
                vault
                    .query()
                    .search_text(query, 10)
                    .retrieval_effort(Effort::Medium, &[])
                    .run(),
                Err(crate::Error::InvalidTemporalExpression(_))
            ),
            "{query}"
        );
    }
}

#[test]
fn recall_with_a_host_window_ignores_the_query_range() {
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0x6a));
    let now = crate::unix_seconds_now();
    let [older, newer] = witness_query_window_pair(&facade, now);

    // The facade does not expose host temporal windows; use its underlying
    // context-pack builder with the same Medium effort preset and two messages.
    let pack = vault
        .context_pack()
        .search_text("window seat last week", 10)
        .search_temporal(now - 41 * 86_400, now - 39 * 86_400, 10)
        .filter_occurred_range(now - 41 * 86_400, now - 39 * 86_400)
        .limit(10)
        .retrieval_effort(Effort::Medium, &[])
        .run()
        .expect("host-window pack");
    let older_id = facade.get_entity(&older).unwrap().unwrap().id_hex;
    let newer_id = facade.get_entity(&newer).unwrap().unwrap().id_hex;
    let ids: Vec<String> = pack.results.iter().map(|item| item.id.to_hex()).collect();
    assert!(
        ids.contains(&older_id),
        "host-window message: {ids:?}, older={older_id}"
    );
    assert!(
        !ids.contains(&newer_id),
        "outside host window: {ids:?}, newer={newer_id}"
    );
}

/// ARCH-0004: the blend over recency, salience, confidence and gravity is
/// constant at every effort level. The effort's default now anchor is no
/// host window, so it must not switch recency off. Two identical messages
/// tie on every other blend column; the older one is written first and so
/// holds the lower id, which is the order a recall without recency returns.
#[test]
fn recall_default_effort_ranks_the_newer_identical_message_first() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);
    let now = crate::unix_seconds_now();
    let text = "I prefer a window seat when I fly.";
    let mut witnessed = Vec::new();
    for (seed, days_ago) in [(0x62, 56), (0x63, 28)] {
        let receipt = facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([seed; 16]).unwrap().to_hex(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, text)],
                occurred_at: now - days_ago * 86_400,
            })
            .expect("witness");
        witnessed.push(receipt.message_short_ids[0].clone());
    }
    let [older, newer] = <[String; 2]>::try_from(witnessed).expect("two messages");

    // Medium is the SDKs' default recall effort.
    let pack = facade
        .recall(
            "window seat",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .map(|item| item.short_id.split('@').next().unwrap_or_default())
        .collect();
    let position = |id: &str| refs.iter().position(|item| *item == id);
    let (Some(newer_at), Some(older_at)) = (position(&newer), position(&older)) else {
        panic!("both messages recalled: {refs:?}");
    };
    assert!(newer_at < older_at, "newer message first: {refs:?}");
}

#[test]
fn recall_light_effort_ranks_the_newer_identical_message_first() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);
    let now = crate::unix_seconds_now();
    let text = "I prefer a window seat when I fly.";
    let mut witnessed = Vec::new();
    for (seed, days_ago) in [(0x62, 56), (0x63, 28)] {
        let receipt = facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([seed; 16]).unwrap().to_hex(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, text)],
                occurred_at: now - days_ago * 86_400,
            })
            .expect("witness");
        witnessed.push(receipt.message_short_ids[0].clone());
    }
    let [older, newer] = <[String; 2]>::try_from(witnessed).expect("two messages");

    let pack = facade
        .recall(
            "window seat",
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .map(|item| item.short_id.split('@').next().unwrap_or_default())
        .collect();
    let position = |id: &str| refs.iter().position(|item| *item == id);
    let (Some(newer_at), Some(older_at)) = (position(&newer), position(&older)) else {
        panic!("both messages recalled: {refs:?}");
    };
    assert!(newer_at < older_at, "newer message first: {refs:?}");
}

#[test]
fn recall_light_effort_ranks_a_salient_claim_above_an_identical_plain_one() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x67);
    let facade = facade_for(&vault, actor);
    let mut ids = Vec::new();
    // Distinct subjects avoid claim supersession; their indexed claim text,
    // confidence and timestamps match. Write the plain claim first.
    for (seed, salience) in [(0x68, None), (0x69, Some(0.9))] {
        let subject = put_person(&vault, seed);
        let mut input = claim_input(
            "preference.lighting",
            &subject,
            "user_stated",
            serde_json::json!("amber lantern"),
        );
        input.id = Some(EntityId::from_bytes([seed + 2; 16]).unwrap().to_hex());
        input.salience = salience;
        let receipt = facade.claim_upsert(&input).expect("claim");
        assert_eq!(receipt.approval, "auto");
        let claim_id = EntityId::from_hex(input.id.as_deref().unwrap()).unwrap();
        vault
            .batch()
            .text(&claim_id, &[("body", "amber lantern")])
            .commit()
            .expect("index claim text");
        ids.push(short_id_part(&receipt.claim_short_id).to_owned());
    }
    let [plain, salient] = <[String; 2]>::try_from(ids).expect("two claims");
    let pack = facade
        .recall(
            "amber lantern",
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .map(|item| short_id_part(item.short_id.split('@').next().unwrap_or_default()))
        .collect();
    let position = |id: &str| refs.iter().position(|item| *item == id);
    let (Some(salient_at), Some(plain_at)) = (position(&salient), position(&plain)) else {
        panic!("both claims recalled: {refs:?}");
    };
    assert!(salient_at < plain_at, "salient claim first: {refs:?}");
}
