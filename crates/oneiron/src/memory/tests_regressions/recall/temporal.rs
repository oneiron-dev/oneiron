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
