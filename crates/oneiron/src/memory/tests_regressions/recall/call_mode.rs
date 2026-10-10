// Call mode (retrieval hub #call-mode): recall under a hard deadline, through the
// SDK door every recall door lands on.

/// One recall through the SDK door, with `vector` as the query's embedding.
fn recall_at(
    facade: &Memory<'_>,
    query: &str,
    effort: crate::memory::RecallEffort,
    deadline_ms: Option<u64>,
    vector: Option<&[f32]>,
) -> crate::memory::MemoryPack {
    crate::task_verb::sdk::recall_with_vector(
        facade,
        crate::task_verb::sdk::RecallRequest {
            query: query.to_owned(),
            effort: Some(effort),
            scope: None,
            limit: Some(20),
            format: None,
            as_of: None,
            deadline_ms,
        },
        |_| vector.map(<[f32]>::to_vec),
    )
    .expect("recall")
}

/// Witnesses one user message, `age_days` before now, in its own conversation.
fn witness_said(facade: &Memory<'_>, conversation: u8, said: &str, age_days: u64) {
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([conversation; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, said)],
            occurred_at: crate::unix_seconds_now() - age_days * 86_400,
        })
        .expect("witness");
}

/// Whether the pack hands its reader `said`: in an item or a message it cites.
fn pack_gives(pack: &crate::memory::MemoryPack, said: &str) -> bool {
    pack.items.iter().any(|item| {
        item.value_text.contains(said)
            || item
                .cited_messages
                .iter()
                .any(|message| message.value_text.contains(said))
    })
}

/// A slow channel never holds a call-mode answer past its deadline: the
/// slow stage yields when its share of the deadline runs out, and the answer
/// holds what the other channel found, marked partial. The text channel
/// reaches the month-old message; the temporal channel's now anchor reaches
/// only the fresh one. A stage that starts past its share (after a stall
/// that does not yield) is cut at its first candidate, inside the channel,
/// and its hits are dropped. The deadline counts from the instant the test
/// measures from; the answer's quarter of the budget is slack for a loaded
/// host.
#[test]
fn a_slow_channel_never_holds_a_call_mode_answer_past_its_deadline() {
    use crate::memory::RecallEffort;
    use crate::retrieval_depth::SlowRetrievalStage;
    use crate::store::RetrievalSignal;
    use crate::task_verb::sdk::{RecallDoor, RecallRequest, recall_at_door};
    use std::time::{Duration, Instant};

    const DEADLINE_MS: u64 = 4_000;
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x81);
    let facade = facade_for(&vault, actor);
    witness_said(
        &facade,
        0x82,
        "I booked the aisle seat on the night train",
        30,
    );
    witness_said(&facade, 0x83, "the harbour lights were out", 0);

    let whole = recall_at(&facade, "aisle seat", RecallEffort::Light, None, None);
    assert!(!whole.retrieval_meta.partial);
    assert!(pack_gives(&whole, "aisle seat"));
    assert!(pack_gives(&whole, "harbour lights"));

    // The stages share three quarters of the budget, and the text stage
    // opens first, with half of it: 1.5 s.
    for (slow, duration_ms, yields, kept, dropped) in [
        (RetrievalSignal::Temporal, 30_000, true, "aisle seat", None),
        (RetrievalSignal::Text, 30_000, true, "harbour lights", None),
        (
            RetrievalSignal::Text,
            2_000,
            false,
            "harbour lights",
            Some("aisle seat"),
        ),
    ] {
        vault.arm_slow_retrieval_stage_for_test(Some(SlowRetrievalStage {
            signal: slow,
            duration: Duration::from_millis(duration_ms),
            yields,
        }));
        let arrived = Instant::now();
        let pack = recall_at_door(
            &facade,
            RecallRequest {
                query: "aisle seat".to_owned(),
                effort: Some(RecallEffort::Call),
                scope: None,
                limit: Some(20),
                format: None,
                as_of: None,
                deadline_ms: Some(DEADLINE_MS),
            },
            |_| None,
            &RecallDoor {
                arrived,
                on_cut: None,
            },
        )
        .expect("call-mode recall");
        let took = arrived.elapsed();
        vault.arm_slow_retrieval_stage_for_test(None);
        assert!(
            took < Duration::from_millis(DEADLINE_MS),
            "{slow:?} held the answer {took:?}"
        );
        assert!(pack.retrieval_meta.partial, "{slow:?}");
        assert!(pack_gives(&pack, kept), "{slow:?} lost {kept}: {pack:?}");
        if let Some(dropped) = dropped {
            assert!(!pack_gives(&pack, dropped), "{slow:?} kept {dropped}");
        }
    }
}

/// A deadline that never fires changes nothing: the same fixed queries rank
/// the same items, with and without a query vector, whether the deadline
/// comes from call mode or a light recall's own `deadline_ms`.
#[test]
fn a_deadline_that_never_fires_ranks_exactly_as_no_deadline() {
    use crate::memory::RecallEffort;
    use crate::memory::caps::MAX_RECALL_DEADLINE_MS;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x84);
    let facade = facade_for(&vault, actor);
    for (conversation, said, age_days) in [
        (0x85, "a window seat on the night train", 30),
        (0x86, "an aisle seat on the morning train", 9),
        (0x87, "the night ferry had no seats left", 2),
        (0x88, "train tickets for the harbour", 0),
    ] {
        witness_said(&facade, conversation, said, age_days);
    }
    let as_of = crate::unix_seconds_now();
    let vector = vec![0.5; vault.config.dimensions];
    for query in ["seat", "night train", "harbour", "ferry seats"] {
        for vector in [None, Some(vector.as_slice())] {
            let run = |effort, deadline_ms| {
                crate::task_verb::sdk::recall_with_vector(
                    &facade,
                    crate::task_verb::sdk::RecallRequest {
                        query: query.to_owned(),
                        effort: Some(effort),
                        scope: None,
                        limit: Some(10),
                        format: None,
                        as_of: Some(as_of),
                        deadline_ms,
                    },
                    |_| vector.map(<[f32]>::to_vec),
                )
                .expect("recall")
            };
            let unhurried = run(RecallEffort::Light, None);
            assert!(!unhurried.items.is_empty(), "{query}");
            for effort in [RecallEffort::Light, RecallEffort::Call] {
                let hurried = run(effort, Some(MAX_RECALL_DEADLINE_MS));
                assert!(!hurried.retrieval_meta.partial, "{query}");
                assert_eq!(hurried.items, unhurried.items, "{query} {effort:?}");
            }
        }
    }
}

/// Call mode reads through the same fences as every recall: a deleted row,
/// a claim in a world outside the reader's scope, and a message the reader
/// holds no read grant for stay out of its answer, whether or not the
/// deadline cuts a stage, and it never holds an item a light recall
/// without a deadline would withhold.
#[test]
fn call_mode_never_returns_a_row_a_normal_recall_withholds() {
    use crate::memory::RecallEffort;
    use crate::retrieval_depth::SlowRetrievalStage;
    use crate::store::RetrievalSignal;
    use std::time::Duration;

    let short_ids = |pack: &crate::memory::MemoryPack| -> std::collections::BTreeSet<String> {
        pack.items
            .iter()
            .map(|item| item.short_id.clone())
            .collect()
    };
    let slow_temporal = SlowRetrievalStage {
        signal: RetrievalSignal::Temporal,
        duration: Duration::from_secs(10),
        yields: true,
    };

    // A deleted message and a world-two claim, read by an actor with no
    // world grant.
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x89);
    let facade = facade_for(&vault, actor);
    witness_said(&facade, 0x8a, "lantern festival by the river", 3);
    let erased = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x8b; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "lantern secret to forget",
            )],
            occurred_at: crate::unix_seconds_now() - 3 * 86_400,
        })
        .expect("witness");
    let erased = resolve_entity_ref(&vault, &erased.message_short_ids[0]).expect("message id");
    let before = recall_at(&facade, "lantern", RecallEffort::Call, Some(4_000), None);
    assert!(pack_gives(&before, "lantern secret"), "{before:?}");
    vault
        .delete_own_room_record(erased, crate::DeleteReason::UserDelete)
        .expect("delete");
    let subject = EntityId::from_hex(
        &facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "lantern maker"}),
                text_fields: Some(vec![TextIndexField {
                    field: "name".to_owned(),
                    value: "lantern maker".to_owned(),
                }]),
                edges: None,
                occurred_at: 1600,
                learned_at: None,
            })
            .expect("subject")
            .id_hex,
    )
    .expect("subject id");
    let world_two = EntityId::from_bytes([0x8c; 16]).unwrap();
    let mut claim = claim_input(
        "profile.city",
        &subject,
        "user_stated",
        serde_json::json!("lantern town in world two"),
    );
    claim.world_ref = Some(world_two.to_hex());
    facade.claim_upsert(&claim).expect("world claim");

    let withheld = |pack: &crate::memory::MemoryPack| {
        assert!(!pack_gives(pack, "lantern secret"), "deleted: {pack:?}");
        assert!(
            !pack
                .items
                .iter()
                .any(|item| item.world.as_deref() == Some(world_two.to_hex().as_str())),
            "out of scope: {pack:?}"
        );
    };
    let normal = recall_at(&facade, "lantern", RecallEffort::Light, None, None);
    withheld(&normal);
    assert!(pack_gives(&normal, "lantern festival"));
    for slow in [None, Some(slow_temporal)] {
        vault.arm_slow_retrieval_stage_for_test(slow);
        let call = recall_at(&facade, "lantern", RecallEffort::Call, Some(4_000), None);
        vault.arm_slow_retrieval_stage_for_test(None);
        withheld(&call);
        assert!(short_ids(&call).is_subset(&short_ids(&normal)), "{call:?}");
        assert_eq!(call.narrowing.applied, normal.narrowing.applied);
    }

    // A message the scoped reader holds no read grant for.
    let (_dir, vault, owner, scoped) = recall_after_control_writes_fixture(false);
    let owned = recall_at(
        &facade_for(&vault, owner),
        "window seat",
        RecallEffort::Call,
        Some(4_000),
        None,
    );
    assert!(owned.items.iter().any(gives_control_message), "{owned:?}");
    for slow in [None, Some(slow_temporal)] {
        vault.arm_slow_retrieval_stage_for_test(slow);
        let call = recall_at(
            &facade_for(&vault, scoped),
            "window seat",
            RecallEffort::Call,
            Some(4_000),
            None,
        );
        vault.arm_slow_retrieval_stage_for_test(None);
        assert!(
            !call.items.iter().any(gives_control_message),
            "ungranted reader received the message: {call:?}"
        );
    }
}

/// Every deadline is bounded: call mode and a raw `deadline_ms` refuse 0
/// and anything past the cap with a typed error, and an omitted dial is
/// medium with no deadline.
#[test]
fn the_recall_dial_refuses_a_deadline_out_of_range() {
    use crate::memory::caps::MAX_RECALL_DEADLINE_MS;
    use crate::memory::{RecallEffort, resolve_recall_dial};
    use std::time::Duration;

    let vault_deadline = Duration::from_millis(250);
    for effort in [None, Some(RecallEffort::Light), Some(RecallEffort::Call)] {
        for deadline_ms in [0, MAX_RECALL_DEADLINE_MS + 1] {
            let refused = resolve_recall_dial(effort, Some(deadline_ms), vault_deadline)
                .expect_err("out of range");
            assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{deadline_ms}");
        }
    }
    assert_eq!(
        resolve_recall_dial(None, None, vault_deadline).unwrap(),
        (Effort::Medium, None)
    );
    assert_eq!(
        resolve_recall_dial(Some(RecallEffort::Call), None, vault_deadline).unwrap(),
        (Effort::Light, Some(vault_deadline))
    );
    assert_eq!(
        resolve_recall_dial(Some(RecallEffort::Call), Some(40), vault_deadline).unwrap(),
        (Effort::Light, Some(Duration::from_millis(40)))
    );
    assert_eq!(
        resolve_recall_dial(Some(RecallEffort::High), Some(40), vault_deadline).unwrap(),
        (Effort::High, Some(Duration::from_millis(40)))
    );
}

/// A door that stops waiting at the deadline answers with the last pack
/// recall published: before the query embeds, no items under the reader's
/// receipt; once the items are assembled, those items before the scope
/// census. Both are marked partial, and the census marked unfinished.
#[test]
fn a_recall_door_is_handed_the_best_pack_ready_at_each_step() {
    use crate::memory::{MemoryPack, RecallEffort};
    use crate::task_verb::sdk::{RecallDoor, RecallRequest, recall_at_door};
    use std::sync::Mutex;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x8d);
    let facade = facade_for(&vault, actor);
    witness_said(&facade, 0x8e, "the lighthouse keeper rang twice", 2);
    let published: Mutex<Vec<MemoryPack>> = Mutex::default();
    let publish = |pack| published.lock().expect("published packs").push(pack);
    let embedded = Mutex::new(0);
    let pack = recall_at_door(
        &facade,
        RecallRequest {
            query: "lighthouse keeper".to_owned(),
            effort: Some(RecallEffort::Call),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: Some(30_000),
        },
        |_| {
            // The empty pack is already published when the query embeds.
            *embedded.lock().expect("embed count") += 1;
            assert_eq!(published.lock().expect("published packs").len(), 1);
            None
        },
        &RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: Some(&publish),
        },
    )
    .expect("call-mode recall");
    assert_eq!(*embedded.lock().expect("embed count"), 1);
    assert!(!pack.retrieval_meta.partial);
    assert!(pack_gives(&pack, "lighthouse keeper"));
    let published = std::mem::take(&mut *published.lock().expect("published packs"));
    let [before, assembled] = published.as_slice() else {
        panic!("two packs published: {published:?}");
    };
    for cut in [before, assembled] {
        assert!(cut.retrieval_meta.partial);
        assert!(cut.scope_honesty.census_capped);
        assert_eq!(cut.narrowing.applied, pack.narrowing.applied);
    }
    assert!(before.items.is_empty());
    assert_eq!(assembled.items, pack.items);
}
