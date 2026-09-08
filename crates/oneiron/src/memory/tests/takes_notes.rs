//! Note takes on claims, author binding, and stale upsert/retract conflicts.

use super::*;

/// Two actors, one claim, two takes. Divergence is append-only: two NOTE ids,
/// two independent `AuthoredBy` edges, no upsert keyed by `(actor, target)`
/// and no cross-attribution.
#[test]
fn two_actor_divergent_takes() {
    let (_dir, vault) = open_vault();
    let ada = put_person(&vault, 0x71);
    let bo = put_person(&vault, 0x72);
    let subject = put_person(&vault, 0x73);
    let claim = opinion_claim(&vault, ada, subject);

    let ada_markdown = "Right — the passport backs it.";
    let bo_markdown = "Wrong: that is a stage name.";
    let first = facade_for(&vault, ada)
        .author_take(TakeTarget::Claim(claim), ada_markdown)
        .expect("ada take");
    let second = facade_for(&vault, bo)
        .author_take(TakeTarget::Claim(claim), bo_markdown)
        .expect("bo take");

    assert_ne!(
        first.id_hex, second.id_hex,
        "a second actor's take must mint its own NOTE, never overwrite the first"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .len(),
        2
    );

    for (receipt, author, markdown) in [(&first, ada, ada_markdown), (&second, bo, bo_markdown)] {
        let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
        let body = note_body_of(&vault, &note_id);
        assert_eq!(body.kind, NoteKind::OpinionTake);
        assert_eq!(body.markdown, markdown);
        assert_eq!(body.author_ref, author, "takes must not cross-attribute");

        let edges = vault.edges_out(&note_id).expect("edges");
        assert_eq!(edges.len(), 2, "a take writes exactly AuthoredBy + ClaimOf");
        let authored = edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::AuthoredBy)
            .expect("AuthoredBy edge is mandatory");
        assert_eq!(
            authored.target, body.author_ref,
            "the stored author_ref must equal the AuthoredBy target"
        );
        assert!(
            edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::ClaimOf && edge.target == claim)
        );
    }

    // Retrieval keeps both rows typed NOTE — neither is reprinted as a claim.
    for note in vault.entities_by_type(ENTITY_TYPE_NOTE).expect("notes") {
        let view = facade_for(&vault, ada)
            .get_entity(&note.to_hex())
            .expect("get")
            .expect("note view");
        assert_eq!(view.kind, "NOTE");
    }
}

/// The neutral-CLAIM invariant: a take is written BESIDE the claim. The
/// target's raw bytes (body, lifecycle, learned-at), its content hash, and its
/// outbound edges are all identical afterwards; the only difference anywhere
/// is one new inbound `ClaimOf` from the take.
#[test]
fn take_never_mutates_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x74);
    let subject = put_person(&vault, 0x75);
    let facade = facade_for(&vault, actor);
    let claim = opinion_claim(&vault, actor, subject);
    let claim_hex = claim.to_hex();

    let before_raw = vault.get_raw(&claim).expect("raw").expect("claim exists");
    let before_lifecycle = vault
        .get_claim(&claim)
        .expect("claim body")
        .expect("body")
        .lifecycle;
    // The short ref's suffix IS the body content hash: a rewritten claim
    // advances it, so equality here is the content-hash assertion.
    let before_ref = facade
        .get_entity(&claim_hex)
        .expect("get")
        .expect("claim view")
        .short_ref;
    let before_out: Vec<_> = vault
        .edges_out(&claim)
        .expect("edges out")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();
    let before_in: Vec<_> = vault
        .edges_in(&claim)
        .expect("edges in")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();

    let take = facade
        .author_take(TakeTarget::Claim(claim), "Contested; see the 1994 filing.")
        .expect("take");
    let note_id = EntityId::from_hex(&take.id_hex).expect("note id");

    assert_eq!(
        vault.get_raw(&claim).expect("raw").expect("claim exists"),
        before_raw,
        "author_take must leave the target claim byte-identical"
    );
    assert_eq!(
        vault
            .get_claim(&claim)
            .expect("claim body")
            .expect("body")
            .lifecycle,
        before_lifecycle
    );
    assert_eq!(
        facade
            .get_entity(&claim_hex)
            .expect("get")
            .expect("claim view")
            .short_ref,
        before_ref,
        "the claim's content hash must not advance"
    );
    assert_eq!(
        vault
            .edges_out(&claim)
            .expect("edges out")
            .iter()
            .map(|edge| (edge.kind, edge.target))
            .collect::<Vec<_>>(),
        before_out
    );

    let after_in: Vec<_> = vault
        .edges_in(&claim)
        .expect("edges in")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();
    let added: Vec<_> = after_in
        .iter()
        .filter(|edge| !before_in.contains(edge))
        .collect();
    assert_eq!(
        added,
        vec![&(EdgeKind::ClaimOf, note_id)],
        "the only new edge may be the take's inbound ClaimOf"
    );
    assert_eq!(after_in.len(), before_in.len() + 1);
}

/// Every refusal path leaves nothing behind, and no door lets a caller choose
/// the author.
#[test]
fn author_take_fails_closed_and_never_lets_a_caller_pick_the_author() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x76);
    let impostor = put_person(&vault, 0x77);
    let subject = put_person(&vault, 0x78);
    let facade = facade_for(&vault, actor);

    // A `Claim` target that is not type-0 — the ClaimOf edge would lie.
    let err = facade
        .author_take(TakeTarget::Claim(subject), "not a claim")
        .expect_err("non-CLAIM claim target must be refused");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);

    // Missing targets, on both arms.
    let absent = EntityId::from_bytes([0xEE; 16]).expect("absent id");
    for target in [TakeTarget::Subject(absent), TakeTarget::Claim(absent)] {
        let err = facade
            .author_take(target, "about a ghost")
            .expect_err("missing target must be refused");
        assert_eq!(err.code, MEMORY_CODE_NOT_FOUND);
    }

    // Blank markdown never reaches the store.
    assert!(
        facade
            .author_take(TakeTarget::Subject(subject), "   ")
            .is_err(),
        "blank markdown must be refused"
    );

    // An unbound actor cannot author: the binding is store-truth, checked in
    // the same write transaction.
    let unbound = EntityId::from_bytes([0xDD; 16]).expect("unbound id");
    assert!(
        vault
            .memory(unbound, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(subject), "who am I")
            .is_err(),
        "an actor that does not exist must not author a take"
    );

    // Nothing above committed: no orphan NOTE, no orphan edge on the target.
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty(),
        "refused takes must leave no orphan NOTE"
    );
    assert!(
        vault
            .edges_in(&subject)
            .expect("edges in")
            .iter()
            .all(|edge| edge.kind != EdgeKind::About && edge.kind != EdgeKind::ClaimOf),
        "refused takes must leave no orphan link edge"
    );

    // The broad structural door refuses NOTE outright: were it open, a caller
    // could hand-write author_ref and forge another actor's take.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "NOTE".to_owned(),
            body: serde_json::json!({
                "kind": "opinion/take",
                "author_ref": impostor.to_hex(),
                "markdown": "words the impostor never wrote",
            }),
            text_fields: None,
            edges: None,
            occurred_at: 900,
            learned_at: None,
        })
        .expect_err("NOTE must not be writable through put_structural");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(err.suggestions.iter().any(|s| s.contains("author_take")));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty()
    );

    // The honest door stamps the bound actor, not the impostor the caller
    // would have named.
    let receipt = facade
        .author_take(TakeTarget::Subject(subject), "an attributed aside")
        .expect("take");
    let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
    let body = note_body_of(&vault, &note_id);
    assert_eq!(body.author_ref, actor);
    assert_ne!(body.author_ref, impostor);
    let edges = vault.edges_out(&note_id).expect("edges");
    assert_eq!(edges.len(), 2);
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::About && edge.target == subject),
        "a subject take links with About, never ClaimOf"
    );
}

/// Closing `put_structural` was not enough: the raw batch door admits every
/// registered public type, so registering NOTE opened a second way in — one
/// that would have committed a caller-written `author_ref` with no
/// `AuthoredBy` and no link edge at all. Attribution is engine-stamped, so
/// the raw door refuses the type outright on both batch builders and
/// `author_take` remains the only NOTE writer.
#[test]
fn raw_note_put_is_refused_at_the_batch_door() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x79);
    let impostor = put_person(&vault, 0x7A);
    let subject = put_person(&vault, 0x7B);

    let forged = crate::note::encode_note_body(&crate::note::NoteBody {
        kind: NoteKind::OpinionTake,
        author_ref: impostor,
        markdown: "words the impostor never wrote".to_owned(),
    })
    .expect("body encodes");

    let batch_note = EntityId::from_bytes([0x7C; 16]).expect("note id");
    let err = vault
        .batch()
        .put(&batch_note, ENTITY_TYPE_NOTE, test_time(900), 900, &forged)
        .commit()
        .expect_err("raw batch NOTE put must be refused");
    let crate::error::Error::InvalidNoteBody(message) = err else {
        panic!("raw NOTE put must fail as an invalid NOTE body");
    };
    assert!(
        message.contains("author_take"),
        "the refusal must name the only door that stamps an author"
    );

    let txn_note = EntityId::from_bytes([0x7D; 16]).expect("note id");
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&txn_note, ENTITY_TYPE_NOTE, test_time(900), 900, &forged)
                .apply(wtxn)
        })
        .expect_err("raw transaction-batch NOTE put must be refused");
    assert!(matches!(err, crate::error::Error::InvalidNoteBody(_)));

    // The typed door does not inherit the bypass blindly. Handed the forged
    // body and the real actor, it refuses: the stored `author_ref` must be
    // the actor the door was given.
    let typed_note = EntityId::from_bytes([0x7E; 16]).expect("note id");
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_authored_note(&typed_note, &actor, test_time(900), 900, &forged)
                .apply(wtxn)
        })
        .expect_err("the typed door must refuse a body attributed to another actor");
    assert!(matches!(err, crate::error::Error::InvalidNoteBody(_)));

    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty(),
        "a refused raw put must leave no NOTE behind"
    );

    // The typed door is unaffected, and still stamps the bound actor.
    let receipt = facade_for(&vault, actor)
        .author_take(TakeTarget::Subject(subject), "the honest door")
        .expect("take");
    let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
    assert_eq!(note_body_of(&vault, &note_id).author_ref, actor);
}

#[test]
fn facade_stale_upsert_rolls_back_new_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let subject = put_person(&vault, 0x72);
    let facade = facade_for(&vault, actor);

    let prior_id = EntityId::from_bytes([0x76; 16]).expect("prior id");
    let replacement_id = EntityId::from_bytes([0x73; 16]).expect("replacement id");
    let winner_id = EntityId::from_bytes([0x77; 16]).expect("winner id");

    let mut first = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("osaka"),
    );
    first.id = Some(prior_id.to_hex());
    facade.claim_upsert(&first).expect("first revision lands");

    let mut replacement = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("tokyo"),
    );
    replacement.id = Some(replacement_id.to_hex());

    // The advisory prior lookup has already named `prior_id`; a concurrent
    // writer closes it in the window before the write transaction opens. That
    // window is exactly what the in-txn guard exists for.
    let mut winner = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("kyoto"),
    );
    winner.id = Some(winner_id.to_hex());
    let winner_short_ref = std::cell::RefCell::new(String::new());
    let err = facade
        .claim_upsert_with_pre_txn_hook(&replacement, || {
            let receipt = facade_for(&vault, actor)
                .claim_upsert(&winner)
                .expect("the concurrent revision wins the race");
            *winner_short_ref.borrow_mut() = receipt.claim_short_id;
        })
        .expect_err("the advisory prior moved before the transaction");

    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(
        err.successor_short_id.as_deref(),
        Some(winner_short_ref.borrow().as_str()),
        "the successor travels as a typed field, not only in prose"
    );

    // The staged replacement rolled back with the refusal: it was never
    // written, and the prior kept the close the WINNER gave it.
    assert!(
        vault
            .get_claim(&replacement_id)
            .expect("read replacement")
            .is_none(),
        "a refused upsert must not leave its staged claim behind"
    );
    assert_eq!(
        vault
            .get_claim(&prior_id)
            .expect("read prior")
            .expect("prior")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .get_claim(&winner_id)
            .expect("read winner")
            .expect("winner")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the refusal never retargets the verb at the successor"
    );
}

#[test]
fn facade_stale_retract_exposes_invalid_state_and_successor() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x74);
    let subject = put_person(&vault, 0x75);
    let facade = facade_for(&vault, actor);

    let prior_id = EntityId::from_bytes([0x78; 16]).expect("prior id");
    let replacement_id = EntityId::from_bytes([0x79; 16]).expect("replacement id");

    let mut first = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("osaka"),
    );
    first.id = Some(prior_id.to_hex());
    facade.claim_upsert(&first).expect("first revision lands");

    let mut replacement = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("tokyo"),
    );
    replacement.id = Some(replacement_id.to_hex());
    let replacement_receipt = facade
        .claim_upsert(&replacement)
        .expect("replacement supersedes the first");

    // By hex id: the prior's short ref rotated its content-hash suffix when
    // the supersession rewrote its body, and a client holding the pre-close
    // ref would get NOT_FOUND before ever reaching the guard.
    let err = facade
        .claim_retract(&prior_id.to_hex())
        .expect_err("retracting a replaced head is a stale-target refusal");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(
        err.successor_short_id.as_deref(),
        Some(replacement_receipt.claim_short_id.as_str())
    );

    // Never retargeted, never silently no-opped: the successor stays live and
    // the stale target keeps its own close.
    assert_eq!(
        vault
            .get_claim(&replacement_id)
            .expect("read successor")
            .expect("successor")
            .lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault
            .get_claim(&prior_id)
            .expect("read prior")
            .expect("prior")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}
