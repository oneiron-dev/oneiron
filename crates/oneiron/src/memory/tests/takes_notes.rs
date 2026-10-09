//! Note takes on claims, author binding, and stale upsert/retract conflicts.

use super::*;

/// One point read through `read`'s lane, with its receipt.
fn point(
    read: &crate::claim::ScopedRead<'_>,
    target: crate::claim::PointRead<'_>,
) -> crate::claim::ScopedReadResult<Option<crate::claim::ReadRow>> {
    read.read(&[target], None).unwrap().single()
}

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
        assert_eq!(
            body.kind,
            NoteKind::parse("opinion/take").expect("shipped kind")
        );
        assert_eq!(body.markdown, markdown);
        assert_eq!(vault.note_document(note_id).unwrap().markdown, markdown);
        assert_eq!(body.author_ref, author, "takes must not cross-attribute");

        let edges = vault.edges_out(&note_id).expect("edges");
        assert_eq!(
            edges.len(),
            3,
            "a take writes exactly AuthoredBy + ClaimOf + its birth FacetOf stamp"
        );
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
            .value
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
        .value
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
            .value
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
    assert_eq!(edges.len(), 3);
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
        kind: NoteKind::parse("opinion/take").expect("shipped kind"),
        author_ref: impostor,
        markdown: "words the impostor never wrote".to_owned(),
        source_revision_ref: [0x42; 16],
    })
    .expect("body encodes");

    let batch_note = EntityId::from_bytes([0x7C; 16]).expect("note id");
    let err = vault
        .batch()
        .put(&batch_note, ENTITY_TYPE_NOTE, test_time(900), 900, &forged)
        .commit()
        .expect_err("raw batch NOTE put must be refused");
    let crate::error::Error::Record(crate::error::RecordError::InvalidNoteBody(message)) = err
    else {
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
    assert!(matches!(
        err,
        crate::error::Error::Record(crate::error::RecordError::InvalidNoteBody(_))
    ));

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
    assert!(matches!(
        err,
        crate::error::Error::Record(crate::error::RecordError::InvalidNoteBody(_))
    ));

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
            facade_for(&vault, actor)
                .claim_upsert(&winner)
                .expect("the concurrent revision wins the race");
            let body = vault.get_claim(&winner_id).unwrap().unwrap();
            vault
                .approve_inbox_member_with_edit_at(
                    &winner_id,
                    &crate::claim::encode_claim_body(&body).unwrap(),
                    crate::unix_seconds_now(),
                )
                .expect("owner confirms concurrent winner");
            *winner_short_ref.borrow_mut() = facade_for(&vault, actor)
                .short_ref_or_hex(&winner_id)
                .unwrap();
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
        .expect("replacement is proposed");
    assert_eq!(replacement_receipt.approval, "proposed");
    let body = vault.get_claim(&replacement_id).unwrap().unwrap();
    vault
        .approve_inbox_member_with_edit_at(
            &replacement_id,
            &crate::claim::encode_claim_body(&body).unwrap(),
            crate::unix_seconds_now(),
        )
        .expect("owner confirms replacement");
    let replacement_short_ref = facade.short_ref_or_hex(&replacement_id).unwrap();

    // By hex id: the prior's short ref rotated its content-hash suffix when
    // the supersession rewrote its body, and a client holding the pre-close
    // ref would get NOT_FOUND before ever reaching the guard.
    let err = facade
        .claim_retract(&prior_id.to_hex())
        .expect_err("retracting a replaced head is a stale-target refusal");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(
        err.successor_short_id.as_deref(),
        Some(replacement_short_ref.as_str())
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

#[test]
fn diary_note_is_actor_private_across_reads_recall_and_pack_neighbors() {
    use crate::claim::ScopedReadActorKey;
    use crate::context_pack::ContextEntity;
    use crate::note::{NoteScope, NoteWriteEnvelope};
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::test_util::embedding_test_config())
        .expect("vault with vectors and default policy");
    let owner = put_person(&vault, 0x61);
    let other = put_person(&vault, 0x62);
    let owner_memory = facade_for(&vault, owner);
    let other_memory = facade_for(&vault, other);
    let revision = [0x63; 16];
    let receipt = owner_memory
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::parse("diary").expect("shipped kind"),
            scope: NoteScope::ActorPrivate { owner_ref: owner },
            source_revision_ref: revision,
            markdown: "privatecanary journal".to_owned(),
            mask: None,
        })
        .expect("diary via NOTE writer");
    let id = EntityId::from_hex(&receipt.id_hex).expect("note id");
    let body = note_body_of(&vault, &id);
    assert_eq!(body.kind, NoteKind::parse("diary").expect("shipped kind"));
    assert_eq!(body.author_ref, owner);
    assert_eq!(body.source_revision_ref, revision);
    assert!(
        vault
            .edges_out(&id)
            .expect("edges")
            .iter()
            .any(|edge| edge.kind == EdgeKind::AuthoredBy && edge.target == owner)
    );
    assert!(
        owner_memory
            .get_entity(&receipt.id_hex)
            .expect("owner read")
            .is_some()
    );
    assert!(
        other_memory
            .get_entity(&receipt.id_hex)
            .expect("other read")
            .is_none()
    );
    assert!(
        other_memory
            .hydrate(std::slice::from_ref(&receipt.entity_ref))
            .is_err()
    );

    // C07 requires logged proof as well as C01's live NOTE author identity.
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"diary read fixture").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mint_actor = |actor: EntityId| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(actor.as_bytes()).as_bytes();
        claims.holder_ref = actor.to_hex();
        claims.actor_class = Some("human".into());
        vault.mint_capability_slip(&issuer, claims).unwrap()
    };
    let proof_of = |slip: &crate::authority::CapabilitySlip| {
        let signature = issuer.binding_proof(slip, b"diary-read").unwrap();
        vault
            .verify_capability_slip(&issuer.public_key(), slip, b"diary-read", &signature)
            .unwrap()
    };
    let read_key = |slip: &crate::authority::CapabilitySlip| {
        ScopedReadActorKey::from_verified_slip(&proof_of(slip)).unwrap()
    };
    let owner_slip = mint_actor(owner);
    let other_slip = mint_actor(other);
    let owner_read = vault.scoped_read(read_key(&owner_slip));
    let other_read = vault.scoped_read(read_key(&other_slip));
    // The vault is rooted now, so neither actor is an unbound owner: each
    // facade reads under the credential its actor holds.
    let owner_memory = facade_for(&vault, owner).with_read_proof(&proof_of(&owner_slip));
    let other_memory = facade_for(&vault, other).with_read_proof(&proof_of(&other_slip));
    let unproven =
        vault.scoped_read(ScopedReadActorKey::with_actor_class(owner.to_hex(), "human").unwrap());
    assert!(
        unproven
            .read(&[crate::claim::PointRead::id(id)], None)
            .unwrap()
            .single()
            .is_none()
    );
    let mut narrowed = owner_slip;
    issuer
        .attenuate(
            &mut narrowed,
            crate::authority::SlipCaveat {
                records: Some(std::collections::BTreeSet::from([other.to_hex()])),
                ..Default::default()
            },
        )
        .unwrap();
    let limited = vault.scoped_read(read_key(&narrowed));
    assert!(
        limited
            .read(&[crate::claim::PointRead::id(id)], None)
            .unwrap()
            .single()
            .is_none()
    );
    assert!(limited.memory_timeline(&id).unwrap().records.is_empty());
    assert_eq!(
        crate::note::decode_note_body(
            &owner_read
                .read(&[crate::claim::PointRead::id(id)], None)
                .expect("read")
                .single()
                .value
                .and_then(|row| row.body)
                .expect("body")
        )
        .expect("decode"),
        body
    );
    assert!(
        other_read
            .read(&[crate::claim::PointRead::id(id)], None)
            .expect("read")
            .single()
            .is_none()
    );
    let (short, hash) =
        crate::entity_id::parse_short_ref_syntax(&receipt.entity_ref).expect("short ref");
    assert!(
        owner_read
            .read(&[crate::claim::PointRead::short(short, hash)], None)
            .expect("owner hydrate")
            .single()
            .is_some()
    );
    assert!(
        other_read
            .read(&[crate::claim::PointRead::short(short, hash)], None)
            .expect("other hydrate")
            .single()
            .is_none()
    );
    assert!(
        other_read
            .memory_timeline(&id)
            .expect("timeline")
            .records
            .is_empty()
    );
    assert!(other_read.edges_out(&id).expect("edges").is_none());
    assert!(
        limited
            .read(&[crate::claim::PointRead::short(short, hash)], None)
            .unwrap()
            .single()
            .is_none()
    );
    let classless = vault.scoped_read(ScopedReadActorKey::new(owner.to_hex()).expect("key"));
    assert!(
        classless
            .read(&[crate::claim::PointRead::id(id)], None)
            .expect("class required")
            .single()
            .is_none()
    );
    let wrong_class = vault
        .scoped_read(ScopedReadActorKey::with_actor_class(owner.to_hex(), "system").expect("key"));
    assert!(
        wrong_class
            .read(&[crate::claim::PointRead::id(id)], None)
            .expect("class bound")
            .single()
            .is_none()
    );
    let pin = vault.pin_entity_revision(&id).expect("pin diary");
    for mode in [
        crate::vault::ReadMode::Live,
        crate::vault::ReadMode::Indexed,
        crate::vault::ReadMode::Pinned(pin),
    ] {
        let bytes = owner_read
            .read(&[crate::claim::PointRead::id(id).at(mode)], None)
            .expect("owner frontier read")
            .single()
            .value
            .and_then(|row| row.body)
            .expect("owner diary");
        assert_eq!(crate::note::decode_note_body(&bytes).expect("note"), body);
        assert!(
            owner_memory
                .get_entity_with_mode(&receipt.id_hex, mode)
                .unwrap()
                .is_some()
        );
        assert!(
            other_memory
                .get_entity_with_mode(&receipt.id_hex, mode)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            other_memory
                .hydrate_with_mode(std::slice::from_ref(&receipt.id_hex), mode)
                .expect_err("private frontier cannot hydrate")
                .code,
            MEMORY_CODE_NOT_FOUND,
        );
        for reader in [&other_read, &classless, &wrong_class] {
            let withheld = reader
                .read(
                    &[
                        crate::claim::PointRead::id(id).at(mode),
                        crate::claim::PointRead::short(short, hash).at(mode),
                    ],
                    None,
                )
                .expect("scoped frontier");
            assert_eq!(withheld.value, vec![None, None]);
        }
    }

    // A private row must stay hidden even if an index or graph nominates it.
    vault
        .batch()
        .text(&id, &[("body", "privatecanary journal")])
        .text(&other, &[("body", "publiccanary")])
        .edge(&other, EdgeKind::About, &id, 1.0)
        .commit()
        .expect("index + edge");
    assert!(
        vault
            .search_text("privatecanary", 10)
            .expect("bare search")
            .is_empty()
    );
    assert!(
        other_memory
            .query_bm25("privatecanary", 10)
            .expect("bm25")
            .is_empty()
    );
    for memory in [&owner_memory, &other_memory] {
        for effort in [Effort::Light, Effort::Medium] {
            let recalled = memory
                .recall(
                    "privatecanary",
                    effort,
                    &RecallScope::default(),
                    10,
                    Some("json"),
                    None,
                )
                .expect("recall");
            assert!(
                recalled
                    .items
                    .iter()
                    .all(|item| item.short_id != receipt.entity_ref)
            );
            assert!(
                !recalled
                    .rendered
                    .unwrap_or_default()
                    .contains("privatecanary")
            );
        }
    }
    let pack = vault
        .context_pack()
        .search_text("publiccanary", 10)
        .include_edges(true)
        .edge_hop(2)
        .run()
        .expect("ordinary pack");
    assert!(
        !pack
            .results
            .iter()
            .chain(&pack.neighbors)
            .any(|entity| entity.id == id)
    );
    assert!(
        !pack
            .results
            .iter()
            .chain(&pack.neighbors)
            .flat_map(|entity| entity.edges.iter().flatten())
            .any(|edge| edge.target == id)
    );
    assert!(
        other_memory
            .neighbors(
                &other.to_hex(),
                &NeighborOpts {
                    limit: 10,
                    ..Default::default()
                }
            )
            .expect("neighbors")
            .iter()
            .all(|hit| hit.short_id != receipt.entity_ref)
    );

    let dimensions = vault.config.dimensions;
    let mut query = vec![0.0; dimensions];
    query[0] = 1.0;
    vault
        .put_vector(&id, &query)
        .expect("private nearest vector");
    let mut public = query.clone();
    public[1] = 0.1;
    vault.put_vector(&other, &public).expect("public vector");
    public[1] = 0.2;
    vault
        .put_vector(&owner, &public)
        .expect("second public vector");
    let hits = vault.search_vector(&query, 2).expect("visible top k");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|hit| hit.id != id));

    // A caller-supplied assembled pack is checked too, including orphaned
    // neighbors that were reachable only from the excluded diary result.
    let mut injected = vault
        .context_pack()
        .search_text("no-such-content", 10)
        .run()
        .expect("empty pack");
    let entity = ContextEntity {
        critical: false,
        id,
        short_id: receipt.entity_ref.clone(),
        content_hash: hash,
        source_revision_ref: None,
        entity_type: ENTITY_TYPE_NOTE,
        score: 1.0,
        fields: None,
        edges: None,
        vector: None,
    };
    injected.results = vec![entity.clone()];
    injected.neighbors = vec![ContextEntity {
        id: owner,
        entity_type: ENTITY_TYPE_PERSON,
        ..entity
    }];
    let mut narrowed_pack = injected.clone();
    limited.filter_context_pack(&mut narrowed_pack).unwrap();
    assert!(narrowed_pack.results.is_empty());
    assert!(narrowed_pack.neighbors.is_empty());
    let mut owner_pack = injected.clone();
    owner_read
        .filter_context_pack(&mut owner_pack)
        .expect("owner pack");
    assert_eq!(owner_pack.results[0].id, id);
    other_read
        .filter_context_pack(&mut injected)
        .expect("other pack");
    assert!(injected.results.is_empty());
    assert!(injected.neighbors.is_empty());
    // Seed the retained-row archive state; cleanup nomination is a different law.
    vault
        .with_write_txn(|txn| {
            let marker = crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
                deleted_at: 200,
                request_id: [0x71; 16],
            };
            vault
                .store
                .sync_state
                .put(txn, &format!("ac:{}", owner.to_hex()), &marker.encode())?;
            Ok(())
        })
        .expect("archive marker");
    assert!(
        owner_read
            .read(&[crate::claim::PointRead::id(id)], None)
            .expect("archived read")
            .single()
            .is_none()
    );
    assert!(
        owner_read
            .read(&[crate::claim::PointRead::short(short, hash)], None)
            .expect("archived hydrate")
            .single()
            .is_none()
    );
    assert!(
        owner_read
            .memory_timeline(&id)
            .expect("archived timeline")
            .records
            .is_empty()
    );
    owner_read
        .filter_context_pack(&mut owner_pack)
        .expect("archived pack");
    assert!(owner_pack.results.is_empty());
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .sync_state
                .delete(txn, &format!("ac:{}", owner.to_hex()))?;
            Ok(())
        })
        .expect("remove archive fixture");
    vault
        .delete_entity_with_reason(&owner, crate::deletion::DeleteReason::UserDelete)
        .expect("soft delete owner");
    assert!(
        owner_read
            .read(&[crate::claim::PointRead::id(id)], None)
            .expect("deleted author read")
            .single()
            .is_none()
    );
}

#[test]
fn diary_note_rejects_foreign_or_public_scope_without_writing() {
    use crate::note::{NoteScope, NoteWriteEnvelope};
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x64);
    let other = put_person(&vault, 0x65);
    let memory = facade_for(&vault, owner);
    for (kind, scope) in [
        (
            NoteKind::parse("diary").expect("shipped kind"),
            NoteScope::ActorPrivate { owner_ref: other },
        ),
        (
            NoteKind::parse("diary").expect("shipped kind"),
            NoteScope::About(TakeTarget::Subject(owner)),
        ),
        (
            NoteKind::parse("opinion/take").expect("shipped kind"),
            NoteScope::ActorPrivate { owner_ref: owner },
        ),
    ] {
        let error = memory
            .author_note(&NoteWriteEnvelope {
                kind,
                scope,
                source_revision_ref: [0x66; 16],
                markdown: "privatecanary".to_owned(),
                mask: None,
            })
            .expect_err("scope mismatch");
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    }
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty()
    );
}

#[test]
fn diary_note_conjoins_actor_privacy_and_room_audience() {
    use crate::claim::ScopedReadActorKey;
    use crate::conversation::{ConversationBody, HistoryChoice};
    use crate::note::{NoteScope, NoteWriteEnvelope};
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    let owner = put_person(&vault, 0x71);
    let other = put_person(&vault, 0x72);
    let actor = crate::WriteActor::new(owner, crate::EdgeActorClass::Human);
    let room = EntityId::now();
    vault
        .create_conversation(room, &ConversationBody::default(), actor, 1)
        .unwrap();
    vault
        .join_member(room, owner, actor, 2, HistoryChoice::None)
        .unwrap();
    let receipt = facade_for(&vault, owner)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: owner },
            source_revision_ref: [0x73; 16],
            markdown: "private room diary".to_owned(),
            mask: None,
        })
        .unwrap();
    let id = EntityId::from_hex(&receipt.id_hex).unwrap();
    vault
        .batch()
        .edge(&id, EdgeKind::PartOf, &room, 1.0)
        .commit()
        .unwrap();
    let (short, hash) = crate::entity_id::parse_short_ref_syntax(&receipt.entity_ref).unwrap();
    // Text migration is an owner verb, so it runs before the host root below:
    // a rooted vault demands a folded owner binding this fixture does not mint.
    #[cfg(feature = "sync")]
    {
        let authority = vault
            .authenticate_owner(
                owner,
                "principal:note-merge-test",
                true,
                crate::store::GateDecisionId::now(),
            )
            .unwrap();
        vault
            .migrate_entity_text(
                &id,
                &crate::entity_doc::TextField::MapField("markdown".to_owned()),
                actor,
                &crate::entity_doc::DocAuthorization::Owner(&authority),
            )
            .unwrap();
    }
    // Scoped reads need logged proof; an asserted actor key alone reads nothing.
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"diary audience fixture").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let read_key = |actor: EntityId| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(actor.as_bytes()).as_bytes();
        claims.holder_ref = actor.to_hex();
        claims.actor_class = Some("human".into());
        let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
        let signature = issuer.binding_proof(&slip, b"diary-audience").unwrap();
        let proof = vault
            .verify_capability_slip(&issuer.public_key(), &slip, b"diary-audience", &signature)
            .unwrap();
        ScopedReadActorKey::from_verified_slip(&proof).unwrap()
    };
    let owner_key = read_key(owner);
    let other_key = read_key(other);
    for (key, audience, allowed) in [
        (&owner_key, vec![owner], true),
        (&owner_key, vec![other], false),
        (&other_key, vec![owner], false),
        (&owner_key, vec![], false),
    ] {
        let read = vault.scoped_read(key.clone()).for_audience(&audience);
        let point = read
            .read(&[crate::claim::PointRead::id(id)], None)
            .unwrap()
            .single();
        assert_eq!(point.value.is_some(), allowed);
        assert_eq!(point.receipt.suppressed_count, 0);
        if !allowed {
            let missing = EntityId::from_bytes([0x74; 16]).unwrap();
            let absent = read
                .read(&[crate::claim::PointRead::id(missing)], None)
                .unwrap();
            assert_eq!(point.receipt, absent.receipt);
            assert!(
                !point
                    .receipt
                    .narrowed_axes
                    .iter()
                    .any(|axis| axis == "row_authority")
            );
        }
        assert_eq!(read.is_entity_readable(&id).unwrap(), allowed);
        assert_eq!(
            read.read(&[crate::claim::PointRead::short(short, hash)], None)
                .unwrap()
                .single()
                .is_some(),
            allowed
        );
    }
}

#[test]
fn versioned_notes_gate_historic_private_bodies_when_live_note_is_public() {
    use crate::claim::ScopedReadActorKey;
    use crate::context_pack::ContextEntity;
    use crate::note::{NoteScope, NoteWriteEnvelope};
    use crate::vault::ReadMode;

    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x64);
    let other = put_person(&vault, 0x65);
    let receipt = facade_for(&vault, owner)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: owner },
            markdown: "private historic note".into(),
            source_revision_ref: [0x66; 16],
            mask: None,
        })
        .expect("private note");
    let id = EntityId::from_hex(&receipt.id_hex).expect("id");
    let pin = vault.pin_entity_revision(&id).expect("pin private body");
    let private_body = note_body_of(&vault, &id);
    // A NOTE birth body is immutable. A changed body is a new public take that
    // derives from and supersedes the private one.
    let public = facade_for(&vault, owner)
        .author_take(TakeTarget::Subject(owner), "public current note")
        .expect("public take");
    let public_id = EntityId::from_hex(&public.id_hex).expect("public id");
    vault
        .batch()
        .edge(&public_id, EdgeKind::DerivedFrom, &id, 1.0)
        .edge(&public_id, EdgeKind::Supersedes, &id, 1.0)
        .commit()
        .expect("link the public take to the private note");
    let public_body = note_body_of(&vault, &public_id);

    // Scoped reads need logged proof; an asserted actor key alone reads nothing.
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"versioned notes fixture").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let proof_of = |actor: EntityId| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(actor.as_bytes()).as_bytes();
        claims.holder_ref = actor.to_hex();
        claims.actor_class = Some("human".into());
        let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
        let signature = issuer.binding_proof(&slip, b"versioned-notes").unwrap();
        vault
            .verify_capability_slip(&issuer.public_key(), &slip, b"versioned-notes", &signature)
            .unwrap()
    };
    let (owner_proof, other_proof) = (proof_of(owner), proof_of(other));
    let owner_read =
        vault.scoped_read(ScopedReadActorKey::from_verified_slip(&owner_proof).unwrap());
    let other_read =
        vault.scoped_read(ScopedReadActorKey::from_verified_slip(&other_proof).unwrap());
    let live = other_read
        .read(
            &[crate::claim::PointRead::id(public_id).at(ReadMode::Live)],
            None,
        )
        .unwrap()
        .single()
        .value
        .and_then(|row| row.body)
        .unwrap();
    assert_eq!(crate::note::decode_note_body(&live).unwrap(), public_body);
    // The rooted vault's facades read under each actor's credential.
    let owner_memory = facade_for(&vault, owner).with_read_proof(&owner_proof);
    let other_memory = facade_for(&vault, other).with_read_proof(&other_proof);
    let missing = EntityId::from_bytes([0x67; 16]).unwrap();
    for mode in [ReadMode::Indexed, ReadMode::Pinned(pin)] {
        assert!(
            other_memory
                .get_entity_with_mode(&receipt.id_hex, mode)
                .unwrap()
                .is_none()
        );
        assert!(
            owner_memory
                .get_entity_with_mode(&receipt.id_hex, mode)
                .unwrap()
                .is_some()
        );
        let denied = other_read
            .read(&[crate::claim::PointRead::id(id).at(mode)], None)
            .unwrap()
            .single();
        assert!(denied.value.is_none());
        // A private NOTE denial is indistinguishable from a missing row.
        assert_eq!(denied.receipt.suppressed_count, 0);
        assert_eq!(
            denied.receipt,
            other_read
                .get_entity_parts_with_mode_with_receipt(&missing, mode, None)
                .unwrap()
                .receipt
        );
        assert!(
            !denied
                .receipt
                .narrowed_axes
                .iter()
                .any(|axis| axis == "row_authority")
        );
        assert!(
            !denied
                .receipt
                .replan_hint
                .iter()
                .any(|axis| axis == "row_authority")
        );
        let permitted = owner_read
            .read(&[crate::claim::PointRead::id(id).at(mode)], None)
            .unwrap()
            .single();
        assert_eq!(permitted.receipt.suppressed_count, 0);
        let bytes = permitted.value.and_then(|row| row.body).unwrap();
        assert_eq!(crate::note::decode_note_body(&bytes).unwrap(), private_body);
    }

    let (_, hash) = crate::entity_id::parse_short_ref_syntax(&receipt.entity_ref).unwrap();
    let mut pack = vault
        .context_pack()
        .search_text("no-such-note-probe", 1)
        .run()
        .unwrap();
    pack.results = vec![ContextEntity {
        id,
        short_id: receipt.entity_ref,
        content_hash: hash,
        source_revision_ref: Some(pin.0),
        entity_type: ENTITY_TYPE_NOTE,
        score: 1.0,
        critical: false,
        fields: None,
        edges: None,
        vector: None,
    }];
    let mut owner_pack = pack.clone();
    owner_read.filter_context_pack(&mut owner_pack).unwrap();
    assert_eq!(owner_pack.results.len(), 1);
    other_read.filter_context_pack(&mut pack).unwrap();
    assert!(pack.results.is_empty());
}

/// A host-rooted human slip for `actor`, verified: the credential its reads carry.
fn diary_coref_proof(
    vault: &crate::Vault,
    issuer: &crate::authority::HostSlipIssuer,
    root: &crate::authority::CapabilitySlip,
    actor: EntityId,
) -> crate::authority::VerifiedSlip {
    let mut claims = root.claims.clone();
    claims.slip_id = *blake3::hash(actor.as_bytes()).as_bytes();
    claims.holder_ref = actor.to_hex();
    claims.actor_class = Some("human".into());
    let slip = vault.mint_capability_slip(issuer, claims).unwrap();
    let sig = issuer.binding_proof(&slip, b"diary-coref").unwrap();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, b"diary-coref", &sig)
        .unwrap()
}

#[test]
fn cross_resident_diary_coreference_requires_both_exact_grants_on_every_read() {
    use crate::claim::ScopedReadActorKey;
    use crate::context_pack::ContextEntity;
    use crate::note::{NoteScope, NoteWriteEnvelope};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::test_util::embedding_test_config())
        .expect("vault with vectors and default policy");
    let a = put_person(&vault, 0x41);
    let b = put_person(&vault, 0x42);
    let author_a = facade_for(&vault, a);
    let author_b = facade_for(&vault, b);
    let make_diary = |memory: &Memory<'_>, author, text: &str| {
        let receipt = memory
            .author_note(&NoteWriteEnvelope {
                kind: NoteKind::Diary,
                scope: NoteScope::ActorPrivate { owner_ref: author },
                markdown: text.into(),
                source_revision_ref: [0x7a; 16],
                mask: None,
            })
            .unwrap();
        EntityId::from_hex(&receipt.id_hex).unwrap()
    };
    let note_a = make_diary(&author_a, a, "diaryalpha private");
    let note_b = make_diary(&author_b, b, "diarycounterpart private");
    let (left, right) = if note_a < note_b {
        (note_a, note_b)
    } else {
        (note_b, note_a)
    };
    let outsider = put_person(&vault, 0x43);
    let wrong_kind = put_person(&vault, 0x44);
    let absent = EntityId::from_bytes([0xe1; 16]).unwrap();
    assert!(
        facade_for(&vault, outsider)
            .link_diary_coreference(note_a, note_b)
            .is_err()
    );
    assert!(author_a.link_diary_coreference(note_a, note_a).is_err());
    assert!(!vault.edge_exists(&left, EdgeKind::SameAs, &right).unwrap());
    // Resident-facing submissions must not answer whether a guessed foreign
    // diary exists, has the right kind, or is already linked.
    assert!(author_a.link_diary_coreference(note_a, absent).is_ok());
    assert!(author_a.link_diary_coreference(note_a, wrong_kind).is_ok());
    let (missing_left, missing_right) = if note_a < absent {
        (note_a, absent)
    } else {
        (absent, note_a)
    };
    assert!(
        !vault
            .edge_exists(&missing_left, EdgeKind::SameAs, &missing_right)
            .unwrap()
    );
    assert!(author_a.link_diary_coreference(note_a, note_b).is_ok());
    assert!(author_a.link_diary_coreference(note_a, note_b).is_ok());
    assert!(vault.edge_exists(&left, EdgeKind::SameAs, &right).unwrap());
    let actor = crate::WriteActor::new(a, EdgeActorClass::Human);
    assert!(
        crate::federation::coreference_share_consent(
            &vault,
            &actor,
            left,
            right,
            &[0x88; crate::claim::COREFERENCE_PACT_ID_LEN],
            test_time(2),
            2,
        )
        .is_err(),
        "diary links cannot become cross-vault PERSON shares"
    );
    assert!(
        facade_for(&vault, outsider)
            .grant_diary_coreference(note_a, note_b)
            .is_err()
    );
    // Generic grant writes cannot impersonate either resident's consent.
    let forged = crate::access_grant::AccessGrant {
        authority_scope: crate::federation::scope_codec::read_preset(),
        principal_ref: b,
        scope: crate::access_grant::AccessGrantScope::DiaryCoreference {
            left_ref: left,
            right_ref: right,
        },
        capability: crate::access_grant::AccessGrantCapability::DiaryCoreferenceRead,
        status: crate::access_grant::AccessGrantStatus::Active,
        created_at: 1,
        revoked_at: None,
        expires_at: None,
    };
    assert!(
        vault
            .create_access_grant(&EntityId::now(), &forged)
            .is_err()
    );
    assert_eq!(note_body_of(&vault, &note_a).author_ref, a);
    assert_eq!(note_body_of(&vault, &note_b).author_ref, b);
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"diary coreference read").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let proof_of = |actor| diary_coref_proof(&vault, &issuer, &root, actor);
    let read_key = |proof: &crate::authority::VerifiedSlip| {
        ScopedReadActorKey::from_verified_slip(proof).unwrap()
    };
    let (proof_a, proof_b) = (proof_of(a), proof_of(b));
    let read_a = vault.scoped_read(read_key(&proof_a));
    let read_b = vault.scoped_read(read_key(&proof_b));
    // The vault is rooted now: each resident's facade reads under the
    // credential that resident holds.
    let reader_a = facade_for(&vault, a).with_read_proof(&proof_a);
    let reader_b = facade_for(&vault, b).with_read_proof(&proof_b);
    vault
        .batch()
        .text(&note_a, &[("body", "diaryalpha private")])
        .text(&note_b, &[("body", "diarycounterpart private")])
        .commit()
        .unwrap();
    let private_rows = || {
        let edge = vault
            .edges_out(&left)
            .unwrap()
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::SameAs)
            .unwrap();
        let entity = |id: EntityId| ContextEntity {
            critical: false,
            id,
            short_id: id.to_hex(),
            content_hash: 0,
            source_revision_ref: None,
            entity_type: ENTITY_TYPE_NOTE,
            score: 1.0,
            fields: None,
            edges: (id == left).then_some(vec![edge.clone()]),
            vector: None,
        };
        let mut pack = vault
            .context_pack()
            .search_text("unmatched-content", 5)
            .run()
            .unwrap();
        pack.results = vec![entity(note_a), entity(note_b)];
        pack
    };
    let absent_id = EntityId::from_bytes([0x99; 16]).unwrap();
    let probe_record = |id| crate::deletion::MemoryTimelineRecord {
        id,
        state: crate::deletion::MemoryTimelineRecordState::Live,
        entity_type: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        body_bytes: None,
        deletion: None,
        supersedes: Vec::new(),
        superseded_by: Vec::new(),
    };
    let assert_opaque = |hidden: EntityId| {
        let absent = point(&read_a, crate::claim::PointRead::id(absent_id));
        let denied = point(&read_a, crate::claim::PointRead::id(hidden));
        assert!(absent.value.is_none() && denied.value.is_none());
        assert_eq!(denied.receipt, absent.receipt);
        assert_eq!(denied.receipt.suppressed_count, 0);
        assert!(
            !denied
                .receipt
                .narrowed_axes
                .iter()
                .any(|axis| axis == "row_authority")
        );
        assert!(
            !denied
                .receipt
                .replan_hint
                .iter()
                .any(|axis| axis == "row_authority")
        );
        let batch = read_a
            .get_entities_parts_with_receipt(&[absent_id, hidden], None)
            .unwrap();
        assert!(batch.value.iter().all(Option::is_none));
        assert_eq!(batch.receipt.suppressed_count, 0);
        let graph = read_a.edges_out(&hidden).unwrap();
        assert!(graph.value.is_none());
        assert_eq!(graph.receipt, read_a.edges_out(&absent_id).unwrap().receipt);
        let timeline = read_a.memory_timeline(&hidden).unwrap();
        assert!(timeline.value.records.is_empty());
        assert_eq!(
            timeline.receipt,
            read_a.memory_timeline(&absent_id).unwrap().receipt
        );
        let absent_parts = read_a
            .memory_timeline_parts_with_receipt(&[probe_record(absent_id)], None)
            .unwrap();
        let hidden_parts = read_a
            .memory_timeline_parts_with_receipt(&[probe_record(hidden)], None)
            .unwrap();
        assert_eq!(hidden_parts.value, vec![None]);
        assert_eq!(hidden_parts.receipt, absent_parts.receipt);
        assert_eq!(hidden_parts.receipt.suppressed_count, 0);
        let scored = read_a
            .filter_scored_entities(vec![crate::ScoredEntity {
                id: hidden,
                score: 1.0,
            }])
            .unwrap();
        assert!(scored.value.is_empty());
        assert_eq!(scored.receipt.suppressed_count, 0);
    };
    let assert_hidden_short = || {
        let reference = author_b.short_ref_or_hex(&note_b).unwrap();
        let (short, hash) = crate::entity_id::parse_short_ref_syntax(&reference).unwrap();
        let denied = point(&read_a, crate::claim::PointRead::short(short, hash));
        let absent = point(&read_a, crate::claim::PointRead::short("missing", 0));
        assert!(denied.value.is_none() && absent.value.is_none());
        assert_eq!(denied.receipt, absent.receipt);
    };
    let type_filter = crate::gate::RetrievalFilter {
        entity_types: Some(std::collections::BTreeSet::from([ENTITY_TYPE_NOTE])),
        ..Default::default()
    };
    let ordinary_denial = read_a
        .get_entity_parts_with_receipt(&a, Some(&type_filter))
        .unwrap();
    assert!(ordinary_denial.value.is_none());
    assert_eq!(ordinary_denial.receipt.suppressed_count, 1);
    let ordinary_timeline = read_a
        .memory_timeline_parts_with_receipt(&[probe_record(a)], None)
        .unwrap();
    assert_eq!(ordinary_timeline.value, vec![None]);
    assert_eq!(ordinary_timeline.receipt.suppressed_count, 1);

    let check = |shared: bool| {
        for (read, own, foreign, query) in [
            (&read_a, note_a, note_b, "diarycounterpart"),
            (&read_b, note_b, note_a, "diaryalpha"),
        ] {
            let row = |id| point(read, crate::claim::PointRead::id(id)).value;
            assert!(row(own).is_some());
            assert_eq!(row(foreign).is_some(), shared);
            let search = read.search_text(query, 10, None).unwrap();
            assert_eq!(search.value.iter().any(|hit| hit.id == foreign), shared);
            if !shared {
                assert_eq!(search.receipt.suppressed_count, 0);
            }
            let graph = read.edges_out(&left).unwrap();
            if !shared && own == left {
                assert_eq!(graph.receipt.suppressed_count, 0);
            }
            let edges = graph.value;
            assert_eq!(
                edges.as_ref().is_some_and(|rows| rows
                    .iter()
                    .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == right)),
                shared
            );
            let mut pack = private_rows();
            read.filter_context_pack(&mut pack).unwrap();
            assert_eq!(
                pack.results.iter().any(|entity| entity.id == foreign),
                shared
            );
            assert_eq!(
                pack.results
                    .iter()
                    .flat_map(|entity| entity.edges.iter().flatten())
                    .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == right),
                shared
            );
        }
        assert_eq!(
            reader_a.get_entity(&note_b.to_hex()).unwrap().is_some(),
            shared
        );
        assert_eq!(
            reader_b.get_entity(&note_a.to_hex()).unwrap().is_some(),
            shared
        );
    };
    check(false); // Empty scope: no resident learns the other endpoint or link.
    assert_opaque(note_b);
    assert_hidden_short();
    let absent_grant = author_a.grant_diary_coreference(note_a, absent).unwrap();
    let wrong_kind_grant = author_a
        .grant_diary_coreference(note_a, wrong_kind)
        .unwrap();
    let reciprocal_absent = author_b.grant_diary_coreference(note_b, absent).unwrap();
    for id in [absent_grant, wrong_kind_grant, reciprocal_absent] {
        assert_opaque(id);
    }
    author_a
        .revoke_diary_coreference_grant(absent_grant)
        .unwrap();
    author_a
        .revoke_diary_coreference_grant(wrong_kind_grant)
        .unwrap();
    author_b
        .revoke_diary_coreference_grant(reciprocal_absent)
        .unwrap();
    let grant_a = author_a.grant_diary_coreference(note_a, note_b).unwrap();
    let persisted = vault.get_access_grant(&grant_a).unwrap().unwrap();
    assert_eq!(persisted.principal_ref, a);
    assert_eq!(persisted.scope, forged.scope);
    assert!(author_b.revoke_diary_coreference_grant(grant_a).is_err());
    check(false); // One signature is insufficient.
    assert_opaque(note_b);
    assert_opaque(grant_a);
    assert_hidden_short();
    assert!(author_b.grant_diary_coreference(note_a, note_b).is_ok());
    check(true); // Both authors now share exactly this pair.
    assert_opaque(grant_a); // Consent is not a grant-row read capability.
    let query = "diarycounterpart";
    let indexed = vault
        .indexed_revision(&note_b)
        .unwrap()
        .expect("birth frontier");
    let depth = || {
        read_a
            .search_with_effort(&crate::retrieval_depth::DepthSearchRequest {
                probe: crate::retrieval_depth::SearchProbe::Text {
                    query: query.into(),
                },
                effort: Effort::Light,
                limit: 10,
                session_scope: None,
                lease: None,
                backend: None,
                token_budget: None,
                deadline: None,
            })
            .unwrap()
    };
    let first = depth();
    assert!(first.hits.iter().any(|hit| hit.id == note_b));
    assert_eq!(first.revisions.get(&note_b), Some(&indexed));
    author_b
        .edit_note(
            &note_b.to_hex(),
            &crate::note::NoteProgramEdit::WholeText {
                text: "diarycounterpart edited in the live document".into(),
                timeout_ms: 100,
                base: None,
            },
        )
        .unwrap();
    assert_eq!(vault.indexed_revision(&note_b).unwrap(), Some(indexed));
    let during_debounce = depth();
    assert!(during_debounce.hits.iter().any(|hit| hit.id == note_b));
    assert_eq!(during_debounce.revisions.get(&note_b), Some(&indexed));

    // Text and vector channels use one blend for public and shared-private
    // NOTEs; a public-only query retains ordinary result ids and scores.
    let public = author_a
        .author_take(TakeTarget::Subject(a), "diarycounterpart public note")
        .unwrap();
    let public_id = EntityId::from_hex(&public.id_hex).unwrap();
    let public_1 = author_a
        .author_take(TakeTarget::Subject(a), "publiconlyneedle first")
        .unwrap();
    let public_2 = author_b
        .author_take(TakeTarget::Subject(b), "publiconlyneedle second")
        .unwrap();
    let public_1_id = EntityId::from_hex(&public_1.id_hex).unwrap();
    let public_2_id = EntityId::from_hex(&public_2.id_hex).unwrap();
    vault
        .batch()
        .text(&public_id, &[("body", "diarycounterpart public note")])
        .text(&public_1_id, &[("body", "publiconlyneedle first")])
        .text(&public_2_id, &[("body", "publiconlyneedle second")])
        .commit()
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn).unwrap();
    let filter = crate::gate::narrow_retrieval_filter(
        &policy.retrieval_floor_for_actor(Some(read_a.actor_key())),
        None,
    )
    .unwrap();
    drop(txn);
    let ordinary = vault
        .query()
        .authority_filter(filter)
        .search_text("publiconlyneedle", 10)
        .limit(10)
        .run_for_pack()
        .unwrap()
        .scores;
    let scoped = read_a.search_text("publiconlyneedle", 10, None).unwrap();
    assert_eq!(
        scoped.value, ordinary,
        "public-only ranking must not change"
    );
    let mixed = read_a.search_text(query, 10, None).unwrap();
    assert!(mixed.value.iter().any(|hit| hit.id == note_b));
    assert!(mixed.value.iter().any(|hit| hit.id == public_id));
    let mut vector = vec![0.0; vault.config.dimensions];
    vector[0] = 1.0;
    let mut public_vector = vec![0.0; vault.config.dimensions];
    public_vector[1] = 1.0;
    vault.put_vector(&public_id, &public_vector).unwrap();
    vault.put_vector(&note_b, &vector).unwrap();
    let vector_only = read_a.search_vector(&vector, 1, None).unwrap();
    assert_eq!(vector_only.value.first().map(|hit| hit.id), Some(note_b));
    let bare = vault.search_vector(&vector, 1).unwrap();
    assert!(!bare.iter().any(|hit| hit.id == note_b));
    assert_eq!(bare.first().map(|hit| hit.id), Some(public_id));
    let outsider_read = vault.scoped_read(read_key(&proof_of(outsider)));
    assert!(
        !outsider_read
            .search_vector(&vector, 10, None)
            .unwrap()
            .value
            .iter()
            .any(|hit| hit.id == note_b)
    );
    let vector_depth = || {
        read_a
            .search_with_effort(&crate::retrieval_depth::DepthSearchRequest {
                probe: crate::retrieval_depth::SearchProbe::Vector {
                    embedding: vector.clone(),
                    query_text: None,
                },
                effort: Effort::Light,
                limit: 10,
                session_scope: None,
                lease: None,
                backend: None,
                token_budget: None,
                deadline: None,
            })
            .unwrap()
    };
    let dense = vector_depth();
    assert!(dense.hits.iter().any(|hit| hit.id == note_b));
    assert_eq!(
        dense.revisions.get(&note_b),
        vault.indexed_revision(&note_b).unwrap().as_ref()
    );
    let hybrid = read_a.search(query, &vector, 10, None).unwrap();
    assert!(hybrid.value.iter().any(|hit| hit.id == note_b));
    assert!(hybrid.value.iter().any(|hit| hit.id == public_id));

    // A second NOTE by A is a DIFFERENT pair. Seeing B through a1-b must
    // never make the ungranted a2-b edge visible to either resident.
    let note_a2 = make_diary(&author_a, a, "other private thought");
    author_b.link_diary_coreference(note_a2, note_b).unwrap();
    let links = NeighborOpts {
        edge_kind: Some("same_as".into()),
        limit: 10,
        ..Default::default()
    };
    assert!(
        reader_a
            .neighbors(&note_a2.to_hex(), &links)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reader_a.neighbors(&note_a.to_hex(), &links).unwrap().len(),
        1
    );
    assert_eq!(
        reader_b.neighbors(&note_b.to_hex(), &links).unwrap().len(),
        1
    );
    let grant_a2 = author_a.grant_diary_coreference(note_a2, note_b).unwrap();
    assert!(
        reader_a
            .neighbors(&note_a2.to_hex(), &links)
            .unwrap()
            .is_empty()
    );
    let _grant_b2 = author_b.grant_diary_coreference(note_a2, note_b).unwrap();
    assert_eq!(
        reader_a.neighbors(&note_a2.to_hex(), &links).unwrap().len(),
        1
    );
    assert_eq!(
        reader_b.neighbors(&note_b.to_hex(), &links).unwrap().len(),
        2
    );
    author_a.revoke_diary_coreference_grant(grant_a2).unwrap();
    assert!(
        reader_a
            .neighbors(&note_a2.to_hex(), &links)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reader_b.neighbors(&note_b.to_hex(), &links).unwrap().len(),
        1
    );
    assert_eq!(
        reader_a.neighbors(&note_a.to_hex(), &links).unwrap().len(),
        1
    );

    author_a.revoke_diary_coreference_grant(grant_a).unwrap();
    check(false); // Revocation takes effect at read time.
    assert_opaque(note_b);
    assert_opaque(grant_a);
    assert_hidden_short();
    assert!(
        !read_a
            .search_vector(&vector, 10, None)
            .unwrap()
            .value
            .iter()
            .any(|hit| hit.id == note_b)
    );
    assert!(!vector_depth().hits.iter().any(|hit| hit.id == note_b));
}

#[test]
fn empty_or_revoked_diary_link_does_not_use_a_neighbor_slot() {
    use crate::context_pack::ContextEntity;
    use crate::note::{NoteScope, NoteWriteEnvelope};
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x51);
    let b = put_person(&vault, 0x52);
    let ma = facade_for(&vault, a);
    let mb = facade_for(&vault, b);
    let diary = |memory: &Memory<'_>, owner: EntityId, text: &str| {
        EntityId::from_hex(
            &memory
                .author_note(&NoteWriteEnvelope {
                    kind: NoteKind::Diary,
                    scope: NoteScope::ActorPrivate { owner_ref: owner },
                    markdown: text.into(),
                    source_revision_ref: [0x71; 16],
                    mask: None,
                })
                .unwrap()
                .id_hex,
        )
        .unwrap()
    };
    let b_note = diary(&mb, b, "private b");
    let a1 = diary(&ma, a, "private a one");
    let a2 = diary(&ma, a, "private a two");
    let (low, high) = if a1 < a2 { (a1, a2) } else { (a2, a1) };
    // Scan order: outbound before inbound, then peer id. Put the Empty pair
    // first in that order regardless of how the injected clock mints ids.
    let (hidden, visible) = if b_note > low && b_note < high {
        (high, low)
    } else {
        (low, high)
    };
    mb.link_diary_coreference(b_note, hidden).unwrap();
    mb.link_diary_coreference(b_note, visible).unwrap();
    let visible_grant_a = ma.grant_diary_coreference(b_note, visible).unwrap();
    let visible_grant_b = mb.grant_diary_coreference(b_note, visible).unwrap();
    assert!(
        b_note < low,
        "injected ID source orders b before both a notes"
    );
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"diary graph-ask matrix").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let proof_of = |actor: EntityId| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(actor.as_bytes()).as_bytes();
        claims.holder_ref = actor.to_hex();
        claims.actor_class = Some("human".into());
        let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
        let sig = issuer
            .binding_proof(&slip, b"diary graph-ask matrix")
            .unwrap();
        vault
            .verify_capability_slip(&issuer.public_key(), &slip, b"diary graph-ask matrix", &sig)
            .unwrap()
    };
    let proof = proof_of(a);
    let read_a =
        vault.scoped_read(crate::claim::ScopedReadActorKey::from_verified_slip(&proof).unwrap());
    // The vault is rooted now: B's facade reads under B's credential.
    let reader_b = facade_for(&vault, b).with_read_proof(&proof_of(b));
    let graph = || {
        read_a
            .graph_ask_neighbors(&b_note, 3, 3, 16_384)
            .unwrap()
            .unwrap()
    };
    let baseline_graph: Vec<_> = graph().into_iter().map(|row| row.0).collect();
    assert_eq!(baseline_graph.len(), 3);
    assert_eq!(baseline_graph.last(), Some(&visible));
    assert!(!baseline_graph.contains(&hidden));
    let outbound = read_a.edges_out(&b_note).unwrap().value.unwrap();
    assert!(
        outbound
            .iter()
            .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == visible)
    );
    assert!(
        !outbound
            .iter()
            .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == hidden)
    );
    let pack_check = |shared_hidden: bool| {
        let item = |id: EntityId, edges| ContextEntity {
            critical: false,
            id,
            short_id: id.to_hex(),
            content_hash: 0,
            source_revision_ref: None,
            entity_type: ENTITY_TYPE_NOTE,
            score: 1.0,
            fields: None,
            edges,
            vector: None,
        };
        let mut pack = vault
            .context_pack()
            .search_text("absent-pack-query", 4)
            .run()
            .unwrap();
        pack.results = vec![item(b_note, Some(vault.edges_out(&b_note).unwrap()))];
        pack.neighbors = vec![item(hidden, None), item(visible, None)];
        let receipt = read_a.filter_context_pack(&mut pack).unwrap();
        assert_eq!(
            pack.neighbors
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            if shared_hidden {
                vec![hidden, visible]
            } else {
                vec![visible]
            }
        );
        let edges = pack.results[0].edges.as_ref().unwrap();
        assert_eq!(
            edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == hidden),
            shared_hidden
        );
        assert!(
            edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::SameAs && edge.target == visible)
        );
        if !shared_hidden {
            assert_eq!(receipt.suppressed_count, 0);
        }
    };
    pack_check(false);
    let opts = NeighborOpts {
        edge_kind: Some("same_as".into()),
        limit: 1,
        ..Default::default()
    };
    let only = reader_b.neighbors(&b_note.to_hex(), &opts).unwrap();
    assert_eq!(only.len(), 1);
    assert_eq!(only[0].short_id, ma.short_ref_or_hex(&visible).unwrap());
    let hidden_grant = ma.grant_diary_coreference(b_note, hidden).unwrap();
    mb.grant_diary_coreference(b_note, hidden).unwrap();
    let first = reader_b.neighbors(&b_note.to_hex(), &opts).unwrap();
    assert_eq!(first[0].short_id, ma.short_ref_or_hex(&hidden).unwrap());
    let newly_shared: Vec<_> = graph().into_iter().map(|row| row.0).collect();
    assert_eq!(newly_shared.len(), 3);
    assert_eq!(newly_shared.last(), Some(&hidden));
    pack_check(true);
    ma.revoke_diary_coreference_grant(hidden_grant).unwrap();
    pack_check(false);
    assert_eq!(
        graph().into_iter().map(|row| row.0).collect::<Vec<_>>(),
        baseline_graph
    );
    let restored = reader_b.neighbors(&b_note.to_hex(), &opts).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].short_id, ma.short_ref_or_hex(&visible).unwrap());

    let wrong_scope_id = EntityId::now();
    vault
        .create_access_grant(
            &wrong_scope_id,
            &crate::access_grant::AccessGrant::companion_profile_read(a, a, visible, 1),
        )
        .unwrap();
    let malformed_id = EntityId::now();
    vault
        .with_write_txn(|txn| {
            let raw = vault
                .store
                .entities
                .get(txn, visible_grant_a.as_bytes())?
                .unwrap();
            let mut malformed = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            malformed.extend_from_slice(b"not a grant body");
            vault
                .store
                .entities
                .put(txn, malformed_id.as_bytes(), &malformed)?;
            Ok(())
        })
        .unwrap();
    let absent = EntityId::from_bytes([0xf5; 16]).unwrap();
    let opaque = ma.revoke_diary_coreference_grant(absent).unwrap_err();
    for id in [b_note, visible_grant_b, wrong_scope_id, malformed_id] {
        assert_eq!(ma.revoke_diary_coreference_grant(id).unwrap_err(), opaque);
    }
    assert_eq!(
        graph().into_iter().map(|row| row.0).collect::<Vec<_>>(),
        baseline_graph
    );
    ma.revoke_diary_coreference_grant(visible_grant_a).unwrap();
    assert!(
        read_a
            .graph_ask_neighbors(&b_note, 3, 3, 16_384)
            .unwrap()
            .is_none()
    );
}
