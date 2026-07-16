//! ONE-1743 (MS-01) unit tests: op vocabulary, the full (state, op)
//! transition table, the ledger fold, CRDT precedence, wire round-trips,
//! and the vault merge/split apply + undo paths.

use super::*;

fn test_config() -> crate::config::VaultConfig {
    let mut cfg = crate::config::VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test-model-v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = crate::config::HnswConfig::default();
    cfg
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(test_config())
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("test id")
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let person = id(byte);
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"person fixture",
        )
        .expect("put person");
    person
}

fn evidence() -> IdentityOpEvidence {
    IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "fixture rationale".to_owned(),
    }
}

fn merge_op(sources: Vec<EntityId>, survivor: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Merge(MergeOp {
        sources,
        survivor,
        evidence: evidence(),
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    })
}

fn split_op(entity: EntityId, heads: Vec<EntityId>) -> IdentityTopologyOp {
    IdentityTopologyOp::Split(SplitOp {
        entity,
        heads,
        reassignment: ReassignmentMap::default(),
        evidence: evidence(),
    })
}

fn facet_op(entity: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Facet(FacetOp {
        entity,
        facets: vec![FacetSpec {
            label: "fixture-mask".to_owned(),
        }],
        reassignment: ReassignmentMap::default(),
        evidence: evidence(),
    })
}

fn distinct_op(a: EntityId, b: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
        a,
        b,
        reason: "fixture reason".to_owned(),
    })
}

fn states_of(
    pairs: &[(EntityId, EntityLifecycleState)],
) -> BTreeMap<EntityId, EntityLifecycleState> {
    pairs.iter().copied().collect()
}

fn expect_rejection(error: Error) -> IdentityTopologyRejection {
    match error {
        Error::IdentityTopologyRejected(rejection) => rejection,
        other => panic!("expected identity-topology rejection, got {other:?}"),
    }
}

// ─── Pure vocabulary + table ────────────────────────────────────────────────

#[test]
fn lifecycle_state_strings_round_trip_and_shell_flags_hold() {
    let cases = [
        (EntityLifecycleState::Active, "active", false),
        (EntityLifecycleState::Merged, "merged", true),
        (EntityLifecycleState::Split, "split", true),
    ];
    assert_eq!(cases.len(), 3);
    for (state, wire, shell) in cases {
        assert_eq!(state.as_str(), wire);
        assert_eq!(EntityLifecycleState::parse(wire), Some(state));
        assert_eq!(state.is_redirect_shell(), shell);
    }
    assert_eq!(EntityLifecycleState::parse("tombstoned"), None);
}

#[test]
fn lifecycle_can_transition_to_pins_the_full_matrix() {
    use EntityLifecycleState::{Active, Merged, Split};
    // Full 3×3 matrix: shells only enter from Active and only exit to
    // Active (undo); shells never transition into each other directly.
    let expected = [
        (Active, Active, false),
        (Active, Merged, true),
        (Active, Split, true),
        (Merged, Active, true),
        (Merged, Merged, false),
        (Merged, Split, false),
        (Split, Active, true),
        (Split, Merged, false),
        (Split, Split, false),
    ];
    assert_eq!(expected.len(), 9);
    for (from, to, allowed) in expected {
        assert_eq!(
            from.can_transition_to(to),
            allowed,
            "can_transition_to({from:?}, {to:?})"
        );
    }
}

#[test]
fn predicate_contracts_are_pinned_and_grammar_valid() {
    assert_eq!(PREDICATE_IDENTITY_TOPOLOGY_OP, "entity.identity_op");
    assert_eq!(PREDICATE_ENTITY_DISTINCT_FROM, "entity.distinct_from");
    // Both pass the D17 public-write grammar (no reserved namespace).
    for predicate in [
        PREDICATE_IDENTITY_TOPOLOGY_OP,
        PREDICATE_ENTITY_DISTINCT_FROM,
    ] {
        crate::claim::validate_predicate(predicate, false).expect("grammar-valid predicate");
    }
}

#[test]
fn lifecycle_merge_join_uses_fixed_precedence_and_is_cai() {
    use EntityLifecycleState::{Active, Merged, Split};
    // Full 3×3 join table: Split > Merged > Active.
    let expected = [
        (Active, Active, Active),
        (Active, Merged, Merged),
        (Active, Split, Split),
        (Merged, Active, Merged),
        (Merged, Merged, Merged),
        (Merged, Split, Split),
        (Split, Active, Split),
        (Split, Merged, Split),
        (Split, Split, Split),
    ];
    assert_eq!(expected.len(), 9);
    for (left, right, joined) in expected {
        assert_eq!(merge_lifecycle_states(left, right), joined);
        // Commutativity.
        assert_eq!(
            merge_lifecycle_states(left, right),
            merge_lifecycle_states(right, left)
        );
        // Idempotence.
        assert_eq!(merge_lifecycle_states(joined, joined), joined);
        // Associativity against every third state.
        for third in [Active, Merged, Split] {
            assert_eq!(
                merge_lifecycle_states(merge_lifecycle_states(left, right), third),
                merge_lifecycle_states(left, merge_lifecycle_states(right, third))
            );
        }
    }
}

#[test]
fn transition_table_covers_every_state_and_role_cell() {
    use EntityLifecycleState::{Active, Merged, Split};
    let a = id(0x11);
    let b = id(0x12);

    for state in [Active, Merged, Split] {
        // merge SOURCE cell.
        let got = evaluate_transition(&states_of(&[(a, state)]), &merge_op(vec![a], b));
        match state {
            Active => assert_eq!(got, Ok(vec![(a, Merged)])),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: a,
                    state: shell,
                })
            ),
        }
        // merge SURVIVOR cell.
        let got = evaluate_transition(&states_of(&[(b, state)]), &merge_op(vec![a], b));
        match state {
            Active => assert_eq!(got, Ok(vec![(a, Merged)])),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: b,
                    state: shell,
                })
            ),
        }
        // split ORIGINAL cell.
        let got = evaluate_transition(&states_of(&[(a, state)]), &split_op(a, vec![b]));
        match state {
            Active => assert_eq!(got, Ok(vec![(a, Split)])),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: a,
                    state: shell,
                })
            ),
        }
        // split HEAD cell.
        let got = evaluate_transition(&states_of(&[(b, state)]), &split_op(a, vec![b]));
        match state {
            Active => assert_eq!(got, Ok(vec![(a, Split)])),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: b,
                    state: shell,
                })
            ),
        }
        // facet BASE cell — no lifecycle movement on success (r6).
        let got = evaluate_transition(&states_of(&[(a, state)]), &facet_op(a));
        match state {
            Active => assert_eq!(got, Ok(Vec::new())),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: a,
                    state: shell,
                })
            ),
        }
        // assert_distinct PAIR cell — symmetric, no lifecycle movement.
        let got = evaluate_transition(&states_of(&[(a, state)]), &distinct_op(a, b));
        match state {
            Active => assert_eq!(got, Ok(Vec::new())),
            shell => assert_eq!(
                got,
                Err(IdentityTopologyRejection::NotActive {
                    entity: a,
                    state: shell,
                })
            ),
        }
    }

    // Shape cells.
    let empty = BTreeMap::new();
    assert_eq!(
        evaluate_transition(&empty, &merge_op(Vec::new(), b)),
        Err(IdentityTopologyRejection::EmptySources)
    );
    assert_eq!(
        evaluate_transition(&empty, &merge_op(vec![a, a], b)),
        Err(IdentityTopologyRejection::DuplicateParticipant { entity: a })
    );
    assert_eq!(
        evaluate_transition(&empty, &merge_op(vec![b], b)),
        Err(IdentityTopologyRejection::SelfReference { entity: b })
    );
    assert_eq!(
        evaluate_transition(&empty, &split_op(a, Vec::new())),
        Err(IdentityTopologyRejection::EmptyHeads)
    );
    assert_eq!(
        evaluate_transition(&empty, &split_op(a, vec![b, b])),
        Err(IdentityTopologyRejection::DuplicateParticipant { entity: b })
    );
    assert_eq!(
        evaluate_transition(&empty, &split_op(a, vec![a])),
        Err(IdentityTopologyRejection::SelfReference { entity: a })
    );
    assert_eq!(
        evaluate_transition(&empty, &distinct_op(a, a)),
        Err(IdentityTopologyRejection::SelfReference { entity: a })
    );

    // Reassignment-map cells.
    let foreign = id(0x13);
    let mut bad_split = SplitOp {
        entity: a,
        heads: vec![b],
        reassignment: ReassignmentMap {
            entries: vec![ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x14)),
                target: ReassignmentTarget::Head(foreign),
            }],
        },
        evidence: evidence(),
    };
    assert_eq!(
        evaluate_transition(&empty, &IdentityTopologyOp::Split(bad_split.clone())),
        Err(IdentityTopologyRejection::UnknownHead { head: foreign })
    );
    bad_split.reassignment.entries[0].target = ReassignmentTarget::Facet { index: 0 };
    assert_eq!(
        evaluate_transition(&empty, &IdentityTopologyOp::Split(bad_split)),
        Err(IdentityTopologyRejection::InvalidReassignmentTarget)
    );
    let mut bad_facet = FacetOp {
        entity: a,
        facets: vec![FacetSpec {
            label: "one".to_owned(),
        }],
        reassignment: ReassignmentMap {
            entries: vec![ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x14)),
                target: ReassignmentTarget::Facet { index: 1 },
            }],
        },
        evidence: evidence(),
    };
    assert_eq!(
        evaluate_transition(&empty, &IdentityTopologyOp::Facet(bad_facet.clone())),
        Err(IdentityTopologyRejection::UnknownFacet { index: 1 })
    );
    bad_facet.reassignment.entries[0].target = ReassignmentTarget::Head(b);
    assert_eq!(
        evaluate_transition(&empty, &IdentityTopologyOp::Facet(bad_facet.clone())),
        Err(IdentityTopologyRejection::InvalidReassignmentTarget)
    );
    bad_facet.facets.clear();
    assert_eq!(
        evaluate_transition(&empty, &IdentityTopologyOp::Facet(bad_facet)),
        Err(IdentityTopologyRejection::EmptyFacets)
    );
}

#[test]
fn distinct_pair_key_normalizes_symmetric_order() {
    let a = id(0x21);
    let b = id(0x22);
    assert_eq!(distinct_pair_key(a, b), distinct_pair_key(b, a));
    assert_eq!(distinct_pair_key(a, b), (a, b));
    assert_eq!(distinct_pair_key(a, a), (a, a));
}

// ─── Ledger fold ────────────────────────────────────────────────────────────

#[test]
fn fold_applies_merge_undo_and_rejects_stale_or_double_undo() {
    let a = id(0x31);
    let b = id(0x32);
    let e1 = id(0x41);
    let u1 = id(0x42);
    let e2 = id(0x43);
    let u2 = id(0x44);

    // Apply e1, then a second merge of the now-shelled source must reject.
    let fold = fold_identity_topology_log(&[
        IdentityTopologyEvent {
            event_id: e1,
            at: 100,
            action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        },
        IdentityTopologyEvent {
            event_id: e2,
            at: 200,
            action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        },
    ]);
    assert_eq!(fold.states.len(), 1);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Merged));
    assert_eq!(fold.current_event.get(&b), Some(&e1));
    assert_eq!(
        fold.rejections,
        vec![(
            e2,
            IdentityTopologyRejection::NotActive {
                entity: b,
                state: EntityLifecycleState::Merged,
            },
        )]
    );

    // Undo restores Active; undoing again is stale; undoing the undo is
    // not undoable.
    let fold = fold_identity_topology_log(&[
        IdentityTopologyEvent {
            event_id: e1,
            at: 100,
            action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        },
        IdentityTopologyEvent {
            event_id: u1,
            at: 200,
            action: IdentityTopologyAction::Undo { target: e1 },
        },
        IdentityTopologyEvent {
            event_id: e2,
            at: 300,
            action: IdentityTopologyAction::Undo { target: e1 },
        },
        IdentityTopologyEvent {
            event_id: u2,
            at: 400,
            action: IdentityTopologyAction::Undo { target: u1 },
        },
    ]);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Active));
    assert_eq!(fold.current_event.len(), 0);
    assert_eq!(
        fold.rejections,
        vec![
            (e2, IdentityTopologyRejection::NotCurrent { event: e1 }),
            (u2, IdentityTopologyRejection::NotUndoable { event: u1 }),
        ]
    );
}

#[test]
fn fold_orders_events_deterministically_by_time_then_event_id() {
    let a = id(0x31);
    let b = id(0x32);
    let e1 = id(0x41);
    let u1 = id(0x42);
    let events = vec![
        IdentityTopologyEvent {
            event_id: u1,
            at: 200,
            action: IdentityTopologyAction::Undo { target: e1 },
        },
        IdentityTopologyEvent {
            event_id: e1,
            at: 100,
            action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        },
    ];
    let mut reversed = events.clone();
    reversed.reverse();
    let fold = fold_identity_topology_log(&events);
    let fold_reversed = fold_identity_topology_log(&reversed);
    assert_eq!(fold, fold_reversed);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Active));
    assert_eq!(fold.rejections.len(), 0);

    // Same-second tie: the smaller event id folds first, so the undo (u1,
    // later id) still lands after its target.
    let tied = vec![
        IdentityTopologyEvent {
            event_id: u1,
            at: 100,
            action: IdentityTopologyAction::Undo { target: e1 },
        },
        IdentityTopologyEvent {
            event_id: e1,
            at: 100,
            action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        },
    ];
    let fold = fold_identity_topology_log(&tied);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Active));
    assert_eq!(fold.rejections.len(), 0);
}

#[test]
fn stored_event_wire_round_trips_and_fails_closed() {
    let a = id(0x31);
    let b = id(0x32);
    let c = id(0x33);
    let actor = WriteActor::new(id(0x51), EdgeActorClass::Agent);
    let cases = vec![
        StoredIdentityOpEvent {
            at: 100,
            actor: Some(actor),
            action: StoredIdentityOpAction::Merge {
                sources: vec![b, c],
                survivor: a,
            },
        },
        StoredIdentityOpEvent {
            at: 200,
            actor: None,
            action: StoredIdentityOpAction::Split {
                entity: a,
                heads: vec![b, c],
                assigned: 2,
                residue: 1,
            },
        },
        StoredIdentityOpEvent {
            at: 300,
            actor: None,
            action: StoredIdentityOpAction::Undo { target: b },
        },
    ];
    assert_eq!(cases.len(), 3);
    for event in cases {
        let decoded = StoredIdentityOpEvent::decode(&event.encode()).expect("round trip");
        assert_eq!(decoded, event);
    }

    // Fail-closed decode: non-map, unknown kind, missing field, unknown plan.
    assert!(matches!(
        StoredIdentityOpEvent::decode(&Value::from("merge")),
        Err(Error::InvalidClaimBody(_))
    ));
    let unknown_kind = Value::Map(vec![
        (Value::from("kind"), Value::from("rename")),
        (Value::from("at"), Value::from(1_u64)),
    ]);
    assert!(matches!(
        StoredIdentityOpEvent::decode(&unknown_kind),
        Err(Error::InvalidClaimBody(_))
    ));
    let missing_survivor = Value::Map(vec![
        (Value::from("kind"), Value::from("merge")),
        (Value::from("at"), Value::from(1_u64)),
        (Value::from("plan"), Value::from("read_through")),
        (Value::from("sources"), Value::Array(Vec::new())),
    ]);
    assert!(matches!(
        StoredIdentityOpEvent::decode(&missing_survivor),
        Err(Error::InvalidClaimBody(_))
    ));
    let unknown_plan = Value::Map(vec![
        (Value::from("kind"), Value::from("merge")),
        (Value::from("at"), Value::from(1_u64)),
        (Value::from("plan"), Value::from("rewrite_references")),
        (Value::from("sources"), Value::Array(Vec::new())),
        (
            Value::from("survivor"),
            Value::Binary(a.as_bytes().to_vec()),
        ),
    ]);
    assert!(matches!(
        StoredIdentityOpEvent::decode(&unknown_plan),
        Err(Error::InvalidClaimBody(_))
    ));
}

// ─── Vault apply paths ──────────────────────────────────────────────────────

#[test]
fn merge_apply_writes_shell_edges_ledger_event_and_never_rewrites_subjects() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let actor = WriteActor::new(put_person(&vault, 0x63), EdgeActorClass::Human);

    // A pre-existing claim whose subject is the loser (provenance truth).
    let note_id = id(0x64);
    let note = ClaimBody::new(
        "user.note",
        ClaimSubject::Entity(loser),
        Value::from("fixture note"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(
            &note_id,
            &note,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put note claim");

    let write = IdentityOpWrite::auto(ClaimSource::Inferred).with_actor(actor);
    let outcome = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
        .expect("apply merge");
    assert_eq!(
        outcome.transitions,
        vec![(loser, EntityLifecycleState::Merged)]
    );

    // Canonical D11 edge: exactly one merged_into, loser -> survivor.
    let targets = vault
        .targets(&loser, EdgeKind::MergedInto, None)
        .expect("read merged_into");
    assert_eq!(targets, vec![survivor]);
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Merged
    );
    assert_eq!(
        vault
            .entity_lifecycle_state(&survivor)
            .expect("survivor state"),
        EntityLifecycleState::Active
    );

    // The loser is a shell, NOT a tombstone: body and type stay readable.
    assert!(vault.get(&loser).expect("read loser body").is_some());
    assert_eq!(
        vault.get_entity_type(&loser).expect("read loser type"),
        Some(crate::registry::ENTITY_TYPE_PERSON)
    );

    // Exactly one ledger event, attached to the survivor, Auto by default,
    // carrying evidence + actor.
    let survivor_claims = vault
        .claims_for_subject(&survivor)
        .expect("survivor claims");
    assert_eq!(survivor_claims.len(), 1);
    let event_id = outcome.event;
    assert_eq!(survivor_claims, vec![event_id]);
    let event = vault
        .get_claim(&event_id)
        .expect("read event")
        .expect("event exists");
    assert_eq!(event.predicate, PREDICATE_IDENTITY_TOPOLOGY_OP);
    assert_eq!(event.approval, ClaimApprovalStatus::Auto);
    assert_eq!(event.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(event.subject, ClaimSubject::Entity(survivor));
    assert_eq!(event.valid_from, Some(200));
    assert_eq!(event.source, Some(ClaimSource::Inferred));
    assert!(event.evidence.is_some());
    let stored = StoredIdentityOpEvent::decode(&event.value).expect("decode event");
    assert_eq!(
        stored,
        StoredIdentityOpEvent {
            at: 200,
            actor: Some(actor),
            action: StoredIdentityOpAction::Merge {
                sources: vec![loser],
                survivor,
            },
        }
    );

    // r6: the note claim's stored subject is NOT rewritten to the survivor.
    let note_after = vault
        .get_claim(&note_id)
        .expect("read note")
        .expect("note exists");
    assert_eq!(note_after.subject, ClaimSubject::Entity(loser));
    assert_eq!(
        vault
            .claims_for_subject(&loser)
            .expect("loser claims")
            .len(),
        1
    );

    // The apply event rides the existing IdentityLifecycle receipt kind.
    let receipts = vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
        )
        .expect("query receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].receipt_kind,
        crate::receipt::ReceiptKind::IdentityLifecycle
    );
    assert_eq!(receipts[0].outcome, "merge");
    assert_eq!(receipts[0].occurred_at, 200);
    assert_eq!(receipts[0].actor, Some(actor.entity_ref().to_hex()));
    assert_eq!(receipts[0].fields.get("survivor"), Some(&survivor.to_hex()));
    assert_eq!(
        receipts[0].fields.get("source_count"),
        Some(&"1".to_owned())
    );
}

#[test]
fn merge_apply_rejects_shells_facets_missing_and_non_structural_participants() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let bystander = put_person(&vault, 0x65);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
        .expect("apply merge");

    // Shell SOURCE: merging the shell again rejects — resolution through
    // the redirect is read-time (r6), the ledger stays explicit.
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![loser], bystander), &write, 300)
        .expect_err("shell source must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotActive {
            entity: loser,
            state: EntityLifecycleState::Merged,
        }
    );

    // Shell SURVIVOR: merging INTO a shell rejects.
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![bystander], loser), &write, 300)
        .expect_err("shell survivor must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotActive {
            entity: loser,
            state: EntityLifecycleState::Merged,
        }
    );

    // FACET participant: the no-merge canon cell (ARCH-0022 / §5).
    let facet = id(0x66);
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"facet fixture",
        )
        .expect("put facet");
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![facet], bystander), &write, 300)
        .expect_err("facet merge must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::FacetMerge { entity: facet }
    );

    // Missing participant.
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![id(0x67)], bystander), &write, 300)
        .expect_err("missing source must reject");
    assert!(matches!(err, Error::EntityNotFound));

    // Non-structural participant (a CLAIM): claims supersede, entities merge.
    let claim_id = id(0x68);
    let claim = ClaimBody::new(
        "user.note",
        ClaimSubject::Entity(bystander),
        Value::from("fixture"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(
            &claim_id,
            &claim,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put claim fixture");
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![claim_id], bystander), &write, 300)
        .expect_err("claim participant must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotStructural { entity: claim_id }
    );

    // Shape rejections through the vault door.
    let err = vault
        .apply_identity_topology_op(&merge_op(Vec::new(), bystander), &write, 300)
        .expect_err("empty sources must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::EmptySources
    );
    let err = vault
        .apply_identity_topology_op(&merge_op(vec![bystander], bystander), &write, 300)
        .expect_err("self merge must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::SelfReference { entity: bystander }
    );

    // Nothing extra was written by the rejected ops: the bystander is
    // still Active with zero shell edges, and no ledger event attached.
    assert_eq!(
        vault
            .entity_lifecycle_state(&bystander)
            .expect("bystander state"),
        EntityLifecycleState::Active
    );
    assert_eq!(
        vault
            .targets(&bystander, EdgeKind::MergedInto, None)
            .expect("bystander edges")
            .len(),
        0
    );
}

#[test]
fn undo_merge_removes_edges_restores_active_and_appends_counter_event() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let outcome = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
        .expect("apply merge");
    let undo = vault
        .undo_identity_topology_event(&outcome.event, &write, 300)
        .expect("undo merge");
    assert_eq!(
        undo.transitions,
        vec![(loser, EntityLifecycleState::Active)]
    );

    // Counter-event semantics: edge removed, state restored, BOTH ledger
    // events still readable (append-only, r1).
    assert_eq!(
        vault
            .targets(&loser, EdgeKind::MergedInto, None)
            .expect("merged_into after undo")
            .len(),
        0
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
    let survivor_claims = vault
        .claims_for_subject(&survivor)
        .expect("survivor claims");
    assert_eq!(survivor_claims.len(), 2);
    let counter = vault
        .get_claim(&undo.event)
        .expect("read counter event")
        .expect("counter exists");
    let stored = StoredIdentityOpEvent::decode(&counter.value).expect("decode counter");
    assert_eq!(
        stored.action,
        StoredIdentityOpAction::Undo {
            target: outcome.event,
        }
    );
    let original = vault
        .get_claim(&outcome.event)
        .expect("read original event")
        .expect("original still readable");
    assert_eq!(original.lifecycle, ClaimLifecycleStatus::Active);

    // Double undo is stale.
    let err = vault
        .undo_identity_topology_event(&outcome.event, &write, 400)
        .expect_err("double undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotCurrent {
            event: outcome.event,
        }
    );
    // Undoing the counter-event is not undoable.
    let err = vault
        .undo_identity_topology_event(&undo.event, &write, 400)
        .expect_err("undo of undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotUndoable { event: undo.event }
    );

    // Both ledger events project as IdentityLifecycle receipts: the apply
    // AND its counter-event (symmetric honesty — undo is never silent).
    let receipts = vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
        )
        .expect("query receipts");
    assert_eq!(receipts.len(), 2);
    let undo_receipts: Vec<_> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == "undo")
        .collect();
    assert_eq!(undo_receipts.len(), 1);
    assert_eq!(undo_receipts[0].occurred_at, 300);
    assert_eq!(
        undo_receipts[0].fields.get("undo_of"),
        Some(&outcome.event.to_hex())
    );
}

#[test]
fn undo_binds_to_the_current_ledger_event_not_edge_shape() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Same-second merge → undo → re-merge: the first event's undo must be
    // stale even though the re-merged edge bytes are identical.
    let first = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 100)
        .expect("first merge");
    vault
        .undo_identity_topology_event(&first.event, &write, 100)
        .expect("undo first merge");
    let second = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 100)
        .expect("re-merge");

    let err = vault
        .undo_identity_topology_event(&first.event, &write, 100)
        .expect_err("stale undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotCurrent { event: first.event }
    );

    vault
        .undo_identity_topology_event(&second.event, &write, 100)
        .expect("undo current merge");
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn split_apply_writes_head_edges_event_stats_and_undo_restores() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head_a = put_person(&vault, 0x62);
    let head_b = put_person(&vault, 0x63);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let op = IdentityTopologyOp::Split(SplitOp {
        entity: original,
        heads: vec![head_a, head_b],
        reassignment: ReassignmentMap {
            entries: vec![
                ReassignmentEntry {
                    item: ClaimSubject::Entity(id(0x71)),
                    target: ReassignmentTarget::Head(head_a),
                },
                ReassignmentEntry {
                    item: ClaimSubject::Entity(id(0x72)),
                    target: ReassignmentTarget::Residue,
                },
            ],
        },
        evidence: evidence(),
    });
    let outcome = vault
        .apply_identity_topology_op(&op, &write, 200)
        .expect("apply split");
    assert_eq!(
        outcome.transitions,
        vec![(original, EntityLifecycleState::Split)]
    );

    let mut heads = vault
        .targets(&original, EdgeKind::SplitInto, None)
        .expect("split_into targets");
    heads.sort();
    let mut expected = vec![head_a, head_b];
    expected.sort();
    assert_eq!(heads, expected);
    assert_eq!(
        vault
            .entity_lifecycle_state(&original)
            .expect("original state"),
        EntityLifecycleState::Split
    );
    assert_eq!(
        vault.entity_lifecycle_state(&head_a).expect("head state"),
        EntityLifecycleState::Active
    );

    // r2 first-class stats on the ledger event.
    let event = vault
        .get_claim(&outcome.event)
        .expect("read event")
        .expect("event exists");
    let stored = StoredIdentityOpEvent::decode(&event.value).expect("decode event");
    assert_eq!(
        stored.action,
        StoredIdentityOpAction::Split {
            entity: original,
            heads: vec![head_a, head_b],
            assigned: 1,
            residue: 1,
        }
    );

    // The split apply event projects one IdentityLifecycle receipt with the
    // r2 stats as fields.
    let receipts = vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
        )
        .expect("query receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "split");
    assert_eq!(receipts[0].fields.get("head_count"), Some(&"2".to_owned()));
    assert_eq!(receipts[0].fields.get("assigned"), Some(&"1".to_owned()));
    assert_eq!(receipts[0].fields.get("residue"), Some(&"1".to_owned()));

    // MS-01 zero-head split parks until the redirect projection (ONE-1744).
    let err = vault
        .apply_identity_topology_op(&split_op(id(0x64), Vec::new()), &write, 300)
        .expect_err("zero heads must reject");
    assert!(matches!(err, Error::EntityNotFound));
    let fresh = put_person(&vault, 0x64);
    let err = vault
        .apply_identity_topology_op(&split_op(fresh, Vec::new()), &write, 300)
        .expect_err("zero heads must reject");
    assert_eq!(expect_rejection(err), IdentityTopologyRejection::EmptyHeads);

    // Undo restores the original and removes both head edges.
    let undo = vault
        .undo_identity_topology_event(&outcome.event, &write, 400)
        .expect("undo split");
    assert_eq!(
        undo.transitions,
        vec![(original, EntityLifecycleState::Active)]
    );
    assert_eq!(
        vault
            .targets(&original, EdgeKind::SplitInto, None)
            .expect("split_into after undo")
            .len(),
        0
    );
    assert_eq!(
        vault
            .entity_lifecycle_state(&original)
            .expect("original state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn facet_and_assert_distinct_doors_validate_then_stay_unarmed() {
    let (_dir, vault) = open_vault();
    let base = put_person(&vault, 0x61);
    let other = put_person(&vault, 0x62);
    let survivor = put_person(&vault, 0x63);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Shell base: the transition table fires before the unarmed door.
    vault
        .apply_identity_topology_op(&merge_op(vec![base], survivor), &write, 200)
        .expect("apply merge");
    let err = vault
        .apply_identity_topology_op(&facet_op(base), &write, 300)
        .expect_err("facet of a shell must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotActive {
            entity: base,
            state: EntityLifecycleState::Merged,
        }
    );
    let err = vault
        .apply_identity_topology_op(&distinct_op(other, other), &write, 300)
        .expect_err("self distinct must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::SelfReference { entity: other }
    );

    // Valid ops hit the honest unarmed door and write NOTHING.
    let err = vault
        .apply_identity_topology_op(&facet_op(other), &write, 300)
        .expect_err("facet apply is unarmed");
    assert!(matches!(err, Error::IdentityTopologyUnarmed(_)));
    let err = vault
        .apply_identity_topology_op(&distinct_op(other, survivor), &write, 300)
        .expect_err("assert_distinct apply is unarmed");
    assert!(matches!(err, Error::IdentityTopologyUnarmed(_)));
    assert_eq!(
        vault
            .claims_for_subject(&other)
            .expect("other claims")
            .len(),
        0
    );
    assert_eq!(
        vault.entity_lifecycle_state(&other).expect("other state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn lifecycle_state_fails_closed_on_conflicting_shell_edges() {
    let (_dir, vault) = open_vault();
    let entity = put_person(&vault, 0x61);
    let peer_a = put_person(&vault, 0x62);
    let peer_b = put_person(&vault, 0x63);

    // Raw writes can only produce this outside the apply path; reads must
    // refuse to guess which shell state wins.
    vault
        .put_edge(&entity, EdgeKind::MergedInto, &peer_a, 0.3)
        .expect("raw merged_into");
    vault
        .put_edge(&entity, EdgeKind::SplitInto, &peer_b, 0.3)
        .expect("raw split_into");
    let err = vault
        .entity_lifecycle_state(&entity)
        .expect_err("conflicting shells must fail closed");
    assert!(matches!(err, Error::CorruptedIndex(_)));
}

// ─── Edge-kind registry pins for the new redirect edges ────────────────────

#[test]
fn merged_into_and_split_into_edge_kind_pins() {
    // Discriminants 21/22 — byte 20 stays unregistered (the ARCH-0034
    // frontier probe pins it; final byte assignment is an L0 registry
    // ruling, flagged in the ONE-1743 out-file).
    assert_eq!(EdgeKind::MergedInto as u8, 21);
    assert_eq!(EdgeKind::SplitInto as u8, 22);
    assert_eq!(EdgeKind::try_from_u8(20), None);
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));

    // Structural 12-byte layout, supersedes-class stored-weight prior, and
    // supersedes-class PPR λ.
    for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
        let value = crate::edge::encode_edge_value(kind, 0.3, 1, Vad::NEUTRAL, None)
            .expect("encode structural value");
        assert_eq!(value.len(), 12);
        assert_eq!(kind.default_weight(), Some(0.3));
        assert_eq!(crate::ppr::lambda_for_kind(kind), Some(0.3));
    }
}
