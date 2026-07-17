//! ONE-1743 (MS-01) unit tests: op vocabulary, the full (state, op)
//! transition table, the seq-ordered ledger fold, CRDT precedence, the
//! type-76 record wire, and the vault merge/split apply + undo doors
//! (consent axis, actor validation, reserved edges, receipts).

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

fn expect_applied(outcome: IdentityOpOutcome) -> (EntityId, Vec<(EntityId, EntityLifecycleState)>) {
    match outcome {
        IdentityOpOutcome::Applied { event, transitions } => (event, transitions),
        other => panic!("expected Applied outcome, got {other:?}"),
    }
}

fn expect_parked(outcome: IdentityOpOutcome) -> EntityId {
    match outcome {
        IdentityOpOutcome::Parked { event } => event,
        other => panic!("expected Parked outcome, got {other:?}"),
    }
}

fn fold_event(
    event_id: EntityId,
    seq: u64,
    action: IdentityTopologyAction,
) -> IdentityTopologyEvent {
    IdentityTopologyEvent {
        event_id,
        seq,
        approval: ClaimApprovalStatus::Auto,
        action,
    }
}

fn event_count(vault: &Vault) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .identity_topology_events_in_txn(&rtxn)
        .expect("scan events")
        .len()
}

/// Writes a raw shell edge through the INTERNAL op path (the public
/// builders reject reserved kinds), to fabricate corruption fixtures.
fn force_edge(vault: &Vault, src: EntityId, kind: EdgeKind, tgt: EntityId) {
    vault
        .with_write_txn(|wtxn| {
            crate::batch::apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![BatchOp::EdgeWithCreatedAt {
                    src,
                    kind,
                    tgt,
                    weight: 0.3,
                    created_at: 100,
                    vad: crate::affect::Vad::NEUTRAL,
                    provenance: None,
                }],
                true,
                false,
                true,
            )
        })
        .expect("force edge");
}

fn identity_receipts(vault: &Vault) -> Vec<crate::receipt::ReceiptRecord> {
    vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
        )
        .expect("query receipts")
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
fn distinct_from_contract_is_pinned_and_grammar_valid() {
    assert_eq!(PREDICATE_ENTITY_DISTINCT_FROM, "entity.distinct_from");
    // Passes the D17 public-write grammar (no reserved namespace): the
    // anti-merge assertion stays a public CLAIM (statement, not action).
    crate::claim::validate_predicate(PREDICATE_ENTITY_DISTINCT_FROM, false)
        .expect("grammar-valid predicate");
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
        fold_event(e1, 1, IdentityTopologyAction::Apply(merge_op(vec![b], a))),
        fold_event(e2, 2, IdentityTopologyAction::Apply(merge_op(vec![b], a))),
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
        fold_event(e1, 1, IdentityTopologyAction::Apply(merge_op(vec![b], a))),
        fold_event(u1, 2, IdentityTopologyAction::Undo { target: e1 }),
        fold_event(e2, 3, IdentityTopologyAction::Undo { target: e1 }),
        fold_event(u2, 4, IdentityTopologyAction::Undo { target: u1 }),
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
fn fold_orders_by_engine_seq_and_ignores_input_order() {
    let a = id(0x31);
    let b = id(0x32);
    let e1 = id(0x41);
    let u1 = id(0x42);
    let events = vec![
        fold_event(u1, 2, IdentityTopologyAction::Undo { target: e1 }),
        fold_event(e1, 1, IdentityTopologyAction::Apply(merge_op(vec![b], a))),
    ];
    let mut reversed = events.clone();
    reversed.reverse();
    let fold = fold_identity_topology_log(&events);
    let fold_reversed = fold_identity_topology_log(&reversed);
    assert_eq!(fold, fold_reversed);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Active));
    assert_eq!(fold.rejections.len(), 0);

    // Seq tie (divergent replicas): the smaller event id folds first, so
    // the outcome stays deterministic regardless of input order.
    let tied = vec![
        fold_event(u1, 1, IdentityTopologyAction::Undo { target: e1 }),
        fold_event(e1, 1, IdentityTopologyAction::Apply(merge_op(vec![b], a))),
    ];
    let fold = fold_identity_topology_log(&tied);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Active));
    assert_eq!(fold.rejections.len(), 0);
}

#[test]
fn fold_counts_effective_events_only() {
    let a = id(0x31);
    let b = id(0x32);
    let parked = IdentityTopologyEvent {
        event_id: id(0x41),
        seq: 1,
        approval: ClaimApprovalStatus::Proposed,
        action: IdentityTopologyAction::Apply(merge_op(vec![b], a)),
    };
    // A parked proposal has ZERO topology effects: the source stays
    // Active and a later effective merge of the same pair applies.
    let fold = fold_identity_topology_log(std::slice::from_ref(&parked));
    assert_eq!(fold.states.len(), 0);
    assert_eq!(fold.current_event.len(), 0);
    assert_eq!(fold.rejections.len(), 0);

    let fold = fold_identity_topology_log(&[
        parked,
        fold_event(
            id(0x42),
            2,
            IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        ),
    ]);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Merged));
    assert_eq!(fold.current_event.get(&b), Some(&id(0x42)));
    assert_eq!(fold.rejections.len(), 0);
}

// ─── Type-76 record wire ────────────────────────────────────────────────────

#[test]
fn stored_event_wire_round_trips_canonically_and_fails_closed() {
    let a = id(0x31);
    let b = id(0x32);
    let c = id(0x33);
    let actor = WriteActor::new(id(0x51), EdgeActorClass::Agent);

    // The split map is given UNSORTED; the wire canonicalizes by item
    // bytes and the decode yields the canonical order (codex#6: the map is
    // carried verbatim, never reduced to stats).
    let unsorted = ReassignmentMap {
        entries: vec![
            ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x72)),
                target: ReassignmentTarget::Residue,
            },
            ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x71)),
                target: ReassignmentTarget::Head(b),
            },
        ],
    };
    let split_record = StoredIdentityOpEvent {
        seq: 2,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 0.9,
        evidence: None,
        action: StoredIdentityOpAction::Split {
            entity: a,
            heads: vec![b, c],
            reassignment: unsorted.clone(),
        },
    };
    let decoded =
        StoredIdentityOpEvent::decode_value(&split_record.encode_value()).expect("split decode");
    let StoredIdentityOpAction::Split { reassignment, .. } = &decoded.action else {
        panic!("expected split action");
    };
    assert_eq!(*reassignment, unsorted.canonicalized());
    assert_eq!(reassignment.entries.len(), 2);
    assert_eq!(reassignment.entries[0].item, ClaimSubject::Entity(id(0x71)));
    assert_eq!(reassignment.assigned_and_residue_counts(), (1, 1));

    // Merge + undo round trips, with actor and evidence carried.
    let cases = vec![
        StoredIdentityOpEvent {
            seq: 1,
            at: 100,
            actor: Some(actor),
            source: ClaimSource::UserStated,
            approval: ClaimApprovalStatus::Approved,
            confidence: 1.0,
            evidence: Some(IdentityOpEvidence {
                refs: vec![b, c],
                rationale: "same referent".to_owned(),
            }),
            action: StoredIdentityOpAction::Merge {
                sources: vec![b, c],
                survivor: a,
            },
        },
        StoredIdentityOpEvent {
            seq: 3,
            at: 300,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Proposed,
            confidence: 0.5,
            evidence: None,
            action: StoredIdentityOpAction::Undo { target: b },
        },
    ];
    assert_eq!(cases.len(), 2);
    for record in cases {
        let bytes = encode_identity_topology_event_body(&record).expect("encode");
        let decoded = decode_identity_topology_event_body(&bytes).expect("decode");
        assert_eq!(decoded, record);
        // Trailing bytes fail closed.
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(matches!(
            decode_identity_topology_event_body(&padded),
            Err(Error::InvalidIdentityTopologyEventBody(_))
        ));
    }

    // Fail-closed decode: non-map, unknown kind, unknown plan, missing
    // seq, out-of-range confidence, both-targets map row.
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::from("merge")),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
    let base = |kind: &str| -> Vec<(Value, Value)> {
        vec![
            (Value::from("kind"), Value::from(kind)),
            (Value::from("seq"), Value::from(1_u64)),
            (Value::from("at"), Value::from(1_u64)),
            (Value::from("src"), Value::from("inferred")),
            (Value::from("appr"), Value::from("auto")),
            (Value::from("conf"), Value::F32(1.0)),
        ]
    };
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::Map(base("rename"))),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
    let mut bad_plan = base("merge");
    bad_plan.push((Value::from("sources"), Value::Array(Vec::new())));
    bad_plan.push((
        Value::from("survivor"),
        Value::Binary(a.as_bytes().to_vec()),
    ));
    bad_plan.push((Value::from("plan"), Value::from("rewrite_references")));
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::Map(bad_plan)),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
    let mut no_seq = base("undo");
    no_seq.retain(|(key, _)| key.as_str() != Some("seq"));
    no_seq.push((Value::from("target"), Value::Binary(a.as_bytes().to_vec())));
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::Map(no_seq)),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
    let mut bad_conf = base("undo");
    bad_conf.retain(|(key, _)| key.as_str() != Some("conf"));
    bad_conf.push((Value::from("conf"), Value::F32(1.5)));
    bad_conf.push((Value::from("target"), Value::Binary(a.as_bytes().to_vec())));
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::Map(bad_conf)),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
    let mut both_targets = base("split");
    both_targets.push((Value::from("entity"), Value::Binary(a.as_bytes().to_vec())));
    both_targets.push((
        Value::from("heads"),
        Value::Array(vec![Value::Binary(b.as_bytes().to_vec())]),
    ));
    both_targets.push((
        Value::from("map"),
        Value::Array(vec![Value::Map(vec![
            (
                Value::from("item"),
                Value::Binary(id(0x71).as_bytes().to_vec()),
            ),
            (Value::from("head"), Value::Binary(b.as_bytes().to_vec())),
            (Value::from("facet"), Value::from(0_u32)),
        ])]),
    ));
    assert!(matches!(
        StoredIdentityOpEvent::decode_value(&Value::Map(both_targets)),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));
}

// ─── Vault doors ────────────────────────────────────────────────────────────

#[test]
fn type_76_is_a_pinned_engine_authored_maintenance_kind() {
    // Conformance pin for the owner-ruled seat (byte-space v3 canon row).
    assert_eq!(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, 76);
    assert!(!crate::registry::is_structural_kind(76));
    assert!(crate::registry::short_id_prefix(76).is_err());

    // D5/MODEL pattern: public puts are rejected typed; only the
    // identity-topology door (allow_maintenance) writes the byte.
    let (_dir, vault) = open_vault();
    let err = vault
        .put_entity(
            &id(0x50),
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"forged event",
        )
        .expect_err("public put of type 76 must reject");
    assert!(matches!(err, Error::MaintenanceKindNotWritable(76)));
    assert_eq!(event_count(&vault), 0);
}

#[test]
fn reserved_edge_kinds_reject_every_public_write_path() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x61);
    let b = put_person(&vault, 0x62);

    // Raw put_edge / put_edge_with_vad (grok P2 / codex#3).
    let err = vault
        .put_edge(&a, EdgeKind::MergedInto, &b, 0.3)
        .expect_err("raw merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));
    let err = vault
        .put_edge_with_vad(
            &a,
            EdgeKind::SplitInto,
            &b,
            0.3,
            crate::affect::Vad::NEUTRAL,
        )
        .expect_err("raw split_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("split_into")));

    // Batch builder creation + deletion ops.
    let err = vault
        .batch()
        .edge_with_created_at(&a, EdgeKind::MergedInto, &b, 0.3, 100)
        .commit()
        .expect_err("batch created_at merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));
    let err = vault
        .batch()
        .edge_with_created_at_and_vad(
            &a,
            EdgeKind::SplitInto,
            &b,
            0.3,
            100,
            crate::affect::Vad::NEUTRAL,
        )
        .commit()
        .expect_err("batch created_at+vad split_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("split_into")));
    let err = vault
        .delete_edge(&a, EdgeKind::MergedInto, &b)
        .expect_err("public delete of merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));

    // Txn builder path.
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge(&a, EdgeKind::SplitInto, &b, 0.3)
                .apply(wtxn)
        })
        .expect_err("txn builder split_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("split_into")));

    // Operational setters (MS-01 perimeter: the reseat's "setters cannot
    // alter topology" carve-out was wrong — a zero weight makes PPR drop
    // the shell edge entirely, an unledgered topology effect).
    let err = vault
        .set_edge_weight(&a, EdgeKind::MergedInto, &b, 0.0)
        .expect_err("weight setter merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));
    let err = vault
        .set_edge_vad(&a, EdgeKind::SplitInto, &b, crate::affect::Vad::NEUTRAL)
        .expect_err("vad setter split_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("split_into")));
    let err = vault
        .batch()
        .set_edge_weight(&a, EdgeKind::SplitInto, &b, 0.9)
        .commit()
        .expect_err("batch weight setter split_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("split_into")));
    let err = vault
        .batch()
        .set_edge_vad(&a, EdgeKind::MergedInto, &b, crate::affect::Vad::NEUTRAL)
        .commit()
        .expect_err("batch vad setter merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .set_edge_vad(&a, EdgeKind::MergedInto, &b, crate::affect::Vad::NEUTRAL)
                .apply(wtxn)
        })
        .expect_err("txn vad setter merged_into must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));

    // Nothing leaked through any of the rejected paths.
    assert_eq!(
        vault
            .targets(&a, EdgeKind::MergedInto, None)
            .expect("merged_into targets")
            .len(),
        0
    );
    assert_eq!(
        vault
            .targets(&a, EdgeKind::SplitInto, None)
            .expect("split_into targets")
            .len(),
        0
    );
}

#[test]
fn merge_apply_writes_shell_edges_event_record_and_receipt() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let actor = WriteActor::new(put_person(&vault, 0x63), EdgeActorClass::Human);

    // A pre-existing claim whose subject is the loser (provenance truth).
    let note_id = id(0x64);
    let note = crate::claim::ClaimBody::new(
        "user.note",
        ClaimSubject::Entity(loser),
        Value::from("fixture note"),
        1.0,
        ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
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
    let (event_id, transitions) = expect_applied(outcome);
    assert_eq!(transitions, vec![(loser, EntityLifecycleState::Merged)]);

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

    // Exactly one type-76 ledger event, seq-stamped, Auto by default,
    // carrying actor + evidence.
    assert_eq!(event_count(&vault), 1);
    let record = vault
        .identity_topology_event(&event_id)
        .expect("read event")
        .expect("event exists");
    assert_eq!(record.seq, 1);
    assert_eq!(record.at, 200);
    assert_eq!(record.actor, Some(actor));
    assert_eq!(record.source, ClaimSource::Inferred);
    assert_eq!(record.approval, ClaimApprovalStatus::Auto);
    assert!(record.evidence.is_some());
    assert_eq!(
        record.action,
        StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        }
    );

    // r6: the note claim's stored subject is NOT rewritten to the survivor.
    let note_after = vault
        .get_claim(&note_id)
        .expect("read note")
        .expect("note exists");
    assert_eq!(note_after.subject, ClaimSubject::Entity(loser));

    // The apply event rides the existing IdentityLifecycle receipt kind.
    let receipts = identity_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].receipt_kind,
        crate::receipt::ReceiptKind::IdentityLifecycle
    );
    assert_eq!(receipts[0].outcome, "merge");
    assert_eq!(receipts[0].occurred_at, 200);
    assert_eq!(receipts[0].actor, Some(actor.entity_ref().to_hex()));
    assert_eq!(receipts[0].fields.get("seq"), Some(&"1".to_owned()));
    assert_eq!(receipts[0].fields.get("approval"), Some(&"auto".to_owned()));
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
    assert_eq!(event_count(&vault), 1);

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
    let claim = crate::claim::ClaimBody::new(
        "user.note",
        ClaimSubject::Entity(bystander),
        Value::from("fixture"),
        1.0,
        ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
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

    // Nothing was written by the rejected ops: no new event record, no
    // shell edge, bystander still Active.
    assert_eq!(event_count(&vault), 1);
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
fn actor_is_validated_at_the_door() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let person = put_person(&vault, 0x63);

    // Unknown actor entity: rejected before anything is staged.
    let ghost_actor = WriteActor::new(id(0x6F), EdgeActorClass::Human);
    let err = vault
        .apply_identity_topology_op(
            &merge_op(vec![loser], survivor),
            &IdentityOpWrite::auto(ClaimSource::Inferred).with_actor(ghost_actor),
            200,
        )
        .expect_err("ghost actor must reject");
    assert!(matches!(err, Error::EntityNotFound));

    // Class mismatch per the provenance rule (a PERSON is never `system`).
    let mismatched = WriteActor::new(person, EdgeActorClass::System);
    let err = vault
        .apply_identity_topology_op(
            &merge_op(vec![loser], survivor),
            &IdentityOpWrite::auto(ClaimSource::Inferred).with_actor(mismatched),
            200,
        )
        .expect_err("class mismatch must reject");
    assert!(matches!(err, Error::ActorClassMismatch { .. }));

    // Nothing recorded, nothing shelled.
    assert_eq!(event_count(&vault), 0);
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn approval_axis_parks_proposed_and_noops_rejected() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let auto = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Rejected = the consent no-op: nothing written.
    let mut rejected = auto;
    rejected.approval = ClaimApprovalStatus::Rejected;
    let outcome = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &rejected, 150)
        .expect("rejected apply is a no-op");
    assert_eq!(outcome, IdentityOpOutcome::Noop);
    assert_eq!(event_count(&vault), 0);

    // Proposed PARKS: the event is recorded for legibility, but zero
    // topology effects — no edge, no lifecycle movement.
    let mut proposed = auto;
    proposed.approval = ClaimApprovalStatus::Proposed;
    let parked_event = expect_parked(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &proposed, 200)
            .expect("proposed apply parks"),
    );
    assert_eq!(event_count(&vault), 1);
    assert_eq!(
        vault
            .targets(&loser, EdgeKind::MergedInto, None)
            .expect("merged_into targets")
            .len(),
        0
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
    let record = vault
        .identity_topology_event(&parked_event)
        .expect("read parked event")
        .expect("parked event exists");
    assert_eq!(record.approval, ClaimApprovalStatus::Proposed);
    // The parked proposal is visible in the receipt family.
    let receipts = identity_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get("approval"),
        Some(&"proposed".to_owned())
    );

    // The park is not a topology writer: the same pair still merges Auto.
    let (applied_event, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &auto, 300)
            .expect("auto apply after park"),
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Merged
    );

    // A PARKED undo leaves the shell intact.
    let parked_undo = expect_parked(
        vault
            .undo_identity_topology_event(&applied_event, &proposed, 400)
            .expect("proposed undo parks"),
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Merged
    );
    let undo_record = vault
        .identity_topology_event(&parked_undo)
        .expect("read parked undo")
        .expect("parked undo exists");
    assert_eq!(
        undo_record.action,
        StoredIdentityOpAction::Undo {
            target: applied_event,
        }
    );

    // Undo of the PARKED proposal itself is not current (never effective).
    let err = vault
        .undo_identity_topology_event(&parked_event, &auto, 500)
        .expect_err("undoing a parked event must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotCurrent {
            event: parked_event,
        }
    );
}

#[test]
fn undo_merge_removes_edges_restores_active_and_appends_counter_event() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
            .expect("apply merge"),
    );
    let (counter, transitions) = expect_applied(
        vault
            .undo_identity_topology_event(&event, &write, 300)
            .expect("undo merge"),
    );
    assert_eq!(transitions, vec![(loser, EntityLifecycleState::Active)]);

    // Counter-event semantics: edge removed, state restored, BOTH ledger
    // records still readable (append-only, r1).
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
    assert_eq!(event_count(&vault), 2);
    let counter_record = vault
        .identity_topology_event(&counter)
        .expect("read counter event")
        .expect("counter exists");
    assert_eq!(counter_record.seq, 2);
    assert_eq!(
        counter_record.action,
        StoredIdentityOpAction::Undo { target: event }
    );
    assert!(
        vault
            .identity_topology_event(&event)
            .expect("read original event")
            .is_some()
    );

    // Both ledger events project as IdentityLifecycle receipts: the apply
    // AND its counter-event (symmetric honesty — undo is never silent).
    let receipts = identity_receipts(&vault);
    assert_eq!(receipts.len(), 2);
    let undo_receipts: Vec<_> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == "undo")
        .collect();
    assert_eq!(undo_receipts.len(), 1);
    assert_eq!(undo_receipts[0].occurred_at, 300);
    assert_eq!(
        undo_receipts[0].fields.get("undo_of"),
        Some(&event.to_hex())
    );

    // Double undo is stale.
    let err = vault
        .undo_identity_topology_event(&event, &write, 400)
        .expect_err("double undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotCurrent { event }
    );
    // Undoing the counter-event is not undoable.
    let err = vault
        .undo_identity_topology_event(&counter, &write, 400)
        .expect_err("undo of undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotUndoable { event: counter }
    );
}

#[test]
fn undo_currency_rides_engine_seq_not_wall_clock() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Merge, undo, then RE-MERGE with a BACKDATED wall clock (now = 50,
    // earlier than the first event's 100). Causality is the engine seq:
    // the first event's undo is stale, the backdated re-merge is current.
    let (first, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 100)
            .expect("first merge"),
    );
    vault
        .undo_identity_topology_event(&first, &write, 100)
        .expect("undo first merge");
    let (second, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 50)
            .expect("backdated re-merge"),
    );

    let err = vault
        .undo_identity_topology_event(&first, &write, 100)
        .expect_err("stale undo must reject");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotCurrent { event: first }
    );

    vault
        .undo_identity_topology_event(&second, &write, 25)
        .expect("undo current merge with an even earlier wall clock");
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn split_apply_records_canonical_map_and_undo_restores() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head_a = put_person(&vault, 0x62);
    let head_b = put_person(&vault, 0x63);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Map entries given UNSORTED: the recorded event carries the CANONICAL
    // map (codex#6 — never discarded; ONE-1745 replays it).
    let map = ReassignmentMap {
        entries: vec![
            ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x72)),
                target: ReassignmentTarget::Residue,
            },
            ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x71)),
                target: ReassignmentTarget::Head(head_a),
            },
        ],
    };
    let op = IdentityTopologyOp::Split(SplitOp {
        entity: original,
        heads: vec![head_a, head_b],
        reassignment: map.clone(),
        evidence: evidence(),
    });
    let (event, transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&op, &write, 200)
            .expect("apply split"),
    );
    assert_eq!(transitions, vec![(original, EntityLifecycleState::Split)]);

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

    let record = vault
        .identity_topology_event(&event)
        .expect("read event")
        .expect("event exists");
    assert_eq!(
        record.action,
        StoredIdentityOpAction::Split {
            entity: original,
            heads: vec![head_a, head_b],
            reassignment: map.canonicalized(),
        }
    );

    // Receipt carries the r2 stats derived from the recorded map.
    let receipts = identity_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "split");
    assert_eq!(receipts[0].fields.get("head_count"), Some(&"2".to_owned()));
    assert_eq!(receipts[0].fields.get("assigned"), Some(&"1".to_owned()));
    assert_eq!(receipts[0].fields.get("residue"), Some(&"1".to_owned()));

    // MS-01 zero-head split parks until the redirect projection (ONE-1744).
    let fresh = put_person(&vault, 0x64);
    let err = vault
        .apply_identity_topology_op(&split_op(fresh, Vec::new()), &write, 300)
        .expect_err("zero heads must reject");
    assert_eq!(expect_rejection(err), IdentityTopologyRejection::EmptyHeads);

    // Undo restores the original and removes both head edges.
    let (_, undo_transitions) = expect_applied(
        vault
            .undo_identity_topology_event(&event, &write, 400)
            .expect("undo split"),
    );
    assert_eq!(
        undo_transitions,
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
    assert_eq!(event_count(&vault), 1);
    let err = vault
        .apply_identity_topology_op(&facet_op(other), &write, 300)
        .expect_err("facet apply is unarmed");
    assert!(matches!(err, Error::IdentityTopologyUnarmed(_)));
    let err = vault
        .apply_identity_topology_op(&distinct_op(other, survivor), &write, 300)
        .expect_err("assert_distinct apply is unarmed");
    assert!(matches!(err, Error::IdentityTopologyUnarmed(_)));
    assert_eq!(event_count(&vault), 1);
    assert_eq!(
        vault.entity_lifecycle_state(&other).expect("other state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn lifecycle_reads_fail_closed_on_corrupt_shells() {
    let (_dir, vault) = open_vault();
    let entity = put_person(&vault, 0x61);
    let peer_a = put_person(&vault, 0x62);
    let peer_b = put_person(&vault, 0x63);

    // Sanity: one door-shaped merged_into edge reads Merged.
    force_edge(&vault, entity, EdgeKind::MergedInto, peer_a);
    assert_eq!(
        vault.entity_lifecycle_state(&entity).expect("one shell"),
        EntityLifecycleState::Merged
    );

    // codex#7: TWO merged_into targets = corruption (a merge redirects to
    // exactly one canonical head); reads must refuse to guess.
    force_edge(&vault, entity, EdgeKind::MergedInto, peer_b);
    let err = vault
        .entity_lifecycle_state(&entity)
        .expect_err("multi merged_into must fail closed");
    assert!(matches!(err, Error::CorruptedIndex(_)));

    // Both shell kinds at once is equally corrupt.
    let other = put_person(&vault, 0x64);
    force_edge(&vault, other, EdgeKind::MergedInto, peer_a);
    force_edge(&vault, other, EdgeKind::SplitInto, peer_b);
    let err = vault
        .entity_lifecycle_state(&other)
        .expect_err("conflicting shells must fail closed");
    assert!(matches!(err, Error::CorruptedIndex(_)));

    // A split keeps its N-head set readable.
    let split_entity = put_person(&vault, 0x65);
    force_edge(&vault, split_entity, EdgeKind::SplitInto, peer_a);
    force_edge(&vault, split_entity, EdgeKind::SplitInto, peer_b);
    assert_eq!(
        vault
            .entity_lifecycle_state(&split_entity)
            .expect("n-head split"),
        EntityLifecycleState::Split
    );
}

// ─── Edge-kind registry pins for the redirect edges ─────────────────────────

#[test]
fn merged_into_and_split_into_edge_kind_pins() {
    // Ratified bytes 21/22; byte 20 stays unregistered (the ONE-1414
    // same-as parking spot, pinned by the ARCH-0034 frontier probe).
    assert_eq!(EdgeKind::MergedInto as u8, 21);
    assert_eq!(EdgeKind::SplitInto as u8, 22);
    assert_eq!(EdgeKind::try_from_u8(20), None);
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));

    // Structural 12-byte layout, supersedes-class stored-weight prior, and
    // supersedes-class PPR λ.
    for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
        let value = crate::edge::encode_edge_value(kind, 0.3, 1, crate::affect::Vad::NEUTRAL, None)
            .expect("encode structural value");
        assert_eq!(value.len(), 12);
        assert_eq!(kind.default_weight(), Some(0.3));
        assert_eq!(crate::ppr::lambda_for_kind(kind), Some(0.3));
    }
}

// ─── MS-01 trust-model perimeter (ONE-1743 fix round) ───────────────────────

/// Plants a type-76 record row the way the sync ingest door's
/// `put_replicated` stores it (replicated-shape put through `apply_ops`),
/// standing in for a record replicated from another vault so the
/// seq-join/reconcile helpers can be exercised without the sync feature.
fn put_identity_event_record(vault: &Vault, event_id: EntityId, record: &StoredIdentityOpEvent) {
    let body = encode_identity_topology_event_body(record).expect("encode record");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![BatchOp::Put {
                    id: event_id,
                    entity_type: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
                    occurred: TimeRange {
                        start: record.at,
                        end: record.at,
                    },
                    learned_at: record.at,
                    data: body.clone(),
                    allow_maintenance: true,
                    allow_reserved_predicate: true,
                }],
                true,
                false,
                true,
            )
        })
        .expect("plant replicated record");
}

fn replicated_merge_record(
    sources: Vec<EntityId>,
    survivor: EntityId,
    seq: u64,
) -> StoredIdentityOpEvent {
    StoredIdentityOpEvent {
        seq,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge { sources, survivor },
    }
}

#[test]
fn partial_multi_participant_merge_authorizes_no_shell_until_complete() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let present_source = put_person(&vault, 0x62);
    let missing_source = id(0x63);
    let event_id = id(0x70);
    let record = replicated_merge_record(vec![present_source, missing_source], survivor, 50);
    put_identity_event_record(&vault, event_id, &record);

    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile partially materialized merge");
    assert!(
        !vault
            .edge_exists(&present_source, EdgeKind::MergedInto, &survivor)
            .expect("read present-source shell"),
        "one absent participant must defer the whole event, not authorize a partial shell"
    );

    put_person(&vault, 0x63);
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile complete merge");
    for source in [present_source, missing_source] {
        assert!(
            vault
                .edge_exists(&source, EdgeKind::MergedInto, &survivor)
                .expect("read complete shell"),
            "every shell becomes authorized together once all participants materialize"
        );
    }
}

#[test]
fn partial_multi_head_split_authorizes_no_shell_until_complete() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let present_head = put_person(&vault, 0x62);
    let missing_head = id(0x63);
    let event_id = id(0x70);
    put_identity_event_record(
        &vault,
        event_id,
        &StoredIdentityOpEvent {
            seq: 50,
            at: 200,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: StoredIdentityOpAction::Split {
                entity: original,
                heads: vec![present_head, missing_head],
                reassignment: ReassignmentMap::default(),
            },
        },
    );

    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile partially materialized split");
    assert!(
        !vault
            .edge_exists(&original, EdgeKind::SplitInto, &present_head)
            .expect("read present-head shell"),
        "one absent head must defer the whole split, not authorize a partial shell"
    );

    put_person(&vault, 0x63);
    for head in [present_head, missing_head] {
        assert!(
            vault
                .edge_exists(&original, EdgeKind::SplitInto, &head)
                .expect("read complete split shell"),
            "every split shell becomes authorized together once all heads materialize"
        );
    }
}

#[test]
fn plain_local_put_retriggers_deferred_topology_at_shared_boundary() {
    let (_dir, vault) = open_vault();
    let survivor = id(0x61);
    let source = id(0x62);
    let event_id = id(0x70);
    put_identity_event_record(
        &vault,
        event_id,
        &replicated_merge_record(vec![source], survivor, 50),
    );

    put_person(&vault, 0x62);
    assert!(
        !vault
            .edge_exists(&source, EdgeKind::MergedInto, &survivor)
            .expect("read deferred shell"),
        "the first ordinary put leaves the whole event deferred"
    );
    put_person(&vault, 0x61);
    assert!(
        vault
            .edge_exists(&source, EdgeKind::MergedInto, &survivor)
            .expect("read reconciled shell"),
        "the shared successful-put boundary must reconcile when the final participant lands"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&source).expect("source state"),
        EntityLifecycleState::Merged
    );
}

#[test]
fn operational_setters_leave_live_shell_edges_intact() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
        .expect("apply merge");

    // codex P1: pre-fix, `set_edge_weight(loser, merged_into, survivor, 0)`
    // succeeded and PPR dropped the shell edge — an unledgered
    // topology-effect mutation. The setter must reject typed and leave the
    // door-written weight untouched.
    let err = vault
        .set_edge_weight(&loser, EdgeKind::MergedInto, &survivor, 0.0)
        .expect_err("weight rewrite of a live shell edge must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));
    let err = vault
        .set_edge_vad(
            &loser,
            EdgeKind::MergedInto,
            &survivor,
            crate::affect::Vad::NEUTRAL,
        )
        .expect_err("vad rewrite of a live shell edge must reject");
    assert!(matches!(err, Error::ReservedEdgeKind("merged_into")));

    let edges = vault.edges_out(&loser).expect("edges out");
    let shell = edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::MergedInto)
        .expect("shell edge survives");
    assert_eq!(shell.weight, 0.3, "door-written weight is untouched");
}

#[test]
fn type_76_events_are_delete_protected_on_every_delete_door() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let outcome = vault
        .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
        .expect("apply merge");
    let (event_id, _) = expect_applied(outcome);

    // Public hard delete + every ARCH-0038 reason door (soft and hard):
    // dropping the event while the merged_into edge survives would wedge
    // the shell (undo → EntityNotFound), so all reject typed.
    let err = vault
        .delete_entity(&event_id)
        .expect_err("delete_entity must reject the ledger event");
    assert!(matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
    ));
    for reason in [
        crate::deletion::DeleteReason::UserDelete,
        crate::deletion::DeleteReason::UserHardDelete,
        crate::deletion::DeleteReason::GdprDelete,
        crate::deletion::DeleteReason::PolicyDelete,
    ] {
        let err = vault
            .delete_entity_with_reason(&event_id, reason)
            .expect_err("reasoned delete must reject the ledger event");
        assert!(matches!(
            err,
            Error::MaintenanceKindNotWritable(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        ));
    }
    // Generic batch delete door.
    let err = vault
        .batch()
        .delete(&event_id)
        .commit()
        .expect_err("batch delete must reject the ledger event");
    assert!(matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
    ));
    // Replayed CRDT tombstone door (a malformed value decodes HARD).
    let err = vault
        .apply_replayed_tombstone(&event_id, &[])
        .expect_err("replayed tombstone must reject the ledger event");
    assert!(matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
    ));

    // Record and shell both survived every rejected door; undo still works.
    assert!(
        vault
            .identity_topology_event(&event_id)
            .expect("read event")
            .is_some()
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Merged
    );
    vault
        .undo_identity_topology_event(&event_id, &write, 300)
        .expect("undo remains possible");
}

#[test]
fn stored_malformed_type_76_row_reads_as_corruption() {
    let (_dir, vault) = open_vault();
    let event_id = id(0x70);
    vault
        .with_write_txn(|wtxn| {
            let mut blob = Vec::new();
            blob.push(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT);
            blob.extend_from_slice(&100_u64.to_be_bytes());
            blob.extend_from_slice(&100_u64.to_be_bytes());
            blob.extend_from_slice(&100_u64.to_be_bytes());
            blob.extend_from_slice(b"not msgpack");
            vault.store.entities.put(wtxn, event_id.as_bytes(), &blob)?;
            let mut type_key = vec![ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT];
            type_key.extend_from_slice(event_id.as_bytes());
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
        .expect("plant corrupt stored row");

    // A damaged STORED row is on-disk corruption (fail-closed
    // CorruptedIndex), never the InvalidIdentityTopologyEventBody ingress
    // rejection — the quarantine classifier treats the latter as a
    // rejectable REMOTE input, and local damage must never ride that lane.
    let err = vault
        .identity_topology_event(&event_id)
        .expect_err("corrupt stored row must fail the point read");
    assert!(matches!(err, Error::CorruptedIndex(_)));
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let err = vault
        .identity_topology_events_in_txn(&rtxn)
        .expect_err("corrupt stored row must fail the family scan");
    assert!(matches!(err, Error::CorruptedIndex(_)));
}

#[test]
fn reassignment_map_rejects_duplicate_items_in_the_table() {
    let entity = id(0x61);
    let head_a = id(0x62);
    let head_b = id(0x63);
    let claim = ClaimSubject::Entity(id(0x64));

    // Two assignments for one item must not both validate (split role).
    let op = IdentityTopologyOp::Split(SplitOp {
        entity,
        heads: vec![head_a, head_b],
        reassignment: ReassignmentMap {
            entries: vec![
                ReassignmentEntry {
                    item: claim,
                    target: ReassignmentTarget::Head(head_a),
                },
                ReassignmentEntry {
                    item: claim,
                    target: ReassignmentTarget::Head(head_b),
                },
            ],
        },
        evidence: evidence(),
    });
    assert_eq!(
        evaluate_transition(&states_of(&[]), &op),
        Err(IdentityTopologyRejection::DuplicateReassignmentItem)
    );

    // Same cell on the facet role.
    let op = IdentityTopologyOp::Facet(FacetOp {
        entity,
        facets: vec![
            FacetSpec {
                label: "mask-a".to_owned(),
            },
            FacetSpec {
                label: "mask-b".to_owned(),
            },
        ],
        reassignment: ReassignmentMap {
            entries: vec![
                ReassignmentEntry {
                    item: claim,
                    target: ReassignmentTarget::Facet { index: 0 },
                },
                ReassignmentEntry {
                    item: claim,
                    target: ReassignmentTarget::Facet { index: 1 },
                },
            ],
        },
        evidence: evidence(),
    });
    assert_eq!(
        evaluate_transition(&states_of(&[]), &op),
        Err(IdentityTopologyRejection::DuplicateReassignmentItem)
    );
}

#[test]
fn reassignment_map_wire_rejects_unsorted_and_duplicate_rows() {
    let record = StoredIdentityOpEvent {
        seq: 1,
        at: 100,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Split {
            entity: id(0x61),
            heads: vec![id(0x62)],
            reassignment: ReassignmentMap {
                entries: vec![
                    ReassignmentEntry {
                        item: ClaimSubject::Entity(id(0x01)),
                        target: ReassignmentTarget::Residue,
                    },
                    ReassignmentEntry {
                        item: ClaimSubject::Entity(id(0x02)),
                        target: ReassignmentTarget::Residue,
                    },
                ],
            },
        },
    };

    // Canonical bytes round-trip.
    let canonical = encode_identity_topology_event_body(&record).expect("encode");
    decode_identity_topology_event_body(&canonical).expect("canonical bytes decode");

    let tamper = |mutate: &dyn Fn(&mut Vec<Value>)| -> Vec<u8> {
        let Value::Map(mut entries) = record.encode_value() else {
            panic!("record encodes as map");
        };
        for (key, value) in &mut entries {
            if key.as_str() == Some(BODY_KEY_MAP)
                && let Value::Array(rows) = value
            {
                mutate(rows);
            }
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode tampered");
        bytes
    };

    // Out-of-order rows re-serialize differently than stored — reject on
    // decode so on-disk bytes always equal their re-encoding.
    let unsorted = tamper(&|rows| rows.swap(0, 1));
    let err = decode_identity_topology_event_body(&unsorted)
        .expect_err("unsorted map rows must fail decode");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));

    // Duplicate items are the two-assignments-for-one-claim shape.
    let duplicated = tamper(&|rows| {
        let first = rows[0].clone();
        rows[1] = first;
    });
    let err = decode_identity_topology_event_body(&duplicated)
        .expect_err("duplicate map items must fail decode");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));
}

#[test]
fn type_76_decoder_rejects_noncanonical_map_fields() {
    let record = StoredIdentityOpEvent {
        seq: 1,
        at: 100,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Split {
            entity: id(0x61),
            heads: vec![id(0x62)],
            reassignment: ReassignmentMap {
                entries: vec![ReassignmentEntry {
                    item: ClaimSubject::Entity(id(0x63)),
                    target: ReassignmentTarget::Head(id(0x62)),
                }],
            },
        },
    };
    let canonical = encode_identity_topology_event_body(&record).expect("encode canonical body");
    let expected = record.clone();
    assert_eq!(
        decode_identity_topology_event_body(&canonical).expect("canonical body decodes"),
        expected
    );

    #[allow(clippy::type_complexity)]
    let tamper_row = |mutate: &dyn Fn(&mut Vec<(Value, Value)>)| -> Vec<u8> {
        let Value::Map(mut event_fields) = record.encode_value() else {
            panic!("event encodes as map");
        };
        for (key, value) in &mut event_fields {
            if key.as_str() == Some(BODY_KEY_MAP)
                && let Value::Array(rows) = value
                && let Value::Map(fields) = &mut rows[0]
            {
                mutate(fields);
            }
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(event_fields))
            .expect("encode tampered body");
        bytes
    };

    let noncanonical_order = tamper_row(&|fields| fields.swap(0, 1));
    let duplicate_key = tamper_row(&|fields| fields.push(fields[0].clone()));
    let unknown_key = tamper_row(&|fields| {
        fields.push((Value::from("unknown"), Value::from(true)));
    });
    for (name, bytes) in [
        ("noncanonical field order", noncanonical_order),
        ("duplicate field", duplicate_key),
        ("unknown field", unknown_key),
    ] {
        let err = decode_identity_topology_event_body(&bytes)
            .expect_err("noncanonical body must fail admission");
        assert!(
            matches!(err, Error::InvalidIdentityTopologyEventBody(_)),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn replicated_event_caps_reject_oversized_participant_and_body_work() {
    let participant_ids = (1..=MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS + 1)
        .map(|index| {
            let mut bytes = [0_u8; 16];
            bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
            EntityId::from_bytes(bytes).expect("participant id")
        })
        .collect::<Vec<_>>();
    let over_participant_cap = replicated_merge_record(participant_ids, id(0x61), 1);
    let bytes = encode_identity_topology_event_body(&over_participant_cap).expect("encode record");
    let err = decode_identity_topology_event_body(&bytes)
        .expect_err("over-cap participant fan-out must reject before storage");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));

    let mut over_body_cap = replicated_merge_record(vec![id(0x62)], id(0x61), 1);
    over_body_cap.evidence = Some(IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "x".repeat(MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES + 1),
    });
    let bytes = encode_identity_topology_event_body(&over_body_cap).expect("encode large record");
    assert!(bytes.len() > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES);
    let err = decode_identity_topology_event_body(&bytes)
        .expect_err("over-cap body must reject before MessagePack decode");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));
}

#[test]
fn seq_clock_joins_ingested_history_before_local_allocation() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);

    // A replicated record accepted at seq 50 joins the clock; a stale
    // lower join later never rewinds it.
    vault
        .with_write_txn(|wtxn| vault.advance_identity_topology_seq_in_txn(wtxn, 50))
        .expect("join ingested seq");
    vault
        .with_write_txn(|wtxn| vault.advance_identity_topology_seq_in_txn(wtxn, 3))
        .expect("stale join is a no-op");

    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (event_id, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
            .expect("apply merge"),
    );
    let record = vault
        .identity_topology_event(&event_id)
        .expect("read event")
        .expect("event exists");
    assert_eq!(
        record.seq, 51,
        "local allocation must order AFTER ingested history"
    );
}

#[test]
fn local_sequence_allocator_refuses_the_replicated_terminal_band() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let last_network_sequence = IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING - 1;
    vault
        .with_write_txn(|wtxn| {
            vault.advance_identity_topology_seq_in_txn(wtxn, last_network_sequence)
        })
        .expect("join the last network-admissible sequence");
    let events_before = event_count(&vault);

    let err = vault
        .apply_identity_topology_op(
            &merge_op(vec![loser], survivor),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            200,
        )
        .expect_err("local allocation must not enter the peer-rejected terminal band");
    assert!(matches!(
        err,
        Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq is in the reserved terminal range"
        )
    ));
    assert_eq!(event_count(&vault), events_before, "no event was minted");
    assert!(
        !vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .expect("read shell"),
        "a refused allocation has zero topology effects"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .read_identity_topology_seq_in_txn(&rtxn)
            .expect("read seq clock"),
        last_network_sequence,
        "the failed allocation must not advance the clock"
    );
}

#[test]
fn ledger_predicate_admits_only_fold_mandated_shell_edges() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let other = put_person(&vault, 0x63);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (event_id, _) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![loser], survivor), &write, 200)
            .expect("apply merge"),
    );

    {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        // The mandated pair carries the mandating event's `at` — the
        // door-written `created_at` the sync doors pin value bytes to.
        assert_eq!(
            vault
                .identity_topology_mandated_shell_edge_in_txn(
                    &rtxn,
                    &loser,
                    EdgeKind::MergedInto,
                    &survivor
                )
                .expect("mandated edge"),
            Some(200)
        );
        // Wrong target, wrong kind, wrong direction: all unledgered.
        for (src, kind, tgt) in [
            (loser, EdgeKind::MergedInto, other),
            (loser, EdgeKind::SplitInto, survivor),
            (survivor, EdgeKind::MergedInto, loser),
        ] {
            assert_eq!(
                vault
                    .identity_topology_mandated_shell_edge_in_txn(&rtxn, &src, kind, &tgt)
                    .expect("predicate reads"),
                None,
                "unledgered shape must not be admitted"
            );
        }
    }

    // After undo the fold mandates nothing for the loser.
    vault
        .undo_identity_topology_event(&event_id, &write, 300)
        .expect("undo merge");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .identity_topology_mandated_shell_edge_in_txn(
                &rtxn,
                &loser,
                EdgeKind::MergedInto,
                &survivor
            )
            .expect("predicate reads"),
        None,
        "an undone merge no longer mandates its shell edge"
    );
}

#[test]
fn reconcile_materializes_and_tears_shell_edges_from_the_fold() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);

    // A replicated merge record lands WITHOUT its edge (the record rides
    // the entities container; the edge may be quarantined or late).
    // Reconciliation derives the shell edge from the validated ledger.
    let merge_event = id(0x70);
    let merge_record = replicated_merge_record(vec![loser], survivor, 50);
    put_identity_event_record(&vault, merge_event, &merge_record);
    vault
        .with_write_txn(|wtxn| {
            vault.advance_identity_topology_seq_in_txn(wtxn, merge_record.seq)?;
            vault.reconcile_identity_topology_edges_in_txn(wtxn)
        })
        .expect("reconcile ingested merge");
    assert_eq!(
        vault
            .targets(&loser, EdgeKind::MergedInto, None)
            .expect("read merged_into"),
        vec![survivor]
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Merged
    );

    // The replicated undo counter-event tears the edge back down.
    let undo_event = id(0x71);
    let undo_record = StoredIdentityOpEvent {
        seq: 51,
        at: 300,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Undo {
            target: merge_event,
        },
    };
    put_identity_event_record(&vault, undo_event, &undo_record);
    vault
        .with_write_txn(|wtxn| {
            vault.advance_identity_topology_seq_in_txn(wtxn, undo_record.seq)?;
            vault.reconcile_identity_topology_edges_in_txn(wtxn)
        })
        .expect("reconcile ingested undo");
    assert!(
        vault
            .targets(&loser, EdgeKind::MergedInto, None)
            .expect("read merged_into")
            .is_empty()
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
}

#[test]
fn out_of_order_ingest_reconciles_every_changed_shell_source() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x61);
    let b = put_person(&vault, 0x62);
    let c = put_person(&vault, 0x63);

    let later_id = id(0x72);
    let later = replicated_merge_record(vec![b], a, 2);
    put_identity_event_record(&vault, later_id, &later);
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile later event first");
    assert!(
        vault
            .edge_exists(&b, EdgeKind::MergedInto, &a)
            .expect("read initial shell"),
        "precondition: seq=2 initially shells B into A"
    );

    let earlier_id = id(0x71);
    let earlier = replicated_merge_record(vec![a], c, 1);
    put_identity_event_record(&vault, earlier_id, &earlier);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let expected = fold_identity_topology_log(
        &vault
            .identity_topology_events_in_txn(&rtxn)
            .expect("fold event family"),
    );
    let expected_b = expected
        .states
        .get(&b)
        .copied()
        .unwrap_or(EntityLifecycleState::Active);
    assert_eq!(expected_b, EntityLifecycleState::Active);
    drop(rtxn);

    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile out-of-order insert");
    assert_eq!(
        vault.entity_lifecycle_state(&b).expect("B lifecycle"),
        expected_b,
        "the shell projection must match the full seq-ordered fold"
    );
    assert!(
        !vault
            .edge_exists(&b, EdgeKind::MergedInto, &a)
            .expect("read stale shell"),
        "the now-rejected seq=2 event must not leave B->A live"
    );
}

#[test]
fn idempotent_reconcile_repairs_both_mandated_edge_values() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let event_id = id(0x70);
    let record = replicated_merge_record(vec![loser], survivor, 50);
    put_identity_event_record(&vault, event_id, &record);
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("initial reconcile");

    let out_key = crate::store::Store::encode_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    let in_key = crate::store::Store::encode_edge_key(&survivor, EdgeKind::MergedInto, &loser);
    let forged = crate::edge::encode_edge_value(
        EdgeKind::MergedInto,
        0.0,
        record.at,
        crate::affect::Vad::NEUTRAL,
        None,
    )
    .expect("encode forged edge");
    vault
        .with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &out_key, &forged)?;
            vault.store.edges_in.put(wtxn, &in_key, &forged)?;
            Ok(())
        })
        .expect("plant forged pair values");

    let expected = crate::edge::encode_edge_value(
        EdgeKind::MergedInto,
        EdgeKind::MergedInto.default_weight().expect("shell weight"),
        record.at,
        crate::affect::Vad::NEUTRAL,
        None,
    )
    .expect("encode canonical edge");
    assert_ne!(
        forged, expected,
        "precondition: stored value is noncanonical"
    );

    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("idempotent record replay reconciles values");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let repaired_out = vault
        .store
        .edges_out
        .get(&rtxn, &out_key)
        .expect("read out value")
        .expect("out value exists");
    let repaired_in = vault
        .store
        .edges_in
        .get(&rtxn, &in_key)
        .expect("read in value")
        .expect("in value exists");
    assert_eq!(repaired_out, expected.as_slice());
    assert_eq!(repaired_in, expected.as_slice());
}

#[test]
fn undo_of_ingested_merge_orders_after_it_in_the_fold() {
    // The P1 cross-vault scenario: a fresh replica ingests merge E
    // (seq=50) plus its shell edge, then undoes E LOCALLY. Without the
    // seq join the undo allocates seq 1, folds BEFORE E, is rejected
    // NotCurrent on the next fold, and ledger and edge truth diverge.
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let merge_event = id(0x70);
    let merge_record = replicated_merge_record(vec![loser], survivor, 50);
    put_identity_event_record(&vault, merge_event, &merge_record);
    vault
        .with_write_txn(|wtxn| {
            vault.advance_identity_topology_seq_in_txn(wtxn, merge_record.seq)?;
            vault.reconcile_identity_topology_edges_in_txn(wtxn)
        })
        .expect("ingest merge");

    let write = IdentityOpWrite::auto(ClaimSource::UserStated);
    let (undo_id, transitions) = expect_applied(
        vault
            .undo_identity_topology_event(&merge_event, &write, 300)
            .expect("undo ingested merge"),
    );
    assert_eq!(transitions, vec![(loser, EntityLifecycleState::Active)]);
    let undo_record = vault
        .identity_topology_event(&undo_id)
        .expect("read undo")
        .expect("undo exists");
    assert!(
        undo_record.seq > merge_record.seq,
        "the undo must order after the ingested merge, got {} <= {}",
        undo_record.seq,
        merge_record.seq
    );

    // Ledger fold and edge truth agree: the loser is Active on both axes.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let fold = fold_identity_topology_log(
        &vault
            .identity_topology_events_in_txn(&rtxn)
            .expect("events"),
    );
    assert_eq!(fold.states.get(&loser), Some(&EntityLifecycleState::Active));
    assert!(fold.rejections.is_empty(), "no NotCurrent divergence");
    drop(rtxn);
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
}
