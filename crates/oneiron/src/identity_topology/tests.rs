//! ONE-1743 (MS-01) unit tests: op vocabulary, the full (state, op)
//! transition table, the seq-ordered ledger fold, CRDT precedence, the
//! type-76 record wire, and the vault merge/split apply + undo doors
//! (consent axis, actor validation, reserved edges, receipts).

use std::collections::BTreeMap;

use rmpv::Value;

use super::distinct_claim::distinct_claim_value;
use super::event_body_codec::id_value;
use super::wire_keys::{BODY_KEY_MAP, EVENT_KIND_MERGE, EVENT_KIND_SPLIT};
use super::*;
use crate::batch::{BatchOp, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::temporal::TimeRange;
use crate::test_util::embedding_test_config;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(embedding_test_config())
}

fn id(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
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
    let a = id(0x60);
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
    // ONE-1744 lifted the zero-head guard: `heads: []` is the legal r2
    // "gone" form and shells the original like any other split.
    assert_eq!(
        evaluate_transition(&empty, &split_op(a, Vec::new())),
        Ok(vec![(a, EntityLifecycleState::Split)])
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
    let u1 = id(0x65);
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
    let u1 = id(0x65);
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
            id(0x65),
            2,
            IdentityTopologyAction::Apply(merge_op(vec![b], a)),
        ),
    ]);
    assert_eq!(fold.states.get(&b), Some(&EntityLifecycleState::Merged));
    assert_eq!(fold.current_event.get(&b), Some(&id(0x65)));
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
            applied_assigned: 0,
            applied_residue: 0,
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
            // DECLARED 1 + 1, APPLIED 0 + 0 (ONE-1745): the map's items are
            // bare fixture ids, and this vault holds no CLAIM row for either,
            // so the door recorded neither. Exactly the gap the two count
            // families exist to make visible.
            applied_assigned: 0,
            applied_residue: 0,
        }
    );

    // Receipt carries the r2 stats derived from the recorded map.
    let receipts = identity_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "split");
    assert_eq!(receipts[0].fields.get("head_count"), Some(&"2".to_owned()));
    assert_eq!(receipts[0].fields.get("assigned"), Some(&"1".to_owned()));
    assert_eq!(receipts[0].fields.get("residue"), Some(&"1".to_owned()));
    assert_eq!(
        receipts[0].fields.get("applied_assigned"),
        Some(&"0".to_owned())
    );
    assert_eq!(
        receipts[0].fields.get("applied_residue"),
        Some(&"0".to_owned())
    );

    // ONE-1744 lifted the zero-head guard: the r2 "gone" form now APPLIES,
    // shelling the entity with no successor and no `split_into` edge.
    let fresh = put_person(&vault, 0x64);
    let (_, zero_head_transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&split_op(fresh, Vec::new()), &write, 300)
            .expect("zero-head split applies"),
    );
    assert_eq!(
        zero_head_transitions,
        vec![(fresh, EntityLifecycleState::Split)]
    );

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

/// CONTRACT INVERTED BY ONE-1745, THEN ONE-1746 (arming, not deletion): both
/// cells that read "validates, then refuses" now read "validates, then
/// MINTS" — facet masks, and the `entity.distinct_from` claim. Every
/// pre-existing assert is kept: the shell-base rejection, the self-distinct
/// rejection, the unarmed facet PROPOSE lane, and the untouched lifecycle of
/// every participant; the two armed halves assert the effect instead of its
/// absence.
#[test]
fn facet_and_assert_distinct_doors_mint_their_own_effects() {
    let (_dir, vault) = open_vault();
    let base = put_person(&vault, 0x61);
    let other = put_person(&vault, 0x62);
    let survivor = put_person(&vault, 0x63);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // Shell base: the transition table fires before the apply door.
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

    assert_eq!(event_count(&vault), 1);
    let (event, transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&facet_op(other), &write, 300)
            .expect("facet apply is armed"),
    );
    // r6: a facet op moves NO lifecycle state — the base stays Active and
    // the op's only new ids are the masks themselves.
    assert!(transitions.is_empty());
    assert_eq!(event_count(&vault), 2);
    let masks = vault.facets_of(&other).expect("facets of");
    assert_eq!(masks.len(), 1);
    assert_eq!(
        vault
            .identity_topology_event(&event)
            .expect("read facet event")
            .expect("facet event exists")
            .action,
        StoredIdentityOpAction::Facet {
            entity: other,
            facets: masks.clone(),
            reassignment: ReassignmentMap::default(),
            applied_assigned: 0,
            applied_residue: 0,
        }
    );
    // The mask is a live type-13 entity carrying the spec's label as its
    // body — the label is runtime data on the entity, never on the ledger.
    assert_eq!(
        vault
            .read_entity_header(&masks[0])
            .expect("read mask header")
            .expect("mask exists")
            .entity_type,
        crate::registry::ENTITY_TYPE_FACET
    );
    assert_eq!(
        vault.get(&masks[0]).expect("read mask body"),
        Some(b"fixture-mask".to_vec())
    );

    // The propose lane is NOT armed for this kind: a park would name masks it
    // never minted, and the resolution door has no scope target for it.
    let err = vault
        .apply_identity_topology_op(
            &facet_op(other),
            &IdentityOpWrite {
                approval: ClaimApprovalStatus::Proposed,
                ..write
            },
            300,
        )
        .expect_err("facet proposals are unarmed");
    assert!(matches!(err, Error::IdentityTopologyUnarmed(_)));

    // ONE-1746: assert_distinct now applies. Like a facet op it moves NO
    // lifecycle state (§6) — its whole effect is the `entity.distinct_from`
    // claim, which the ledger event names.
    let (event, transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(other, survivor), &write, 300)
            .expect("assert_distinct apply is armed"),
    );
    assert!(transitions.is_empty());
    assert_eq!(event_count(&vault), 3);
    let pair = distinct_pair_key(other, survivor);
    let claims = vault
        .distinct_claims_for_pair(&survivor, &other)
        .expect("distinct claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(
        vault
            .identity_topology_event(&event)
            .expect("read assert event")
            .expect("assert event exists")
            .action,
        StoredIdentityOpAction::AssertDistinct {
            a: pair.0,
            b: pair.1,
            claim: claims[0],
        }
    );
    assert_eq!(
        vault.entity_lifecycle_state(&other).expect("other state"),
        EntityLifecycleState::Active
    );
    assert_eq!(
        vault
            .entity_lifecycle_state(&survivor)
            .expect("survivor state"),
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
    // Ratified bytes 21/22, untouched by ONE-1414's mint at byte 20: the
    // redirect pair keeps its own slots and its own supersedes-class weights.
    assert_eq!(EdgeKind::MergedInto as u8, 21);
    assert_eq!(EdgeKind::SplitInto as u8, 22);
    assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));
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
                    hub_sync_imported: false,
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
                applied_assigned: 0,
                applied_residue: 0,
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
            applied_assigned: 0,
            applied_residue: 0,
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
            applied_assigned: 0,
            applied_residue: 0,
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
fn local_sequence_allocator_keeps_headroom_after_largest_replicated_seq() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let loser = put_person(&vault, 0x62);
    let last_network_sequence =
        IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING - IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM - 1;
    vault
        .with_write_txn(|wtxn| {
            vault.advance_identity_topology_seq_in_txn(wtxn, last_network_sequence)
        })
        .expect("join the last network-admissible sequence");

    let (event_id, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &merge_op(vec![loser], survivor),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                200,
            )
            .expect("local allocation must retain headroom after the largest replicated seq"),
    );
    let record = vault
        .identity_topology_event(&event_id)
        .expect("read local event")
        .expect("local event exists");
    assert_eq!(record.seq, last_network_sequence + 1);
    assert!(
        vault
            .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
            .expect("read shell"),
        "the local topology apply must succeed after the largest replicated seq"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .read_identity_topology_seq_in_txn(&rtxn)
            .expect("read seq clock"),
        last_network_sequence + 1,
        "the successful local allocation advances into retained headroom"
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

// ─── ONE-1747 (MS-05): the proposal resolution door ─────────────────────────

/// Parks a merge proposal of `losers` into `survivor` and returns its id.
fn park_merge_proposal(
    vault: &Vault,
    losers: Vec<EntityId>,
    survivor: EntityId,
    at: u64,
) -> EntityId {
    let mut proposed = IdentityOpWrite::auto(ClaimSource::Inferred);
    proposed.approval = ClaimApprovalStatus::Proposed;
    expect_parked(
        vault
            .apply_identity_topology_op(&merge_op(losers, survivor), &proposed, at)
            .expect("proposed merge parks"),
    )
}

/// The decider's write: ruling IS the act of deciding, so it is effective.
fn ruling_write() -> IdentityOpWrite {
    IdentityOpWrite::auto(ClaimSource::UserStated)
}

fn proposal_outcome_receipts(vault: &Vault) -> Vec<crate::receipt::ReceiptRecord> {
    vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::ProposalOutcome),
        )
        .expect("query proposal-outcome receipts")
}

#[test]
fn amend_then_approve_applies_the_amended_body_not_the_original() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x73);
    let kept = put_person(&vault, 0x74);
    let dropped = put_person(&vault, 0x75);

    // Proposed: fold BOTH losers in. Amended: narrow to `kept` alone.
    let proposal = park_merge_proposal(&vault, vec![kept, dropped], survivor, 200);
    let narrowed = encode_identity_op_amendment(&merge_op(vec![kept], survivor))
        .expect("encode narrowed amendment");
    let (outcome, resolution) = vault
        .resolve_identity_proposal(
            &proposal,
            ProposalRuling::AmendThenApprove(&narrowed),
            &ruling_write(),
            300,
        )
        .expect("amend then approve");
    assert_eq!(outcome, ProposalOutcome::ApprovedAmended);

    // The NARROWER merge landed: `kept` moved, `dropped` was never touched.
    assert_eq!(
        vault.entity_lifecycle_state(&kept).expect("kept state"),
        EntityLifecycleState::Merged
    );
    assert_eq!(
        vault
            .entity_lifecycle_state(&dropped)
            .expect("dropped state"),
        EntityLifecycleState::Active,
        "the amended-away subject must keep its topology untouched"
    );

    // The ledger records the APPLIED form, not the proposed one.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let applied: Vec<IdentityTopologyOp> = vault
        .identity_topology_events_in_txn(&rtxn)
        .expect("events")
        .into_iter()
        .filter(|event| event.approval == ClaimApprovalStatus::Approved)
        .filter_map(|event| match event.action {
            IdentityTopologyAction::Apply(op) => Some(op),
            _ => None,
        })
        .collect();
    drop(rtxn);
    // `evidence` is envelope data the stored action does not carry, so the
    // fold view reconstructs it empty — the SUBJECT SET is the assertion.
    assert_eq!(
        applied.as_slice(),
        [IdentityTopologyOp::Merge(MergeOp {
            sources: vec![kept],
            survivor,
            evidence: IdentityOpEvidence::default(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        })],
        "the ledger must record the AMENDED form as the applied op"
    );

    // The receipt carries the amended bytes verbatim.
    let record = vault
        .identity_topology_event(&resolution)
        .expect("read resolution")
        .expect("resolution exists");
    let StoredIdentityOpAction::ProposalResolution {
        proposal: recorded,
        amended_body,
        ..
    } = &record.action
    else {
        panic!("resolution row must carry a ProposalResolution action");
    };
    assert_eq!(recorded, &proposal);
    assert_eq!(amended_body.as_deref(), Some(narrowed.as_slice()));
}

#[test]
fn amendment_out_of_scope_is_rejected_and_writes_nothing() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x76);
    let loser = put_person(&vault, 0x77);
    let stranger = put_person(&vault, 0x78);

    let proposal = park_merge_proposal(&vault, vec![loser], survivor, 200);
    let events_before = event_count(&vault);

    // (a) A DIFFERENT op kind: "approve this merge, amended" must never be a
    // capability to apply a split instead.
    let wrong_kind = encode_identity_op_amendment(&split_op(survivor, vec![loser]))
        .expect("encode split amendment");
    let error = vault
        .resolve_identity_proposal(
            &proposal,
            ProposalRuling::AmendThenApprove(&wrong_kind),
            &ruling_write(),
            300,
        )
        .expect_err("a different op kind is out of scope");
    assert!(
        matches!(error, Error::IdentityProposalAmendmentOutOfScope(_)),
        "expected out-of-scope rejection, got {error:?}"
    );

    // (b) A subject the proposal never named: an amendment narrows what the
    // decider reviewed, it can never reach further.
    let wider = encode_identity_op_amendment(&merge_op(vec![loser, stranger], survivor))
        .expect("encode widened amendment");
    let error = vault
        .resolve_identity_proposal(
            &proposal,
            ProposalRuling::AmendThenApprove(&wider),
            &ruling_write(),
            300,
        )
        .expect_err("an unnamed subject is out of scope");
    assert!(
        matches!(error, Error::IdentityProposalAmendmentOutOfScope(_)),
        "expected out-of-scope rejection, got {error:?}"
    );

    // (c) Bytes that are not an op body at all.
    let error = vault
        .resolve_identity_proposal(
            &proposal,
            ProposalRuling::AmendThenApprove(b"not-an-op-body"),
            &ruling_write(),
            300,
        )
        .expect_err("a malformed body is out of scope");
    assert!(
        matches!(error, Error::IdentityProposalAmendmentOutOfScope(_)),
        "expected out-of-scope rejection, got {error:?}"
    );

    // Fail-closed: nothing applied, no receipt, and the park stays OPEN — so
    // a good amendment still resolves it afterwards.
    assert_eq!(event_count(&vault), events_before);
    assert!(proposal_outcome_receipts(&vault).is_empty());
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
    let (outcome, _) = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Approve, &ruling_write(), 400)
        .expect("the still-open park resolves");
    assert_eq!(outcome, ProposalOutcome::ApprovedUntouched);
}

#[test]
fn reject_leaves_zero_effects_and_retires_the_park() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x79);
    let loser = put_person(&vault, 0x7A);

    let proposal = park_merge_proposal(&vault, vec![loser], survivor, 200);
    let (outcome, _) = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Reject, &ruling_write(), 300)
        .expect("reject resolves");
    assert_eq!(outcome, ProposalOutcome::Rejected);

    // Zero topology effects.
    assert_eq!(
        vault.entity_lifecycle_state(&loser).expect("loser state"),
        EntityLifecycleState::Active
    );
    assert_eq!(
        vault
            .targets(&loser, EdgeKind::MergedInto, None)
            .expect("merged_into targets")
            .len(),
        0
    );

    // The park is RETIRED: a second ruling on it errors typed, whatever the
    // ruling — a resolved proposal is spent, not re-decidable.
    for ruling in [ProposalRuling::Approve, ProposalRuling::Reject] {
        let error = vault
            .resolve_identity_proposal(&proposal, ruling, &ruling_write(), 400)
            .expect_err("a resolved proposal cannot be re-resolved");
        assert_eq!(
            expect_rejection(error),
            IdentityTopologyRejection::ProposalAlreadyResolved { proposal }
        );
    }
}

#[test]
fn resolution_rejects_non_proposals_and_ineffective_rulings() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x7B);
    let loser = put_person(&vault, 0x7C);

    // An AUTO-applied event is not a parked proposal a ruling can act on.
    let (applied, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &merge_op(vec![loser], survivor),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                150,
            )
            .expect("auto merge applies"),
    );
    let error = vault
        .resolve_identity_proposal(&applied, ProposalRuling::Approve, &ruling_write(), 300)
        .expect_err("an applied event is not a proposal");
    assert_eq!(
        expect_rejection(error),
        IdentityTopologyRejection::NotProposed { event: applied }
    );

    // An absent id is not found.
    let error = vault
        .resolve_identity_proposal(&id(0x7D), ProposalRuling::Approve, &ruling_write(), 300)
        .expect_err("an absent proposal is not found");
    assert!(matches!(error, Error::EntityNotFound), "got {error:?}");

    // A ruling carried on a NON-effective consent axis is refused: deciding
    // is itself an effective act, so a "proposed ruling" is incoherent.
    // A fresh subject: `loser` is Merged by the apply above, so it can no
    // longer be proposed.
    let fresh_loser = put_person(&vault, 0x8C);
    let proposal = park_merge_proposal(&vault, vec![fresh_loser], survivor, 200);
    let mut parked_ruling = IdentityOpWrite::auto(ClaimSource::UserStated);
    parked_ruling.approval = ClaimApprovalStatus::Proposed;
    let error = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Approve, &parked_ruling, 300)
        .expect_err("a non-effective ruling is refused");
    assert_eq!(
        expect_rejection(error),
        IdentityTopologyRejection::ProposalRulingNotEffective
    );
}

#[test]
fn outcome_receipt_stamps_ramp_scope_on_all_three_outcomes() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x7E);
    let untouched_loser = put_person(&vault, 0x7F);
    let amended_loser = put_person(&vault, 0x80);
    let rejected_loser = put_person(&vault, 0x81);

    let untouched = park_merge_proposal(&vault, vec![untouched_loser], survivor, 200);
    vault
        .resolve_identity_proposal(&untouched, ProposalRuling::Approve, &ruling_write(), 300)
        .expect("approve");

    let amended = park_merge_proposal(&vault, vec![amended_loser], survivor, 210);
    let body = encode_identity_op_amendment(&merge_op(vec![amended_loser], survivor))
        .expect("encode amendment");
    vault
        .resolve_identity_proposal(
            &amended,
            ProposalRuling::AmendThenApprove(&body),
            &ruling_write(),
            310,
        )
        .expect("amend then approve");

    let rejected = park_merge_proposal(&vault, vec![rejected_loser], survivor, 220);
    vault
        .resolve_identity_proposal(&rejected, ProposalRuling::Reject, &ruling_write(), 320)
        .expect("reject");

    let receipts = proposal_outcome_receipts(&vault);
    assert_eq!(receipts.len(), 3);
    for receipt in &receipts {
        // MS-06 (ONE-1748) rebuilds per-scope ramp stats from receipts ALONE:
        // without the DEC-0006 scope tuple stamped here, that is unsatisfiable.
        assert_eq!(receipt.fields.get("op_kind"), Some(&"merge".to_owned()));
        assert_eq!(
            receipt.fields.get("target_class"),
            Some(&"PERSON".to_owned())
        );
        assert!(receipt.fields.contains_key("actor"));
        assert!(receipt.fields.contains_key("proposal_ref"));
        // The reserved Δ slot is never written at this ticket.
        assert_eq!(crate::receipt::proposal_outcome_delta(receipt), None);
    }

    // Exactly the three outcome states, and the amended body rides only the
    // amended one.
    let mut outcomes: Vec<&str> = receipts.iter().map(|r| r.outcome.as_str()).collect();
    outcomes.sort_unstable();
    assert_eq!(
        outcomes,
        ["approved_amended", "approved_untouched", "rejected"]
    );
    let carrying: Vec<&crate::receipt::ReceiptRecord> = receipts
        .iter()
        .filter(|r| crate::receipt::proposal_outcome_amended_body(r).is_some())
        .collect();
    assert_eq!(carrying.len(), 1);
    assert_eq!(carrying[0].outcome, "approved_amended");
    assert_eq!(
        crate::receipt::proposal_outcome_amended_body(carrying[0]),
        Some(body)
    );
}

#[test]
fn outcome_receipts_are_queryable_by_kind_and_outcome() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x82);
    let approved_loser = put_person(&vault, 0x83);
    let rejected_loser = put_person(&vault, 0x84);

    let approved = park_merge_proposal(&vault, vec![approved_loser], survivor, 200);
    vault
        .resolve_identity_proposal(&approved, ProposalRuling::Approve, &ruling_write(), 300)
        .expect("approve");
    let rejected = park_merge_proposal(&vault, vec![rejected_loser], survivor, 210);
    vault
        .resolve_identity_proposal(&rejected, ProposalRuling::Reject, &ruling_write(), 310)
        .expect("reject");

    let mut query = crate::receipt::ReceiptQuery::new(10)
        .with_kind(crate::receipt::ReceiptKind::ProposalOutcome);
    query.outcome = Some("rejected".to_owned());
    let filtered = vault.receipts(query).expect("filtered query");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].outcome, "rejected");

    // The two type-76 receipt kinds do not bleed into each other: a
    // lifecycle-only query never returns resolution rows, and vice versa.
    assert!(
        identity_receipts(&vault)
            .iter()
            .all(|r| r.receipt_kind == crate::receipt::ReceiptKind::IdentityLifecycle),
        "an identity-lifecycle query must not return proposal-outcome rows"
    );
    assert!(
        proposal_outcome_receipts(&vault)
            .iter()
            .all(|r| r.receipt_kind == crate::receipt::ReceiptKind::ProposalOutcome),
        "a proposal-outcome query must not return identity-lifecycle rows"
    );
}

#[test]
fn amendment_codec_round_trips_and_refuses_unarmed_kinds() {
    // The codec carries the ACTION shape only: `evidence` is event-envelope
    // data (the resolution's own, never the amendment's), so it decodes back
    // empty by design. The subject set is what the scope check reads, and it
    // round-trips exactly.
    let merge = merge_op(vec![id(0x85), id(0x86)], id(0x87));
    let encoded = encode_identity_op_amendment(&merge).expect("encode merge");
    assert_eq!(
        decode_identity_op_amendment(&encoded).expect("decode merge"),
        IdentityTopologyOp::Merge(MergeOp {
            sources: vec![id(0x85), id(0x86)],
            survivor: id(0x87),
            evidence: IdentityOpEvidence::default(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        })
    );

    let split = split_op(id(0x88), vec![id(0x89), id(0x8A)]);
    let encoded = encode_identity_op_amendment(&split).expect("encode split");
    assert_eq!(
        decode_identity_op_amendment(&encoded).expect("decode split"),
        IdentityTopologyOp::Split(SplitOp {
            entity: id(0x88),
            heads: vec![id(0x89), id(0x8A)],
            reassignment: ReassignmentMap::default(),
            evidence: IdentityOpEvidence::default(),
        })
    );

    // Only the two ops whose apply door is armed are amendable.
    assert!(matches!(
        encode_identity_op_amendment(&facet_op(id(0x8B))),
        Err(Error::IdentityTopologyUnarmed(_))
    ));

    // Trailing bytes are refused: an amendment must not smuggle a
    // non-canonical encoding past the scope check.
    let mut trailing = encode_identity_op_amendment(&merge).expect("encode merge");
    trailing.push(0x00);
    assert!(decode_identity_op_amendment(&trailing).is_err());
}

#[test]
fn amendment_scope_includes_reassignment_map() {
    // (a) An in-scope map row: the SAME claim item, reassigned to the OTHER
    // named head — narrowing the reviewed decision, so it amends cleanly.
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x8D);
    let head_a = put_person(&vault, 0x8E);
    let head_b = put_person(&vault, 0x8F);
    let claim_item = id(0x90);
    let stranger = put_person(&vault, 0x91);

    let mut proposed = IdentityOpWrite::auto(ClaimSource::Inferred);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let park = |vault: &Vault, original: EntityId, head_a: EntityId, head_b: EntityId| {
        expect_parked(
            vault
                .apply_identity_topology_op(
                    &IdentityTopologyOp::Split(SplitOp {
                        entity: original,
                        heads: vec![head_a, head_b],
                        reassignment: ReassignmentMap {
                            entries: vec![ReassignmentEntry {
                                item: ClaimSubject::Entity(claim_item),
                                target: ReassignmentTarget::Head(head_a),
                            }],
                        },
                        evidence: evidence(),
                    }),
                    &proposed,
                    200,
                )
                .expect("proposed split parks"),
        )
    };
    let amend = |vault: &Vault,
                 proposal: EntityId,
                 amended: IdentityTopologyOp|
     -> Result<ProposalOutcome> {
        let body = encode_identity_op_amendment(&amended).expect("encode amendment");
        vault
            .resolve_identity_proposal(
                &proposal,
                ProposalRuling::AmendThenApprove(&body),
                &ruling_write(),
                300,
            )
            .map(|(outcome, _)| outcome)
    };
    let split_with_heads = |original: EntityId,
                            head_a: EntityId,
                            head_b: EntityId,
                            entries: Vec<ReassignmentEntry>| {
        IdentityTopologyOp::Split(SplitOp {
            entity: original,
            heads: vec![head_a, head_b],
            reassignment: ReassignmentMap { entries },
            evidence: evidence(),
        })
    };

    // (a) in-scope: same claim item, retargeted onto the OTHER named head.
    let proposal = park(&vault, original, head_a, head_b);
    let outcome = amend(
        &vault,
        proposal,
        split_with_heads(
            original,
            head_a,
            head_b,
            vec![ReassignmentEntry {
                item: ClaimSubject::Entity(claim_item),
                target: ReassignmentTarget::Head(head_b),
            }],
        ),
    )
    .expect("an in-scope map row amends");
    assert_eq!(outcome, ProposalOutcome::ApprovedAmended);

    // (b) A bare claim item the proposal never named is NOT a route — the
    // map re-routes claims across the split's own heads, so a fresh claim
    // rides the same named heads without leaving scope. (A stranger only
    // enters through (c)/(d) routes, never as the item.)
    let original_b = put_person(&vault, 0x92);
    let head_a_b = put_person(&vault, 0x93);
    let head_b_b = put_person(&vault, 0x94);
    let proposal = park(&vault, original_b, head_a_b, head_b_b);
    let outcome = amend(
        &vault,
        proposal,
        split_with_heads(
            original_b,
            head_a_b,
            head_b_b,
            vec![ReassignmentEntry {
                item: ClaimSubject::Entity(id(0x95)),
                target: ReassignmentTarget::Head(head_a_b),
            }],
        ),
    )
    .expect("a fresh bare claim item still rides named heads");
    assert_eq!(outcome, ProposalOutcome::ApprovedAmended);

    // (c) A map row targeting a head the proposal never named — a ROUTE
    // through a stranger — must reject as out of scope, not merely as a
    // foreign head (that is the transition table's job; the scope pin
    // rejects it first, as review scope).
    let original_c = put_person(&vault, 0x96);
    let head_a_c = put_person(&vault, 0x97);
    let head_b_c = put_person(&vault, 0x98);
    let proposal = park(&vault, original_c, head_a_c, head_b_c);
    let error = amend(
        &vault,
        proposal,
        split_with_heads(
            original_c,
            head_a_c,
            head_b_c,
            vec![ReassignmentEntry {
                item: ClaimSubject::Entity(claim_item),
                target: ReassignmentTarget::Head(stranger),
            }],
        ),
    )
    .expect_err("a head route to a stranger is out of scope");
    assert!(
        matches!(error, Error::IdentityProposalAmendmentOutOfScope(_)),
        "expected out-of-scope, got {error:?}"
    );

    // (d) A map row whose ITEM is an EDGE with an endpoint the proposal
    // never named — replay moves that edge, so its endpoints are routes.
    let original_d = put_person(&vault, 0x99);
    let head_a_d = put_person(&vault, 0x9A);
    let head_b_d = put_person(&vault, 0x9B);
    let proposal = park(&vault, original_d, head_a_d, head_b_d);
    let error = amend(
        &vault,
        proposal,
        split_with_heads(
            original_d,
            head_a_d,
            head_b_d,
            vec![ReassignmentEntry {
                item: ClaimSubject::Edge {
                    source: head_a_d,
                    kind: EdgeKind::About,
                    target: stranger,
                },
                target: ReassignmentTarget::Head(head_b_d),
            }],
        ),
    )
    .expect_err("an edge route through a stranger is out of scope");
    assert!(
        matches!(error, Error::IdentityProposalAmendmentOutOfScope(_)),
        "expected out-of-scope, got {error:?}"
    );

    // Every rejection was fail-closed: no out-of-scope park resolved and no
    // stranger took any topology effect.
    let resolved = vault
        .receipts(
            crate::receipt::ReceiptQuery::new(50)
                .with_kind(crate::receipt::ReceiptKind::ProposalOutcome),
        )
        .expect("query outcome receipts");
    assert_eq!(resolved.len(), 2, "only the two in-scope rulings landed");
    assert_eq!(
        vault.entity_lifecycle_state(&stranger).expect("stranger"),
        EntityLifecycleState::Active
    );
}

#[test]
fn replicated_resolution_is_validated_against_the_same_door_rule() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC0);
    let loser = put_person(&vault, 0xC1);

    // A genuine parked proposal, resolved locally — the fold retires it.
    let proposal = park_merge_proposal(&vault, vec![loser], survivor, 200);
    let (outcome, _) = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Approve, &ruling_write(), 300)
        .expect("local ruling resolves the park");
    assert_eq!(outcome, ProposalOutcome::ApprovedUntouched);

    // A REPLICATED resolution row naming the SAME proposal: whatever a peer
    // claims, the fold this replay is judged against already resolved it —
    // the shared rule rejects it typed, never a lighter replay-side pass.
    let second = StoredIdentityOpEvent {
        seq: 500,
        at: 400,
        actor: None,
        source: ClaimSource::UserStated,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::ProposalResolution {
            proposal,
            outcome: ProposalOutcome::ApprovedUntouched,
            scope: ProposalScope {
                op_kind: EVENT_KIND_MERGE,
                target_class: "PERSON".to_owned(),
                actor: PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned(),
            },
            amended_body: None,
        },
    };
    let error = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.validate_replicated_identity_topology_event_in_txn(&rtxn, &second)
    }
    .expect_err("a second ruling on a retired park rejects on replay");
    assert_eq!(
        expect_rejection(error),
        IdentityTopologyRejection::ProposalAlreadyResolved { proposal },
    );

    // A replicated resolution whose stamped scope is NOT the tuple the
    // proposal row derives: replayed under a scope it was never ruled in —
    // the same rule rejects it, as mismatch, even while the park named is
    // an OPEN park.
    let other_loser = put_person(&vault, 0xC2);
    let open_park = park_merge_proposal(&vault, vec![other_loser], survivor, 210);
    let misscoped = StoredIdentityOpEvent {
        seq: 501,
        at: 400,
        actor: None,
        source: ClaimSource::UserStated,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::ProposalResolution {
            proposal: open_park,
            outcome: ProposalOutcome::ApprovedUntouched,
            scope: ProposalScope {
                op_kind: EVENT_KIND_SPLIT,
                target_class: "PERSON".to_owned(),
                actor: PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned(),
            },
            amended_body: None,
        },
    };
    let error = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.validate_replicated_identity_topology_event_in_txn(&rtxn, &misscoped)
    }
    .expect_err("a mis-stamped scope rejects on replay");
    assert_eq!(
        expect_rejection(error),
        IdentityTopologyRejection::ResolutionRuleMismatch {
            reason: "stamped ramp scope is not the proposal's derived tuple",
        },
    );
}

#[test]
fn approved_resolution_preserves_proposal_evidence() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xB4);
    let loser = put_person(&vault, 0xB5);
    let backed_claim = put_person(&vault, 0xB6);

    // Park a proposal carrying REAL evidence — the refs a replay must not
    // lose when the ruling re-applies the op as its own Approved event.
    let proposer_evidence = IdentityOpEvidence {
        refs: vec![backed_claim],
        rationale: "duplicate person record from import batch 7".to_owned(),
    };
    let mut proposed = IdentityOpWrite::auto(ClaimSource::Inferred);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let proposal = expect_parked(
        vault
            .apply_identity_topology_op(
                &IdentityTopologyOp::Merge(MergeOp {
                    sources: vec![loser],
                    survivor,
                    evidence: proposer_evidence.clone(),
                    survivorship_plan: SurvivorshipPlan::ReadThrough,
                }),
                &proposed,
                200,
            )
            .expect("proposed merge parks"),
    );

    let (outcome, _) = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Approve, &ruling_write(), 300)
        .expect("approve resolves");
    assert_eq!(outcome, ProposalOutcome::ApprovedUntouched);

    // The NEW applied event (the Approved merge, distinct from both the park
    // and the resolution row) carries the proposal's evidence: the ruling
    // did not sever the decision from what backed it.
    let applied: Vec<EntityId> = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .identity_topology_events_in_txn(&rtxn)
            .expect("events")
            .into_iter()
            .filter(|event| {
                event.approval == ClaimApprovalStatus::Approved
                    && matches!(event.action, IdentityTopologyAction::Apply(_))
            })
            .map(|event| event.event_id)
            .collect()
    };
    assert_eq!(applied.len(), 1, "exactly one approved op event");
    let record = vault
        .identity_topology_event(&applied[0])
        .expect("read applied")
        .expect("applied event exists");
    assert_eq!(
        record.approval,
        ClaimApprovalStatus::Approved,
        "the applied event is the ruling-grade row"
    );
    assert_eq!(
        record.evidence.as_ref(),
        Some(&proposer_evidence),
        "the proposal's refs and rationale persist through the Approved apply"
    );
    assert_eq!(
        record.evidence.as_ref().map(|e| e.refs.as_slice()),
        Some(&[backed_claim][..])
    );
    assert!(
        record
            .evidence
            .as_ref()
            .is_some_and(|e| e.rationale.contains("import batch 7")),
    );
}

#[test]
fn fold_rejected_duplicate_resolution_mints_no_outcome_receipt() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xB7);
    let loser = put_person(&vault, 0xB8);

    // A parked proposal, resolved LOCALLY — the winning ruling, and the
    // receipt MUST project from it.
    let proposal = park_merge_proposal(&vault, vec![loser], survivor, 200);
    let (outcome, winner) = vault
        .resolve_identity_proposal(&proposal, ProposalRuling::Reject, &ruling_write(), 300)
        .expect("local ruling resolves the park");
    assert_eq!(outcome, ProposalOutcome::Rejected);

    // A SECOND resolution row rides in on the replicated path (a peer
    // double-ruled the same park in the same replication frame). The fold
    // retires the park on the FIRST ruling in (seq, id) order, so this
    // later row lands as a fold REJECTION — it is still stored (the ledger
    // keeps the evidence) but it must mint NO outcome receipt: projecting
    // one would read as a second, contradictory decision about one review.
    let winner_record = vault
        .identity_topology_event(&winner)
        .expect("read winner")
        .expect("winner exists");
    let loser_row = StoredIdentityOpEvent {
        seq: winner_record.seq + 1,
        at: 400,
        actor: None,
        source: ClaimSource::UserStated,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::ProposalResolution {
            proposal,
            outcome: ProposalOutcome::ApprovedUntouched,
            scope: match &winner_record.action {
                StoredIdentityOpAction::ProposalResolution { scope, .. } => scope.clone(),
                _ => panic!("winner carries a resolution"),
            },
            amended_body: None,
        },
    };
    put_identity_event_record(&vault, id(0xB9), &loser_row);

    let receipts = proposal_outcome_receipts(&vault);
    assert_eq!(
        receipts.len(),
        1,
        "exactly one proposal-outcome receipt — the winning ruling only"
    );
    assert_eq!(
        receipts[0].receipt_id,
        format!("proposal_outcome:{}", winner.to_hex()),
        "the receipt projects from the fold's accepted ruling"
    );
    assert_eq!(receipts[0].outcome, "rejected");

    // The rejected row is still queryable as LEDGER (evidence kept), it just
    // carries no receipt PROJECTION of its own — the store remains the
    // record, the projection refuses the double-count.
    let stored = vault
        .identity_topology_event(&id(0xB9))
        .expect("read rejected row")
        .expect("fold-rejected rows are still stored");
    assert!(matches!(
        stored.action,
        StoredIdentityOpAction::ProposalResolution { .. }
    ));
}

// ─── ONE-1745 (MS-03): reassignment application + FACET minting ─────────────

/// Writes a committed claim about `subject` and returns its id.
///
/// The predicate sits under `profile.`, the one prefix the DEFAULT policy
/// manifest rates `criticality: normal` — every unmatched predicate defaults
/// to `critical`, which the Gate QUEUES for consent instead of committing.
/// These contracts need the claim to actually exist.
fn write_note_claim(vault: &Vault, claim: EntityId, subject: EntityId) -> EntityId {
    vault
        .put_claim(
            &claim,
            &crate::claim::ClaimBody::new(
                "profile.note",
                ClaimSubject::Entity(subject),
                Value::from("reassignment fixture"),
                0.9,
                ClaimApprovalStatus::Auto,
                crate::claim::ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put note claim");
    claim
}

fn split_op_with_map(
    entity: EntityId,
    heads: Vec<EntityId>,
    entries: Vec<ReassignmentEntry>,
) -> IdentityTopologyOp {
    IdentityTopologyOp::Split(SplitOp {
        entity,
        heads,
        reassignment: ReassignmentMap { entries },
        evidence: evidence(),
    })
}

fn facet_op_with_map(
    entity: EntityId,
    labels: &[&str],
    entries: Vec<ReassignmentEntry>,
) -> IdentityTopologyOp {
    IdentityTopologyOp::Facet(FacetOp {
        entity,
        facets: labels
            .iter()
            .map(|label| FacetSpec {
                label: (*label).to_owned(),
            })
            .collect(),
        reassignment: ReassignmentMap { entries },
        evidence: evidence(),
    })
}

/// r2/r6: application records WHERE each claim went and rewrites NOTHING.
/// The stored subject bytes are the provenance an unmerge has to unwind, so
/// the assignment lives beside them, never on top of them.
#[test]
fn split_map_application_records_assignment_without_rewriting_subjects() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head_a = put_person(&vault, 0x62);
    let head_b = put_person(&vault, 0x63);
    let assigned = write_note_claim(&vault, id(0x71), original);
    let residue = write_note_claim(&vault, id(0x72), original);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &split_op_with_map(
                    original,
                    vec![head_a, head_b],
                    vec![
                        ReassignmentEntry {
                            item: ClaimSubject::Entity(assigned),
                            target: ReassignmentTarget::Head(head_a),
                        },
                        ReassignmentEntry {
                            item: ClaimSubject::Entity(residue),
                            target: ReassignmentTarget::Residue,
                        },
                    ],
                ),
                &write,
                200,
            )
            .expect("apply split with map"),
    );

    assert_eq!(
        vault.claims_assigned_to(&head_a).expect("head a"),
        vec![assigned]
    );
    assert!(
        vault
            .claims_assigned_to(&head_b)
            .expect("head b")
            .is_empty()
    );
    assert_eq!(
        vault
            .ambiguous_residue_claims(&original)
            .expect("residue claims"),
        vec![residue]
    );
    assert_eq!(
        vault
            .claims_remaining_on_origin(&original)
            .expect("remaining"),
        vec![residue]
    );

    // r6, the Wikidata unmerge killer: BOTH subjects still name the original,
    // and subject-bound membership is unchanged by the assignment.
    for claim in [assigned, residue] {
        assert_eq!(
            vault
                .get_claim(&claim)
                .expect("read claim")
                .expect("claim exists")
                .subject,
            ClaimSubject::Entity(original)
        );
    }
    let mut subject_bound = vault
        .claims_for_subject(&original)
        .expect("claims for subject");
    subject_bound.sort();
    let mut expected = vec![assigned, residue];
    expected.sort();
    assert_eq!(subject_bound, expected);

    // The APPLIED counts are stamped on the event, so the pure receipt
    // projector reads them without a vault.
    let StoredIdentityOpAction::Split {
        applied_assigned,
        applied_residue,
        ..
    } = vault
        .identity_topology_event(&event)
        .expect("read split event")
        .expect("split event exists")
        .action
    else {
        panic!("expected a split action");
    };
    assert_eq!((applied_assigned, applied_residue), (1, 1));
}

/// A map row naming something this vault holds no CLAIM for records nothing —
/// DECLARED and APPLIED diverge, and the divergence is on the event.
#[test]
fn split_map_records_only_rows_that_name_a_stored_claim() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head = put_person(&vault, 0x62);
    let real = write_note_claim(&vault, id(0x71), original);
    // A PERSON is not a claim, and 0x73 is nothing at all.
    let not_a_claim = put_person(&vault, 0x64);
    let absent = id(0x73);

    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &split_op_with_map(
                    original,
                    vec![head],
                    vec![real, not_a_claim, absent]
                        .into_iter()
                        .map(|item| ReassignmentEntry {
                            item: ClaimSubject::Entity(item),
                            target: ReassignmentTarget::Head(head),
                        })
                        .collect(),
                ),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                200,
            )
            .expect("apply split with partly-unresolvable map"),
    );

    assert_eq!(vault.claims_assigned_to(&head).expect("head"), vec![real]);
    let record = vault
        .identity_topology_event(&event)
        .expect("read event")
        .expect("event exists");
    let StoredIdentityOpAction::Split {
        reassignment,
        applied_assigned,
        applied_residue,
        ..
    } = &record.action
    else {
        panic!("expected a split action");
    };
    assert_eq!(reassignment.assigned_and_residue_counts(), (3, 0));
    assert_eq!((*applied_assigned, *applied_residue), (1, 0));
}

/// r1: undo is a counter-event, and it takes the assignment rows with it —
/// same lifecycle as the shell edges it removes, on the same door.
#[test]
fn undo_of_a_mapped_split_reverses_its_assignment_rows() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head = put_person(&vault, 0x62);
    let claim = write_note_claim(&vault, id(0x71), original);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &split_op_with_map(
                    original,
                    vec![head],
                    vec![ReassignmentEntry {
                        item: ClaimSubject::Entity(claim),
                        target: ReassignmentTarget::Head(head),
                    }],
                ),
                &write,
                200,
            )
            .expect("apply split with map"),
    );
    assert_eq!(vault.claims_assigned_to(&head).expect("head"), vec![claim]);

    vault
        .undo_identity_topology_event(&event, &write, 300)
        .expect("undo split");
    assert!(
        vault.claims_assigned_to(&head).expect("head").is_empty(),
        "an undone split assigns nothing"
    );
    assert!(
        vault
            .ambiguous_residue_claims(&original)
            .expect("residue")
            .is_empty()
    );
    assert_eq!(
        vault
            .claims_remaining_on_origin(&original)
            .expect("remaining"),
        vec![claim],
        "the claim reads as the original's again"
    );
    // A PARKED undo moves nothing, so the rows must survive one: re-apply and
    // check the parked counter-event leaves the assignment standing.
    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &split_op_with_map(
                    original,
                    vec![head],
                    vec![ReassignmentEntry {
                        item: ClaimSubject::Entity(claim),
                        target: ReassignmentTarget::Head(head),
                    }],
                ),
                &write,
                400,
            )
            .expect("re-apply split"),
    );
    expect_parked(
        vault
            .undo_identity_topology_event(
                &event,
                &IdentityOpWrite {
                    approval: ClaimApprovalStatus::Proposed,
                    ..write
                },
                500,
            )
            .expect("park undo"),
    );
    assert_eq!(vault.claims_assigned_to(&head).expect("head"), vec![claim]);
}

/// A facet op has no undo: it moves no lifecycle state, so the family's
/// currency test has nothing to test, and reversing one would be an ENTITY
/// retraction (ARCH-0038's door), not an edge retraction. Typed, not silent.
#[test]
fn undo_of_a_facet_event_is_typed_not_silent() {
    let (_dir, vault) = open_vault();
    let base = put_person(&vault, 0x61);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(&facet_op(base), &write, 200)
            .expect("apply facet"),
    );

    let err = vault
        .undo_identity_topology_event(&event, &write, 300)
        .expect_err("facet events are not undoable");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotUndoable { event }
    );
    // Nothing was orphaned by the refusal: the mask and its wiring stand.
    assert_eq!(vault.facets_of(&base).expect("facets").len(), 1);
    assert_eq!(event_count(&vault), 1);
}

/// The sync-ingest door never runs the apply door, so a REPLICATED split
/// arrives with its map and no rows. The reconciler — the chokepoint the
/// redirect projection already rides — is where those rows are born, and
/// where they die when the ledger stops mandating them.
#[test]
fn sync_reconcile_derives_and_retires_replicated_assignment_rows() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let head = put_person(&vault, 0x62);
    let claim = write_note_claim(&vault, id(0x71), original);
    let event_id = id(0x74);
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Split {
            entity: original,
            heads: vec![head],
            reassignment: ReassignmentMap {
                entries: vec![ReassignmentEntry {
                    item: ClaimSubject::Entity(claim),
                    target: ReassignmentTarget::Head(head),
                }],
            },
            // The PEER's applied counts are its own; this vault re-derives
            // the rows from the map against its OWN claims.
            applied_assigned: 1,
            applied_residue: 0,
        },
    };
    put_identity_event_record(&vault, event_id, &record);
    assert!(
        vault.claims_assigned_to(&head).expect("head").is_empty(),
        "planting the row alone assigns nothing"
    );

    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile replicated split");
    assert_eq!(vault.claims_assigned_to(&head).expect("head"), vec![claim]);

    // Retire the split by replicating its counter-event: the reconciler
    // re-derives from the fold, which no longer mandates the rows.
    put_identity_event_record(
        &vault,
        id(0x75),
        &StoredIdentityOpEvent {
            seq: 51,
            action: StoredIdentityOpAction::Undo { target: event_id },
            evidence: None,
            ..record
        },
    );
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile undone split");
    assert!(
        vault.claims_assigned_to(&head).expect("head").is_empty(),
        "a reverted split mandates no assignment"
    );
    assert_eq!(
        vault
            .claims_remaining_on_origin(&original)
            .expect("remaining"),
        vec![claim]
    );
}

/// The two arms record in different places on purpose, so neither may erase
/// the other: a split reconcile rebuilds the split index wholesale, and a
/// facet's canonical `facet_of` stamps must survive it untouched.
#[test]
fn split_reconcile_never_erases_facet_scoping_on_the_same_base() {
    let (_dir, vault) = open_vault();
    let base = put_person(&vault, 0x61);
    let head = put_person(&vault, 0x62);
    let scoped = write_note_claim(&vault, id(0x71), base);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    let masks = seam_apply_facet(&vault, base, &["work", "home"], &[(scoped, 0)]);
    assert_eq!(
        vault.claims_assigned_to(&masks[0]).expect("mask a"),
        vec![scoped]
    );
    assert!(
        vault
            .claims_assigned_to(&masks[1])
            .expect("mask b")
            .is_empty(),
        "profiles never blend across masks"
    );

    vault
        .apply_identity_topology_op(&split_op(base, vec![head]), &write, 300)
        .expect("split the base");
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile");
    assert_eq!(
        vault.claims_assigned_to(&masks[0]).expect("mask a"),
        vec![scoped]
    );
    assert_eq!(vault.facets_of(&base).expect("facets").len(), 2);
}

/// Applies a facet op and returns its minted masks in spec order.
fn seam_apply_facet(
    vault: &Vault,
    entity: EntityId,
    labels: &[&str],
    assignments: &[(EntityId, u32)],
) -> Vec<EntityId> {
    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &facet_op_with_map(
                    entity,
                    labels,
                    assignments
                        .iter()
                        .map(|(claim, index)| ReassignmentEntry {
                            item: ClaimSubject::Entity(*claim),
                            target: ReassignmentTarget::Facet { index: *index },
                        })
                        .collect(),
                ),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                200,
            )
            .expect("apply facet"),
    );
    let StoredIdentityOpAction::Facet { facets, .. } = vault
        .identity_topology_event(&event)
        .expect("read facet event")
        .expect("facet event exists")
        .action
    else {
        panic!("expected a facet action");
    };
    facets
}

/// Facet events round-trip on the pinned wire, and the mask count is bounded
/// on the stateless path every admitting door runs — a facet op names ONE
/// participant however many masks it mints, so the participant bound does not
/// reach it.
#[test]
fn facet_event_wire_round_trips_and_bounds_its_mask_count() {
    let record = |facets: Vec<EntityId>| StoredIdentityOpEvent {
        seq: 1,
        at: 100,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Facet {
            entity: id(0x61),
            facets,
            reassignment: ReassignmentMap {
                entries: vec![ReassignmentEntry {
                    item: ClaimSubject::Entity(id(0x71)),
                    target: ReassignmentTarget::Facet { index: 0 },
                }],
            },
            applied_assigned: 1,
            applied_residue: 0,
        },
    };

    let one = record(vec![id(0x62)]);
    let bytes = encode_identity_topology_event_body(&one).expect("encode facet event");
    assert_eq!(
        decode_identity_topology_event_body(&bytes).expect("decode facet event"),
        one
    );

    // Zero masks is the `EmptyFacets` op shape, refused on the wire.
    let err = decode_identity_topology_event_body(
        &encode_identity_topology_event_body(&record(Vec::new())).expect("encode empty"),
    )
    .expect_err("a facet event minting nothing is not a legal op shape");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));

    let over_cap = (0..=MAX_IDENTITY_TOPOLOGY_EVENT_FACETS)
        .map(|index| {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            EntityId::from_bytes(bytes).expect("mask id")
        })
        .collect();
    let err = decode_identity_topology_event_body(
        &encode_identity_topology_event_body(&record(over_cap)).expect("encode over-cap"),
    )
    .expect_err("mask fan-out is bounded");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));
}

/// The applied counts are OMITTED from the wire when zero, which is what
/// keeps a parked split and an amendment body byte-identical to their
/// pre-ONE-1745 encoding — both codecs demand an exact re-encode.
#[test]
fn zero_applied_counts_stay_off_the_wire() {
    let entries = |action| {
        StoredIdentityOpEvent {
            seq: 1,
            at: 100,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action,
        }
        .encode_value()
    };
    let keys = |value: Value| -> Vec<String> {
        let Value::Map(entries) = value else {
            panic!("record encodes as map");
        };
        entries
            .iter()
            .filter_map(|(key, _)| key.as_str().map(str::to_owned))
            .collect()
    };
    let split = |applied_assigned, applied_residue| StoredIdentityOpAction::Split {
        entity: id(0x61),
        heads: vec![id(0x62)],
        reassignment: ReassignmentMap::default(),
        applied_assigned,
        applied_residue,
    };

    let bare = keys(entries(split(0, 0)));
    assert!(!bare.iter().any(|key| key == "asg" || key == "res"));
    let stamped = keys(entries(split(2, 1)));
    assert!(stamped.iter().any(|key| key == "asg"));
    assert!(stamped.iter().any(|key| key == "res"));

    // An amendment body is a PROPOSED body, so it carries neither count —
    // and the codec's exact-re-encode demand is what would have caught a
    // stray `asg: 0`. (Evidence is envelope data the codec never carries.)
    let amended = encode_identity_op_amendment(&split_op(id(0x61), vec![id(0x62)]))
        .expect("encode amendment");
    assert_eq!(
        decode_identity_op_amendment(&amended).expect("canonical amendment round-trips"),
        IdentityTopologyOp::Split(SplitOp {
            entity: id(0x61),
            heads: vec![id(0x62)],
            reassignment: ReassignmentMap::default(),
            evidence: IdentityOpEvidence::default(),
        })
    );
}

/// The projection may not depend on DELIVERY ORDER.
///
/// A map row records only when this vault holds the CLAIM it names, which is
/// deliberate (r2 lets a decision name an item a peer does not have) — and it
/// is exactly why a mapped claim can arrive AFTER the event that maps it. The
/// claim is not a participant of the op, so nothing woke the reconcile door
/// when it landed and its row was never born; the peer that received the
/// claim first recorded it. Same ledger, two projections.
///
/// The stamped APPLIED counts stay honest either way: they are what the DOOR
/// recorded, so the late-claim event stays at 0/0 while the reconcile-derived
/// index carries the row.
#[test]
fn a_mapped_claim_arriving_after_its_split_still_gets_its_row() {
    let projection = |claim_first: bool| -> (Vec<EntityId>, (u64, u64)) {
        let (_dir, vault) = open_vault();
        let original = put_person(&vault, 0x61);
        let head = put_person(&vault, 0x62);
        let claim = id(0x71);
        if claim_first {
            write_note_claim(&vault, claim, original);
        }
        let (event, _) = expect_applied(
            vault
                .apply_identity_topology_op(
                    &split_op_with_map(
                        original,
                        vec![head],
                        vec![ReassignmentEntry {
                            item: ClaimSubject::Entity(claim),
                            target: ReassignmentTarget::Head(head),
                        }],
                    ),
                    &IdentityOpWrite::auto(ClaimSource::Inferred),
                    200,
                )
                .expect("apply split with map"),
        );
        if !claim_first {
            assert!(
                vault.claims_assigned_to(&head).expect("head").is_empty(),
                "there is no claim to record yet"
            );
            write_note_claim(&vault, claim, original);
        }
        let StoredIdentityOpAction::Split {
            applied_assigned,
            applied_residue,
            ..
        } = vault
            .identity_topology_event(&event)
            .expect("read split event")
            .expect("split event exists")
            .action
        else {
            panic!("expected a split action");
        };
        (
            vault.claims_assigned_to(&head).expect("head"),
            (applied_assigned, applied_residue),
        )
    };

    let (claim_first_rows, claim_first_counts) = projection(true);
    let (event_first_rows, event_first_counts) = projection(false);
    assert_eq!(claim_first_rows, vec![id(0x71)]);
    assert_eq!(claim_first_counts, (1, 0));
    assert_eq!(
        event_first_rows, claim_first_rows,
        "two peers that saw the same event and the same claim agree, whatever order they arrived in"
    );
    assert_eq!(
        event_first_counts,
        (0, 0),
        "the stamp records what the DOOR did, not what the index later derived"
    );
}

/// A `ReassignmentEntry` is "where an item OF the split/facet entity goes",
/// and nothing upstream enforces the "of": the transition table checks the
/// map's TARGETS, never its items' provenance, and a peer's map replicates
/// verbatim. So the resolver is the door — otherwise a split of A files an
/// unrelated B's claim under A's head, and a facet of A stamps B's claim
/// `FacetOf` a mask A owns.
#[test]
fn reassignment_records_only_claims_the_origin_owns() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0x61);
    let stranger = put_person(&vault, 0x62);
    let head = put_person(&vault, 0x63);
    let mine = write_note_claim(&vault, id(0x71), original);
    let theirs = write_note_claim(&vault, id(0x72), stranger);

    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(
                &split_op_with_map(
                    original,
                    vec![head],
                    vec![mine, theirs]
                        .into_iter()
                        .map(|item| ReassignmentEntry {
                            item: ClaimSubject::Entity(item),
                            target: ReassignmentTarget::Head(head),
                        })
                        .collect(),
                ),
                &IdentityOpWrite::auto(ClaimSource::Inferred),
                200,
            )
            .expect("apply split naming a foreign claim"),
    );
    assert_eq!(
        vault.claims_assigned_to(&head).expect("head"),
        vec![mine],
        "the stranger's claim is not the origin's to route"
    );
    assert!(
        vault
            .ambiguous_residue_claims(&stranger)
            .expect("stranger residue")
            .is_empty()
    );
    // Dropped, not fatal — the same posture as a row naming an item this
    // vault holds no claim for, with the same visible declared-vs-applied gap.
    let StoredIdentityOpAction::Split {
        reassignment,
        applied_assigned,
        applied_residue,
        ..
    } = vault
        .identity_topology_event(&event)
        .expect("read split event")
        .expect("split event exists")
        .action
    else {
        panic!("expected a split action");
    };
    assert_eq!(reassignment.assigned_and_residue_counts(), (2, 0));
    assert_eq!((applied_assigned, applied_residue), (1, 0));

    // The FACET arm shares the resolver, so it inherits the same rule: no
    // cross-identity `facet_of` stamp is ever minted.
    let base = put_person(&vault, 0x64);
    let ours = write_note_claim(&vault, id(0x73), base);
    let masks = seam_apply_facet(&vault, base, &["work", "home"], &[(theirs, 0), (ours, 1)]);
    assert!(
        vault
            .claims_assigned_to(&masks[0])
            .expect("mask a")
            .is_empty(),
        "a mask of the base never scopes another entity's claim"
    );
    assert_eq!(
        vault.claims_assigned_to(&masks[1]).expect("mask b"),
        vec![ours]
    );
}

/// A facet op has no propose lane, and the rule has to hold at BOTH doors:
/// the local door refuses to record a park (a parked facet mints nothing yet
/// must name its masks, and the resolution door has no scope target for one),
/// so a stateless door that admits the same body from a peer persists exactly
/// the unresolvable orphan the local path calls corruption.
#[test]
fn a_parked_facet_event_is_refused_at_the_replicated_door_too() {
    let record = |approval| StoredIdentityOpEvent {
        seq: 7,
        at: 100,
        actor: None,
        source: ClaimSource::Inferred,
        approval,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Facet {
            entity: id(0x61),
            facets: vec![id(0x62)],
            reassignment: ReassignmentMap::default(),
            applied_assigned: 0,
            applied_residue: 0,
        },
    };

    // Control: the effective form is admitted, so the rejection below is the
    // consent axis and nothing else.
    let effective = record(ClaimApprovalStatus::Auto);
    let bytes = encode_identity_topology_event_body(&effective).expect("encode effective facet");
    assert_eq!(
        decode_identity_topology_event_body(&bytes).expect("decode effective facet"),
        effective
    );

    let err = decode_identity_topology_event_body(
        &encode_identity_topology_event_body(&record(ClaimApprovalStatus::Proposed))
            .expect("encode parked facet"),
    )
    .expect_err("a parked facet is unresolvable, so it is never stored");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));

    // The local door's answer, for the same body shape.
    let (_dir, vault) = open_vault();
    let base = put_person(&vault, 0x61);
    let err = vault
        .apply_identity_topology_op(
            &facet_op(base),
            &IdentityOpWrite {
                approval: ClaimApprovalStatus::Proposed,
                ..IdentityOpWrite::auto(ClaimSource::Inferred)
            },
            200,
        )
        .expect_err("the local door refuses a parked facet");
    assert!(matches!(
        err,
        Error::IdentityTopologyUnarmed("facet proposal")
    ));
}

/// The applied counts are an AUDIT record the receipt projects verbatim, so
/// the wire may not state one the record itself contradicts: a park applied
/// nothing, and an applied row is always a SUBSET of the map's declaration in
/// its own class (the resolver drops rows, it never reclassifies them).
#[test]
fn applied_counts_are_bounded_by_the_map_and_the_consent_axis() {
    let record = |approval, entries: Vec<ReassignmentEntry>, applied_assigned, applied_residue| {
        StoredIdentityOpEvent {
            seq: 9,
            at: 100,
            actor: None,
            source: ClaimSource::Inferred,
            approval,
            confidence: 1.0,
            evidence: None,
            action: StoredIdentityOpAction::Split {
                entity: id(0x61),
                heads: vec![id(0x62)],
                reassignment: ReassignmentMap { entries },
                applied_assigned,
                applied_residue,
            },
        }
    };
    let assign = vec![ReassignmentEntry {
        item: ClaimSubject::Entity(id(0x71)),
        target: ReassignmentTarget::Head(id(0x62)),
    }];
    let residue = vec![ReassignmentEntry {
        item: ClaimSubject::Entity(id(0x71)),
        target: ReassignmentTarget::Residue,
    }];
    let admits = |record: &StoredIdentityOpEvent| {
        decode_identity_topology_event_body(
            &encode_identity_topology_event_body(record).expect("encode"),
        )
        .is_ok()
    };

    // Exact and under-applied are both legal — a row naming an item this
    // vault holds no claim for records nothing.
    assert!(admits(&record(
        ClaimApprovalStatus::Auto,
        assign.clone(),
        1,
        0
    )));
    assert!(admits(&record(
        ClaimApprovalStatus::Auto,
        assign.clone(),
        0,
        0
    )));
    assert!(admits(&record(
        ClaimApprovalStatus::Auto,
        residue.clone(),
        0,
        1
    )));

    let err = decode_identity_topology_event_body(
        &encode_identity_topology_event_body(&record(
            ClaimApprovalStatus::Auto,
            assign.clone(),
            2,
            0,
        ))
        .expect("encode over-applied"),
    )
    .expect_err("a one-row map cannot have applied two");
    assert!(matches!(err, Error::InvalidIdentityTopologyEventBody(_)));

    // Over-applied in EITHER class, in either direction.
    assert!(!admits(&record(
        ClaimApprovalStatus::Auto,
        assign.clone(),
        1,
        1
    )));
    assert!(!admits(&record(ClaimApprovalStatus::Auto, residue, 1, 1)));

    // A park applied nothing, whatever its map declares.
    assert!(admits(&record(
        ClaimApprovalStatus::Proposed,
        assign.clone(),
        0,
        0
    )));
    assert!(!admits(&record(
        ClaimApprovalStatus::Proposed,
        assign,
        1,
        0
    )));
}

// ─── ONE-1746 (MS-04): entity.distinct_from ─────────────────────────────────

fn proposed(write: IdentityOpWrite) -> IdentityOpWrite {
    IdentityOpWrite {
        approval: ClaimApprovalStatus::Proposed,
        ..write
    }
}

/// The claim body an `assert_distinct` event named, read back off the ledger.
fn distinct_claim_of_event(vault: &Vault, event: &EntityId) -> (EntityId, ClaimBody) {
    let record = vault
        .identity_topology_event(event)
        .expect("read event")
        .expect("event exists");
    let StoredIdentityOpAction::AssertDistinct { claim, .. } = record.action else {
        panic!(
            "expected an assert_distinct action, got {:?}",
            record.action
        );
    };
    (
        claim,
        vault
            .get_claim(&claim)
            .expect("read distinct claim")
            .expect("distinct claim exists"),
    )
}

#[test]
fn assert_distinct_mints_one_normalized_claim_per_unordered_pair() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let pair = distinct_pair_key(a, b);

    let (first, _) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &write, 200)
            .expect("assert (a, b)"),
    );
    let (claim, body) = distinct_claim_of_event(&vault, &first);
    // §9 G.1: the claim is anchored on the pair's lex-first entity and its
    // value IS the normalized pair, so argument order cannot fork the row.
    assert_eq!(body.predicate, PREDICATE_ENTITY_DISTINCT_FROM);
    assert_eq!(body.subject, ClaimSubject::Entity(pair.0));
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(body.value, distinct_claim_value(pair));

    // Idempotent: the reversed assertion records its own ledger event and
    // ADOPTS the same claim — one pair, one row.
    let (second, transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(b, a), &write, 300)
            .expect("assert (b, a)"),
    );
    assert!(transitions.is_empty());
    assert_ne!(second, first);
    assert_eq!(distinct_claim_of_event(&vault, &second).0, claim);
    assert_eq!(
        vault.distinct_claims_for_pair(&a, &b).expect("pair claims"),
        vec![claim]
    );
    assert_eq!(
        vault.distinct_claims_for_pair(&b, &a).expect("pair claims"),
        vec![claim]
    );

    // Pair-exact: a different pair is a different claim, never a widening of
    // this one.
    vault
        .apply_identity_topology_op(&distinct_op(a, c), &write, 400)
        .expect("assert (a, c)");
    let unrelated = vault
        .distinct_claims_for_pair(&a, &c)
        .expect("unrelated pair claims");
    assert_eq!(unrelated.len(), 1);
    assert_ne!(unrelated[0], claim);
    assert!(
        vault
            .distinct_claims_for_pair(&b, &c)
            .expect("never-asserted pair")
            .is_empty()
    );
}

#[test]
fn distinct_claim_suppresses_only_proposed_merges_over_the_covered_pair() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let c = put_person(&vault, 0x23);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    vault
        .apply_identity_topology_op(&distinct_op(a, b), &write, 200)
        .expect("assert distinct");
    let pair = distinct_pair_key(a, b);

    // §6: the covered pair's re-proposal is refused typed, in either
    // direction and whichever side survives.
    for op in [merge_op(vec![b], a), merge_op(vec![a], b)] {
        let err = vault
            .apply_identity_topology_op(&op, &proposed(write), 300)
            .expect_err("a covered pair must not re-propose");
        assert_eq!(
            expect_rejection(err),
            IdentityTopologyRejection::DistinctPairSuppressed {
                a: pair.0,
                b: pair.1,
            }
        );
    }
    // A proposal that merely TOUCHES a covered entity is untouched — only a
    // proposal naming BOTH sides conflates the asserted pair.
    expect_parked(
        vault
            .apply_identity_topology_op(&merge_op(vec![c], a), &proposed(write), 300)
            .expect("unrelated pair still parks"),
    );
    assert!(
        vault
            .open_merge_proposals_for_pair(&a, &b)
            .expect("open proposals")
            .is_empty()
    );
    assert_eq!(
        vault
            .open_merge_proposals_for_pair(&a, &c)
            .expect("open proposals")
            .len(),
        1
    );

    // The claim suppresses agent RE-ASKING, never an owner's ruling: the same
    // merge applies unchanged on the effective lane.
    let (_, transitions) = expect_applied(
        vault
            .apply_identity_topology_op(&merge_op(vec![b], a), &write, 400)
            .expect("an effective merge is never blocked"),
    );
    assert_eq!(transitions, vec![(b, EntityLifecycleState::Merged)]);
}

#[test]
fn a_proposed_distinct_assertion_suppresses_nothing_until_it_is_effective() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);

    // The park mints its claim — a proposal with no row could never be
    // approved — but the row carries `Proposed` and suppresses nothing.
    let parked = expect_parked(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &proposed(write), 200)
            .expect("propose an assertion"),
    );
    let (proposed_claim, body) = distinct_claim_of_event(&vault, &parked);
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert!(
        vault
            .distinct_claims_for_pair(&a, &b)
            .expect("pair claims")
            .is_empty()
    );
    expect_parked(
        vault
            .apply_identity_topology_op(&merge_op(vec![b], a), &proposed(write), 300)
            .expect("an unapproved assertion suppresses nothing"),
    );

    // A proposal must not ABSORB an effective assertion: the effective write
    // RULES the park rather than being swallowed by it, so a producer who
    // proposes the pair first cannot neutralize an owner-ruled assertion.
    let (effective, _) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &write, 400)
            .expect("assert distinct"),
    );
    let (effective_claim, effective_body) = distinct_claim_of_event(&vault, &effective);
    assert_eq!(effective_claim, proposed_claim);
    assert_eq!(effective_body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        vault.distinct_claims_for_pair(&a, &b).expect("pair claims"),
        vec![effective_claim]
    );
    assert!(matches!(
        expect_rejection(
            vault
                .apply_identity_topology_op(&merge_op(vec![b], a), &proposed(write), 500)
                .expect_err("now suppressed")
        ),
        IdentityTopologyRejection::DistinctPairSuppressed { .. }
    ));
}

/// The park's ONLY resolution door. [`proposal_scope_target`] is unarmed for
/// this op kind, so `resolve_identity_proposal` can never rule on a parked
/// assertion — asserting the pair effectively is the ruling, and it has to
/// promote the parked row rather than mint a second Active one beside it.
#[test]
fn an_effective_re_assertion_promotes_the_parked_distinct_row_in_place() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let pair = distinct_pair_key(a, b);
    let proposer = IdentityOpWrite::auto(ClaimSource::Inferred);

    let parked = expect_parked(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &proposed(proposer), 200)
            .expect("propose an assertion"),
    );
    let (parked_claim, parked_body) = distinct_claim_of_event(&vault, &parked);
    assert_eq!(parked_body.approval, ClaimApprovalStatus::Proposed);

    // There is no other door: the park cannot reach the resolution ramp.
    assert!(matches!(
        vault
            .resolve_identity_proposal(
                &parked,
                ProposalRuling::Approve,
                &IdentityOpWrite::auto(ClaimSource::UserStated),
                300,
            )
            .expect_err("assert_distinct has no resolution ramp"),
        Error::IdentityTopologyUnarmed(_)
    ));

    // Asserting the pair effectively IS the ruling — same claim id back, in
    // either pair order, with only the approval cell moved.
    let ruler = IdentityOpWrite {
        approval: ClaimApprovalStatus::Approved,
        ..IdentityOpWrite::auto(ClaimSource::UserStated)
    };
    let (ruled, _) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(b, a), &ruler, 400)
            .expect("rule the park by asserting it"),
    );
    let (ruled_claim, ruled_body) = distinct_claim_of_event(&vault, &ruled);
    assert_eq!(ruled_claim, parked_claim);
    assert_eq!(ruled_body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(ruled_body.value, parked_body.value);
    assert_eq!(ruled_body.subject, parked_body.subject);
    assert_eq!(ruled_body.source, parked_body.source);
    assert_eq!(ruled_body.confidence, parked_body.confidence);

    let rtxn = vault.store.env.read_txn().expect("read txn");
    // ONE pair, ONE Active row — the promoted one, never a second mint.
    let covering: Vec<EntityId> = vault
        .active_distinct_claims_in_txn(&rtxn, &pair.0)
        .expect("active distinct rows")
        .into_iter()
        .filter(|row| row.pair == pair)
        .map(|row| row.claim)
        .collect();
    assert_eq!(covering, vec![parked_claim]);
    // The promotion moved consent, not the proposer's occurred/learned window.
    let raw = vault
        .store
        .entities
        .get(&rtxn, parked_claim.as_bytes())
        .expect("read claim row")
        .expect("claim row exists");
    let header = EntityMetadataHeader::parse(&raw).expect("claim header");
    assert_eq!(
        (
            header.occurred_start,
            header.occurred_end,
            header.learned_at
        ),
        (200, 200, 200)
    );
    drop(rtxn);

    // And the promoted row is what §6 suppression reads.
    assert_eq!(
        vault.distinct_claims_for_pair(&a, &b).expect("pair claims"),
        vec![parked_claim]
    );
}

#[test]
fn retracting_the_distinct_claim_lifts_suppression() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &write, 200)
            .expect("assert distinct"),
    );
    let (claim, _) = distinct_claim_of_event(&vault, &event);

    // The claim's own lifecycle is the retraction door — no shadow state, so
    // closing it is the whole undo.
    vault.retract_claim(&claim, 300).expect("retract claim");
    assert!(
        vault
            .distinct_claims_for_pair(&a, &b)
            .expect("pair claims")
            .is_empty()
    );
    expect_parked(
        vault
            .apply_identity_topology_op(&merge_op(vec![b], a), &proposed(write), 400)
            .expect("a retracted assertion suppresses nothing"),
    );
    // And the ledger event survives the retraction (r1: append-only history).
    assert!(
        vault
            .identity_topology_event(&event)
            .expect("read event")
            .is_some()
    );
}

#[test]
fn assert_distinct_event_is_not_undoable() {
    let (_dir, vault) = open_vault();
    let a = put_person(&vault, 0x21);
    let b = put_person(&vault, 0x22);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (event, _) = expect_applied(
        vault
            .apply_identity_topology_op(&distinct_op(a, b), &write, 200)
            .expect("assert distinct"),
    );
    let err = vault
        .undo_identity_topology_event(&event, &write, 300)
        .expect_err("an assertion is retracted through its claim, never undone");
    assert_eq!(
        expect_rejection(err),
        IdentityTopologyRejection::NotUndoable { event }
    );
}

#[test]
fn assert_distinct_event_wire_round_trips_and_pins_the_normalized_pair() {
    let pair = distinct_pair_key(id(0x21), id(0x22));
    let record = StoredIdentityOpEvent {
        seq: 7,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: Some(evidence()),
        action: StoredIdentityOpAction::AssertDistinct {
            a: pair.0,
            b: pair.1,
            claim: id(0x23),
        },
    };
    let bytes = encode_identity_topology_event_body(&record).expect("encode");
    assert_eq!(
        decode_identity_topology_event_body(&bytes).expect("decode"),
        record
    );

    // A descending pair is the unnormalized spelling one pair must not have.
    let unnormalized = StoredIdentityOpEvent {
        action: StoredIdentityOpAction::AssertDistinct {
            a: pair.1,
            b: pair.0,
            claim: id(0x23),
        },
        ..record.clone()
    };
    let bytes = encode_identity_topology_event_body(&unnormalized).expect("encode");
    assert!(matches!(
        decode_identity_topology_event_body(&bytes),
        Err(Error::InvalidIdentityTopologyEventBody(_))
    ));

    // Neither is a self-pair, and an amendment of this kind has no park to
    // amend (the resolution door owns merge and split only).
    let self_paired = StoredIdentityOpEvent {
        action: StoredIdentityOpAction::AssertDistinct {
            a: pair.0,
            b: pair.0,
            claim: id(0x23),
        },
        ..record
    };
    let bytes = encode_identity_topology_event_body(&self_paired).expect("encode");
    assert!(decode_identity_topology_event_body(&bytes).is_err());
    assert!(matches!(
        encode_identity_op_amendment(&distinct_op(id(0x21), id(0x22))),
        Err(Error::IdentityTopologyUnarmed(_))
    ));
}

#[test]
fn distinct_from_claim_structure_pins_the_pair_and_its_subject() {
    let pair = distinct_pair_key(id(0x21), id(0x22));
    let body = |subject, value| {
        ClaimBody::new(
            PREDICATE_ENTITY_DISTINCT_FROM,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
    };
    validate_distinct_from_claim_structure(&body(pair.0, distinct_claim_value(pair)))
        .expect("the normalized shape is the valid one");

    // The two bounds that make one unordered pair exactly one claim: the
    // value is normalized, and the subject is its lex-first entity. Without
    // either, an agent could mint a second row for the same pair.
    for rejected in [
        body(pair.0, distinct_claim_value((pair.1, pair.0))),
        body(pair.1, distinct_claim_value(pair)),
        body(pair.0, distinct_claim_value((pair.0, pair.0))),
        body(pair.0, Value::from("not a pair")),
        body(
            pair.0,
            Value::Map(vec![(Value::from("a"), id_value(&pair.0))]),
        ),
    ] {
        assert!(matches!(
            validate_distinct_from_claim_structure(&rejected),
            Err(Error::InvalidClaimBody(_))
        ));
    }
}
