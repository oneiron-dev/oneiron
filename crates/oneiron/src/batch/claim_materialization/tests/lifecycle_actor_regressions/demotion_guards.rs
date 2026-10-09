//! Exact demotion deltas and current source-lineage authority.

use super::*;
use crate::error::GateError;

#[test]
fn demotion_binding_rejects_body_author_metadata_and_edge_rebinding() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    // Start below the default 1.0 edge weight, so a later valid-range
    // increase is a real counterexample rather than an equal-weight decay.
    vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.5,
        },
        19,
    )?;
    let raw = vault.get_raw(&id)?.expect("authored row");
    let digest = binding_digest(&vault, id)?;
    let decisions = vault.store.gate_decisions(128)?;
    let before_metrics = gate_metric_emission_count_for_test();
    let mut decayed = vault.get_claim(&id)?.expect("claim");
    decayed.scope = Some(Value::Map(vec![(
        crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY.into(),
        "decayed".into(),
    )]));
    let valid = vec![
        BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange { start: 10, end: 20 },
            learned_at: 10,
            data: encode_claim_body(&decayed)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        BatchOp::SetEdgeWeight {
            src: id,
            kind: EdgeKind::ClaimOf,
            tgt: entity(0x62),
            weight: 0.1,
        },
    ];
    for change in 0..18 {
        let mut ops = valid.clone();
        let mut body = decayed.clone();
        match change {
            0 => body.value = "different claim".into(),
            1 => body.source = Some(ClaimSource::Observed),
            2 => body.approval = ClaimApprovalStatus::Proposed,
            3 => body.confidence = 0.5,
            4 => body.stale = true,
            5 => body.valid_to = Some(20),
            6 => body.lifecycle = ClaimLifecycleStatus::Retracted,
            7 => body.session_tag = Some("another session".into()),
            8 => {
                let Some(Value::Map(entries)) = &mut body.evidence else {
                    panic!("stamp");
                };
                entries
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some("actor_entity_ref"))
                    .expect("actor")
                    .1 = Value::Binary(entity(0x63).as_bytes().to_vec());
            }
            9 => {
                let Some(Value::Map(entries)) = &mut body.scope else {
                    panic!("scope");
                };
                entries.push(("unrelated".into(), true.into()));
            }
            10 => {
                let BatchOp::Put { occurred, .. } = &mut ops[0] else {
                    unreachable!();
                };
                occurred.start += 1;
            }
            11 => {
                let BatchOp::Put { learned_at, .. } = &mut ops[0] else {
                    unreachable!();
                };
                *learned_at += 1;
            }
            12 => {
                let BatchOp::Put {
                    hub_sync_imported, ..
                } = &mut ops[0]
                else {
                    unreachable!();
                };
                *hub_sync_imported = true;
            }
            13 => {
                let BatchOp::SetEdgeWeight { tgt, .. } = &mut ops[1] else {
                    unreachable!();
                };
                *tgt = entity(0x63);
            }
            14 => {
                let BatchOp::SetEdgeWeight { kind, .. } = &mut ops[1] else {
                    unreachable!();
                };
                *kind = EdgeKind::Supports;
            }
            15 => {
                let BatchOp::SetEdgeWeight { weight, .. } = &mut ops[1] else {
                    unreachable!();
                };
                *weight = 1.0;
            }
            16 => {
                ops.pop();
            }
            _ => ops.push(ops[1].clone()),
        }
        let BatchOp::Put { data, .. } = &mut ops[0] else {
            unreachable!();
        };
        *data = encode_claim_body(&body)?;
        let error = vault
            .with_write_txn(|txn| ClaimMaterialization::apply_demotion(&vault, txn, ops))
            .expect_err("only the constrained demotion may borrow current authority");
        assert!(
            matches!(
                error,
                Error::InvalidClaimBody("claim materialization binding mismatch")
            ),
            "change {change}: {error:?}"
        );
        assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
        assert_eq!(binding_digest(&vault, id)?, digest);
    }
    assert_eq!(vault.store.gate_decisions(128)?, decisions);
    assert_eq!(gate_metric_emission_count_for_test(), before_metrics);
    // The same exact operation is admissible, and an outer abort rolls back
    // both the finalized binding and the demotion body/edge mutation.
    let error = vault
        .with_write_txn(|txn| {
            ClaimMaterialization::apply_demotion(&vault, txn, valid)?;
            Err::<(), _>(Error::InvariantViolation("abort demotion"))
        })
        .expect_err("outer transaction abort");
    assert!(matches!(error, Error::InvariantViolation("abort demotion")));
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    Ok(())
}

#[test]
fn demotion_preserves_lineage_scope_and_session_and_rechecks_current_policy() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    let envelope = WriteEnvelope::with_lineage(
        actor,
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("demotion lineage fixture"))?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::ToolOutput).with(ClaimSource::Generated),
    )
    .with_session_tag("demotion-session");
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "profile.lifecycle_actor",
                ClaimSubject::Entity(entity(0x62)),
                "fact".into(),
                1.0,
            )
            .with_scope(Value::Map(vec![("context".into(), "retained".into())])),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()?;
    // Both permits name the exact actor, so an unattributed demotion cannot
    // pass this control even though the default first-party ceiling is Auto.
    let original = vault.get_claim(&id)?.expect("claim");
    vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        20,
    )?;
    let demoted = vault.get_claim(&id)?.expect("demoted");
    assert_eq!(demoted.evidence, original.evidence);
    assert_eq!(demoted.source, original.source);
    assert_eq!(demoted.approval, original.approval);
    assert_eq!(demoted.session_tag, original.session_tag);
    let Some(Value::Map(scope)) = &demoted.scope else {
        panic!("scope");
    };
    assert!(scope.contains(&("context".into(), "retained".into())));
    {
        let txn = vault.store.env.read_txn()?;
        let current = lifecycle_envelope(&vault.store, &txn, &id, &demoted)?.expect("bound");
        assert_eq!(current, envelope);
    }
    let raw = vault.get_raw(&id)?.expect("demoted");
    let digest = binding_digest(&vault, id)?;
    // A weakening is the Dreamer's write, gated under its own permits. Its
    // successor carries the predecessor's lineage forward, so without a
    // permit for every lineage member it pends and writes nothing. The
    // author keeps its own permits: the close of its claim is still its own.
    crate::test_util::provision_engine_machines(&vault);
    let dreamer = vault.dreamer_authority()?;
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, Some(actor.entity_ref())),
            (ClaimSource::Generated, None),
        ],
    )?;
    let error = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            21,
        )
        .expect_err("the Dreamer's permits must cover the carried lineage");
    assert!(
        matches!(&error, Error::Gate(GateError::GateWriteRejected { outcome: "pending", reason_codes })
        if reason_codes == &vec!["gate.pending.source_trust"]),
        "{error:?}"
    );
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, None),
            (ClaimSource::Generated, None),
        ],
    )?;
    // The successor is the Dreamer's, never the original author's, so the
    // Dreamer's lineage-bound policy governs its later lifecycle.
    let successor = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            21,
        )?
        .claim;
    assert_current_actor(&vault, successor, dreamer)?;
    let weakened = vault.get_claim(&successor)?.expect("successor");
    assert_eq!(weakened.source, Some(ClaimSource::Generated));
    assert_eq!(weakened.session_tag, original.session_tag);
    let Some(Value::Map(stamp)) = &weakened.evidence else {
        panic!("stamp");
    };
    assert!(stamp.iter().any(|(key, value)| {
        key.as_str() == Some("lineage")
            && value
                .as_array()
                .is_some_and(|sources| sources.contains(&Value::from("tool_output")))
    }));
    vault.retract_claim(&successor, 30)?;
    Ok(())
}

/// REV-9 D1 (ARCH-0003 change policy, RD-23; ARCH-0026 Curate): a confidence
/// weakening supersedes. The weakened claim closes and stays readable as
/// history; a successor carries the lower confidence, the rung stamp and the
/// decayed claim_of weight; and the claim can rise again. The successor is
/// the Dreamer's own claim, and its provenance names the claim it weakened.
#[test]
fn weakening_supersedes_and_keeps_the_old_claim_as_history() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    let dreamer = dreamer_claim(&vault, id)?;
    let original = vault.get_claim(&id)?.expect("authored claim");
    vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        20,
    )?;
    let weakened = vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Weaken {
            new_confidence: 0.5,
        },
        21,
    )?;
    assert_eq!(weakened.rung, ClaimDemotionRung::Weakened);
    assert_ne!(weakened.claim, id);

    let old = vault
        .get_claim(&id)?
        .expect("the weakened claim stays readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old.valid_to, Some(21));
    assert_eq!(old.confidence, original.confidence);
    assert_eq!(old.value, original.value);

    let successor = vault.get_claim(&weakened.claim)?.expect("successor");
    assert_eq!(successor.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(successor.confidence, 0.5);
    assert_eq!(
        claim_demotion_rung(&successor)?,
        Some(ClaimDemotionRung::Weakened)
    );
    assert_eq!(successor.predicate, original.predicate);
    assert_eq!(successor.value, original.value);
    assert_eq!(successor.source, Some(ClaimSource::Generated));
    assert_current_actor(&vault, weakened.claim, dreamer)?;
    let Some(Value::Map(stamp)) = &successor.evidence else {
        panic!("stamp");
    };
    assert!(
        stamp
            .iter()
            .any(|(key, value)| key.as_str() == Some("provenance")
                && value.as_map().is_some_and(|provenance| provenance
                    .contains(&("predecessor".into(), Value::Binary(id.as_bytes().to_vec())))))
    );
    let edges = vault.edges_out(&weakened.claim)?;
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Supersedes && edge.target == id)
    );
    assert!(edges.iter().any(|edge| edge.kind == EdgeKind::ClaimOf
        && edge.target == entity(0x62)
        && edge.weight == 0.1));

    // A weakening is not terminal: an ordinary supersession raises it again.
    let risen = entity(0x66);
    authored_local_claim(&vault, actor, risen)?;
    vault.supersede_claim(&risen, &weakened.claim, 30)?;
    assert_eq!(
        vault.get_claim(&weakened.claim)?.expect("closed").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(vault.get_claim(&risen)?.expect("risen").confidence, 1.0);
    Ok(())
}

/// A weakening keeps the predecessor's facet stamp: a claim forked under a
/// mask and then weakened is still listed by that mask, as its successor.
#[test]
fn weakening_a_forked_claim_keeps_its_facet_stamp() -> Result<()> {
    let (_dir, vault, _) = fixture()?;
    let id = entity(0x64);
    let dreamer = dreamer_claim(&vault, id)?;
    let mask = entity(0x67);
    facet_mask(&vault, mask)?;
    let fork = entity(0x68);
    let writer =
        crate::batch::SuccessionWriter::new(Some(dreamer), ClaimSource::Generated, "test.fork");
    vault.with_write_txn(|txn| {
        vault.fork_claim_to_facet_in_txn(txn, (id, fork), mask, true, writer, 15)
    })?;
    vault.apply_claim_demotion(
        &fork,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        20,
    )?;
    let weakened = vault.apply_claim_demotion(
        &fork,
        ClaimDemotionAction::Weaken {
            new_confidence: 0.5,
        },
        21,
    )?;
    assert!(
        vault
            .edges_out(&weakened.claim)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::FacetOf && edge.target == mask)
    );
    assert_eq!(
        vault
            .get_claim(&weakened.claim)?
            .expect("successor")
            .scope_facet,
        mask
    );
    assert!(vault.claims_assigned_to(&mask)?.contains(&weakened.claim));
    Ok(())
}

/// Astra #1336 P1 repro: a weakening is the Dreamer's act, so it never
/// borrows the authority of the person who wrote the claim. The Dreamer's
/// successor is `Generated`, which never closes user truth: the weakening is
/// refused and the claim stays as its author wrote it.
#[test]
fn a_dreamer_weakening_never_closes_user_truth() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        20,
    )?;
    let raw = vault.get_raw(&id)?.expect("decayed");
    let error = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            21,
        )
        .expect_err("the Dreamer never closes user truth");
    assert!(
        matches!(
            error,
            Error::InvalidClaimBody("generated claim cannot supersede user-stated truth")
        ),
        "{error:?}"
    );
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
    assert_current_actor(&vault, id, actor)?;
    Ok(())
}

/// Astra #1336 R2 repro: a host's unattributed successor carries no
/// envelope, so its predecessor's restricted history must still clear the
/// Gate under the host. A ToolOutput claim whose ToolOutput permit names
/// only its author cannot be forked by an actor-less Generated decision.
#[test]
fn an_unattributed_successor_keeps_its_predecessors_restricted_history() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, actor, id)?;
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, Some(actor.entity_ref())),
            (ClaimSource::Generated, None),
        ],
    )?;
    let mask = entity(0x67);
    facet_mask(&vault, mask)?;
    let fork = entity(0x68);
    let host = crate::batch::SuccessionWriter::new(None, ClaimSource::Generated, "test.fork");
    let error = vault
        .with_write_txn(|txn| {
            vault.fork_claim_to_facet_in_txn(txn, (id, fork), mask, true, host, 15)
        })
        .expect_err("the host has no permit for the inherited tool output");
    assert!(
        matches!(
            error,
            Error::Gate(GateError::SourceNotTrustedForAuto {
                claim_source: "tool_output"
            })
        ),
        "{error:?}"
    );
    assert!(vault.get_raw(&fork)?.is_none());
    assert_eq!(
        vault.get_claim(&id)?.expect("origin").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

/// Astra #1336 R3 repro: an unbound successor records the history it
/// continues, so the next successor inherits it. A host fork of tool output
/// is `Generated`, yet forking that fork again still needs the host's permit
/// for the tool output underneath.
#[test]
fn an_unattributed_successor_records_the_history_it_continues() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, actor, id)?;
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, None),
            (ClaimSource::Generated, None),
        ],
    )?;
    let (mask, other) = (entity(0x67), entity(0x69));
    facet_mask(&vault, mask)?;
    facet_mask(&vault, other)?;
    let host = crate::batch::SuccessionWriter::new(None, ClaimSource::Generated, "test.fork");
    let fork = entity(0x68);
    vault.with_write_txn(|txn| {
        vault.fork_claim_to_facet_in_txn(txn, (id, fork), mask, true, host, 15)
    })?;
    assert_eq!(
        vault.get_claim(&fork)?.expect("fork").source,
        Some(ClaimSource::Generated)
    );
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, Some(actor.entity_ref())),
            (ClaimSource::Generated, None),
        ],
    )?;
    let refork = entity(0x6a);
    let error = vault
        .with_write_txn(|txn| {
            vault.fork_claim_to_facet_in_txn(txn, (fork, refork), other, true, host, 16)
        })
        .expect_err("the fork still carries tool output the host may no longer write");
    assert!(
        matches!(
            error,
            Error::Gate(GateError::SourceNotTrustedForAuto {
                claim_source: "tool_output"
            })
        ),
        "{error:?}"
    );
    assert!(vault.get_raw(&refork)?.is_none());
    Ok(())
}

/// Astra #1336 R3 verification repro: the lineage record joins an unbound
/// successor's carried evidence without hiding it. A host fork of a claim
/// whose typed evidence cites a source that is not live is not supported
/// either.
#[test]
fn an_unattributed_successor_keeps_typed_citations_where_readers_look() -> Result<()> {
    use crate::dreamer_consolidation::{
        ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
    };
    let (_dir, vault, _) = fixture()?;
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, None),
            (ClaimSource::Generated, None),
        ],
    )?;
    let id = entity(0x64);
    let mut body = crate::claim::ClaimBody::new(
        "test.materialization",
        ClaimSubject::Entity(entity(0x62)),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::ToolOutput);
    body.evidence = Some(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![entity(0x6b)],
            chain: Vec::new(),
            source_meet: ClaimSource::ToolOutput,
        },
    ));
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: 10,
            end: u64::MAX,
        },
        10,
    )?;
    let mask = entity(0x67);
    facet_mask(&vault, mask)?;
    let host = crate::batch::SuccessionWriter::new(None, ClaimSource::Generated, "test.fork");
    let fork = entity(0x68);
    vault.with_write_txn(|txn| {
        vault.fork_claim_to_facet_in_txn(txn, (id, fork), mask, true, host, 15)
    })?;
    let forked = vault.get_claim(&fork)?.expect("fork");
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(!crate::claim::has_live_support_in_txn(
        &vault.store,
        &txn,
        &forked
    )?);
    Ok(())
}

/// Astra #1336 R3 verification 2 repro: a writer's own evidence stays the
/// writer's in a host successor. A person's tool output whose evidence holds
/// a key named like an engine stamp still forks, with or without a lineage
/// record, and the key never reaches the fork's top level.
#[test]
fn an_unattributed_successor_keeps_a_writers_evidence_under_the_writer() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    // The key a MACHINE claim's top-level signature lives under.
    let payload = Value::Map(vec![(
        "machine_signature".into(),
        "external receipt proof".into(),
    )]);
    let origins = [entity(0x64), entity(0x65)];
    for id in origins {
        let envelope = WriteEnvelope::with_lineage(
            actor,
            ClaimSource::ToolOutput,
            WriteProvenance::new(Value::from("host operation"))?,
            ClaimApprovalStatus::Auto,
            SourceLineage::of(ClaimSource::ToolOutput),
        );
        vault
            .batch()
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    "test.materialization",
                    ClaimSubject::Entity(entity(0x62)),
                    Value::from("fact"),
                    1.0,
                )
                .with_evidence(payload.clone()),
                &envelope,
                TimeRange {
                    start: 10,
                    end: u64::MAX,
                },
                10,
            )
            .commit()?;
    }
    permit_rows(
        &vault,
        &[
            (ClaimSource::ToolOutput, None),
            (ClaimSource::Generated, None),
        ],
    )?;
    let mask = entity(0x67);
    facet_mask(&vault, mask)?;
    // A `Generated` fork records the tool output under it; a person's
    // declared fork keeps the origin's source and needs no record.
    for (origin, fork, declared, recorded) in [
        (origins[0], entity(0x68), ClaimSource::Generated, true),
        (origins[1], entity(0x69), ClaimSource::UserStated, false),
    ] {
        let host = crate::batch::SuccessionWriter::new(None, declared, "test.fork");
        vault.with_write_txn(|txn| {
            vault.fork_claim_to_facet_in_txn(txn, (origin, fork), mask, true, host, 15)
        })?;
        let Some(Value::Map(entries)) = vault.get_claim(&fork)?.expect("fork").evidence else {
            panic!("fork evidence map");
        };
        let keys: Vec<_> = entries.iter().filter_map(|(key, _)| key.as_str()).collect();
        let mut expected = vec![crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY];
        if recorded {
            expected.insert(
                0,
                crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY,
            );
        }
        assert_eq!(keys, expected, "{declared:?}");
        assert!(entries.contains(&(
            crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY.into(),
            payload.clone()
        )));
    }
    Ok(())
}

/// Writes a FACET mask row under `id`.
fn facet_mask(vault: &Vault, id: EntityId) -> Result<()> {
    let mut facet = Vec::new();
    rmpv::encode::write_value(
        &mut facet,
        &Value::Map(vec![
            ("label".into(), "work".into()),
            ("sensitivity".into(), "sensitive".into()),
        ]),
    )
    .expect("facet body");
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &facet,
    )
}
