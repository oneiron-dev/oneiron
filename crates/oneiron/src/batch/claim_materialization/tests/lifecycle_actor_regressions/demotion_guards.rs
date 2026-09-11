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
    permit(&vault, actor.entity_ref(), &[ClaimSource::ToolOutput])?;
    let error = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            21,
        )
        .expect_err("the declared source cannot cover a revoked lineage member");
    assert!(
        matches!(&error, Error::Gate(GateError::GateWriteRejected { outcome: "pending", reason_codes })
        if reason_codes == &vec!["gate.pending.source_trust"]),
        "{error:?}"
    );
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    permit(
        &vault,
        actor.entity_ref(),
        &[ClaimSource::ToolOutput, ClaimSource::Generated],
    )?;
    vault.apply_claim_demotion(
        &id,
        ClaimDemotionAction::Weaken {
            new_confidence: 0.5,
        },
        21,
    )?;
    assert_current_actor(&vault, id, actor)?;
    vault.retract_claim(&id, 30)?;
    Ok(())
}
