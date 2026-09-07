use super::*;

fn assert_claim_candidate_lineage_permits(
    source: ClaimSource,
    lineage: &crate::write_envelope::SourceLineage,
    rows: &[(ClaimSource, SourceTrustRow)],
    allows: bool,
) -> Result<()> {
    let actor = test_id(0x20);
    let (_tmp, vault) = temp_vault();
    let trust_rows = rows
        .iter()
        .map(|(source, row)| {
            (
                Value::from(source.as_str()),
                Value::Map(vec![
                    (
                        Value::from(ACTOR_REF_KEY),
                        Value::from(row.actor_ref.expect("actor-bound fixture").to_hex()),
                    ),
                    (
                        Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                        Value::from(u64::from(row.max_auto_sensitivity.expect("fixture cap"))),
                    ),
                    (
                        Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                        Value::from(row.receipted),
                    ),
                    (
                        Value::from(SOURCE_TRUST_WARNED_KEY),
                        Value::from(row.warned),
                    ),
                ]),
            )
        })
        .collect();
    let mut data = encode_policy_manifest(vec![(
        Value::from(POLICY_SOURCE_TRUST_KEY),
        Value::Map(trust_rows),
    )]);
    replace_actor_ceilings(
        &mut data,
        vec![actor_ceiling_row_for_ref("system", &actor.to_hex(), "auto")],
    );
    put_policy_manifest_bytes(&vault, test_id(0x23), &data)?;
    vault.put_entity(&actor, ENTITY_TYPE_MACHINE, test_time(1), 1, b"gate actor")?;
    let mut body = source_trust_claim(source);
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"subject")?;
    }
    let policy = resolve(&vault)?;
    // The final Auto ceiling and evaluator must consult the same member rows.
    assert_eq!(
        check_claim_source_trust(&body, Some(&actor.to_hex()), &policy, Some(lineage)).is_ok(),
        allows,
        "final ceiling: {source:?}, {rows:?}"
    );

    for (index, approval) in [
        ClaimApprovalStatus::Proposed,
        ClaimApprovalStatus::Approved,
        ClaimApprovalStatus::Auto,
    ]
    .into_iter()
    .enumerate()
    {
        body.approval = approval;
        let envelope = WriteEnvelope::with_lineage(
            WriteActor::new(actor, EdgeActorClass::System),
            source,
            WriteProvenance::new(Value::from("gate-test"))?,
            approval,
            lineage.clone(),
        );
        // Public commit covers preflight and application; batch_in has no preflight.
        for in_txn in [false, true] {
            let id = test_id(0x24 + index as u8 * 2 + u8::from(in_txn));
            let candidate = claim_candidate_from_body(&body);
            let result = if in_txn {
                vault.with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
                        .apply(wtxn)
                })
            } else {
                vault
                    .batch()
                    .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
                    .commit()
            };
            let proposed = approval == ClaimApprovalStatus::Proposed;
            assert_eq!(
                result.is_ok(),
                allows || proposed,
                "{source:?}, {rows:?}, {approval:?}, batch_in={in_txn}: {result:?}"
            );
            if allows || proposed {
                let stored = stored_claim_body(&vault, &id)?;
                assert_eq!(stored.source, Some(source));
                assert_eq!(stored.approval, approval);
            } else {
                assert_gate_rejected(
                    result.expect_err("each restricted member needs its own permit"),
                    "pending",
                    &["gate.pending.source_trust"],
                );
                assert!(vault.get_raw(&id)?.is_none());
            }
            assert_eq!(has_pending_gate_consent(&vault, &id)?, proposed && !allows);
            // Preflight emits a receipt on both outcomes. Caller-owned apply
            // emits a fresh receipt when it attaches pending consent.
            if !in_txn || (proposed && !allows) {
                let decisions = vault.store.gate_decisions(20)?;
                let decision = decisions
                    .iter()
                    .find(|decision| decision.claim_id == Some(*id.as_bytes()))
                    .expect("candidate gate decision");
                assert_eq!(decision.outcome, if allows { "allow" } else { "pending" });
                assert_eq!(
                    decision.reason_codes,
                    vec![if allows {
                        "gate.allow"
                    } else {
                        "gate.pending.source_trust"
                    }]
                );
                if proposed && !allows {
                    let pending = vault.pending_gate_consents(20)?;
                    let pending = pending
                        .iter()
                        .find(|pending| pending.claim_id == *id.as_bytes())
                        .expect("pending source-trust consent");
                    assert_eq!(pending.decision_id, decision.decision_id);
                    assert_eq!(pending.reason_codes, vec!["gate.pending.source_trust"]);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn claim_candidate_generated_tool_lineage_requires_both_member_permits() -> Result<()> {
    use crate::write_envelope::SourceLineage;

    let valid = SourceTrustRow {
        actor_ref: Some(test_id(0x20)),
        max_auto_sensitivity: Some(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        receipted: true,
        warned: true,
    };
    let generated = ClaimSource::Generated;
    let tool = ClaimSource::ToolOutput;
    let lineage = SourceLineage::of(generated).with(tool);
    for (rows, allows) in [
        (vec![], false),
        (vec![(generated, valid)], false),
        (vec![(tool, valid)], false),
        (vec![(generated, valid), (tool, valid)], true),
    ] {
        assert_claim_candidate_lineage_permits(generated, &lineage, &rows, allows)?;
    }
    // A broken permit on EITHER member refuses; the other row stays valid.
    for invalid in [
        SourceTrustRow {
            actor_ref: Some(test_id(0x22)),
            ..valid
        },
        SourceTrustRow {
            receipted: false,
            ..valid
        },
        SourceTrustRow {
            warned: false,
            ..valid
        },
        SourceTrustRow {
            max_auto_sensitivity: Some(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND - 1),
            ..valid
        },
    ] {
        for rows in [
            vec![(generated, invalid), (tool, valid)],
            vec![(generated, valid), (tool, invalid)],
        ] {
            assert_claim_candidate_lineage_permits(generated, &lineage, &rows, false)?;
        }
    }
    // A one-member Generated declaration still uses its own valid permit.
    assert_claim_candidate_lineage_permits(
        generated,
        &SourceLineage::of(generated),
        &[(generated, valid)],
        true,
    )?;
    Ok(())
}

#[test]
fn claim_candidate_user_stated_tool_lineage_requires_tool_permit() -> Result<()> {
    use crate::write_envelope::SourceLineage;

    let user = ClaimSource::UserStated;
    let tool = ClaimSource::ToolOutput;
    let lineage = SourceLineage::of(user).with(tool);
    let valid = SourceTrustRow {
        actor_ref: Some(test_id(0x20)),
        max_auto_sensitivity: Some(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        receipted: true,
        warned: true,
    };
    for (rows, allows) in [
        (vec![], false),
        (vec![(user, valid)], false),
        (vec![(tool, valid)], true),
        (vec![(user, valid), (tool, valid)], true),
        // UserStated keeps its ordinary cap, but does not acquire the
        // restricted classes' receipt/warning requirements from ToolOutput.
        (
            vec![
                (
                    user,
                    SourceTrustRow {
                        receipted: false,
                        warned: false,
                        ..valid
                    },
                ),
                (tool, valid),
            ],
            true,
        ),
        (
            vec![
                (
                    user,
                    SourceTrustRow {
                        max_auto_sensitivity: Some(0),
                        ..valid
                    },
                ),
                (tool, valid),
            ],
            false,
        ),
    ] {
        assert_claim_candidate_lineage_permits(user, &lineage, &rows, allows)?;
    }
    // Clean non-Auto UserStated remains the compatibility control.
    assert_claim_candidate_lineage_permits(user, &SourceLineage::of(user), &[], true)?;
    Ok(())
}
