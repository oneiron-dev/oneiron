//! Dreamer-approval VAD vetting and bundle hooks.

use super::*;

#[cfg(test)]
mod vad_vetting_tests {
    use super::*;
    use crate::affect::{CLAIM_VAD_REAPPRAISAL_PREDICATE, Vad, VadAnnotation, VadAnnotationSource};
    use crate::registry::ENTITY_TYPE_TURN;

    const RUN: &str = "bundle-vad-vetting";
    const FULL_VAD: Vad = Vad {
        valence: -0.5,
        arousal: 0.75,
        dominance: 0.25,
    };

    fn pending_member(vault: &crate::Vault, predicate: &str) -> Result<EntityId> {
        pending_member_with_turn(vault, predicate).map(|(claim, _)| claim)
    }

    fn pending_member_with_turn(
        vault: &crate::Vault,
        predicate: &str,
    ) -> Result<(EntityId, EntityId)> {
        let turn = EntityId::now();
        let claim = EntityId::now();
        let turn_body =
            rmp_serde::to_vec_named(&serde_json::json!({"txt": "evidence"})).expect("turn body");
        vault.put_entity(&turn, ENTITY_TYPE_TURN, test_time(2), 2, &turn_body)?;
        vault.annotate_turn_vad(
            &turn,
            VadAnnotation::new(FULL_VAD, VadAnnotationSource::ModelInference, 3)?,
        )?;
        let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
        body.predicate = predicate.to_owned();
        body.approval = ClaimApprovalStatus::Proposed;
        body.evidence = Some(precommit_evidence(vec![turn]));
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(vault, &body, test_id(0x40), RUN)?;
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
            .commit()?;
        assert!(has_pending_gate_consent(vault, &claim)?);
        vault.put_edge(&claim, EdgeKind::Mentions, &test_id(0x21), 0.6)?;
        vault.put_edge(&claim, EdgeKind::BelongsTo, &test_id(0x21), 1.0)?;
        Ok((claim, turn))
    }

    #[derive(Clone, Copy)]
    enum ApprovalDoor {
        Claim,
        Batch,
        TransactionalBatch,
    }

    const APPROVAL_DOORS: [ApprovalDoor; 3] = [
        ApprovalDoor::Claim,
        ApprovalDoor::Batch,
        ApprovalDoor::TransactionalBatch,
    ];

    fn approval_candidate_parts(
        vault: &crate::Vault,
        mut body: ClaimBody,
    ) -> Result<(ClaimCandidate, crate::write_envelope::WriteEnvelope)> {
        // Restore the candidate portion, not an envelope nested in itself.
        body.evidence = body
            .evidence
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|entries| {
                entries.iter().find(|(key, _)| {
                    key.as_str()
                        == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)
                })
            })
            .map(|(_, value)| value.clone());
        dreamer_claim_candidate_write_parts(vault, &body, test_id(0x40), RUN)
    }

    fn assert_neutral_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        claim: &EntityId,
    ) -> Result<()> {
        let key = crate::store::Store::encode_edge_key(claim, EdgeKind::Mentions, &test_id(0x21));
        let raw = vault
            .store
            .edges_out
            .get(txn, &key)?
            .expect("semantic edge");
        let edge = crate::edge::parse_strict_edge_record(&key, &raw)?;
        assert_eq!(edge.decoded.vad, Some(Vad::NEUTRAL));
        Ok(())
    }

    fn vad_states(vault: &crate::Vault, claim: &EntityId) -> Result<Vec<EntityId>> {
        let mut states = Vec::new();
        for edge in vault.edges_in(claim)? {
            if edge.kind == EdgeKind::ClaimOf
                && let Some(body) = vault.get_claim(&edge.target)?
                && body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
            {
                states.push(edge.target);
            }
        }
        Ok(states)
    }

    fn generic_approve(
        vault: &crate::Vault,
        claim: EntityId,
        door: ApprovalDoor,
        amend: bool,
    ) -> Result<()> {
        let mut body = vault.get_claim(&claim)?.expect("pending member");
        body.approval = ClaimApprovalStatus::Approved;
        if amend {
            body.value = Value::from("unbound replacement");
        }
        match door {
            ApprovalDoor::Claim => vault.put_claim(&claim, &body, test_time(10), 10),
            ApprovalDoor::Batch => {
                let (candidate, envelope) = approval_candidate_parts(vault, body)?;
                vault
                    .batch()
                    .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
                    .commit()
            }
            ApprovalDoor::TransactionalBatch => {
                let (candidate, envelope) = approval_candidate_parts(vault, body)?;
                vault.with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
                        .apply(wtxn)?;
                    // Applying the batch must not open a nested writer or
                    // populate before the actual transaction owner commits.
                    assert_neutral_in_txn(vault, wtxn, &claim)
                })
            }
        }
    }

    #[test]
    fn generic_dreamer_approval_doors_populate_vad_after_commit() -> Result<()> {
        for door in APPROVAL_DOORS {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(
                &vault,
                test_id(0x70),
                &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
            )?;
            let claim = pending_member(&vault, "profile.name")?;
            generic_approve(&vault, claim, door, false)?;
            assert!(!has_pending_gate_consent(&vault, &claim)?);
            assert_eq!(
                vault.get_claim(&claim)?.expect("durable approval").approval,
                ClaimApprovalStatus::Approved
            );
            let edges = vault.edges_out(&claim)?;
            assert_eq!(
                edges
                    .iter()
                    .find(|edge| edge.kind == EdgeKind::Mentions)
                    .expect("semantic")
                    .vad,
                Some(FULL_VAD)
            );
            assert_eq!(
                edges
                    .iter()
                    .find(|edge| edge.kind == EdgeKind::BelongsTo)
                    .expect("structural")
                    .vad,
                None
            );
            let states = vad_states(&vault, &claim)?;
            assert_eq!(states.len(), 1, "one postcommit state before any retry");
            let retry = vault.consolidate_claim_vad_now(&claim, crate::unix_seconds_now())?;
            assert_eq!(retry.reappraisal.active_claim_id, Some(states[0]));
            assert_eq!(retry.vad, Some(FULL_VAD));
            assert!(retry.reappraisal.active_claim_id.is_some());
            assert_eq!(retry.reappraisal.created_claim_id, None);
            let again = vault.consolidate_claim_vad_now(&claim, crate::unix_seconds_now())?;
            assert_eq!(
                again.reappraisal.active_claim_id,
                retry.reappraisal.active_claim_id
            );
            assert_eq!(again.reappraisal.created_claim_id, None);
        }
        Ok(())
    }

    #[test]
    fn generic_dreamer_approval_failures_preserve_commit_boundary() -> Result<()> {
        for door in APPROVAL_DOORS {
            for stale_binding in [false, true] {
                let (_tmp, vault) = temp_vault();
                put_policy_manifest_bytes(
                    &vault,
                    test_id(0x70),
                    &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
                )?;
                let claim = pending_member(&vault, CLAIM_VAD_REAPPRAISAL_PREDICATE)?;
                let result = generic_approve(&vault, claim, door, stale_binding);
                if stale_binding {
                    assert!(matches!(result, Err(Error::GateConsentStale { .. })));
                    assert!(has_pending_gate_consent(&vault, &claim)?);
                    assert_eq!(
                        vault.get_claim(&claim)?.expect("uncommitted").approval,
                        ClaimApprovalStatus::Proposed
                    );
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::InvalidClaimBody(
                            "claim VAD state claims cannot be consolidated"
                        ))
                    ));
                    assert!(!has_pending_gate_consent(&vault, &claim)?);
                    assert_eq!(
                        vault.get_claim(&claim)?.expect("committed").approval,
                        ClaimApprovalStatus::Approved
                    );
                    assert!(matches!(
                        vault.consolidate_claim_vad_now(&claim, 30),
                        Err(Error::InvalidClaimBody(
                            "claim VAD state claims cannot be consolidated"
                        ))
                    ));
                }
                assert_eq!(
                    vault
                        .edges_out(&claim)?
                        .iter()
                        .find(|edge| edge.kind == EdgeKind::Mentions)
                        .expect("semantic")
                        .vad,
                    Some(Vad::NEUTRAL)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn generic_dreamer_vad_failure_recovers_through_canonical_retry() -> Result<()> {
        for door in APPROVAL_DOORS {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(
                &vault,
                test_id(0x70),
                &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
            )?;
            let (claim, turn) = pending_member_with_turn(&vault, "profile.name")?;
            let annotation = crate::affect::vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
            let original = {
                let txn = vault.store.env.read_txn()?;
                vault
                    .store
                    .entities
                    .get(&txn, annotation.as_bytes())?
                    .expect("annotation claim")
                    .to_vec()
            };
            vault.with_write_txn(|wtxn| {
                let corrupt = crate::test_util::entity_record(
                    ENTITY_TYPE_PERSON,
                    test_time(3),
                    3,
                    b"corrupt annotation",
                );
                vault
                    .store
                    .entities
                    .put(wtxn, annotation.as_bytes(), &corrupt)?;
                Ok(())
            })?;
            assert!(matches!(
                generic_approve(&vault, claim, door, false),
                Err(Error::CorruptedIndex("VAD annotation claim"))
            ));
            assert_eq!(
                vault.get_claim(&claim)?.expect("durable approval").approval,
                ClaimApprovalStatus::Approved
            );
            assert!(!has_pending_gate_consent(&vault, &claim)?);
            vault.with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .put(wtxn, annotation.as_bytes(), &original)?;
                Ok(())
            })?;
            let recovered = vault.consolidate_claim_vad_now(&claim, crate::unix_seconds_now())?;
            assert_eq!(recovered.vad, Some(FULL_VAD));
            assert!(recovered.reappraisal.created_claim_id.is_some());
            let retry = vault.consolidate_claim_vad_now(&claim, crate::unix_seconds_now())?;
            assert_eq!(
                retry.reappraisal.active_claim_id,
                recovered.reappraisal.active_claim_id
            );
            assert_eq!(retry.reappraisal.created_claim_id, None);
        }
        Ok(())
    }

    #[test]
    fn generic_non_dreamer_consent_does_not_run_vad_hook() -> Result<()> {
        for door in APPROVAL_DOORS {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
            let claim = pending_member(&vault, CLAIM_VAD_REAPPRAISAL_PREDICATE)?;
            vault.with_write_txn(|wtxn| {
                let mut pending = vault
                    .store
                    .pending_gate_consent_in_txn(wtxn, &claim)?
                    .expect("pending member");
                pending.dreamer_run_id = None;
                vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
            })?;
            generic_approve(&vault, claim, door, false)?;
            assert_eq!(
                vault.get_claim(&claim)?.expect("approved").approval,
                ClaimApprovalStatus::Approved
            );
        }
        Ok(())
    }

    #[test]
    fn transactional_dreamer_approval_rollback_discards_postcommit_work() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x70),
            &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
        )?;
        let claim = pending_member(&vault, "profile.name")?;
        let mut body = vault.get_claim(&claim)?.expect("pending member");
        body.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = approval_candidate_parts(&vault, body)?;
        let result = vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
                .apply(wtxn)?;
            assert_neutral_in_txn(&vault, wtxn, &claim)?;
            assert_eq!(
                vault
                    .get_claim_in_txn(wtxn, &claim)?
                    .expect("staged")
                    .approval,
                ClaimApprovalStatus::Approved
            );
            Err::<(), _>(Error::InvalidConfig("deliberate rollback".to_owned()))
        });
        assert!(
            matches!(result, Err(Error::InvalidConfig(reason)) if reason == "deliberate rollback")
        );
        // Reusing the owner on this thread must not inherit the discarded work.
        vault.with_write_txn(|_| Ok(()))?;
        assert!(has_pending_gate_consent(&vault, &claim)?);
        assert_eq!(
            vault.get_claim(&claim)?.expect("rolled back").approval,
            ClaimApprovalStatus::Proposed
        );
        assert!(vad_states(&vault, &claim)?.is_empty());
        {
            let txn = vault.store.env.read_txn()?;
            assert_neutral_in_txn(&vault, &txn, &claim)?;
        }
        generic_approve(&vault, claim, ApprovalDoor::TransactionalBatch, false)?;
        assert_eq!(vad_states(&vault, &claim)?.len(), 1);
        Ok(())
    }

    #[test]
    fn transactional_dreamer_approvals_from_multiple_batches_share_one_commit() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x70),
            &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
        )?;
        let mut approvals = Vec::new();
        for _ in 0..2 {
            let claim = pending_member(&vault, "profile.name")?;
            let mut body = vault.get_claim(&claim)?.expect("pending member");
            body.approval = ClaimApprovalStatus::Approved;
            let (candidate, envelope) = approval_candidate_parts(&vault, body)?;
            approvals.push((claim, candidate, envelope));
        }
        let claims = approvals
            .iter()
            .map(|(claim, _, _)| *claim)
            .collect::<Vec<_>>();
        vault.with_write_txn(|wtxn| {
            for (claim, candidate, envelope) in approvals {
                vault
                    .batch_in()
                    .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
                    .apply(wtxn)?;
                assert_neutral_in_txn(&vault, wtxn, &claim)?;
            }
            Ok(())
        })?;
        for claim in claims {
            let states = vad_states(&vault, &claim)?;
            assert_eq!(states.len(), 1);
            let retry = vault.consolidate_claim_vad_now(&claim, crate::unix_seconds_now())?;
            assert_eq!(retry.vad, Some(FULL_VAD));
            assert_eq!(retry.reappraisal.active_claim_id, Some(states[0]));
            assert_eq!(retry.reappraisal.created_claim_id, None);
        }
        Ok(())
    }

    #[test]
    fn transactional_dreamer_approval_uses_final_owner_state() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        // temp_vault removes the default manifest; install the consent policy
        // so both the initial proposal and the final replacement are parked.
        put_policy_manifest_bytes(
            &vault,
            test_id(0x70),
            &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
        )?;
        let claim = pending_member(&vault, "profile.name")?;
        let mut body = vault.get_claim(&claim)?.expect("pending member");
        body.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = approval_candidate_parts(&vault, body.clone())?;
        body.approval = ClaimApprovalStatus::Proposed;
        let (replacement, replacement_envelope) = approval_candidate_parts(&vault, body)?;
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
                .apply(wtxn)?;
            vault
                .batch_in()
                .claim_candidate(
                    &claim,
                    replacement,
                    &replacement_envelope,
                    test_time(10),
                    10,
                )
                .apply(wtxn)
        })?;
        assert_eq!(
            vault
                .get_claim(&claim)?
                .expect("final owner state")
                .approval,
            ClaimApprovalStatus::Proposed
        );
        assert!(has_pending_gate_consent(&vault, &claim)?);
        assert!(vad_states(&vault, &claim)?.is_empty());
        let txn = vault.store.env.read_txn()?;
        assert_neutral_in_txn(&vault, &txn, &claim)
    }

    #[test]
    fn gate_bundle_approve_hook_populates_full_vad_and_skips_structural() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x70),
            &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
        )?;
        let claim = pending_member(&vault, "profile.name")?;
        let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
        let bundle = vault.review_gate_consent_bundle(&reviewer, RUN)?;
        let owner = consent_bundle_owner(&vault, test_id(0x60))?;
        vault.resolve_gate_consent_bundle(
            &owner,
            bundle.bundle_id,
            RUN,
            GateConsentBundleAction::Approve,
            20,
        )?;
        assert_eq!(
            vault.get_claim(&claim)?.expect("approved").approval,
            ClaimApprovalStatus::Approved
        );
        // Observe the production hook's state BEFORE any explicit retry.
        let edges = vault.edges_out(&claim)?;
        assert_eq!(
            edges
                .iter()
                .find(|edge| edge.kind == EdgeKind::Mentions)
                .expect("semantic edge")
                .vad,
            Some(FULL_VAD)
        );
        assert_eq!(
            edges
                .iter()
                .find(|edge| edge.kind == EdgeKind::BelongsTo)
                .expect("structural edge")
                .vad,
            None
        );
        let mut states = Vec::new();
        for edge in vault.edges_in(&claim)? {
            if edge.kind == EdgeKind::ClaimOf
                && let Some(body) = vault.get_claim(&edge.target)?
                && body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                states.push(edge.target);
            }
        }
        assert_eq!(states.len(), 1);
        let retry = vault.consolidate_claim_vad_now(&claim, 30)?;
        assert_eq!(retry.vad, Some(FULL_VAD));
        assert_eq!(retry.reappraisal.active_claim_id, Some(states[0]));
        assert_eq!(retry.reappraisal.created_claim_id, None);
        assert!(matches!(
            vault.resolve_gate_consent_bundle(
                &owner,
                bundle.bundle_id,
                RUN,
                GateConsentBundleAction::Approve,
                31,
            ),
            Err(Error::EntityNotFound)
        ));
        Ok(())
    }

    #[test]
    fn gate_bundle_vad_failure_is_loud_after_approved_commit_but_decline_skips() -> Result<()> {
        for action in [
            GateConsentBundleAction::Approve,
            GateConsentBundleAction::Decline,
        ] {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(
                &vault,
                test_id(0x70),
                &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Inferred, 3)]),
            )?;
            let claim = pending_member(&vault, CLAIM_VAD_REAPPRAISAL_PREDICATE)?;
            let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
            let bundle = vault.review_gate_consent_bundle(&reviewer, RUN)?;
            let owner = consent_bundle_owner(&vault, test_id(0x60))?;
            let result =
                vault.resolve_gate_consent_bundle(&owner, bundle.bundle_id, RUN, action, 20);
            let stored = vault.get_claim(&claim)?.expect("committed member");
            if action == GateConsentBundleAction::Approve {
                assert!(matches!(
                    result,
                    Err(Error::InvalidClaimBody(
                        "claim VAD state claims cannot be consolidated"
                    ))
                ));
                assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
                assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
            } else {
                result?;
                assert_eq!(stored.approval, ClaimApprovalStatus::Rejected);
                assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Retracted);
            }
            assert!(!has_pending_gate_consent(&vault, &claim)?);
            assert_eq!(consent_bundle_receipts(&vault)?.len(), 1);
            assert!(matches!(
                vault.resolve_gate_consent_bundle(&owner, bundle.bundle_id, RUN, action, 30),
                Err(Error::EntityNotFound)
            ));
        }
        Ok(())
    }
}
