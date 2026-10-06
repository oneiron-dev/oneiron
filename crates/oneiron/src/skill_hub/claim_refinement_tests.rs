//! Claim refinements use the same typed question and independent held-out rule.
use super::*;
use crate::{
    Vault, VaultConfig,
    claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        encode_claim_body,
    },
    consent::AuthenticatedOwner,
    deletion::{ReplayedTombstoneOutcome, TombstoneReason, TombstoneValueV2},
    llm::decision::{
        AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionQuestion,
        DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
    },
    skill_hub::{
        ClaimRefinementMergeDisposition, HeldOutClaimReplayCase, HeldOutClaimReplayScorer,
        UsefulUpstreamClaimJudge,
    },
};

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn question(id: EntityId) -> DecisionQuestion {
    DecisionQuestion {
        id,
        version: 1,
        text: "Useful upstream?".to_owned(),
        class: DecisionClass::UsefulUpstream,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    base: EntityId,
    resident: EntityId,
    owner: AuthenticatedOwner,
    subject: EntityId,
}
impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            at(1),
            1,
            b"owner",
        )?;
        let owner = vault.authenticate_owner(
            subject,
            "principal:claim-refinement",
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let resident = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")?
            .expect("seeded agent")
            .0;
        let base = EntityId::now();
        let mut original = ClaimBody::new(
            "booking.refinement",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("old"),
            0.8,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        original.source = Some(ClaimSource::Inferred);
        vault.put_claim(&base, &original, at(2), 2)?;
        let label = EntityId::now();
        let mut evidence = ClaimBody::new(
            "booking.label",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("adjudicated"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        evidence.source = Some(ClaimSource::UserStated);
        vault.put_claim(&label, &evidence, at(3), 3)?;
        vault.reserve_claim_refinement_holdout(&owner, base, &[label])?;
        Ok(Self {
            vault,
            _dir: dir,
            base,
            resident,
            owner,
            subject,
        })
    }
    fn proposal(&self, value: &str) -> ClaimBody {
        let mut body = ClaimBody::new(
            "booking.refinement",
            ClaimSubject::Entity(self.subject),
            rmpv::Value::from(value),
            0.9,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.source = Some(ClaimSource::Inferred);
        body.session_tag = Some("session:claim-refine".to_owned());
        body
    }
    fn submit(&self, value: &str) -> Result<EntityId> {
        self.vault.submit_local_claim_refinement(
            self.base,
            self.resident,
            "session:claim-refine",
            &self.proposal(value),
            at(5),
            5,
        )
    }
}
struct Useful(bool);
impl UsefulUpstreamClaimJudge for Useful {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        _: &ClaimBody,
        _: &ClaimBody,
    ) -> Result<TypedDecision> {
        Ok(TypedDecision {
            answer: DecisionAnswer::Noul(self.0),
            probability: Some(if self.0 { 0.9 } else { 0.1 }),
            evidence: vec![],
            in_band: false,
            receipt: DecisionReceipt {
                question: question.id,
                question_version: question.version,
                principal: resident,
                providers: vec![ProviderPin {
                    rung: DecisionRung::SystemOne,
                    model: "system-one".to_owned(),
                    version: "1".to_owned(),
                }],
                band: DecisionBand::default(),
                band_version: 0,
                evidence_versions: Vec::new(),
                cost_per_thousand: None,
            },
            human_ask: None,
        })
    }
}
struct Replay;
impl HeldOutClaimReplayScorer for Replay {
    fn score(&self, case: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
        assert_eq!(case.held_out_receipts.len(), 1);
        Ok(if case.claim.value.as_str() == Some("improved") {
            0.9
        } else {
            0.2
        })
    }
}
struct NoReplay;
impl HeldOutClaimReplayScorer for NoReplay {
    fn score(&self, _: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
        panic!("replay must not run")
    }
}
#[test]
fn rejected_branch_claim_stays_local_and_cannot_use_the_generic_claim_door() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    assert_eq!(
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(true), &NoReplay, 6)?,
        ClaimRefinementMergeDisposition::PendingConsent
    );
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    let ClaimRefinementMergeDisposition::Ruled(receipt) =
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(false), &NoReplay, 6)?
    else {
        panic!("consented")
    };
    assert!(!receipt.accepted);
    assert_eq!(receipt.before, None);
    assert_eq!(receipt.resident, f.resident.to_hex());
    let staged = f
        .vault
        .local_claim_refinement(candidate)?
        .unwrap()
        .claim_body()?;
    assert_eq!(staged.value, f.proposal("improved").value);
    assert_eq!(staged.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        crate::claim::session_claim_producer(&staged),
        Some(f.resident)
    );
    assert_eq!(f.vault.get_claim(&candidate)?, Some(staged));
    assert!(
        f.vault
            .put_claim(&candidate, &f.proposal("improved"), at(7), 7)
            .is_err()
    );
    assert!(
        f.vault
            .batch()
            .put(
                &candidate,
                crate::registry::ENTITY_TYPE_CLAIM,
                at(7),
                7,
                &encode_claim_body(&f.proposal("improved"))?
            )
            .commit()
            .is_err()
    );
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        f.vault.claim_refinement_merge_receipt(candidate)?,
        Some(*receipt)
    );
    Ok(())
}
#[test]
fn claim_yes_needs_held_out_win_and_supersedes_only_at_the_merge_door() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    let ClaimRefinementMergeDisposition::Ruled(receipt) =
        f.vault
            .merge_local_claim_refinement(&ask, &Useful(true), &Replay, 8)?
    else {
        panic!("consented")
    };
    assert!(receipt.accepted);
    assert_eq!(receipt.before, Some(0.2));
    assert_eq!(receipt.after, Some(0.9));
    assert_eq!(
        f.vault.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert!(f.vault.local_claim_refinement(candidate)?.is_some());
    Ok(())
}
#[test]
fn claim_tie_keeps_the_branch_and_base() -> Result<()> {
    struct Tie;
    impl HeldOutClaimReplayScorer for Tie {
        fn score(&self, _: &HeldOutClaimReplayCase<'_>) -> Result<f32> {
            Ok(0.5)
        }
    }
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    assert!(
        matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(true), &Tie, 8)?,
        ClaimRefinementMergeDisposition::Ruled(receipt) if !receipt.accepted)
    );
    assert_eq!(
        f.vault.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(f.vault.local_claim_refinement(candidate)?.is_some());
    assert_eq!(
        f.vault.get_claim(&f.base)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn staged_claim_scans_private_keys_sensitive_fields_and_session_metadata_before_persistence()
-> Result<()> {
    let f = Fixture::new()?;
    let private_key = crate::test_util::SYNTHETIC_PRIVATE_KEY_BLOCK;
    let mut proposals = vec![f.proposal(private_key)];
    let mut sensitive = f.proposal("ordinary");
    sensitive.value = rmpv::Value::Map(vec![(
        "password".into(),
        "synthetic-sensitive-value".into(),
    )]);
    proposals.push(sensitive);
    for proposal in &proposals {
        let error = f
            .vault
            .submit_local_claim_refinement(
                f.base,
                f.resident,
                "session:claim-refine",
                proposal,
                at(5),
                5,
            )
            .expect_err("scan before staging");
        assert!(matches!(
            error,
            crate::Error::Gate(crate::error::GateError::GateWriteRejected { .. })
        ));
    }
    let mut metadata = f.proposal("ordinary");
    metadata.session_tag = Some(private_key.to_owned());
    assert!(
        f.vault
            .submit_local_claim_refinement(f.base, f.resident, private_key, &metadata, at(5), 5)
            .is_err()
    );
    let txn = f.vault.store.env.read_txn()?;
    assert!(
        f.vault
            .store
            .vault_meta
            .prefix_iter(&txn, b"skill_hub/refinement-control/v1\0")?
            .next()
            .is_none(),
        "no recoverable branch body entered vault_meta"
    );
    Ok(())
}

#[test]
fn explicit_delete_erases_pending_rejected_and_admitted_claim_branch_bytes_even_after_reopen()
-> Result<()> {
    for state in ["pending", "rejected"] {
        let f = Fixture::new()?;
        let candidate = f.submit("unique-branch-payload")?;
        if state == "rejected" {
            let ask = f.vault.prepare_claim_refinement_merge(
                candidate,
                f.resident,
                question(candidate),
            )?;
            f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
            assert!(
                matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(false), &NoReplay, 8)?,
                ClaimRefinementMergeDisposition::Ruled(receipt) if !receipt.accepted)
            );
        }
        assert!(
            f.vault
                .delete_entity_with_reason(
                    &candidate,
                    crate::deletion::DeleteReason::UserHardDelete,
                )?
                .existed,
            "{state} must count as real delete scope"
        );
        assert!(f.vault.local_claim_refinement(candidate)?.is_none());
        assert!(f.vault.claim_refinement_merge_receipt(candidate)?.is_none());
        let Fixture {
            vault, _dir: dir, ..
        } = f;
        drop(vault);
        let reopened = Vault::open(dir.path(), VaultConfig::default())?;
        assert!(reopened.local_claim_refinement(candidate)?.is_none());
        assert!(
            reopened
                .claim_refinement_merge_receipt(candidate)?
                .is_none()
        );
    }
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    assert!(
        matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(true), &Replay, 8)?,
        ClaimRefinementMergeDisposition::Ruled(receipt) if receipt.accepted)
    );
    assert!(f.vault.local_claim_refinement(candidate)?.is_some());
    assert!(
        f.vault
            .delete_entity_with_reason(&candidate, crate::deletion::DeleteReason::UserHardDelete,)?
            .existed
    );
    assert!(f.vault.local_claim_refinement(candidate)?.is_none());
    assert!(f.vault.claim_refinement_merge_receipt(candidate)?.is_none());
    assert!(f.vault.get_claim(&candidate)?.is_none());
    let Fixture {
        vault, _dir: dir, ..
    } = f;
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert!(reopened.local_claim_refinement(candidate)?.is_none());
    assert!(
        reopened
            .claim_refinement_merge_receipt(candidate)?
            .is_none()
    );
    assert!(reopened.get_claim(&candidate)?.is_none());
    Ok(())
}

#[test]
fn replayed_delete_erases_admitted_claim_branch_copy_after_reopen() -> Result<()> {
    for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
        let f = Fixture::new()?;
        let candidate = f.submit("improved")?;
        let ask =
            f.vault
                .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
        f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
        assert!(
            matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(true), &Replay, 8)?,
            ClaimRefinementMergeDisposition::Ruled(receipt) if receipt.accepted)
        );
        let tombstone = TombstoneValueV2 {
            reason,
            deleted_at: 9,
            request_id: *EntityId::now().as_bytes(),
        }
        .encode();
        let outcome = f.vault.apply_replayed_tombstone(&candidate, &tombstone)?;
        assert!(matches!(
            outcome,
            ReplayedTombstoneOutcome::SoftErased { changed: true }
                | ReplayedTombstoneOutcome::HardPurged { erased: true, .. }
        ));
        assert!(f.vault.local_claim_refinement(candidate)?.is_none());
        assert!(f.vault.claim_refinement_merge_receipt(candidate)?.is_none());
        let Fixture {
            vault, _dir: dir, ..
        } = f;
        drop(vault);
        let reopened = Vault::open(dir.path(), VaultConfig::default())?;
        assert!(reopened.local_claim_refinement(candidate)?.is_none());
        assert!(
            reopened
                .claim_refinement_merge_receipt(candidate)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn replayed_soft_and_hard_delete_erase_headerless_claim_refinement() -> Result<()> {
    for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
        for rejected in [false, true] {
            let f = Fixture::new()?;
            let candidate = f.submit("branch-replay-payload")?;
            if rejected {
                let ask = f.vault.prepare_claim_refinement_merge(
                    candidate,
                    f.resident,
                    question(candidate),
                )?;
                f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
                f.vault
                    .merge_local_claim_refinement(&ask, &Useful(false), &NoReplay, 8)?;
            }
            let tombstone = TombstoneValueV2 {
                reason,
                deleted_at: 9,
                request_id: *EntityId::now().as_bytes(),
            }
            .encode();
            let outcome = f.vault.apply_replayed_tombstone(&candidate, &tombstone)?;
            assert!(matches!(
                outcome,
                ReplayedTombstoneOutcome::SoftErased { changed: true }
                    | ReplayedTombstoneOutcome::HardPurged { erased: true, .. }
            ));
            assert!(f.vault.local_claim_refinement(candidate)?.is_none());
            assert!(f.vault.claim_refinement_merge_receipt(candidate)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn raw_batch_delete_keeps_content_free_guard_against_same_id_claim_reput() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    let ask = f
        .vault
        .prepare_claim_refinement_merge(candidate, f.resident, question(candidate))?;
    f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
    assert!(
        matches!(f.vault.merge_local_claim_refinement(&ask, &Useful(false), &NoReplay, 8)?,
        ClaimRefinementMergeDisposition::Ruled(receipt) if !receipt.accepted)
    );
    let mut attempted = f
        .vault
        .local_claim_refinement(candidate)?
        .unwrap()
        .claim_body()?;
    attempted.approval = ClaimApprovalStatus::Approved;
    attempted.session_tag = None;
    f.vault.batch().delete(&candidate).commit()?;
    assert!(f.vault.local_claim_refinement(candidate)?.is_none());
    assert!(f.vault.claim_refinement_merge_receipt(candidate)?.is_none());
    assert!(f.vault.put_claim(&candidate, &attempted, at(9), 9).is_err());
    assert!(
        f.vault
            .batch()
            .put_replicated(
                &candidate,
                crate::registry::ENTITY_TYPE_CLAIM,
                at(9),
                9,
                &encode_claim_body(&attempted)?
            )
            .commit()
            .is_err()
    );
    assert!(f.vault.get_claim(&candidate)?.is_none());
    Ok(())
}

#[test]
fn native_claim_erase_matrix_keeps_the_id_fenced_after_reopen() -> Result<()> {
    for state in ["pending", "refused", "admitted"] {
        for mode in ["raw", "local", "replayed"] {
            let f = Fixture::new()?;
            let candidate = f.submit("improved")?;
            if state != "pending" {
                let ask = f.vault.prepare_claim_refinement_merge(
                    candidate,
                    f.resident,
                    question(candidate),
                )?;
                f.vault.approve_claim_refinement_merge(&ask, &f.owner)?;
                let scorer: &dyn HeldOutClaimReplayScorer = if state == "admitted" {
                    &Replay
                } else {
                    &NoReplay
                };
                f.vault.merge_local_claim_refinement(
                    &ask,
                    &Useful(state == "admitted"),
                    scorer,
                    8,
                )?;
            }
            let mut attempted = f
                .vault
                .get_claim(&candidate)?
                .expect("native claim before deletion");
            attempted.approval = ClaimApprovalStatus::Approved;
            attempted.session_tag = None;
            match mode {
                "raw" => {
                    f.vault.batch().delete(&candidate).commit()?;
                }
                "local" => {
                    assert!(f.vault.delete_entity(&candidate)?);
                }
                _ => {
                    let tombstone = TombstoneValueV2 {
                        reason: TombstoneReason::GdprDelete,
                        deleted_at: 10,
                        request_id: *EntityId::now().as_bytes(),
                    }
                    .encode();
                    f.vault.apply_replayed_tombstone(&candidate, &tombstone)?;
                }
            }
            assert!(
                f.vault.local_claim_refinement(candidate)?.is_none(),
                "{state}/{mode}"
            );
            assert!(
                f.vault.claim_refinement_merge_receipt(candidate)?.is_none(),
                "{state}/{mode}"
            );
            let Fixture {
                vault, _dir: dir, ..
            } = f;
            drop(vault);
            let reopened = Vault::open(dir.path(), VaultConfig::default())?;
            assert!(reopened.local_claim_refinement(candidate)?.is_none());
            assert!(
                reopened
                    .claim_refinement_merge_receipt(candidate)?
                    .is_none()
            );
            assert!(
                reopened
                    .batch()
                    .put_replicated(
                        &candidate,
                        crate::registry::ENTITY_TYPE_CLAIM,
                        at(11),
                        11,
                        &encode_claim_body(&attempted)?
                    )
                    .commit()
                    .is_err(),
                "{state}/{mode}: erased id must stay fenced"
            );
        }
    }
    Ok(())
}

#[test]
fn replicated_refinement_origin_without_control_cannot_publish_approved_claim() -> Result<()> {
    let f = Fixture::new()?;
    let proposed = f.submit("improved")?;
    let mut forged = f
        .vault
        .get_claim(&proposed)?
        .expect("native proposed claim");
    forged.approval = ClaimApprovalStatus::Approved;
    let unrelated_id = EntityId::now();
    assert!(
        f.vault
            .batch()
            .put_replicated(
                &unrelated_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at(10),
                10,
                &encode_claim_body(&forged)?
            )
            .commit()
            .is_err()
    );
    assert!(f.vault.get_claim(&unrelated_id)?.is_none());
    assert_eq!(
        f.vault.get_claim(&proposed)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[test]
fn native_proposed_refinement_is_absent_from_canonical_context_pack() -> Result<()> {
    let f = Fixture::new()?;
    let candidate = f.submit("improved")?;
    assert_eq!(
        f.vault.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    // Force a matching lexical index entry so absence is the admission gate,
    // not merely missing retrieval data for the staged native claim.
    f.vault
        .batch()
        .text(&candidate, &[("body", "unique-refinement-proposal-term")])
        .commit()?;
    let pack = f
        .vault
        .context_pack()
        .search_text("unique-refinement-proposal-term", 10)
        .run()?;
    assert!(!pack.results.iter().any(|result| result.id == candidate));
    Ok(())
}

fn replay_claim_refinement_entity(
    vault: &Vault,
    id: EntityId,
    body: &ClaimBody,
    stamp: u64,
) -> Result<()> {
    let data = encode_claim_body(body)?;
    #[cfg(feature = "sync")]
    {
        crate::sync::replay::replay_entity(
            vault,
            crate::sync::replay::ReplicatedEntity {
                id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred: at(stamp),
                learned_at: stamp,
                body: &data,
            },
            crate::sync::client::ImportTier::OwnDevice,
        )
    }
    #[cfg(not(feature = "sync"))]
    {
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at(stamp),
                stamp,
                &data,
            )
            .commit()
    }
}

#[test]
fn proposed_replay_pins_origin_across_stripped_overwrite_and_raw_delete() -> Result<()> {
    let source = Fixture::new()?;
    let candidate = source.submit("improved")?;
    let native_proposed = source
        .vault
        .get_claim(&candidate)?
        .expect("native proposal");
    let dir = tempfile::tempdir()?;
    let receiver = Vault::open(dir.path(), VaultConfig::default())?;
    receiver.put_entity(
        &source.subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"same subject on receiving device",
    )?;
    replay_claim_refinement_entity(&receiver, candidate, &native_proposed, 5)?;
    assert_eq!(
        receiver.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(
        receiver.local_claim_refinement(candidate)?.is_none(),
        "a received proposal has no local submission control row"
    );
    let mut stripped = native_proposed;
    stripped.approval = ClaimApprovalStatus::Approved;
    stripped.evidence = None;
    stripped.session_tag = None;
    let refusal = replay_claim_refinement_entity(&receiver, candidate, &stripped, 6)
        .expect_err("stored origin must win over stripped incoming evidence");
    assert_eq!(
        refusal.kind(),
        crate::error::ErrorKind::InvalidSkillBody,
        "{refusal:?}"
    );
    assert_eq!(
        receiver.get_claim(&candidate)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    receiver.batch().delete(&candidate).commit()?;
    assert!(receiver.get_claim(&candidate)?.is_none());
    let refusal = replay_claim_refinement_entity(&receiver, candidate, &stripped, 7)
        .expect_err("raw deletion cannot free a refinement id");
    assert_eq!(
        refusal.kind(),
        crate::error::ErrorKind::InvalidSkillBody,
        "{refusal:?}"
    );
    assert!(receiver.get_claim(&candidate)?.is_none());
    Ok(())
}
