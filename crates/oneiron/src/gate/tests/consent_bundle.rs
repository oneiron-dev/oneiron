//! Gate consent bundles: aggregate, review, approve and decline, and rollback.

use super::*;
use crate::error::GateError;

/// Parks one Dreamer-authored proposal on `run_id`'s consent lane.
pub(super) fn park_consent_bundle_member(
    vault: &crate::Vault,
    claim_id: EntityId,
    actor: EntityId,
    subject_seed: u8,
    run_id: &str,
    value: &'static str,
    learned_at: u64,
) -> Result<()> {
    let mut body = source_trust_claim(ClaimSource::Generated);
    body.subject = ClaimSubject::Entity(test_id(subject_seed));
    body.value = Value::from(value);
    body.approval = ClaimApprovalStatus::Proposed;
    // Dreamer-authored bodies satisfy the evidence floor with their own seeded
    // subject entity.
    body.evidence = Some(precommit_evidence(vec![test_id(subject_seed)]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(vault, &body, actor, run_id)?;
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            test_time(learned_at),
            learned_at,
        )
        .commit()?;
    // Members sort by their parked decision id, which is time-ordered: the
    // pause keeps the fixture's parking order stable.
    std::thread::sleep(Duration::from_millis(2));
    Ok(())
}

pub(super) fn consent_bundle_owner(
    vault: &crate::Vault,
    owner_id: EntityId,
) -> Result<crate::consent::AuthenticatedOwner> {
    vault.put_entity(
        &owner_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"consent bundle owner",
    )?;
    vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
}

/// Every ledger row that represents a bundle ACTION (never a member).
pub(super) fn consent_bundle_receipts(vault: &crate::Vault) -> Result<Vec<GateDecisionRecord>> {
    Ok(vault
        .store
        .gate_decisions(64)?
        .into_iter()
        .filter(|record| record.content_kind == GATE_BUNDLE_CONTENT_KIND)
        .collect())
}

#[test]
fn gate_consent_bundle_aggregates_one_run_into_one_named_unit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-run-a";
    let other_run = "consent-bundle-run-b";
    let first = test_id(0x30);
    let second = test_id(0x31);
    let outsider = test_id(0x32);
    park_consent_bundle_member(&vault, first, test_id(0x40), 0x50, run, "first", 3)?;
    park_consent_bundle_member(&vault, second, test_id(0x40), 0x51, run, "second", 3)?;
    park_consent_bundle_member(
        &vault,
        outsider,
        test_id(0x41),
        0x52,
        other_run,
        "outsider",
        3,
    )?;

    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;

    assert_eq!(bundle.schema_version, GATE_CONSENT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(bundle.dreamer_run_id, run);
    let member_ids: Vec<EntityId> = bundle
        .members
        .iter()
        .map(|member| member.claim_id)
        .collect();
    assert_eq!(
        member_ids,
        vec![first, second],
        "membership is every still-pending row of THIS run, and no other run's"
    );

    // Review preserves the consent bindings of each parked member.
    let rtxn = vault.store.env.read_txn()?;
    for member in &bundle.members {
        let parked = vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &member.claim_id)?
            .expect("member is parked");
        assert_eq!(member.decision_id, parked.decision_id);
        assert_eq!(member.diff_handle, parked.diff_handle);
        assert_eq!(member.read_frontier_hash, parked.read_frontier_hash);
        assert_eq!(member.reason_codes, parked.reason_codes);
    }
    drop(rtxn);

    // No root agent is dispatched in this fixture; display formatting is not identity.
    assert_eq!(bundle.agent_label, None);
    assert!(!bundle.name.is_empty());

    // Repeated review preserves stable identity and consent-relevant contents.
    let reviewed = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(reviewed.bundle_id, bundle.bundle_id);
    assert_eq!(reviewed.schema_version, GATE_CONSENT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(reviewed.dreamer_run_id, run);
    assert_eq!(reviewed.members.len(), bundle.members.len());
    for (member, previous) in reviewed.members.iter().zip(&bundle.members) {
        assert_eq!(member.claim_id, previous.claim_id);
        assert_eq!(member.decision_id, previous.decision_id);
        assert_eq!(member.diff_handle, previous.diff_handle);
        assert_eq!(member.read_frontier_hash, previous.read_frontier_hash);
        assert_eq!(member.reason_codes, previous.reason_codes);
    }

    // Neither this run's proposals nor the isolated outsider are consumed by review.
    for id in [first, second, outsider] {
        assert!(has_pending_gate_consent(&vault, &id)?);
        assert_eq!(
            vault.get_claim(&id)?.expect("member claim").approval,
            ClaimApprovalStatus::Proposed
        );
    }
    Ok(())
}

#[test]
fn gate_consent_bundle_requires_a_named_run_with_open_members() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let actor = test_id(0x40);
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"dreamer actor",
    )?;
    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);

    assert!(matches!(
        vault.review_gate_consent_bundle(&reviewer, ""),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(matches!(
        vault.review_gate_consent_bundle(&reviewer, "consent-bundle-empty"),
        Err(Error::EntityNotFound)
    ));
    Ok(())
}

#[test]
fn gate_consent_bundle_review_is_content_bound_and_goes_stale() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-stale";
    let first = test_id(0x30);
    let second = test_id(0x31);
    park_consent_bundle_member(&vault, first, test_id(0x40), 0x50, run, "first", 3)?;

    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let reviewed = vault.review_gate_consent_bundle(&reviewer, run)?;

    // An edited member body re-parks the proposal, and the digest moves with
    // the bytes it binds.
    park_consent_bundle_member(&vault, first, test_id(0x40), 0x50, run, "first-edited", 5)?;
    let edited = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(edited.members.len(), 1);
    assert_ne!(edited.bundle_id, reviewed.bundle_id);

    // So does an added member.
    park_consent_bundle_member(&vault, second, test_id(0x40), 0x51, run, "second", 6)?;
    let widened = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(widened.members.len(), 2);
    assert_ne!(widened.bundle_id, edited.bundle_id);

    // The first review is now stale, and a stale review resolves nothing.
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    let err = vault
        .resolve_gate_consent_bundle(
            &owner,
            reviewed.bundle_id,
            run,
            GateConsentBundleAction::Approve,
            9,
        )
        .expect_err("a stale review must not resolve");
    assert!(matches!(
        err,
        Error::Gate(GateError::GateConsentStale { .. })
    ));
    for id in [first, second] {
        assert!(has_pending_gate_consent(&vault, &id)?);
        assert_eq!(
            vault.get_claim(&id)?.expect("member claim").approval,
            ClaimApprovalStatus::Proposed
        );
    }
    assert!(consent_bundle_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn gate_consent_bundle_approve_applies_every_member_with_one_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-approve";
    let first = test_id(0x30);
    let second = test_id(0x31);
    park_consent_bundle_member(&vault, first, test_id(0x40), 0x50, run, "first", 3)?;
    park_consent_bundle_member(&vault, second, test_id(0x40), 0x51, run, "second", 3)?;

    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let owner_id = test_id(0x60);
    let owner = consent_bundle_owner(&vault, owner_id)?;

    let receipt = vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Approve,
        9,
    )?;

    assert_eq!(receipt.schema_version, GATE_CONSENT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(receipt.action, GateConsentBundleAction::Approve);
    assert_eq!(receipt.bundle_id, bundle.bundle_id);
    assert_eq!(receipt.dreamer_run_id, run);
    assert_eq!(receipt.member_claim_ids, vec![first, second]);
    assert_eq!(receipt.created_at, 9);

    for id in [first, second] {
        assert_eq!(
            vault.get_claim(&id)?.expect("member claim").approval,
            ClaimApprovalStatus::Approved
        );
        assert!(!has_pending_gate_consent(&vault, &id)?);
    }

    // Exactly ONE ledger row represents the unit, and it is an ordinary
    // gate-decision row queryable through the ordinary ledger.
    let bundle_rows = consent_bundle_receipts(&vault)?;
    assert_eq!(bundle_rows.len(), 1);
    let row = &bundle_rows[0];
    assert_eq!(row.decision_id, receipt.receipt_id);
    assert_eq!(row.outcome, GATE_BUNDLE_OUTCOME_APPROVED);
    assert_eq!(row.reason_codes, vec![GATE_BUNDLE_REASON_APPROVED]);
    assert_eq!(row.claim_id, None);
    assert_eq!(row.diff_handle, bundle.bundle_id.to_vec());
    assert_eq!(row.actor_class, "human");
    assert_eq!(row.actor_ref, Some(owner_id.to_hex()));
    assert_eq!(row.created_at, 9);

    // Per-claim history survives beside it: one resolution receipt per member.
    let member_rows: Vec<GateDecisionRecord> = vault
        .store
        .gate_decisions(64)?
        .into_iter()
        .filter(|record| record.claim_id.is_some() && record.outcome == "approved")
        .collect();
    assert_eq!(member_rows.len(), 2);
    for member_row in &member_rows {
        assert_eq!(member_row.reason_codes, vec![GATE_BUNDLE_REASON_APPROVED]);
        assert_eq!(member_row.content_kind, "claim");
    }

    // The run is empty afterwards; there is nothing left to review.
    assert!(matches!(
        vault.review_gate_consent_bundle(&reviewer, run),
        Err(Error::EntityNotFound)
    ));
    Ok(())
}

#[test]
fn gate_consent_bundle_decline_closes_every_member_with_one_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-decline";
    let first = test_id(0x30);
    let second = test_id(0x31);
    park_consent_bundle_member(&vault, first, test_id(0x40), 0x50, run, "first", 3)?;
    park_consent_bundle_member(&vault, second, test_id(0x40), 0x51, run, "second", 3)?;

    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;

    let receipt = vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Decline,
        9,
    )?;
    assert_eq!(receipt.action, GateConsentBundleAction::Decline);
    assert_eq!(receipt.member_claim_ids, vec![first, second]);

    for id in [first, second] {
        let claim = vault.get_claim(&id)?.expect("member claim");
        assert_eq!(claim.approval, ClaimApprovalStatus::Rejected);
        assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Retracted);
        assert_eq!(claim.valid_to, Some(9));
        assert!(
            !has_pending_gate_consent(&vault, &id)?,
            "no member stays pending after a successful decline"
        );
    }

    let bundle_rows = consent_bundle_receipts(&vault)?;
    assert_eq!(bundle_rows.len(), 1);
    assert_eq!(bundle_rows[0].decision_id, receipt.receipt_id);
    assert_eq!(bundle_rows[0].outcome, GATE_BUNDLE_OUTCOME_DECLINED);
    assert_eq!(
        bundle_rows[0].reason_codes,
        vec![GATE_BUNDLE_REASON_DECLINED]
    );
    assert_eq!(bundle_rows[0].claim_id, None);
    assert_eq!(bundle_rows[0].diff_handle, bundle.bundle_id.to_vec());
    Ok(())
}

#[test]
fn gate_consent_bundle_rolls_back_when_one_member_is_stale() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-rollback";
    let good = test_id(0x30);
    let bad = test_id(0x31);
    park_consent_bundle_member(&vault, good, test_id(0x40), 0x50, run, "good", 3)?;
    park_consent_bundle_member(&vault, bad, test_id(0x40), 0x51, run, "bad", 3)?;

    // The LATER member's parked binding no longer answers to its own body, so
    // the unit fails after the earlier member has already passed the gate and
    // had its tray row closed inside the same transaction.
    vault.with_write_txn(|wtxn| {
        let mut pending = vault
            .store
            .pending_gate_consent_in_txn(wtxn, &bad)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))?;
        pending.diff_handle = vec![0xFF];
        vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
    })?;

    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(bundle.members.len(), 2);
    assert_eq!(bundle.members[0].claim_id, good);
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    let metric_emissions_before = gate_metric_emission_count_for_test();

    let err = vault
        .resolve_gate_consent_bundle(
            &owner,
            bundle.bundle_id,
            run,
            GateConsentBundleAction::Approve,
            9,
        )
        .expect_err("one bad member must abort the whole bundle");
    assert!(
        matches!(err, Error::Gate(GateError::GateConsentStale { claim_id }) if claim_id == bad)
    );

    for id in [good, bad] {
        assert_eq!(
            vault.get_claim(&id)?.expect("member claim").approval,
            ClaimApprovalStatus::Proposed,
            "no member commits when any member fails"
        );
        assert!(has_pending_gate_consent(&vault, &id)?);
    }
    assert!(consent_bundle_receipts(&vault)?.is_empty());
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before,
        "a rolled-back bundle emits no gate metrics"
    );
    Ok(())
}

#[test]
fn gate_consent_bundle_resolution_is_owner_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "consent-bundle-owner-only";
    let claim = test_id(0x30);
    let agent = test_id(0x40);
    park_consent_bundle_member(&vault, claim, agent, 0x50, run, "proposal", 3)?;

    // The proposing agent can REVIEW its own run...
    let reviewer = WriteActor::new(agent, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(bundle.members.len(), 1);

    // ...but `resolve_gate_consent_bundle` takes an `AuthenticatedOwner`, and
    // `Vault::authenticate_owner` is its only constructor. A non-human actor
    // and an unauthenticated principal both fail there, so an agent has no
    // route to approve or decline what it proposed.
    let machine = test_id(0x71);
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        test_time(1),
        1,
        b"agent host",
    )?;
    assert!(matches!(
        vault.authenticate_owner(machine, &machine.to_hex(), true, GateDecisionId::now()),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    let owner_id = test_id(0x60);
    vault.put_entity(&owner_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    assert!(matches!(
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), false, GateDecisionId::now()),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));

    // Nothing resolved: the proposal is still parked and still proposed.
    assert!(has_pending_gate_consent(&vault, &claim)?);
    assert_eq!(
        vault.get_claim(&claim)?.expect("member claim").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(consent_bundle_receipts(&vault)?.is_empty());

    // The authenticated owner does resolve it.
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Approve,
        9,
    )?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("member claim").approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(consent_bundle_receipts(&vault)?.len(), 1);
    Ok(())
}
