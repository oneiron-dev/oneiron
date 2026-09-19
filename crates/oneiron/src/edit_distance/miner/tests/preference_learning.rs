use super::*;
use crate::claim::{ClaimLifecycleStatus, ScopedReadActorKey};
use crate::inbox::InboxBulkVerb;
use crate::skill_optimize::{
    SkillOptimizeCandidate, optimize_brief, optimize_brief_for_principal_at,
};

const YEAR: u64 = 365 * 86_400;

fn proposal(
    vault: &Vault,
    run: &MinerRun,
    subject: EntityId,
    text: &str,
    at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    let envelope = miner_envelope(run, &[0; 32])?;
    let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![subject],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    );
    let candidate = ClaimCandidate::new(
        "profile.salutation",
        ClaimSubject::Entity(subject),
        Value::from(text),
        0.9,
    )
    .with_evidence(evidence)
    .with_scope(edit_cost_scope("correspondence"));
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .claim_candidate(&id, candidate, &envelope, t(at), at)
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

#[test]
fn untouched_approvals_are_proposed_wins_not_skill_credit() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let owner = fixture_owner(&vault);
    let run = miner_run(&vault);
    let subject = put_actor(&vault);
    let mut receipts = Vec::new();
    for index in 0..3 {
        proposal(&vault, &run, subject, "cheers", 100 + index)?;
        let decision = vault.resolve_inbox_group_as_at(
            owner,
            &run.run_id,
            InboxBulkVerb::AcceptAll,
            &CompilationTarget::Fallback,
            200 + index,
        )?;
        receipts.extend(
            decision
                .item_receipts
                .into_iter()
                .map(|receipt| receipt.receipt_id),
        );
        let outcomes = super::super::run_substitution_miner_at(&vault, &run, 300)?;
        if index < 2 {
            assert!(
                !outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, MinedOutcome::UntouchedApprovalWin(_)))
            );
        } else {
            let [MinedOutcome::UntouchedApprovalWin(id)] = outcomes.as_slice() else {
                panic!("expected one untouched win, got {outcomes:?}");
            };
            let body = vault.get_claim(id)?.expect("win claim");
            assert_eq!(body.predicate, "preference.affirmed");
            assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
            assert_eq!(
                crate::claim::claim_principal_id(&body)?,
                Some(owner.entity_ref())
            );
            assert_eq!(body.subject, ClaimSubject::Entity(run.agent.entity_ref()));
            let cited = evidence_key(candidate_evidence(&body), MINED_EVIDENCE_RECEIPTS_KEY)
                .as_array()
                .expect("receipt array");
            assert_eq!(cited.len(), 3);
            for receipt in &receipts {
                assert!(cited.contains(&Value::from(receipt.as_str())));
            }
        }
    }
    assert!(super::super::run_substitution_miner_at(&vault, &run, 301)?.is_empty());
    assert!(pending_substitution_skill_edits(&vault)?.is_empty());
    Ok(())
}

#[test]
fn explicit_targets_route_rejections_without_inventing_language_rules() -> Result<()> {
    for (target, predicate) in [
        (
            CompilationTarget::Ban("no salutations".into()),
            "preference.ban",
        ),
        (
            CompilationTarget::StyleRule("terse".into()),
            "preference.style_rule",
        ),
        (
            CompilationTarget::CharterLine("cite primary sources".into()),
            "charter.line",
        ),
        (
            CompilationTarget::BriefUpdate("include the deadline".into()),
            "brief.preference",
        ),
    ] {
        let (_dir, vault) = temp_vault();
        let owner = fixture_owner(&vault);
        let run = miner_run(&vault);
        let subject = put_actor(&vault);
        set_miner_k(&vault, 2)?;
        for index in 0..2 {
            proposal(&vault, &run, subject, "regards", 100 + index)?;
            vault.resolve_inbox_group_as_at(
                owner,
                &run.run_id,
                InboxBulkVerb::RejectAll,
                &target,
                200 + index,
            )?;
        }
        let outcomes = super::super::run_substitution_miner_at(&vault, &run, 300)?;
        let [MinedOutcome::PreferenceClaim(id)] = outcomes.as_slice() else {
            panic!("expected explicit compilation, got {outcomes:?}");
        };
        let body = vault.get_claim(id)?.expect("compiled proposal");
        assert_eq!(body.predicate, predicate);
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(value_field(&body, "text").as_deref(), target.text());
        assert_eq!(
            crate::claim::claim_principal_id(&body)?,
            Some(owner.entity_ref())
        );
        assert_eq!(
            vault
                .expression_preferences(&owner.entity_ref(), 300)?
                .style,
            None
        );
        assert!(super::super::run_substitution_miner_at(&vault, &run, 301)?.is_empty());
    }
    Ok(())
}

#[test]
fn inbox_fallback_amendments_still_mine_lexical_phrasing() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let owner = fixture_owner(&vault);
    let run = miner_run(&vault);
    let subject = put_actor(&vault);
    for index in 0..3 {
        let id = proposal(&vault, &run, subject, "regards", 100 + index)?;
        let mut changed = vault.get_claim(&id)?.expect("proposal");
        changed.value = Value::from("cheers");
        vault.approve_inbox_member_with_edit_as_at(
            owner,
            &id,
            &crate::claim::encode_claim_body(&changed)?,
            &CompilationTarget::Fallback,
            200 + index,
        )?;
    }
    let outcomes = super::super::run_substitution_miner_at(&vault, &run, 300)?;
    let [MinedOutcome::PreferenceClaim(id)] = outcomes.as_slice() else {
        panic!("{outcomes:?}");
    };
    let body = vault.get_claim(id)?.expect("phrasing proposal");
    assert_eq!(body.predicate, PREDICATE_PREFERENCE_PHRASING);
    assert_eq!(
        value_field(&body, PREFERENCE_VALUE_KEY_FROM).as_deref(),
        Some("regards")
    );
    assert_eq!(
        value_field(&body, PREFERENCE_VALUE_KEY_TO).as_deref(),
        Some("cheers")
    );
    Ok(())
}

#[test]
fn legacy_evidence_and_other_principals_do_not_cross_the_miner_threshold() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    let a = fixture_owner(&vault);
    let b = WriteActor::new(put_actor(&vault), EdgeActorClass::Human);
    for (i, principal) in [Some(a), Some(a), Some(b), None, None, None]
        .into_iter()
        .enumerate()
    {
        sign_off(
            &format!("gate:isolated-{i}"),
            "isolated",
            actor,
            i,
            100 + i as u64,
        )
        .land_bound(&vault, principal)?;
    }
    assert!(emitted(&super::super::run_substitution_miner_at(&vault, &run, 300)?).is_empty());
    sign_off("gate:isolated-last", "isolated", actor, 9, 200).land_bound(&vault, Some(a))?;
    let outcomes = emitted(&super::super::run_substitution_miner_at(&vault, &run, 300)?);
    let [MinedOutcome::PreferenceClaim(id)] = outcomes.as_slice() else {
        panic!("{outcomes:?}");
    };
    let body = vault.get_claim(id)?.expect("A preference");
    assert_eq!(
        crate::claim::claim_principal_id(&body)?,
        Some(a.entity_ref())
    );
    // A different owner cannot approve A's mined preference.
    assert!(
        vault
            .resolve_inbox_group_as_at(
                b,
                &run.run_id,
                InboxBulkVerb::AcceptAll,
                &CompilationTarget::Fallback,
                301
            )
            .is_err()
    );
    // Consent still uses the normal content-bound inbox door.
    vault.resolve_inbox_group_as_at(
        a,
        &run.run_id,
        InboxBulkVerb::AcceptAll,
        &CompilationTarget::Fallback,
        301,
    )?;
    assert_eq!(
        mined_preferences_for_principal(&vault, &a.entity_ref(), 302)?.len(),
        1
    );
    assert!(mined_preferences_for_principal(&vault, &b.entity_ref(), 302)?.is_empty());
    assert!(mined_preferences_for_principal(&vault, &a.entity_ref(), 302 + YEAR * 2)?.is_empty());
    assert!(
        vault.get_claim(id)?.is_some(),
        "decay never deletes history"
    );
    let other = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(b.entity_ref().to_hex(), "human").expect("key"),
    );
    assert!(other.get_entity_parts(id)?.is_none());
    Ok(())
}

#[test]
fn optimizer_reads_only_live_dev_substitutions_for_its_explicit_principal() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let owner = fixture_owner(&vault);
    let other = WriteActor::new(put_actor(&vault), EdgeActorClass::Human);
    let run = miner_run(&vault);
    let skill = put_skill(&vault);
    let mut index = 0;
    let mut admitted = 0;
    while admitted < 3 {
        let receipt = format!("gate:principal-dev-{index}");
        index += 1;
        if crate::skill_optimize::receipt_is_held_out(&skill, &receipt) {
            continue;
        }
        reschedule(
            &receipt,
            "schedule",
            actor,
            Some(skill),
            index,
            100 + admitted,
        )
        .land_bound(&vault, Some(owner))?;
        admitted += 1;
    }
    super::super::run_substitution_miner_at(&vault, &run, 300)?;
    let posterior = crate::skill_reliability::skill_reliability_prior(&vault, &skill)?;
    let candidate = SkillOptimizeCandidate {
        skill,
        posterior,
        prior: posterior,
        attributed_outcomes: 0,
    };
    assert!(
        optimize_brief(&vault, &candidate)?
            .substitution_proposals
            .is_empty()
    );
    let brief = optimize_brief_for_principal_at(&vault, &candidate, owner, 300)?;
    assert_eq!(brief.substitution_proposals.len(), 1);
    assert_eq!(brief.principal, Some(owner.entity_ref()));
    assert!(
        optimize_brief_for_principal_at(&vault, &candidate, other, 300)?
            .substitution_proposals
            .is_empty()
    );
    assert!(
        optimize_brief_for_principal_at(&vault, &candidate, owner, 300 + YEAR * 2)?
            .substitution_proposals
            .is_empty()
    );
    assert_eq!(
        pending_substitution_skill_edits(&vault)?.len(),
        1,
        "aged evidence remains auditable"
    );
    Ok(())
}

#[test]
fn owner_identity_and_scope_validation_fail_closed() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let run = miner_run(&vault);
    let subject = put_actor(&vault);
    let id = proposal(&vault, &run, subject, "regards", 100)?;
    assert!(
        vault
            .resolve_inbox_group_as_at(
                run.agent,
                &run.run_id,
                InboxBulkVerb::AcceptAll,
                &CompilationTarget::Fallback,
                200
            )
            .is_err()
    );
    assert_eq!(
        vault.get_claim(&id)?.expect("unchanged").approval,
        ClaimApprovalStatus::Proposed
    );
    let owner = fixture_owner(&vault);
    assert!(
        vault
            .resolve_inbox_group_as_at(
                owner,
                &run.run_id,
                InboxBulkVerb::AcceptAll,
                &CompilationTarget::StyleRule("Not a token".into()),
                200
            )
            .is_err()
    );
    let mut body = ClaimBody::new(
        "preference.ban",
        ClaimSubject::Entity(subject),
        Value::Map(vec![(Value::from("text"), Value::from("never guess"))]),
        0.5,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    for scope in [
        Value::Map(vec![(Value::from("principal"), Value::from("unknown"))]),
        Value::Map(vec![(Value::from("principal"), Value::Binary(vec![1; 15]))]),
        Value::Map(vec![
            (
                Value::from("principal"),
                Value::Binary(owner.entity_ref().as_bytes().to_vec()),
            ),
            (
                Value::from("principal"),
                Value::Binary(owner.entity_ref().as_bytes().to_vec()),
            ),
        ]),
    ] {
        body.scope = Some(scope);
        assert!(crate::claim::claim_principal_id(&body).is_err());
        assert!(
            vault
                .put_claim(&EntityId::now(), &body, t(200), 200)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn aged_corrections_do_not_mine_and_bindings_cannot_be_relabelled() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let owner = fixture_owner(&vault);
    let other = WriteActor::new(put_actor(&vault), EdgeActorClass::Human);
    let run = miner_run(&vault);
    for i in 0..3 {
        sign_off(
            &format!("gate:old-{i}"),
            "outbound",
            actor,
            i,
            100 + i as u64,
        )
        .land_bound(&vault, Some(owner))?;
    }
    assert!(
        bind_amendment_preference_principal(
            &vault,
            other,
            "gate:old-0",
            &CompilationTarget::Fallback
        )
        .is_err()
    );
    assert!(super::super::run_substitution_miner_at(&vault, &run, YEAR * 2)?.is_empty());
    assert!(preference_rows(&vault, &actor)?.is_empty());
    // Raw clusters still report the historical audit evidence.
    assert_eq!(mine_substitution_clusters(&vault)?.len(), 1);
    Ok(())
}
