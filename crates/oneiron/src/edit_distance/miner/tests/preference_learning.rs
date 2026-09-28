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

/// Each route starts with an actual corrected ED-00 text and ends as a
/// Proposed claim at the ordinary write gate. The caller binds a principal,
/// but supplies Fallback rather than the desired family or its text.
#[test]
fn measured_deltas_compile_four_reviewable_target_families() -> Result<()> {
    for (scope, before, after, target, predicate) in [
        (
            "outbound",
            "allow greetings",
            "never use salutations",
            CompilationTarget::Ban("never use salutations".into()),
            "preference.ban",
        ),
        (
            "expression.style:outbound",
            "formal",
            "terse",
            CompilationTarget::StyleRule("terse".into()),
            "preference.style_rule",
        ),
        (
            "charter:agent",
            "copy outdated policy",
            "cite primary sources",
            CompilationTarget::CharterLine("cite primary sources".into()),
            "charter.line",
        ),
        (
            "brief:campaign",
            "omit exact dates",
            "include the deadline",
            CompilationTarget::BriefUpdate("include the deadline".into()),
            "brief.preference",
        ),
    ] {
        let (_dir, vault) = temp_vault();
        let owner = fixture_owner(&vault);
        let run = miner_run(&vault);
        let actor = put_actor(&vault);
        set_miner_k(&vault, 2)?;
        for index in 0..2 {
            let amendment = Amendment {
                receipt_id: format!("gate:compiled-{index}"),
                scope: scope.into(),
                actor,
                skill: None,
                cause: AmendmentCause::DeciderPreference,
                proposed: before.into(),
                finalized: after.into(),
                at: 100 + index,
            };
            amendment.land(&vault)?;
        }
        let clusters = mine_substitution_clusters(&vault)?;
        let [cluster] = clusters.as_slice() else {
            panic!("one compiled cluster expected: {clusters:?}");
        };
        assert_eq!(cluster.target, target, "{scope}: evidence chose target");
        assert_eq!(cluster.principal, Some(owner.entity_ref()));
        let outcomes = super::super::run_substitution_miner_at(&vault, &run, 300)?;
        let [MinedOutcome::PreferenceClaim(id)] = outcomes.as_slice() else {
            panic!("{scope}: expected gated claim, got {outcomes:?}");
        };
        let body = vault.get_claim(id)?.expect("compiled claim");
        assert_eq!(body.predicate, predicate);
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(body.source, Some(ClaimSource::Generated));
        assert_eq!(body.subject, ClaimSubject::Entity(actor));
        assert_eq!(
            crate::claim::claim_principal_id(&body)?,
            Some(owner.entity_ref())
        );
        assert_eq!(value_field(&body, "text").as_deref(), target.text());
        let evidence = body.evidence.as_ref().expect("gate-stamped evidence");
        let provenance = evidence_key(
            evidence,
            crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
        );
        assert_eq!(
            evidence_key(provenance, PROVENANCE_KEY_RUN).as_str(),
            Some(run.run_id.as_str())
        );
        assert_eq!(
            evidence_key(provenance, PROVENANCE_KEY_SESSION).as_str(),
            Some(run.session.to_hex().as_str()),
        );
        let decoded =
            crate::dreamer_consolidation::decode_consolidation_evidence(candidate_evidence(&body))?
                .expect("gate candidate envelope");
        assert_eq!(decoded.source_meet, ClaimSource::Inferred);
        let record_id = mined_evidence_record_id(&cluster_handle(cluster))?;
        assert_eq!(decoded.refs, [record_id]);
        let record: StoredMinedEvidence = decode_row(
            &vault.get(&record_id)?.expect("resolved evidence record"),
            MINED_EVIDENCE_ROW_LABEL,
        )?;
        assert_eq!(record.target, target);
        assert_eq!(record.receipt_refs, cluster.receipt_refs);
        assert_eq!(record.count, 2);
        assert!(super::super::run_substitution_miner_at(&vault, &run, 301)?.is_empty());
        assert_eq!(
            vault
                .expression_preferences(&owner.entity_ref(), 302)?
                .style,
            None
        );
    }
    Ok(())
}

#[test]
fn ambiguous_and_unscoped_deltas_preserve_the_existing_chooser() {
    use super::super::policy::infer_target;
    let (_dir, vault) = temp_vault();
    let owner = fixture_owner(&vault);
    let txn = vault.store.env.read_txn().expect("read policy");
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn).expect("resolve policy");
    let policies = policy.compilation_policies.as_slice();
    let holder = owner.entity_ref();
    assert_eq!(
        infer_target(policies, holder, "outbound", "regards", "cheers"),
        CompilationTarget::Fallback
    );
    assert_eq!(
        infer_target(policies, holder, "outbound", "fri", "mon"),
        CompilationTarget::Fallback
    );
    assert_eq!(
        infer_target(policies, holder, "charter:", "old", "cite primary sources"),
        CompilationTarget::Fallback
    );
    assert_eq!(
        infer_target(
            policies,
            holder,
            "expression.style:outbound",
            "formal",
            "two words"
        ),
        CompilationTarget::Fallback
    );
    assert_eq!(
        infer_target(policies, holder, "outbound", "never guess", "never invent"),
        CompilationTarget::Fallback
    );
    assert_eq!(
        infer_target(
            policies,
            holder,
            "expression.style:outbound",
            "formal",
            "never use salutations"
        ),
        CompilationTarget::Fallback,
        "an invalid typed-scope correction cannot fall through into a ban"
    );
}

/// Edit only the trusted default policy entity so ordinary gate grants stay
/// intact. In production the owner installs the edited manifest through the
/// owner-authenticated authoring door.
fn compilation_manifest(vault: &Vault, change: impl FnOnce(&mut Value)) -> Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("shipped manifest decodes");
    change(&mut manifest);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &manifest).expect("manifest encodes");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &encoded,
    )
}

fn policy_key<'a>(map: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(entries) = map else {
        panic!("policy map")
    };
    entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .map_or_else(|| panic!("missing policy key {key}"), |(_, value)| value)
}

fn policy_rows(manifest: &mut Value) -> &mut Vec<Value> {
    let Value::Array(rows) = policy_key(policy_key(manifest, "compilation_policy"), "rows") else {
        panic!("compilation rows")
    };
    rows
}

fn route_family(route: &Value, family: &str) -> bool {
    let Value::Map(entries) = route else {
        return false;
    };
    entries
        .iter()
        .any(|(key, value)| key.as_str() == Some("family") && value.as_str() == Some(family))
}

fn policy_route(family: &str, enabled: bool) -> Value {
    Value::Map(vec![
        (Value::from("family"), Value::from(family)),
        (Value::from("enabled"), Value::Boolean(enabled)),
        (Value::from("scope_prefix"), Value::from("")),
        (Value::from("scope_not_prefixes"), Value::Array(Vec::new())),
        (Value::from("require_scope_suffix"), Value::Boolean(false)),
        (Value::from("to_prefix"), Value::from("")),
        (Value::from("from_not_prefix"), Value::from("")),
        (Value::from("style_atom"), Value::Boolean(false)),
    ])
}

#[test]
fn vault_policy_disables_bans_but_retains_skill_edit_fallback() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let run = miner_run(&vault);
    let actor = put_actor(&vault);
    let skill = put_skill(&vault);
    compilation_manifest(&vault, |manifest| {
        let rows = policy_rows(manifest);
        let Value::Array(routes) = policy_key(&mut rows[0], "routes") else {
            panic!("routes")
        };
        let ban = routes
            .iter_mut()
            .find(|route| route_family(route, "ban"))
            .expect("shipped ban");
        *policy_key(ban, "enabled") = Value::Boolean(false);
    })?;
    for index in 0..2 {
        Amendment {
            receipt_id: format!("gate:narrow-{index}"),
            scope: "outbound".into(),
            actor,
            skill: Some(skill),
            cause: AmendmentCause::DeciderPreference,
            proposed: "allow greetings".into(),
            finalized: "never use salutations".into(),
            at: 100 + index,
        }
        .land(&vault)?;
    }
    set_miner_k(&vault, 2)?;
    let outcomes = super::super::run_substitution_miner_at(&vault, &run, 300)?;
    assert!(matches!(
        outcomes.as_slice(),
        [MinedOutcome::SkillEditProposal(_)]
    ));
    assert_eq!(pending_substitution_skill_edits(&vault)?.len(), 1);
    assert!(vault.claims_for_subject(&actor)?.is_empty());
    Ok(())
}

#[test]
fn holder_cannot_widen_vault_or_parent_compilation_routes() -> Result<()> {
    use super::super::policy::infer_target;
    let (_dir, vault) = temp_vault();
    let child = fixture_owner(&vault).entity_ref();
    let parent = put_actor(&vault);
    compilation_manifest(&vault, |manifest| {
        let rows = policy_rows(manifest);
        let Value::Array(routes) = policy_key(&mut rows[0], "routes") else {
            panic!("routes")
        };
        for route in routes.iter_mut() {
            if route_family(route, "ban") {
                *policy_key(route, "enabled") = Value::Boolean(false);
            }
        }
        rows.push(Value::Map(vec![
            (Value::from("holder"), Value::from(parent.to_hex())),
            (
                Value::from("routes"),
                Value::Array(vec![policy_route("ban", false)]),
            ),
        ]));
        rows.push(Value::Map(vec![
            (Value::from("holder"), Value::from(child.to_hex())),
            (Value::from("parent"), Value::from(parent.to_hex())),
            (
                Value::from("routes"),
                Value::Array(vec![policy_route("ban", true)]),
            ),
        ]));
    })?;
    let txn = vault.store.env.read_txn()?;
    let resolved = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert!(!resolved.diagnostics.is_fail_closed());
    assert_eq!(
        infer_target(
            &resolved.compilation_policies,
            child,
            "outbound",
            "allow greetings",
            "never use salutations"
        ),
        CompilationTarget::Fallback,
    );
    // Restore the vault's ban permit: the parent's refusal still caps the child.
    drop(txn);
    compilation_manifest(&vault, |manifest| {
        let rows = policy_rows(manifest);
        let Value::Array(routes) = policy_key(&mut rows[0], "routes") else {
            panic!("routes")
        };
        for route in routes.iter_mut() {
            if route_family(route, "ban") {
                *policy_key(route, "enabled") = Value::Boolean(true);
            }
        }
        rows.push(Value::Map(vec![
            (Value::from("holder"), Value::from(parent.to_hex())),
            (
                Value::from("routes"),
                Value::Array(vec![policy_route("ban", false)]),
            ),
        ]));
        rows.push(Value::Map(vec![
            (Value::from("holder"), Value::from(child.to_hex())),
            (Value::from("parent"), Value::from(parent.to_hex())),
            (
                Value::from("routes"),
                Value::Array(vec![policy_route("ban", true)]),
            ),
        ]));
    })?;
    let txn = vault.store.env.read_txn()?;
    let resolved = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert!(!resolved.diagnostics.is_fail_closed());
    assert_eq!(
        infer_target(
            &resolved.compilation_policies,
            child,
            "outbound",
            "allow greetings",
            "never use salutations"
        ),
        CompilationTarget::Fallback,
    );
    assert_eq!(
        infer_target(
            &resolved.compilation_policies,
            parent,
            "outbound",
            "allow greetings",
            "never use salutations"
        ),
        CompilationTarget::Fallback,
    );
    Ok(())
}

#[test]
fn manifest_order_and_pattern_select_the_route() -> Result<()> {
    use super::super::policy::infer_target;
    let (_dir, vault) = temp_vault();
    let holder = fixture_owner(&vault).entity_ref();
    compilation_manifest(&vault, |manifest| {
        let rows = policy_rows(manifest);
        let Value::Array(routes) = policy_key(&mut rows[0], "routes") else {
            panic!("routes")
        };
        let ban = routes
            .iter_mut()
            .find(|route| route_family(route, "ban"))
            .expect("ban");
        *policy_key(ban, "to_prefix") = Value::from("terse");
        *policy_key(ban, "scope_not_prefixes") = Value::Array(Vec::new());
    })?;
    let read_route = |vault: &Vault| -> Result<CompilationTarget> {
        let txn = vault.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        Ok(infer_target(
            &policy.compilation_policies,
            holder,
            "expression.style:outbound",
            "formal",
            "terse",
        ))
    };
    assert_eq!(
        read_route(&vault)?,
        CompilationTarget::StyleRule("terse".into())
    );
    compilation_manifest(&vault, |manifest| {
        let policy = policy_key(manifest, "compilation_policy");
        *policy_key(policy, "order") = Value::Array(vec![
            Value::from("ban"),
            Value::from("style_rule"),
            Value::from("charter_line"),
            Value::from("brief_update"),
        ]);
        let rows = policy_rows(manifest);
        let Value::Array(routes) = policy_key(&mut rows[0], "routes") else {
            panic!("routes")
        };
        let ban = routes
            .iter_mut()
            .find(|route| route_family(route, "ban"))
            .expect("ban");
        *policy_key(ban, "to_prefix") = Value::from("terse");
        *policy_key(ban, "scope_not_prefixes") = Value::Array(Vec::new());
    })?;
    assert_eq!(read_route(&vault)?, CompilationTarget::Ban("terse".into()));
    Ok(())
}

#[test]
fn duplicate_holder_parent_is_not_silently_dropped() {
    use super::super::policy::CompilationPolicy;
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest = rmpv::decode::read_value(&mut bytes.as_slice()).expect("manifest");
    let rows = policy_rows(&mut manifest);
    rows.push(Value::Map(vec![
        (Value::from("holder"), Value::from(EntityId::now().to_hex())),
        (Value::from("parent"), Value::from(EntityId::now().to_hex())),
        (Value::from("parent"), Value::from(EntityId::now().to_hex())),
        (
            Value::from("routes"),
            Value::Array(vec![policy_route("ban", true)]),
        ),
    ]));
    assert!(CompilationPolicy::decode(policy_key(&mut manifest, "compilation_policy")).is_none());
}

#[test]
fn inbox_amendment_infers_ban_without_a_host_target() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let owner = fixture_owner(&vault);
    let run = miner_run(&vault);
    let actor = put_actor(&vault);
    set_miner_k(&vault, 2)?;
    for index in 0..2 {
        let id = proposal(&vault, &run, actor, "allow greetings", 100 + index)?;
        let mut changed = vault.get_claim(&id)?.expect("proposed claim");
        changed.value = Value::from("never use salutations");
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
        panic!("inbox delta did not compile into a reviewable claim: {outcomes:?}");
    };
    let body = vault.get_claim(id)?.expect("mined claim");
    assert_eq!(body.predicate, "preference.ban");
    assert_eq!(
        value_field(&body, "text").as_deref(),
        Some("never use salutations")
    );
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        crate::claim::claim_principal_id(&body)?,
        Some(owner.entity_ref())
    );
    assert_eq!(
        crate::dreamer_consolidation::decode_consolidation_evidence(candidate_evidence(&body))?
            .expect("gate evidence")
            .source_meet,
        ClaimSource::Inferred,
    );
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
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = other
        .read(&[crate::claim::PointRead::id(*id)], None)?
        .single();
    assert!(value.is_none());
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
