use super::*;

/// Done-means 6: identical input under the same id returns the prior outcome
/// and mints nothing.
#[test]
fn onboarding_replay_is_idempotent() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth);

    let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;
    let counts = [
        type_count(&vault, ENTITY_TYPE_AGENT_DEF),
        type_count(&vault, ENTITY_TYPE_PERSON),
        type_count(&vault, ENTITY_TYPE_FEDERATION_GRANT),
        type_count(&vault, ENTITY_TYPE_FACET),
        type_count(&vault, ENTITY_TYPE_ACCESS_GRANT),
        type_count(&vault, ENTITY_TYPE_CHANNEL_IDENTITY),
    ];

    let second = vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
    assert_eq!(first, second);
    assert_eq!(
        counts,
        [
            type_count(&vault, ENTITY_TYPE_AGENT_DEF),
            type_count(&vault, ENTITY_TYPE_PERSON),
            type_count(&vault, ENTITY_TYPE_FEDERATION_GRANT),
            type_count(&vault, ENTITY_TYPE_FACET),
            type_count(&vault, ENTITY_TYPE_ACCESS_GRANT),
            type_count(&vault, ENTITY_TYPE_CHANNEL_IDENTITY),
        ]
    );
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 2);
    Ok(())
}

/// Done-means 7: a run that dies after `ActorLinked` resumes and finishes with
/// exactly the entity population a single clean run produces.
#[test]
fn crash_resume_finishes_without_duplicates() -> Result<()> {
    let build = |venture_name: &str| {
        let (dir, vault, mut intent) = fixture(venture_name);
        let birth = companion_birth();
        intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
        intent.companion_birth = Some(birth);
        (dir, vault, intent)
    };
    let census = |vault: &Vault| {
        [
            type_count(vault, ENTITY_TYPE_AGENT_DEF),
            type_count(vault, ENTITY_TYPE_PERSON),
            type_count(vault, ENTITY_TYPE_FEDERATION_GRANT),
            type_count(vault, ENTITY_TYPE_FACET),
            type_count(vault, ENTITY_TYPE_ACCESS_GRANT),
            type_count(vault, ENTITY_TYPE_CHANNEL_IDENTITY),
        ]
    };

    let (_clean_dir, clean, clean_intent) = build("Antevon");
    let expected_outcome = clean.onboard_workspace_member(clean_intent, &writer(WRITER), None)?;
    let expected_census = census(&clean);

    let (_dir, vault, intent) = build("Antevon");
    let halted = vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        None,
        MemberOnboardingStep::ActorLinked,
    )?;
    assert!(halted.is_none(), "a halted run has no outcome yet");

    let journal = read_journal(&vault, &intent.onboarding_id)?
        .expect("halted run leaves a resumable journal");
    assert_eq!(journal.step, MemberOnboardingStep::ActorLinked);
    assert_eq!(journal.completed_at, None);

    let resumed = vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
    assert_eq!(resumed, expected_outcome);
    assert_eq!(census(&vault), expected_census);
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 2);
    Ok(())
}

/// Done-means 6: the same id with different inputs fails typed, and the prior
/// outcome survives the attempt intact.
#[test]
fn changed_input_same_id_fails_typed() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;

    let mut changed = intent.clone();
    changed.occurred_at = AT + 1;
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER), None)
        .expect_err("changed input under a used id must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut renamed = intent.clone();
    renamed.workspace.venture_name = "Somewhere Else".to_owned();
    let err = vault
        .onboard_workspace_member(renamed, &writer(WRITER), None)
        .expect_err("a changed venture name is changed input");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // The original replay still answers with the original outcome.
    assert_eq!(
        vault.onboard_workspace_member(intent, &writer(WRITER), None)?,
        first
    );
    Ok(())
}

#[test]
fn mailbox_replay_is_incomplete_without_duplicates_and_pins_starting_mode() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth);
    intent.delegated_mailbox = Some(requested.clone());
    register_mailbox_custody(&vault, &requested, &requested.address)?;
    let census = || {
        [
            ENTITY_TYPE_PERSON,
            ENTITY_TYPE_AGENT_DEF,
            ENTITY_TYPE_FEDERATION_GRANT,
            ENTITY_TYPE_FACET,
            ENTITY_TYPE_ACCESS_GRANT,
            ENTITY_TYPE_CHANNEL_IDENTITY,
            crate::registry::ENTITY_TYPE_CLAIM,
        ]
        .map(|kind| type_count(&vault, kind))
    };
    let first = vault
        .onboard_workspace_member(
            intent.clone(),
            &writer(WRITER),
            Some(&mailbox_owner(&vault)?),
        )
        .expect_err("request must be refused");
    assert_eq!(first.kind(), ErrorKind::WorkspaceMailboxAutonomyNotReady);
    let counts = census();
    let second = vault
        .onboard_workspace_member(
            intent.clone(),
            &writer(WRITER),
            Some(&mailbox_owner(&vault)?),
        )
        .expect_err("request must be refused");
    assert_eq!(second.kind(), first.kind());
    assert_eq!(census(), counts);
    let journal = read_journal(&vault, &intent.onboarding_id)?.expect("fixture value exists");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    // The unfinished companion is not published in the roster.
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 1);
    let mut changed = intent;
    changed
        .delegated_mailbox
        .as_mut()
        .expect("fixture value exists")
        .autonomy
        .read_envelope
        .not_after = Some(AT + 120);
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER), Some(&mailbox_owner(&vault)?))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(census(), counts);
    Ok(())
}

#[test]
fn every_completed_step_resumes_with_identical_stable_refs() -> Result<()> {
    for step in ONBOARDING_STEPS {
        let (_dir, vault, mut intent) = fixture("Antevon");
        let birth = companion_birth();
        intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
        intent.companion_birth = Some(birth);
        vault.onboard_workspace_member_halting_after(
            intent.clone(),
            &writer(WRITER),
            None,
            step,
        )?;
        let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;
        let counts = [
            ENTITY_TYPE_PERSON,
            ENTITY_TYPE_AGENT_DEF,
            ENTITY_TYPE_FEDERATION_GRANT,
            ENTITY_TYPE_FACET,
            ENTITY_TYPE_ACCESS_GRANT,
            crate::registry::ENTITY_TYPE_CLAIM,
        ]
        .map(|kind| type_count(&vault, kind));
        assert_eq!(
            vault.onboard_workspace_member(intent, &writer(WRITER), None)?,
            first
        );
        assert_eq!(
            counts,
            [
                ENTITY_TYPE_PERSON,
                ENTITY_TYPE_AGENT_DEF,
                ENTITY_TYPE_FEDERATION_GRANT,
                ENTITY_TYPE_FACET,
                ENTITY_TYPE_ACCESS_GRANT,
                crate::registry::ENTITY_TYPE_CLAIM
            ]
            .map(|kind| type_count(&vault, kind))
        );
    }
    Ok(())
}

/// CompanionBorn contains several commits; the journal advances only after
/// all of them. A retry must accept a PERSON whose baseline already landed.
#[test]
fn companion_birth_retries_after_baseline_commit_and_grant_failure() -> Result<()> {
    for fail_grant in [false, true] {
        let (_dir, vault, mut intent) = fixture("Antevon");
        let birth = companion_birth();
        intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
        intent.companion_birth = Some(birth.clone());
        let owner = writer(WRITER);
        vault.onboard_workspace_member_halting_after(
            intent.clone(),
            &owner,
            None,
            MemberOnboardingStep::ActorLinked,
        )?;
        let expected_grant = AccessGrant::companion_profile_read(
            intent.person_ref,
            intent.person_ref,
            birth.person_ref,
            intent.occurred_at,
        );
        if fail_grant {
            // The wrong grant occupies the requested id: the birth step gets
            // past its baseline write, then fails before the journal moves.
            let wrong = AccessGrant::companion_profile_read(
                entity(OUTSIDER),
                intent.person_ref,
                birth.person_ref,
                intent.occurred_at,
            );
            vault.put_access_grant(&birth.profile_grant_ref, &wrong)?;
            let err = vault
                .onboard_workspace_member(intent.clone(), &owner, None)
                .expect_err("conflicting profile grant refuses this attempt");
            assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
            assert_eq!(
                vault.get_access_grant(&birth.profile_grant_ref)?,
                Some(wrong)
            );
            // Repair only the failed dependency; the PERSON must not be erased.
            vault.put_access_grant(&birth.profile_grant_ref, &expected_grant)?;
        } else {
            // Model a crash after the complete birth write but before the
            // separate CompanionBorn journal write.
            birth_companion(&vault, &intent, &birth, &owner)?;
        }
        let journal = read_journal(&vault, &intent.onboarding_id)?
            .expect("the birth step did not advance its journal");
        assert_eq!(
            journal.step,
            if fail_grant {
                MemberOnboardingStep::MemberGranted
            } else {
                MemberOnboardingStep::ActorLinked
            }
        );
        let before = vault
            .get(&birth.person_ref)?
            .expect("baseline committed on PERSON");
        let fields = decode_map(&before)?;
        assert!(
            fields
                .iter()
                .any(|(key, _)| key.as_str() == Some("persona_definition"))
        );

        let outcome = vault.onboard_workspace_member(intent.clone(), &owner, None)?;
        assert_eq!(outcome.companion_person_ref, Some(birth.person_ref));
        assert_eq!(vault.get(&birth.person_ref)?, Some(before));
        assert_eq!(
            vault.get_access_grant(&birth.profile_grant_ref)?,
            Some(expected_grant)
        );
        assert_eq!(
            read_journal(&vault, &intent.onboarding_id)?
                .expect("completed journal")
                .step,
            MemberOnboardingStep::Complete
        );
        assert_eq!(
            vault.onboard_workspace_member(intent, &owner, None)?,
            outcome
        );
    }
    Ok(())
}

#[test]
fn companion_retry_rejects_conflicting_roster_identity_after_baseline() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth.clone());
    let owner = writer(WRITER);
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &owner,
        None,
        MemberOnboardingStep::ActorLinked,
    )?;
    birth_companion(&vault, &intent, &birth, &owner)?;
    let mut fields = decode_map(&vault.get(&birth.person_ref)?.expect("PERSON"))?;
    let name = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("display_name"))
        .expect("roster name");
    name.1 = Value::from("different person");
    let conflicting = encode_value(&Value::Map(fields))?;
    vault
        .batch()
        .put(
            &birth.person_ref,
            ENTITY_TYPE_PERSON,
            TimeRange { start: AT, end: AT },
            AT + 1,
            &conflicting,
        )
        .commit()?;
    let err = vault
        .onboard_workspace_member(intent, &owner, None)
        .expect_err("a conflicting roster identity cannot be adopted");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(vault.get(&birth.person_ref)?, Some(conflicting));
    Ok(())
}

#[test]
fn companion_retry_preserves_valid_owner_edited_persona_baseline() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth.clone());
    let owner = writer(WRITER);
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &owner,
        None,
        MemberOnboardingStep::ActorLinked,
    )?;
    birth_companion(&vault, &intent, &birth, &owner)?;
    vault.put_persona_baseline(
        &birth.person_ref,
        &serde_json::json!({ "display_name": "different persona" }),
        AT + 1,
    )?;
    let before = vault.get(&birth.person_ref)?;
    let outcome = vault.onboard_workspace_member(intent, &owner, None)?;
    assert_eq!(outcome.companion_person_ref, Some(birth.person_ref));
    assert_eq!(vault.get(&birth.person_ref)?, before);
    assert_eq!(
        crate::companion::validated_persona_baseline(&before.expect("edited PERSON"))?,
        serde_json::json!({ "display_name": "different persona" })
    );
    Ok(())
}
