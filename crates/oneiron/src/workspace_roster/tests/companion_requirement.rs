use super::*;

type RawRows = Vec<(Vec<u8>, Vec<u8>)>;

fn onboarding_rows(vault: &Vault) -> Result<Vec<RawRows>> {
    let txn = vault.store.env.read_txn()?;
    let mut result = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.vault_meta,
        &vault.store.edges_out,
        &vault.store.edges_in,
    ] {
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            rows.push((key.to_vec(), value.to_vec()));
        }
        result.push(rows);
    }
    Ok(result)
}

#[test]
fn missing_companion_is_rejected_before_any_effect_and_does_not_burn_the_intent() -> Result<()> {
    for dangling_grant in [false, true] {
        let (_dir, vault, intent) = fixture("Antevon");
        let mut missing = intent.clone();
        missing.companion_birth = None;
        if !dangling_grant {
            missing.grant_bundle.companion_profile_grant_ref = None;
        }
        let before = onboarding_rows(&vault)?;
        let err = vault
            .onboard_workspace_member(missing, &writer(WRITER))
            .expect_err("a companion is required even without a profile grant request");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("every onboarded principal requires a quiz-named companion")
        ));
        assert_eq!(onboarding_rows(&vault)?, before);
        assert!(read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.is_none());
        assert!(
            vault
                .workspace_roster(&intent.workspace.workspace_ref)?
                .is_empty()
        );
        let birth = intent
            .companion_birth
            .as_ref()
            .expect("valid fixture")
            .clone();
        let outcome = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
        assert_eq!(outcome.companion_person_ref, Some(birth.person_ref));
        assert_eq!(outcome.companion_actor_ref, Some(birth.actor_ref));
        let complete = onboarding_rows(&vault)?;
        assert_eq!(
            vault.onboard_workspace_member(intent, &writer(WRITER))?,
            outcome
        );
        assert_eq!(onboarding_rows(&vault)?, complete);
    }
    Ok(())
}

#[test]
fn missing_companion_cannot_pass_the_step_roster_or_journal_doors() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    intent.companion_birth = None;
    intent.grant_bundle.companion_profile_grant_ref = None;
    let before = onboarding_rows(&vault)?;
    assert!(
        vault
            .run_onboarding_step(
                MemberOnboardingStep::CompanionBorn,
                &intent,
                &writer(WRITER)
            )
            .is_err()
    );
    assert!(record_roster_member(&vault, &intent, &writer(WRITER)).is_err());
    assert!(
        write_journal(
            &vault,
            &onboarding_key(&intent.onboarding_id),
            &intent,
            &OnboardingJournal {
                intent_digest: intent_digest(&intent)?,
                step: MemberOnboardingStep::Complete,
                completed_at: Some(AT),
            },
            &writer(WRITER),
        )
        .is_err()
    );
    assert_eq!(onboarding_rows(&vault)?, before);
    Ok(())
}

#[test]
fn companion_name_must_be_supplied_and_nonblank_without_an_engine_default() -> Result<()> {
    for name in ["", " \t\n", "invalid\0name"] {
        let (_dir, vault, mut intent) = fixture("Antevon");
        intent
            .companion_birth
            .as_mut()
            .expect("fixture birth")
            .display_name = name.to_owned();
        let before = onboarding_rows(&vault)?;
        assert_eq!(
            vault
                .onboard_workspace_member(intent, &writer(WRITER))
                .expect_err("quiz must supply a usable name")
                .kind(),
            ErrorKind::InvalidClaimBody
        );
        assert_eq!(onboarding_rows(&vault)?, before);
    }
    Ok(())
}

#[test]
fn a_companion_cannot_be_reused_for_a_second_principal() -> Result<()> {
    let (_dir, vault, first) = fixture("Antevon");
    vault.onboard_workspace_member(first.clone(), &writer(WRITER))?;
    let mut second = first.clone();
    second.onboarding_id = "second-principal".to_owned();
    second.person_ref = seed_plain(&vault, 0xD6, ENTITY_TYPE_PERSON);
    second.actor_ref = entity(0xD9);
    second.grant_bundle.federation_grant_ref = entity(0xD8);
    let before = onboarding_rows(&vault)?;
    let err = vault
        .onboard_workspace_member(second.clone(), &writer(WRITER))
        .expect_err("companion ownership must remain per principal");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("companion person already belongs to a different principal")
    ));
    assert_eq!(onboarding_rows(&vault)?, before);
    assert!(read_journal(&vault, &onboarding_key(&second.onboarding_id))?.is_none());
    assert_eq!(
        vault
            .workspace_roster(&first.workspace.workspace_ref)?
            .len(),
        2
    );
    Ok(())
}

#[test]
fn a_completed_principal_cannot_mint_another_companion_under_a_new_intent() -> Result<()> {
    let (_dir, vault, first) = fixture("Antevon");
    let outcome = vault.onboard_workspace_member(first.clone(), &writer(WRITER))?;
    let mut second = first.clone();
    second.onboarding_id = "replacement-companion".to_owned();
    let birth = second.companion_birth.as_mut().expect("fixture birth");
    birth.person_ref = entity(0xD1);
    birth.actor_ref = entity(0xD2);
    birth.companion_record_ref = entity(0xD3);
    birth.profile_grant_ref = entity(0xD4);
    second.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    let before = onboarding_rows(&vault)?;
    assert_eq!(
        vault
            .onboard_workspace_member(second, &writer(WRITER))
            .expect_err("principal slot is already reserved")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    assert_eq!(onboarding_rows(&vault)?, before);
    assert_eq!(
        vault.onboard_workspace_member(first, &writer(WRITER))?,
        outcome
    );
    Ok(())
}

#[test]
fn stored_member_rows_cannot_silently_omit_companion_person_actor_or_facet() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
    let birth = intent.companion_birth.as_ref().expect("fixture birth");
    for omitted in 0..3 {
        let mut row = RosterMemberRow {
            person_ref: intent.person_ref,
            actor_ref: intent.actor_ref,
            companion_person_ref: Some(birth.person_ref),
            companion_actor_ref: Some(birth.actor_ref),
            companion_facet_ref: Some(birth.work_facet_ref),
            identity_ref: None,
        };
        match omitted {
            0 => row.companion_person_ref = None,
            1 => row.companion_actor_ref = None,
            _ => row.companion_facet_ref = None,
        }
        assert_eq!(
            companion_entry(&vault, &intent.workspace, &row)
                .expect_err("missing companion is not an empty roster entry")
                .kind(),
            ErrorKind::InvalidClaimBody
        );
    }
    Ok(())
}
