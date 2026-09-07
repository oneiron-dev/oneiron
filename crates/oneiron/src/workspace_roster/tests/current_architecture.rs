use super::*;
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};

pub(super) fn register_mailbox_custody(
    vault: &Vault,
    mailbox: &DelegatedMailboxOnboarding,
    subject_address: &str,
) -> Result<EntityId> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: mailbox.custody_name.clone(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"test-only-oauth-bytes".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: AT,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: crate::channel_identity::delegated_custody_scopes(
                &mailbox.channel,
                subject_address,
            ),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })
}

#[test]
fn missing_custody_leaves_resumable_journal_and_no_identity() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::SecretRefNotFound);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_none()
    );
    let journal = read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
        .expect("fixture value exists");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    register_mailbox_custody(&vault, &requested, &requested.address)?;
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::WorkspaceMailboxAutonomyNotReady);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_some()
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
            ENTITY_TYPE_COMPANION_REGISTER,
            ENTITY_TYPE_ACCESS_GRANT,
            ENTITY_TYPE_CHANNEL_IDENTITY,
            crate::registry::ENTITY_TYPE_CLAIM,
        ]
        .map(|kind| type_count(&vault, kind))
    };
    let first = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(first.kind(), ErrorKind::WorkspaceMailboxAutonomyNotReady);
    let counts = census();
    let second = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(second.kind(), first.kind());
    assert_eq!(census(), counts);
    let journal = read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
        .expect("fixture value exists");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    // The unfinished companion is not published in the roster.
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 1);
    let mut changed = intent;
    changed
        .delegated_mailbox
        .as_mut()
        .expect("fixture value exists")
        .starting_mode = "observe".to_owned();
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(census(), counts);
    Ok(())
}

#[test]
fn custody_for_another_mailbox_is_not_authority() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    register_mailbox_custody(&vault, &requested, "other@example.test")?;
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::SecretBindingDenied);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_none()
    );
    Ok(())
}

#[test]
fn an_occupied_identity_id_cannot_be_adopted() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    let existing =
        vault.create_own_app_channel_identity(&requested.identity_ref, entity(OUTSIDER), AT)?;
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_channel_identity(&requested.identity_ref)?,
        Some(existing)
    );
    Ok(())
}

#[test]
fn existing_actor_composition_must_match_without_overwriting_owner_edits() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let mut existing = intent.actor_definition.clone();
    existing.display_name = Some("Owner chosen name".to_owned());
    existing.enabled = false;
    vault.define_agent(
        &intent.actor_ref,
        &existing,
        TimeRange { start: AT, end: AT },
        AT,
    )?;
    vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
    assert_eq!(
        vault.get_agent_definition(&intent.actor_ref)?,
        Some(existing)
    );

    let (_dir2, other, intent2) = fixture("Antevon");
    other.define_agent(
        &intent2.actor_ref,
        &definition("unrelated.actor"),
        TimeRange { start: AT, end: AT },
        AT,
    )?;
    let err = other
        .onboard_workspace_member(intent2, &writer(WRITER))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

#[test]
fn every_completed_step_resumes_with_identical_stable_refs() -> Result<()> {
    for step in ONBOARDING_STEPS {
        let (_dir, vault, mut intent) = fixture("Antevon");
        let birth = companion_birth();
        intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
        intent.companion_birth = Some(birth);
        vault.onboard_workspace_member_halting_after(intent.clone(), &writer(WRITER), step)?;
        let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
        let counts = [
            ENTITY_TYPE_PERSON,
            ENTITY_TYPE_AGENT_DEF,
            ENTITY_TYPE_FEDERATION_GRANT,
            ENTITY_TYPE_COMPANION_REGISTER,
            ENTITY_TYPE_ACCESS_GRANT,
            crate::registry::ENTITY_TYPE_CLAIM,
        ]
        .map(|kind| type_count(&vault, kind));
        assert_eq!(
            vault.onboard_workspace_member(intent, &writer(WRITER))?,
            first
        );
        assert_eq!(
            counts,
            [
                ENTITY_TYPE_PERSON,
                ENTITY_TYPE_AGENT_DEF,
                ENTITY_TYPE_FEDERATION_GRANT,
                ENTITY_TYPE_COMPANION_REGISTER,
                ENTITY_TYPE_ACCESS_GRANT,
                crate::registry::ENTITY_TYPE_CLAIM
            ]
            .map(|kind| type_count(&vault, kind))
        );
    }
    Ok(())
}

#[test]
fn a_second_onboarding_id_cannot_replace_a_principals_companion() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth);
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        MemberOnboardingStep::ActorLinked,
    )?;
    let mut changed = intent.clone();
    changed.onboarding_id = "second-onboarding".to_owned();
    changed.actor_ref = entity(0xD1);
    changed.grant_bundle.federation_grant_ref = entity(0xD2);
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER))
        .expect_err("principal slot belongs to the unfinished journal");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(vault.get_entity_type(&entity(0xD1))?.is_none());
    vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 2);
    Ok(())
}

#[test]
fn owner_house_name_override_is_runtime_data() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    intent.workspace.house_display_name = Some("Owner named house".to_owned());
    vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Owner named house"
    );
    Ok(())
}

#[test]
fn minted_kind_collision_is_rejected_before_the_first_effect() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let occupied = seed_plain(&vault, 0xD3, ENTITY_TYPE_PERSON);
    intent.grant_bundle.federation_grant_ref = occupied;
    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER))
        .expect_err("maintenance grant id cannot alias a person");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.is_none());
    assert!(actor_subject_anchor(&vault, &intent.workspace.house_actor_ref, AT)?.is_none());
    Ok(())
}

#[test]
fn resumed_onboarding_requires_current_admin_authority() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        MemberOnboardingStep::ActorLinked,
    )?;
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            entity(WRITER),
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER))
        .expect_err("a demoted writer cannot resume membership minting");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(
        vault
            .get_entity_type(&intent.grant_bundle.federation_grant_ref)?
            .is_none()
    );
    assert_eq!(
        read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
            .expect("journal survives refusal")
            .step,
        MemberOnboardingStep::ActorLinked
    );
    Ok(())
}

#[test]
fn existing_grant_must_match_exactly_and_is_never_rewritten() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let occupied = FederationGrant::new(
        FederationGrantScope::vault(VAULT_ID),
        entity(OUTSIDER),
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    );
    seed_federation_grant(&vault, MEMBER_GRANT, &occupied);
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER))
        .expect_err("an occupied grant id is not an invitation to overwrite it");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        read_federation_grant_in_txn(&vault, &txn, &entity(MEMBER_GRANT))?,
        Some(occupied)
    );
    Ok(())
}

#[test]
fn house_name_can_be_owner_edited_without_rewriting_the_seed_or_replay() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let seed_before = vault.get_agent_definition(&intent.workspace.house_actor_ref)?;
    let outcome = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
    vault.set_workspace_house_display_name(
        "antevon-slack",
        Some("Renamed house".to_owned()),
        &writer(WRITER),
    )?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Renamed house"
    );
    assert_eq!(
        vault.get_agent_definition(&intent.workspace.house_actor_ref)?,
        seed_before
    );
    assert_eq!(
        vault.onboard_workspace_member(intent, &writer(WRITER))?,
        outcome
    );
    let err = vault
        .set_workspace_house_display_name("antevon-slack", None, &writer(OUTSIDER))
        .expect_err("outsider cannot rename the house");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Renamed house"
    );
    vault.set_workspace_house_display_name("antevon-slack", None, &writer(WRITER))?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Antevon"
    );
    Ok(())
}
