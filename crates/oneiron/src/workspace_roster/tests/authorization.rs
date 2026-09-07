use super::*;
use crate::subject_model::tests::authorization::root_owner;

type Mutation = fn(&Vault, &MemberOnboardingIntent, &WriteActor) -> Result<()>;
type RawRows = Vec<(Vec<u8>, Vec<u8>)>;

fn birth(intent: &MemberOnboardingIntent) -> &CompanionBirthIntent {
    intent.companion_birth.as_ref().expect("companion fixture")
}

/// Capture durable effects, not just the returned error. Authority entries
/// are included; callers take the baseline after committing the revocation.
fn durable_rows(vault: &Vault) -> Result<Vec<RawRows>> {
    let txn = vault.store.env.read_txn()?;
    let mut result = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.vault_meta,
        &vault.store.edges_out,
        &vault.store.edges_in,
        &vault.store.type_index,
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
fn every_onboarding_mutation_rechecks_revoked_authority_after_preflight() -> Result<()> {
    let mutations: &[(&str, Mutation)] = &[
        ("house anchor", |v, i, w| {
            ensure_subject_anchor(v, i, i.workspace.house_actor_ref, i.workspace.org_ref, w)
        }),
        ("preset", |v, i, w| ensure_preset_row(v, &i.workspace, w)),
        ("member actor", |v, i, w| {
            ensure_agent_definition(v, i, &i.actor_ref, &i.actor_definition, w)
        }),
        ("member anchor", |v, i, w| {
            ensure_subject_anchor(v, i, i.actor_ref, i.person_ref, w)
        }),
        ("member grant", grant_member_bundle),
        ("companion person", |v, i, w| {
            ensure_companion_person(v, i, birth(i), w)
        }),
        ("model substrate", |v, i, w| {
            ensure_model_substrate(v, i, birth(i).person_ref, w)
        }),
        ("companion actor", |v, i, w| {
            ensure_agent_definition(v, i, &birth(i).actor_ref, &birth(i).actor_definition, w)
        }),
        ("companion anchor", |v, i, w| {
            ensure_subject_anchor(v, i, birth(i).actor_ref, birth(i).person_ref, w)
        }),
        ("work facet", |v, i, w| {
            ensure_work_facet_edge(v, i, birth(i).person_ref, birth(i).work_facet_ref, w)
        }),
        ("companion record", |v, i, w| {
            ensure_companion_record(v, i, birth(i), w)
        }),
        ("profile grant", |v, i, w| {
            ensure_companion_profile_grant(v, i, birth(i), w)
        }),
        ("mailbox", |v, i, w| {
            bind_delegated_mailbox(v, i, i.delegated_mailbox.as_ref().expect("mailbox"), w)
        }),
        ("roster", record_roster_member),
        ("journal reservation", |v, i, w| {
            write_journal(
                v,
                &onboarding_key(&i.onboarding_id),
                i,
                &OnboardingJournal {
                    intent_digest: intent_digest(i)?,
                    step: MemberOnboardingStep::Started,
                    completed_at: None,
                },
                w,
            )
        }),
    ];
    for &(name, mutate) in mutations {
        let (_dir, vault, mut intent) = fixture("Antevon");
        let companion = companion_birth();
        intent.grant_bundle.companion_profile_grant_ref = Some(companion.profile_grant_ref);
        intent.companion_birth = Some(companion.clone());
        let requested = mailbox();
        intent.delegated_mailbox = Some(requested.clone());
        let owner = writer(WRITER);
        let revoke = root_owner(&vault, owner, 0xE3)?;
        // Only satisfy prerequisites. Leave the tested effect ABSENT.
        if matches!(name, "member anchor" | "mailbox") {
            ensure_agent_definition(
                &vault,
                &intent,
                &intent.actor_ref,
                &intent.actor_definition,
                &owner,
            )?;
        }
        if matches!(
            name,
            "model substrate"
                | "companion anchor"
                | "work facet"
                | "companion record"
                | "profile grant"
        ) {
            ensure_companion_person(&vault, &intent, &companion, &owner)?;
        }
        if matches!(
            name,
            "companion anchor" | "companion record" | "profile grant"
        ) {
            ensure_agent_definition(
                &vault,
                &intent,
                &companion.actor_ref,
                &companion.actor_definition,
                &owner,
            )?;
        }
        if name == "mailbox" {
            register_mailbox_custody(&vault, &requested, &requested.address)?;
        }
        require_workspace_authority(&vault, VAULT_ID, &owner)?;
        vault.put_authority_log_entry(
            &revoke,
            TimeRange {
                start: 102,
                end: 102,
            },
            102,
        )?;
        let before = durable_rows(&vault)?;
        let err = mutate(&vault, &intent, &owner).expect_err(name);
        assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority, "{name}");
        assert_eq!(
            durable_rows(&vault)?,
            before,
            "{name} left a durable effect"
        );
    }
    Ok(())
}

#[test]
fn final_roster_write_observes_revocation_while_waiting_for_writer_lock() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let owner = writer(WRITER);
    let revoke = root_owner(&vault, owner, 0xE4)?;
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &owner,
        MemberOnboardingStep::MailboxBound,
    )?;
    let key = roster_member_key(&intent.workspace.workspace_ref, &intent.person_ref);
    let journal_before = read_journal(&vault, &onboarding_key(&intent.onboarding_id))?;
    let mut revocation_txn = vault.store.env.write_txn()?;
    vault.put_authority_log_entries_in_txn(
        &mut revocation_txn,
        &[(
            revoke,
            TimeRange {
                start: 102,
                end: 102,
            },
            102,
        )],
    )?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<()> {
        let worker = scope.spawn(|| -> Result<()> {
            require_workspace_authority(&vault, VAULT_ID, &owner)?;
            ready_tx.send(()).expect("notify successful preflight");
            record_roster_member(&vault, &intent, &owner)
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("preflight completed");
        revocation_txn.commit()?;
        worker.join().expect("roster worker")
    });
    assert_eq!(
        result.expect_err("revoked admin").kind(),
        ErrorKind::ActorLacksClaimAuthority
    );
    let txn = vault.store.env.read_txn()?;
    assert!(vault.store.vault_meta.get(&txn, &key)?.is_none());
    drop(txn);
    assert_eq!(
        read_journal(&vault, &onboarding_key(&intent.onboarding_id))?,
        journal_before
    );
    Ok(())
}

#[test]
fn journal_completion_rechecks_authority_after_an_authorized_roster_write() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let owner = writer(WRITER);
    let revoke = root_owner(&vault, owner, 0xE5)?;
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &owner,
        MemberOnboardingStep::MailboxBound,
    )?;
    record_roster_member(&vault, &intent, &owner)?;
    require_workspace_authority(&vault, VAULT_ID, &owner)?;
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    let before = durable_rows(&vault)?;
    let err = write_journal(
        &vault,
        &onboarding_key(&intent.onboarding_id),
        &intent,
        &OnboardingJournal {
            intent_digest: intent_digest(&intent)?,
            step: MemberOnboardingStep::Complete,
            completed_at: Some(AT),
        },
        &owner,
    )
    .expect_err("revoked admin cannot publish completion");
    assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority);
    assert_eq!(durable_rows(&vault)?, before);
    assert_eq!(
        read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
            .expect("resumable journal")
            .step,
        MemberOnboardingStep::MailboxBound
    );
    Ok(())
}

#[test]
fn grant_demotion_blocks_roster_and_rename_but_reauthorization_resumes() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let owner = writer(WRITER);
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &owner,
        MemberOnboardingStep::MailboxBound,
    )?;
    require_workspace_authority(&vault, VAULT_ID, &owner)?;
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            owner.entity_ref(),
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let before = durable_rows(&vault)?;
    assert_eq!(
        record_roster_member(&vault, &intent, &owner)
            .expect_err("demoted admin")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    assert!(
        vault
            .set_workspace_house_display_name(
                &intent.workspace.workspace_ref,
                Some("Not authorized".to_owned()),
                &owner,
            )
            .is_err()
    );
    assert_eq!(durable_rows(&vault)?, before);
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            owner.entity_ref(),
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        ),
    );
    let outcome = vault.onboard_workspace_member(intent.clone(), &owner)?;
    let completed = durable_rows(&vault)?;
    assert_eq!(vault.onboard_workspace_member(intent, &owner)?, outcome);
    assert_eq!(durable_rows(&vault)?, completed);
    Ok(())
}

#[test]
fn mailbox_retry_rechecks_custody_and_never_completes_autonomy() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let owner = writer(WRITER);
    let requested = mailbox();
    intent.delegated_mailbox = Some(requested.clone());
    register_mailbox_custody(&vault, &requested, &requested.address)?;
    assert_eq!(
        vault
            .onboard_workspace_member(intent.clone(), &owner)
            .expect_err("ONE1829 remains unavailable")
            .kind(),
        ErrorKind::WorkspaceMailboxAutonomyNotReady
    );
    let identity = vault
        .get_channel_identity(&requested.identity_ref)?
        .expect("Requested row");
    assert_eq!(identity.state, ChannelIdentityState::Requested);
    assert!(!identity.may_send());
    // A successful first provisioning does not authorize a later retry.
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            owner.entity_ref(),
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let before = durable_rows(&vault)?;
    assert_eq!(
        bind_delegated_mailbox(&vault, &intent, &requested, &owner)
            .expect_err("demoted mailbox writer")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    assert_eq!(durable_rows(&vault)?, before);
    assert_eq!(
        vault.get_channel_identity(&requested.identity_ref)?,
        Some(identity.clone())
    );
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            owner.entity_ref(),
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        ),
    );
    vault.revoke_secret(&requested.custody_name, AT + 1)?;
    let before = durable_rows(&vault)?;
    let err = bind_delegated_mailbox(&vault, &intent, &requested, &owner)
        .expect_err("existing identity is not proof of live custody");
    assert_eq!(err.kind(), ErrorKind::SecretCustodyNotActive);
    assert_eq!(durable_rows(&vault)?, before);
    assert_eq!(
        vault.get_channel_identity(&requested.identity_ref)?,
        Some(identity)
    );
    let journal =
        read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.expect("resumable journal");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    Ok(())
}

#[test]
fn class_valid_bound_admins_keep_authorized_onboarding_behavior() -> Result<()> {
    for class in [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ] {
        let (_dir, vault, intent) = fixture("Antevon");
        let actor = match class {
            EdgeActorClass::Human => entity(WRITER),
            EdgeActorClass::Agent => {
                let actor = entity(0xD4);
                vault.define_agent(
                    &actor,
                    &definition("fixture.admin"),
                    TimeRange { start: AT, end: AT },
                    AT,
                )?;
                actor
            }
            EdgeActorClass::System => {
                seed_plain(&vault, 0xD4, crate::registry::ENTITY_TYPE_MACHINE)
            }
        };
        let admin = WriteActor::new(actor, class);
        root_owner(&vault, admin, 0xE6)?;
        seed_federation_grant(
            &vault,
            ADMIN_GRANT,
            &FederationGrant::new(
                FederationGrantScope::vault(VAULT_ID),
                actor,
                FederationGrantRole::Admin,
                FederationGrantPreset::Admin,
            ),
        );
        let outcome = vault.onboard_workspace_member(intent.clone(), &admin)?;
        assert_eq!(
            actor_subject_anchor(&vault, &intent.actor_ref)?,
            Some(intent.person_ref)
        );
        assert_eq!(
            vault.onboard_workspace_member(intent.clone(), &admin)?,
            outcome
        );
        if class != EdgeActorClass::Human {
            let before = durable_rows(&vault)?;
            let err = crate::subject_model::anchor_actor_subject(
                &vault,
                intent.actor_ref,
                intent.workspace.org_ref,
                admin,
                AT + 1,
            )
            .expect_err("admin enrollment is not human-owner reattribution");
            assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority);
            assert_eq!(durable_rows(&vault)?, before);
        }
    }
    Ok(())
}
