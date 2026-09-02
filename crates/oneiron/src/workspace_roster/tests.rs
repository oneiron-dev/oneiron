//! ONE-1832 workspace roster + member onboarding tests.
//!
//! Every fixture name here is invented BY THE TEST. If a display name in an
//! assertion also appeared in `workspace_roster.rs`, the "names are runtime
//! data" contract would already be broken.

use super::*;

use crate::agent_def::{AgentCeiling, AgentScope};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::test_util::{entity, open_test_vault_with};

const VAULT_ID: u64 = 7;
const AT: u64 = 1_800_000_000;

const WRITER: u8 = 0x9A;
const OUTSIDER: u8 = 0x9B;
const MEMBER_PERSON: u8 = 0xB1;
const ORG: u8 = 0xB2;
const MEMBER_FACET: u8 = 0xB3;
const MEMBER_ACTOR: u8 = 0xB5;
const MEMBER_GRANT: u8 = 0xB6;
const ADMIN_GRANT: u8 = 0xB7;
const COMPANION_PERSON: u8 = 0xC1;
const COMPANION_ACTOR: u8 = 0xC2;
const COMPANION_FACET: u8 = 0xC3;
const COMPANION_RECORD: u8 = 0xC4;
const PROFILE_GRANT: u8 = 0xC5;
const MAILBOX_IDENTITY: u8 = 0xC6;

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 32 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

fn writer(seed: u8) -> WriteActor {
    WriteActor::new(entity(seed), EdgeActorClass::Human)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "workspace roster fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from(agent_id))]),
        None,
        true,
        None,
    )
}

fn seed_plain(vault: &Vault, seed: u8, entity_type: u8) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"workspace roster fixture",
        )
        .expect("seed entity");
    id
}

/// Writes a federation grant straight through the engine-internal maintenance
/// Put. The fixture needs the ADMIN grant that authorizes onboarding, and no
/// public door mints one at this head.
fn seed_federation_grant(vault: &Vault, seed: u8, grant: &FederationGrant) -> EntityId {
    let id = entity(seed);
    let data = encode_federation_grant_body(grant).expect("encode grant");
    vault
        .with_write_txn(|wtxn| {
            apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    occurred: TimeRange {
                        start: 100,
                        end: 100,
                    },
                    learned_at: 100,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                false,
                false,
                true,
            )
        })
        .expect("seed federation grant");
    id
}

/// The seeded house row: ONE-1890 owns it, this ticket only borrows it.
fn house_actor_ref(vault: &Vault) -> EntityId {
    vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seed lookup")
        .expect("sys.team_lead is seeded on open")
        .0
}

fn preset(vault: &Vault, workspace_ref: &str, venture_name: &str) -> WorkspaceRosterPreset {
    WorkspaceRosterPreset {
        workspace_ref: workspace_ref.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: entity(ORG),
        venture_name: venture_name.to_owned(),
        house_display_name: None,
        house_actor_ref: house_actor_ref(vault),
        house_identity_ref: None,
    }
}

fn companion_birth() -> CompanionBirthIntent {
    CompanionBirthIntent {
        person_ref: entity(COMPANION_PERSON),
        actor_ref: entity(COMPANION_ACTOR),
        work_facet_ref: entity(COMPANION_FACET),
        companion_record_ref: entity(COMPANION_RECORD),
        profile_grant_ref: entity(PROFILE_GRANT),
        actor_definition: definition("fixture.companion"),
        display_name: "Quillfeather".to_owned(),
    }
}

fn mailbox() -> DelegatedMailboxOnboarding {
    DelegatedMailboxOnboarding {
        identity_ref: entity(MAILBOX_IDENTITY),
        channel: "gmail".to_owned(),
        address: "member@example.test".to_owned(),
        custody_name: "custody/member-mailbox".to_owned(),
        scopes: vec![DelegatedGrantScope::MailRead],
    }
}

fn intent(vault: &Vault, workspace_ref: &str, venture_name: &str) -> MemberOnboardingIntent {
    MemberOnboardingIntent {
        onboarding_id: "onboard-1".to_owned(),
        workspace: preset(vault, workspace_ref, venture_name),
        person_ref: entity(MEMBER_PERSON),
        actor_ref: entity(MEMBER_ACTOR),
        actor_definition: definition("fixture.member"),
        work_facet_ref: entity(MEMBER_FACET),
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: entity(MEMBER_GRANT),
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: None,
        },
        companion_birth: None,
        delegated_mailbox: None,
        occurred_at: AT,
    }
}

/// Seeds the entities every onboarding references plus the writer's admin grant.
fn fixture(venture_name: &str) -> (tempfile::TempDir, Vault, MemberOnboardingIntent) {
    let (dir, vault) = test_vault();
    seed_plain(&vault, MEMBER_PERSON, ENTITY_TYPE_PERSON);
    seed_plain(&vault, ORG, ENTITY_TYPE_ORG);
    seed_plain(&vault, MEMBER_FACET, ENTITY_TYPE_FACET);
    seed_plain(&vault, COMPANION_FACET, ENTITY_TYPE_FACET);
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            entity(WRITER),
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        ),
    );
    let intent = intent(&vault, "antevon-slack", venture_name);
    (dir, vault, intent)
}

fn type_count(vault: &Vault, entity_type: u8) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[entity_type])
        .expect("prefix iter")
        .count()
}

// ---------------------------------------------------------------------------

/// Done-means 1/11: the same compiled code produces two different house names
/// because the venture name is intent data, not an engine constant.
#[test]
fn venture_name_is_runtime_data() -> Result<()> {
    let mut names = Vec::new();
    for venture_name in ["Antevon", "Oneiron"] {
        let (_dir, vault, intent) = fixture(venture_name);
        vault.onboard_workspace_member(intent, &writer(WRITER))?;
        let roster = vault.workspace_roster("antevon-slack")?;
        let house = roster
            .iter()
            .find(|entry| entry.role == WorkspaceRosterRole::HouseMind)
            .expect("house mind row");
        assert_eq!(house.display_name, venture_name);
        // Done-means 1: the house mind stands behind the workspace ORG.
        assert_eq!(house.subject_ref, entity(ORG));
        names.push(house.display_name.clone());
    }
    assert_eq!(names, vec!["Antevon".to_owned(), "Oneiron".to_owned()]);

    // The `@Oneiron` reading is a coincidence of the second deployment's
    // venture name, so it must not be findable in this module's source.
    let source = include_str!("../workspace_roster.rs");
    assert!(!source.contains("Antevon"));
    assert!(!source.contains("Oneiron\""));
    Ok(())
}

/// Done-means 3: exactly `(Member, Member)`, and an asked-for widening is a
/// typed refusal rather than a silent downgrade.
#[test]
fn member_bundle_never_widens_to_admin() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let outcome = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;

    let rtxn = vault.store.env.read_txn()?;
    let grant = read_federation_grant_in_txn(&vault, &rtxn, &outcome.federation_grant_ref)?
        .expect("member grant");
    drop(rtxn);
    assert_eq!(grant.role, FederationGrantRole::Member);
    assert_eq!(grant.preset, FederationGrantPreset::Member);
    assert_eq!(grant.scope, FederationGrantScope::vault(VAULT_ID));
    assert_eq!(grant.member_ref, entity(MEMBER_PERSON));
    assert!(!grant.role.is_admin());

    for (role, preset) in [
        (FederationGrantRole::Admin, FederationGrantPreset::Admin),
        (FederationGrantRole::Owner, FederationGrantPreset::Owner),
        (FederationGrantRole::Member, FederationGrantPreset::Admin),
    ] {
        let mut widened = intent.clone();
        widened.onboarding_id = format!("widen-{}", role.as_str());
        widened.grant_bundle.role = role;
        widened.grant_bundle.preset = preset;
        let err = vault
            .onboard_workspace_member(widened, &writer(WRITER))
            .expect_err("widened bundle must be refused");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    }
    Ok(())
}

/// Done-means 4: a companion is a whole someone, and its profile grant is
/// exactly as narrow as the intent asked for.
#[test]
fn companion_birth_is_full_person() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth.clone());

    let outcome = vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(outcome.companion_person_ref, Some(birth.person_ref));
    assert_eq!(outcome.companion_actor_ref, Some(birth.actor_ref));

    // A PERSON, not a new kind, and made of model.
    assert_eq!(
        vault.get_entity_type(&birth.person_ref)?,
        Some(ENTITY_TYPE_PERSON)
    );
    assert_eq!(
        person_substrate(&vault, &birth.person_ref)?,
        Some(PersonSubstrate::Model)
    );

    // Its own actor, anchored to itself; no ACTOR entity kind anywhere.
    assert_eq!(
        vault.get_entity_type(&birth.actor_ref)?,
        Some(ENTITY_TYPE_AGENT_DEF)
    );
    assert_eq!(
        actor_subject_anchor(&vault, &birth.actor_ref)?,
        Some(birth.person_ref)
    );

    // Work facet association.
    assert!(
        vault
            .edges_out(&birth.person_ref)?
            .into_iter()
            .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == birth.work_facet_ref)
    );

    // Companion-register record.
    assert!(
        vault
            .get_companion_record(&birth.companion_record_ref)?
            .is_some()
    );

    // Exactly the requested companion-profile read, and nothing wider.
    let grant = vault
        .get_access_grant(&birth.profile_grant_ref)?
        .expect("profile grant");
    assert!(grant.allows_companion_profile_read(
        &entity(MEMBER_PERSON),
        &entity(MEMBER_PERSON),
        &birth.actor_ref,
    ));
    assert!(!grant.allows_companion_profile_read(
        &entity(OUTSIDER),
        &entity(MEMBER_PERSON),
        &birth.actor_ref,
    ));
    assert!(!grant.allows_companion_profile_read(
        &entity(MEMBER_PERSON),
        &entity(MEMBER_PERSON),
        &entity(MEMBER_ACTOR),
    ));
    assert_eq!(type_count(&vault, ENTITY_TYPE_ACCESS_GRANT), 1);

    // Done-means 8: the roster is the house mind PLUS this principal's named
    // companion, as separate rows.
    let roster = vault.workspace_roster("antevon-slack")?;
    assert_eq!(roster.len(), 2);
    let companion_row = &roster[1];
    assert_eq!(companion_row.role, WorkspaceRosterRole::PrincipalCompanion);
    assert_eq!(companion_row.principal_ref, Some(entity(MEMBER_PERSON)));
    assert_eq!(companion_row.actor_ref, birth.actor_ref);
    assert_eq!(companion_row.subject_ref, birth.person_ref);
    assert_eq!(companion_row.facet_ref, Some(birth.work_facet_ref));
    assert_eq!(companion_row.display_name, birth.display_name);
    Ok(())
}

/// Done-means 6: identical input under the same id returns the prior outcome
/// and mints nothing.
#[test]
fn onboarding_replay_is_idempotent() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth);
    intent.delegated_mailbox = Some(mailbox());

    let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;
    let counts = [
        type_count(&vault, ENTITY_TYPE_AGENT_DEF),
        type_count(&vault, ENTITY_TYPE_PERSON),
        type_count(&vault, ENTITY_TYPE_FEDERATION_GRANT),
        type_count(&vault, ENTITY_TYPE_COMPANION_REGISTER),
        type_count(&vault, ENTITY_TYPE_ACCESS_GRANT),
        type_count(&vault, ENTITY_TYPE_CHANNEL_IDENTITY),
    ];

    let second = vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(first, second);
    assert_eq!(
        counts,
        [
            type_count(&vault, ENTITY_TYPE_AGENT_DEF),
            type_count(&vault, ENTITY_TYPE_PERSON),
            type_count(&vault, ENTITY_TYPE_FEDERATION_GRANT),
            type_count(&vault, ENTITY_TYPE_COMPANION_REGISTER),
            type_count(&vault, ENTITY_TYPE_ACCESS_GRANT),
            type_count(&vault, ENTITY_TYPE_CHANNEL_IDENTITY),
        ]
    );
    assert_eq!(vault.workspace_roster("antevon-slack")?.len(), 2);
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
        intent.delegated_mailbox = Some(mailbox());
        (dir, vault, intent)
    };
    let census = |vault: &Vault| {
        [
            type_count(vault, ENTITY_TYPE_AGENT_DEF),
            type_count(vault, ENTITY_TYPE_PERSON),
            type_count(vault, ENTITY_TYPE_FEDERATION_GRANT),
            type_count(vault, ENTITY_TYPE_COMPANION_REGISTER),
            type_count(vault, ENTITY_TYPE_ACCESS_GRANT),
            type_count(vault, ENTITY_TYPE_CHANNEL_IDENTITY),
        ]
    };

    let (_clean_dir, clean, clean_intent) = build("Antevon");
    let expected_outcome = clean.onboard_workspace_member(clean_intent, &writer(WRITER))?;
    let expected_census = census(&clean);

    let (_dir, vault, intent) = build("Antevon");
    let halted = vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        MemberOnboardingStep::ActorLinked,
    )?;
    assert!(halted.is_none(), "a halted run has no outcome yet");

    let journal = read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
        .expect("halted run leaves a resumable journal");
    assert_eq!(journal.step, MemberOnboardingStep::ActorLinked);
    assert_eq!(journal.completed_at, None);

    let resumed = vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(resumed, expected_outcome);
    assert_eq!(census(&vault), expected_census);
    assert_eq!(vault.workspace_roster("antevon-slack")?.len(), 2);
    Ok(())
}

/// Done-means 5: the mailbox row carries a custody NAME and read scopes. The
/// intent has no field a token could occupy, so the stored body cannot hold one.
#[test]
fn optional_delegated_mailbox_uses_custody_ref_only() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    intent.delegated_mailbox = Some(requested.clone());

    let outcome = vault.onboard_workspace_member(intent, &writer(WRITER))?;
    assert_eq!(outcome.delegated_identity_ref, Some(requested.identity_ref));

    let identity = vault
        .get_channel_identity(&requested.identity_ref)?
        .expect("delegated identity");
    assert!(identity.is_delegated());
    assert_eq!(
        identity.binding.actor_ref(),
        Some(entity(MEMBER_ACTOR)),
        "the member's actor holds the mailbox"
    );
    let grant = identity.delegated_grant.expect("custody handle");
    assert_eq!(grant.custody_record_ref, requested.custody_name);
    assert_eq!(grant.scopes, requested.scopes);

    // Scoped-read is structural: there is no write variant to name.
    for scope in &grant.scopes {
        assert!(matches!(
            scope,
            DelegatedGrantScope::MailRead | DelegatedGrantScope::MailMetadata
        ));
    }

    // The stored body holds the custody NAME, and the module never saw a token.
    let raw = vault
        .get(&requested.identity_ref)?
        .expect("identity body bytes");
    let body = String::from_utf8_lossy(&raw);
    assert!(body.contains(&requested.custody_name));
    Ok(())
}

/// Done-means 3: authority is a stored grant, and an unprivileged caller is
/// refused before the journal exists at all.
#[test]
fn unprivileged_writer_rejected() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");

    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(OUTSIDER))
        .expect_err("an unprivileged writer must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // No journal, no actor, no grant: the refusal left no trace to resume from.
    assert!(read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.is_none());
    assert_eq!(vault.get_entity_type(&entity(MEMBER_ACTOR))?, None);
    assert_eq!(vault.get_entity_type(&entity(MEMBER_GRANT))?, None);
    assert!(vault.workspace_roster("antevon-slack")?.is_empty());

    // A member-grade grant is not an administrative one.
    seed_federation_grant(
        &vault,
        0xB8,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            entity(OUTSIDER),
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let err = vault
        .onboard_workspace_member(intent, &writer(OUTSIDER))
        .expect_err("a member-grade writer must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

/// Done-means 6: the same id with different inputs fails typed, and the prior
/// outcome survives the attempt intact.
#[test]
fn changed_input_same_id_fails_typed() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let first = vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;

    let mut changed = intent.clone();
    changed.occurred_at = AT + 1;
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER))
        .expect_err("changed input under a used id must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut renamed = intent.clone();
    renamed.workspace.venture_name = "Somewhere Else".to_owned();
    let err = vault
        .onboard_workspace_member(renamed, &writer(WRITER))
        .expect_err("a changed venture name is changed input");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // The original replay still answers with the original outcome.
    assert_eq!(
        vault.onboard_workspace_member(intent, &writer(WRITER))?,
        first
    );
    Ok(())
}

/// A second workspace_ref cannot claim a preset that disagrees with the stored
/// one, and a second member joins the same workspace without disturbing it.
#[test]
fn workspace_preset_is_settled_once_and_shared() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    vault.onboard_workspace_member(intent.clone(), &writer(WRITER))?;

    let mut conflicting = intent.clone();
    conflicting.onboarding_id = "onboard-2".to_owned();
    conflicting.workspace.venture_name = "Different Venture".to_owned();
    conflicting.person_ref = seed_plain(&vault, 0xB9, ENTITY_TYPE_PERSON);
    conflicting.actor_ref = entity(0xBA);
    conflicting.grant_bundle.federation_grant_ref = entity(0xBB);
    let err = vault
        .onboard_workspace_member(conflicting, &writer(WRITER))
        .expect_err("a disagreeing preset must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut second = intent;
    second.onboarding_id = "onboard-2".to_owned();
    second.person_ref = entity(0xB9);
    second.actor_ref = entity(0xBA);
    second.grant_bundle.federation_grant_ref = entity(0xBB);
    let outcome = vault.onboard_workspace_member(second, &writer(WRITER))?;
    assert_eq!(outcome.person_ref, entity(0xB9));

    // Two members, no companions: the roster is still just the house mind.
    let roster = vault.workspace_roster("antevon-slack")?;
    assert_eq!(roster.len(), 1);
    assert_eq!(roster[0].role, WorkspaceRosterRole::HouseMind);
    Ok(())
}

/// An intent that aliases a minted id onto a referenced one is refused before
/// anything is written.
#[test]
fn aliased_entity_ids_are_refused() {
    let (_dir, vault, intent) = fixture("Antevon");

    let mut aliased = intent.clone();
    aliased.actor_ref = aliased.person_ref;
    let err = vault
        .onboard_workspace_member(aliased, &writer(WRITER))
        .expect_err("an actor id aliased onto the member PERSON must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut mismatched = intent;
    mismatched.grant_bundle.companion_profile_grant_ref = Some(entity(PROFILE_GRANT));
    let err = vault
        .onboard_workspace_member(mismatched, &writer(WRITER))
        .expect_err("a profile grant ref without a companion birth must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
}
