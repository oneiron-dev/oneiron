//! ONE-1832 workspace roster + member onboarding tests.
//!
//! Every fixture name here is invented BY THE TEST. If a display name in an
//! assertion also appeared in `workspace_roster.rs`, the "names are runtime
//! data" contract would already be broken.

use super::*;

mod authorization;
mod companion_requirement;
mod current_architecture;
mod onboarding_replay;
use current_architecture::{assert_mailbox_lifecycle_receipt, register_mailbox_custody};

use crate::agent_def::{AgentCeiling, AgentScope};
use crate::channel_identity_autonomy::{ChannelIdentityActionEnvelope, MailboxReadEnvelope};
use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor,
    ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult,
};
use crate::channel_identity_selection::RelationshipContext;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::{ErrorKind, RecordError};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::test_util::{entity, open_test_vault_with};

const VAULT_ID: u64 = 7;
const AT: u64 = 1_700_000_000;

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
        channel: "email".to_owned(),
        address: "member@example.test".to_owned(),
        custody_name: "custody/member-mailbox".to_owned(),
        scopes: vec![DelegatedGrantScope::MailRead],
        autonomy: ChannelIdentityAutonomyRequest::draft_only(
            entity(MEMBER_ACTOR),
            MailboxReadEnvelope {
                identity_ref: entity(MAILBOX_IDENTITY),
                label_allowlist: vec!["inbox".to_owned()],
                thread_allowlist: vec!["thread:1".to_owned()],
                not_before: Some(AT),
                not_after: Some(AT + 60),
            },
            ChannelIdentityActionEnvelope {
                identity_ref: entity(MAILBOX_IDENTITY),
                relationship_context: RelationshipContext::WorkDeal,
                counterparty_class: Some("known".to_owned()),
                max_actions: 3,
                window_secs: 86_400,
            },
        ),
    }
}

fn mailbox_owner(vault: &Vault) -> Result<AuthenticatedOwner> {
    vault.authenticate_owner(
        entity(MEMBER_PERSON),
        &entity(MEMBER_PERSON).to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
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
            companion_profile_grant_ref: Some(entity(PROFILE_GRANT)),
        },
        companion_birth: Some(companion_birth()),
        delegated_mailbox: None,
        occurred_at: AT,
    }
}

/// Seeds the entities every onboarding references plus the writer's admin grant.
fn fixture(venture_name: &str) -> (tempfile::TempDir, Vault, MemberOnboardingIntent) {
    let (dir, vault) = test_vault();
    seed_plain(&vault, WRITER, ENTITY_TYPE_PERSON);
    seed_plain(&vault, OUTSIDER, ENTITY_TYPE_PERSON);
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
    for venture_name in ["Antevon", "Oneiron"] {
        let (_dir, vault, intent) = fixture(venture_name);
        vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
        let roster = vault.workspace_roster("antevon-slack", AT)?;
        let house = roster
            .iter()
            .find(|entry| entry.role == WorkspaceRosterRole::HouseMind)
            .expect("house mind row");
        assert_eq!(house.display_name, venture_name);
        // Done-means 1: the house mind stands behind the workspace ORG.
        assert_eq!(house.subject_ref, entity(ORG));
    }
    Ok(())
}

/// Done-means 3: exactly `(Member, Member)`, and an asked-for widening is a
/// typed refusal rather than a silent downgrade.
#[test]
fn member_bundle_never_widens_to_admin() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let outcome = vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;

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
            .onboard_workspace_member(widened, &writer(WRITER), None)
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

    let outcome = vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
    assert_eq!(outcome.companion_person_ref, Some(birth.person_ref));
    assert_eq!(outcome.companion_actor_ref, Some(birth.actor_ref));

    // A PERSON, not a new kind, and made of model.
    assert_eq!(
        vault.get_entity_type(&birth.person_ref)?,
        Some(ENTITY_TYPE_PERSON)
    );
    assert_eq!(
        person_substrate(&vault, &birth.person_ref, AT)?,
        Some(PersonSubstrate::Model)
    );

    // Its own actor, anchored to itself; no ACTOR entity kind anywhere.
    assert_eq!(
        vault.get_entity_type(&birth.actor_ref)?,
        Some(ENTITY_TYPE_AGENT_DEF)
    );
    assert_eq!(
        actor_subject_anchor(&vault, &birth.actor_ref, AT)?,
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
    let roster = vault.workspace_roster("antevon-slack", AT)?;
    assert_eq!(roster.len(), 2);
    let companion_row = roster
        .iter()
        .find(|row| {
            row.role == WorkspaceRosterRole::PrincipalCompanion
                && row.principal_ref == Some(entity(MEMBER_PERSON))
        })
        .expect("principal's companion row");
    assert_eq!(companion_row.actor_ref, birth.actor_ref);
    assert_eq!(companion_row.subject_ref, birth.person_ref);
    assert_eq!(companion_row.facet_ref, Some(birth.work_facet_ref));
    assert_eq!(companion_row.display_name, birth.display_name);
    Ok(())
}

/// Done-means 5: the mailbox row carries a custody NAME and read scopes. The
/// intent has no field a token could occupy, so the stored body cannot hold one.
#[test]
fn optional_delegated_mailbox_uses_custody_ref_only() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    intent.delegated_mailbox = Some(requested.clone());

    register_mailbox_custody(&vault, &requested, &requested.address)?;
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER), Some(&mailbox_owner(&vault)?))
        .expect_err("Requested lifecycle cannot complete autonomy");
    assert!(matches!(
        err,
        Error::Record(RecordError::WorkspaceMailboxAutonomyNotReady { identity_ref, requested_mode })
            if identity_ref == requested.identity_ref && requested_mode == requested.autonomy.rung.as_str()
    ));

    let identity = vault
        .get_channel_identity(&requested.identity_ref)?
        .expect("delegated identity");
    assert!(identity.is_delegated());
    assert_eq!(
        identity.binding,
        ChannelIdentityBinding::agent(entity(MEMBER_ACTOR)),
        "the member's actor holds the mailbox"
    );
    assert_eq!(identity.state, ChannelIdentityState::Requested);
    assert!(!identity.may_send());
    let grant = identity.grant.expect("custody handle");
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
    assert!(!body.contains("test-only-oauth-bytes"));
    Ok(())
}

/// Done-means 3: authority is a stored grant, and an unprivileged caller is
/// refused before the journal exists at all.
#[test]
fn unprivileged_writer_rejected() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");

    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(OUTSIDER), None)
        .expect_err("an unprivileged writer must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // No journal, no actor, no grant: the refusal left no trace to resume from.
    assert!(read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.is_none());
    assert_eq!(vault.get_entity_type(&entity(MEMBER_ACTOR))?, None);
    assert_eq!(vault.get_entity_type(&entity(MEMBER_GRANT))?, None);
    assert!(vault.workspace_roster("antevon-slack", AT)?.is_empty());

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
        .onboard_workspace_member(intent, &writer(OUTSIDER), None)
        .expect_err("a member-grade writer must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

/// A second workspace_ref cannot claim a preset that disagrees with the stored
/// one, and a second member joins the same workspace without disturbing it.
#[test]
fn workspace_preset_is_settled_once_and_shared() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;

    let mut conflicting = intent.clone();
    conflicting.onboarding_id = "onboard-2".to_owned();
    conflicting.workspace.venture_name = "Different Venture".to_owned();
    conflicting.person_ref = seed_plain(&vault, 0xB9, ENTITY_TYPE_PERSON);
    conflicting.actor_ref = entity(0xBA);
    conflicting.grant_bundle.federation_grant_ref = entity(0xBB);
    let err = vault
        .onboard_workspace_member(conflicting, &writer(WRITER), None)
        .expect_err("a disagreeing preset must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut second = intent;
    second.onboarding_id = "onboard-2".to_owned();
    second.person_ref = entity(0xB9);
    second.actor_ref = entity(0xBA);
    second.grant_bundle.federation_grant_ref = entity(0xBB);
    let mut second_birth = companion_birth();
    second_birth.person_ref = entity(0xD1);
    second_birth.actor_ref = entity(0xD2);
    second_birth.companion_record_ref = entity(0xD3);
    second_birth.profile_grant_ref = entity(0xD4);
    second_birth.actor_definition = definition("fixture.second_companion");
    second_birth.display_name = "Silverleaf".to_owned();
    second.grant_bundle.companion_profile_grant_ref = Some(second_birth.profile_grant_ref);
    second.companion_birth = Some(second_birth.clone());
    let outcome = vault.onboard_workspace_member(second, &writer(WRITER), None)?;
    assert_eq!(outcome.person_ref, entity(0xB9));

    // Each principal has their own quiz-named companion beside the same house.
    let roster = vault.workspace_roster("antevon-slack", AT)?;
    assert_eq!(roster.len(), 3);
    assert_eq!(roster[0].role, WorkspaceRosterRole::HouseMind);
    for (principal, birth) in [
        (entity(MEMBER_PERSON), companion_birth()),
        (entity(0xB9), second_birth),
    ] {
        let row = roster
            .iter()
            .find(|row| row.principal_ref == Some(principal))
            .expect("one companion per principal");
        assert_eq!(row.subject_ref, birth.person_ref);
        assert_eq!(row.actor_ref, birth.actor_ref);
        assert_eq!(row.display_name, birth.display_name);
    }
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
        .onboard_workspace_member(aliased, &writer(WRITER), None)
        .expect_err("an actor id aliased onto the member PERSON must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    let mut mismatched = intent;
    mismatched.grant_bundle.companion_profile_grant_ref = Some(entity(0xD5));
    let err = vault
        .onboard_workspace_member(mismatched, &writer(WRITER), None)
        .expect_err("a mismatched companion profile grant ref must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
}

fn mailbox_fixture() -> Result<(
    tempfile::TempDir,
    Vault,
    MemberOnboardingIntent,
    AuthenticatedOwner,
)> {
    let (dir, vault, mut intent) = fixture("Antevon");
    seed_mailbox_bind_policy(&vault)?;
    let requested = mailbox();
    register_mailbox_custody(&vault, &requested, &requested.address)?;
    intent.delegated_mailbox = Some(requested);
    let owner = mailbox_owner(&vault)?;
    Ok((dir, vault, intent, owner))
}

fn seed_mailbox_bind_policy(vault: &Vault) -> Result<()> {
    // The legacy fixture removes the default policy. Without a persisted policy,
    // reopen reseeds one and invalidates the frontier hash on prior draft grants.
    let manifest = serde_json::json!({
        "schema_version": "1.1",
        "pack_id": "roster-mailbox-test",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [
            {"actor_class": "human", "actor_ref": entity(WRITER).to_hex(), "ceiling": "auto"},
            {"actor_class": "human", "actor_ref": entity(MEMBER_PERSON).to_hex(), "ceiling": "auto"}
        ],
        "scoped_grants": [{
            "actor_class": "human", "actor_ref": entity(MEMBER_PERSON).to_hex(),
            "effector": "external:bind", "scope": {"channel": "email"}
        }]
    });
    let bytes = rmp_serde::to_vec_named(&manifest).expect("fixture policy");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn mailbox_bind_request(
    identity: EntityId,
    owner: &AuthenticatedOwner,
) -> ChannelIdentityLifecycleRequest {
    ChannelIdentityLifecycleRequest {
        actor: ChannelIdentityLifecycleActor {
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.actor().to_hex()),
            actor_entity_ref: Some(owner.actor()),
        },
        gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
        requested_at: AT + 1,
        intent: ChannelIdentityLifecycleIntent::Bind(BindIntent {
            identity_id: identity,
            fulfillment_mode: crate::channel_identity::ChannelIdentityFulfillment::Manual,
        }),
    }
}

fn bind_mailbox(vault: &Vault, identity: EntityId) -> Result<()> {
    let request = mailbox_bind_request(identity, &mailbox_owner(vault)?);
    let result = vault.apply_channel_identity_lifecycle_intent(request)?;
    assert_eq!(result.outcome, "pending_fulfillment");
    assert_eq!(
        result
            .identity
            .as_ref()
            .expect("identity")
            .pending_fulfillment,
        Some(crate::channel_identity::ChannelIdentityFulfillment::Manual)
    );
    assert_mailbox_lifecycle_receipt(vault, identity, &result, "bind", Some("allow"))
}

fn fulfill_mailbox(vault: &Vault, identity: EntityId) -> Result<()> {
    // This represents external manual completion by a trusted host. The actor
    // attributes the marker; fulfillment itself does not authenticate an owner.
    let result = vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
        actor: mailbox_bind_request(identity, &mailbox_owner(vault)?).actor,
        identity_id: identity,
        fulfilled_at: AT + 2,
    })?;
    assert_eq!(result.outcome, "active");
    assert_eq!(
        result
            .identity
            .as_ref()
            .expect("identity")
            .pending_fulfillment,
        None
    );
    assert_mailbox_lifecycle_receipt(vault, identity, &result, "fulfill", None)
}

fn activate_mailbox(vault: &Vault, identity: EntityId) -> Result<()> {
    bind_mailbox(vault, identity)?;
    fulfill_mailbox(vault, identity)
}

fn assert_mailbox_waiting(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    owner: &AuthenticatedOwner,
) -> Result<OnboardingJournal> {
    let mailbox = intent.delegated_mailbox.as_ref().expect("mailbox");
    let error = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER), Some(owner))
        .expect_err("external fulfillment is still required");
    assert!(matches!(
        error,
        Error::Record(RecordError::WorkspaceMailboxAutonomyNotReady { identity_ref, requested_mode })
            if identity_ref == mailbox.identity_ref && requested_mode == mailbox.autonomy.rung.as_str()
    ));
    let journal = read_journal(vault, &onboarding_key(&intent.onboarding_id))?.expect("journal");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    assert_eq!(
        vault
            .workspace_roster(&intent.workspace.workspace_ref, AT)?
            .len(),
        1
    );
    assert!(
        !vault
            .get_channel_identity(&mailbox.identity_ref)?
            .expect("identity")
            .may_send()
    );
    assert_eq!(type_count(vault, ENTITY_TYPE_ACCESS_GRANT), 1);
    assert_eq!(
        type_count(vault, crate::registry::ENTITY_TYPE_OUTBOUND_GRANT),
        0
    );
    Ok(journal)
}
