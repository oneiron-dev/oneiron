//! One-vault mode reads and the joining notice through public engine doors,
//! and one test door that stops an onboarding half way.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test workspace_one_vault_mode`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::access_grant::AccessGrant;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantPreset, FederationGrantRole};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::{PersonSubstrate, anchor_actor_subject};
use oneiron::test_doors::stored_workspace_roster_rows::rewrite_workspace_rows_before_one_vault;
use oneiron::test_doors::workspace_onboarding_halt::onboard_workspace_member_halting_after;
use oneiron::workspace_roster::{
    CompanionChoice, MemberGrantBundle, MemberOnboardingIntent, MemberOnboardingStep, OneVaultMode,
    OneVaultSetting, OneVaultSource, WorkspaceRosterPreset,
};
use oneiron::{
    CompanionBirthIntent, EntityId, ErrorKind, TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKSPACE: &str = "one-vault-mode-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const VAULT_ID: u64 = 41;
const VENTURE: &str = "Garden Works";
const GET_VERB: &str = "vault.workspace.one_vault.get";

fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes())
        .expect("a fresh v7 uuid is not a reserved id")
}

fn seed_row(vault: &Vault, entity_type: u8, body: &[u8]) -> TestResult<EntityId> {
    let id = fresh_id();
    vault.put_entity(
        &id,
        entity_type,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        body,
    )?;
    Ok(id)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "one-vault mode fixture",
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
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    org: EntityId,
    house: EntityId,
}

fn setup() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let org = seed_row(&vault, ENTITY_TYPE_ORG, b"one-vault mode org")?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        owner_proof,
        org,
        house,
    })
}

fn preset(fixture: &Fixture) -> WorkspaceRosterPreset {
    WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: fixture.org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: fixture.house,
        house_identity_ref: None,
    }
}

/// Keeps encoding failures separate from the Owner door's refusal.
fn install_one_vault(fixture: &Fixture, row: Value) -> TestResult<oneiron::Result<()>> {
    let policy = json!({
        "schema_version": "1.2",
        "pack_id": "one-vault-mode-test",
        "pack_version": "1.0.0",
        "min_engine_version": "0.0.0",
        "defaults": {},
        "rules": [],
        "actor_ceilings": [],
        "one_vault": row,
    });
    let bytes = rmp_serde::to_vec_named(&policy)?;
    Ok(fixture.vault.install_owner_policy_manifest(
        &fixture.owner_proof,
        fresh_id(),
        bytes,
        fixture.vault.now_recorded_at(),
    ))
}

fn get_via_verb(
    fixture: &Fixture,
    member: EntityId,
) -> Result<Value, oneiron::memory::MemoryError> {
    let memory = fixture.vault.memory(member, EdgeActorClass::Human);
    oneiron::verbs::invoke(&memory, GET_VERB, json!({ "workspace_ref": WORKSPACE }))
}

/// Establishes the workspace preset required by the read verb.
fn onboard_owen_work(
    fixture: &Fixture,
    onboarding_id: &str,
) -> TestResult<(EntityId, oneiron::MemberOnboardingOutcome)> {
    let member = seed_row(&fixture.vault, ENTITY_TYPE_PERSON, b"owen")?;
    let member_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"owen work facet")?;
    let companion_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"owen companion facet")?;
    let profile_grant = fresh_id();
    let intent = MemberOnboardingIntent {
        onboarding_id: onboarding_id.to_owned(),
        workspace: preset(fixture),
        person_ref: member,
        actor_ref: fresh_id(),
        actor_definition: definition("garden.member"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: fresh_id(),
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: fresh_id(),
            actor_ref: fresh_id(),
            work_facet_ref: companion_facet,
            profile_grant_ref: profile_grant,
            actor_definition: definition("garden.companion"),
            display_name: "yuki".to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: fixture.vault.now_recorded_at(),
    };
    let outcome = fixture.vault.onboard_workspace_member(
        intent,
        &WriteActor::new(fixture.owner, EdgeActorClass::Human),
        None,
    )?;
    Ok((member, outcome))
}

/// Writes yuki's model-backed companion with an anchored actor and a
/// profile-read grant, and the intent that brings it; onboards nothing.
fn yuki_bring_intent(
    fixture: &Fixture,
    onboarding_id: &str,
) -> TestResult<(EntityId, EntityId, MemberOnboardingIntent)> {
    let yuki = seed_row(&fixture.vault, ENTITY_TYPE_PERSON, b"yuki")?;
    let member_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"yuki work facet")?;
    let companion_person = seed_row(
        &fixture.vault,
        ENTITY_TYPE_PERSON,
        b"yuki companion owen@example.com",
    )?;
    let companion_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"yuki companion facet")?;
    let companion_actor = fresh_id();
    fixture.vault.define_agent(
        &companion_actor,
        &definition("yuki.companion"),
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    let writer = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    fixture.vault.set_person_substrate(
        companion_person,
        PersonSubstrate::Model,
        &writer,
        fixture.vault.now_recorded_at(),
    )?;
    anchor_actor_subject(
        &fixture.vault,
        companion_actor,
        companion_person,
        writer,
        fixture.vault.now_recorded_at(),
    )?;
    fixture.vault.create_access_grant(
        &fresh_id(),
        &AccessGrant::companion_profile_read(
            yuki,
            companion_person,
            None,
            fixture.vault.now_recorded_at(),
        ),
    )?;
    let member_proof =
        fixture
            .vault
            .authenticate_owner(yuki, &yuki.to_hex(), true, GateDecisionId::now())?;
    let intent = MemberOnboardingIntent {
        onboarding_id: onboarding_id.to_owned(),
        workspace: preset(fixture),
        person_ref: yuki,
        actor_ref: fresh_id(),
        actor_definition: definition("garden.member"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: fresh_id(),
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: None,
        },
        companion: CompanionChoice::Bring {
            person: companion_person,
            actor: companion_actor,
            work_facet: companion_facet,
            proof: member_proof,
        },
        delegated_mailbox: None,
        occurred_at: fixture.vault.now_recorded_at(),
    };
    Ok((yuki, companion_actor, intent))
}

/// Brings a model-backed companion with an anchored actor and a profile-read grant.
fn onboard_yuki_bring(
    fixture: &Fixture,
    onboarding_id: &str,
) -> TestResult<(EntityId, EntityId, oneiron::MemberOnboardingOutcome)> {
    let (yuki, companion_actor, intent) = yuki_bring_intent(fixture, onboarding_id)?;
    let outcome = fixture.vault.onboard_workspace_member(
        intent,
        &WriteActor::new(fixture.owner, EdgeActorClass::Human),
        None,
    )?;
    Ok((yuki, companion_actor, outcome))
}

#[test]
fn one_vault_mode_reads_off_without_a_row_and_on_after_the_owner_installs_it() -> TestResult {
    let fixture = setup()?;
    let (owen, _) = onboard_owen_work(&fixture, "one-vault-read-owen")?;
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::Off),
            source: OneVaultSource::Default,
        }
    );
    let first = get_via_verb(&fixture, owen)?;
    assert_eq!(first["mode"], json!("off"));
    assert_eq!(first["source"], json!("default"));

    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::On),
            source: OneVaultSource::Row,
        }
    );
    let second = get_via_verb(&fixture, owen)?;
    assert_eq!(second["mode"], json!("on"));
    assert_eq!(second["source"], json!("row"));
    Ok(())
}

#[test]
fn a_malformed_one_vault_row_makes_the_manifest_unreadable() -> TestResult {
    let fixture = setup()?;
    let (owen, _) = onboard_owen_work(&fixture, "one-vault-malformed-owen")?;
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::Off),
            source: OneVaultSource::Default,
        }
    );
    let before = get_via_verb(&fixture, owen)?;
    assert_eq!(before["mode"], json!("off"));
    assert_eq!(before["source"], json!("default"));

    // The Owner door refuses the malformed row at install, as it refuses a
    // malformed `inquiry` row: the whole manifest decode fails, nothing is
    // stored, and the read still answers the old setting.
    let installed = install_one_vault(&fixture, json!({ "version": 1, "mode": "maybe" }))?;
    assert!(
        matches!(installed, Err(oneiron::Error::InvalidConfig(_))),
        "a malformed one_vault row is refused at install as a malformed manifest: {installed:?}"
    );
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::Off),
            source: OneVaultSource::Default,
        }
    );
    let after = get_via_verb(&fixture, owen)?;
    assert_eq!(after["mode"], json!("off"));
    assert_eq!(after["source"], json!("default"));
    Ok(())
}

#[test]
fn onboarding_under_one_vault_mode_tells_the_member() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::On),
            source: OneVaultSource::Row,
        }
    );

    let (yuki, companion_actor, outcome) = onboard_yuki_bring(&fixture, "one-vault-on-yuki")?;
    assert!(
        outcome.one_vault,
        "the joining client shows line 2 one-vault"
    );
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    let entry = roster
        .iter()
        .find(|entry| entry.principal_ref == Some(yuki))
        .ok_or("yuki roster entry")?;
    assert_eq!(entry.actor_ref, companion_actor);
    assert_eq!(entry.one_vault_told, Some(outcome.completed_at));
    let entry_json = serde_json::to_value(entry)?;
    assert_eq!(entry_json["one_vault_told"], json!(outcome.completed_at));
    let got = get_via_verb(&fixture, yuki)?;
    assert_eq!(got["mode"], json!("on"));
    assert_eq!(got["source"], json!("row"));
    Ok(())
}

#[test]
fn onboarding_without_the_row_tells_the_member_plain_line_two() -> TestResult {
    let fixture = setup()?;
    let (yuki, companion_actor, outcome) = onboard_yuki_bring(&fixture, "one-vault-off-yuki")?;
    assert!(!outcome.one_vault, "the joining client shows plain line 2");
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    let entry = roster
        .iter()
        .find(|entry| entry.principal_ref == Some(yuki))
        .ok_or("yuki roster entry")?;
    assert_eq!(entry.actor_ref, companion_actor);
    assert_eq!(entry.one_vault_told, None, "no told mark without the row");
    let entry_json = serde_json::to_value(entry)?;
    assert!(entry_json["one_vault_told"].is_null());
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: Some(OneVaultMode::Off),
            source: OneVaultSource::Default,
        }
    );
    let got = get_via_verb(&fixture, yuki)?;
    assert_eq!(got["mode"], json!("off"));
    assert_eq!(got["source"], json!("default"));
    Ok(())
}

#[test]
fn conflicting_one_vault_rows_read_unreadable_and_refuse_the_joining_member() -> TestResult {
    let fixture = setup()?;
    let (owen, _) = onboard_owen_work(&fixture, "one-vault-conflict-owen")?;
    let writer = WriteActor::new(fixture.owner, EdgeActorClass::Human);

    // yuki's onboarding passes its grant step while the setting still reads;
    // only her Complete step is left for after the rows conflict.
    let (yuki, _, resumed_intent) = yuki_bring_intent(&fixture, "one-vault-conflict-yuki")?;
    let halted = onboard_workspace_member_halting_after(
        &fixture.vault,
        resumed_intent.clone(),
        &writer,
        None,
        MemberOnboardingStep::MailboxBound,
    )?;
    assert!(halted.is_none(), "the onboarding stops before Complete");
    // A second member starts joining only after the rows conflict.
    let (late_member, _, late_intent) =
        yuki_bring_intent(&fixture, "one-vault-conflict-late-member")?;

    // Two trusted Owner manifests name different rows: no deterministic
    // mode, so the policy fails closed and no mode is answered.
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "off" }))??;
    assert_eq!(
        fixture.vault.one_vault_mode()?,
        OneVaultSetting {
            mode: None,
            source: OneVaultSource::Unreadable,
        }
    );
    let got = get_via_verb(&fixture, owen)?;
    assert!(
        got["mode"].is_null(),
        "an unreadable setting answers no mode"
    );
    assert_eq!(got["source"], json!("unreadable"));

    // A fresh joining stops earlier: its grant step's default policy fails
    // closed on the same conflict.
    let late = fixture
        .vault
        .onboard_workspace_member(late_intent, &writer, None);
    assert!(
        late.is_err(),
        "a fresh onboarding refuses under conflicting rows"
    );

    // The resumed Complete step refuses rather than guess the joining line.
    let refused = fixture
        .vault
        .onboard_workspace_member(resumed_intent, &writer, None);
    let error =
        refused.expect_err("the resumed onboarding refuses under an unreadable one_vault row");
    assert!(
        matches!(error.kind(), ErrorKind::OneVaultSettingUnreadable),
        "the refusal names the unreadable setting: {error}"
    );
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    assert!(
        roster
            .iter()
            .all(|entry| entry.principal_ref != Some(yuki)
                && entry.principal_ref != Some(late_member)),
        "a refused member has no roster row"
    );
    Ok(())
}

#[test]
fn rows_stored_before_one_vault_mode_read_and_their_member_reads_as_not_told() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    let (yuki, companion_actor, intent) =
        yuki_bring_intent(&fixture, "stored-rows-before-one-vault-yuki")?;
    let writer = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let outcome = fixture
        .vault
        .onboard_workspace_member(intent.clone(), &writer, None)?;
    assert!(
        outcome.one_vault,
        "the head initially tells the joining member"
    );
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    let entry = roster
        .iter()
        .find(|entry| entry.principal_ref == Some(yuki))
        .ok_or("yuki roster entry before rewriting stored rows")?;
    assert_eq!(entry.one_vault_told, Some(outcome.completed_at));
    let entry_json = serde_json::to_value(entry)?;
    assert_eq!(entry_json["one_vault_told"], json!(outcome.completed_at));

    rewrite_workspace_rows_before_one_vault(
        &fixture.vault,
        WORKSPACE,
        yuki,
        &intent.onboarding_id,
    )?;

    // This public read decodes the stored preset before the stored member.
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    assert_eq!(
        roster.len(),
        2,
        "the preset's house and the member's companion"
    );
    let house = roster
        .iter()
        .find(|entry| entry.principal_ref.is_none())
        .ok_or("house roster entry from the stored preset")?;
    assert_eq!(house.actor_ref, fixture.house);
    assert_eq!(house.subject_ref, fixture.org);
    assert_eq!(house.display_name, VENTURE);
    let entry = roster
        .iter()
        .find(|entry| entry.principal_ref == Some(yuki))
        .ok_or("yuki roster entry after rewriting stored rows")?;
    assert_eq!(entry.actor_ref, companion_actor);
    assert_eq!(entry.one_vault_told, None);
    let entry_json = serde_json::to_value(entry)?;
    assert_eq!(entry_json["one_vault_told"], Value::Null);

    // The exact same request reads its completed journal, not Complete again.
    let replay = fixture
        .vault
        .onboard_workspace_member(intent, &writer, None)?;
    assert_eq!(replay.onboarding_id, outcome.onboarding_id);
    assert_eq!(replay.person_ref, yuki);
    assert_eq!(replay.companion_actor_ref, Some(companion_actor));
    assert_eq!(replay.completed_at, outcome.completed_at);
    assert!(!replay.one_vault, "the stored member has no told mark");
    let got = get_via_verb(&fixture, yuki)?;
    assert_eq!(got["mode"], json!("on"), "the current setting is still on");
    assert_eq!(got["source"], json!("row"));
    Ok(())
}
