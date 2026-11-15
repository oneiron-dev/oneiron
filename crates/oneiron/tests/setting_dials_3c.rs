//! DESIGN 15-setting-primitive, stage 2 (SETTING-DIALS D3c; Engine RULING 21:39
//! SETTING-DIALS-PURPOSE-DEFAULTS-POWERS = A): the inference defaults are one setting key,
//! `models.purpose_defaults`, set through the one door under DEC-0005's policy power.
//! - the owner's table lands, every reader reads it, and a clear brings back the shipped table;
//! - a person who holds the policy power over `settings.inference_defaults` (an Admin whose
//!   Owner-minted `policy.change` grant names its target) widens and narrows at once;
//! - a member without that power asks, and the defaults stay as they are;
//! - over a table the owner set, a policy holder's change asks (a key that reads one row keeps a
//!   holder clear of the owner's row);
//! - an agent holding the key's Grant line narrows at once and asks to widen, and an agent
//!   without the line asks for a narrowing too.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_3c`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis};
use oneiron::llm::{PurposeDefaultTable, purpose_default_grant_target};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, set_line};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{CallPurpose, EntityId, ModelLocality, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const KEY: &str = "models.purpose_defaults";
const SET: &str = "vault.settings.set";
const SHARED: u64 = 42;

/// The shipped table with extraction, and its bound, widened to the own server.
fn widened() -> PurposeDefaultTable {
    let mut table = PurposeDefaultTable::default();
    table.extraction_max_locality = ModelLocality::OwnServer;
    table
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("the extraction row")
        .locality = ModelLocality::OwnServer;
    table
}

/// The shipped table with consolidation narrowed from the own server to the device.
fn narrowed() -> PurposeDefaultTable {
    let mut table = PurposeDefaultTable::default();
    let row = table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .expect("the consolidation row");
    assert_eq!(row.locality, ModelLocality::OwnServer, "the shipped row");
    row.locality = ModelLocality::OnDevice;
    table
}

fn change(table: &PurposeDefaultTable) -> SetSetting {
    SetSetting::vault_value(KEY, serde_json::to_value(table).expect("the table as JSON"))
}

fn applied(outcome: SetSettingOutcome) {
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the change applies at once: {outcome:?}"
    );
}

fn pending(outcome: SetSettingOutcome) {
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "the change asks: {outcome:?}"
    );
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A shared vault whose roster holds its embedded owner as Owner and an Admin who accepted its
/// founding invitation.
struct Shared {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    admin: EntityId,
    admin_proof: AuthenticatedOwner,
}

impl Shared {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let admin = EntityId::now();
        vault
            .put_entity(
                &admin,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(Role::Owner),
                    },
                    InitialSharedMember {
                        member_ref: admin,
                        role: Some(Role::Admin),
                    },
                ],
                1,
            )
            .expect("a shared vault with an Admin");
        let admin_proof = proof(&vault, admin);
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED)
            .expect("the Admin's invitations")
            .into_iter()
            .find(|open| open.role == Role::Admin)
            .expect("the Admin's founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
            .expect("the Admin accepts");
        let owner_proof = proof(&vault, owner);
        Self {
            vault,
            _dir: dir,
            owner_proof,
            admin,
            admin_proof,
        }
    }

    /// The Owner's `policy.change` grant to the Admin, naming the inference defaults' target.
    fn give_policy_power(&self) {
        let bound = GrantBound::action(
            ActorBound::new(self.admin.to_hex())
                .expect("actor bound")
                .with_actor_class("human")
                .expect("a person's bound"),
            ActionClass::new("policy.change").expect("action class"),
            ActionEnvelope::new(["owner_policy_rows".to_owned()])
                .expect("envelope")
                .with_target(purpose_default_grant_target())
                .expect("the exact target"),
        )
        .expect("the policy.change bound");
        self.vault
            .create_standing_grant(&self.owner_proof, bound)
            .expect("the Owner mints the policy.change grant");
    }

    fn as_owner(&self, table: &PurposeDefaultTable) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), change(table))
            .expect("the owner's change")
    }

    fn as_admin(&self, table: &PurposeDefaultTable) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Person(&self.admin_proof), change(table))
            .expect("the Admin's change, applied or asked")
    }

    fn defaults(&self) -> PurposeDefaultTable {
        self.vault.purpose_default_table().expect("the defaults")
    }
}

#[test]
fn the_owner_sets_the_inference_defaults_as_one_setting_row_and_every_reader_reads_it() {
    let shared = Shared::new();
    applied(shared.as_owner(&widened()));
    assert_eq!(
        shared.defaults(),
        widened(),
        "the owner's table is in force"
    );
    let clear = SetSetting {
        value: None,
        ..change(&widened())
    };
    applied(
        shared
            .vault
            .set_setting(SettingCaller::Owner(&shared.owner_proof), clear)
            .expect("the owner's clear"),
    );
    assert_eq!(
        shared.defaults(),
        PurposeDefaultTable::default(),
        "a clear brings back the shipped table"
    );
}

#[test]
fn a_person_holding_the_policy_power_widens_and_narrows_the_defaults_at_once() {
    let shared = Shared::new();
    shared.give_policy_power();
    applied(shared.as_admin(&widened()));
    assert_eq!(
        shared.defaults(),
        widened(),
        "the holder's widening is in force"
    );
    applied(shared.as_admin(&narrowed()));
    assert_eq!(
        shared.defaults(),
        narrowed(),
        "the holder's narrowing is in force"
    );
}

#[test]
fn a_member_without_the_policy_power_asks_and_the_defaults_stay() {
    let shared = Shared::new();
    pending(shared.as_admin(&widened()));
    pending(shared.as_admin(&narrowed()));
    assert_eq!(
        shared.defaults(),
        PurposeDefaultTable::default(),
        "an ask moves nothing"
    );
}

#[test]
fn over_a_table_the_owner_set_a_policy_holder_asks() {
    let shared = Shared::new();
    shared.give_policy_power();
    applied(shared.as_owner(&widened()));
    pending(shared.as_admin(&PurposeDefaultTable::default()));
    assert_eq!(
        shared.defaults(),
        widened(),
        "the owner's table stays in force"
    );
}

/// A rooted vault with its install enrolled and its embedded owner bound.
struct Rooted {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Rooted {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let keystore = Arc::new(MemoryKeystore::new());
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = proof(&vault, owner);
        Self {
            vault,
            _dir: dir,
            owner_proof,
        }
    }

    /// An enabled agent with an Auto ceiling, whose live owner Grant names `read` and `verbs`.
    fn agent(&self, verbs: &[&str]) -> EntityId {
        let agent = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("defaults-agent-{}", agent.to_hex()),
                    "desc": "purpose defaults fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        agent
    }

    fn as_agent(&self, agent: EntityId, table: &PurposeDefaultTable) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Agent(agent), change(table))
            .expect("the agent's change, applied or asked")
    }
}

#[test]
fn an_agent_holding_the_keys_line_narrows_at_once_and_asks_to_widen() {
    let rooted = Rooted::new();
    let defaults = || rooted.vault.purpose_default_table().expect("the defaults");
    let unlined = rooted.agent(&[SET]);
    pending(rooted.as_agent(unlined, &narrowed()));
    assert_eq!(
        defaults(),
        PurposeDefaultTable::default(),
        "an agent without the line asks, even to narrow"
    );

    let lined = rooted.agent(&[SET, &set_line(KEY)]);
    pending(rooted.as_agent(lined, &widened()));
    assert_eq!(
        defaults(),
        PurposeDefaultTable::default(),
        "the widening waits on the user"
    );
    applied(rooted.as_agent(lined, &narrowed()));
    assert_eq!(defaults(), narrowed(), "the narrowing is in force");
}
