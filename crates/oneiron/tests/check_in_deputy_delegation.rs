//! ROLES-CHECKIN P2.4a, piece 2g (ARCH-0082 #roles and #composing; Engine
//! ruling P24-SHAPE Q1 and Q2 = A, 13 Nov 19:32): a Deputy's role comes from
//! its live membership row, and its delegated Owner powers are the
//! Owner-issued agent Grant it holds. No new grant kind and no per-Grant
//! mode row: the Deputy runs the Deputy column of the role table.
//!
//! The house of a stored workspace, the seeded `sys.default` agent, is bound
//! to the shared vault at a role (its membership row), and the Owner mints it
//! a Grant that names verbs (its powers). `vault.check_in.preflight` then
//! answers from the verb row's act class, the house's membership role and
//! the Grant:
//!
//! - a Deputy house asks when unsure on a member add its Grant names (and
//!   waits, since no decision model is sure), always asks on a member
//!   remove, and asks the Owner on a vault delete, a catastrophe row;
//! - without the named power it is absent, may still propose an erase, and
//!   goes on reversible work its Grant names;
//! - an agent with no membership row reads its Grant's own role, Delegate,
//!   and so does a house at the Owner role: an agent's own proof as Owner
//!   comes with agent Owner keys (canon's PR 4).
//!
//! On the base (P2.3c) the first case fails at its first assert: the house
//! reads its Grant's role, Delegate, so a named member add always asks
//! (`always_ask`, mode `manual`). The other cases hold on the base too; they
//! guard the cells this change must not move.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_deputy_delegation`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const PREFLIGHT: &str = "vault.check_in.preflight";
/// `member_add`: a Deputy asks when unsure; a Delegate holds it only as an
/// extra power, and then always asks.
const MEMBER_ADD: &str = "vault.members.add";
/// `member_remove`: a Deputy always asks.
const MEMBER_REMOVE: &str = "vault.members.remove";
/// `vault_delete`: a catastrophe row, so every role but the Owner asks.
const VAULT_DELETE: &str = "vault.shared.propose_delete";
/// `erase`: any role may propose it.
const ERASE: &str = "vault.records.erase_confirm";
/// `reversible_work`: a Deputy goes.
const REVERSIBLE: &str = "vault.projects.goal.propose";

const WORKSPACE: &str = "check-in-deputy-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 43;

/// A shared vault whose workspace house is bound at one role.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_proof: AuthenticatedOwner,
    house: EntityId,
}

impl Org {
    /// A vault as a host starts one (rooted under the host, the owner bound,
    /// the root signed once, this install profiled to carry the owner's
    /// Grant acts), its shared vault, and the stored workspace whose house,
    /// `sys.default`, the owner binds at `role`.
    fn with_house_at(role: FederationGrantRole) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let signer = vault
            .owner_project_signer(&issuer)
            .expect("the owner's project signer");
        let root = vault.root_project().expect("the root project");
        vault
            .sign_owner_project(&owner_proof, &signer, root)
            .expect("the root's first signature");
        let org = EntityId::now();
        vault
            .put_entity(
                &org,
                ENTITY_TYPE_ORG,
                TimeRange { start: 1, end: 1 },
                1,
                b"check-in deputy org",
            )
            .expect("org row");
        vault
            .initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())
            .expect("the owner initializes the shared vault");
        let (house, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: VAULT_ID,
            org_ref: org,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        };
        vault
            .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)
            .expect("the owner stores the workspace");
        vault
            .bind_workspace_house_leader(WORKSPACE, role, &owner_proof, &signer)
            .expect("the owner binds the house");
        Self {
            _dir: dir,
            vault,
            owner_proof,
            house,
        }
    }

    /// An enabled, active agent definition the owner creates, with no
    /// membership row.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("check-in-deputy-agent-{}", id.to_hex()),
                    "desc": "check-in deputy fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's live Grant for `agent` naming `read` and `verbs` over
    /// every world.
    fn grant(&self, agent: EntityId, verbs: &[&str]) {
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
    }

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// `memory`'s preflight of `verb`'s act at the vault scope over the effect
/// `byte`.
fn preflight(memory: &Memory<'_>, verb: &str, byte: u8) -> Value {
    invoke(
        memory,
        PREFLIGHT,
        json!({ "verb": verb, "effect_digest": digest(byte) }),
    )
    .unwrap_or_else(|error| panic!("{PREFLIGHT} of {verb} answers: {error:?}"))
}

/// A wait with no open ask, as preflight answers it.
fn wait(reason: &str, act_class: &str, mode: &str) -> Value {
    json!({ "outcome": "wait", "reason": reason, "act_class": act_class, "mode": mode,
            "handle": null })
}

#[test]
fn a_deputy_house_reads_the_deputy_column_for_the_acts_its_grant_names() {
    let org = Org::with_house_at(FederationGrantRole::Deputy);
    org.grant(org.house, &[MEMBER_ADD, MEMBER_REMOVE, VAULT_DELETE]);
    let house = org.as_agent(org.house);
    assert_eq!(
        preflight(&house, MEMBER_ADD, 0x71),
        wait("unsure", "member_add", "auto"),
        "a Deputy asks when unsure on a member add its Grant names, and no decision model \
         is sure, so it waits"
    );
    assert_eq!(
        preflight(&house, MEMBER_REMOVE, 0x72),
        wait("always_ask", "member_remove", "manual"),
        "a Deputy always asks on a member remove"
    );
    assert_eq!(
        preflight(&house, VAULT_DELETE, 0x73),
        wait("always_ask", "vault_delete", "manual"),
        "a vault delete is a catastrophe row: a Deputy asks the Owner and never acts on its \
         own proof"
    );
}

#[test]
fn a_deputy_house_without_the_named_power_is_absent_and_may_propose_an_erase() {
    let org = Org::with_house_at(FederationGrantRole::Deputy);
    org.grant(org.house, &[REVERSIBLE]);
    let house = org.as_agent(org.house);
    assert_eq!(
        preflight(&house, MEMBER_ADD, 0x81),
        json!({ "outcome": "absent", "why": "no live owner Grant of the caller lists the verb" }),
        "the membership row gives the role, never the power: no Grant names the member add"
    );
    assert_eq!(
        preflight(&house, ERASE, 0x82),
        json!({ "outcome": "propose", "act_class": "erase" }),
        "any role may propose an erase"
    );
    assert_eq!(
        preflight(&house, REVERSIBLE, 0x83),
        json!({ "outcome": "go", "reason": "never_ask", "act_class": "reversible_work" }),
        "a Deputy goes on reversible work its Grant names"
    );
}

#[test]
fn an_agent_with_no_membership_and_an_owner_house_read_the_grants_own_role() {
    let org = Org::with_house_at(FederationGrantRole::Owner);
    let agent = org.agent();
    org.grant(agent, &[MEMBER_ADD]);
    assert_eq!(
        preflight(&org.as_agent(agent), MEMBER_ADD, 0x91),
        wait("always_ask", "member_add", "manual"),
        "no membership row: the Grant's own role, Delegate, holds the member add only as an \
         extra power, which always asks"
    );
    org.grant(org.house, &[MEMBER_ADD, VAULT_DELETE]);
    let house = org.as_agent(org.house);
    assert_eq!(
        preflight(&house, MEMBER_ADD, 0x92),
        wait("always_ask", "member_add", "manual"),
        "a house at the Owner role reads its Grant's role until agents hold Owner keys"
    );
    assert_eq!(
        preflight(&house, VAULT_DELETE, 0x93),
        wait("always_ask", "vault_delete", "manual"),
        "an agent never acts on its own proof as Owner here: the vault delete asks"
    );
}
