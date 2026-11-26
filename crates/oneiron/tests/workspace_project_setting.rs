//! RECALL-SESSION-PROJECT PR 1 (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q3 = A,
//! the binding is the owner's act and stores a hash plus a label): the owner binds a folder to a
//! PROJECT with the family Setting key `workspace.project`, one item per folder named by its
//! workspace id (64 lower-case hex, the SHA-256 of the folder's canonical checkout path), and an
//! attached session's folder ids resolve to that project.
//!
//! Red on the base: the Setting primitive has no `workspace.project` key and the engine no
//! `session_project` module, so this file does not build there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! workspace_project_setting`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::session_project::{WORKSPACE_PROJECT_KEY, is_workspace_id};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, set_line};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// A folder's own workspace id (a linked worktree's checkout).
const WORKTREE_ID: &str = "1f0e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// Its main checkout's workspace id.
const MAIN_ID: &str = "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const OTHER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One rooted vault, seeded with its root PROJECT, and its owner's proof. The vault drops
/// first.
struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    root_project: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("seeded vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[0x5a; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let root_project = vault.root_project().expect("the seeded root PROJECT");
        Self {
            vault,
            proof,
            root_project,
            _dir: dir,
        }
    }

    /// `caller`'s change of the row for `workspace`: `value`, or a clear for `None`.
    fn set(
        &self,
        caller: SettingCaller<'_>,
        workspace: &str,
        value: Option<Value>,
    ) -> oneiron::Result<SetSettingOutcome> {
        let mut change = SetSetting::vault_value(WORKSPACE_PROJECT_KEY, Value::Null);
        change.item = Some(workspace.to_owned());
        change.value = value;
        self.vault.set_setting(caller, change)
    }

    /// The owner binds `workspace` to `project`, labelled `label`.
    fn owner_binds(&self, workspace: &str, project: EntityId, label: &str) {
        let outcome = self
            .set(
                SettingCaller::Owner(&self.proof),
                workspace,
                Some(json!({ "project": project.to_hex(), "label": label })),
            )
            .unwrap_or_else(|error| panic!("the owner binds {workspace}: {error}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's binding applies at once: {outcome:?}"
        );
    }

    /// The project a session naming `ids` reads by default.
    fn session_project(&self, ids: &[&str]) -> Option<EntityId> {
        let ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
        self.vault
            .workspace_project(&ids)
            .expect("the folder's binding reads")
    }
}

#[test]
fn the_owner_binds_a_folder_and_its_session_reads_that_project() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.session_project(&[MAIN_ID]),
        None,
        "a folder nobody bound selects no project"
    );
    fixture.owner_binds(MAIN_ID, fixture.root_project, "alpha");
    assert_eq!(
        fixture.session_project(&[MAIN_ID]),
        Some(fixture.root_project),
        "the bound folder selects its project"
    );
    assert_eq!(
        fixture.session_project(&[OTHER_ID]),
        None,
        "another folder stays unbound"
    );
}

#[test]
fn a_linked_worktree_with_no_binding_of_its_own_reads_its_main_checkouts_project() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_ID, fixture.root_project, "alpha");
    assert_eq!(
        fixture.session_project(&[WORKTREE_ID, MAIN_ID]),
        Some(fixture.root_project),
        "the worktree falls back to its main checkout's binding"
    );
}

#[test]
fn a_folders_own_binding_decides_before_its_main_checkouts() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_ID, fixture.root_project, "alpha");
    // The worktree's own row names no project: the owner bound it to none.
    let outcome = fixture
        .set(
            SettingCaller::Owner(&fixture.proof),
            WORKTREE_ID,
            Some(json!({ "label": "alpha-fork" })),
        )
        .expect("the owner's unbound row for the worktree");
    assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
    assert_eq!(
        fixture.session_project(&[WORKTREE_ID, MAIN_ID]),
        Some(fixture.root_project),
        "a row that names no project binds nothing, so the main checkout's decides"
    );
}

#[test]
fn a_binding_must_name_a_live_project() {
    let fixture = Fixture::open();
    let not_a_project = EntityId::now();
    let refused = fixture.set(
        SettingCaller::Owner(&fixture.proof),
        MAIN_ID,
        Some(json!({ "project": not_a_project.to_hex(), "label": "alpha" })),
    );
    let error = refused.expect_err("an id that names no PROJECT is refused");
    assert!(
        error.to_string().contains("is not a live PROJECT"),
        "the refusal names the reason: {error}"
    );
    assert_eq!(fixture.session_project(&[MAIN_ID]), None);
}

#[test]
fn an_item_that_is_not_a_workspace_id_is_refused() {
    let fixture = Fixture::open();
    for item in [
        "alpha",
        "/srv/checkouts/alpha",
        &MAIN_ID.to_uppercase(),
        &MAIN_ID[..63],
    ] {
        assert!(!is_workspace_id(item), "{item} is no workspace id");
        let refused = fixture.set(
            SettingCaller::Owner(&fixture.proof),
            item,
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        );
        assert!(
            refused.is_err(),
            "a row named by {item:?} is refused: {refused:?}"
        );
    }
    assert!(is_workspace_id(MAIN_ID));
}

#[test]
fn a_label_with_a_control_character_is_refused() {
    let fixture = Fixture::open();
    let refused = fixture.set(
        SettingCaller::Owner(&fixture.proof),
        MAIN_ID,
        Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha\nbeta" })),
    );
    assert!(refused.is_err(), "the label is refused: {refused:?}");
    assert_eq!(fixture.session_project(&[MAIN_ID]), None);
}

#[test]
fn the_owner_unbinds_a_folder() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_ID, fixture.root_project, "alpha");
    let outcome = fixture
        .set(SettingCaller::Owner(&fixture.proof), MAIN_ID, None)
        .expect("the owner's clear");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's clear applies at once: {outcome:?}"
    );
    assert_eq!(
        fixture.session_project(&[MAIN_ID]),
        None,
        "an unbound folder selects no project"
    );
}

/// An enabled agent with a live owner Grant naming `read`, `vault.settings.set` and the key's own
/// line: the most an agent can hold for this key.
fn key_holder(fixture: &Fixture) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": format!("workspace-binder-{}", agent.to_hex()),
                "desc": "Workspace project key test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("the owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "vault.settings.set".to_owned(),
        set_line(WORKSPACE_PROJECT_KEY),
    ]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the agent a Grant");
    assert!(minted.grant.confers, "the Grant confers");
    agent
}

#[test]
fn an_agents_binding_waits_for_the_owner_and_binds_nothing() {
    let fixture = Fixture::open();
    let agent = key_holder(&fixture);
    let outcome = fixture
        .set(
            SettingCaller::Agent(agent),
            MAIN_ID,
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        )
        .expect("the agent's binding answers");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "an agent's binding waits on the owner's answer: {outcome:?}"
    );
    assert_eq!(
        fixture.session_project(&[MAIN_ID]),
        None,
        "the folder stays unbound until the owner says yes"
    );
}
