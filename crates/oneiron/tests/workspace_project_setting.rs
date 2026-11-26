//! RECALL-SESSION-PROJECT PR 1 (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q3 = A,
//! the binding is the owner's act and stores a hash plus a label; Engine NOTE 22:5x: the id is
//! keyed by the vault): the owner binds a folder, named by its digest, to a PROJECT. The vault
//! keys the digest with its own id into the folder's workspace id, the item of the family
//! Setting key `workspace.project`, and an attached session's folder digests resolve to that
//! project. Each row is one folder's own value (no itemless row, no pin), and the key is a
//! choice about this install: a binding never leaves the machine (review round 1 of #10550).
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
use oneiron::session_project::{
    WORKSPACE_PROJECT_KEY, WorkspaceBindRequest, WorkspaceUnbindRequest, is_digest_text,
};
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope, SettingSync, set_line,
    spec_named, widen_line, widen_scope_line,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// A folder's own digest (a linked worktree's checkout).
const WORKTREE_DIGEST: &str =
    "blake3:1f0e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// Its main checkout's digest.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const OTHER_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    /// The workspace id this vault keys `folder_digest` into.
    fn workspace_id(&self, folder_digest: &str) -> String {
        self.vault
            .workspace_id(folder_digest)
            .unwrap_or_else(|| panic!("{folder_digest} is a folder digest"))
    }

    /// `caller`'s own change of the row named `item`: `value`, or a clear for `None`.
    fn set(
        &self,
        caller: SettingCaller<'_>,
        item: &str,
        value: Option<Value>,
    ) -> oneiron::Result<SetSettingOutcome> {
        let mut change = SetSetting::vault_value(WORKSPACE_PROJECT_KEY, Value::Null);
        change.item = Some(item.to_owned());
        change.value = value;
        self.vault.set_setting(caller, change)
    }

    /// The owner's bind of the folder `folder_digest` to `project`, labelled `label`.
    fn bind(
        &self,
        folder_digest: &str,
        project: EntityId,
        label: &str,
    ) -> oneiron::Result<oneiron::session_project::WorkspaceBinding> {
        self.vault.bind_workspace_as_owner(
            &self.proof,
            Some(ActSurface::ThisInstall),
            WorkspaceBindRequest {
                folder_digest: folder_digest.to_owned(),
                project,
                label: Some(label.to_owned()),
            },
        )
    }

    /// The owner binds `folder_digest` to `project`, labelled `label`.
    fn owner_binds(&self, folder_digest: &str, project: EntityId, label: &str) {
        let binding = self
            .bind(folder_digest, project, label)
            .unwrap_or_else(|error| panic!("the owner binds {folder_digest}: {error}"));
        assert_eq!(binding.workspace_id, self.workspace_id(folder_digest));
        assert_eq!(
            binding.project,
            Some(project),
            "the answer names the project"
        );
        assert_eq!(binding.label.as_deref(), Some(label));
    }

    /// The project a session naming `folder_digests` reads by default.
    fn session_project(&self, folder_digests: &[&str]) -> Option<EntityId> {
        let folder_digests: Vec<String> = folder_digests
            .iter()
            .map(|digest| (*digest).to_owned())
            .collect();
        self.vault
            .workspace_project(&folder_digests)
            .expect("the folder's binding reads")
    }
}

#[test]
fn the_owner_binds_a_folder_and_its_session_reads_that_project() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        None,
        "a folder nobody bound selects no project"
    );
    fixture.owner_binds(MAIN_DIGEST, fixture.root_project, "alpha");
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        Some(fixture.root_project),
        "the bound folder selects its project"
    );
    assert_eq!(
        fixture.session_project(&[OTHER_DIGEST]),
        None,
        "another folder stays unbound"
    );
}

#[test]
fn a_linked_worktree_with_no_binding_of_its_own_reads_its_main_checkouts_project() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_DIGEST, fixture.root_project, "alpha");
    assert_eq!(
        fixture.session_project(&[WORKTREE_DIGEST, MAIN_DIGEST]),
        Some(fixture.root_project),
        "the worktree falls back to its main checkout's binding"
    );
}

#[test]
fn a_folders_own_binding_decides_before_its_main_checkouts() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_DIGEST, fixture.root_project, "alpha");
    // The worktree's own row names no project: the owner bound it to none.
    let outcome = fixture
        .set(
            SettingCaller::Owner(&fixture.proof),
            &fixture.workspace_id(WORKTREE_DIGEST),
            Some(json!({ "label": "alpha-fork" })),
        )
        .expect("the owner's unbound row for the worktree");
    assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
    assert_eq!(
        fixture.session_project(&[WORKTREE_DIGEST, MAIN_DIGEST]),
        Some(fixture.root_project),
        "a row that names no project binds nothing, so the main checkout's decides"
    );
}

#[test]
fn a_binding_must_name_a_live_project() {
    let fixture = Fixture::open();
    let not_a_project = EntityId::now();
    let refused = fixture.bind(MAIN_DIGEST, not_a_project, "alpha");
    let error = refused.expect_err("an id that names no PROJECT is refused");
    assert!(
        error.to_string().contains("is not a live PROJECT"),
        "the refusal names the reason: {error}"
    );
    assert_eq!(fixture.session_project(&[MAIN_DIGEST]), None);
}

#[test]
fn a_digest_that_is_not_one_is_refused() {
    let fixture = Fixture::open();
    for digest in [
        "alpha",
        "/srv/checkouts/alpha",
        &MAIN_DIGEST.to_uppercase(),
        &MAIN_DIGEST[..MAIN_DIGEST.len() - 1],
        // The hex alone, with no hash named: the SHA-256-shaped spelling.
        &MAIN_DIGEST["blake3:".len()..],
        &format!("sha256:{}", &MAIN_DIGEST["blake3:".len()..]),
    ] {
        assert!(!is_digest_text(digest), "{digest} is no digest");
        assert_eq!(fixture.vault.workspace_id(digest), None);
        let refused = fixture.bind(digest, fixture.root_project, "alpha");
        assert!(
            refused.is_err(),
            "binding {digest:?} is refused: {refused:?}"
        );
        let refused = fixture.set(
            SettingCaller::Owner(&fixture.proof),
            digest,
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        );
        assert!(
            refused.is_err(),
            "a row named by {digest:?} is refused: {refused:?}"
        );
    }
    assert!(is_digest_text(MAIN_DIGEST));
}

#[test]
fn the_workspace_id_is_the_digest_keyed_by_the_vault() {
    let first = Fixture::open();
    let second = Fixture::open();
    let id = first.workspace_id(MAIN_DIGEST);
    assert!(
        is_digest_text(&id),
        "a workspace id is `blake3:` and 64 lower-case hex: {id}"
    );
    assert_ne!(
        id, MAIN_DIGEST,
        "the vault never stores the client's digest as sent"
    );
    assert_eq!(
        id,
        first.workspace_id(MAIN_DIGEST),
        "one vault keys one folder the same way each time"
    );
    assert_ne!(
        id,
        second.workspace_id(MAIN_DIGEST),
        "two vaults key one folder apart, so its ids do not correlate across vaults"
    );
    assert_ne!(id, first.workspace_id(OTHER_DIGEST));
}

#[test]
fn a_binding_row_from_another_store_binds_nothing() {
    let first = Fixture::open();
    let second = Fixture::open();
    // The row another vault holds for the folder: named by the first vault's workspace id, and
    // naming a project that is live in the second vault.
    let outcome = second
        .set(
            SettingCaller::Owner(&second.proof),
            &first.workspace_id(MAIN_DIGEST),
            Some(json!({ "project": second.root_project.to_hex(), "label": "alpha" })),
        )
        .expect("the row is a well-formed item");
    assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
    assert_eq!(
        second.session_project(&[MAIN_DIGEST]),
        None,
        "a store with another id resolves the folder as unbound, never as another project"
    );
}

#[test]
fn a_row_named_by_the_bare_digest_binds_nothing() {
    let fixture = Fixture::open();
    let outcome = fixture
        .set(
            SettingCaller::Owner(&fixture.proof),
            MAIN_DIGEST,
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        )
        .expect("the row is a well-formed item");
    assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        None,
        "a session's digest reads the row its workspace id names, not one named by the digest"
    );
}

#[test]
fn a_binding_row_is_one_folders_own_value() {
    let fixture = Fixture::open();
    let binding = json!({ "project": fixture.root_project.to_hex(), "label": "alpha" });
    // A row with no item would bind every folder that has no row of its own.
    let mut itemless = SetSetting::vault_value(WORKSPACE_PROJECT_KEY, binding.clone());
    itemless.item = None;
    let error = fixture
        .vault
        .set_setting(SettingCaller::Owner(&fixture.proof), itemless)
        .expect_err("a row with no item is refused");
    assert!(
        error.to_string().contains("one folder's own value"),
        "the refusal names the reason: {error}"
    );
    assert_eq!(
        fixture.session_project(&[OTHER_DIGEST]),
        None,
        "no folder reads a project from a row with no item"
    );
    // A pinned row would outlast the bind and unbind verbs, which write the value.
    let mut pinned = SetSetting::vault_value(WORKSPACE_PROJECT_KEY, binding);
    pinned.item = Some(fixture.workspace_id(MAIN_DIGEST));
    pinned.mode = SettingMode::Pin;
    let error = fixture
        .vault
        .set_setting(SettingCaller::Owner(&fixture.proof), pinned)
        .expect_err("a pinned row is refused");
    assert!(
        error.to_string().contains("one folder's own value"),
        "the refusal names the reason: {error}"
    );
    assert_eq!(fixture.session_project(&[MAIN_DIGEST]), None);
}

#[test]
fn a_binding_is_a_choice_about_this_install() {
    let spec = spec_named(WORKSPACE_PROJECT_KEY).expect("the key is in the catalogue");
    assert_eq!(
        spec.sync,
        SettingSync::Install,
        "a binding never leaves its install: no other machine of the vault receives it, and a \
         restore drops it"
    );
}

#[test]
fn a_label_with_a_control_character_is_refused() {
    let fixture = Fixture::open();
    let refused = fixture.bind(MAIN_DIGEST, fixture.root_project, "alpha\nbeta");
    assert!(refused.is_err(), "the label is refused: {refused:?}");
    assert_eq!(fixture.session_project(&[MAIN_DIGEST]), None);
}

#[test]
fn the_owner_unbinds_a_folder() {
    let fixture = Fixture::open();
    fixture.owner_binds(MAIN_DIGEST, fixture.root_project, "alpha");
    let binding = fixture
        .vault
        .unbind_workspace_as_owner(
            &fixture.proof,
            Some(ActSurface::ThisInstall),
            &WorkspaceUnbindRequest {
                folder_digest: MAIN_DIGEST.to_owned(),
            },
        )
        .expect("the owner's unbind");
    assert_eq!(binding.workspace_id, fixture.workspace_id(MAIN_DIGEST));
    assert_eq!(binding.project, None, "the answer names no project");
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        None,
        "an unbound folder selects no project"
    );
}

/// An enabled agent with a live owner Grant naming `read`, `vault.settings.set` and the key's own
/// line: the most an agent can hold for this key.
fn key_holder(fixture: &Fixture) -> EntityId {
    agent_holding(fixture, &[set_line(WORKSPACE_PROJECT_KEY)])
}

/// An enabled agent with a live owner Grant naming `read`, `vault.settings.set` and `lines`.
fn agent_holding(fixture: &Fixture, lines: &[String]) -> EntityId {
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
    authority_scope.verbs = ScopeAxis::Some(
        ["read".to_owned(), "vault.settings.set".to_owned()]
            .into_iter()
            .chain(lines.iter().cloned())
            .collect(),
    );
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
            &fixture.workspace_id(MAIN_DIGEST),
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        )
        .expect("the agent's binding answers");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "an agent's binding waits on the owner's answer: {outcome:?}"
    );
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        None,
        "the folder stays unbound until the owner says yes"
    );
}

/// Review round 2 of #10550: the owner's standing approval does not cover the key. An agent whose
/// live owner Grant lists the key's widening line and the line of every key at the vault still
/// waits on the owner's answer to its binding, as Q3 = A rules (binding is the owner's act). On
/// the base its binding landed at once, as a standing widening.
#[test]
fn an_agent_with_the_owners_standing_approval_still_waits_for_the_owner() {
    let fixture = Fixture::open();
    let lines = [
        Some(widen_line(WORKSPACE_PROJECT_KEY)),
        widen_scope_line(&SettingScope::Vault),
    ];
    let agent = agent_holding(&fixture, &lines.into_iter().flatten().collect::<Vec<_>>());
    let outcome = fixture
        .set(
            SettingCaller::Agent(agent),
            &fixture.workspace_id(MAIN_DIGEST),
            Some(json!({ "project": fixture.root_project.to_hex(), "label": "alpha" })),
        )
        .expect("the agent's binding answers");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "a standing approval lands no binding: {outcome:?}"
    );
    assert_eq!(fixture.session_project(&[MAIN_DIGEST]), None);
}

/// Review round 2 of #10550: the owner's bind of the binding a row already holds is a change of
/// its own, so the key's check runs on it again (a PROJECT gone since is refused, never reported
/// bound). On the base the repeat answered as unchanged, with no change recorded and no check.
#[test]
fn the_owners_repeated_bind_records_a_change_and_is_checked_again() {
    let fixture = Fixture::open();
    let id = fixture.workspace_id(MAIN_DIGEST);
    let value = json!({ "project": fixture.root_project.to_hex(), "label": "alpha" });
    let first = fixture
        .set(
            SettingCaller::Owner(&fixture.proof),
            &id,
            Some(value.clone()),
        )
        .expect("the owner binds");
    let again = fixture
        .set(SettingCaller::Owner(&fixture.proof), &id, Some(value))
        .expect("the owner binds again");
    let sequence = |outcome: &SetSettingOutcome| match outcome {
        SetSettingOutcome::Applied { sequence, .. } => *sequence,
        other => panic!("the owner's bind applies: {other:?}"),
    };
    assert!(sequence(&first).is_some(), "the first bind is a change");
    assert!(
        sequence(&again).is_some_and(|again| Some(again) > sequence(&first)),
        "the repeat is a change of its own, checked again: {again:?}"
    );
    assert_eq!(
        fixture.session_project(&[MAIN_DIGEST]),
        Some(fixture.root_project)
    );
}
