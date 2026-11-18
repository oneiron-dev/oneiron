//! An agent may open an erase proposal (UNBUILT-05; the lead's
//! AGENT-ERASE-ASK-SCOPE = B, 15 Nov 20:1x; ARCH-0082 #role-defaults: "Any
//! actor, in any role, may open an erase proposal. Erase stays a C row.").
//! `vault.records.erase_propose` takes the agent's ask on its own live owner
//! Grant whose read reaches the record:
//! - in a personal vault, one inbox ask to the owner naming the record;
//! - in a shared vault, the erase ask the person door writes, the agent its
//!   asker, with the same inbox ask to every live Owner.
//!
//! The ask erases nothing, and asking again answers the same ask; in a shared
//! vault an ask the Owner declined answers too, so the agent does not ask the
//! Owners again what they declined. A record the agent's Grant does not read,
//! and one that is not live, are refused alike, and no one is asked; a record
//! only the owner's policy reads to the agent is outside its own Grant and is
//! refused too (Astra review of #8340), and so is a record outside the facets
//! its own Grant reads, on every admission path (Astra delta review of #8340,
//! D1). An agent the owner switched off asks nothing, though its Grant still
//! reads the record.
//!
//! On main every case fails at its first call: no verb row is named
//! `vault.records.erase_propose`, so the agent has no door to ask through
//! (the check-in preflight answers its erase `propose` and nothing takes it).
//!
//! The personal vault's ask offers its owner one tap, the record's erase
//! preview, while the record is live, and none once it is erased (FIX
//! AGENT-ERASE-PROPOSAL-INBOX-TAP). On main after #8340 that case fails at
//! its first assertion: the ask offers no tap.
//!
//! The record that case erases is a child project with its own live goal: the
//! owner's erase retires the goal with the project it tears, and recreates
//! nothing (FIX ROOT-PROJECT-ERASE-REPUT-REFUSED). On main the confirm fails:
//! the goal's retirement re-puts the project after its hard-delete marker, and
//! the put guard refuses that id. The root project is the vault itself
//! (ARCH-0067) and no delete door takes it: its ask offers no erase preview,
//! the preview and the delete rail refuse it before any writer commits (a
//! privacy erase's audience-edit write included), and it stays with its
//! goal. On main its ask offers the preview, which its erase then fails
//! behind.
//!
//! A project another live project names as its parent refuses a hard delete
//! before any writer commits, so its erase leaves it readable with its child
//! (round-2 P1 of #9494). On main the owner's erase publishes the tombstone
//! and its read fence, the purge then refuses, and the parent stays fenced:
//! the case fails where the parent should still read. A new project never
//! names a parent whose hard delete published; on main its put stands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_erase_proposal`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::federation::{
    EraseAskStatus, FederationGrantRole as Role, InitialSharedMember,
    NOTIFICATION_PRODUCER_ERASE_ASK, Scope, ScopeAxis, ScopeId,
};
use oneiron::inbox::NotificationKind;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{
    define_agent, fence_row_for_hard_delete, last_committed_txn_id, write_project_goal,
    write_root_goal,
};
use oneiron::test_doors::derive::grant_core_read_of_kinds;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{
    AgentGrantMintRequest, OwnerConfirmPreviewRequest, RecordEraseConfirmRequest,
    confirm_record_erase, mint_agent_grant_as, preview_owner_confirm,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use serde_json::{Value, json};

const PROPOSE: &str = "vault.records.erase_propose";
/// The tap a personal vault's erase ask offers its owner: the one-way
/// confirm preview of the owner's own erase.
const PREVIEW: &str = "vault.owner_confirm.preview";
/// The owner's erase the preview shows, and its confirm then calls.
const ERASE_CONFIRM: &str = "vault.records.erase_confirm";
/// The inbox producer of a personal vault's agent erase ask.
const PERSONAL_PRODUCER: &str = "vault.erase_proposal";
const SHARED: u64 = 42;

/// A vault, its owner's id and proof, its root project, and the project's
/// goal claim.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    project: EntityId,
    goal_claim: EntityId,
}

impl Fixture {
    /// A personal vault; with `shared`, first made the shared vault
    /// `SHARED` with its owner as its one Owner.
    fn new(shared: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
        let owner_proof = owner(&vault).expect("owner proof");
        let owner = vault.ensure_embedded_owner_actor().expect("owner id");
        if shared {
            vault
                .initialize_shared_vault(
                    &owner_proof,
                    SHARED,
                    None,
                    &[InitialSharedMember {
                        member_ref: owner,
                        role: Some(Role::Owner),
                    }],
                    1,
                )
                .expect("a shared vault");
        }
        let project = write_root_goal(&vault, &owner_proof).expect("goal");
        let goal_claim = EntityId::from_hex(
            vault
                .project(project)
                .expect("project read")
                .expect("root project")
                .goal
                .as_deref()
                .expect("goal claim pointer"),
        )
        .expect("goal claim id");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            project,
            goal_claim,
        }
    }

    /// A fresh agent holding the owner's live `read` Grant over projects
    /// alone: it reads the project, not its goal claim.
    fn project_reader(&self) -> EntityId {
        self.reader_of(self.vault.project_type_byte().expect("project type"))
    }

    /// A fresh agent holding the owner's live `read` Grant over rows of type
    /// `band` alone.
    fn reader_of(&self, band: u8) -> EntityId {
        self.reader_of_in(band, ScopeAxis::All)
    }

    /// A fresh agent holding the owner's live `read` Grant over rows of type
    /// `band` placed in `facets` alone.
    fn reader_of_in(&self, band: u8, facets: ScopeAxis<ScopeId>) -> EntityId {
        let agent = define_agent(&self.vault).expect("an agent");
        let mut authority_scope = Scope::top();
        authority_scope.bands = ScopeAxis::Some(BTreeSet::from([band]));
        authority_scope.facets = facets;
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner's read Grant");
        assert!(minted.grant.confers, "the Grant confers");
        agent
    }

    /// A child project of the root with its own live goal: a project the
    /// owner may erase, as the root project never is.
    fn child_project_with_goal(&self) -> EntityId {
        let root = self.vault.root_project().expect("the root project");
        let project = EntityId::now();
        let record =
            ProjectRecord::new(project, Some(root), root, self.owner).expect("a project record");
        self.vault
            .put_project(project, &record, self.vault.now_recorded_at())
            .expect("the child project");
        write_project_goal(&self.vault, &self.owner_proof, project)
            .expect("the child project's goal");
        project
    }

    /// The owner's put of a new project under `parent`, and its id.
    fn put_project_under(&self, parent: EntityId) -> (EntityId, oneiron::Result<()>) {
        let root = self.vault.root_project().expect("the root project");
        let project = EntityId::now();
        let record =
            ProjectRecord::new(project, Some(parent), root, self.owner).expect("a project record");
        let put = self
            .vault
            .put_project(project, &record, self.vault.now_recorded_at());
        (project, put)
    }

    /// The taps each of the owner's personal erase asks offers.
    fn owner_erase_taps(&self) -> Vec<Value> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| {
                row.kind == NotificationKind::Ask && row.source.producer == PERSONAL_PRODUCER
            })
            .map(|row| serde_json::to_value(&row.actions).expect("the row's taps"))
            .collect()
    }

    fn propose(&self, agent: EntityId, record: EntityId) -> oneiron::memory::MemoryResult<Value> {
        invoke(
            &self.vault.memory(agent, EdgeActorClass::Agent),
            PROPOSE,
            json!({ "record": record.to_hex() }),
        )
    }

    /// The owner's inbox asks from `producer`, as (subject refs, result).
    fn owner_asks(&self, producer: &str) -> Vec<(Vec<String>, Option<String>)> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| row.kind == NotificationKind::Ask && row.source.producer == producer)
            .map(|row| (row.subject_refs, row.source.result))
            .collect()
    }
}

#[test]
fn an_agent_with_read_opens_an_erase_proposal() {
    let fx = Fixture::new(false);
    let agent = fx.project_reader();
    let answer = fx
        .propose(agent, fx.project)
        .expect("the agent asks to erase a record it reads");
    assert_eq!(
        answer,
        json!({ "record": fx.project.to_hex(), "kind": "request", "shared_ask": null }),
        "a Delegate's request in a personal vault, with no shared ask"
    );
    let asked = vec![(vec![fx.project.to_hex()], Some(fx.project.to_hex()))];
    assert_eq!(
        fx.owner_asks(PERSONAL_PRODUCER),
        asked,
        "the owner holds one inbox ask naming the record"
    );

    let again = fx.propose(agent, fx.project).expect("the agent asks again");
    assert_eq!(again, answer, "asking again answers the same ask");
    assert_eq!(
        fx.owner_asks(PERSONAL_PRODUCER),
        asked,
        "and puts no second inbox ask"
    );
    assert!(
        fx.vault
            .project(fx.project)
            .expect("project read")
            .is_some(),
        "the ask erases nothing"
    );
}

#[test]
fn a_switched_off_agent_cannot_open_an_erase_proposal() {
    let fx = Fixture::new(false);
    let agent = fx.project_reader();
    let mut off = fx
        .vault
        .get_agent_definition(&agent)
        .expect("read the definition")
        .expect("the agent's definition");
    off.enabled = false;
    off.version = "2".to_owned();
    fx.vault
        .update_agent_definition_as(
            &fx.owner_proof,
            &agent,
            &off,
            TimeRange { start: 2, end: 2 },
            2,
        )
        .expect("the owner switches the agent off");
    let refused = fx
        .propose(agent, fx.project)
        .expect_err("a switched-off agent asks nothing, though its Grant still reads the record");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        fx.owner_asks(PERSONAL_PRODUCER).is_empty(),
        "and no one is asked"
    );
}

#[test]
fn an_agent_without_read_cannot_open_an_erase_proposal() {
    let fx = Fixture::new(false);
    let agent = fx.project_reader();
    let unread = fx
        .propose(agent, fx.goal_claim)
        .expect_err("the Grant does not read the goal claim");
    assert_eq!(unread.code, MEMORY_CODE_FORBIDDEN, "{unread:?}");
    let absent = fx
        .propose(agent, EntityId::now())
        .expect_err("no live record has the id");
    assert_eq!(
        (absent.code.as_str(), absent.message.as_str()),
        (unread.code.as_str(), unread.message.as_str()),
        "an unread record and an absent one answer alike"
    );
    let ungranted = define_agent(&fx.vault).expect("an agent with no Grant");
    let bare = fx
        .propose(ungranted, fx.project)
        .expect_err("no live owner Grant reads the record");
    assert_eq!(bare.code, MEMORY_CODE_FORBIDDEN, "{bare:?}");
    assert!(
        fx.owner_asks(PERSONAL_PRODUCER).is_empty(),
        "no one is asked"
    );
}

#[test]
fn an_agent_cannot_propose_a_record_only_the_policy_reads_to_it() {
    let fx = Fixture::new(false);
    // Its own owner Grant reads claims alone; the owner's policy also reads
    // projects to it, so its plain read lane admits the project.
    let agent = fx.reader_of(ENTITY_TYPE_CLAIM);
    grant_core_read_of_kinds(
        &fx.vault,
        agent,
        &[fx.vault.project_type_byte().expect("project type")],
    )
    .expect("the owner's policy reads projects to the agent");
    let refused = fx
        .propose(agent, fx.project)
        .expect_err("a record no live owner Grant of the agent reads");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        fx.owner_asks(PERSONAL_PRODUCER).is_empty(),
        "and no one is asked"
    );
}

#[test]
fn an_agent_cannot_propose_a_record_outside_its_grant_facets() {
    let fx = Fixture::new(false);
    // Its own owner Grant reads projects, but only those placed in a facet
    // the project is not in; every other axis of the Grant covers the
    // project. The read through the agent's own Grant (its identity key has
    // no credential and no room) judges the record's position, which names
    // no facet, so it must also hold the row to the Grant's facets (Astra
    // delta review of #8340, D1). The first test is this agent with every
    // facet: it asks.
    let elsewhere = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    let agent = fx.reader_of_in(
        fx.vault.project_type_byte().expect("project type"),
        elsewhere,
    );
    let refused = fx
        .propose(agent, fx.project)
        .expect_err("a record outside the facets its own Grant reads");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        fx.owner_asks(PERSONAL_PRODUCER).is_empty(),
        "and no one is asked"
    );
}

#[test]
fn an_agent_in_a_shared_vault_opens_the_shared_erase_ask() {
    let fx = Fixture::new(true);
    let agent = fx.project_reader();
    let answer = fx
        .propose(agent, fx.project)
        .expect("the agent asks to erase a record it reads");
    let ask = &answer["shared_ask"];
    assert_eq!(
        (
            answer["kind"].as_str(),
            ask["asker"].as_str(),
            ask["record"].as_str(),
            ask["status"].as_str(),
        ),
        (
            Some("request"),
            Some(agent.to_hex().as_str()),
            Some(fx.project.to_hex().as_str()),
            Some("open"),
        ),
        "the shared vault's erase ask, the agent its asker: {answer}"
    );
    let listed = fx
        .vault
        .shared_erase_asks(&fx.owner_proof, SHARED)
        .expect("the Owner reads the asks");
    assert_eq!(
        listed
            .iter()
            .map(|open| open.id.as_str())
            .collect::<Vec<_>>(),
        vec![ask["id"].as_str().expect("ask id")],
        "the Owner lists it with the person door's asks"
    );
    assert_eq!(
        fx.owner_asks(NOTIFICATION_PRODUCER_ERASE_ASK),
        vec![(
            vec![fx.project.to_hex()],
            ask["id"].as_str().map(str::to_owned)
        )],
        "the Owner holds the shared erase ask's inbox ask"
    );
    assert!(
        fx.owner_asks(PERSONAL_PRODUCER).is_empty(),
        "and no personal vault ask"
    );
    let again = fx.propose(agent, fx.project).expect("the agent asks again");
    assert_eq!(again, answer, "asking again answers the open ask");
}

#[test]
fn an_agent_does_not_ask_again_what_the_owner_declined() {
    let fx = Fixture::new(true);
    let agent = fx.project_reader();
    let answer = fx
        .propose(agent, fx.project)
        .expect("the agent asks to erase a record it reads");
    let id = answer["shared_ask"]["id"]
        .as_str()
        .expect("the shared ask's id")
        .to_owned();
    fx.vault
        .close_shared_erase_ask(&fx.owner_proof, &id, false, None)
        .expect("the Owner declines the ask");
    let again = fx.propose(agent, fx.project).expect("the agent asks again");
    assert_eq!(
        again["shared_ask"]["id"].as_str(),
        Some(id.as_str()),
        "the declined ask answers: {again}"
    );
    let listed = fx
        .vault
        .shared_erase_asks(&fx.owner_proof, SHARED)
        .expect("the Owner reads the asks");
    assert_eq!(listed.len(), 1, "no second ask is opened: {listed:?}");
    assert!(
        matches!(listed[0].status, EraseAskStatus::Declined { .. }),
        "the one ask stays declined: {listed:?}"
    );
    assert_eq!(
        fx.owner_asks(NOTIFICATION_PRODUCER_ERASE_ASK).len(),
        1,
        "and the Owner is not asked again"
    );
}

#[test]
fn the_owners_ask_offers_the_erase_preview_until_the_record_is_erased() {
    let fx = Fixture::new(false);
    let project = fx.child_project_with_goal();
    let agent = fx.project_reader();
    fx.propose(agent, project)
        .expect("the agent asks to erase a record it reads");
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let offered = fx.owner_erase_taps();
    assert_eq!(
        offered,
        vec![json!([{
            "verb": PREVIEW,
            "args": { "verb": ERASE_CONFIRM, "input": { "record": project.to_hex() } },
        }])],
        "the owner's ask offers the record's erase preview"
    );
    let input: OwnerConfirmPreviewRequest = serde_json::from_value(offered[0][0]["args"].clone())
        .expect("the tap's args are the preview verb's own input");
    let shown = preview_owner_confirm(&owner, &fx.owner_proof, input)
        .expect("the owner previews the erase");
    assert_eq!(shown.verb, ERASE_CONFIRM, "the preview of the erase");
    assert_eq!(
        shown
            .takes
            .as_ref()
            .and_then(|takes| takes["record"].as_str()),
        Some(project.to_hex().as_str()),
        "of the record the agent named"
    );
    let confirm: RecordEraseConfirmRequest = serde_json::from_value(json!({
        "record": project.to_hex(),
        "confirm": shown.confirm,
    }))
    .expect("the confirm input");
    confirm_record_erase(&owner, &fx.owner_proof, confirm)
        .expect("the owner erases the record on their own proof");
    assert_eq!(
        fx.owner_erase_taps(),
        vec![json!([])],
        "the ask stays, and an erased record offers no tap"
    );
}

#[test]
fn the_owners_ask_offers_no_erase_of_the_root_project_and_no_door_takes_it() {
    let fx = Fixture::new(false);
    let agent = fx.project_reader();
    fx.propose(agent, fx.project)
        .expect("the agent asks to erase the root project it reads");
    assert_eq!(
        fx.owner_erase_taps(),
        vec![json!([])],
        "the owner's ask offers no erase of the root project"
    );
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let input: OwnerConfirmPreviewRequest = serde_json::from_value(json!({
        "verb": ERASE_CONFIRM,
        "input": { "record": fx.project.to_hex() },
    }))
    .expect("the preview input");
    preview_owner_confirm(&owner, &fx.owner_proof, input)
        .expect_err("the root project previews no erase");
    let committed = last_committed_txn_id(&fx.vault);
    for reason in [DeleteReason::OwnerErase, DeleteReason::GdprDelete] {
        let refused = fx
            .vault
            .delete_entity_with_reason(&fx.project, reason)
            .expect_err("the delete rail refuses the root project");
        assert!(
            refused.to_string().contains("cannot delete root project"),
            "the rail refuses it as the root ({reason:?}): {refused}"
        );
    }
    assert_eq!(
        last_committed_txn_id(&fx.vault),
        committed,
        "before any writer commits, a privacy erase's included"
    );
    assert_eq!(
        fx.vault
            .project(fx.project)
            .expect("project read")
            .expect("the root project stays")
            .goal
            .as_deref(),
        Some(fx.goal_claim.to_hex().as_str()),
        "with its goal"
    );
}

#[test]
fn a_project_with_a_live_child_refuses_its_erase_before_any_writer_and_stays_readable() {
    let fx = Fixture::new(false);
    let parent = fx.child_project_with_goal();
    let (child, put) = fx.put_project_under(parent);
    put.expect("the parent's live child");
    let committed = last_committed_txn_id(&fx.vault);
    for reason in [DeleteReason::OwnerErase, DeleteReason::GdprDelete] {
        let refused = fx
            .vault
            .delete_entity_with_reason(&parent, reason)
            .expect_err("the delete rail refuses a project with a live child");
        assert!(
            refused.to_string().contains("project has live children"),
            "the rail refuses it for its child ({reason:?}): {refused}"
        );
    }
    assert_eq!(
        last_committed_txn_id(&fx.vault),
        committed,
        "before any writer commits"
    );
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let input: OwnerConfirmPreviewRequest = serde_json::from_value(json!({
        "verb": ERASE_CONFIRM,
        "input": { "record": parent.to_hex() },
    }))
    .expect("the preview input");
    if let Ok(shown) = preview_owner_confirm(&owner, &fx.owner_proof, input) {
        let confirm: RecordEraseConfirmRequest = serde_json::from_value(json!({
            "record": parent.to_hex(),
            "confirm": shown.confirm,
        }))
        .expect("the confirm input");
        confirm_record_erase(&owner, &fx.owner_proof, confirm)
            .expect_err("the owner's erase of a project with a live child refuses");
    }
    assert!(
        fx.vault.get(&parent).expect("the parent's read").is_some(),
        "the parent still reads: no publication fenced it"
    );
    assert!(
        fx.vault.project(parent).expect("project read").is_some(),
        "the parent project stays"
    );
    assert!(
        fx.vault.project(child).expect("project read").is_some(),
        "with its child"
    );
}

#[test]
fn no_new_project_names_a_parent_whose_hard_delete_published() {
    let fx = Fixture::new(false);
    let parent = fx.child_project_with_goal();
    fence_row_for_hard_delete(&fx.vault, parent).expect("the parent's publication fence");
    let (child, put) = fx.put_project_under(parent);
    let refused = put.expect_err("a new child of a fenced parent refuses");
    assert!(
        refused.to_string().contains("parent project is deleted"),
        "the put refuses it for its fenced parent: {refused}"
    );
    assert!(
        fx.vault.project(child).expect("project read").is_none(),
        "and no child stands"
    );
}
