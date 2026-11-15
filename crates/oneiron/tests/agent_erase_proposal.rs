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
//! Owners again what they declined (Astra review of #8340). A record
//! the agent's Grant does not read, and one that is not live, are refused
//! alike, and no one is asked. An agent the owner switched off asks nothing,
//! though its Grant still reads the record.
//!
//! On main every case fails at its first call: no verb row is named
//! `vault.records.erase_propose`, so the agent has no door to ask through
//! (the check-in preflight answers its erase `propose` and nothing takes it).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_erase_proposal`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EraseAskStatus, FederationGrantRole as Role, InitialSharedMember,
    NOTIFICATION_PRODUCER_ERASE_ASK, Scope, ScopeAxis,
};
use oneiron::inbox::NotificationKind;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{define_agent, write_root_goal};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use serde_json::{Value, json};

const PROPOSE: &str = "vault.records.erase_propose";
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
        let agent = define_agent(&self.vault).expect("an agent");
        let mut authority_scope = Scope::top();
        authority_scope.bands = ScopeAxis::Some(BTreeSet::from([self
            .vault
            .project_type_byte()
            .expect("project type")]));
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
