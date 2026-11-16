//! The room-add check-in tests' shared fixture (`check_in_room_add.rs`,
//! ROLES-CHECKIN P2.6a): a rooted vault whose project home room seats the
//! owner, a person and three agents, and a private thread on the room's
//! trunk whose audience is the owner and two of the agents: `agent`, whose
//! Grant lists both add verbs, and `ungranted`, whose Grant lists neither.
//! `seeker` and the person stay out of the thread.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING, Memory, MemoryError,
    MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::workspace_roster::{
    ProjectRecord, ThreadAudienceAddRequest, ThreadAudienceHistory, ThreadAudienceReceipt,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

pub(crate) const ADD: &str = "vault.rooms.thread_audience.add";
pub(crate) const APPROVE: &str = "vault.rooms.thread_join.approve";

pub(crate) struct Org {
    _dir: tempfile::TempDir,
    pub(crate) vault: Vault,
    pub(crate) owner: EntityId,
    /// In the thread; its Grant lists both add verbs.
    pub(crate) agent: EntityId,
    /// In the thread; its Grant lists neither.
    pub(crate) ungranted: EntityId,
    /// In the room, out of the thread.
    pub(crate) seeker: EntityId,
    /// A person in the room, out of the thread.
    pub(crate) member: EntityId,
    pub(crate) room: EntityId,
    pub(crate) anchor: EntityId,
    pub(crate) thread: EntityId,
}

impl Org {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let member = EntityId::now();
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        let [agent, ungranted, seeker] =
            std::array::from_fn(|_| create_agent(&vault, &owner_proof));
        // The roster is set before the project's birth, and the birth
        // before the vault is rooted.
        let root = vault.root_project().expect("root project");
        let project = EntityId::now();
        let mut record =
            ProjectRecord::new(project, Some(root), root, owner).expect("a project record");
        record
            .roster
            .extend([member, agent, ungranted, seeker].map(|id| id.to_hex()));
        vault
            .put_project(project, &record, vault.now_recorded_at())
            .expect("the project");
        let room = EntityId::from_hex(&record.home_room).expect("home room id");
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        grant(&vault, &owner_proof, agent, &[ADD, APPROVE]);
        grant(&vault, &owner_proof, ungranted, &[]);
        let org = Self {
            _dir: dir,
            vault,
            owner,
            agent,
            ungranted,
            seeker,
            member,
            room,
            anchor: EntityId::now(),
            thread: EntityId::now(),
        };
        org.speak(org.anchor, None);
        org.speak(org.thread, Some(BTreeSet::from([owner, agent, ungranted])));
        org
    }

    /// The owner's witness turn `turn` in the room, one MESSAGE: the trunk
    /// turn, or with `audience` the root of a private thread on the trunk.
    pub(crate) fn speak(&self, turn: EntityId, audience: Option<BTreeSet<EntityId>>) {
        let mut metadata = serde_json::Map::new();
        if audience.is_some() {
            metadata.insert("room_thread_of".into(), self.anchor.to_hex().into());
        }
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&WitnessTurn {
                conversation_ref: self.room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: audience,
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "a turn of the room".into(),
                    parts: None,
                    metadata: Some(serde_json::Value::Object(metadata)),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.vault.now_recorded_at(),
                assertions: Default::default(),
            })
            .expect("the owner speaks");
    }

    pub(crate) fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// `memory`'s add of `person` to the thread.
    pub(crate) fn add(
        &self,
        memory: &Memory<'_>,
        person: EntityId,
        history: ThreadAudienceHistory,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        memory.rooms_thread_audience_add(&ThreadAudienceAddRequest {
            thread_ref: self.thread.to_hex(),
            person_ref: person.to_hex(),
            history,
            check_in_ref: check_in_ref.map(str::to_owned),
        })
    }

    /// The Owner approves pending check-in `id` over the effect it waits on,
    /// through `vault.check_in.answer`.
    pub(crate) fn owner_approves(&self, id: &str) {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
        .expect("the Owner answers");
        assert_eq!(
            settled["eligible"].as_str(),
            Some("approved"),
            "the Owner's approval makes the add eligible: {settled}"
        );
    }

    /// Every `check_in` receipt in the vault, by outcome.
    pub(crate) fn check_in_receipts(&self) -> Vec<String> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::CheckIn].into();
        let mut receipts = self.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
            .into_iter()
            .map(|receipt| receipt.outcome)
            .collect()
    }
}

/// An enabled, active agent definition the owner creates.
pub(crate) fn create_agent(vault: &Vault, owner: &AuthenticatedOwner) -> EntityId {
    let id = vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        vault,
        owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": format!("room-add-{}", id.to_hex()),
                "desc": "room add fixture",
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

/// The owner's live Grant for `agent` naming `read` and `verbs`.
pub(crate) fn grant(vault: &Vault, owner: &AuthenticatedOwner, agent: EntityId, verbs: &[&str]) {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(
        std::iter::once("read")
            .chain(verbs.iter().copied())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
    );
    let minted = mint_agent_grant_as(
        vault,
        owner,
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

/// The check-in a refusal waits on, 32 hex.
pub(crate) fn pending_id(error: &MemoryError) -> String {
    assert_eq!(
        error.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the act waits: {error:?}"
    );
    error
        .reason_codes
        .iter()
        .find_map(|reason| reason.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the wait names its check-in")
        .to_owned()
}

/// The decision an agent's approved add records.
pub(crate) fn approved(id: &str) -> Option<CheckInDecision> {
    Some(CheckInDecision {
        act_class: "room_add".to_owned(),
        role: "delegate".to_owned(),
        mode: Some("auto".to_owned()),
        basis: "approved".to_owned(),
        check_in: Some(id.to_owned()),
        requester: None,
    })
}
