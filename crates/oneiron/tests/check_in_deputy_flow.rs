//! ROLES-CHECKIN P2.6c, piece 2n (ARCH-0082 #human-owner-deputy and #build;
//! Engine ruling P26-SHAPE Q6 = A, 15 Nov 02:04): the check-in paths a
//! house Deputy walks, in one story. Tests only; it composes what is built
//! and claims the PR 2 part of canon's `deputy_checks_in_then_becomes_owner`
//! alone.
//!
//! The house of a stored workspace, the seeded `sys.default` agent, is bound
//! to the shared vault at Deputy, and the Owner mints it a Grant naming a
//! reversible act, the thread add and the erase. The house sits in a group
//! room and in a private thread there; a newcomer sits in the room only.
//!
//! - Reversible work goes: its check-in answers `go`, `never_ask`. No door
//!   judges a `reversible_work` act yet, and the Deputy cannot call the
//!   archive verb, which is the Owner's.
//! - Its add of the newcomer waits (`CHECK_IN_PENDING`): an agent's add asks
//!   when unsure, and no decision model is sure yet (P23-SHAPE Q5 = A), so
//!   "adds on a sure check" is not claimed here.
//! - Its erase ask is held: the record stays, and the Owner's confirm naming
//!   the unanswered ask erases nothing. Both asks wait on the grantor rung,
//!   which pins the Owner alone.
//! - A person the rung does not pin cannot answer; the Owner approves both
//!   through `vault.check_in.answer`.
//! - The house's call naming the approved add lands it from now on, once;
//!   the Owner applies the approved erase on their own proof (P25-SHAPE Q1
//!   = A), and its outcome names the house as requester.
//!
//! On the stack's base (1ffd62d8ab9) this file does not build: the add
//! request has no `check_in_ref` and its receipt no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_deputy_flow`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/room_add_fixture.rs"]
mod room_add_fixture;

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::check_in::{
    CheckInDecision, CheckInMode, PendingCheckIn, Rung, record_erase_effect_digest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::federation::FederationGrantRole;
use oneiron::memory::{
    BlobArtifactInput, MEMORY_CODE_CHECK_IN_PENDING, MEMORY_CODE_FORBIDDEN, Memory, MemoryResult,
    WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    RecordEraseConfirmRequest, RecordEraseOutcome, RecordEraseRequest, confirm_record_erase,
    preview_record_erase,
};
use oneiron::workspace_roster::{
    ThreadAudienceAddRequest, ThreadAudienceHistory, ThreadAudienceReceipt, WorkCompanionPolicy,
    WorkspaceRosterPreset,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use room_add_fixture::{ADD, grant, pending_id};
use serde_json::{Value, json};

/// `erase`: a Deputy whose Grant names it always asks the Owner.
const ERASE: &str = "vault.records.erase_confirm";
/// `reversible_work`: a Deputy goes.
const REVERSIBLE: &str = "vault.projects.goal.propose";
const WORKSPACE: &str = "check-in-deputy-flow-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const SHARED: u64 = 45;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Flow {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    house: EntityId,
    /// In the room, out of the thread.
    newcomer: EntityId,
    room: EntityId,
    thread: EntityId,
}

impl Flow {
    /// A vault as a host starts one (rooted, the owner bound, the root
    /// signed), its shared vault, the stored workspace whose house the owner
    /// binds at Deputy and grants, and the owner's group room seating the
    /// owner, the house and the newcomer, with a private thread whose
    /// audience is the owner and the house.
    fn new() -> Self {
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
        let [org, newcomer] = std::array::from_fn(|_| EntityId::now());
        for (id, kind) in [(org, ENTITY_TYPE_ORG), (newcomer, ENTITY_TYPE_PERSON)] {
            vault
                .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"deputy flow")
                .expect("a live row");
        }
        vault
            .initialize_shared_vault(&owner_proof, SHARED, None, &[], vault.now_recorded_at())
            .expect("the owner initializes the shared vault");
        let (house, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: SHARED,
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
            .bind_workspace_house_leader(
                WORKSPACE,
                FederationGrantRole::Deputy,
                &owner_proof,
                &signer,
            )
            .expect("the owner binds the house at deputy");
        grant(&vault, &owner_proof, house, &[REVERSIBLE, ADD, ERASE]);
        let room = EntityId::now();
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![owner, house, newcomer],
                    ..Default::default()
                },
                WriteActor::new(owner, EdgeActorClass::Human),
                vault.now_recorded_at(),
            )
            .expect("the room");
        let flow = Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            house,
            newcomer,
            room,
            thread: EntityId::now(),
        };
        let anchor = EntityId::now();
        flow.speak(anchor, None);
        flow.speak(flow.thread, Some((anchor, [owner, house].into())));
        flow
    }

    /// The owner's witness turn `turn`: the trunk turn, or with `thread` the
    /// root of a private thread on the trunk turn it names.
    fn speak(&self, turn: EntityId, thread: Option<(EntityId, BTreeSet<EntityId>)>) {
        let mut metadata = serde_json::Map::new();
        if let Some((anchor, _)) = &thread {
            metadata.insert("room_thread_of".into(), anchor.to_hex().into());
        }
        self.person(self.owner)
            .rooms_speak(&WitnessTurn {
                conversation_ref: self.room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: thread.map(|(_, audience)| audience),
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "a turn of the room".into(),
                    parts: None,
                    metadata: Some(Value::Object(metadata)),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.vault.now_recorded_at(),
                assertions: Default::default(),
            })
            .expect("the owner speaks");
    }

    fn person(&self, person: EntityId) -> Memory<'_> {
        self.vault.memory(person, EdgeActorClass::Human)
    }

    fn house(&self) -> Memory<'_> {
        self.vault.memory(self.house, EdgeActorClass::Agent)
    }

    /// The house's add of the newcomer to the thread, from now on.
    fn add(&self, check_in_ref: Option<&str>) -> MemoryResult<ThreadAudienceReceipt> {
        self.house()
            .rooms_thread_audience_add(&ThreadAudienceAddRequest {
                thread_ref: self.thread.to_hex(),
                person_ref: self.newcomer.to_hex(),
                history: ThreadAudienceHistory::FromNow,
                check_in_ref: check_in_ref.map(str::to_owned),
            })
    }

    fn row(&self, id: &str) -> PendingCheckIn {
        self.vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored")
    }

    /// `person` approves check-in `id` over the effect it waits on.
    fn approves(&self, person: EntityId, id: &str) -> MemoryResult<Value> {
        let digest = hex(&self.row(id).effect_digest);
        invoke(
            &self.person(person),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
    }

    /// The owner previews the erase of `record`, then confirms it on their
    /// own proof, naming `check_in_ref`.
    fn erase(&self, record: EntityId, check_in_ref: &str) -> MemoryResult<RecordEraseOutcome> {
        let memory = self.person(self.owner);
        let preview = preview_record_erase(&memory, RecordEraseRequest { record })
            .expect("the owner previews the erase");
        confirm_record_erase(
            &memory,
            &self.owner_proof,
            RecordEraseConfirmRequest {
                record,
                preview_digest: preview.preview_digest,
                also_same_bytes: false,
                check_in_ref: Some(check_in_ref.to_owned()),
            },
        )
    }
}

#[test]
fn a_house_deputy_goes_waits_is_held_and_its_approved_acts_land_once() {
    let flow = Flow::new();
    let house = flow.house();

    // Reversible work its Grant names goes.
    let reversible = invoke(
        &house,
        "vault.check_in.preflight",
        json!({ "verb": REVERSIBLE, "effect_digest": hex(&[0x61; 32]) }),
    )
    .expect("the preflight answers");
    assert_eq!(
        reversible,
        json!({ "outcome": "go", "reason": "never_ask", "act_class": "reversible_work" }),
        "a Deputy goes on reversible work"
    );

    // Its add waits: it asks when unsure, and no decision model is sure.
    let add_id = pending_id(&flow.add(None).expect_err("the house's add waits"));
    let add_row = flow.row(&add_id);
    assert_eq!(
        (add_row.asker, add_row.verb.as_str(), add_row.mode),
        (flow.house, ADD, CheckInMode::AskWhenUnsure),
        "the house's own ask, from its Deputy cell"
    );
    let early = flow
        .add(Some(&add_id))
        .expect_err("an unanswered check-in lands nothing");
    assert_ne!(early.code, MEMORY_CODE_CHECK_IN_PENDING, "{early:?}");

    // Its erase ask is held until the Owner answers.
    let record = flow
        .person(flow.owner)
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "deputy flow record".to_owned(),
            media_type: "text/plain".to_owned(),
            occurred_at: 1,
            learned_at: None,
        })
        .expect("the owner writes an artifact");
    let record = EntityId::from_hex(&record.id_hex).expect("an artifact id");
    let opened = invoke(
        &house,
        "vault.check_in.open",
        json!({ "verb": ERASE, "effect_digest": hex(&record_erase_effect_digest(&record, false)) }),
    )
    .expect("the house opens its erase ask");
    assert_eq!(
        (opened["outcome"].as_str(), opened["reason"].as_str()),
        (Some("wait"), Some("always_ask")),
        "a Deputy always asks the Owner on an erase: {opened}"
    );
    let erase_id = opened["handle"]["handle"]
        .as_str()
        .expect("a handle")
        .to_owned();
    for id in [&add_id, &erase_id] {
        let row = flow.row(id);
        let rung = row.current_rung().expect("a rung");
        let pinned: BTreeSet<EntityId> =
            rung.holders.iter().map(|holder| holder.principal).collect();
        assert_eq!(
            (rung.rung, pinned),
            (Rung::Grantor, BTreeSet::from([flow.owner])),
            "the Owner who minted the Grant is asked first"
        );
    }
    assert!(
        flow.erase(record, &erase_id).is_err(),
        "the Owner's confirm naming the unanswered ask erases nothing"
    );
    assert!(
        flow.vault.get(&record).expect("read the record").is_some(),
        "the held erase erased nothing"
    );

    // A person the rung does not pin cannot answer; the Owner approves.
    let stranger = flow
        .approves(flow.newcomer, &add_id)
        .expect_err("the newcomer cannot answer");
    assert_eq!(stranger.code, MEMORY_CODE_FORBIDDEN, "{stranger:?}");
    assert!(
        stranger
            .message
            .contains("only a person pinned on the current rung answers"),
        "{stranger:?}"
    );
    for id in [&add_id, &erase_id] {
        let settled = flow.approves(flow.owner, id).expect("the Owner answers");
        assert_eq!(
            (settled["rung"].as_str(), settled["eligible"].as_str()),
            (Some("grantor"), Some("approved")),
            "{settled}"
        );
    }

    // The house's call naming the approved add lands it, once.
    let landed = flow.add(Some(&add_id)).expect("the approved add lands");
    assert_eq!(landed.history, Some(ThreadAudienceHistory::FromNow));
    assert_eq!(
        landed.check_in,
        Some(CheckInDecision {
            act_class: "room_add".to_owned(),
            role: "deputy".to_owned(),
            mode: Some(CheckInMode::AskWhenUnsure.as_str().to_owned()),
            basis: "approved".to_owned(),
            check_in: Some(add_id.clone()),
            requester: None,
        }),
        "the receipt records the Deputy's approved decision"
    );
    let again = flow
        .add(Some(&add_id))
        .expect_err("a spent check-in lands nothing again");
    assert!(again.message.contains("already ran"), "{again:?}");

    // The Owner applies the approved erase on their own proof, once.
    let outcome = flow
        .erase(record, &erase_id)
        .expect("the Owner applies the approved erase");
    assert_eq!(outcome.first.reason, "owner_erase", "{outcome:?}");
    assert_eq!(
        outcome.check_in,
        Some(CheckInDecision {
            act_class: "erase".to_owned(),
            role: "owner".to_owned(),
            mode: None,
            basis: "own_proof".to_owned(),
            check_in: Some(erase_id.clone()),
            requester: Some(flow.house.to_hex()),
        }),
        "the outcome names the ask it applied and the house that asked"
    );
    assert!(
        flow.row(&erase_id).consumed_at.is_some(),
        "the confirm spent the erase ask"
    );
}
