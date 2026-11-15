// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! PR 2's person-act sweep (RULING HANDED-ON-PERSON-SWEEP-SCOPE = A): every
//! census site asks `acts_as_own_person()`. A Human credential handed on to
//! another key acts as its key's holder, never as the person it names
//! (HANDED-ON-SLIP-PERSON, 15 Nov: Q1 = A, its writes are Generated or
//! Observed, never UserStated; Q2 = A, a hand-on to the person's own other
//! device key is no person either).
//!
//! Each red fails at the base (the handed-on handle acts as the owner) and
//! passes with the change; each guard (the owner's own slip, same act)
//! passes on both. The booking/calendar lock-in and the D1/D2 read guard
//! pass on both trees: no PR 2 change touches them.
//!
//! Commit 3's handle mark (Q'): a room NOTE birth is never the person's (H91).
//! Commit 3's handle mark (Q'): a code run on a handed-on slip never asks itself (H2).
//! Commit 3's handle mark (Q'): a base NOTE birth is never the person's (H86).
//! Commit 3's handle mark (Q'): a code run on a handed-on slip still reads its vault (D5).
//! Commit 5 (Astra on #8562): a marked handle with no proof takes no owner run control (F1),
//! mints no embedded owner or native person proof (F2), keeps no platform announcement (F3),
//! stamps no Stated text receipt (F4) and captures a marked solved-run scope (F5).
//! Commit 6 (Astra delta on #8562): an unmarked Agent handle on the owner's PERSON keeps the
//! announcement (F3 guard) and a handed-on Active SKILL stages Generated off record (F6).
//! Commit 7 (Astra delta-2 on #8562): a handed-on Agent handle on the owner's PERSON keeps the
//! announcement too (finding 3 guard).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test handed_on_person_sweep`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::blob_artifact::{ArtifactCreateRequest, NativeOutputRequest, ProposalSettleRequest};
use oneiron::calendar::meeting::{CalendarMeetingRequest, check_in_due};
use oneiron::campaign::register_crm_pack;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomRole};
use oneiron::core_write::ConversationCreateInput;
use oneiron::memory::campaign_records::{
    CAMPAIGN_SCHEMA_VERSION, CampaignLifecycle, CreateCampaignRequest,
};
use oneiron::memory::{
    BlobArtifactInput, BlobVersionAppendOutcome, ExpressionPreferenceInput,
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MessageStreamError, MessageStreamPolicy,
    resolve_entity_ref,
};
use oneiron::note::TakeTarget;
use oneiron::registry::{
    ENTITY_TYPE_PERSON, TYPE_BYTE_ZONE_COMPILED_PRODUCT_END, TYPE_BYTE_ZONE_COMPILED_PRODUCT_START,
    TypeByteFamily, allocate_type_byte,
};
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskQuestion, TaskAskSpec,
};
use oneiron::test_doors::owner_write_actor::verify_for_test;
use oneiron::verbs::{ShareRevokeRequest, revoke_share_as_caller};
use oneiron::workspace_roster::RoomMemberRoleSet;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, ExpressionPreferenceOrigin, ExpressionPreferenceValue, TimeRange,
    Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer = HostSlipIssuer::from_secret(b"transferred-slip-not-person")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let agent = vault
            .ensure_agent_principal("transferred-slip-agent")
            .expect("agent");
        let subject = person(&vault);
        let facet = vault.default_facet().expect("default facet");
        Self {
            vault,
            owner,
            issuer,
            agent,
            subject,
            facet,
            _directory: directory,
        }
    }

    /// A Human slip for the owner from the host root, held by the owner or
    /// handed on to another key first.
    fn owner_slip(&self, handed_on: bool) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        if !handed_on {
            let challenge = b"transferred slip own slip";
            let binding = self
                .issuer
                .binding_proof(&slip, challenge)
                .expect("the own binding proof");
            let own = self
                .vault
                .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
                .expect("the own slip verifies");
            assert!(!own.is_transferred(), "control: the owner holds this one");
            return own;
        }
        self.hand_on(slip, b"transferred slip handed slip")
    }

    /// `slip` handed on by its holder to another key, as that key presents it
    /// under `challenge`.
    fn hand_on(&self, mut slip: CapabilitySlip, challenge: &[u8]) -> VerifiedSlip {
        let next = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(b"transferred slip handed holder").as_bytes(),
        );
        self.issuer
            .attenuate_to(
                &mut slip,
                SlipCaveat::default(),
                next.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        let binding = next
            .sign(
                &slip
                    .binding_transcript(challenge)
                    .expect("the binding transcript"),
            )
            .to_bytes();
        let handed = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
            .expect("the handed slip verifies");
        assert!(handed.is_transferred(), "control: the slip was handed on");
        handed
    }

    /// The owner's handle presenting `slip`.
    fn owner_memory(&self, slip: &VerifiedSlip) -> oneiron::memory::Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_read_proof(slip)
    }

    /// An Agent-class slip for the owner's PERSON from the host root, held by
    /// the owner (unmarked) or handed on to another key first (marked): the
    /// credential route Astra names for finding 3.
    fn owner_agent_slip(&self, handed_on: bool) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("agent".to_owned());
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's agent slip");
        if handed_on {
            return self.hand_on(slip, b"transferred slip handed agent slip");
        }
        let challenge = b"transferred slip own agent slip";
        let binding = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("the own agent binding proof");
        let own = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
            .expect("the own agent slip verifies");
        assert!(!own.is_transferred(), "control: the owner holds this one");
        own
    }

    /// The owner's PERSON bound as Agent, presenting `slip`.
    fn owner_agent_memory(&self, slip: &VerifiedSlip) -> oneiron::memory::Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Agent)
            .with_read_proof(slip)
    }

    /// An Observed Auto `profile.note` about the subject on the raw door: no
    /// envelope author, so never the owner's own row. Observed, because a
    /// Generated Auto row needs an actor-bound permit no unattributed write
    /// holds (Astra review on #8434, F4: the demotion pair failed in setup).
    fn raw_note(&self) -> EntityId {
        let mut body = observed_body(NOTE, self.subject, Value::from("a note"));
        body.scope_facet = self.facet;
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(), LEARNED_AT)
            .expect("the note lands");
        id
    }

    /// The agent's Inferred language row about the subject.
    fn agent_preference(&self) -> EntityId {
        let now = self.vault.now_recorded_at();
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .set_expression_preference(
                &ExpressionPreferenceInput {
                    subject_ref: self.subject.to_hex(),
                    value: ExpressionPreferenceValue::Language("en-US".to_owned()),
                    origin: ExpressionPreferenceOrigin::Inferred,
                    valid_from: now,
                },
                now,
            )
            .expect("the agent's preference lands");
        self.claim_id(&receipt.claim_short_id)
    }

    fn claim_id(&self, short_id: &str) -> EntityId {
        resolve_entity_ref(&self.vault, short_id).expect("the claim's id")
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }

    /// The subject's NOTE brief about `recipient`, for a share the subject
    /// issues and the owner revokes.
    fn subject_take(&self, recipient: EntityId) -> String {
        self.vault
            .memory(self.subject, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(recipient), "a brief for the recipient")
            .expect("the subject authors a NOTE")
            .id_hex
    }

    /// The shipped policy plus `actor`'s explicit permission to create a
    /// brief share on the shared-brief channel (as
    /// `tests/delegation_expiry_wall_clock.rs` permits the owner).
    fn permit_share_for(&self, actor: EntityId) {
        let id = oneiron_store::policy_record::default_policy_manifest_id()
            .expect("the default manifest id");
        let bytes = self
            .vault
            .get(&id)
            .expect("read default manifest")
            .expect("the shipped manifest is stored");
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
        manifest["scoped_grants"]
            .as_array_mut()
            .expect("the shipped scoped-grant table")
            .push(json!({
                "actor_ref": actor.to_hex(),
                "effector": "external:share_brief",
                "scope": oneiron::test_support::effect_preset(),
                "selectors": { "channel": "shared_brief" },
            }));
        oneiron::test_support::put_policy_manifest_bytes(
            &self.vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
        )
        .expect("store share permission");
    }

    /// A live person's owner proof (as `tests/admin_is_not_deputy.rs`
    /// mints one).
    fn owner_proof(&self, person: EntityId) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("a person proof")
    }

    /// The CRM pack at the first two free product type bytes (as
    /// `tests/campaign_enroll_typed_door.rs` registers it).
    fn register_crm(&self) {
        let family = TypeByteFamily::Productivity;
        let mut occupied: Vec<u8> = (TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
            ..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
            .filter(|kind| self.vault.structural_kind_registration(*kind).is_some())
            .collect();
        let campaign = allocate_type_byte(family, &occupied).expect("a free campaign type byte");
        occupied.push(campaign);
        let saved_query =
            allocate_type_byte(family, &occupied).expect("a free saved-query type byte");
        register_crm_pack(&self.vault, campaign, saved_query, family)
            .expect("the CRM pack registers");
    }

    /// An artifact with a kept proposal, settled by the owner's own handle:
    /// the artifact and the kept proposal's ref, ready for an undo.
    fn kept_proposal(&self) -> (EntityId, String) {
        let own = self.vault.memory(self.owner, EdgeActorClass::Human);
        let now = self.vault.now_recorded_at();
        let artifact = EntityId::now();
        own.put_blob_artifact(&BlobArtifactInput {
            id: Some(artifact.to_hex()),
            name: "kept.bin".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            occurred_at: now,
            learned_at: None,
        })
        .expect("the artifact registers");
        let landed = own
            .append_blob_version(&artifact.to_hex(), b"the first version", None, now, None)
            .expect("the first version lands");
        assert!(
            matches!(landed, BlobVersionAppendOutcome::Landed(_)),
            "the owner's first version lands live: {landed:?}"
        );
        let pending = own
            .artifacts_propose_output(&NativeOutputRequest {
                artifact_ref: artifact.to_hex(),
                run_ref: "sweep-undo-run".to_owned(),
                name: "kept.bin".to_owned(),
                media_type: "application/octet-stream".to_owned(),
                content_base64: "dGhlIHNlY29uZCB2ZXJzaW9u".to_owned(),
                report: json!(null),
                made_by: None,
                read_rows: Vec::new(),
                delta_receipt: None,
            })
            .expect("the second version is proposed");
        own.artifacts_keep(&ProposalSettleRequest {
            artifact_ref: artifact.to_hex(),
            proposal_ref: pending.proposal_ref.clone(),
            brief_ref: None,
            reason: None,
        })
        .expect("the owner keeps the proposal");
        (artifact, pending.proposal_ref)
    }

    /// A room seating the owner and the subject, with no roles (no gate on
    /// either tree).
    fn plain_room(&self) -> EntityId {
        let room = EntityId::now();
        self.vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![self.owner, self.subject],
                    ..Default::default()
                },
                WriteActor::new(self.owner, EdgeActorClass::Human),
                self.vault.now_recorded_at(),
            )
            .expect("a room with no roles");
        room
    }
}

fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// A live PERSON.
fn person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(), LEARNED_AT, b"human")
        .expect("a live person");
    person
}

fn observed_body(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
    body.scope = None;
    body
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

/// Red (memory-rest): the handed-on handle sets no message-stream policy.
#[test]
fn a_handed_on_owner_slip_never_sets_the_message_stream_policy() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);
    let mut policy = MessageStreamPolicy::default();
    policy.idle_timeout_ms = 60_000;

    let refused = f
        .owner_memory(&slip)
        .set_message_stream_policy(&policy)
        .expect_err("a handed-on owner slip sets no stream policy");

    assert!(
        matches!(refused, MessageStreamError::WrongActor),
        "the refusal is the actor's: {refused:?}"
    );
    assert!(
        refused.to_string().contains("belongs to another actor"),
        "the refusal names its reason: {refused}"
    );
    assert_eq!(
        f.vault.message_stream_policy().expect("policy read"),
        MessageStreamPolicy::default(),
        "the vault keeps its default policy"
    );
}

/// Guard (memory-rest): the owner's own slip still sets it.
#[test]
fn the_owners_own_slip_still_sets_the_message_stream_policy() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);
    let mut policy = MessageStreamPolicy::default();
    policy.idle_timeout_ms = 60_000;

    f.owner_memory(&slip)
        .set_message_stream_policy(&policy)
        .expect("the owner's own slip sets the policy");

    assert_eq!(
        f.vault.message_stream_policy().expect("policy read"),
        policy,
        "the vault holds the set policy"
    );
}

/// Red (note): the handed-on handle stamps no person policy seed.
#[test]
fn a_handed_on_owner_slip_never_blesses_a_brief_kind() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .bless_brief_kind()
        .expect_err("a handed-on owner slip blesses no brief kind");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused.message.contains("must be person-stamped"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert!(
        f.vault
            .brief_kind_contract()
            .expect("contract read")
            .is_none(),
        "no contract is stamped"
    );
}

/// Guard (note): the owner's own slip still blesses it.
#[test]
fn the_owners_own_slip_still_blesses_a_brief_kind() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);

    let contract = f
        .owner_memory(&slip)
        .bless_brief_kind()
        .expect("the owner's own slip blesses the kind");

    assert_eq!(contract.person(), f.owner);
    assert!(
        f.vault
            .brief_kind_contract()
            .expect("contract read")
            .is_some(),
        "the contract stands"
    );
}

/// Red (office/blob): the handed-on handle uploads no version without a run.
#[test]
fn a_handed_on_owner_slip_never_creates_an_artifact_without_a_run_ref() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .artifacts_create(&ArtifactCreateRequest {
            name: "handed.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            content_base64: "aGk=".to_owned(),
            run_ref: None,
            made_by: None,
        })
        .expect_err("a handed-on owner slip uploads no run-less version");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused.message.contains("names its run_ref"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (office/blob): the owner's own slip still uploads one.
#[test]
fn the_owners_own_slip_still_creates_an_artifact_without_a_run_ref() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);

    let view = f
        .owner_memory(&slip)
        .artifacts_create(&ArtifactCreateRequest {
            name: "handed.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            content_base64: "aGk=".to_owned(),
            run_ref: None,
            made_by: None,
        })
        .expect("the owner's own slip uploads");

    assert!(view.is_some(), "the artifact lands");
}

/// Red (conversation): the handed-on handle creates no room with roles.
#[test]
fn a_handed_on_owner_slip_never_creates_a_room_with_roles() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);
    let owner_hex = f.owner.to_hex();
    let mut roles = serde_json::Map::new();
    roles.insert(owner_hex.clone(), json!("owner"));

    let refused = f
        .owner_memory(&slip)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "member_ids": [owner_hex, f.subject.to_hex()],
                "roles": roles,
            }),
            text: None,
        })
        .expect_err("a handed-on owner slip creates no room with roles");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused
            .message
            .contains("conversation actor is not authorized"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (conversation): the owner's own slip still creates one.
#[test]
fn the_owners_own_slip_still_creates_a_room_with_roles() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);
    let owner_hex = f.owner.to_hex();
    let mut roles = serde_json::Map::new();
    roles.insert(owner_hex.clone(), json!("owner"));

    f.owner_memory(&slip)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "member_ids": [owner_hex, f.subject.to_hex()],
                "roles": roles,
            }),
            text: None,
        })
        .expect("the owner's own slip creates the room");
}

/// Red (roster/rooms): the handed-on handle sets no member's room role.
#[test]
fn a_handed_on_owner_slip_never_sets_a_members_room_role() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .rooms_members_role_set(&RoomMemberRoleSet {
            room,
            person: f.subject,
            role: RoomRole::Admin,
        })
        .expect_err("a handed-on owner slip sets no room role");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains("sets a member's room role"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert!(
        f.vault
            .conversation_body(room)
            .expect("room read")
            .roles
            .is_empty(),
        "no role is set"
    );
}

/// Guard (roster/rooms): the owner's own slip still sets it.
#[test]
fn the_owners_own_slip_still_sets_a_members_room_role() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_slip(false);

    let receipt = f
        .owner_memory(&slip)
        .rooms_members_role_set(&RoomMemberRoleSet {
            room,
            person: f.subject,
            role: RoomRole::Admin,
        })
        .expect("the owner's own slip sets the role");

    assert_eq!(receipt.role, RoomRole::Admin);
    assert_eq!(
        f.vault
            .conversation_body(room)
            .expect("room read")
            .roles
            .get(&f.subject.to_hex()),
        Some(&RoomRole::Admin),
        "the member is an admin"
    );
}

/// Red (task): the handed-on handle asks no self-ask (it falls into the
/// agent path and has no verified human principal).
#[test]
fn a_handed_on_owner_slip_never_asks_itself() {
    let f = Fixture::new();
    let claim = f.raw_note();
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    let option = TaskAskOptionId::new("upheld").expect("option id");
    question
        .options
        .insert(option, TaskAskOption::new("upheld"));
    let spec = TaskAskSpec::shorthand(None, question, None, TaskAskDefault::AskMe);
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .tasks_ask(&spec)
        .expect_err("a handed-on owner slip asks no self-ask");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused
            .message
            .contains("agent has no verified human principal"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (task): the owner's own slip still asks itself.
#[test]
fn the_owners_own_slip_still_asks_itself() {
    let f = Fixture::new();
    let claim = f.raw_note();
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    let option = TaskAskOptionId::new("upheld").expect("option id");
    question
        .options
        .insert(option, TaskAskOption::new("upheld"));
    let spec = TaskAskSpec::shorthand(None, question, None, TaskAskDefault::AskMe);
    let slip = f.owner_slip(false);

    f.owner_memory(&slip)
        .tasks_ask(&spec)
        .expect("the owner's own slip asks itself");
}

/// Red (claim/reaction): the handed-on handle retracts no row it did not
/// write. (PR 1's `:159` override pair already pins the ExplicitUser gate;
/// this pins the retract gate beside it.)
#[test]
fn a_handed_on_owner_slip_never_retracts_anothers_preference() {
    let f = Fixture::new();
    let agents = f.agent_preference();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .retract_expression_preference(&agents.to_hex())
        .expect_err("a handed-on owner slip retracts no foreign row");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused
            .message
            .contains("retracted by the actor that wrote it"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert_eq!(
        f.stored(agents).lifecycle,
        ClaimLifecycleStatus::Active,
        "the agent's row stands"
    );
}

/// Guard (claim/reaction): the owner's own slip still retracts it as owner.
#[test]
fn the_owners_own_slip_still_retracts_anothers_preference() {
    let f = Fixture::new();
    let agents = f.agent_preference();
    let slip = f.owner_slip(false);

    f.owner_memory(&slip)
        .retract_expression_preference(&agents.to_hex())
        .expect("the owner's own slip retracts as the owner");

    assert_eq!(
        f.stored(agents).lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the agent's row is retracted"
    );
}

/// Red (comm/edit/typed): the handed-on handle settles no artifact as the
/// owner (its settle rides no owner consent without a brief).
#[test]
fn a_handed_on_owner_slip_never_settles_an_artifact_as_the_owner() {
    let f = Fixture::new();
    let (artifact, proposal) = f.kept_proposal();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .artifacts_undo(&ProposalSettleRequest {
            artifact_ref: artifact.to_hex(),
            proposal_ref: proposal,
            brief_ref: None,
            reason: None,
        })
        .expect_err("a handed-on owner slip settles no artifact as the owner");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused.message.contains("names the brief its grant covers"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (comm/edit/typed): the owner's own slip still undoes a Keep as a
/// user upload.
#[test]
fn the_owners_own_slip_still_undoes_a_keep_as_a_user_upload() {
    let f = Fixture::new();
    let (artifact, proposal) = f.kept_proposal();
    let slip = f.owner_slip(false);

    let undone = f
        .owner_memory(&slip)
        .artifacts_undo(&ProposalSettleRequest {
            artifact_ref: artifact.to_hex(),
            proposal_ref: proposal,
            brief_ref: None,
            reason: None,
        })
        .expect("the owner's own slip undoes the Keep");

    assert_eq!(undone.version.provenance, "user_upload");
    assert_eq!(undone.version.run_ref, None);
}

/// Red (code_run/authority/agent): the handed-on handle passes no owner
/// write.
#[test]
fn a_handed_on_owner_slip_never_passes_the_owner_write_gate() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);

    let refused = verify_for_test(&f.owner_memory(&slip))
        .expect_err("a handed-on owner slip passes no owner write");

    assert!(
        refused.contains("an owner write requires a human actor"),
        "the refusal names its reason: {refused}"
    );
}

/// Guard (code_run/authority/agent): the owner's own slip still passes it.
#[test]
fn the_owners_own_slip_still_passes_the_owner_write_gate() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);

    verify_for_test(&f.owner_memory(&slip)).expect("the owner's own slip passes");
}

/// Red (share/federation/gate): the handed-on handle revokes no share
/// another issuer made (D4: PR 1's delete-authority return guards no
/// `Vault::revoke_share` path, so the verb door pins `:43`).
#[test]
fn a_handed_on_owner_slip_never_revokes_anothers_share() {
    let f = Fixture::new();
    let recipient = person(&f.vault);
    let brief = f.subject_take(recipient);
    f.permit_share_for(f.subject);
    let share_id = EntityId::now();
    let now = f.vault.now_recorded_at();
    f.vault
        .create_share(
            &share_id,
            &WriteActor::new(f.subject, EdgeActorClass::Human),
            &Share {
                recipient_ref: recipient,
                brief_ref: brief,
                world_refs: BTreeSet::new(),
                facet_refs: BTreeSet::new(),
                include_unscoped: true,
                status: AccessGrantStatus::Active,
                created_at: now,
                revoked_at: None,
                expires_at: None,
                mention: None,
            },
        )
        .expect("the subject's share is admitted");
    let slip = f.owner_slip(true);

    let refused = revoke_share_as_caller(
        &f.owner_memory(&slip),
        ShareRevokeRequest {
            share_ref: share_id.to_hex(),
        },
    )
    .expect_err("a handed-on owner slip revokes no foreign share");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused
            .message
            .contains("share revocation requires issuer or owner"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert_eq!(
        f.vault
            .get_share(&share_id)
            .expect("share read")
            .expect("the share stands")
            .status,
        AccessGrantStatus::Active,
        "the share stays active"
    );
}

/// Guard (share/federation/gate): the owner's own slip still revokes it.
#[test]
fn the_owners_own_slip_still_revokes_anothers_share() {
    let f = Fixture::new();
    let recipient = person(&f.vault);
    let brief = f.subject_take(recipient);
    f.permit_share_for(f.subject);
    let share_id = EntityId::now();
    let now = f.vault.now_recorded_at();
    f.vault
        .create_share(
            &share_id,
            &WriteActor::new(f.subject, EdgeActorClass::Human),
            &Share {
                recipient_ref: recipient,
                brief_ref: brief,
                world_refs: BTreeSet::new(),
                facet_refs: BTreeSet::new(),
                include_unscoped: true,
                status: AccessGrantStatus::Active,
                created_at: now,
                revoked_at: None,
                expires_at: None,
                mention: None,
            },
        )
        .expect("the subject's share is admitted");
    let slip = f.owner_slip(false);

    let receipt = revoke_share_as_caller(
        &f.owner_memory(&slip),
        ShareRevokeRequest {
            share_ref: share_id.to_hex(),
        },
    )
    .expect("the owner's own slip revokes as the owner");

    assert_eq!(receipt.status, "revoked");
    assert_eq!(
        f.vault
            .get_share(&share_id)
            .expect("share read")
            .expect("the share stands")
            .status,
        AccessGrantStatus::Revoked,
        "the share is revoked"
    );
}

/// Red (vault/campaign/rest): the handed-on handle launches no campaign
/// without a covering launch grant.
#[test]
fn a_handed_on_owner_slip_never_launches_a_campaign_without_a_grant() {
    let f = Fixture::new();
    f.register_crm();
    let own = f.vault.memory(f.owner, EdgeActorClass::Human);
    let now = f.vault.now_recorded_at();
    let campaign = own
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "sweep campaign".to_owned(),
                reply_snooze_policy: None,
                voice_guide_ref: None,
                copy_review: None,
            },
            now,
        )
        .expect("the owner creates a campaign")
        .campaign_ref;
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .campaign_launch(campaign, 1, now + 1)
        .expect_err("a handed-on owner slip launches no campaign without a grant");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused
            .message
            .contains("requires a grant naming campaign launch"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert_eq!(
        own.campaign_read(campaign)
            .expect("campaign read")
            .expect("the campaign stands")
            .definition
            .lifecycle,
        CampaignLifecycle::Draft,
        "the campaign stays a draft"
    );
}

/// Guard (vault/campaign/rest): the owner's own slip still launches it.
#[test]
fn the_owners_own_slip_still_launches_a_campaign() {
    let f = Fixture::new();
    f.register_crm();
    let own = f.vault.memory(f.owner, EdgeActorClass::Human);
    let now = f.vault.now_recorded_at();
    let campaign = own
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "sweep campaign".to_owned(),
                reply_snooze_policy: None,
                voice_guide_ref: None,
                copy_review: None,
            },
            now,
        )
        .expect("the owner creates a campaign")
        .campaign_ref;
    let slip = f.owner_slip(false);

    let launched = f
        .owner_memory(&slip)
        .campaign_launch(campaign, 1, now + 1)
        .expect("the owner's own slip launches");

    assert_eq!(launched.definition.lifecycle, CampaignLifecycle::Active);
}

/// Lock-in (booking/calendar/connector_key): the calendar check-in door
/// still needs the caller's own owner proof. PR 2 changes nothing here; the
/// handed-on handle with another person's proof is refused on both trees,
/// and the owner's own slip with its own proof passes the owner check.
#[test]
fn calendar_check_in_still_needs_the_callers_own_owner_proof() {
    let f = Fixture::new();
    let input = CalendarMeetingRequest {
        event_ref: EntityId::now().to_hex(),
    };

    let refused = check_in_due(
        &f.owner_memory(&f.owner_slip(true)),
        &f.owner_proof(f.subject),
        &input,
    )
    .expect_err("another person's proof opens no check-in");

    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused
            .message
            .contains("must act as its authenticated owner"),
        "the refusal names its reason: {}",
        refused.message
    );

    let due = check_in_due(
        &f.owner_memory(&f.owner_slip(false)),
        &f.owner_proof(f.owner),
        &input,
    )
    .expect("the owner's own proof passes the owner check");
    assert!(due.value.is_none(), "no event stands");
}

/// Guard (D1/D2): the handed-on handle still reads inside its scope.
#[test]
fn a_handed_on_owner_slip_still_reads_inside_its_scope() {
    let f = Fixture::new();
    let agents = f.agent_preference();
    let slip = f.owner_slip(true);

    let view = f
        .owner_memory(&slip)
        .expression_preferences(&f.subject.to_hex(), f.vault.now_recorded_at())
        .expect("a handed-on owner slip reads inside its scope");

    assert_eq!(view.language.as_deref(), Some("en-US"));
    assert_eq!(
        f.stored(agents).lifecycle,
        ClaimLifecycleStatus::Active,
        "the agent's row stands behind the view"
    );
}

/// Red (room NOTE birth, H91): a handed-on owner's room NOTE is never the person's.
#[test]
fn a_handed_on_owner_slip_never_stamps_a_rooms_note_as_the_person() {
    let f = Fixture::new();
    let session = f
        .vault
        .off_record_session_vault()
        .enter(
            "sweep-room-note-handed",
            oneiron::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let slip = f.owner_slip(true);

    let receipt = f
        .owner_memory(&slip)
        .create_note_in_session(&session, NOTE, "a room note with enough text", &[])
        .expect("the room NOTE stages");
    let row = EntityId::from_hex(&receipt.id_hex).expect("row id");

    let birth = oneiron::test_doors::off_record_shell::room_row_birth(&session, &row)
        .expect("room birth read")
        .expect("the room NOTE has a birth");

    assert_eq!(
        birth.made_by.process.class,
        oneiron::write_envelope::provenance::made_by::MadeByClass::Concluded,
        "a handed-on owner's room NOTE is never the person's: {birth:?}"
    );
}

/// Guard (room NOTE birth, H91): the owner's own slip still stamps it as the person.
#[test]
fn the_owners_own_slip_still_stamps_a_rooms_note_as_the_person() {
    let f = Fixture::new();
    let session = f
        .vault
        .off_record_session_vault()
        .enter(
            "sweep-room-note-own",
            oneiron::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let slip = f.owner_slip(false);

    let receipt = f
        .owner_memory(&slip)
        .create_note_in_session(&session, NOTE, "a room note with enough text", &[])
        .expect("the room NOTE stages");
    let row = EntityId::from_hex(&receipt.id_hex).expect("row id");

    let birth = oneiron::test_doors::off_record_shell::room_row_birth(&session, &row)
        .expect("room birth read")
        .expect("the room NOTE has a birth");

    assert_eq!(
        birth.made_by.process.class,
        oneiron::write_envelope::provenance::made_by::MadeByClass::Stated,
        "the owner's own room NOTE stays the person's: {birth:?}"
    );
}

/// Red (code-run dispatcher consult ask, H2): a code run on a handed-on slip never asks itself.
#[test]
fn a_code_run_on_a_handed_on_owner_slip_never_asks_itself() {
    let f = Fixture::new();
    let claim = f.raw_note();
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    let option = TaskAskOptionId::new("upheld").expect("option id");
    question
        .options
        .insert(option, TaskAskOption::new("upheld"));
    let spec = TaskAskSpec::shorthand(None, question, None, TaskAskDefault::AskMe);
    let actor = WriteActor::new(f.owner, EdgeActorClass::Human).with_handed_on_credential();

    let outcome = oneiron::test_doors::code_run_dispatch::dispatch_self_call_for_test(
        &f.vault,
        actor,
        oneiron::code_run::SelfCall::TasksAsk(Box::new(spec)),
    )
    .expect("dispatch runs");

    assert!(
        matches!(outcome, oneiron::code_run::SelfDispatchOutcome::Failed(_)),
        "a handed-on opener asks no self-ask: {outcome:?}"
    );
}

/// Guard (code-run dispatcher consult ask, H2): the owner's own slip still asks itself.
#[test]
fn a_code_run_on_the_owners_own_slip_still_asks_itself() {
    let f = Fixture::new();
    let claim = f.raw_note();
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    let option = TaskAskOptionId::new("upheld").expect("option id");
    question
        .options
        .insert(option, TaskAskOption::new("upheld"));
    let spec = TaskAskSpec::shorthand(None, question, None, TaskAskDefault::AskMe);
    let actor = WriteActor::new(f.owner, EdgeActorClass::Human);

    let outcome = oneiron::test_doors::code_run_dispatch::dispatch_self_call_for_test(
        &f.vault,
        actor,
        oneiron::code_run::SelfCall::TasksAsk(Box::new(spec)),
    )
    .expect("dispatch runs");

    assert!(
        matches!(outcome, oneiron::code_run::SelfDispatchOutcome::TaskAsk(_)),
        "the owner's own opener still asks itself: {outcome:?}"
    );
}

/// Red (base NOTE birth, H86): a handed-on owner's NOTE birth is never the person's.
#[test]
fn a_handed_on_owner_slip_never_stamps_a_note_birth_as_the_person() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);

    let receipt = f
        .owner_memory(&slip)
        .create_note(NOTE, "a base note with enough text for any minimum")
        .expect("the NOTE creates");
    let note = EntityId::from_hex(&receipt.id_hex).expect("note id");

    let birth = f.vault.row_birth(&note).expect("birth read");

    assert!(
        birth.is_none(),
        "a handed-on owner's base NOTE has no Stated birth: {birth:?}"
    );
}

/// Guard (base NOTE birth, H86): the owner's own slip still stamps it as the person.
#[test]
fn the_owners_own_slip_still_stamps_a_note_birth_as_the_person() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);

    let receipt = f
        .owner_memory(&slip)
        .create_note(NOTE, "a base note with enough text for any minimum")
        .expect("the NOTE creates");
    let note = EntityId::from_hex(&receipt.id_hex).expect("note id");

    let birth = f
        .vault
        .row_birth(&note)
        .expect("birth read")
        .expect("the owner's NOTE has a birth");

    assert_eq!(
        birth.made_by.process.class,
        oneiron::write_envelope::provenance::made_by::MadeByClass::Stated,
        "the owner's own base NOTE stays the person's: {birth:?}"
    );
}

/// Guard (D5, Q' reads still land): a code run on a handed-on slip still reads its vault.
#[test]
fn a_code_run_on_a_handed_on_owner_slip_still_reads_its_vault() {
    let f = Fixture::new();
    let actor = WriteActor::new(f.owner, EdgeActorClass::Human).with_handed_on_credential();

    let outcome = oneiron::test_doors::code_run_dispatch::dispatch_self_call_for_test(
        &f.vault,
        actor,
        oneiron::code_run::SelfCall::InferenceDefaultsRead,
    )
    .expect("a handed-on opener still reads");

    assert!(
        matches!(
            outcome,
            oneiron::code_run::SelfDispatchOutcome::InferenceDefaults(_)
        ),
        "the read lands: {outcome:?}"
    );
}

/// Red (F2 embedded owner): the handed-on handle mints no owner proof.
#[test]
fn a_handed_on_owner_slip_never_mints_the_embedded_owner_proof() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, true,
    )
    .expect("marked no-proof handle");

    let refused = memory
        .embedded_owner("vault.packs.remove")
        .expect_err("a handed-on owner slip mints no embedded owner proof");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains("is the vault owner's"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (F2 embedded owner): the owner's own slip still mints it.
#[test]
fn the_owners_own_slip_still_mints_the_embedded_owner_proof() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, false,
    )
    .expect("unmarked no-proof handle");

    memory
        .embedded_owner("vault.packs.remove")
        .expect("the owner's own slip mints the proof");
}

/// Red (F5 browser scope): the handed-on handle marks its solved-run scope.
#[test]
fn a_handed_on_owner_slip_never_captures_an_unmarked_solved_run_scope() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, true,
    )
    .expect("marked no-proof handle");

    let scope = memory.solved_run_scope().expect("solved-run scope builds");
    let json = serde_json::to_value(&scope).expect("scope serializes");

    assert_eq!(
        json.get("handed_on_credential").and_then(|v| v.as_bool()),
        Some(true),
        "a handed-on scope is marked: {json}"
    );
}

/// Guard (F5 browser scope): the owner's own slip still captures unmarked.
#[test]
fn the_owners_own_slip_still_captures_an_unmarked_solved_run_scope() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, false,
    )
    .expect("unmarked no-proof handle");

    let scope = memory.solved_run_scope().expect("solved-run scope builds");
    let json = serde_json::to_value(&scope).expect("scope serializes");

    assert_ne!(
        json.get("handed_on_credential").and_then(|v| v.as_bool()),
        Some(true),
        "the owner's own scope stays unmarked: {json}"
    );
}

/// Red (F1 run control): the handed-on handle takes no owner override on a branch with no TASK.
#[test]
fn a_handed_on_owner_slip_never_pauses_a_branch_without_a_task_as_owner() {
    let f = Fixture::new();
    let queue = oneiron::attempt_queue::AttemptQueue::new(&f.vault);
    let outcome = queue
        .enqueue(oneiron::attempt_queue::EnqueueAttempt {
            kind: "sweep-f1".to_owned(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: f.vault.now_recorded_at(),
        })
        .expect("enqueue branch");
    let branch = match outcome {
        oneiron::attempt_queue::EnqueueOutcome::Enqueued(record)
        | oneiron::attempt_queue::EnqueueOutcome::Existing(record) => record.id,
    };
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, true,
    )
    .expect("marked no-proof handle");

    let refused = memory
        .control_run(
            branch,
            oneiron::task_verb::run_control::RunControl::Pause,
            None,
        )
        .expect_err("a handed-on owner slip takes no owner override");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused
            .message
            .contains("only the vault owner pauses or resumes"),
        "the refusal names its reason: {}",
        refused.message
    );
}

/// Guard (F1 run control): the owner's own slip still pauses it.
#[test]
fn the_owners_own_slip_still_pauses_a_branch_without_a_task_as_owner() {
    let f = Fixture::new();
    let queue = oneiron::attempt_queue::AttemptQueue::new(&f.vault);
    let outcome = queue
        .enqueue(oneiron::attempt_queue::EnqueueAttempt {
            kind: "sweep-f1-guard".to_owned(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: f.vault.now_recorded_at(),
        })
        .expect("enqueue branch");
    let branch = match outcome {
        oneiron::attempt_queue::EnqueueOutcome::Enqueued(record)
        | oneiron::attempt_queue::EnqueueOutcome::Existing(record) => record.id,
    };
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, false,
    )
    .expect("unmarked no-proof handle");

    memory
        .control_run(
            branch,
            oneiron::task_verb::run_control::RunControl::Pause,
            None,
        )
        .expect("the owner's own slip pauses the branch");
}

/// Red (F4 entity-doc): a handed-on edit proposes no Stated receipt.
#[test]
fn a_handed_on_owner_slip_never_proposes_a_stated_entity_text_receipt() {
    let f = Fixture::new();
    let entity = EntityId::now();
    f.vault
        .put_entity(
            &entity,
            oneiron::registry::ENTITY_TYPE_ASSET,
            at(),
            LEARNED_AT,
            b"seed text",
        )
        .expect("seed entity");
    f.vault
        .migrate_entity_text(
            &entity,
            &oneiron::entity_doc::TextField::Utf8Body,
            WriteActor::new(f.owner, EdgeActorClass::Human),
            &oneiron::entity_doc::DocAuthorization::Owner(&f.owner_proof(f.owner)),
        )
        .expect("migrate text");
    let base = f
        .vault
        .entity_text_frontier(&entity)
        .expect("base frontier");
    let actor = WriteActor::new(f.owner, EdgeActorClass::Human).with_handed_on_credential();

    let outcome = f
        .vault
        .update_entity_text(
            &oneiron::entity_doc::TextUpdateRequest {
                entity,
                proposal: EntityId::now(),
                base,
                text: "seed text plus a handed edit".to_owned(),
                actor,
                timeout_ms: 5000,
                at: f.vault.now_recorded_at(),
            },
            &oneiron::entity_doc::DocAuthorization::ProposeOnly,
        )
        .expect("propose update");
    let oneiron::entity_doc::TextUpdateOutcome::ProposedFork { fork, .. } = outcome else {
        panic!("a ProposeOnly update retains a fork: {outcome:?}");
    };

    let provenance = f
        .vault
        .entity_text_provenance(&fork)
        .expect("fork provenance read")
        .expect("the fork has provenance");

    assert_eq!(
        provenance.class,
        oneiron::write_envelope::provenance::made_by::MadeByClass::Concluded,
        "a handed-on edit never proposes Stated: {provenance:?}"
    );
}

/// Guard (F4 entity-doc): the owner's own edit still proposes Stated.
#[test]
fn the_owners_own_slip_still_proposes_a_stated_entity_text_receipt() {
    let f = Fixture::new();
    let entity = EntityId::now();
    f.vault
        .put_entity(
            &entity,
            oneiron::registry::ENTITY_TYPE_ASSET,
            at(),
            LEARNED_AT,
            b"seed text",
        )
        .expect("seed entity");
    f.vault
        .migrate_entity_text(
            &entity,
            &oneiron::entity_doc::TextField::Utf8Body,
            WriteActor::new(f.owner, EdgeActorClass::Human),
            &oneiron::entity_doc::DocAuthorization::Owner(&f.owner_proof(f.owner)),
        )
        .expect("migrate text");
    let base = f
        .vault
        .entity_text_frontier(&entity)
        .expect("base frontier");
    let actor = WriteActor::new(f.owner, EdgeActorClass::Human);

    let outcome = f
        .vault
        .update_entity_text(
            &oneiron::entity_doc::TextUpdateRequest {
                entity,
                proposal: EntityId::now(),
                base,
                text: "seed text plus the owner's edit".to_owned(),
                actor,
                timeout_ms: 5000,
                at: f.vault.now_recorded_at(),
            },
            &oneiron::entity_doc::DocAuthorization::ProposeOnly,
        )
        .expect("propose update");
    let oneiron::entity_doc::TextUpdateOutcome::ProposedFork { fork, .. } = outcome else {
        panic!("a ProposeOnly update retains a fork: {outcome:?}");
    };

    let provenance = f
        .vault
        .entity_text_provenance(&fork)
        .expect("fork provenance read")
        .expect("the fork has provenance");

    assert_eq!(
        provenance.class,
        oneiron::write_envelope::provenance::made_by::MadeByClass::Stated,
        "the owner's own edit still proposes Stated: {provenance:?}"
    );
}

/// Red (F3 announcement): the handed-on handle's TURN loses its platform styling.
#[test]
fn a_handed_on_owner_slip_never_keeps_a_turns_platform_announcement() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_slip(true);

    let receipt = f
        .owner_memory(&slip)
        .conversations_turns_create(&oneiron::core_write::ConversationTurnCreateInput {
            conversation: room.to_hex(),
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "message_type": "platform_announcement",
                "text": "hello from a handed key",
            }),
            text: None,
        })
        .expect("the TURN lands");

    assert!(
        receipt.body.get("message_type").is_none(),
        "a handed-on TURN keeps no platform selector: {}",
        receipt.body
    );
}

/// Guard (F3 announcement): the owner's own TURN still keeps it.
#[test]
fn the_owners_own_slip_still_keeps_a_turns_platform_announcement() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_slip(false);

    let receipt = f
        .owner_memory(&slip)
        .conversations_turns_create(&oneiron::core_write::ConversationTurnCreateInput {
            conversation: room.to_hex(),
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "message_type": "platform_announcement",
                "text": "hello from the owner",
            }),
            text: None,
        })
        .expect("the TURN lands");

    assert_eq!(
        receipt.body.get("message_type").and_then(|v| v.as_str()),
        Some("platform_announcement"),
        "the owner's own TURN keeps its selector: {}",
        receipt.body
    );
}

/// Guard (F3 Agent preservation): an unmarked Agent handle on the owner's
/// PERSON still keeps the announcement selector.
#[test]
fn an_agent_handle_on_the_owners_person_keeps_the_owners_announcement() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_agent_slip(false);

    let receipt = f
        .owner_agent_memory(&slip)
        .conversations_turns_create(&oneiron::core_write::ConversationTurnCreateInput {
            conversation: room.to_hex(),
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "message_type": "platform_announcement",
                "text": "hello from the owner's agent credential",
            }),
            text: None,
        })
        .expect("the TURN lands");

    assert_eq!(
        receipt.body.get("message_type").and_then(|v| v.as_str()),
        Some("platform_announcement"),
        "an unmarked Agent TURN keeps its selector: {}",
        receipt.body
    );
}

/// Guard (Astra delta-2 on #8562, finding 3): an Agent-class slip on the
/// owner's PERSON handed on to another key keeps the announcement selector,
/// as before this PR: the rule relabels a person's credential, never an
/// Agent's, marked or not.
#[test]
fn a_handed_on_agent_handle_on_the_owners_person_keeps_the_owners_announcement() {
    let f = Fixture::new();
    let room = f.plain_room();
    let slip = f.owner_agent_slip(true);

    let receipt = f
        .owner_agent_memory(&slip)
        .conversations_turns_create(&oneiron::core_write::ConversationTurnCreateInput {
            conversation: room.to_hex(),
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "message_type": "platform_announcement",
                "text": "hello from a handed-on agent credential",
            }),
            text: None,
        })
        .expect("the TURN lands");

    assert_eq!(
        receipt.body.get("message_type").and_then(|v| v.as_str()),
        Some("platform_announcement"),
        "a handed-on Agent TURN keeps its selector: {}",
        receipt.body
    );
}

/// An Active SKILL with a person's provenance, as the F6 residual's attack
/// stages it: lifecycle Active, source UserStated, generated false,
/// human_authored true.
fn active_skill_record() -> oneiron::skill::SkillRecord {
    oneiron::skill::SkillRecord::new(
        "handed.active.skill",
        "active instructions",
        "1",
        ClaimApprovalStatus::Approved,
        oneiron::skill::SkillLifecycle::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("origin"), Value::from("test"))]),
    )
}

/// Raw-puts [`active_skill_record`] in a fresh off-record session through the
/// owner's slip (`handed_on` or his own) and reads the overlay copy back.
fn stage_active_skill_off_record(
    f: &Fixture,
    session_name: &str,
    handed_on: bool,
) -> oneiron::skill::SkillRecord {
    let session = f
        .vault
        .off_record_session_vault()
        .enter(
            session_name,
            oneiron::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let slip = f.owner_slip(handed_on);
    let memory = f
        .owner_memory(&slip)
        .in_off_record_session(session.session_ref());
    let id = EntityId::now();
    let body = oneiron::skill::encode_skill_record(&active_skill_record()).expect("encode skill");
    let now = f.vault.now_recorded_at();

    memory
        .raw_put_entity(oneiron::RawEntityPut {
            id,
            entity_type: oneiron::registry::ENTITY_TYPE_SKILL,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: &body,
        })
        .expect("the SKILL stages");
    let staged = memory
        .raw_get_entity(&id)
        .expect("overlay read")
        .expect("the SKILL stands in the overlay");
    oneiron::skill::decode_skill_record(&staged).expect("decode staged skill")
}

/// Red (F6 residual): a handed-on owner's Active SKILL never stages a
/// person's provenance off record.
#[test]
fn a_handed_on_owner_slip_never_stages_a_persons_active_skill_off_record() {
    let f = Fixture::new();

    let record = stage_active_skill_off_record(&f, "sweep-skill-active-handed", true);

    assert_eq!(
        record.source,
        ClaimSource::Generated,
        "a handed-on Active SKILL stages Generated: {record:?}"
    );
    assert!(
        record.generated,
        "a handed-on Active SKILL stages generated"
    );
    assert!(
        !record.human_authored,
        "a handed-on Active SKILL stages not human-authored"
    );
}

/// Guard (F6 residual): the owner's own Active SKILL still stages UserStated.
#[test]
fn the_owners_own_slip_still_stages_a_persons_active_skill_off_record() {
    let f = Fixture::new();

    let record = stage_active_skill_off_record(&f, "sweep-skill-active-own", false);

    assert_eq!(
        record.source,
        ClaimSource::UserStated,
        "the owner's own Active SKILL keeps UserStated: {record:?}"
    );
    assert!(
        !record.generated,
        "the owner's own Active SKILL keeps generated false"
    );
    assert!(
        record.human_authored,
        "the owner's own Active SKILL keeps human-authored"
    );
}

/// A check-in answer for `memory` on a handle no check-in names: the person
/// gate answers first, so a refusal that names the person act is the gate's.
fn check_in_answer_on_no_such_handle(memory: &oneiron::memory::Memory<'_>) -> String {
    oneiron::verbs::check_in_answer(
        memory,
        oneiron::verbs::CheckInAnswerRequest {
            handle: EntityId::now().to_hex(),
            answer: oneiron::verbs::CheckInAnswerWord::Approve,
            effect_digest: "0".repeat(64),
        },
    )
    .expect_err("no check-in has this handle")
    .message
}

/// Red (F2 native person proof): the handed-on handle answers no check-in as the person.
#[test]
fn a_handed_on_owner_slip_never_answers_a_check_in_as_the_person() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, true,
    )
    .expect("marked no-proof handle");

    let refused = check_in_answer_on_no_such_handle(&memory);

    assert!(
        refused.contains("is a live person's own act"),
        "the person gate refuses a handed-on handle: {refused}"
    );
}

/// Guard (F2 native person proof): the owner's own handle passes the person gate.
#[test]
fn the_owners_own_slip_still_answers_a_check_in_as_the_person() {
    let f = Fixture::new();
    let memory = oneiron::test_doors::handed_on_no_proof::memory_with_host_origin_for_test(
        &f.vault, f.owner, false,
    )
    .expect("unmarked no-proof handle");

    let refused = check_in_answer_on_no_such_handle(&memory);

    assert!(
        !refused.contains("is a live person's own act"),
        "the owner's own handle passes the person gate to the missing check-in: {refused}"
    );
}
