//! An agent's generic row writers follow ARCH-0053:20 for AGENT_DEF rows.
//!
//! Canon ARCH-0053:20 (owner, 22 Sep 2026): "An agent may author an
//! AGENT_DEF for later use under the same rule as a skill: a definition that
//! widens nothing lands Active at the author's ceiling; anything beyond the
//! author's slice is a proposal."
//!
//! `vault.agents.put` applies that rule. An agent's code-mode run also reaches
//! the generic `vault.structural.put` and `vault.batch` rows: a pumped run's
//! `RunHostDoor` answers them on the agent's own Agent-class `Memory`
//! (crates/oneiron-server/src/server/run_host_door.rs:830-876), and that
//! `Memory` also holds the raw entity put. These tests write an AGENT_DEF
//! through each of those doors on an Agent-class `Memory`.
//!
//! A new definition wider than its Base, ceiling-Proposed author lands as a
//! proposal no dispatch runs; one inside the author's slice lands active. A
//! put that grants a stored definition more than its author's slice holds
//! leaves that definition as it is, still working, and stores the wider
//! version as a separate proposal record that names it (ARCH-0053 r6: "a
//! skill update that widens the capability surface requires human
//! re-consent; doc-only or narrowing edits flow auto"). An author whose own
//! slice holds the wider grant applies it. An edit that grants nothing new
//! stays active. None of these is refused.
//!
//! The slice is what the writer can itself use (owner, 10 Nov 2026: "a
//! definition within the creating agent's own powers goes live"). An agent
//! with no definition of its own lends the slice its grant gives it, and one
//! with no grant at all lends none. A definition that names a skill its
//! author can load is inside the slice; one that names a skill or a
//! connector its author cannot use is a proposal.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::authority::{ActSurface, AgentTier};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, base_world_id};
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{CanAnswer, CanEffectVerdict};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use oneiron::skill::{SkillDependency, SkillLifecycle, SkillRecord};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, CanRequest};
use oneiron::{EdgeActorClass, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const AUTHOR: u8 = 0x70;
const WIDE_AUTHOR: u8 = 0x71;

/// The key the engine derives the id of a proposed change under
/// (`agent_def/doors.rs`, `PROPOSED_CHANGE_ID_CONTEXT`).
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

/// The id the engine stores version `version` of the definition at `stored`
/// under, as a proposal: the first 16 bytes of the keyed BLAKE3 hash of the
/// stored id's bytes then the version's.
fn proposed_change_id(stored: &EntityId, version: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(stored.as_bytes());
    hasher.update(version.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).expect("derived proposal id")
}

fn definition(
    name: &str,
    scope: AgentScope,
    ceiling: AgentCeiling,
    source: ClaimSource,
    generated: bool,
    human_authored: bool,
) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "generic writer conformance fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        source,
        1.0,
        generated,
        human_authored,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => Value::Bool(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("an integer fits i64 or u64"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => Value::String(text.as_str().expect("UTF-8").to_owned()),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

/// How a new candidate stands against its Base, ceiling-Proposed author.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slice {
    /// Scope All, ceiling Auto.
    Wider,
    /// Scope Base, ceiling Proposed: the author's own.
    Within,
}

/// A new candidate: Approved, Active, enabled, at the scope and ceiling
/// `slice` names.
fn candidate(slice: Slice) -> AgentDefinition {
    let (scope, ceiling) = match slice {
        Slice::Wider => (AgentScope::All, AgentCeiling::Auto),
        Slice::Within => (AgentScope::Base, AgentCeiling::Proposed),
    };
    definition(
        "conformance.candidate",
        scope,
        ceiling,
        ClaimSource::Generated,
        true,
        false,
    )
}

/// A personal vault whose owner created two agents.
struct Fixture {
    vault: Vault,
    /// The embedded owner's PERSON row.
    owner_person: EntityId,
    /// The Base, ceiling-Proposed agent the owner created.
    author: EntityId,
    /// The All, ceiling-Proposed agent the owner created.
    wide_author: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &definition(
                "conformance.author",
                AgentScope::Base,
                AgentCeiling::Proposed,
                ClaimSource::UserStated,
                false,
                true,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    let wide_author = EntityId::from_bytes([WIDE_AUTHOR; 16]).expect("wide author id");
    vault
        .create_agent_definition_as(
            &owner,
            &wide_author,
            &definition(
                "conformance.wide_author",
                AgentScope::All,
                AgentCeiling::Proposed,
                ClaimSource::UserStated,
                false,
                true,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the All, ceiling-Proposed author");
    // A put over a stored row is admitted only on a lane that reads the row.
    // Each author reads the rows it updates; the permits grant a read alone.
    // One call installs both: the installer takes the unchanged stock policy.
    vault
        .install_read_permits_for_test(&[
            oneiron::WriteActor::new(author, EdgeActorClass::Agent),
            oneiron::WriteActor::new(wide_author, EdgeActorClass::Agent),
        ])
        .expect("each author reads the stored rows it updates");
    Fixture {
        vault,
        owner_person,
        author,
        wide_author,
        _dir: dir,
    }
}

/// A door an Agent-class `Memory` writes an AGENT_DEF row through.
#[derive(Clone, Copy)]
enum Door {
    /// The generated `vault.structural.put` row.
    StructuralPut,
    /// The generated `vault.batch` row.
    Batch,
    /// `Memory::raw_put_entity`.
    RawPut,
}

impl Door {
    fn name(self) -> &'static str {
        match self {
            Self::StructuralPut => "vault.structural.put",
            Self::Batch => "vault.batch",
            Self::RawPut => "memory.raw_put_entity",
        }
    }
}

/// Puts `def` at `id` through `door` on the Agent-class `Memory` of `writer`,
/// as the run host door binds it.
fn put(
    vault: &Vault,
    writer: EntityId,
    door: Door,
    id: EntityId,
    def: &AgentDefinition,
    at: u64,
) -> Result<(), String> {
    let memory = vault.memory(writer, EdgeActorClass::Agent);
    let bytes = encode_agent_definition(def).expect("valid definition");
    let input = match door {
        Door::RawPut => {
            return memory
                .raw_put_entity(RawEntityPut {
                    id,
                    entity_type: ENTITY_TYPE_AGENT_DEF,
                    occurred: TimeRange { start: at, end: at },
                    learned_at: at,
                    data: &bytes,
                })
                .map_err(|error| format!("{error:?}"));
        }
        Door::StructuralPut => json!({
            "id": id.to_hex(),
            "kind": "AGENT_DEF",
            "body": json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack")),
            "occurred_at": at,
            "learned_at": at,
        }),
        Door::Batch => json!({"entities": [{
            "id": id.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": at,
            "occurred_end": at,
            "learned_at": at,
            "body": json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack")),
        }]}),
    };
    let verb = door.name();
    assert!(
        oneiron::task_verb::sdk::code_mode_verb_names().any(|name| name == verb),
        "{verb} is a code-mode row"
    );
    oneiron::task_verb::sdk::invoke(&memory, verb, input)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

/// What ARCH-0053:20 says a put left at its id.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lands {
    /// A proposal: stored, never dispatched.
    Proposal,
    /// Active at the author's approval, and dispatchable.
    Active,
}

/// One dispatch of the definition at `id`, as a label.
fn dispatch_of(vault: &Vault, id: EntityId) -> String {
    match AgentDispatcher::new(vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: NOW + 9,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

fn write_label_of(write: &Result<(), String>) -> String {
    match write {
        Ok(()) => "landed".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

/// How a definition stands, as a label; `absent` for no row.
fn standing_of(def: Option<&AgentDefinition>) -> String {
    def.map_or_else(
        || "absent".to_owned(),
        |def| {
            format!(
                "version={} approval={:?} lifecycle={:?} enabled={} scope={:?} ceiling={:?} source={:?}",
                def.version,
                def.approval_status,
                def.lifecycle_status,
                def.enabled,
                def.scope,
                def.ceiling,
                def.source
            )
        },
    )
}

/// Holds a put that widened the stored definition `before` at `id` to a
/// proposed change: the stored row is as it was and still dispatches, and
/// version `version` stands beside it as a proposal that names it and that no
/// dispatch runs. Prints one `CONFORMANCE` line.
fn assert_proposed_change(
    case: &str,
    write: &Result<(), String>,
    vault: &Vault,
    id: EntityId,
    before: &AgentDefinition,
    version: &str,
) {
    let stored = vault
        .get_agent_definition(&id)
        .expect("read the stored row");
    let proposal_id = proposed_change_id(&id, version);
    let proposal = vault
        .get_agent_definition(&proposal_id)
        .expect("read the proposal id");
    let stored_dispatch = dispatch_of(vault, id);
    let proposal_dispatch = dispatch_of(vault, proposal_id);
    let write_label = write_label_of(write);
    println!(
        "CONFORMANCE case={case} write={write_label} stored=[{}] dispatch={stored_dispatch} proposal=[{}] proposal_dispatch={proposal_dispatch}",
        standing_of(stored.as_ref()),
        standing_of(proposal.as_ref()),
    );
    assert!(
        write.is_ok(),
        "ARCH-0053:20: {case}: the put was refused: {write_label}"
    );
    assert!(
        stored.as_ref() == Some(before),
        "ARCH-0053 r6: {case}: a put wider than its author's slice changed the stored definition"
    );
    assert_eq!(
        stored_dispatch, "dispatched",
        "{case}: the stored definition keeps working after a widening put"
    );
    let proposal = proposal.expect("ARCH-0053 r6: the wider version is stored as a proposal");
    assert_eq!(
        proposal.approval_status,
        ClaimApprovalStatus::Proposed,
        "ARCH-0053:20: {case}: the wider version is stored as other than a proposal"
    );
    assert_eq!(
        proposal.version, version,
        "{case}: the proposal is the version put"
    );
    assert!(
        proposal.scope == AgentScope::All,
        "{case}: the proposal holds the wider scope"
    );
    let names_stored = match &proposal.provenance {
        RmpValue::Map(entries) => entries.iter().any(|(key, value)| {
            key.as_str() == Some("replaces") && value.as_str() == Some(id.to_hex().as_str())
        }),
        _ => false,
    };
    assert!(
        names_stored,
        "{case}: the proposal names the definition it would replace"
    );
    assert_ne!(
        proposal_dispatch, "dispatched",
        "ARCH-0053:20: {case}: the proposal is dispatchable"
    );
}

/// Reads `id` back after `write`, tries one dispatch of it, prints one
/// `CONFORMANCE` line and holds the row to `lands`.
fn assert_lands(case: &str, write: &Result<(), String>, vault: &Vault, id: EntityId, lands: Lands) {
    let stored = vault.get_agent_definition(&id).expect("read the row");
    let dispatch = dispatch_of(vault, id);
    let write_label = write_label_of(write);
    let standing = standing_of(stored.as_ref());
    println!("CONFORMANCE case={case} write={write_label} stored=[{standing}] dispatch={dispatch}");
    assert!(
        write.is_ok(),
        "ARCH-0053:20: {case}: the put was refused: {write_label}"
    );
    let def = stored.expect("the put left a definition");
    assert_eq!(
        def.lifecycle_status,
        ClaimLifecycleStatus::Active,
        "{case}: a saved definition is live at rest"
    );
    match lands {
        Lands::Proposal => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Proposed,
                "ARCH-0053:20: {case}: a definition wider than its author's slice is stored as other than a proposal"
            );
            assert_ne!(
                dispatch, "dispatched",
                "ARCH-0053:20: {case}: a definition wider than its author's slice is dispatchable"
            );
        }
        Lands::Active => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Approved,
                "ARCH-0053:20: {case}: a definition inside its author's slice is not at the author's approval"
            );
            assert!(def.enabled, "{case}: the definition stays enabled");
            assert_eq!(
                dispatch, "dispatched",
                "ARCH-0053:20: {case}: a definition inside its author's slice is undispatchable"
            );
        }
    }
}

/// The author puts a new candidate through `door`.
fn run_new_definition(door: Door, candidate_seed: u8, slice: Slice) {
    let fixture = fixture();
    let id = EntityId::from_bytes([candidate_seed; 16]).expect("candidate id");
    assert!(
        fixture
            .vault
            .get_agent_definition(&id)
            .expect("fresh id")
            .is_none()
    );
    let write = put(
        &fixture.vault,
        fixture.author,
        door,
        id,
        &candidate(slice),
        NOW + 1,
    );
    let (slice_label, lands) = match slice {
        Slice::Wider => ("wider", Lands::Proposal),
        Slice::Within => ("within", Lands::Active),
    };
    assert_lands(
        &format!("agent-memory/{}/new/{slice_label}", door.name()),
        &write,
        &fixture.vault,
        id,
        lands,
    );
}

/// `author` creates a Base, ceiling-Proposed child through `vault.batch`,
/// inside its own slice, and the child stands active.
fn author_creates_child(
    fixture: &Fixture,
    author: EntityId,
    child_seed: u8,
) -> (EntityId, AgentDefinition) {
    let id = EntityId::from_bytes([child_seed; 16]).expect("child id");
    put(
        &fixture.vault,
        author,
        Door::Batch,
        id,
        &candidate(Slice::Within),
        NOW + 1,
    )
    .expect("the author creates a child inside its slice");
    let child = fixture
        .vault
        .get_agent_definition(&id)
        .expect("read the child")
        .expect("the child row");
    assert_eq!(
        child.approval_status,
        ClaimApprovalStatus::Approved,
        "a child inside its author's slice starts active"
    );
    (id, child)
}

#[test]
fn agent_structural_put_stores_no_active_definition_wider_than_its_slice() {
    run_new_definition(Door::StructuralPut, 0x72, Slice::Wider);
}

#[test]
fn agent_batch_stores_no_active_definition_wider_than_its_slice() {
    run_new_definition(Door::Batch, 0x73, Slice::Wider);
}

#[test]
fn agent_structural_put_stores_a_definition_inside_its_slice_active() {
    run_new_definition(Door::StructuralPut, 0x74, Slice::Within);
}

#[test]
fn agent_batch_stores_a_definition_inside_its_slice_active() {
    run_new_definition(Door::Batch, 0x75, Slice::Within);
}

#[test]
fn agent_raw_put_stores_no_active_definition_wider_than_its_slice() {
    run_new_definition(Door::RawPut, 0x76, Slice::Wider);
}

#[test]
fn agent_raw_put_stores_a_definition_inside_its_slice_active() {
    run_new_definition(Door::RawPut, 0x77, Slice::Within);
}

/// A PERSON bound as an agent that holds no definition and no grant has no
/// slice to lend: even the narrowest definition it authors is a proposal.
#[test]
fn agent_without_a_definition_or_a_grant_stores_a_new_definition_as_a_proposal() {
    let fixture = fixture();
    let id = EntityId::from_bytes([0x78; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        fixture.owner_person,
        Door::Batch,
        id,
        &candidate(Slice::Within),
        NOW + 1,
    );
    assert_lands(
        "person-as-agent-memory/vault.batch/new/narrowest",
        &write,
        &fixture.vault,
        id,
        Lands::Proposal,
    );
}

/// The author's own stored definition as it stands, and that definition at
/// scope All, version "2".
fn own_definition_widened(fixture: &Fixture) -> (AgentDefinition, AgentDefinition) {
    let before = fixture
        .vault
        .get_agent_definition(&fixture.author)
        .expect("read the author")
        .expect("the author row");
    let mut wider = before.clone();
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    (before, wider)
}

#[test]
fn agent_batch_widening_its_own_definition_stores_a_separate_proposal() {
    let fixture = fixture();
    let (before, wider) = own_definition_widened(&fixture);
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        fixture.author,
        &wider,
        NOW + 5,
    );
    assert_proposed_change(
        "agent-memory/vault.batch/own-row/scope-base-to-all",
        &write,
        &fixture.vault,
        fixture.author,
        &before,
        "2",
    );
}

#[test]
fn agent_raw_put_widening_its_own_definition_stores_a_separate_proposal() {
    let fixture = fixture();
    let (before, wider) = own_definition_widened(&fixture);
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::RawPut,
        fixture.author,
        &wider,
        NOW + 5,
    );
    assert_proposed_change(
        "agent-memory/memory.raw_put_entity/own-row/scope-base-to-all",
        &write,
        &fixture.vault,
        fixture.author,
        &before,
        "2",
    );
}

#[test]
fn agent_batch_widening_a_definition_it_authored_stores_a_separate_proposal() {
    let fixture = fixture();
    let (id, before) = author_creates_child(&fixture, fixture.author, 0x79);
    let mut wider = before.clone();
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        id,
        &wider,
        NOW + 5,
    );
    assert_proposed_change(
        "agent-memory/vault.batch/authored-row/scope-base-to-all",
        &write,
        &fixture.vault,
        id,
        &before,
        "2",
    );
}

/// An author whose own slice holds the wider grant holds the power to give
/// it: its widening put of a definition it authored is applied.
#[test]
fn agent_batch_widening_inside_its_own_slice_is_applied() {
    let fixture = fixture();
    let (id, mut wider) = author_creates_child(&fixture, fixture.wide_author, 0x7B);
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    let write = put(
        &fixture.vault,
        fixture.wide_author,
        Door::Batch,
        id,
        &wider,
        NOW + 5,
    );
    assert_lands(
        "wide-agent-memory/vault.batch/authored-row/scope-base-to-all",
        &write,
        &fixture.vault,
        id,
        Lands::Active,
    );
    let stored = fixture
        .vault
        .get_agent_definition(&id)
        .expect("read the child")
        .expect("the child row");
    assert!(
        stored.scope == AgentScope::All && stored.version == "2",
        "the widening inside the author's slice landed"
    );
}

#[test]
fn agent_batch_edit_that_grants_a_stored_definition_nothing_new_stays_active() {
    let fixture = fixture();
    let (id, mut edited) = author_creates_child(&fixture, fixture.author, 0x7A);
    edited.instructions = Some("Count twice.\n".to_owned());
    edited.version = "2".to_owned();
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        id,
        &edited,
        NOW + 5,
    );
    assert_lands(
        "agent-memory/vault.batch/authored-row/instructions-only",
        &write,
        &fixture.vault,
        id,
        Lands::Active,
    );
    let stored = fixture
        .vault
        .get_agent_definition(&id)
        .expect("read the child")
        .expect("the child row");
    assert_eq!(stored.version, "2", "the edit landed");
}

/// A named agent's principal: a PERSON row, which holds no definition.
fn named_agent(fixture: &Fixture, name: &str) -> EntityId {
    let writer = fixture
        .vault
        .ensure_agent_principal(name)
        .expect("named agent principal");
    assert_eq!(
        fixture.vault.get_entity_type(&writer).expect("entity type"),
        Some(ENTITY_TYPE_PERSON),
        "a named agent's principal holds no definition"
    );
    writer
}

/// The owner grants `writer` read, propose and write over base reality alone,
/// through `vault.agents.grants.mint`.
///
/// The owner's grant act is signed by this install's machine key, so the
/// vault is rooted and the install enrolled first, as a serving start does.
fn grant_base_reach(fixture: &Fixture, writer: EntityId) {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = oneiron::verbs::mint_agent_grant_as(
        &fixture.vault,
        &owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: writer,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("the owner grants the agent base reality");
    assert!(minted.grant.confers, "the grant confers");
}

/// An agent with no definition of its own lends the slice its grant gives
/// it: a definition inside the grant's worlds lands active.
#[test]
fn agent_with_a_grant_and_no_definition_stores_a_definition_inside_its_grant_active() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.granted-author");
    grant_base_reach(&fixture, writer);
    let id = EntityId::from_bytes([0x7C; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        writer,
        Door::Batch,
        id,
        &candidate(Slice::Within),
        NOW + 1,
    );
    assert_lands(
        "granted-agent-memory/vault.batch/new/base-inside-base-grant",
        &write,
        &fixture.vault,
        id,
        Lands::Active,
    );
}

/// The same grant does not hold every world: a definition at scope All, with
/// the ceiling left Proposed so the scope alone is wider, is a proposal.
#[test]
fn agent_with_a_grant_and_no_definition_stores_a_definition_wider_than_its_grant_as_a_proposal() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.granted-author");
    grant_base_reach(&fixture, writer);
    let id = EntityId::from_bytes([0x7D; 16]).expect("candidate id");
    let mut wider = candidate(Slice::Within);
    wider.scope = AgentScope::All;
    let write = put(&fixture.vault, writer, Door::Batch, id, &wider, NOW + 1);
    assert_lands(
        "granted-agent-memory/vault.batch/new/all-outside-base-grant",
        &write,
        &fixture.vault,
        id,
        Lands::Proposal,
    );
}

/// The control of the two tests above: the same kind of principal with no
/// grant lends no slice.
#[test]
fn named_agent_with_no_grant_stores_a_new_definition_as_a_proposal() {
    let fixture = fixture();
    let writer = named_agent(&fixture, "conformance.grantless-author");
    let id = EntityId::from_bytes([0x7E; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        writer,
        Door::Batch,
        id,
        &candidate(Slice::Within),
        NOW + 1,
    );
    assert_lands(
        "grantless-agent-memory/vault.batch/new/narrowest",
        &write,
        &fixture.vault,
        id,
        Lands::Proposal,
    );
}

/// The name of the shared skill [`shared_active_skill`] stores.
const SHARED_SKILL: &str = "conformance.shared";

/// Stores a shared skill, active and approved, and loads it on a leased
/// attempt bound to `writer` through the public load door: the writer can
/// use this skill. Returns the dependency that names it.
fn shared_active_skill(fixture: &Fixture, writer: EntityId) -> SkillDependency {
    let vault = &fixture.vault;
    let skill = EntityId::from_bytes([0x6B; 16]).expect("skill id");
    let mut record = SkillRecord::new(
        SHARED_SKILL,
        "generic writer conformance skill",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        RmpValue::Map(vec![(
            RmpValue::from("source"),
            RmpValue::from("conformance"),
        )]),
    );
    let at = |offset: u64| TimeRange {
        start: NOW + offset,
        end: NOW + offset,
    };
    vault
        .put_skill_record(&skill, &record, at(1), NOW + 1)
        .expect("the skill is born a candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&skill, &record, at(2), NOW + 2)
        .expect("the skill is activated");
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(queued) = queue
        .enqueue(EnqueueAttempt {
            kind: "conformance.skill-load".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: None,
            now: NOW + 3,
        })
        .expect("enqueue the writer's attempt")
    else {
        panic!("a fresh attempt is enqueued");
    };
    vault
        .bind_actor_attempt(queued.id, &writer)
        .expect("the attempt is the writer's");
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            "conformance.skill-load",
            ClaimAttempt {
                lease_owner: "conformance-skill-worker".to_owned(),
                now: NOW + 4,
            },
        )
        .expect("claim the writer's attempt")
    else {
        panic!("the attempt is leased");
    };
    let loaded = vault
        .load_attempt_skill_pack(
            leased.id,
            &skill,
            "conformance-skill-worker",
            leased.attempt_count,
            "conformance/model@1",
            NOW + 5,
        )
        .expect("the load door loads the skill on the writer's attempt");
    assert_eq!(loaded.record.skill_id, SHARED_SKILL);
    println!(
        "CONFORMANCE case=skill-load writer={} skill={SHARED_SKILL} load=loaded",
        writer.to_hex()
    );
    SkillDependency::new(SHARED_SKILL)
}

/// A definition that names a skill its author can load is inside the slice,
/// though the author's own definition lists no skill.
#[test]
fn agent_batch_stores_a_definition_naming_a_skill_its_author_can_load_active() {
    let fixture = fixture();
    let dependency = shared_active_skill(&fixture, fixture.author);
    let author = fixture
        .vault
        .get_agent_definition(&fixture.author)
        .expect("read the author")
        .expect("the author row");
    assert!(
        author.skills.is_empty(),
        "the author's definition lists no skill"
    );
    let mut requested = candidate(Slice::Within);
    requested.skills = vec![dependency];
    let id = EntityId::from_bytes([0x7F; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        id,
        &requested,
        NOW + 6,
    );
    assert_lands(
        "agent-memory/vault.batch/new/skill-the-author-loads",
        &write,
        &fixture.vault,
        id,
        Lands::Active,
    );
}

/// A definition that names a skill the vault does not hold names one its
/// author cannot load: a proposal.
#[test]
fn agent_batch_stores_a_definition_naming_a_skill_its_author_cannot_load_as_a_proposal() {
    let fixture = fixture();
    let mut requested = candidate(Slice::Within);
    requested.skills = vec![SkillDependency::new("conformance.absent")];
    let id = EntityId::from_bytes([0x80; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        id,
        &requested,
        NOW + 1,
    );
    assert_lands(
        "agent-memory/vault.batch/new/skill-the-author-cannot-load",
        &write,
        &fixture.vault,
        id,
        Lands::Proposal,
    );
}

/// A definition that names a connector its author cannot call is a proposal.
/// The runtime's own preflight of a call on that connector does not allow it
/// for the author.
#[test]
fn agent_batch_stores_a_definition_naming_a_connector_its_author_cannot_use_as_a_proposal() {
    const CONNECTOR: &str = "conformance_forbidden";
    let fixture = fixture();
    let preflight: CanRequest = serde_json::from_value(json!({
        "effect": {"connector_call": {"name": CONNECTOR, "tool": "fetch", "arguments": {}}}
    }))
    .expect("a connector call preflight");
    let answer = fixture
        .vault
        .memory(fixture.author, EdgeActorClass::Agent)
        .can(&preflight);
    let (allowed, label) = match &answer {
        Ok(CanAnswer::Effect(answer)) => (
            answer.verdict == CanEffectVerdict::Allow,
            format!(
                "{:?} reasons={:?} holds={:?}",
                answer.verdict, answer.reasons, answer.holds
            ),
        ),
        Ok(_) => (false, "an ask preflight".to_owned()),
        Err(error) => (false, format!("refused: {error:?}")),
    };
    println!("CONFORMANCE case=connector-preflight connector={CONNECTOR} can={label}");
    assert!(
        !allowed,
        "the author cannot call {CONNECTOR}: the preflight answered {label}"
    );
    let mut requested = candidate(Slice::Within);
    requested.connectors = vec![CONNECTOR.to_owned()];
    let id = EntityId::from_bytes([0x81; 16]).expect("candidate id");
    let write = put(
        &fixture.vault,
        fixture.author,
        Door::Batch,
        id,
        &requested,
        NOW + 1,
    );
    assert_lands(
        "agent-memory/vault.batch/new/connector-the-author-cannot-use",
        &write,
        &fixture.vault,
        id,
        Lands::Proposal,
    );
}
