//! The owner's writer of an agent's world access (ARCH-0067 #tiers; census
//! L2-56; rulings L2-56-VERB-SHAPE = A and L2-56-CONFIRM = A, 14 Nov 2026).
//!
//! ARCH-0067: an ALLOWED-SET grant is the owner's ("the agent can never
//! self-widen it"), and a DEFAULT-SUBSET is "owner-set or agent-proposed".
//! The owner sets both through `vault.agents.worlds.set` under the owner's
//! proof, and a change records the owner's act. The set replaces the grant
//! in force (the fold meets every grant, so a second row could only narrow),
//! an empty set revokes without falling back to base reality, and a grant
//! that no longer covers the agent's default narrows the default in the same
//! commit, so the agent's reads never fail closed. A set that changes
//! nothing writes and records nothing; a caller other than the owner, and an
//! id that names no agent or no world, are refused with nothing written. A
//! default counts when the agent or the owner wrote it, never because another
//! writer's row carries the owner's stamps.
//!
//! Every door is reached by its verb name, and every read and fixture
//! through a door the base (#7793) already has, so this file builds on a tree
//! without the doors and fails there at the first verb call.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test world_access_owner_writer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::world_access::put_world_access_row;
use oneiron::write_envelope::{
    WriteActor, WriteEnvelope, WriteProvenance, write_envelope_evidence,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, ResolvedWorldAuthority, TimeRange, Vault, VaultConfig,
    WorldAuthoritySet, world_access_claim_body,
};
use serde_json::{Value, json};

const GET: &str = "vault.agents.worlds.get";
const SET: &str = "vault.agents.worlds.set";
/// The owner act's setting name (`PolicySetting::as_str`).
const SETTING: &str = "settings.agent_world_access";
const LEARNED_AT: u64 = 1_780_000_000;

/// A vault this process owns (the writer lease), so the owner's handle
/// carries the owner's proof, with an agent definition and two worlds.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    w1: EntityId,
    w2: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault, owner) = open_owned(dir.path());
        let agent = define_agent(&vault).expect("an agent");
        let w1 = put_world(&vault);
        let w2 = put_world(&vault);
        Self {
            vault,
            owner,
            agent,
            w1,
            w2,
            _dir: dir,
        }
    }

    fn call(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        verb: &str,
        input: Value,
    ) -> MemoryResult<Value> {
        invoke(&self.vault.memory(actor, class), verb, input)
    }

    /// The owner sets the agent's grant, and its default when named.
    fn set(&self, allowed: Value, default_on: Option<Value>) -> MemoryResult<Value> {
        let mut input = json!({ "agent": self.agent.to_hex(), "allowed": allowed });
        if let Some(default_on) = default_on {
            input["default_on"] = default_on;
        }
        self.call(self.owner, EdgeActorClass::Human, SET, input)
    }

    /// The owner reads the agent's access.
    fn get(&self) -> Value {
        self.call(
            self.owner,
            EdgeActorClass::Human,
            GET,
            json!({ "agent": self.agent.to_hex() }),
        )
        .expect("the owner reads the agent's worlds")
    }

    /// The tiers the agent's reads resolve with no selection, through the
    /// board door main already has.
    fn authority(&self) -> ResolvedWorldAuthority {
        self.vault
            .board_world_authority(Some(self.agent), None)
            .expect("the agent's reads resolve")
    }

    /// The owner's acts on this setting, as this install recorded them.
    fn acts(&self) -> usize {
        self.vault
            .policy_setting_acts()
            .expect("the owner's setting acts")
            .iter()
            .filter(|receipt| receipt.setting.as_str() == SETTING)
            .count()
    }

    /// The agent's own default, stamped with its envelope as its own door
    /// stamps one, landed through #7793's fixture door (the raw put door
    /// parks a world-access row at the criticality floor).
    fn put_agent_default(&self, include_base: bool, worlds: &[EntityId]) {
        self.put_default(
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            (ClaimSource::Inferred, ClaimApprovalStatus::Auto),
            None,
            &authority_set(include_base, worlds),
        );
    }

    /// A default about the agent stamped with `writer`'s envelope, with the
    /// source and approval `stamps` names, valid from `valid_from`.
    fn put_default(
        &self,
        writer: WriteActor,
        stamps: (ClaimSource, ClaimApprovalStatus),
        valid_from: Option<u64>,
        subset: &WorldAuthoritySet,
    ) {
        let (source, approval) = stamps;
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            self.agent,
            subset,
            source,
            approval,
            valid_from,
            None,
        )
        .unwrap();
        let envelope = WriteEnvelope::new(
            writer,
            source,
            WriteProvenance::new(rmpv::Value::from("world-default-test")).unwrap(),
            approval,
        );
        body.evidence = Some(write_envelope_evidence(&envelope, None));
        // An agent definition has no substrate FACET, so the row takes the
        // vault default facet, as the setter's rows do.
        body.scope_facet = self.vault.default_facet().unwrap();
        put_world_access_row(
            &self.vault,
            &EntityId::now(),
            &body,
            at(LEARNED_AT),
            LEARNED_AT,
        )
        .expect("a default row about the agent");
    }
}

fn open_owned(path: &Path) -> (Vault, EntityId) {
    let vault = Vault::open_owned(path, VaultConfig::device()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn put_world(vault: &Vault) -> EntityId {
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            at(LEARNED_AT),
            LEARNED_AT,
            b"world",
        )
        .expect("a WORLD");
    world
}

/// A worlds value as the verbs spell it: base reality, and world ids
/// ascending.
fn worlds(include_base: bool, ids: &[EntityId]) -> Value {
    let mut ids = ids.to_vec();
    ids.sort();
    json!({
        "include_base": include_base,
        "worlds": ids.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
    })
}

fn authority_set(include_base: bool, ids: &[EntityId]) -> WorldAuthoritySet {
    WorldAuthoritySet::new(include_base, ids.iter().copied()).unwrap()
}

/// The owner grants base reality and W1 with W1 as the default: the agent's
/// reads resolve to them, the read verb answers them, and the change records
/// one owner act. The owner-set default counts beside the agent's own.
#[test]
fn the_owners_set_grants_the_agent_its_worlds() {
    let f = Fixture::new();
    let set_answer = f
        .set(worlds(true, &[f.w1]), Some(worlds(false, &[f.w1])))
        .expect("the owner sets the agent's worlds");
    assert_eq!(set_answer["changed"], json!(true), "{set_answer}");
    assert_eq!(set_answer["access"]["allowed"], worlds(true, &[f.w1]));
    assert_eq!(set_answer["access"]["default_on"], worlds(false, &[f.w1]));

    let authority = f.authority();
    assert_eq!(authority.allowed_set, authority_set(true, &[f.w1]));
    assert_eq!(authority.active_set, authority_set(false, &[f.w1]));
    assert_eq!(authority.allowed_claim_ids.len(), 1, "one grant row");
    assert!(
        authority.default_claim_id.is_some(),
        "the owner's default row"
    );

    let read = f.get();
    assert_eq!(read["governed"], json!(true), "{read}");
    assert_eq!(read["allowed"], worlds(true, &[f.w1]));
    assert_eq!(read["default_on"], worlds(false, &[f.w1]));
    assert_eq!(f.acts(), 1, "the change records the owner's act");
}

/// A wider grant replaces the narrower one. Under the fold's meet a second
/// row beside the first would have kept W1 alone.
#[test]
fn a_wider_set_replaces_the_narrower_one() {
    let f = Fixture::new();
    f.set(worlds(false, &[f.w1]), None)
        .expect("the owner grants W1");
    assert_eq!(f.authority().allowed_set, authority_set(false, &[f.w1]));

    f.set(worlds(false, &[f.w1, f.w2]), None)
        .expect("the owner widens to W1 and W2");
    let authority = f.authority();
    assert_eq!(
        authority.allowed_set,
        authority_set(false, &[f.w1, f.w2]),
        "the wider grant replaced the narrower one"
    );
    assert_eq!(
        authority.allowed_claim_ids.len(),
        1,
        "the grant in force was superseded, not met"
    );
    assert_eq!(f.acts(), 2, "each change records the owner's act");
}

/// An empty grant revokes: the agent reads nothing, never base reality.
#[test]
fn an_empty_set_revokes_and_never_falls_back_to_base() {
    let f = Fixture::new();
    f.set(worlds(true, &[f.w1]), None)
        .expect("the owner grants base and W1");
    assert_eq!(f.authority().active_set, authority_set(true, &[]));

    f.set(worlds(false, &[]), None).expect("the owner revokes");
    let authority = f.authority();
    assert!(authority.allowed_set.is_empty(), "{authority:?}");
    assert!(
        authority.active_set.is_empty(),
        "a revoked agent reads nothing, not base reality: {authority:?}"
    );
    let read = f.get();
    assert_eq!(read["governed"], json!(true), "{read}");
    assert_eq!(read["allowed"], worlds(false, &[]));
    assert_eq!(read["default_on"], worlds(false, &[]));
}

/// The agent's own default holds W1 and W2. The owner narrows the grant to
/// W1 and names no default: the default narrows to W1 in the same commit,
/// so the agent's reads still resolve instead of failing closed.
#[test]
fn a_narrowing_keeps_the_agents_reads_open() {
    let f = Fixture::new();
    f.set(worlds(false, &[f.w1, f.w2]), None)
        .expect("the owner grants W1 and W2");
    f.put_agent_default(false, &[f.w1, f.w2]);
    assert_eq!(
        f.authority().active_set,
        authority_set(false, &[f.w1, f.w2])
    );

    f.set(worlds(false, &[f.w1]), None)
        .expect("the owner narrows to W1");
    let authority = f
        .vault
        .board_world_authority(Some(f.agent), None)
        .expect("the agent's reads still resolve after the owner narrows its grant");
    assert_eq!(authority.allowed_set, authority_set(false, &[f.w1]));
    assert_eq!(
        authority.active_set,
        authority_set(false, &[f.w1]),
        "the default narrowed to the grant"
    );
}

/// The same access again writes nothing and records no act.
#[test]
fn an_unchanged_set_writes_and_records_nothing() {
    let f = Fixture::new();
    let first = f
        .set(worlds(true, &[f.w1]), Some(worlds(true, &[])))
        .expect("the owner sets");
    let again = f
        .set(worlds(true, &[f.w1]), Some(worlds(true, &[])))
        .expect("the same set again");
    assert_eq!(again["changed"], json!(false), "{again}");
    assert_eq!(
        again["access"], first["access"],
        "the rows in force are the first set's"
    );
    assert_eq!(f.acts(), 1, "an unchanged set records no act");
}

/// A default another writer wrote about the agent never counts, though it
/// is user-stated and approved, as a holder's settlement of that writer's
/// proposal leaves it: approval is no owner decision. Valid from an earlier
/// time, it would win precedence over the owner's empty default.
#[test]
fn a_default_another_writer_stated_never_counts() {
    let f = Fixture::new();
    f.set(worlds(true, &[]), Some(worlds(false, &[])))
        .expect("the owner grants base reality with an empty default");
    let other = f
        .vault
        .ensure_agent_principal("yuki")
        .expect("another agent");
    f.put_default(
        WriteActor::new(other, EdgeActorClass::Agent),
        (ClaimSource::UserStated, ClaimApprovalStatus::Approved),
        Some(LEARNED_AT),
        &authority_set(true, &[]),
    );

    let authority = f.authority();
    assert!(
        authority.active_set.is_empty(),
        "another writer's default moved the agent's: {authority:?}"
    );
    assert_eq!(f.get()["default_on"], worlds(false, &[]));
}

/// Only the owner sets or reads an agent's worlds. A listed id that is not a
/// WORLD, base reality named by its id, a default outside the grant, and an
/// id that names no agent are refused. Nothing is written or recorded.
#[test]
fn only_the_owner_sets_valid_worlds() {
    let f = Fixture::new();
    let agent = EdgeActorClass::Agent;
    let input = json!({ "agent": f.agent.to_hex(), "allowed": worlds(true, &[f.w1]) });
    let refusal = f
        .call(f.agent, agent, SET, input)
        .expect_err("an agent never sets its own worlds");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");
    let refusal = f
        .call(f.agent, agent, GET, json!({ "agent": f.agent.to_hex() }))
        .expect_err("an agent never reads the owner's door");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");

    let refusal = f
        .set(worlds(false, &[EntityId::now()]), None)
        .expect_err("an id with no row");
    assert!(refusal.message.contains("not a live WORLD"), "{refusal:?}");
    let refusal = f
        .set(worlds(false, &[oneiron::claim::base_world_id()]), None)
        .expect_err("base reality named by its id");
    assert!(refusal.message.contains("include_base"), "{refusal:?}");
    let refusal = f
        .set(worlds(false, &[f.w1]), Some(worlds(false, &[f.w2])))
        .expect_err("a default outside the grant");
    assert!(refusal.message.contains("within"), "{refusal:?}");
    let refusal = f
        .call(
            f.owner,
            EdgeActorClass::Human,
            SET,
            json!({ "agent": f.owner.to_hex(), "allowed": worlds(true, &[]) }),
        )
        .expect_err("the owner's PERSON is no agent");
    assert!(refusal.message.contains("agent principal"), "{refusal:?}");

    assert_eq!(f.acts(), 0, "a refused set records nothing");
    assert_eq!(
        f.authority(),
        ungoverned(),
        "a refused set writes nothing: the agent still reads base reality"
    );
}

/// Control: an agent no grant governs reads base reality. Passes on main
/// too.
#[test]
fn an_agent_no_grant_governs_reads_base_reality() {
    let f = Fixture::new();
    assert_eq!(f.authority(), ungoverned());
}

/// The tiers of an actor no grant governs: base reality only.
fn ungoverned() -> ResolvedWorldAuthority {
    let base = authority_set(true, &[]);
    ResolvedWorldAuthority {
        allowed_set: base.clone(),
        default_subset: base.clone(),
        active_set: base,
        allowed_claim_ids: Vec::new(),
        default_claim_id: None,
    }
}
