// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [WORLD-ACCESS-GRANT-ROW-OVERWRITE-UNGOVERNS]: an agent's put below the
//! owner over the id of the owner's ALLOWED-SET grant about it.
//! `core.world_access.*` is no reserved predicate, so a sourceless row under
//! another predicate landed at that id whenever the agent's lane read the
//! grant row. The fold then found no grant about the agent, and the agent
//! read base reality: out of a confinement to one WORLD, or out of a pause.
//!
//! The lane's stored-target check (`put_target_admitted_in`) now refuses a
//! put below the owner over a world-access grant or default; only the
//! governed doors write either tier. The agent holds the owner's read Grant
//! over the whole vault, so its lane reads the grant row by id: each test
//! asserts that precondition before the put.
//!
//! The owner's grant lands through the cfg door #7793 added
//! (`test_doors::world_access`); the agent writes through its own bound raw
//! put and through `vault.claims.upsert`'s door.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test world_access_grant_row_guard`.
#![cfg(oneiron_test_support)]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::memory::{ClaimInput, MemoryResult};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::world_access::put_world_access_row;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, RawEntityPut, ResolvedWorldAuthority, TimeRange, Vault,
    VaultConfig, WorldAuthoritySet, world_access_claim_body,
};
use serde_json::{Value, json};

const LEARNED_AT: u64 = 1_780_000_000;

/// The predicate of the agent's own row. The shipped manifest rates
/// `profile.` normal, so the agent's Auto ceiling lands it Auto.
const NOTE: &str = "profile.note";

/// A vault rooted under a host (an owner's native Grant needs a rooted
/// vault) with the shipped default manifest; an agent the owner granted read
/// over the whole vault and an Auto ceiling; and one WORLD.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    world: EntityId,
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
        let issuer =
            HostSlipIssuer::from_secret(b"world-access-grant-row").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("world-grant-row-agent")
            .expect("agent");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent read and an Auto ceiling");
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
        Self {
            vault,
            agent,
            world,
            facet,
            _directory: directory,
        }
    }

    /// The owner's grant of `set` to the agent, landed through the cfg door
    /// at a fresh id. Returns that id.
    fn grant(&self, set: &WorldAuthoritySet) -> EntityId {
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            set,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap();
        body.scope_facet = self.facet;
        let id = EntityId::now();
        put_world_access_row(&self.vault, &id, &body, at(LEARNED_AT), LEARNED_AT)
            .expect("the owner's grant");
        id
    }

    /// The agent's raw put, through its own bound handle, of a sourceless
    /// Auto row about itself at `id`, in the facet the owner's grant is in.
    fn agent_puts_a_note_at(&self, id: EntityId) -> MemoryResult<()> {
        let mut body = ClaimBody::new(
            NOTE,
            ClaimSubject::Entity(self.agent),
            rmpv::Value::from("a note"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.source = None;
        body.scope_facet = self.facet;
        let data = encode_claim_body(&body).unwrap();
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .raw_put_entity(RawEntityPut {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: at(LEARNED_AT),
                learned_at: LEARNED_AT,
                data: &data,
            })
    }

    /// Whether the agent's own lane reads the row at `id` by id.
    fn agent_reads_by_id(&self, id: EntityId) -> bool {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .get_entity(&id.to_hex())
            .expect("the agent's read by id")
            .value
            .is_some()
    }

    /// The agent writes its own default through `vault.claims.upsert`'s door.
    fn agent_writes_its_default(&self, value: Value) -> MemoryResult<String> {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_upsert(&ClaimInput {
                id: None,
                predicate: PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET.to_owned(),
                subject_ref: self.agent.to_hex(),
                value,
                confidence: 1.0,
                confidence_details: None,
                source: "observed".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: Some(json!({ "facet": self.facet.to_hex() })),
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
            })
            .map(|receipt| receipt.approval)
    }

    /// The tiers the agent's reads resolve with no selection.
    fn agent_reads(&self) -> ResolvedWorldAuthority {
        self.vault
            .board_world_authority(Some(self.agent), None)
            .expect("the agent's tiers resolve")
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A world-access value with no world ids, as the JSON doors spell it.
fn json_base_only(include_base: bool) -> Value {
    json!({
        "schema_version": 1,
        "include_base": include_base,
        "worlds": [],
    })
}

/// The owner grants the agent the set `granted` names; the agent, whose
/// lane reads that grant row by id, puts its own row over the grant's id.
/// The put is refused, the grant row keeps its predicate, and the grant
/// still governs the agent.
fn the_grant_survives_the_agents_put_over_its_id(granted: fn(&Fixture) -> WorldAuthoritySet) {
    let f = Fixture::new();
    let set = &granted(&f);
    let grant = f.grant(set);
    let before = f.agent_reads();
    assert_eq!(
        &before.allowed_set, set,
        "the owner's grant governs the agent"
    );
    assert_eq!(before.allowed_claim_ids, vec![grant]);
    assert!(
        f.agent_reads_by_id(grant),
        "the agent's lane reads the grant row by id (the FIX row's precondition)"
    );

    let put = f.agent_puts_a_note_at(grant);

    let after = f.agent_reads();
    assert_eq!(
        &after.allowed_set, set,
        "the owner's grant still governs the agent after its put over the grant's id \
         (put: {put:?})"
    );
    assert_eq!(after.allowed_claim_ids, vec![grant]);
    assert!(
        put.is_err(),
        "the put over the grant's id is refused: {put:?}"
    );
    let stored = f
        .vault
        .get_claim(&grant)
        .expect("read the grant row")
        .expect("the grant row stands");
    assert_eq!(
        stored.predicate, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        "the grant row keeps its predicate"
    );
}

/// The owner confines the agent to one WORLD, without base reality.
#[test]
fn an_agents_put_over_its_confinement_grant_never_ungoverns_it() {
    the_grant_survives_the_agents_put_over_its_id(|f| {
        WorldAuthoritySet::new(false, [f.world]).unwrap()
    });
}

/// The owner pauses the agent: no world and no base reality.
#[test]
fn an_agents_put_over_its_pause_grant_never_ungoverns_it() {
    the_grant_survives_the_agents_put_over_its_id(|_| WorldAuthoritySet::new(false, []).unwrap());
}

/// Control: the same row at a fresh id lands, and governs nothing.
#[test]
fn an_agents_row_at_a_fresh_id_lands() {
    let f = Fixture::new();
    let set = WorldAuthoritySet::new(false, [f.world]).unwrap();
    let grant = f.grant(&set);
    let id = EntityId::now();

    f.agent_puts_a_note_at(id)
        .expect("the agent's own row at a fresh id lands");

    let stored = f
        .vault
        .get_claim(&id)
        .expect("read the agent's row")
        .expect("the agent's row stands");
    assert_eq!(stored.predicate, NOTE);
    let reads = f.agent_reads();
    assert_eq!(reads.allowed_set, set, "the owner's grant still governs");
    assert_eq!(reads.allowed_claim_ids, vec![grant]);
}

/// Control: the agent's second default through the claim door replaces its
/// first. The door closes the first default in its own writer, never by a
/// put over its id, so the guard leaves it as it was.
#[test]
fn an_agents_second_default_replaces_its_first() {
    let f = Fixture::new();
    f.grant(&WorldAuthoritySet::new(true, [f.world]).unwrap());

    let first = f
        .agent_writes_its_default(json_base_only(true))
        .expect("the agent's first default lands");
    let first_id = f.agent_reads().default_claim_id;
    let second = f
        .agent_writes_its_default(json_base_only(false))
        .expect("the agent's second default lands");

    assert_eq!((first.as_str(), second.as_str()), ("auto", "auto"));
    let reads = f.agent_reads();
    assert_eq!(
        reads.default_subset,
        WorldAuthoritySet::new(false, []).unwrap(),
        "the agent's newest default is its default"
    );
    assert!(
        reads.default_claim_id.is_some() && reads.default_claim_id != first_id,
        "the second default is a row of its own: {:?} after {first_id:?}",
        reads.default_claim_id
    );
}
