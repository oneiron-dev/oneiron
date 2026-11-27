//! A bound caller's raw vector put is held to its write lane (FIX 6068;
//! review of #10218, round 1). `Memory::raw_put_vector` and
//! `raw_put_vector_with_provenance`, which the C, N-API, Swift and Android
//! hosts call for a bound vault, committed a vector over any stored row: the
//! batch terminal judged only puts. A bound agent whose Grant reaches TURNs
//! alone replaced the vector and the device mark of an ASSET the owner wrote,
//! a row its lane withholds. That put now answers as missing, marked or not,
//! and the owner's vector and mark stay; a vector over a row the lane reads
//! still lands with its mark.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test bound_raw_vector_lane`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::{EmbeddingDevice, EmbeddingProvenance};
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{MEMORY_CODE_NOT_FOUND, Memory};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The vault clock's fixed time: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;
/// The vault's embedding model and width.
const MODEL: &str = "test/model@v1";
const DIMENSIONS: usize = 4;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

/// A rooted vault that names its embedding model, with its install enrolled
/// and its embedded owner, opened owned (as `agent_delegated_owner_reads`).
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(MODEL.to_owned());
    let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        vault,
        _dir: dir,
        owner,
    }
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// `name`'s agent definition with an owner Grant of base reach over TURNs
/// alone, listing the full-access tier's verbs: every row of another kind
/// is withheld from its lane.
fn turns_only_agent(fixture: &Fixture, name: &str) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.bands = [ENTITY_TYPE_TURN].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
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
    .expect("the owner grants the agent base reach over TURNs");
    assert!(minted.grant.confers, "the grant confers");
    agent
}

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// The owner's row of `kind` with `body`, put unbound.
fn owner_row(fixture: &Fixture, kind: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_entity(&id, kind, TimeRange { start: at, end: at }, at, body)
        .expect("the owner's row");
    id
}

/// Whether `agent`'s own lane reads the row at `id` by id.
fn agent_reads(fixture: &Fixture, agent: EntityId, id: EntityId) -> bool {
    agent_memory(fixture, agent)
        .get_entity(&id.to_hex())
        .is_ok_and(|read| read.value.is_some())
}

/// A vector whose components f16 holds exactly (the vault stores f16), so
/// a stored vector compares equal to the one put.
fn vector(seed: f32) -> Vec<f32> {
    (0..DIMENSIONS)
        .map(|index| seed + f32::from(u8::try_from(index).expect("width")) / 4.0)
        .collect()
}

#[test]
fn a_bound_raw_vector_put_over_a_row_the_lane_withholds_answers_as_missing() {
    let fixture = rooted_vault();
    let agent = turns_only_agent(&fixture, "turns-only-vector-writer");
    let turn_body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let readable = owner_row(&fixture, ENTITY_TYPE_TURN, &turn_body);
    let withheld = owner_row(&fixture, ENTITY_TYPE_ASSET, b"the owner's private asset");
    assert!(
        agent_reads(&fixture, agent, readable),
        "FIXTURE: the agent's lane reads the owner's TURN"
    );
    assert!(
        !agent_reads(&fixture, agent, withheld),
        "FIXTURE: the agent's lane withholds the owner's ASSET"
    );

    let owner_mark = EmbeddingProvenance::new(EmbeddingDevice::Metal, "owner-embedder 1.0");
    fixture
        .vault
        .put_vector_with_provenance(&withheld, &vector(0.125), owner_mark.clone())
        .expect("the owner's marked vector");

    // A row the lane reads takes the agent's marked vector.
    let agent_mark = EmbeddingProvenance::new(EmbeddingDevice::Cpu, "agent-embedder 2.0");
    agent_memory(&fixture, agent)
        .raw_put_vector_with_provenance(&readable, &vector(0.5), agent_mark.clone())
        .expect("a marked vector over a row the lane reads");
    assert_eq!(
        fixture
            .vault
            .embedding_provenance(&readable)
            .expect("read the TURN's mark"),
        Some(agent_mark.clone())
    );

    // A row the lane withholds answers as missing, marked or not.
    let marked = agent_memory(&fixture, agent)
        .raw_put_vector_with_provenance(&withheld, &vector(2.0), agent_mark)
        .expect_err("a marked vector over a withheld row is refused");
    assert_eq!(
        marked.code, MEMORY_CODE_NOT_FOUND,
        "the withheld row answers as missing: {marked:?}"
    );
    let unmarked = agent_memory(&fixture, agent)
        .raw_put_vector(&withheld, &vector(2.0))
        .expect_err("an unmarked vector over a withheld row is refused");
    assert_eq!(
        unmarked.code, MEMORY_CODE_NOT_FOUND,
        "the withheld row answers as missing: {unmarked:?}"
    );

    // The owner's vector and its mark stay.
    assert_eq!(
        fixture
            .vault
            .get_vector(&withheld)
            .expect("read the ASSET's vector"),
        Some(vector(0.125))
    );
    assert_eq!(
        fixture
            .vault
            .embedding_provenance(&withheld)
            .expect("read the ASSET's mark"),
        Some(owner_mark)
    );
}
