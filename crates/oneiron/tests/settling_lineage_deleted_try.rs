//! FIX [SETTLING-LINEAGE-PRUNED-DELEGATION-LINK]: a settling lineage stays
//! whole through a try the owner deleted from the archive. An attenuated
//! fork's pin keeps only the id of the try whose run minted it (FIX 9559);
//! the agent that try ran, and the try above it, lived only in its queue
//! row. The deletion receipt now keeps those two links, so once the row is
//! gone the fork's lineage still reads: the fork selects a stranger's lens
//! proposal (refused as an unknown lineage before), and never one its chain
//! proposed, the spawner's or the delegator's above it.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test settling_lineage_deleted_try`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::lens::{
    CollectionAtom, GeneratedLens, LensAtom, LensAtomId, LensNode, LensProposeRequest, LensSlot,
    LensText,
};
use oneiron::memory::{Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::dispatch_chain_deleted_try::{
    DelegatedFork, complete_and_archive_try, spawn_delegated_fork,
};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const KEY: &str = "lens.slot.agent_select";
const ACTIVATE_AS: &str = "vault.lenses.activate_as";
const SET: &str = "vault.settings.set";
const DELETE_PREVIEW: &str = "vault.archive.attempt.delete.preview";
const DELETE_CONFIRM: &str = "vault.archive.attempt.delete.confirm";
/// The first-party weave lens pack and its lens, as the vault seeds them at
/// open (`WEAVE_LENS_PACK_NAME`, `WEAVE_REPORT_LENS`).
const WEAVE_PACK: &str = "oneiron.weave";
const WEAVE_LENS: &str = "weave-report";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

/// A rooted vault with its install enrolled and its embedded owner.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
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

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// `name`'s agent definition (`Proposed`) with an owner Grant of base reach,
/// listing the full-access tier's verbs and `extra`.
fn granted_agent(fixture: &Fixture, name: &str, extra: &[&str]) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    grant_extra(fixture, agent, extra);
    agent
}

/// The owner Grant of base reach [`granted_agent`] mints, for an agent
/// defined another way (a fork).
fn grant_extra(fixture: &Fixture, agent: EntityId, extra: &[&str]) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .chain(extra.iter())
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
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

/// The owner turns the agent-select key on for every agent.
fn owner_turns_on(fixture: &Fixture) {
    let applied = invoke(
        &owner_memory(fixture),
        SET,
        json!({ "key": KEY, "scope": { "kind": "vault" }, "value": true }),
    )
    .unwrap_or_else(|error| panic!("the owner turns the key on: {error:?}"));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
}

/// A minimal valid compiled tree: one sheet card, stamped current.
fn compiled_tree() -> GeneratedLens {
    let root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("valid atom id"),
        LensAtom::Sheet(CollectionAtom {
            title: LensText::new("Card").expect("valid text"),
            rows: Vec::new(),
        }),
        LensText::new("Card").expect("valid text"),
    );
    GeneratedLens::new(root).expect("a current tree validates")
}

/// The weave slot the vault seeds at open: its installed content hash and
/// the skill id of its lens's slot.
fn weave_slot(fixture: &Fixture) -> (String, String) {
    let entry = fixture
        .vault
        .pack_lens(WEAVE_PACK, WEAVE_LENS)
        .expect("the open seeds the weave lens pack Active");
    (entry.content_hash, entry.skill_id)
}

/// `proposer`'s proposal of the compiled tree for the weave slot: its lens
/// ref and its revision hash.
fn propose(fixture: &Fixture, proposer: EntityId) -> (String, String) {
    let (content_hash, skill_id) = weave_slot(fixture);
    let receipt = agent_memory(fixture, proposer)
        .lenses_propose(LensProposeRequest {
            slot: LensSlot {
                pack_name: WEAVE_PACK.to_owned(),
                skill_id,
            },
            pack_content_hash: content_hash,
            compiled: compiled_tree(),
            intent_prompt: "word the week's changes for the reader".to_owned(),
            trigger: None,
            scope: None,
        })
        .unwrap_or_else(|error| panic!("the proposer proposes: {error:?}"));
    (receipt.lens_ref, receipt.compiled_hash)
}

/// The slot's selected lens ref, if the slot holds one now.
fn selected(fixture: &Fixture) -> Option<String> {
    let (_, skill_id) = weave_slot(fixture);
    let skill = EntityId::from_hex(&skill_id).expect("the slot's skill id");
    fixture
        .vault
        .active_pack_lens(WEAVE_PACK, &skill)
        .expect("the slot reads")
        .map(|(lens_ref, _)| lens_ref.to_hex())
}

/// The agent's selection of `lens_ref` at `compiled_hash` for its slot, or
/// the door's refusal.
fn try_select(
    fixture: &Fixture,
    agent: EntityId,
    lens_ref: &str,
    compiled_hash: &str,
) -> Result<Value, MemoryError> {
    invoke(
        &agent_memory(fixture, agent),
        ACTIVATE_AS,
        json!({ "lens_ref": lens_ref, "compiled_hash": compiled_hash }),
    )
}

/// The agent's selection is refused for the lineage rule.
fn assert_lineage_refused(fixture: &Fixture, agent: EntityId, lens_ref: &str, hash: &str) {
    let refused = try_select(fixture, agent, lens_ref, hash)
        .expect_err("a fork never selects its own lineage's proposal");
    assert!(
        refused.message.contains("lineage"),
        "its own lineage's proposal is refused as its own: {refused:?}"
    );
}

fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A delegator's run that dispatched a spawner whose run minted an
/// attenuated fork, with the spawner's try completed, archived, and then
/// deleted by the owner through the archive delete door. The fork holds a
/// grant listing the select verb, and the key is on for every agent.
struct DeletedSpawnFixture {
    fixture: Fixture,
    delegator: EntityId,
    chain: DelegatedFork,
}

fn fork_whose_spawning_try_was_deleted() -> DeletedSpawnFixture {
    let fixture = rooted_vault();
    let delegator = granted_agent(&fixture, "lineage-delegator", &[]);
    let spawner = granted_agent(&fixture, "lineage-spawner", &[]);
    let chain = spawn_delegated_fork(&fixture.vault, delegator, spawner)
        .expect("the spawner's run mints an attenuated fork");
    assert_eq!(
        chain.spawner, spawner,
        "both are Proposed, so the delegator's run dispatched the spawner unforked"
    );
    grant_extra(&fixture, chain.fork, &[ACTIVATE_AS]);
    owner_turns_on(&fixture);

    complete_and_archive_try(&fixture.vault, chain.spawning_try)
        .expect("the spawner's try completes and is archived");
    let owner = owner_memory(&fixture).with_owner_authorship(&owner_proof(&fixture));
    let attempt = attempt_hex(chain.spawning_try);
    let preview = invoke(&owner, DELETE_PREVIEW, json!({ "attempt": attempt }))
        .unwrap_or_else(|error| panic!("the owner previews the archived try: {error:?}"));
    let receipt = invoke(
        &owner,
        DELETE_CONFIRM,
        json!({ "attempt": attempt, "expected": preview["expected"] }),
    )
    .unwrap_or_else(|error| panic!("the owner deletes the archived try: {error:?}"));
    assert_eq!(receipt["attempt"], json!(attempt), "{receipt}");
    invoke(&owner, DELETE_PREVIEW, json!({ "attempt": attempt }))
        .expect_err("the deleted try is no longer in the queue");
    DeletedSpawnFixture {
        fixture,
        delegator,
        chain,
    }
}

#[test]
fn a_fork_whose_spawning_try_was_deleted_selects_a_strangers_proposal() {
    let DeletedSpawnFixture { fixture, chain, .. } = fork_whose_spawning_try_was_deleted();
    let stranger = granted_agent(&fixture, "lineage-stranger", &[]);
    let (lens_ref, compiled_hash) = propose(&fixture, stranger);

    // The deleted try's receipt still names the spawner and the delegator's
    // try, so the fork's lineage reads whole and does not meet the stranger.
    let receipt = try_select(&fixture, chain.fork, &lens_ref, &compiled_hash)
        .unwrap_or_else(|error| panic!("the fork selects the stranger's proposal: {error:?}"));
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
    assert_eq!(
        receipt["decided_by"],
        json!(chain.fork.to_hex()),
        "{receipt}"
    );
    assert_eq!(
        selected(&fixture),
        Some(lens_ref),
        "the slot holds the lens"
    );
}

#[test]
fn a_fork_whose_spawning_try_was_deleted_never_selects_its_chains_proposals() {
    let DeletedSpawnFixture {
        fixture,
        delegator,
        chain,
    } = fork_whose_spawning_try_was_deleted();

    // The spawner is the agent the deleted try ran.
    let (spawner_ref, spawner_hash) = propose(&fixture, chain.spawner);
    assert_lineage_refused(&fixture, chain.fork, &spawner_ref, &spawner_hash);
    // The delegator is reached only through the try the deleted try's
    // payload recorded above it.
    let (delegator_ref, delegator_hash) = propose(&fixture, delegator);
    assert_lineage_refused(&fixture, chain.fork, &delegator_ref, &delegator_hash);
    assert_eq!(selected(&fixture), None, "the refused fork changed nothing");
}
