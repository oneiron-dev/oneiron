//! Row [RECALL-EXPANDED-ROW-FACTS-REREAD]: a recall's candidate gate
//! (`ScopedRead::recall_candidate_gate`) judges each row once in each retrieval
//! snapshot. In a High recall the two-hop walk asks the gate about every row it
//! meets, through the author's PERSON to every message the author wrote, and
//! the post-blend filters then ask again about every fused row, in the same
//! snapshot. The gate keeps each answer for its snapshot, so the second ask
//! costs no second judgement, and its answers stay those of a fresh judgement:
//! an agent still never reads a message outside its grant.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recall_gate_judges_once`.

use std::collections::HashMap;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::memory::{
    Effort, Memory, MemoryPack, RecallScope, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::rerank::{RerankCandidate, Reranker};
use oneiron::retrieval_depth::RecallExecution;
use oneiron::test_doors::recall_gate_judgements::count_recall_gate_judgements;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor,
};

/// The word only the seed message holds.
const SEED_WORD: &str = "lanternwick";

/// The other messages in the grant's space: each holds its own word and none
/// of the query's, so the walk alone reaches them, through their author.
const REACHED_WORDS: [&str; 4] = ["harbourrope", "orchardgate", "millstream", "copperbell"];

/// The word of the owner's message outside every space, which the agent may
/// not read.
const HIDDEN_WORD: &str = "cellarkey";

/// A reranker that keeps the block's order, with no model.
struct OrderReranker;

impl Reranker for OrderReranker {
    fn id(&self) -> &str {
        "test/order-reranker@v1"
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
    ) -> oneiron::Result<Vec<f32>> {
        Ok((0..candidates.len()).map(|rank| -(rank as f32)).collect())
    }
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    /// The TURN of the seed message.
    seed_turn: EntityId,
    /// The TURNs of the [`REACHED_WORDS`] messages.
    reached_turns: Vec<EntityId>,
    _dir: tempfile::TempDir,
}

/// One owner and one agent. The agent holds a `MessagesRead` grant on one
/// space, and the owner witnesses one message per TURN: the seed message and
/// the reached messages in that space, and the hidden message in none (an
/// owner's own message, which the agent's grant does not reach).
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("a vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("the host owner");
    let agent = EntityId::now();
    vault
        .put_entity(
            &agent,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"recall-gate agent",
        )
        .expect("the agent's PERSON");
    vault
        .install_read_permit_for_test(WriteActor::new(agent, EdgeActorClass::Agent))
        .expect("the agent's read permit");
    // A message naming a space is refused unless the space is a live
    // RELATIONSHIP (gate/witness_message.rs).
    let space = EntityId::now();
    vault
        .put_entity(
            &space,
            oneiron::registry::ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"recall-gate space",
        )
        .expect("the space");
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope: oneiron::federation::Scope::top(),
                principal_ref: agent,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: vault.now_recorded_at(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )
        .expect("the agent's grant on the space");
    let seed_turn = witness(
        &vault,
        owner,
        &format!("{SEED_WORD} by the door"),
        Some(space),
    );
    let reached_turns = REACHED_WORDS
        .iter()
        .map(|word| witness(&vault, owner, &format!("{word} in the yard"), Some(space)))
        .collect();
    witness(
        &vault,
        owner,
        &format!("{HIDDEN_WORD} under the stair"),
        None,
    );
    Fixture {
        vault,
        owner,
        agent,
        seed_turn,
        reached_turns,
        _dir: dir,
    }
}

/// Witnesses `content` as the owner's one message in its own TURN, in `space`
/// when one is named, and returns the TURN.
fn witness(vault: &Vault, owner: EntityId, content: &str, space: Option<EntityId>) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: space.map(|space| serde_json::json!({ "rel": space.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .expect("witness one message")
        .turn_id
}

/// One High recall of `query` by `memory`, with the order reranker, and the
/// gate's full judgements it made: per (snapshot, row), how many.
fn high_recall(memory: &Memory<'_>, query: &str) -> (MemoryPack, HashMap<(u64, EntityId), usize>) {
    let lease = BudgetGuard::new(
        "recall-gate-judges-once",
        10_000_000,
        BudgetExhaustionPolicy::Suspend,
    )
    .admit()
    .expect("a lease")
    .lease;
    let execution = RecallExecution {
        reranker: Some(&OrderReranker),
        ..RecallExecution::default()
    };
    let (pack, judgements) = count_recall_gate_judgements(|| {
        memory.recall_with_execution(
            query,
            Effort::High,
            &RecallScope::default(),
            10,
            None,
            Some(&lease),
            &execution,
        )
    });
    (pack.expect("a High recall"), judgements)
}

/// The rows the gate judged more than once in one snapshot, with the count.
fn judged_again(judgements: &HashMap<(u64, EntityId), usize>) -> Vec<(u64, EntityId, usize)> {
    let mut again: Vec<_> = judgements
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|((snapshot, id), count)| (*snapshot, *id, *count))
        .collect();
    again.sort();
    again
}

/// Whether the gate judged `id` in any snapshot.
fn judged(judgements: &HashMap<(u64, EntityId), usize>, id: &EntityId) -> bool {
    judgements.keys().any(|(_, judged)| judged == id)
}

fn texts(pack: &MemoryPack) -> Vec<&str> {
    pack.items
        .iter()
        .map(|item| item.value_text.as_str())
        .collect()
}

/// The owner's High recall of the seed word: the walk reaches every message of
/// the owner through the owner's PERSON, the post-blend filters see them again,
/// and the gate judges each row once in each snapshot.
#[test]
fn an_owner_high_recall_judges_each_row_once_per_snapshot() {
    let fixture = fixture();
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let (pack, judgements) = high_recall(&memory, SEED_WORD);
    assert!(
        texts(&pack).iter().any(|text| text.contains(SEED_WORD)),
        "FIXTURE: the owner's recall returns the seed turn: {:?}",
        texts(&pack)
    );
    assert!(
        judged(&judgements, &fixture.seed_turn),
        "FIXTURE: the gate judged the seed turn"
    );
    assert!(
        fixture
            .reached_turns
            .iter()
            .any(|turn| judged(&judgements, turn)),
        "FIXTURE: the gate judged a TURN the walk alone reached"
    );
    assert_eq!(
        judged_again(&judgements),
        Vec::new(),
        "the gate judged these rows more than once in one snapshot (snapshot, row, count)"
    );
}

/// The agent's High recall of the seed word and the hidden word: the gate
/// refuses the owner's message outside the agent's grant, the walk meets it
/// again through the author and is refused again, and no word of it reaches
/// the agent. Each row is judged once in each snapshot.
#[test]
fn an_agent_high_recall_judges_each_row_once_and_still_refuses_a_hidden_message() {
    let fixture = fixture();
    let query = format!("{SEED_WORD} {HIDDEN_WORD}");
    let owner_memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let (owner_pack, _) = high_recall(&owner_memory, &query);
    assert!(
        texts(&owner_pack)
            .iter()
            .any(|text| text.contains(HIDDEN_WORD)),
        "FIXTURE: the owner's recall returns the hidden message's turn: {:?}",
        texts(&owner_pack)
    );
    let agent_memory = fixture.vault.memory(fixture.agent, EdgeActorClass::Agent);
    let (pack, judgements) = high_recall(&agent_memory, &query);
    assert!(
        texts(&pack).iter().any(|text| text.contains(SEED_WORD)),
        "FIXTURE: the agent's recall returns the seed turn: {:?}",
        texts(&pack)
    );
    assert!(
        judged(&judgements, &fixture.seed_turn),
        "FIXTURE: the gate judged the seed turn for the agent"
    );
    assert!(
        texts(&pack).iter().all(|text| !text.contains(HIDDEN_WORD)),
        "no word of the owner's message outside the agent's grant reaches the agent: {:?}",
        texts(&pack)
    );
    assert_eq!(
        judged_again(&judgements),
        Vec::new(),
        "the gate judged these rows more than once in one snapshot for the agent (snapshot, row, count)"
    );
}
