//! A saved lane keeps the access gate its live key read under (FIX
//! SAVED-PRINCIPAL-LANE-DROPS-ACCESS-GATE, Sol F3 on #8061; Engine RULING
//! 15 Nov 11:46).
//!
//! A key that carries no proof and holds no owner standing reads under the
//! access gate (`Memory::read_key`): it refuses every MESSAGE and SUMMARY
//! that names no relationship and no private scope, unless an access grant
//! on the MESSAGE's conversation admits it. Saved work froze that lane as
//! its principal's own, and the saved question's reader rebuilt the
//! principal's key under the relationship gate, which admits those rows: the
//! saved question read the owner's unscoped MESSAGE its live lane refused.
//! The lane now keeps its top Scope and its live key's grant basis, so the
//! rebuilt reader refuses those rows again, and so does a lane frozen again
//! from that reader.
//!
//! The asker is the house mind a fresh vault seeds (`sys.team_lead`). Its
//! shipped policy row lets it read the owner's MESSAGEs, so the grant gate
//! alone decides. Red on #8061 (5a2b1b1ebb7): the saved reader reads the
//! unscoped MESSAGE, the lane freezes as its principal's own and the rebuilt
//! reader reads under the relationship gate, and a lane frozen again reads
//! the MESSAGE too. Guard: a MESSAGE that the house's access grant on its
//! conversation admits still reads through the saved lane.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_access_gate_lane`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::test_doors::question_saved_lane::{
    question_read, reads_under_relationship_gate, saved_question_reader,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

/// A fresh vault whose owner witnessed a MESSAGE that names no relationship
/// and no private scope, and the house mind it seeds.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    house: EntityId,
    conversation: EntityId,
    message: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner");
    let house = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded agent definition read")
        .expect("the fresh vault seeds sys.team_lead")
        .0;
    let conversation = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "The spring garden needs a watering rota.".to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the owner's turn lands");
    Fixture {
        vault,
        _dir: dir,
        house,
        conversation,
        message,
    }
}

/// The house holds a live access grant to read the conversation's MESSAGEs.
fn grant_conversation_messages(fixture: &Fixture) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    fixture
        .vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope,
                principal_ref: fixture.house,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: fixture.conversation,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after the epoch")
                    .as_secs(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )
        .expect("the house's access grant on the conversation");
}

/// The house's own live key: no proof, no owner standing, the access gate.
fn live_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = fixture
        .vault
        .memory(fixture.house, EdgeActorClass::Agent)
        .read_key()
        .expect("the house's own read key");
    assert!(
        !key.reads_as_vault_owner() && !reads_under_relationship_gate(&key),
        "precondition: the house's own key reads below the owner's floor, not under the relationship gate"
    );
    key
}

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// `key`'s lane frozen as saved work keeps it, read back from its stored
/// MessagePack form, as a saved question's lane is.
fn saved_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(key)
        .freeze()
        .expect("the house's read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// What the house's saved question, saved under `frozen`, reads of `row`
/// through the reader the question's own reads build.
fn saved_reads(fixture: &Fixture, frozen: &FrozenReadLane, row: EntityId) -> (bool, String) {
    match saved_question_reader(&fixture.vault, fixture.house, frozen) {
        Ok(key) => reads(&question_read(&fixture.vault, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

#[test]
fn an_access_gated_saved_question_reads_no_unscoped_message_its_live_lane_refused() {
    let fixture = fixture();
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        !live,
        "precondition: the house's live lane refuses the owner's unscoped MESSAGE under the access gate; seen {seen}"
    );
    let (principal, seen) = saved_reads(&fixture, &FrozenReadLane::principal(), fixture.message);
    assert!(
        principal,
        "control: a saved question of the house's own lane reads the unscoped MESSAGE under the relationship gate; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, &frozen, fixture.message);
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected its saved question's reader to refuse the unscoped MESSAGE its live lane refused; seen {seen}"
    );
}

#[test]
fn an_access_gated_saved_lane_keeps_its_scope_and_rebuilds_under_the_access_gate() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture, live_key(&fixture));
    assert!(
        !frozen.reads_as_principal(),
        "actor=the house under the access gate, no proof; expected its saved lane to keep its Scope, not to read as its principal's own"
    );
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &frozen)
        .expect("the saved question's reader rebuilds");
    assert!(
        !reads_under_relationship_gate(&rebuilt),
        "actor=the house under the access gate, no proof; expected its saved question's rebuilt reader to keep the access gate, not the relationship gate that admits unscoped rows"
    );
}

#[test]
fn an_access_gated_saved_lane_frozen_again_from_its_rebuilt_reader_reads_no_unscoped_message() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture, live_key(&fixture));
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &frozen)
        .expect("the saved question's reader rebuilds");
    let refrozen = saved_lane(&fixture, rebuilt);
    let (read, seen) = saved_reads(&fixture, &refrozen, fixture.message);
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected a lane frozen again from its saved question's rebuilt reader to refuse the unscoped MESSAGE; seen {seen}"
    );
}

/// Guard: the rebuilt reader keeps the access gate, not a narrower one, so
/// an access grant on the MESSAGE's conversation still admits it.
#[test]
fn an_access_gated_saved_question_reads_a_message_its_conversation_grant_admits() {
    let fixture = fixture();
    grant_conversation_messages(&fixture);
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        live,
        "precondition: the house's access grant on the conversation admits the unscoped MESSAGE to its live lane; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, &frozen, fixture.message);
    assert!(
        read,
        "actor=the house under the access gate, no proof; expected its saved question's reader to read the MESSAGE its access grant on the conversation admits; seen {seen}"
    );
}
