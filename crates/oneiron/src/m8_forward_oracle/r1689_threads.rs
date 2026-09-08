//! ONE-1689 RT-08: annotation-thread/DAG-wiring and per-thread state-machine oracles plus arming seams.

use super::shared::{empty_map_body, open_vault, person_actor, t};
use crate::Vault;
use crate::anchored_annotation::{Anchor, Locator, ThreadState};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_TURN;
use crate::write_envelope::WriteActor;

// ═══════════════════════════════════════════════════════════════════════
// ONE-1689 — [RT-08] collaborative-doc / RLM layer
// ═══════════════════════════════════════════════════════════════════════

/// Puts a versioned office artifact so annotation threads can open on it
/// with today's API (mirrors `anchored_annotation::tests::put_workbook`).
fn put_workbook(vault: &Vault, actor: WriteActor, at: u64) -> EntityId {
    let artifact_id = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact_id,
            &BlobArtifactBody::new(
                "plan.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            t(at),
            at,
        )
        .expect("put workbook");
    vault
        .append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            t(at),
            at,
        )
        .expect("append v1");
    artifact_id
}

fn xlsx_anchor(artifact_id: EntityId, version: u64) -> Anchor {
    Anchor::new(
        artifact_id,
        version,
        Locator::xlsx("Sheet1", "B2").expect("xlsx locator"),
    )
}

/// ARMING SEAM (ONE-1689): wire an anchored thread to an ARCH-0006a
/// conversation-DAG node (fork/HEAD mechanics stay armer-owned — the
/// WIRING is the contract this oracle pins).
fn wire_thread_to_conversation_dag_node(
    _vault: &Vault,
    _artifact: &EntityId,
    _thread_id: &EntityId,
    _node: &EntityId,
) {
    unimplemented!("ONE-1689 arming seam: OF-368 ↔ conversation-DAG composition (wire)")
}

/// ARMING SEAM (ONE-1689): resolve the conversation-DAG node an anchored
/// thread is wired to.
fn thread_conversation_dag_node(
    _vault: &Vault,
    _artifact: &EntityId,
    _thread_id: &EntityId,
) -> EntityId {
    unimplemented!("ONE-1689 arming seam: OF-368 ↔ conversation-DAG composition (resolve)")
}

/// RT-08: branching opens an ANCHORED thread on the built
/// anchored_annotation ARTIFACT and WIRES it to an ARCH-0006a
/// conversation-DAG node — the OF-368 ↔ conversation-DAG composition. The
/// DAG node is the wiring target, never the anchoring surface (documents
/// anchor threads; conversations fork from them).
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_annotation_thread_anchors_to_a_conversation_dag_node() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x31, EdgeActorClass::Human);
    let artifact = put_workbook(&vault, human, 100);

    // The conversation-DAG node this branch forks from.
    let node = EntityId::now();
    vault
        .put_entity(&node, ENTITY_TYPE_TURN, t(150), 150, &empty_map_body())
        .expect("put conversation-DAG node");

    let thread = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact, 1),
            human,
            "fork the plan here",
            t(200),
            200,
        )
        .expect("open thread on the artifact");
    assert_eq!(
        vault
            .annotation_threads_for_artifact(&artifact)
            .expect("threads on the artifact")
            .len(),
        1,
        "exactly one thread anchored on the artifact"
    );

    wire_thread_to_conversation_dag_node(&vault, &artifact, &thread.thread_id, &node);
    assert_eq!(
        thread_conversation_dag_node(&vault, &artifact, &thread.thread_id),
        node,
        "the thread's node linkage resolves to the wired conversation node"
    );
}

/// ARMING SEAM (ONE-1689): the ticket's exact intermediate state. The
/// arming ticket adds the variant (open → agent-replied → resolved) and
/// replaces this stub with it.
fn agent_replied_thread_state() -> ThreadState {
    unimplemented!("ONE-1689 arming seam: the agent-replied variant between Open and Resolved")
}

/// RT-08: the per-thread state machine is open → agent-replied → resolved.
/// An agent reply must advance the thread BEYOND `Open` without resolving
/// it — this pins the intermediate state's existence and entry without
/// naming the variant (signatures are the arming ticket's).
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_agent_reply_advances_the_thread_state_beyond_open() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x32, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x33, EdgeActorClass::Agent);
    let artifact = put_workbook(&vault, human, 100);

    let thread = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact, 1),
            human,
            "please check B2",
            t(300),
            300,
        )
        .expect("open thread");
    assert_eq!(thread.state, ThreadState::Open);

    vault
        .add_annotation_comment(
            &artifact,
            &thread.thread_id,
            agent,
            "checked — the formula is fixed",
            t(400),
            400,
        )
        .expect("agent reply");

    let replied = vault
        .get_annotation_thread(&artifact, &thread.thread_id)
        .expect("read thread")
        .expect("thread exists");
    assert_ne!(
        replied.state,
        ThreadState::Open,
        "an agent reply must advance open → agent-replied"
    );
    assert_ne!(
        replied.state,
        ThreadState::Resolved,
        "an agent reply alone must NOT resolve — resolution stays human"
    );
    assert_eq!(
        replied.state,
        agent_replied_thread_state(),
        "the EXACT ticket state machine: open → agent-replied → resolved, \
         not any third state that happens to be neither Open nor Resolved"
    );

    let resolved = vault
        .set_annotation_thread_state(
            &artifact,
            &thread.thread_id,
            ThreadState::Resolved,
            human,
            t(500),
            500,
        )
        .expect("resolve");
    assert_eq!(resolved.state, ThreadState::Resolved);
}

/// RT-08: threads progress CONCURRENTLY, per-thread — the agent answers
/// thread A while the human still types in thread B; there is no one
/// global handoff. Linear chat is the degenerate case.
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_threads_progress_per_thread_not_one_global_handoff() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x34, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x35, EdgeActorClass::Agent);
    let artifact = put_workbook(&vault, human, 100);

    let thread_a = vault
        .open_annotation_thread(&xlsx_anchor(artifact, 1), human, "thread A", t(300), 300)
        .expect("open thread A");
    let thread_b = vault
        .open_annotation_thread(&xlsx_anchor(artifact, 1), human, "thread B", t(310), 310)
        .expect("open thread B");
    assert_eq!(
        vault
            .annotation_threads_for_artifact(&artifact)
            .expect("threads")
            .len(),
        2
    );

    vault
        .add_annotation_comment(
            &artifact,
            &thread_a.thread_id,
            agent,
            "answering A",
            t(400),
            400,
        )
        .expect("agent answers A");

    let a = vault
        .get_annotation_thread(&artifact, &thread_a.thread_id)
        .expect("read A")
        .expect("A exists");
    let b = vault
        .get_annotation_thread(&artifact, &thread_b.thread_id)
        .expect("read B")
        .expect("B exists");
    assert_ne!(a.state, ThreadState::Open, "A advanced by the agent reply");
    assert_eq!(
        a.state,
        agent_replied_thread_state(),
        "A sits in the exact agent-replied state"
    );
    assert_eq!(
        b.state,
        ThreadState::Open,
        "B untouched — no global handoff"
    );

    // B still accepts the human's typing while A sits agent-replied.
    vault
        .add_annotation_comment(
            &artifact,
            &thread_b.thread_id,
            human,
            "still typing in B",
            t(410),
            410,
        )
        .expect("human keeps typing in B");
    // Durable, not return-value: B re-read from the store stays Open.
    let b_after = vault
        .get_annotation_thread(&artifact, &thread_b.thread_id)
        .expect("re-read B")
        .expect("B exists");
    assert_eq!(
        b_after.state,
        ThreadState::Open,
        "the human's comment leaves B open in the STORE — per-thread progress only"
    );
}
