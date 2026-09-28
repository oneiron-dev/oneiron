//! ONE-1689 RT-08: admitted per-thread replies and anchored room-DAG wiring.

use super::shared::{empty_map_body, person_actor, t};
use crate::Vault;
use crate::anchored_annotation::{
    ANNOTATION_COMMENT_PREDICATE, Anchor, AnnotationCollaborationState, AnnotationConversationNode,
    Locator, ThreadState,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::conversation_dag::AppendRecord;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

// The test fixture removes the shipped default criticality floor. An explicit
// actor-bound grant below still decides whether the generated reply is admitted.
fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::device())
}

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

fn xlsx_anchor(artifact_id: EntityId) -> Anchor {
    Anchor::new(
        artifact_id,
        1,
        Locator::xlsx("Sheet1", "B2").expect("xlsx locator"),
    )
}

// An agent's first comment is Proposed and cannot surface as an answer. The
// admitted copy uses that same writer-produced value, with an explicit test
// policy and envelope, so provenance—not prose—marks the agent reply.
fn admitted_agent_reply(
    vault: &Vault,
    artifact: EntityId,
    thread: EntityId,
    agent: WriteActor,
    at: u64,
) {
    let proposed = vault
        .add_annotation_comment(&artifact, &thread, agent, "agent answer", t(at), at)
        .expect("proposed comment");
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, thread)
            .unwrap(),
        AnnotationCollaborationState::Open,
    );
    let value = vault
        .get_claim(&proposed.claim_id)
        .expect("read proposal")
        .expect("proposal exists")
        .value;
    crate::conversation_dag::test_support::put_dag_test_policy(vault, agent, true)
        .expect("agent policy");
    let envelope = WriteEnvelope::new(
        agent,
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("admitted annotation reply")).unwrap(),
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &EntityId::now(),
            ClaimCandidate::new(
                ANNOTATION_COMMENT_PREDICATE,
                ClaimSubject::Entity(artifact),
                value,
                1.0,
            ),
            &envelope,
            t(at + 1),
            at + 1,
        )
        .commit()
        .expect("admit agent comment");
}

#[test]
fn one_1689_annotation_thread_anchors_to_a_conversation_dag_node() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x31, EdgeActorClass::Human);
    let artifact = put_workbook(&vault, human, 100);
    let room = EntityId::now();
    vault
        .put_entity(
            &room,
            ENTITY_TYPE_CONVERSATION,
            t(150),
            150,
            &empty_map_body(),
        )
        .expect("put room");
    crate::conversation_dag::test_support::put_dag_test_policy(&vault, human, true)
        .expect("room policy");
    let record = |parent, advance| AppendRecord {
        conversation: room,
        parent,
        reply_to: None,
        address: crate::conversation_dag::AddressMode::Broadcast,
        recipients: vec![],
        advance,
        kind: ENTITY_TYPE_TURN,
        occurred: t(150),
        learned_at: 150,
        body: empty_map_body(),
        text: vec![],
        session: None,
        actor: human,
    };
    let root = vault
        .append_dag_record(&record(None, true))
        .expect("root")
        .id;
    let trunk = vault
        .append_dag_record(&record(Some(root), true))
        .expect("trunk")
        .id;
    let fork = vault
        .reply_in_thread(root, &record(Some(root), false))
        .expect("room thread")
        .id;
    let thread = vault
        .open_annotation_thread(&xlsx_anchor(artifact), human, "fork here", t(200), 200)
        .expect("open annotation thread");
    let binding = AnnotationConversationNode {
        conversation_ref: room,
        turn_ref: fork,
    };
    vault
        .bind_annotation_conversation_node(artifact, thread.thread_id, binding, human, 201)
        .expect("bind room thread");
    assert_eq!(
        vault
            .annotation_conversation_node(artifact, thread.thread_id)
            .unwrap(),
        Some(binding),
    );
    assert_eq!(vault.head(&room).unwrap(), Some(trunk));
    assert_eq!(vault.thread(root).unwrap().root, Some(fork));
}

#[test]
fn one_1689_agent_reply_advances_the_thread_state_beyond_open() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x32, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x33, EdgeActorClass::Agent);
    crate::conversation_dag::test_support::put_dag_test_policy(&vault, human, true)
        .expect("human policy");
    let artifact = put_workbook(&vault, human, 100);
    let thread = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact),
            human,
            "please check B2",
            t(300),
            300,
        )
        .expect("open thread");
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, thread.thread_id)
            .unwrap(),
        AnnotationCollaborationState::Open,
    );
    admitted_agent_reply(&vault, artifact, thread.thread_id, agent, 400);
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, thread.thread_id)
            .unwrap(),
        AnnotationCollaborationState::AgentReplied,
    );
    // The agent did not supersede the human-owned head to claim resolution.
    assert_eq!(
        vault
            .get_annotation_thread(&artifact, &thread.thread_id)
            .unwrap()
            .unwrap()
            .state,
        ThreadState::Open
    );
    vault
        .set_annotation_thread_state(
            &artifact,
            &thread.thread_id,
            ThreadState::Resolved,
            human,
            t(500),
            500,
        )
        .expect("human resolves");
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, thread.thread_id)
            .unwrap(),
        AnnotationCollaborationState::Resolved,
    );
}

#[test]
fn one_1689_threads_progress_per_thread_not_one_global_handoff() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x34, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x35, EdgeActorClass::Agent);
    crate::conversation_dag::test_support::put_dag_test_policy(&vault, human, true)
        .expect("human policy");
    let artifact = put_workbook(&vault, human, 100);
    let a = vault
        .open_annotation_thread(&xlsx_anchor(artifact), human, "A", t(300), 300)
        .unwrap();
    let b = vault
        .open_annotation_thread(&xlsx_anchor(artifact), human, "B", t(310), 310)
        .unwrap();
    admitted_agent_reply(&vault, artifact, a.thread_id, agent, 400);
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, a.thread_id)
            .unwrap(),
        AnnotationCollaborationState::AgentReplied
    );
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, b.thread_id)
            .unwrap(),
        AnnotationCollaborationState::Open
    );
    vault
        .add_annotation_comment(&artifact, &b.thread_id, human, "still typing", t(410), 410)
        .expect("human comments in B");
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, a.thread_id)
            .unwrap(),
        AnnotationCollaborationState::AgentReplied
    );
    assert_eq!(
        vault
            .annotation_collaboration_state(artifact, b.thread_id)
            .unwrap(),
        AnnotationCollaborationState::Open
    );
}
