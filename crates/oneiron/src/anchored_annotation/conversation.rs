//! Composition with existing conversation DAG TURN nodes. Never owns room HEAD.
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::error::{ArtifactError, Error, Result};
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, TimeRange, Vault, WriteActor};
use rmpv::Value;

const NODE_PREDICATE: &str = "annotation.conversation_node";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnotationConversationNode {
    /// Conversation containing the bound DAG node.
    pub conversation_ref: EntityId,
    /// Existing TURN on a verified conversation DAG branch.
    pub turn_ref: EntityId,
}

/// Read projection over one anchored thread. Agent replies are ordinary
/// append-only comments; they do not supersede a human's truth claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationCollaborationState {
    Open,
    AgentReplied,
    Resolved,
}

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAnchor("annotation conversation node"))
}

impl Vault {
    /// Attaches an anchored thread to an existing conversation DAG node.
    /// Binding writes one pointer, not a conversation copy, fork entity, scope,
    /// roster, or HEAD. Conversation mechanics stay with the conversations API.
    pub fn bind_annotation_conversation_node(
        &self,
        artifact: EntityId,
        thread: EntityId,
        node: AnnotationConversationNode,
        author: WriteActor,
        now: u64,
    ) -> Result<()> {
        let envelope = super::codec::annotation_envelope(author, "bind_conversation_node")?;
        let value = Value::Array(vec![
            Value::from(1),
            Value::from(thread.to_hex()),
            Value::from(node.conversation_ref.to_hex()),
            Value::from(node.turn_ref.to_hex()),
        ]);
        let id = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            self.annotation_thread_in_txn(txn, &artifact, &thread, true)?
                .ok_or_else(invalid)?;
            validate_node_in_txn(self, txn, node)?;
            if let Some((existing, settled)) =
                self.annotation_conversation_node_for_effect_in_txn(txn, artifact, thread)?
            {
                validate_node_in_txn(self, txn, existing)?;
                if existing != node {
                    return Err(invalid());
                }
                // A held binding vetoes another node but never stands in for this one.
                if settled {
                    return Ok(());
                }
            }
            self.batch_in()
                .claim_candidate(
                    &id,
                    ClaimCandidate::new(NODE_PREDICATE, ClaimSubject::Entity(artifact), value, 1.0),
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)
        })
    }

    fn annotation_conversation_node_for_effect_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: EntityId,
        thread: EntityId,
    ) -> Result<Option<(AnnotationConversationNode, bool)>> {
        let mut result: Option<(AnnotationConversationNode, bool)> = None;
        for id in self.claims_for_subject_in_txn(txn, &artifact)? {
            let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate != NODE_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            let Some(node) = decode_node(&body.value, thread)? else {
                continue;
            };
            if result.is_some_and(|(old, _)| old != node) {
                return Err(invalid());
            }
            let settled =
                crate::gate::claim_critical_confirm_settled_in_txn(&self.store, txn, &id)?;
            result = Some((node, settled || result.is_some_and(|(_, any)| any)));
        }
        Ok(result)
    }

    pub fn annotation_conversation_node(
        &self,
        artifact: EntityId,
        thread: EntityId,
    ) -> Result<Option<AnnotationConversationNode>> {
        let mut result = None;
        for id in self.claims_for_subject(&artifact)? {
            let Some(body) = self.get_claim(&id)? else {
                continue;
            };
            if body.predicate != NODE_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            let Some(node) = decode_node(&body.value, thread)? else {
                continue;
            };
            validate_node(self, node)?;
            if result.is_some_and(|old| old != node) {
                return Err(invalid());
            }
            result = Some(node);
        }
        Ok(result)
    }

    pub fn annotation_collaboration_state(
        &self,
        artifact: EntityId,
        thread: EntityId,
    ) -> Result<AnnotationCollaborationState> {
        let head = self
            .get_annotation_thread(&artifact, &thread)?
            .ok_or_else(invalid)?;
        if head.state == super::ThreadState::Resolved {
            return Ok(AnnotationCollaborationState::Resolved);
        }
        let comments = self.annotation_thread_comments(&artifact, &thread)?;
        // An admitted agent answer stays answered even when the human adds
        // another comment. The thread head is human-owned; an agent cannot
        // supersede it just to record its own reply.
        let mut agent = false;
        for comment in comments {
            let body = self.get_claim(&comment.claim_id)?.ok_or_else(invalid)?;
            // Identity comes from engine envelope evidence, never comment prose.
            agent |= body
                .evidence
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|map| {
                    map.iter().find(|(key, _)| {
                        key.as_str()
                            == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
                    })
                })
                .and_then(|(_, value)| value.as_u64())
                == Some(crate::edge::EdgeActorClass::Agent as u64);
        }
        Ok(if agent {
            AnnotationCollaborationState::AgentReplied
        } else {
            AnnotationCollaborationState::Open
        })
    }
}

fn decode_node(value: &Value, thread: EntityId) -> Result<Option<AnnotationConversationNode>> {
    let array = value
        .as_array()
        .filter(|a| a.len() == 4)
        .ok_or_else(invalid)?;
    if array[0].as_u64() != Some(1) {
        return Err(invalid());
    }
    let entity = |index: usize| {
        EntityId::from_hex(array[index].as_str().ok_or_else(invalid)?).map_err(|_| invalid())
    };
    if entity(1)? != thread {
        return Ok(None);
    }
    let node = AnnotationConversationNode {
        conversation_ref: entity(2)?,
        turn_ref: entity(3)?,
    };
    Ok(Some(node))
}

fn validate_node_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    node: AnnotationConversationNode,
) -> Result<()> {
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: node.conversation_ref,
        session: None,
        path: crate::conversation_dag::ScopePath::Branch(node.turn_ref),
        include_forks: false,
    };
    let path =
        crate::conversation_dag::resolve_in_txn(vault, txn, &scope).map_err(|_| invalid())?;
    if path.records.last() != Some(&node.turn_ref) {
        return Err(invalid());
    }
    Ok(())
}

fn validate_node(vault: &Vault, node: AnnotationConversationNode) -> Result<()> {
    // A typed TURN on a verified DAG branch, not a MESSAGE merely linked to
    // a conversation by an arbitrary BelongsTo edge. Branch resolution checks
    // the complete parent chain and ownership without moving HEAD.
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: node.conversation_ref,
        session: None,
        path: crate::conversation_dag::ScopePath::Branch(node.turn_ref),
        include_forks: false,
    };
    let path = vault.resolve_dag_scope(&scope).map_err(|_| invalid())?;
    if path.records.last() != Some(&node.turn_ref) {
        return Err(invalid());
    }
    Ok(())
}
