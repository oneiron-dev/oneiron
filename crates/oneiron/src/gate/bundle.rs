use rmpv::Value;

use crate::batch::{BatchOp, EntityMetadataHeader, apply_session_bundle_claim_puts};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, SessionClaimBundle, SessionClaimBundleClaim, encode_claim_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::doors::{
    ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision,
    check_claim_policy_for_write_with_record, claim_gate_input, edge_actor_class_str,
    enforce_gate_decision,
};
use super::input::{GateActor, GateContentKind, GateProvenanceHandles};
use super::resolution::{
    PolicyManifestResolution, check_claim_source_trust, resolve_policy_manifest,
};

impl Vault {
    pub fn review_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let rtxn = self.store.env.read_txn()?;
        self.validate_session_bundle_actor_in_txn(&rtxn, actor)?;
        let members =
            self.session_claim_bundle_members_in_txn(&rtxn, expected_producer, session_tag)?;
        let policy = resolve_policy_manifest(&self.store, &rtxn)?;
        for member in &members {
            let mut approved = member.body.clone();
            approved.approval = ClaimApprovalStatus::Approved;
            check_session_bundle_actor_policy(&self.store, &rtxn, actor, &approved, &policy)?;
        }
        Ok(session_claim_bundle(session_tag, members))
    }

    /// Replays every active proposed claim in a session bundle through the
    /// ordinary gate and commits all resulting approvals atomically.
    ///
    /// Any gate denial or stale pending-consent binding aborts the enclosing
    /// write transaction, leaving every member of the producer-bound session
    /// bundle unchanged.
    pub fn merge_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let (bundle, recorded_decisions) = self.with_write_txn(|wtxn| {
            self.validate_session_bundle_actor_in_txn(&*wtxn, actor)?;
            let members =
                self.session_claim_bundle_members_in_txn(&*wtxn, expected_producer, session_tag)?;
            if members.is_empty() {
                return Ok((
                    session_claim_bundle(session_tag, members),
                    Vec::<RecordedClaimGateDecision>::new(),
                ));
            }

            let policy = resolve_policy_manifest(&self.store, &*wtxn)?;
            let mut merged = Vec::with_capacity(members.len());
            let mut ops = Vec::with_capacity(members.len());
            let mut recorded_decisions = Vec::with_capacity(members.len());
            for member in members {
                let mut body = member.body;
                body.approval = ClaimApprovalStatus::Approved;
                let source = body.source.ok_or(Error::InvalidClaimBody(
                    "session bundle member missing claim source",
                ))?;
                let envelope = WriteEnvelope::new(
                    *actor,
                    source,
                    WriteProvenance::new(Value::from("session-claim-bundle-merge"))?,
                    ClaimApprovalStatus::Approved,
                );
                let mut recorded_decision = None;
                let gate_result = check_claim_policy_for_write_with_record(
                    &self.store,
                    wtxn,
                    &member.id,
                    ClaimGateWrite {
                        body: &body,
                        envelope: Some(&envelope),
                        defer_metrics_until_commit: true,
                    },
                    &policy,
                    GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: true,
                        can_resolve_pending_consent: false,
                        include_source_in_gate_input: true,
                    },
                    &mut recorded_decision,
                );
                if let Some(recorded_decision) = recorded_decision {
                    recorded_decisions.push(recorded_decision);
                }
                gate_result?;
                let data = encode_claim_body(&body)?;
                merged.push(SessionClaimBundleClaim {
                    id: member.id,
                    body,
                });
                ops.push(BatchOp::Put {
                    id: member.id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: member.occurred,
                    learned_at: member.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                });
            }

            apply_session_bundle_claim_puts(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
            )?;

            Ok((
                SessionClaimBundle {
                    session_tag: session_tag.to_owned(),
                    claims: merged,
                },
                recorded_decisions,
            ))
        })?;
        for decision in recorded_decisions {
            decision.record_metrics();
        }
        Ok(bundle)
    }

    fn validate_session_bundle_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        actor: &WriteActor,
    ) -> Result<()> {
        let actor_raw = self
            .store
            .entities
            .get(rtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
    }
}

/// Read-only authorization check for the proposed bodies exposed by review.
/// It uses the same actor, source, sensitivity, and live agent-definition
/// ceiling as merge, but does not persist a decision or consume consent.
fn check_session_bundle_actor_policy(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    actor: &WriteActor,
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, rtxn, *actor);
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                actor_ref: Some(actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            GateContentKind::Claim,
            GateProvenanceHandles {
                actor_entity_ref: Some(actor.entity_ref()),
                ..GateProvenanceHandles::default()
            },
            true,
            agent_definition_ceiling,
            // Read-only review door over proposed claims; no effect facts to
            // classify, so no consent context is composed (pre-DEC-0006 path).
            None,
        );
        enforce_gate_decision(policy.evaluate_gate(&input))?;
    }
    check_claim_source_trust(body, policy)
}

fn session_claim_bundle(
    session_tag: &str,
    members: Vec<crate::claim::SessionClaimBundleMember>,
) -> SessionClaimBundle {
    SessionClaimBundle {
        session_tag: session_tag.to_owned(),
        claims: members
            .into_iter()
            .map(|member| SessionClaimBundleClaim {
                id: member.id,
                body: member.body,
            })
            .collect(),
    }
}
