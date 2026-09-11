//! Write mode types and the small standalone claim doors.

use super::consent::{claim_gate_input, enforce_gate_decision};
use crate::claim::ClaimBody;
#[cfg(feature = "sync")]
use crate::claim::claim_sensitivity_band;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::gate::constants::LOCAL_WRITE_ACTOR_ENTITY_REF;
#[cfg(feature = "sync")]
use crate::gate::decision::{GateDecision, GateReasonCode};
use crate::gate::definition_ceiling::agent_definition_ceiling_for_actor;
use crate::gate::input::{GateActor, GateContentKind, GateProvenanceHandles};
use crate::gate::resolution::{
    PolicyManifestResolution, check_claim_source_trust, hash_bytes, hash_opt_str, hash_str,
};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::llm::{AUTO_CHECK_VALUE_PREVIEW_BYTES, BoundedAutoChecker, truncate_on_char_boundary};
use crate::store::Store;
use crate::write_envelope::{WriteActor, WriteEnvelope};
use rmpv::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWriteMode {
    pub(crate) record_decision: bool,
    pub(crate) persist_pending_consent: bool,
    pub(crate) resolve_pending: bool,
    pub(crate) can_resolve_pending_consent: bool,
    pub(crate) include_source_in_gate_input: bool,
}

pub(crate) struct ClaimGateWrite<'a> {
    pub(crate) body: &'a ClaimBody,
    pub(crate) envelope: Option<&'a WriteEnvelope>,
    /// The host's auto checker for THIS write (ONE-1296), or `None`.
    ///
    /// Injection rides the write options and nothing else: the checker is
    /// never stored on the `Store` or on a resolved `PolicyManifestResolution`,
    /// so there is no hidden mutable host state a later write could inherit,
    /// and every door that does not opt in is unchanged by construction.
    pub(crate) auto_checker: Option<&'a BoundedAutoChecker>,
    pub(crate) defer_metrics_until_commit: bool,
}

impl<'a> ClaimGateWrite<'a> {
    /// The persisted-candidate shape every pre-check door uses.
    ///
    /// No auto checker and no deferral: a door that discards its receipt has
    /// no commit to defer metrics until, and injection rides the write options
    /// of the seams that actually materialize a body.
    pub(crate) fn plain(body: &'a ClaimBody, envelope: Option<&'a WriteEnvelope>) -> Self {
        Self {
            body,
            envelope,
            auto_checker: None,
            defer_metrics_until_commit: false,
        }
    }
}

pub(crate) fn validate_write_envelope(envelope: &WriteEnvelope) -> Result<()> {
    if matches!(envelope.provenance().value(), &Value::Nil) {
        return Err(Error::InvalidClaimBody("write envelope missing provenance"));
    }

    Ok(())
}

/// The bounded claim-value prefix an auto-check candidate carries (ONE-1296).
///
/// A string value is shown as itself; anything else is rendered through the
/// MessagePack value's own display, because the engine does not interpret
/// typed claim payloads. Either way the checker sees at most
/// [`AUTO_CHECK_VALUE_PREVIEW_BYTES`], truncated on a character boundary: this
/// seam asks for a second opinion on a candidate, it is not a disclosure
/// channel for whole claim values.
pub(super) fn auto_check_value_preview(value: &Value) -> String {
    let rendered = match value.as_str() {
        Some(text) => text.to_owned(),
        None => value.to_string(),
    };
    truncate_on_char_boundary(&rendered, AUTO_CHECK_VALUE_PREVIEW_BYTES).to_owned()
}

/// The hex actor ref an envelope attributes a write to, for source-trust row
/// selection. An envelope-less local write stays unattributed (`None`) and so
/// never rides an actor-bound permit.
pub(super) fn write_envelope_actor_ref(envelope: Option<&WriteEnvelope>) -> Option<String> {
    envelope.map(|envelope| envelope.actor().entity_ref().to_hex())
}

pub(super) fn local_write_actor_entity_ref() -> EntityId {
    EntityId::from_bytes(LOCAL_WRITE_ACTOR_ENTITY_REF)
        .expect("local Gate actor entity ref is non-reserved")
}

pub(in crate::gate) const fn edge_actor_class_str(actor_class: EdgeActorClass) -> &'static str {
    actor_class.gate_actor_class()
}

pub(crate) fn check_reserved_claim_policy(
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    let actor_ref = write_envelope_actor_ref(envelope);
    // Envelope-bearing local write path (the batch reserved-predicate door),
    // so it reads the same two axes the main write door reads.
    check_claim_source_trust(
        body,
        actor_ref.as_deref(),
        policy,
        envelope.map(WriteEnvelope::lineage),
    )
}

#[cfg(feature = "sync")]
pub(crate) fn check_federated_claim_admission(
    store: &Store,
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    let decision = federated_claim_admission_decision(body, policy);
    store.diagnostics.gate.record_decision(&decision);
    enforce_gate_decision(decision)
}

#[cfg(feature = "sync")]
fn federated_claim_admission_decision(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> GateDecision {
    if policy.enforces_write_gate() && policy.is_fail_closed() {
        return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
    }

    // Replicated input carries no local write actor, so it is unattributed for
    // row selection and can never ride an actor-bound permit.
    if !policy.source_trust_allows_auto(body.source, claim_sensitivity_band(body), None) {
        return GateDecision::pending(vec![GateReasonCode::PendingSourceTrust]);
    }

    GateDecision::allow()
}

pub(crate) fn check_edge_provenance_claim_policy(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    record: &crate::provenance::EdgeProvenanceClaimBody,
    actor_class: EdgeActorClass,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(
            store,
            txn,
            WriteActor::new(record.actor_entity_ref, actor_class),
        );
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor_class).to_owned(),
                actor_ref: Some(record.actor_entity_ref.to_hex()),
                delegation_grant_ref: None,
            },
            GateContentKind::EdgeProvenanceClaim,
            GateProvenanceHandles {
                actor_entity_ref: Some(record.actor_entity_ref),
                substrate_ref: record.substrate_ref,
                source_revision_ref: record.source_revision_ref,
                body_snapshot_ref: record.body_snapshot_ref,
                ..GateProvenanceHandles::default()
            },
            false,
            agent_definition_ceiling,
            // Edge-provenance claims, like ordinary claims, carry no effect-fact
            // axes; the door keeps its pre-DEC-0006 behaviour (None arm).
            None,
        );
        let decision = policy.evaluate_gate(&input);
        store.diagnostics.gate.record_decision(&decision);
        enforce_gate_decision(decision)?;
    }

    let actor_ref = record.actor_entity_ref.to_hex();
    // Edge-provenance claims arrive with no write envelope, so there is no
    // observed lineage to read: declared-source only, exactly as before.
    check_claim_source_trust(body, Some(actor_ref.as_str()), policy, None)
}

pub(crate) fn standing_outbound_grant_binding_parts(
    intent: &GrantMintIntent,
    policy: &PolicyManifestResolution,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"oneiron.gate.standing_outbound_grant.v0");
    hash_str(&mut hasher, intent.principal_ref.trim());
    hash_str(&mut hasher, intent.origin_component_id.trim());
    hash_str(&mut hasher, intent.origin_action_id.trim());
    hash_opt_str(&mut hasher, intent.origin_receipt_ref.as_deref());
    match &intent.scope {
        GrantMintIntentScope::JustOnce { .. } => {
            return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            )));
        }
        GrantMintIntentScope::Contact { contact_ref } => {
            hash_str(&mut hasher, "contact");
            hash_str(&mut hasher, contact_ref.trim());
        }
        GrantMintIntentScope::VerbClass { verb_class } => {
            hash_str(&mut hasher, "verb_class");
            hash_str(&mut hasher, verb_class.trim());
        }
        GrantMintIntentScope::Channel { channel } => {
            hash_str(&mut hasher, "channel");
            hash_str(&mut hasher, channel.trim());
        }
        GrantMintIntentScope::BundleExactSends { .. } => {
            return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            )));
        }
        GrantMintIntentScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            hash_str(&mut hasher, "brief_verb_class");
            hash_str(&mut hasher, brief_ref.trim());
            hash_str(&mut hasher, verb_class.trim());
        }
        GrantMintIntentScope::Calendar { .. } => {
            return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                "calendar disclosure scope is a read grant, not an outbound grant scope",
            )));
        }
    }
    Ok((hasher.finalize().to_vec(), policy.read_frontier_hash()?))
}
