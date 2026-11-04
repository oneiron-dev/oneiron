//! ONE-1686 (RT-04): the witness MESSAGE approval-ceiling door.
//!
//! Every MESSAGE row the engine writes passes through here, immediately before
//! its own atomic put, inside the witness write transaction. The door is the
//! ONE place that answers "may THIS actor write THIS envelope", and the answer
//! covers the FULL envelope — author, message type, content, ordered parts, metadata
//! (including nested values), visibility and order — never the text alone and
//! never authorship alone.
//!
//! # Why the whole envelope
//!
//! The pre-ONE-1686 witness path verified nothing but the `AuthoredBy` edge
//! target: a caller that held any bound actor could write a row authored
//! `system` (which carries NO `AuthoredBy` edge at all, so nothing downstream
//! could tell it apart from an engine row), hide a row from the transcript,
//! stamp an arbitrary message type, smuggle a nested metadata side channel, or
//! claim any position in the turn. Those are six axes of one envelope, so the
//! door binds every axis together.
//!
//! # The binding
//!
//! [`WitnessMessageEnvelope::encode_body`] is the CANONICAL MESSAGE body
//! encoder — `memory::witness` writes what this module encodes, and nothing
//! else. The door re-encodes the axes it authorized and refuses unless the
//! bytes the caller staged are byte-identical, then hands those proven bytes
//! back as [`WitnessMessageAuthorization::body`]. A write consumes the door's
//! own output, so no axis can move between the check and the put: changing any
//! axis changes the canonical bytes, which changes the binding, and
//! changing the author or the visibility can change the DECISION as well.

use rmpv::Value;

mod binding;
use binding::witness_message_binding;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::ceiling::{PolicyApprovalCeiling, PolicyCriticality};
use super::coach_offer_reach::OfferQuestionPermit;
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::{GateDecision, GateReasonCode};
use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::doors::{edge_actor_class_str, enforce_gate_decision};
use super::input::{GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles};
use super::resolution::PolicyManifestResolution;
use crate::error::RecordError;

pub(crate) use crate::store::witness_message_body::{
    MAX_WITNESS_MESSAGE_ORDER, WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM,
    WITNESS_AUTHOR_USER, WitnessMessageEnvelope,
};
use crate::store::witness_message_body::witness_message_envelope_denial;

/// One authorized MESSAGE write.
///
/// Holding one is the ONLY way to reach the bytes a witness put may stage: the
/// door proved they encode the envelope it authorized, under the actor it
/// authorized, against the policy resolved in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessMessageAuthorization<'a> {
    body: &'a [u8],
    binding: [u8; 32],
}

impl<'a> WitnessMessageAuthorization<'a> {
    /// The proven-canonical body bytes the caller may write, and nothing else.
    pub(crate) fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The content-addressed binding over actor + full envelope. Deterministic
    /// and stable: every axis feeds it, so no two envelopes that differ in any
    /// axis share a binding.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

/// The witness MESSAGE write door.
///
/// Runs INSIDE the caller's write transaction, immediately before the MESSAGE
/// put it authorizes, so the policy manifest, the AGENT_DEF ceiling and the
/// actor binding are all read from the same snapshot the write commits under.
/// A refusal is an `Err`, which aborts the caller's transaction: no MESSAGE
/// row, edge, text posting, TURN re-put or session-activity bump survives it.
///
/// # Errors
///
/// [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected) when the envelope is malformed, the author
/// bucket exceeds the actor's authority, or the policy ceiling refuses.
pub(crate) fn check_witness_message_ceiling<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    envelope: &WitnessMessageEnvelope<'_>,
    body: &'a [u8],
    policy: &PolicyManifestResolution,
) -> Result<WitnessMessageAuthorization<'a>> {
    check_witness_message_ceiling_with_permit(store, txn, actor, envelope, body, policy, None)
}

/// [`check_witness_message_ceiling`] for a MESSAGE that may carry the Coach's
/// offer-question permit (`coach_offer_reach`). The permit is one more way
/// past the System-author floor, never past the envelope bind or the policy
/// verdict.
///
/// # Errors
///
/// As [`check_witness_message_ceiling`].
pub(crate) fn check_witness_message_ceiling_with_permit<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    envelope: &WitnessMessageEnvelope<'_>,
    body: &'a [u8],
    policy: &PolicyManifestResolution,
    permit: Option<&OfferQuestionPermit>,
) -> Result<WitnessMessageAuthorization<'a>> {
    let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, txn, actor);
    let mut input = witness_message_gate_input(actor, agent_definition_ceiling);
    input.foreign_agent_ceiling = super::foreign_agent::resolve(store, txn, actor)?;

    // The floor runs whether or not a manifest is loaded, for the same reason
    // the GATE-12 Dreamer pre-commit floor does: "is this a well-formed
    // envelope the actor may author" is a validity and authority question, not
    // a policy verdict, and a bootstrap vault with no manifest must not become
    // the way to write a forged `system` row. When a manifest IS loaded the
    // policy verdict runs on top and can only narrow the answer.
    let decision = match witness_message_floor_denial(
        envelope,
        actor,
        policy,
        agent_definition_ceiling,
        body,
        permit,
    ) {
        Some(reason_code) => GateDecision::deny(reason_code),
        None if policy.enforces_write_gate() => policy.evaluate_gate(&input),
        None => GateDecision::allow(),
    };
    store.diagnostics.gate.record_decision(&decision);
    enforce_gate_decision(decision)?;

    Ok(WitnessMessageAuthorization {
        body,
        binding: witness_message_binding(actor, body),
    })
}

/// The gate evaluator input for one witness MESSAGE.
///
/// `source`/`sensitivity_band` are `None` (a transcript row is not a claim
/// candidate and carries no provenance meet), `criticality` is `Normal` (there
/// is no predicate to classify, and the criticality floor would otherwise pend
/// every turn a vault ever records), and no consent context is composed. What
/// is left is exactly the actor identity, the actor's ceiling, and the
/// fail-closed manifest checks — the ceiling question this door asks.
fn witness_message_gate_input(
    actor: WriteActor,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
) -> GateEvaluatorInput {
    GateEvaluatorInput {
        actor: GateActor {
            actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            delegation_grant_ref: None,
        },
        source: None,
        content_kind: GateContentKind::WitnessMessage,
        sensitivity_band: None,
        criticality: PolicyCriticality::Normal,
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(actor.entity_ref()),
            ..GateProvenanceHandles::default()
        },
        external_effect: None,
        agent_definition_ceiling,
        foreign_agent_ceiling: None,
        consent: None,
    }
}

/// The manifest-independent floor: envelope validity, the staged-bytes bind,
/// and author authority. `None` means the floor is clear. A `system` row
/// passes on its writer's exact Auto row, or on the Coach's offer-question
/// permit for exactly these bytes (`coach_offer_reach`).
fn witness_message_floor_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    actor: WriteActor,
    policy: &PolicyManifestResolution,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    body: &[u8],
    permit: Option<&OfferQuestionPermit>,
) -> Option<GateReasonCode> {
    if let Some(reason_code) = witness_message_envelope_denial(envelope, body) {
        return Some(reason_code);
    }
    if envelope.author == WITNESS_AUTHOR_SYSTEM
        && !system_author_authorized(actor, policy, agent_definition_ceiling)
        && !permit.is_some_and(|permit| {
            super::coach_offer_reach::offer_question_authorized(
                permit,
                actor,
                body,
                policy,
                agent_definition_ceiling,
            )
        })
    {
        return Some(GateReasonCode::DenyWitnessMessageAuthorNotAuthorized);
    }
    None
}

/// Whether this actor may write an UNATTRIBUTED `system` row.
///
/// System rows speak in the engine's voice and therefore always require an
/// explicit owner-authored `actor_ceilings` row bound to THIS actor ref with an
/// effective `auto` ceiling. This applies equally to a store-verified
/// SYSTEM-class actor (a MACHINE entity) and to a human/agent actor that the
/// owner deliberately delegates. A class-wide row is not enough: the default
/// manifest keeps the `system` class default-deny and its actor-ref binding is
/// what makes the permit narrow. No loaded manifest, no row, a malformed row,
/// or any effective non-`auto` ceiling fails closed.
///
/// An AGENT_DEF-authored `Proposed` self-limit also closes the door: an agent
/// that declared its writes need review cannot emit rows that carry no author.
fn system_author_authorized(
    actor: WriteActor,
    policy: &PolicyManifestResolution,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
) -> bool {
    let actor_class = edge_actor_class_str(actor.actor_class());
    let actor_ref = actor.entity_ref().to_hex();

    // Every system row is an elevated engine-voice write, including when the
    // caller itself is a store-verified MACHINE actor. The default manifest
    // deliberately keeps the `system` class default-deny, so a system actor
    // with no actor-bound row must not inherit authority merely from its
    // entity type. An explicit owner-authored row bound to THIS actor is the
    // only permit, and its effective exact-row ceiling must remain `auto`.
    // Class-wide claim ceilings are not transcript authority and do not enter
    // this fold in either direction.
    !policy.is_fail_closed()
        && policy.enforces_write_gate()
        && agent_definition_ceiling != Some(PolicyApprovalCeiling::Proposed)
        && policy.actor_bound_ceiling(actor_class, actor_ref.as_str())
            == Some(PolicyApprovalCeiling::Auto)
}

pub(crate) use crate::store::witness_message_body::{
    WitnessMessageBodyAuthor, validate_canonical_witness_message_body,
};

/// TEST-ONLY: the canonical MESSAGE body for one envelope, through the SAME
/// encoder every write door uses.
///
/// Fixtures that need a MESSAGE row need canonical BYTES, and hand-rolling
/// them would be a second encoder with nothing keeping it honest.
#[cfg(test)]
pub(crate) fn canonical_witness_message_body_for_test(
    author: &str,
    message_type: &str,
    content: &str,
    is_visible: bool,
    order: u32,
) -> Result<Vec<u8>> {
    WitnessMessageEnvelope {
        author,
        message_type,
        content,
        metadata: None,
        is_visible,
        order,
    }
    .encode_body()
}

/// The REPLICATED MESSAGE door (ONE-1686): CLOSED, on the evidence.
///
/// # What the replicated door actually carries
///
/// A MESSAGE that arrives over sync reaches `batch::apply_put` with
/// `replicated = true`, a `write_envelope` of `None`, a `WindowKey` that is a
/// calendar month (`YYYY-MM`), and a CRDT map key that is the entity id. The
/// body itself is the six-axis transcript envelope and carries no signature,
/// no signer key and no actor ref. `crate::write_envelope::WriteEnvelope` —
/// the type that carries `WriteActor` provenance into a write — appears
/// nowhere in `crate::sync`, and nothing on the replay path reads the row's
/// `AuthoredBy` edge (edges materialize in a LATER pass than entities, so it
/// is not even present when the body lands).
///
/// The kinds that DO admit remote rows carry their own proof inside the body:
/// an AUTHORITY_LOG entry names its signer and is folded against this vault's
/// roster; a REDACTION_AUDIT receipt carries an Ed25519 attestation bound to a
/// mirrored lease. A MESSAGE envelope has no such half. There is no verified
/// source actor or peer at this door to bind remote authorship to.
///
/// # Why that means closed, not narrowed
///
/// `check_witness_message_ceiling` is the ONLY authorization for a MESSAGE
/// row, and its subject is an ACTOR: which actor may author which bucket,
/// against the policy snapshot the write commits under. With no actor there is
/// no ceiling to run, and admitting the row anyway would make sync a second,
/// weaker MESSAGE authorization path — a peer (including a foreign vault whose
/// blob `sync::selector::admit_federated_entity_blob` copies through verbatim,
/// MESSAGE having no pinned admission arm there) could mint transcript rows in
/// this vault's own voice. Every author bucket therefore fails closed, with the
/// bucket named so the quarantine row says which forgery was attempted:
///
/// * `system` — the ENGINE'S own voice, carrying no `AuthoredBy` edge at all;
///   permitted locally only by an owner-authored, actor-bound `auto` ceiling
///   that no replicated envelope can present.
/// * `user`/`companion` — attributed rows whose local counterpart is bound to
///   a store-verified actor entity by an `AuthoredBy` edge the writing door
///   mints in the same transaction. Replicated, there is no actor to bind and
///   nothing downstream could tell an honest row from a forged one.
///
/// This narrows exactly ONE entity kind's remote door. Every other kind
/// converges unchanged, and a local MESSAGE row already in LMDB is skipped by
/// the byte-identical short-circuit in `sync::window::forward_rematerialize`
/// before it ever reaches this door, so a healthy vault replaying its own
/// mirror is untouched.
///
/// A row whose put carries an own-device lane that vouches for it meets
/// [`validate_own_device_witness_message_body`] instead (FIX 9600). This door
/// stays every other replay's: federated, recovered, or from no proven sender.
///
/// # Errors
///
/// [`RecordError::InvalidWitnessMessageBody`](crate::error::RecordError::InvalidWitnessMessageBody), always. `sync::quarantine` classifies
/// the kind as a remote-op rejection, so the row is quarantined with its
/// payload and the window continues; nothing partial is written, because the
/// refusal precedes every store mutation in `apply_put`.
pub(crate) fn validate_replicated_witness_message_body(body: &[u8]) -> Result<()> {
    // The envelope floor runs FIRST even though the verdict is refusal either
    // way: the quarantine row keeps the rejection reason, and "a peer shipped
    // bytes that are not a transcript row at all" is a different operational
    // fact from "a peer shipped a well-formed row it has no authority to
    // author". It also keeps the floor where it belongs if a future protocol
    // revision ever does carry a verified source actor here.
    Err(match validate_canonical_witness_message_body(body)? {
        WitnessMessageBodyAuthor::System => Error::Record(RecordError::InvalidWitnessMessageBody(
            "a replicated MESSAGE may not claim the unattributed system author",
        )),
        WitnessMessageBodyAuthor::User | WitnessMessageBodyAuthor::Companion => {
            Error::Record(RecordError::InvalidWitnessMessageBody(
                "a replicated MESSAGE carries no local actor binding for its author",
            ))
        }
    })
}

/// The REPLICATED MESSAGE door for a row one of the owner's own machines sent
/// (FIX 9600; L02 01:07).
///
/// Its caller holds the row's own-device lane (`sync::ingest::own_device`):
/// `machine`, an own machine whose connection proved it, sent these exact
/// bytes at this id, and no federation peer's import brought them. That proof
/// covers the connection and the bytes and names no actor, and a MESSAGE body
/// names its author bucket, never an actor, so a row passes only where this
/// store itself binds its author, all read in `txn`:
///
/// * `user`: the vault owner's own words, when this is a personal vault whose
///   embedded owner PERSON is live (the one person who speaks as `user`
///   there) and `machine` still stands on this vault's machine roster.
/// * `companion`: its actor is named only by the row's `AuthoredBy` edge and
///   carried birth, which the lane covers neither of, and the edge lands in a
///   later pass than the body: nothing here binds it to a live actor.
/// * `system`: the engine's own voice, never a replay's.
///
/// Every row it does not admit, a body that is no canonical envelope first
/// among them, meets [`validate_replicated_witness_message_body`] with
/// today's refusal.
///
/// # Errors
///
/// [`RecordError::InvalidWitnessMessageBody`](crate::error::RecordError::InvalidWitnessMessageBody)
/// for every row it does not admit, as the replicated door words it.
pub(crate) fn validate_own_device_witness_message_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    body: &[u8],
) -> Result<()> {
    if matches!(
        validate_canonical_witness_message_body(body),
        Ok(WitnessMessageBodyAuthor::User)
    ) {
        // A store fault reading the roster or the vault's kind admits nothing
        // and refuses as the replicated door does, so the row is quarantined
        // as today rather than failing its window.
        match owner_speaks_from(store, txn, machine) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an own machine's user MESSAGE: the owner and roster did not read; refused as a replay"
            ),
        }
    }
    validate_replicated_witness_message_body(body)
}

/// Whether `machine` stands on this vault's machine roster and this is a
/// personal vault whose embedded owner PERSON is live, all in `txn`: the one
/// person whose words its `user` bucket holds, sending from a machine still
/// theirs.
fn owner_speaks_from(store: &Store, txn: &heed::RoTxn<'_>, machine: EntityId) -> Result<bool> {
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    Ok(fold.machine_proof_key(machine).is_some()
        && crate::federation::shared_vault_creation_for_store_in_txn(store, txn)?.is_none()
        && crate::consent::person_is_live_for_store_in_txn(
            store,
            txn,
            &crate::vault::embedded_owner_actor_id()?,
        )?)
}
