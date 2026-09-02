//! ONE-1686 (RT-04): the witness MESSAGE approval-ceiling door.
//!
//! Every MESSAGE row the engine writes passes through here, immediately before
//! its own atomic put, inside the witness write transaction. The door is the
//! ONE place that answers "may THIS actor write THIS envelope", and the answer
//! covers the FULL envelope — author, message type, content, metadata
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
//! door binds all six together.
//!
//! # The binding
//!
//! [`WitnessMessageEnvelope::encode_body`] is the CANONICAL MESSAGE body
//! encoder — `memory::witness` writes what this module encodes, and nothing
//! else. The door re-encodes the axes it authorized and refuses unless the
//! bytes the caller staged are byte-identical, then hands those proven bytes
//! back as [`WitnessMessageAuthorization::body`]. A write consumes the door's
//! own output, so no axis can move between the check and the put: changing any
//! one of the six changes the canonical bytes, which changes the binding, and
//! changing the author or the visibility can change the DECISION as well.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::ceiling::{PolicyApprovalCeiling, PolicyCriticality};
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::{GateDecision, GateReasonCode, record_gate_decision_metrics};
use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::doors::{edge_actor_class_str, enforce_gate_decision};
use super::input::{GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles};
use super::resolution::PolicyManifestResolution;

/// The vault owner's own words.
pub(crate) const WITNESS_AUTHOR_USER: &str = "user";
/// The companion persona's words.
pub(crate) const WITNESS_AUTHOR_COMPANION: &str = "companion";
/// Tooling/engine rows. These carry NO `AuthoredBy` edge, which is exactly why
/// the bucket needs authority the other two do not: an unattributed row reads
/// downstream as the engine's own voice.
pub(crate) const WITNESS_AUTHOR_SYSTEM: &str = "system";

/// The canonical MESSAGE body keys, in canonical order.
const BODY_KEY_AUTHOR: &str = "author";
const BODY_KEY_TYPE: &str = "type";
const BODY_KEY_CONTENT: &str = "content";
const BODY_KEY_METADATA: &str = "metadata";
const BODY_KEY_IS_VISIBLE: &str = "is_visible";
const BODY_KEY_ORDER: &str = "order";

/// The TURN-level grouping key (`memory::witness`'s `speaker` stamp). Listed
/// with the MESSAGE body keys below because metadata that restates it is the
/// same side channel one level up.
const TURN_KEY_SPEAKER: &str = "speaker";

/// Envelope-axis names metadata may not restate, at ANY depth. Metadata is
/// opaque passenger data; a key that shadows an axis the door authorizes is a
/// second, ungated copy of that axis riding inside the first.
const RESERVED_METADATA_KEYS: [&str; 7] = [
    BODY_KEY_AUTHOR,
    BODY_KEY_TYPE,
    BODY_KEY_CONTENT,
    BODY_KEY_METADATA,
    BODY_KEY_IS_VISIBLE,
    BODY_KEY_ORDER,
    TURN_KEY_SPEAKER,
];

/// Message types are a closed set APP-side and opaque here, so the door pins
/// the SHAPE rather than the vocabulary: a bounded, printable, punctuation-only
/// token (`dialogue`, `executor.speak`, `tool_result`). Anything else is an
/// unknown value and fails closed.
const MAX_WITNESS_MESSAGE_TYPE_BYTES: usize = 128;

/// The highest position a message may claim inside one turn. Ordering is a
/// signal readers sort by; an unbounded one is a channel rather than a
/// position.
pub(crate) const MAX_WITNESS_MESSAGE_ORDER: u32 = 65_535;

/// Metadata nesting bound. Depth beyond this is a structure no transcript
/// reader consumes and a decode cost every reader pays.
const MAX_WITNESS_METADATA_DEPTH: usize = 8;

/// Total metadata nodes (keys plus values, recursively).
const MAX_WITNESS_METADATA_NODES: usize = 512;

/// Metadata key length bound.
const MAX_WITNESS_METADATA_KEY_BYTES: usize = 128;

/// One metadata string value may not become a second transcript-sized payload.
/// Counted as UTF-8 bytes, not Unicode scalar values.
const MAX_WITNESS_METADATA_STRING_BYTES: usize = 16 * 1024;

/// Canonical MessagePack bytes for the complete metadata map. The recursive
/// validator first bounds every string and the aggregate key/value text, so
/// checking the exact encoding never allocates in proportion to hostile input.
const MAX_WITNESS_METADATA_BYTES: usize = 64 * 1024;

/// The domain tag for the witness-message binding hash. Bump the suffix if the
/// hashed tuple below ever changes; the value is an ABI.
const WITNESS_MESSAGE_BINDING_DOMAIN: &[u8] = b"oneiron.gate.witness_message.v0";

/// One MESSAGE envelope, exactly as the write door will encode it.
///
/// `metadata` is the rmpv value the body carries (the engine converts JSON to
/// MessagePack before it reaches the door), never the caller's JSON: the door
/// authorizes what will be written.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WitnessMessageEnvelope<'a> {
    /// `user` | `companion` | `system`; anything else fails closed.
    pub(crate) author: &'a str,
    /// App-closed type token.
    pub(crate) message_type: &'a str,
    /// Text content, BM25-indexed by the caller when non-empty.
    pub(crate) content: &'a str,
    /// Opaque passenger data, or `None`.
    pub(crate) metadata: Option<Value>,
    /// Whether the row is part of the visible transcript.
    pub(crate) is_visible: bool,
    /// Position within the turn.
    pub(crate) order: u32,
}

impl WitnessMessageEnvelope<'_> {
    /// The CANONICAL MESSAGE body bytes for this envelope.
    ///
    /// This is the only MESSAGE body encoder in the engine: `memory::witness`
    /// delegates here, and the door below re-runs it to prove the staged bytes
    /// are the authorized ones. Key order is part of the encoding, not an
    /// accident of construction.
    pub(crate) fn encode_body(&self) -> Result<Vec<u8>> {
        let mut entries = vec![
            (Value::from(BODY_KEY_AUTHOR), Value::from(self.author)),
            (Value::from(BODY_KEY_TYPE), Value::from(self.message_type)),
            (Value::from(BODY_KEY_CONTENT), Value::from(self.content)),
        ];
        if let Some(metadata) = &self.metadata {
            entries.push((Value::from(BODY_KEY_METADATA), metadata.clone()));
        }
        entries.push((
            Value::from(BODY_KEY_IS_VISIBLE),
            Value::Boolean(self.is_visible),
        ));
        entries.push((
            Value::from(BODY_KEY_ORDER),
            Value::from(u64::from(self.order)),
        ));
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries))
            .map_err(|_| Error::InvalidClaimBody("witness message body is not encodable"))?;
        Ok(out)
    }
}

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
/// [`Error::GateWriteRejected`] when the envelope is malformed, the author
/// bucket exceeds the actor's authority, or the policy ceiling refuses.
pub(crate) fn check_witness_message_ceiling<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    envelope: &WitnessMessageEnvelope<'_>,
    body: &'a [u8],
    policy: &PolicyManifestResolution,
) -> Result<WitnessMessageAuthorization<'a>> {
    let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, txn, actor);
    let input = witness_message_gate_input(actor, agent_definition_ceiling);

    // The floor runs whether or not a manifest is loaded, for the same reason
    // the GATE-12 Dreamer pre-commit floor does: "is this a well-formed
    // envelope the actor may author" is a validity and authority question, not
    // a policy verdict, and a bootstrap vault with no manifest must not become
    // the way to write a forged `system` row. When a manifest IS loaded the
    // policy verdict runs on top and can only narrow the answer.
    let decision =
        match witness_message_floor_denial(envelope, actor, policy, agent_definition_ceiling, body)
        {
            Some(reason_code) => GateDecision::deny(reason_code),
            None if policy.enforces_write_gate() => policy.evaluate_gate(&input),
            None => GateDecision::allow(),
        };
    record_gate_decision_metrics(&decision);
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
        consent: None,
    }
}

/// The manifest-independent floor: envelope validity, the staged-bytes bind,
/// and author authority. `None` means the floor is clear.
fn witness_message_floor_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    actor: WriteActor,
    policy: &PolicyManifestResolution,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    body: &[u8],
) -> Option<GateReasonCode> {
    if let Some(reason_code) = witness_message_envelope_denial(envelope, body) {
        return Some(reason_code);
    }
    if envelope.author == WITNESS_AUTHOR_SYSTEM
        && !system_author_authorized(actor, policy, agent_definition_ceiling)
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

/// Envelope shape, vocabulary and coherence. Unknown or malformed values fail
/// closed; there is no "pass it through and let the app decide" arm, because
/// the app is exactly who this door does not trust.
fn witness_message_envelope_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    body: &[u8],
) -> Option<GateReasonCode> {
    let malformed = Some(GateReasonCode::DenyWitnessMessageMalformedEnvelope);

    if !matches!(
        envelope.author,
        WITNESS_AUTHOR_USER | WITNESS_AUTHOR_COMPANION | WITNESS_AUTHOR_SYSTEM
    ) {
        return malformed;
    }
    if !valid_message_type(envelope.message_type) {
        return malformed;
    }
    if envelope.order > MAX_WITNESS_MESSAGE_ORDER {
        return malformed;
    }
    // A user's own words are never invisible. `companion`/`system` rows may be
    // hidden (an executor's kept-to-itself reasoning is a real, gated shape);
    // an invisible row attributed to the owner is a forgery with no reader.
    if envelope.author == WITNESS_AUTHOR_USER && !envelope.is_visible {
        return malformed;
    }
    if let Some(metadata) = &envelope.metadata {
        let mut nodes = 0_usize;
        let mut text_bytes = 0_usize;
        if !matches!(metadata, Value::Map(_))
            || !valid_metadata(metadata, 0, &mut nodes, &mut text_bytes)
            || encoded_metadata_len(metadata).is_none_or(|len| len > MAX_WITNESS_METADATA_BYTES)
        {
            return malformed;
        }
    }

    // The BIND. Everything above authorized the AXES; this proves the bytes the
    // caller is about to write are those axes and nothing else — no extra key,
    // no reordered map, no second copy of an axis appended after the encode.
    match envelope.encode_body() {
        Ok(canonical) if canonical == body => None,
        _ => malformed,
    }
}

/// The canonical-envelope verdict for one MESSAGE body, at the storage
/// materialization chokepoint (ONE-1686).
///
/// [`validate_canonical_witness_message_body`] answers with the row's AUTHOR
/// bucket, because that is the axis a door with no actor still has to rule on:
/// a `system` row carries no `AuthoredBy` edge, so nothing downstream can tell
/// it from the engine's own voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessMessageBodyAuthor {
    User,
    Companion,
    System,
}

/// Proves MESSAGE bytes are the canonical envelope this module encodes, and
/// returns the author bucket they claim.
///
/// This is the SAME encoder and the SAME envelope floor
/// [`check_witness_message_ceiling`] runs — decoded here rather than supplied,
/// so a door that holds bytes but no actor (a raw put, a replicated carry) can
/// still refuse anything that is not a well-formed transcript row. It is NOT a
/// second authorization path: it answers "are these bytes an envelope", never
/// "may somebody write it", and every local write still passes the ceiling
/// door before it stages.
///
/// # Errors
///
/// [`Error::InvalidWitnessMessageBody`] when the bytes are not decodable, are
/// not the canonical key set in canonical order, carry an unknown author or
/// type token, exceed the order ceiling, hide a `user` row, carry malformed
/// metadata, or do not re-encode byte-identically.
pub(crate) fn validate_canonical_witness_message_body(
    body: &[u8],
) -> Result<WitnessMessageBodyAuthor> {
    let malformed = || Error::InvalidWitnessMessageBody("MESSAGE body is not a canonical envelope");
    let mut cursor = body;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(malformed());
    };
    if !cursor.is_empty() {
        return Err(malformed());
    }
    let mut author: Option<&str> = None;
    let mut message_type: Option<&str> = None;
    let mut content: Option<&str> = None;
    let mut metadata: Option<Value> = None;
    let mut is_visible: Option<bool> = None;
    let mut order: Option<u32> = None;
    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(malformed());
        };
        // Duplicate keys are a second copy of an axis; the canonical encoder
        // emits each exactly once, so a repeat cannot round-trip anyway. It is
        // rejected by name so the failure names the reason.
        let duplicated = match key {
            BODY_KEY_AUTHOR => {
                author = value.as_str();
                author.is_none()
            }
            BODY_KEY_TYPE => {
                message_type = value.as_str();
                message_type.is_none()
            }
            BODY_KEY_CONTENT => {
                content = value.as_str();
                content.is_none()
            }
            BODY_KEY_METADATA => {
                if metadata.is_some() {
                    return Err(malformed());
                }
                metadata = Some(value.clone());
                false
            }
            BODY_KEY_IS_VISIBLE => {
                is_visible = value.as_bool();
                is_visible.is_none()
            }
            BODY_KEY_ORDER => {
                order = value.as_u64().and_then(|value| u32::try_from(value).ok());
                order.is_none()
            }
            _ => return Err(malformed()),
        };
        if duplicated {
            return Err(malformed());
        }
    }
    let (Some(author), Some(message_type), Some(content), Some(is_visible), Some(order)) =
        (author, message_type, content, is_visible, order)
    else {
        return Err(malformed());
    };
    let envelope = WitnessMessageEnvelope {
        author,
        message_type,
        content,
        metadata,
        is_visible,
        order,
    };
    // The SAME floor the ceiling door runs, including the canonical-bytes bind
    // (`encode_body() == body`), which is what makes key ORDER and the absence
    // of any extra byte part of the answer rather than of the parse.
    if witness_message_envelope_denial(&envelope, body).is_some() {
        return Err(malformed());
    }
    Ok(match envelope.author {
        WITNESS_AUTHOR_USER => WitnessMessageBodyAuthor::User,
        WITNESS_AUTHOR_COMPANION => WitnessMessageBodyAuthor::Companion,
        // The floor above already refused every other value.
        _ => WitnessMessageBodyAuthor::System,
    })
}

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
/// # Errors
///
/// [`Error::InvalidWitnessMessageBody`], always. `sync::quarantine` classifies
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
        WitnessMessageBodyAuthor::System => Error::InvalidWitnessMessageBody(
            "a replicated MESSAGE may not claim the unattributed system author",
        ),
        WitnessMessageBodyAuthor::User | WitnessMessageBodyAuthor::Companion => {
            Error::InvalidWitnessMessageBody(
                "a replicated MESSAGE carries no local actor binding for its author",
            )
        }
    })
}

/// A bounded, printable type token: ASCII alphanumerics plus the separators
/// existing types use. No whitespace, no control bytes, no empty token.
fn valid_message_type(message_type: &str) -> bool {
    !message_type.is_empty()
        && message_type.len() <= MAX_WITNESS_MESSAGE_TYPE_BYTES
        && message_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '+'))
}

/// Recursive metadata validation: bounded depth, node count, individual string
/// bytes, and aggregate key/value text bytes; string keys only, no reserved
/// envelope-axis name at any depth, and no opaque value kind.
fn valid_metadata(value: &Value, depth: usize, nodes: &mut usize, text_bytes: &mut usize) -> bool {
    if depth > MAX_WITNESS_METADATA_DEPTH {
        return false;
    }
    *nodes += 1;
    if *nodes > MAX_WITNESS_METADATA_NODES {
        return false;
    }
    match value {
        Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::F32(_) | Value::F64(_) => true,
        Value::String(text) => text.as_str().is_some_and(|text| {
            text.len() <= MAX_WITNESS_METADATA_STRING_BYTES
                && add_metadata_text_bytes(text_bytes, text.len())
        }),
        // Binary and Ext are byte channels no JSON-shaped metadata can produce;
        // accepting them would reopen the side channel one layer down.
        Value::Binary(_) | Value::Ext(_, _) => false,
        Value::Array(items) => items
            .iter()
            .all(|item| valid_metadata(item, depth + 1, nodes, text_bytes)),
        Value::Map(entries) => entries.iter().all(|(key, entry)| {
            let Some(key) = key.as_str() else {
                return false;
            };
            if key.is_empty()
                || key.len() > MAX_WITNESS_METADATA_KEY_BYTES
                || key.chars().any(char::is_control)
                || RESERVED_METADATA_KEYS.contains(&key)
                || !add_metadata_text_bytes(text_bytes, key.len())
            {
                return false;
            }
            *nodes += 1;
            *nodes <= MAX_WITNESS_METADATA_NODES
                && valid_metadata(entry, depth + 1, nodes, text_bytes)
        }),
    }
}

fn add_metadata_text_bytes(total: &mut usize, bytes: usize) -> bool {
    let Some(next) = total.checked_add(bytes) else {
        return false;
    };
    if next > MAX_WITNESS_METADATA_BYTES {
        return false;
    }
    *total = next;
    true
}

/// Exact canonical encoded size, checked only after the recursive limits above
/// have bounded all allocation-driving values.
fn encoded_metadata_len(metadata: &Value) -> Option<usize> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, metadata).ok()?;
    Some(encoded.len())
}

/// The content-addressed binding for one authorized MESSAGE write: the actor
/// that presented it and the canonical body bytes that carry every envelope
/// axis. Deterministic across processes and stable as an ABI.
fn witness_message_binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
    let entity_ref: EntityId = actor.entity_ref();
    let mut hasher = Sha256::new();
    hasher.update(WITNESS_MESSAGE_BINDING_DOMAIN);
    hasher.update(edge_actor_class_str(actor.actor_class()).as_bytes());
    hasher.update(entity_ref.as_bytes());
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}
