//! ED-00 (ARCH-0056 §2–3): the proposal-artifact substrate the edit-distance
//! feedback loop replays, plus the actor→op binding that makes a replayed op
//! attributable.
//!
//! # What lives here
//!
//! * **Proposal artifacts** — a proposal body (skill edit, merge/split/facet
//!   body, outbound draft) lives in a `LoroText` container for its
//!   proposal→outcome window, so every intermediate edit is a CRDT op rather
//!   than a lost intermediate string. [`proposal_text`] owns that half.
//! * **Op windows** — [`LoroOpRef`] bounds the window: `proposed_ref` is the
//!   version right after the artifact opened, `final_ref` the version at
//!   finalize. ED-01 exports the delta between them.
//! * **Attribution** — [`OpSpan`] is one change's replayed text run and
//!   [`OpAttribution`] names who made it. The stamp rides the Loro commit
//!   MESSAGE (durable in the `Change` record) rather than the commit ORIGIN
//!   (local event metadata that does not survive snapshot/reopen).
//! * **Retention** — [`put_finalized_proposal_text`] persists the
//!   proposed/final pair keyed by the artifact ref. ED-09's reservoir resolves
//!   its training pairs from these rows, so retention is a contract, not a
//!   convenience.
//! * **Peer→actor registration** — [`register_peer_actor`] binds a device peer
//!   id to a [`WriteActor`], which is how an unstamped op (an out-of-band edit)
//!   still resolves to an actor, and how a stamped op is checked against the
//!   peer that authored it.
//!
//! # Feature split
//!
//! Loro is an optional dependency (`pub mod sync` is `#[cfg(feature =
//! "sync")]`; the napi/ffi/driver builds have no sync). Everything in this
//! module root is UNCONDITIONAL — the types, the retention rows, the
//! registration door — because the downstream ED ladder (delta, myers,
//! attribution, miner, graduation, escalation, routing, publisher, reservoir)
//! must compile in every build. Only [`proposal_text`], which holds a
//! `LoroDoc`, rides the sync gate. In a non-sync build nothing produces
//! [`OpSpan`]s; the record shape and the reservoir path are unchanged.
//!
//! # Name collision
//!
//! `crate::distance` is embedding cosine similarity. This tree is
//! `edit_distance` — textual edit distance over proposal artifacts. They are
//! unrelated.

#[cfg(feature = "sync")]
pub mod proposal_text;

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_ACTOR_PEER_BINDING,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Schema version of the persisted proposal-artifact record.
pub const PROPOSAL_ARTIFACT_SCHEMA_VERSION: u64 = 1;

/// Pinned MessagePack key set for a persisted proposal-artifact record.
pub const PROPOSAL_ARTIFACT_RECORD_KEYS: [&str; 8] = [
    "v",
    "artifact",
    "proposed_ref",
    "final_ref",
    "proposed_text",
    "final_text",
    "source_turn",
    "spans",
];

/// Pinned MessagePack key set for one attributed op span inside a record.
pub const PROPOSAL_ARTIFACT_SPAN_KEYS: [&str; 10] = [
    "peer", "ctr", "len", "lamport", "ts", "before", "after", "trust", "actor", "class",
];

const KEY_SCHEMA_VERSION: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[0];
const KEY_ARTIFACT: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[1];
const KEY_PROPOSED_REF: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[2];
const KEY_FINAL_REF: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[3];
const KEY_PROPOSED_TEXT: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[4];
const KEY_FINAL_TEXT: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[5];
const KEY_SOURCE_TURN: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[6];
const KEY_SPANS: &str = PROPOSAL_ARTIFACT_RECORD_KEYS[7];

const SPAN_KEY_PEER: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[0];
const SPAN_KEY_COUNTER: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[1];
const SPAN_KEY_LEN: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[2];
const SPAN_KEY_LAMPORT: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[3];
const SPAN_KEY_TIMESTAMP: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[4];
const SPAN_KEY_BEFORE: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[5];
const SPAN_KEY_AFTER: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[6];
const SPAN_KEY_TRUST: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[7];
const SPAN_KEY_ACTOR: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[8];
const SPAN_KEY_CLASS: &str = PROPOSAL_ARTIFACT_SPAN_KEYS[9];

const PROPOSAL_ARTIFACT_KEY_PREFIX: &[u8] = b"edit_distance/proposal_artifact/v1\0";
const PEER_ACTOR_INDEX_PREFIX: &[u8] = b"edit_distance/peer_actor/v1\0";

/// Value-map key carrying the bound peer id on an `actor.peer_binding` claim.
const PEER_BINDING_VALUE_KEY_PEER: &str = "peer";
/// Value-map key carrying the bound actor class on an `actor.peer_binding` claim.
const PEER_BINDING_VALUE_KEY_CLASS: &str = "class";

/// Durable handle for one proposal artifact.
///
/// Minted when the artifact opens; the retention rows and every
/// [`FinalizedProposalText`] are keyed by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalArtifactRef(EntityId);

impl ProposalArtifactRef {
    /// Wraps an entity id as a proposal-artifact ref.
    #[must_use]
    pub const fn new(id: EntityId) -> Self {
        Self(id)
    }

    /// Mints a fresh proposal-artifact ref.
    #[must_use]
    pub fn mint() -> Self {
        Self(EntityId::now())
    }

    /// The underlying entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

/// A Loro version handle bounding one end of a proposal's edit window.
///
/// Carries the `Frontiers` encoding, which is what `LoroDoc::fork_at` and
/// `find_id_spans_between` consume — so the window is directly replayable
/// rather than merely descriptive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoroOpRef(Vec<u8>);

impl LoroOpRef {
    /// Wraps encoded `Frontiers` bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The encoded `Frontiers` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One replayed change inside a proposal's edit window.
///
/// A Loro `Change` is the natural attribution unit: consecutive ops from one
/// peer merge into one change only when their commit MESSAGE is equal, and the
/// actor stamp rides that message — so a change never mixes two actors.
///
/// `before_text` / `after_text` are the artifact's full text on either side of
/// this change during causal-order replay, which is the substitution pair
/// ED-04 mines. Adjacent spans repeat text on purpose: a span handed to a
/// miner in isolation still describes its own edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpSpan {
    /// Loro peer id that authored the change (the device client id).
    pub peer_id: u64,
    /// Counter of the change's first op.
    pub counter: i32,
    /// Number of ops in the change.
    pub len: u32,
    /// Lamport clock of the change's first op — the causal replay order.
    pub lamport: u32,
    /// Commit timestamp (Unix seconds) recorded on the change.
    pub timestamp: i64,
    /// Artifact text immediately before this change replays.
    pub before_text: String,
    /// Artifact text immediately after this change replays.
    pub after_text: String,
}

/// How an [`OpSpan`]'s actor was resolved.
///
/// The three arms are ordered by trust, and the ladder never guesses: an
/// unresolvable span lands on [`OpAttribution::DevicePeer`] rather than being
/// charged to one of two candidate actors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpAttribution {
    /// The change carried an engine-written actor stamp AND that actor is the
    /// change peer's registered actor at commit time.
    Stamped(WriteActor),
    /// No honored stamp; the actor is the peer's registration active at the
    /// change's commit time. Covers out-of-band edits and stamps a remote peer
    /// is not entitled to.
    Registered(WriteActor),
    /// No registration covers the change's peer at commit time, or two
    /// registrations tie: the span is charged to the device peer, never guessed
    /// onto an actor.
    DevicePeer,
}

impl OpAttribution {
    /// The resolved actor, or `None` for the device-peer fallback.
    #[must_use]
    pub const fn actor(&self) -> Option<WriteActor> {
        match self {
            Self::Stamped(actor) | Self::Registered(actor) => Some(*actor),
            Self::DevicePeer => None,
        }
    }

    /// The pinned on-disk token for this attribution arm.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stamped(_) => "stamped",
            Self::Registered(_) => "registered",
            Self::DevicePeer => "device_peer",
        }
    }
}

/// A finalized proposal artifact: both texts, the op window that produced the
/// difference, and per-change attribution.
///
/// Both texts are retained deliberately. ED-09's reservoir exports
/// (proposed, final) training pairs by proposal ref, so dropping either end
/// makes the export impossible — retention is the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedProposalText {
    /// The artifact this record belongs to.
    pub artifact_ref: ProposalArtifactRef,
    /// Version right after the artifact opened — the window's lower bound.
    pub proposed_ref: LoroOpRef,
    /// Version at finalize — the window's upper bound.
    pub final_ref: LoroOpRef,
    /// Per-change attribution in causal (lamport) replay order.
    pub ops_by_actor: Vec<(OpAttribution, OpSpan)>,
    /// Text as proposed (at `proposed_ref`).
    pub proposed_text: String,
    /// Text as finalized (at `final_ref`).
    pub final_text: String,
    /// The TURN/entity the proposal text derives from, recorded at artifact
    /// mint. `None` for proposals with no turn source. ED-09's off-record
    /// fence probe keys off this, so an absent value there means "not
    /// turn-sourced", never "unknown".
    pub source_turn_ref: Option<EntityId>,
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/// Persists a finalized proposal artifact, keyed by its artifact ref.
///
/// Called by `ProposalTextArtifact::finalize`; also the door a non-sync build
/// would use to seed the reservoir from an already-finalized record.
pub fn put_finalized_proposal_text(vault: &Vault, record: &FinalizedProposalText) -> Result<()> {
    let key = proposal_artifact_key(record.artifact_ref);
    let value = encode_finalized_proposal_text(record)?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    })
}

/// Reads the finalized proposal artifact stored under `artifact_ref`.
pub fn finalized_proposal_text(
    vault: &Vault,
    artifact_ref: ProposalArtifactRef,
) -> Result<Option<FinalizedProposalText>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = proposal_artifact_key(artifact_ref);
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    decode_finalized_proposal_text(&raw).map(Some)
}

fn proposal_artifact_key(artifact_ref: ProposalArtifactRef) -> Vec<u8> {
    let mut key = Vec::with_capacity(PROPOSAL_ARTIFACT_KEY_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(PROPOSAL_ARTIFACT_KEY_PREFIX);
    key.extend_from_slice(artifact_ref.entity_id().as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Peer → actor registration
// ---------------------------------------------------------------------------

/// Registers `actor` as the actor behind Loro peer `peer_id`, superseding the
/// peer's previous registration.
///
/// Engine-authored only: `actor.peer_binding` is in the reserved `actor.*`
/// namespace, so this door — writing through `put_reserved_claim_in_txn` — is
/// the only way a binding exists. The generic public Claim API rejects the
/// predicate outright, which is what makes a binding evidence rather than an
/// assertion.
///
/// Supersession is temporal, not destructive: the previous row stays readable
/// with its `valid_to` closed at `now`, so [`peer_actor_at`] can attribute ops
/// authored BEFORE a re-registration to the actor that was bound then.
pub fn register_peer_actor(vault: &Vault, peer_id: u64, actor: &WriteActor) -> Result<EntityId> {
    let now = crate::unix_seconds_now();
    let actor = *actor;
    vault.with_write_txn(|wtxn| {
        let superseded = peer_binding_rows_in_txn(vault, &*wtxn, peer_id)?
            .into_iter()
            .filter(|(_, body)| body.lifecycle == ClaimLifecycleStatus::Active)
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_ACTOR_PEER_BINDING,
            ClaimSubject::Entity(actor.entity_ref()),
            peer_binding_value(peer_id, actor.actor_class()),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(now);
        // Observed: a binding is this vault's own device fact. The trust pin
        // also keeps a federated (Imported) binding from ever superseding a
        // local one.
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        vault
            .store
            .vault_meta
            .put(wtxn, &peer_actor_index_key(peer_id, &claim_id), &[])?;
        for old_id in superseded {
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, &old_id, now)?;
        }
        Ok(claim_id)
    })
}

/// The actor bound to `peer_id` at `at` (Unix seconds), or `None` when no
/// binding covers that instant.
///
/// Two bindings whose windows both cover `at` with the same `valid_from` are
/// AMBIGUOUS and resolve to `None`: a fallback must never pick between two
/// actors.
pub fn peer_actor_at(vault: &Vault, peer_id: u64, at: u64) -> Result<Option<WriteActor>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut covering = Vec::new();
    for (_, body) in peer_binding_rows_in_txn(vault, &rtxn, peer_id)? {
        if body.lifecycle == ClaimLifecycleStatus::Retracted || !binding_covers(&body, at) {
            continue;
        }
        covering.push((body.valid_from.unwrap_or(0), peer_binding_actor(&body)?));
    }
    let Some(newest) = covering.iter().map(|(from, _)| *from).max() else {
        return Ok(None);
    };
    let mut winners = covering
        .iter()
        .filter(|(from, _)| *from == newest)
        .map(|(_, actor)| *actor);
    let first = winners.next().ok_or(Error::InvariantViolation(
        "peer binding window resolution lost its own newest row",
    ))?;
    // Two bindings opened in the same second on different actors: ambiguous.
    Ok(if winners.any(|actor| actor != first) {
        None
    } else {
        Some(first)
    })
}

/// The peer's currently ACTIVE binding, or `None` when the peer has none.
///
/// One active row per peer is the invariant [`register_peer_actor`] maintains
/// by superseding. A second active row means a supersede write was lost, which
/// is corruption, not ambiguity — so this reports it instead of choosing.
pub fn active_peer_actor(vault: &Vault, peer_id: u64) -> Result<Option<WriteActor>> {
    let rtxn = vault.store.env.read_txn()?;
    let active = peer_binding_rows_in_txn(vault, &rtxn, peer_id)?
        .into_iter()
        .filter(|(_, body)| body.lifecycle == ClaimLifecycleStatus::Active)
        .collect::<Vec<_>>();
    match active.as_slice() {
        [] => Ok(None),
        [(_, body)] => peer_binding_actor(body).map(Some),
        _ => Err(Error::InvariantViolation(
            "peer has more than one active actor binding",
        )),
    }
}

/// The stamp-trust rule: whether a change authored by `peer_id` at `at` may be
/// attributed to the actor its commit message names.
///
/// A commit message replicates to every peer that syncs the doc, so honoring a
/// stamp unconditionally would let a remote peer attribute its own edits to
/// somebody else's actor. The rule is therefore: **a stamp is honored unless
/// the stamped actor is bound to a DIFFERENT peer** at commit time.
///
/// * Actor bound to this peer → honored; the binding vouches for the stamp.
/// * Actor bound to another peer → rejected; that is exactly the forgery the
///   rule exists to stop, and the span falls back to this peer's own binding.
/// * Actor bound to no peer → honored. A device peer hosts more than one
///   actor (a human and an agent on one machine, two agents on one host), and
///   that finer-than-peer grain is the whole reason the stamp exists. Under a
///   stricter "must be bound to this peer" reading, an honored stamp could
///   only ever repeat what the binding already says — the stamp channel would
///   carry no information at all, and one-device human-vs-agent attribution,
///   which ARCH-0056 §2 names, would be unreachable.
pub(crate) fn peer_actor_stamp_is_honored(
    vault: &Vault,
    peer_id: u64,
    at: u64,
    actor: &WriteActor,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, &actor.entity_ref())? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_ACTOR_PEER_BINDING
            || body.lifecycle == ClaimLifecycleStatus::Retracted
            || !binding_covers(&body, at)
        {
            continue;
        }
        if peer_binding_peer_id(&body)? != peer_id {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether a binding's valid-time window covers `at`.
fn binding_covers(body: &ClaimBody, at: u64) -> bool {
    body.valid_from.unwrap_or(0) <= at && !body.valid_to.is_some_and(|to| at >= to)
}

fn peer_binding_value(peer_id: u64, class: EdgeActorClass) -> Value {
    Value::Map(vec![
        (
            Value::from(PEER_BINDING_VALUE_KEY_PEER),
            Value::from(peer_id),
        ),
        (
            Value::from(PEER_BINDING_VALUE_KEY_CLASS),
            Value::from(actor_class_token(class)),
        ),
    ])
}

fn peer_binding_actor(body: &ClaimBody) -> Result<WriteActor> {
    let ClaimSubject::Entity(entity_ref) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "peer binding subject must be an actor entity",
        ));
    };
    let class = binding_field(body, PEER_BINDING_VALUE_KEY_CLASS)?
        .as_str()
        .and_then(actor_class_from_token)
        .ok_or(Error::InvalidClaimBody(
            "peer binding value must carry a known actor class",
        ))?;
    Ok(WriteActor::new(entity_ref, class))
}

fn peer_binding_peer_id(body: &ClaimBody) -> Result<u64> {
    binding_field(body, PEER_BINDING_VALUE_KEY_PEER)?
        .as_u64()
        .ok_or(Error::InvalidClaimBody(
            "peer binding value must carry a peer id",
        ))
}

fn binding_field<'a>(body: &'a ClaimBody, key: &str) -> Result<&'a Value> {
    let Value::Map(entries) = &body.value else {
        return Err(Error::InvalidClaimBody("peer binding value must be a map"));
    };
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or(Error::InvalidClaimBody("peer binding value is incomplete"))
}

fn peer_binding_rows_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    peer_id: u64,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut rows = Vec::new();
    let prefix = peer_actor_index_prefix(peer_id);
    for entry in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, _) = entry?;
        let claim_id = peer_actor_index_claim_id(&key)?;
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate == PREDICATE_ACTOR_PEER_BINDING {
            rows.push((claim_id, body));
        }
    }
    Ok(rows)
}

fn peer_actor_index_prefix(peer_id: u64) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(PEER_ACTOR_INDEX_PREFIX.len() + std::mem::size_of::<u64>());
    prefix.extend_from_slice(PEER_ACTOR_INDEX_PREFIX);
    prefix.extend_from_slice(&peer_id.to_be_bytes());
    prefix
}

fn peer_actor_index_key(peer_id: u64, claim_id: &EntityId) -> Vec<u8> {
    let mut key = peer_actor_index_prefix(peer_id);
    key.extend_from_slice(claim_id.as_bytes());
    key
}

fn peer_actor_index_claim_id(key: &[u8]) -> Result<EntityId> {
    let start = PEER_ACTOR_INDEX_PREFIX.len() + std::mem::size_of::<u64>();
    let bytes: [u8; ENTITY_ID_LEN] = key
        .get(start..)
        .and_then(|tail| tail.try_into().ok())
        .ok_or(Error::CorruptedIndex("peer actor index key"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("peer actor index key"))
}

/// The pinned wire token for an actor class.
///
/// Deliberately NOT `EdgeActorClass::gate_actor_class`: that key belongs to
/// Gate's `actor_ceilings` policy rows and is free to change with policy. This
/// mapping is a storage ABI. The exhaustive match makes a new class a compile
/// error here, which is the point.
pub(crate) const fn actor_class_token(class: EdgeActorClass) -> &'static str {
    match class {
        EdgeActorClass::Human => "human",
        EdgeActorClass::Agent => "agent",
        EdgeActorClass::System => "system",
    }
}

/// Inverse of [`actor_class_token`]; `None` for an unknown token.
pub(crate) fn actor_class_from_token(token: &str) -> Option<EdgeActorClass> {
    [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ]
    .into_iter()
    .find(|class| actor_class_token(*class) == token)
}

// ---------------------------------------------------------------------------
// Record codec
// ---------------------------------------------------------------------------

fn encode_finalized_proposal_text(record: &FinalizedProposalText) -> Result<Vec<u8>> {
    let spans = record
        .ops_by_actor
        .iter()
        .map(|(attribution, span)| encode_span(*attribution, span))
        .collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PROPOSAL_ARTIFACT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ARTIFACT),
            Value::Binary(record.artifact_ref.entity_id().as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PROPOSED_REF),
            Value::Binary(record.proposed_ref.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_FINAL_REF),
            Value::Binary(record.final_ref.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PROPOSED_TEXT),
            Value::from(record.proposed_text.as_str()),
        ),
        (
            Value::from(KEY_FINAL_TEXT),
            Value::from(record.final_text.as_str()),
        ),
        (
            Value::from(KEY_SOURCE_TURN),
            record
                .source_turn_ref
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (Value::from(KEY_SPANS), Value::Array(spans)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("proposal artifact record MessagePack encode failed")
    })?;
    Ok(out)
}

fn encode_span(attribution: OpAttribution, span: &OpSpan) -> Value {
    let (actor, class) = match attribution.actor() {
        Some(actor) => (
            Value::Binary(actor.entity_ref().as_bytes().to_vec()),
            Value::from(actor_class_token(actor.actor_class())),
        ),
        None => (Value::Nil, Value::Nil),
    };
    Value::Map(vec![
        (Value::from(SPAN_KEY_PEER), Value::from(span.peer_id)),
        (
            Value::from(SPAN_KEY_COUNTER),
            Value::from(i64::from(span.counter)),
        ),
        (Value::from(SPAN_KEY_LEN), Value::from(u64::from(span.len))),
        (
            Value::from(SPAN_KEY_LAMPORT),
            Value::from(u64::from(span.lamport)),
        ),
        (Value::from(SPAN_KEY_TIMESTAMP), Value::from(span.timestamp)),
        (
            Value::from(SPAN_KEY_BEFORE),
            Value::from(span.before_text.as_str()),
        ),
        (
            Value::from(SPAN_KEY_AFTER),
            Value::from(span.after_text.as_str()),
        ),
        (
            Value::from(SPAN_KEY_TRUST),
            Value::from(attribution.as_str()),
        ),
        (Value::from(SPAN_KEY_ACTOR), actor),
        (Value::from(SPAN_KEY_CLASS), class),
    ])
}

fn decode_finalized_proposal_text(bytes: &[u8]) -> Result<FinalizedProposalText> {
    let entries = decode_map(bytes)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64)
        != Some(PROPOSAL_ARTIFACT_SCHEMA_VERSION)
    {
        return Err(corrupt());
    }
    let spans = match field(&entries, KEY_SPANS).ok_or_else(corrupt)? {
        Value::Array(items) => items.iter().map(decode_span).collect::<Result<Vec<_>>>()?,
        _ => return Err(corrupt()),
    };
    Ok(FinalizedProposalText {
        artifact_ref: ProposalArtifactRef::new(field_entity_id(&entries, KEY_ARTIFACT)?),
        proposed_ref: LoroOpRef::from_bytes(field_binary(&entries, KEY_PROPOSED_REF)?),
        final_ref: LoroOpRef::from_bytes(field_binary(&entries, KEY_FINAL_REF)?),
        ops_by_actor: spans,
        proposed_text: field_str(&entries, KEY_PROPOSED_TEXT)?.to_owned(),
        final_text: field_str(&entries, KEY_FINAL_TEXT)?.to_owned(),
        source_turn_ref: field_opt_entity_id(&entries, KEY_SOURCE_TURN)?,
    })
}

fn decode_span(value: &Value) -> Result<(OpAttribution, OpSpan)> {
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    let attribution = decode_attribution(entries)?;
    let span = OpSpan {
        peer_id: field_u64(entries, SPAN_KEY_PEER)?,
        counter: i32::try_from(field_i64(entries, SPAN_KEY_COUNTER)?).map_err(|_| corrupt())?,
        len: u32::try_from(field_u64(entries, SPAN_KEY_LEN)?).map_err(|_| corrupt())?,
        lamport: u32::try_from(field_u64(entries, SPAN_KEY_LAMPORT)?).map_err(|_| corrupt())?,
        timestamp: field_i64(entries, SPAN_KEY_TIMESTAMP)?,
        before_text: field_str(entries, SPAN_KEY_BEFORE)?.to_owned(),
        after_text: field_str(entries, SPAN_KEY_AFTER)?.to_owned(),
    };
    Ok((attribution, span))
}

fn decode_attribution(entries: &[(Value, Value)]) -> Result<OpAttribution> {
    let trust = field_str(entries, SPAN_KEY_TRUST)?;
    if trust == OpAttribution::DevicePeer.as_str() {
        return Ok(OpAttribution::DevicePeer);
    }
    let entity_ref = field_entity_id(entries, SPAN_KEY_ACTOR)?;
    let class = actor_class_from_token(field_str(entries, SPAN_KEY_CLASS)?).ok_or_else(corrupt)?;
    let actor = WriteActor::new(entity_ref, class);
    match trust {
        "stamped" => Ok(OpAttribution::Stamped(actor)),
        "registered" => Ok(OpAttribution::Registered(actor)),
        _ => Err(corrupt()),
    }
}

fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt());
    }
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(corrupt()),
    }
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn field_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    field(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(corrupt)
}

fn field_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or_else(corrupt)
}

fn field_i64(entries: &[(Value, Value)], key: &str) -> Result<i64> {
    field(entries, key)
        .and_then(Value::as_i64)
        .ok_or_else(corrupt)
}

fn field_binary(entries: &[(Value, Value)], key: &str) -> Result<Vec<u8>> {
    match field(entries, key) {
        Some(Value::Binary(bytes)) => Ok(bytes.clone()),
        _ => Err(corrupt()),
    }
}

fn field_entity_id(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let bytes: [u8; ENTITY_ID_LEN] = field_binary(entries, key)?
        .try_into()
        .map_err(|_| corrupt())?;
    EntityId::from_bytes(bytes).map_err(|_| corrupt())
}

fn field_opt_entity_id(entries: &[(Value, Value)], key: &str) -> Result<Option<EntityId>> {
    match field(entries, key) {
        None | Some(Value::Nil) => Ok(None),
        Some(_) => field_entity_id(entries, key).map(Some),
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("proposal artifact record")
}

#[cfg(test)]
mod tests;
