//! DREAM-008 (ONE-1250) compaction handoff validation — the fail-closed
//! door a forked-compaction packet must pass before anything downstream may
//! treat it as evidence.
//!
//! A host that compacts a conversation out-of-process hands the engine a
//! [`CompactionPacket`]: a schema-pinned claim about which turns were
//! compacted, which sitting they came from, and which opaque snapshot the
//! compaction produced. Every field of that claim is host-supplied, so none
//! of it is trusted. [`admit_compaction_packet`] is the ONLY door, and it
//! re-derives each axis against what the vault itself recorded.
//!
//! # Witness unforgeability
//!
//! [`ValidatedCompactionPacket`] has private fields, no public constructor,
//! no `Default`, and no deserializer. It cannot be built outside this
//! module, so a consumer holding one holds proof that the door ran — not a
//! caller's assertion that it did. Downstream code takes the witness by
//! value or reference and never re-checks; the check is structural.
//!
//! # Fail-closed, every axis
//!
//! Each axis maps to ONE [`CompactionPacketError`] variant, so a caller can
//! act on the exact refusal. There is no partial admission and no silent
//! migration: a packet that trips any axis yields an `Err` and no witness.
//!
//! The membership axis is the sharp one. A turn proves its sitting through
//! the TURN → SESSION membership row the witness door writes ATOMICALLY
//! with the turn (`session_lifecycle::record_turn_session_membership_in_txn`,
//! inside the same write transaction as the TURN put). A turn carrying no
//! such row — one witnessed before that write landed, one witnessed outside
//! any sitting, or one promoted verbatim out of an off-record overlay — has
//! an UNKNOWN sitting, not an empty one, and is refused with
//! [`CompactionPacketError::SessionMembershipNotRecorded`], which is
//! deliberately distinct from
//! [`CompactionPacketError::TurnFromOtherSession`]. Legacy data never
//! passes silently.
//!
//! # What the engine will not do
//!
//! The engine never resolves a foreign snapshot store. [`CompactionSnapshotRef`]
//! is an opaque content hash plus a byte length; the engine checks it is
//! structurally usable, and compares it to an expected ref ONLY when the
//! caller supplies one. Producing packets (the host cutting a forked
//! compaction) is out of scope here.
//!
//! # Two disjoint facets, one module (RT-05, ONE-1687)
//!
//! Everything above is the DOOR: admission of a packet a host cut OUT of
//! process. Everything below [`CompactionBackend`] is the DRIVER: in-engine
//! context-window compaction — the pluggable cheap backend seam, the margin
//! law, the background-swap state machine, and the epoch-summary mint. The
//! two facets share this module and the `session_ref` / watermark vocabulary
//! and nothing else: the door validates a foreign judgment, the driver
//! produces a local one.
//!
//! The driver owns no scheduler, thread, timer or heartbeat (ARCH-0026 /
//! CROSS-ARCH-0022 / ARCH-0046). It is a state machine plus arithmetic; the
//! host supplies the runtime and calls [`CompactionDriver::observe_serialized_pack`]
//! after every serialized assembly.

mod driver;
mod epoch;

pub use driver::{
    CompactionBackend, CompactionBackendRegistry, CompactionDirective, CompactionDriver,
    CompactionProduct, CompactionRequest, CompactionSignal, CompactionTierClass,
    CompactionWatermark, CompactionWindowMessage, MarginLaw, SwapPlan,
};
pub use epoch::{
    EPOCH_SUMMARY_BODY_KEYS, EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL,
    EPOCH_SUMMARY_MAX_DERIVED_EDGES, EpochSummaryBody, decode_epoch_summary_body,
    encode_epoch_summary_body,
};

use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{CompactionPacketError, Error, Result};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::Vault;

/// Wire schema version of [`CompactionPacket`]. Pinned, not negotiated: a
/// packet stamped with any other value is refused, never migrated.
pub const COMPACTION_PACKET_SCHEMA_VERSION: u16 = 1;

/// Opaque reference to the artifact a forked compaction produced.
///
/// The engine treats both fields as identity bytes only — it never opens,
/// fetches, or interprets the referenced blob, and it holds no snapshot
/// store of its own. `content_hash` is whatever 32-byte digest the producer
/// pinned; `byte_len` is the artifact's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactionSnapshotRef {
    /// 32-byte content digest of the snapshot artifact.
    pub content_hash: [u8; 32],
    /// Byte length of the snapshot artifact.
    pub byte_len: u64,
}

/// What a compaction packet's payload IS. Closed on purpose: an unknown
/// kind byte is a refusal ([`CompactionPacketError::PayloadKindUnknown`]),
/// never a pass-through.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompactionPayloadKind {
    /// A prose digest of the compacted turns.
    TurnDigest = 0,
    /// A working-set handoff naming the entities to carry forward.
    WorkingSetHandoff = 1,
}

impl CompactionPayloadKind {
    /// Stable wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte. `None` for every byte outside the closed set.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::TurnDigest),
            1 => Some(Self::WorkingSetHandoff),
            _ => None,
        }
    }
}

/// One host-supplied compaction handoff claim — UNVALIDATED.
///
/// Every field is caller input. Nothing here is evidence until
/// [`admit_compaction_packet`] returns a [`ValidatedCompactionPacket`].
/// `payload_kind` is the raw wire byte rather than
/// [`CompactionPayloadKind`] precisely so an unknown byte is representable
/// and therefore refusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionPacket {
    /// Must equal [`COMPACTION_PACKET_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// The sitting the compacted turns are claimed to come from.
    pub session_ref: EntityId,
    /// The compacted turns. Never empty.
    pub turn_ids: Vec<EntityId>,
    /// Raw [`CompactionPayloadKind`] wire byte.
    pub payload_kind: u8,
    /// Opaque reference to the compaction artifact.
    pub snapshot: CompactionSnapshotRef,
    /// [`CompactionPayloadKind::TurnDigest`]: required, non-empty.
    /// [`CompactionPayloadKind::WorkingSetHandoff`]: must be absent.
    pub digest_text: Option<String>,
    /// [`CompactionPayloadKind::WorkingSetHandoff`]: required, non-empty.
    /// [`CompactionPayloadKind::TurnDigest`]: must be empty.
    pub working_set_refs: Vec<EntityId>,
}

/// A [`CompactionPacket`] that passed every admission axis.
///
/// Constructed ONLY by [`admit_compaction_packet`] — the fields are
/// private, there is no public constructor, no `Default`, and no
/// deserializer. Holding this value IS the proof that validation ran.
///
/// The compile surface enforces that; a struct literal cannot forge one:
///
/// ```compile_fail
/// use oneiron::compaction::{
///     CompactionPacket, CompactionPayloadKind, CompactionSnapshotRef,
///     ValidatedCompactionPacket, COMPACTION_PACKET_SCHEMA_VERSION,
/// };
/// use oneiron::entity_id::EntityId;
///
/// let session = EntityId::from_bytes([0x51; 16]).unwrap();
/// let forged = ValidatedCompactionPacket {
///     packet: CompactionPacket {
///         schema_version: COMPACTION_PACKET_SCHEMA_VERSION,
///         session_ref: session,
///         turn_ids: vec![session],
///         payload_kind: CompactionPayloadKind::TurnDigest.as_u8(),
///         snapshot: CompactionSnapshotRef { content_hash: [7; 32], byte_len: 9 },
///         digest_text: Some("forged".to_owned()),
///         working_set_refs: Vec::new(),
///     },
///     payload_kind: CompactionPayloadKind::TurnDigest,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCompactionPacket {
    packet: CompactionPacket,
    payload_kind: CompactionPayloadKind,
}

impl ValidatedCompactionPacket {
    /// The pinned schema version this packet was admitted under.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.packet.schema_version
    }

    /// The sitting every carried turn was proven to belong to.
    #[must_use]
    pub const fn session(&self) -> EntityId {
        self.packet.session_ref
    }

    /// The compacted turns, each proven to be a live TURN of [`Self::session`].
    #[must_use]
    pub fn turn_ids(&self) -> &[EntityId] {
        &self.packet.turn_ids
    }

    /// The decoded payload kind.
    #[must_use]
    pub const fn payload_kind(&self) -> CompactionPayloadKind {
        self.payload_kind
    }

    /// The opaque snapshot reference.
    #[must_use]
    pub const fn snapshot(&self) -> &CompactionSnapshotRef {
        &self.packet.snapshot
    }

    /// The digest prose, present exactly for
    /// [`CompactionPayloadKind::TurnDigest`].
    #[must_use]
    pub fn digest_text(&self) -> Option<&str> {
        self.packet.digest_text.as_deref()
    }

    /// The working-set refs, non-empty exactly for
    /// [`CompactionPayloadKind::WorkingSetHandoff`].
    #[must_use]
    pub fn working_set_refs(&self) -> &[EntityId] {
        &self.packet.working_set_refs
    }
}

/// The ONE compaction handoff admission door.
///
/// Validates `p` against what the vault itself recorded and returns the
/// [`ValidatedCompactionPacket`] witness, or the exact
/// [`CompactionPacketError`] axis that refused it. Read-only: admission
/// writes nothing, so a refusal leaves the vault byte-identical and a
/// success commits nothing to undo.
///
/// `expected_snapshot` is the caller's own copy of the snapshot ref. When
/// `Some`, the packet's ref must match it exactly. When `None`, the
/// snapshot is checked for structural usability only — the engine holds no
/// snapshot store and will not resolve a foreign one, so a mismatch is
/// simply not knowable without the caller's ref.
///
/// Cheap axes (pure packet shape) run before the transaction so a
/// malformed packet never opens one.
pub fn admit_compaction_packet(
    vault: &Vault,
    p: CompactionPacket,
    expected_snapshot: Option<&CompactionSnapshotRef>,
) -> Result<ValidatedCompactionPacket> {
    validate_schema_version(p.schema_version)?;
    let payload_kind = validate_payload_kind(p.payload_kind)?;
    validate_payload_shape(&p, payload_kind)?;
    validate_snapshot_ref(&p.snapshot)?;
    validate_snapshot_match(&p.snapshot, expected_snapshot)?;
    validate_turn_ids_non_empty(&p.turn_ids)?;

    let rtxn = vault.store.env.read_txn()?;
    validate_session(&vault.store, &rtxn, p.session_ref)?;
    validate_turn_membership(&vault.store, &rtxn, &p.turn_ids, p.session_ref)?;
    drop(rtxn);

    Ok(ValidatedCompactionPacket {
        packet: p,
        payload_kind,
    })
}

/// Axis: schema pin. No migration path — a foreign version is refused.
fn validate_schema_version(got: u16) -> Result<()> {
    if got != COMPACTION_PACKET_SCHEMA_VERSION {
        return Err(CompactionPacketError::SchemaMismatch {
            expected: COMPACTION_PACKET_SCHEMA_VERSION,
            got,
        }
        .into());
    }
    Ok(())
}

/// Axis: the payload-kind byte is inside the closed set.
fn validate_payload_kind(byte: u8) -> Result<CompactionPayloadKind> {
    CompactionPayloadKind::from_u8(byte)
        .ok_or_else(|| CompactionPacketError::PayloadKindUnknown { byte }.into())
}

/// Axis: payload fields match the shape pinned for the decoded kind. Each
/// kind owns exactly one field family, and the other family must be empty —
/// a packet carrying both is ambiguous about what it hands off.
fn validate_payload_shape(p: &CompactionPacket, kind: CompactionPayloadKind) -> Result<()> {
    let violation = match kind {
        CompactionPayloadKind::TurnDigest => {
            if p.digest_text.as_deref().is_none_or(str::is_empty) {
                Some("turn digest requires non-empty digest_text")
            } else if !p.working_set_refs.is_empty() {
                Some("turn digest carries no working_set_refs")
            } else {
                None
            }
        }
        CompactionPayloadKind::WorkingSetHandoff => {
            if p.working_set_refs.is_empty() {
                Some("working set handoff requires non-empty working_set_refs")
            } else if p.digest_text.is_some() {
                Some("working set handoff carries no digest_text")
            } else {
                None
            }
        }
    };
    match violation {
        Some(detail) => Err(CompactionPacketError::PayloadShapeViolation(detail).into()),
        None => Ok(()),
    }
}

/// Axis: the snapshot ref is structurally usable. A zero digest and a
/// zero-length artifact are both "unset" masquerading as a value.
fn validate_snapshot_ref(snapshot: &CompactionSnapshotRef) -> Result<()> {
    if snapshot.content_hash == [0_u8; 32] {
        return Err(CompactionPacketError::SnapshotMalformed("zero content hash").into());
    }
    if snapshot.byte_len == 0 {
        return Err(CompactionPacketError::SnapshotMalformed("zero byte length").into());
    }
    Ok(())
}

/// Axis: the snapshot ref matches the caller's expected ref, when supplied.
/// The engine resolves no foreign snapshot store, so this axis exists ONLY
/// through the caller's parameter.
fn validate_snapshot_match(
    snapshot: &CompactionSnapshotRef,
    expected: Option<&CompactionSnapshotRef>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if snapshot.content_hash != expected.content_hash {
        return Err(CompactionPacketError::SnapshotMismatch {
            field: "content_hash",
        }
        .into());
    }
    if snapshot.byte_len != expected.byte_len {
        return Err(CompactionPacketError::SnapshotMismatch { field: "byte_len" }.into());
    }
    Ok(())
}

/// Axis: the packet names at least one turn.
fn validate_turn_ids_non_empty(turn_ids: &[EntityId]) -> Result<()> {
    if turn_ids.is_empty() {
        return Err(CompactionPacketError::EmptyTurnIds.into());
    }
    Ok(())
}

/// Axis: `session_ref` resolves to a stored SESSION entity.
fn validate_session(store: &Store, rtxn: &heed::RoTxn<'_>, session: EntityId) -> Result<()> {
    if entity_type_in_txn(store, rtxn, &session)? != Some(ENTITY_TYPE_SESSION) {
        return Err(CompactionPacketError::UnknownSession { session }.into());
    }
    Ok(())
}

/// Axes: every turn resolves, is a TURN, has a RECORDED sitting, and that
/// sitting is the packet's. Membership absence is its own refusal — the
/// unknown answer never collapses into the wrong-session answer.
fn validate_turn_membership(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    turn_ids: &[EntityId],
    session: EntityId,
) -> Result<()> {
    for turn in turn_ids {
        let turn = *turn;
        match entity_type_in_txn(store, rtxn, &turn)? {
            None => return Err(CompactionPacketError::UnknownTurn { turn }.into()),
            Some(ENTITY_TYPE_TURN) => {}
            Some(entity_type) => {
                return Err(CompactionPacketError::TurnNotTurnEntity { turn, entity_type }.into());
            }
        }
        let Some(recorded) = turn_session_membership_in_txn(store, rtxn, &turn)? else {
            return Err(CompactionPacketError::SessionMembershipNotRecorded { turn }.into());
        };
        if recorded != session {
            return Err(CompactionPacketError::TurnFromOtherSession { turn, recorded }.into());
        }
    }
    Ok(())
}

/// Stored type byte of one entity, or `None` when it does not resolve.
fn entity_type_in_txn(store: &Store, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// `vault_meta` key prefix for TURN → SESSION membership rows (DREAM-008,
/// ONE-1250): suffix = 16-byte TURN id, value = 16-byte SESSION id. Its own
/// keyspace, so no existing record shape or version changes.
const SESSION_TURN_MEMBERSHIP_KEY_PREFIX: &[u8] = b"session_lifecycle:v0:turn_session:";

/// `vault_meta` key of one TURN's session-membership row (DREAM-008).
fn turn_session_membership_key(turn: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SESSION_TURN_MEMBERSHIP_KEY_PREFIX.len() + 16);
    key.extend_from_slice(SESSION_TURN_MEMBERSHIP_KEY_PREFIX);
    key.extend_from_slice(turn.as_bytes());
    key
}

/// Decodes a membership row value (a bare 16-byte SESSION id).
fn decode_turn_session_membership(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("session lifecycle turn membership"))?;
    EntityId::from_bytes(raw)
        .map_err(|_| Error::CorruptedIndex("session lifecycle turn membership"))
}

/// Reads the SESSION a TURN was witnessed into, or `None` when no
/// membership fact was recorded for it (DREAM-008, ONE-1250).
///
/// `None` is an UNKNOWN answer, never "no session": turns witnessed before
/// [`record_turn_session_membership_in_txn`] landed carry no row at all, so
/// every consumer must fail closed on `None` rather than treat it as a
/// pass. The compaction door does exactly that
/// ([`crate::error::CompactionPacketError::SessionMembershipNotRecorded`]).
pub(crate) fn turn_session_membership_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &turn_session_membership_key(turn))?
    else {
        return Ok(None);
    };
    decode_turn_session_membership(&raw).map(Some)
}

/// Records the TURN → SESSION membership fact inside the caller's write
/// transaction (DREAM-008, ONE-1250).
///
/// Called from the witness door beside the activity bump, so membership
/// commits ATOMICALLY with the TURN row: a crash can never leave a turn
/// recorded without its sitting. `session` is `None` when no session is
/// open (ARCH-0002 open-endedness — a sessionless turn stays valid) or
/// when the call is an APPEND to an already-stored turn; an append never
/// re-homes a turn into whatever sitting happens to be open now.
///
/// Idempotent and first-write-wins: an already-recorded membership is
/// returned unchanged rather than overwritten, so a turn never carries two
/// sittings.
///
/// # Why a `vault_meta` row and not a TURN → SESSION edge
///
/// Membership is lookup plumbing, not graph substance. A structural edge
/// would enter the TURN's PUBLIC out-edge set — which `Vault::edges_out`
/// exposes and existing witness-path callers count — so every turn
/// witnessed inside a sitting would silently grow an edge that retrieval,
/// PPR traversal and the `ChildOf` conversation binding never asked for.
/// The `off_record` `vault_meta` pattern this module already uses keeps the
/// fact durable, atomic with the turn write, and O(1) to resolve BY TURN —
/// which is exactly the direction validation reads it — without touching
/// the graph surface at all.
pub(crate) fn record_turn_session_membership_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    session: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let Some(session) = session else {
        return Ok(None);
    };
    if let Some(existing) = turn_session_membership_in_txn(store, &*wtxn, turn)? {
        return Ok(Some(existing));
    }
    store
        .vault_meta
        .put(wtxn, &turn_session_membership_key(turn), session.as_bytes())?;
    Ok(Some(session))
}

#[cfg(test)]
mod tests;
