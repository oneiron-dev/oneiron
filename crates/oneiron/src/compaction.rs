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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rmpv::Value;

use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::SerializedContextPack;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{CompactionPacketError, Error, Result};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

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

// ═══════════════════════════════════════════════════════════════════════
// RT-05 (ONE-1687) — the in-engine compaction driver
// ═══════════════════════════════════════════════════════════════════════

/// Registered class of a compaction backend.
///
/// The ladder has exactly two rungs because the owner ruling has exactly two:
/// compaction is cheap, never frontier. This is a REGISTRATION declaration,
/// not an inference from a tier string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompactionTierClass {
    /// The only admissible class — the cheap-model tier a compaction backend
    /// is allowed to be.
    Cheap,
    /// Frontier tiers are banned as compaction backends and are refused at
    /// registration, so one is never present to resolve.
    Frontier,
}

/// A host-registered context-window compactor.
///
/// Cheap by design: [`CompactionBackendRegistry::register`] refuses a
/// frontier-tier implementation before insertion, so the ban is structural
/// rather than a post-hoc audit.
pub trait CompactionBackend: Send + Sync {
    /// The registry key a profile names in `memory_profile.compaction_backend`.
    fn backend_key(&self) -> &str;
    /// The tier class this implementation declares at registration.
    fn tier_class(&self) -> CompactionTierClass;
    /// Compacts one window span into summary text.
    ///
    /// Pure with respect to the vault: the backend sees rendered message
    /// content and a token ceiling, never storage.
    fn compact(&self, request: &CompactionRequest) -> Result<CompactionProduct>;
}

/// One message-log row the host hands the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionWindowMessage {
    pub message_id: EntityId,
    /// The covered TURN entity — the `DerivedFrom` target and the H-S3 probe
    /// subject.
    pub turn_id: EntityId,
    /// Rendered MESSAGE content: the material the backend summarizes.
    pub content: String,
    /// The turn NUMBER this row belongs to, in the session's own ordering.
    pub turn: u64,
    pub tokens: u64,
}

/// The snapshot point a compaction runs against.
///
/// This is the Dreamer's compound consolidation position (ONE-1793 v2), not a
/// bare second: `learned_at` alone cannot separate two turns sharing one
/// second, so the exact temporal-index key rides alongside it. Epoch NUMBER is
/// deliberately absent — it is minted only inside
/// [`CompactionDriver::integrate`]'s write transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionWatermark {
    /// The Dreamer's `last_learned_at` at trigger time.
    pub learned_at: u64,
    /// The Dreamer's `last_turn_id`: `None` is the end-of-second boundary,
    /// `Some` the exact temporal-index key.
    pub turn_id: Option<EntityId>,
}

/// The compaction job the driver hands the host to run on ITS runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRequest {
    /// The SESSION whose window is being compacted — the same `session_ref`
    /// vocabulary the admission door above uses.
    pub session_ref: EntityId,
    /// Ordered message-log span between the last epoch boundary and the
    /// watermark, assembled by the host: the engine never holds the log.
    pub window: Vec<CompactionWindowMessage>,
    /// Token ceiling for the produced summary text.
    pub summary_token_budget: u64,
    /// First turn number this epoch covers, read DURABLY from the session's
    /// prior epoch summaries: prior `turn_end + 1`, or the window's first turn
    /// for the session's first epoch.
    pub turn_start: u64,
    /// The recorded snapshot point.
    pub watermark: CompactionWatermark,
}

/// What a backend produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionProduct {
    pub summary_text: String,
    /// Measured wall time of THIS compact call — the latency half of the
    /// margin law.
    pub latency: Duration,
}

/// The host-constructed backend registry.
///
/// An explicit value the host builds and passes, deliberately NOT a [`Vault`]
/// field: registration is host policy, and the vault holds no policy.
#[derive(Default)]
pub struct CompactionBackendRegistry {
    backends: BTreeMap<String, Arc<dyn CompactionBackend>>,
}

impl std::fmt::Debug for CompactionBackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionBackendRegistry")
            .field("backend_keys", &self.backends.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CompactionBackendRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one backend under its own [`CompactionBackend::backend_key`].
    ///
    /// Refuses a frontier-tier implementation. The ban is EAGER: a frontier
    /// backend never enters the map, so [`Self::resolve`] cannot hand one out
    /// and no call site needs a second check.
    pub fn register(&mut self, backend: Arc<dyn CompactionBackend>) -> Result<()> {
        if backend.tier_class() != CompactionTierClass::Cheap {
            return Err(Error::InvariantViolation(
                "compaction backend declares a frontier tier and is refused",
            ));
        }
        let key = backend.backend_key().to_owned();
        if key.trim().is_empty() {
            return Err(Error::InvariantViolation("backend key must not be blank"));
        }
        self.backends.insert(key, backend);
        Ok(())
    }

    /// Resolves the backend a profile names.
    ///
    /// An unregistered key fails typed rather than falling back. `byoa`
    /// profiles never reach here — [`CompactionDriver::for_profile`] answers
    /// `Ok(None)` before resolution.
    pub fn resolve(&self, profile: &MemoryProfile) -> Result<Arc<dyn CompactionBackend>> {
        self.backends
            .get(profile.compaction_backend.as_str())
            .map(Arc::clone)
            .ok_or(Error::InvariantViolation(
                "compaction backend key is not registered",
            ))
    }

    /// The registered tier class of a registered backend, or `None` when the
    /// key names nothing.
    ///
    /// This is the ONLY authority on "is this backend a frontier tier": a
    /// frontier answer is unreachable through a registered key, which is the
    /// ban made observable.
    #[must_use]
    pub fn tier_class_of(&self, backend_key: &str) -> Option<CompactionTierClass> {
        self.backends
            .get(backend_key)
            .map(|backend| backend.tier_class())
    }
}

/// EMA smoothing factor for both margin estimators.
///
/// It tunes how fast the estimators converge on measured reality. It is NOT
/// the margin and it is not a size: changing it changes convergence speed,
/// never the law.
const MARGIN_EMA_ALPHA: f64 = 0.3;

/// Share of the window budget an epoch summary may occupy when the profile
/// carries no `budget_split`.
///
/// Mirrors the engine's existing default summaries allocation rather than
/// minting a second policy for the same question.
const DEFAULT_SUMMARY_BUDGET_FRACTION: f64 = 0.25;

/// A floor against `margin >= budget` degeneracy — not a margin, not a knob.
const COMPACT_AT_FLOOR_FRACTION: f64 = 0.5;

/// The overflow window a session lives in while a compaction runs.
///
/// **The law (owner comment `58474826`):** `margin >= compaction-latency x
/// token-velocity`. Both factors are MEASURED exponential moving averages.
/// The only constants here are the cold-start seeds and the smoothing factor,
/// and each is displaced or bounded by real samples — there is no constant
/// margin anywhere in this type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarginLaw {
    latency_ema_ms: f64,
    velocity_ema_tps: f64,
    latency_samples: u32,
    velocity_samples: u32,
}

impl Default for MarginLaw {
    fn default() -> Self {
        Self::new()
    }
}

impl MarginLaw {
    /// Cold-start latency seed, in milliseconds. Displaced outright by the
    /// FIRST measured sample — it is a starting guess, not a floor.
    pub const SEED_LATENCY_MS: f64 = 30_000.0;
    /// Cold-start velocity seed, in tokens per second. Displaced outright by
    /// the first measured sample.
    pub const SEED_VELOCITY_TPS: f64 = 50.0;

    #[must_use]
    pub const fn new() -> Self {
        Self {
            latency_ema_ms: Self::SEED_LATENCY_MS,
            velocity_ema_tps: Self::SEED_VELOCITY_TPS,
            latency_samples: 0,
            velocity_samples: 0,
        }
    }

    /// Feeds one measured compaction latency.
    pub fn observe_latency(&mut self, latency: Duration) {
        let sample = latency.as_secs_f64() * 1_000.0;
        self.latency_ema_ms = blend(self.latency_ema_ms, sample, self.latency_samples);
        self.latency_samples = self.latency_samples.saturating_add(1);
    }

    /// Feeds the measured token velocity of the live session. The caller
    /// measures; the law only consumes.
    pub fn observe_velocity(&mut self, tokens_per_second: f64) {
        if !tokens_per_second.is_finite() || tokens_per_second < 0.0 {
            return;
        }
        self.velocity_ema_tps = blend(
            self.velocity_ema_tps,
            tokens_per_second,
            self.velocity_samples,
        );
        self.velocity_samples = self.velocity_samples.saturating_add(1);
    }

    /// `margin = ceil(latency_ema x velocity_ema)` — the law, nothing else.
    #[must_use]
    pub fn margin_tokens(&self) -> u64 {
        let margin = (self.latency_ema_ms / 1_000.0 * self.velocity_ema_tps).ceil();
        if margin.is_finite() && margin > 0.0 {
            margin as u64
        } else {
            0
        }
    }

    /// The latency EMA in milliseconds, rounded half-up — the exact field a
    /// [`CompactionSignal::Starvation`] reports.
    #[must_use]
    pub fn measured_latency_ms(&self) -> u64 {
        round_half_up(self.latency_ema_ms)
    }

    /// The velocity EMA in tokens per second, rounded half-up.
    #[must_use]
    pub fn measured_velocity_tps(&self) -> u64 {
        round_half_up(self.velocity_ema_tps)
    }

    fn velocity_ema_tps(&self) -> f64 {
        self.velocity_ema_tps
    }
}

/// The FIRST sample displaces the seed outright; later samples blend.
fn blend(current: f64, sample: f64, prior_samples: u32) -> f64 {
    if prior_samples == 0 {
        sample
    } else {
        MARGIN_EMA_ALPHA.mul_add(sample, (1.0 - MARGIN_EMA_ALPHA) * current)
    }
}

fn round_half_up(value: f64) -> u64 {
    let rounded = value.round();
    if rounded.is_finite() && rounded > 0.0 {
        rounded as u64
    } else {
        0
    }
}

fn ceil_non_negative(value: f64) -> u64 {
    let ceiled = value.ceil();
    if ceiled.is_finite() && ceiled > 0.0 {
        ceiled as u64
    } else {
        0
    }
}

/// What an observation tells the session to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionDirective {
    /// The soft threshold was crossed: begin compacting the span up to
    /// `watermark` NOW, in the background, while the session keeps working.
    /// Emitted at most once per crossing.
    Begin { watermark: CompactionWatermark },
    /// Nothing to do.
    Quiet,
}

/// A typed signal the driver surfaces INSTEAD of pausing the world.
///
/// The session continues; the consumer decides what the signal means.
/// ONE-1896's landing ladder is the sibling terminal response to this same
/// threshold law — this module emits, never acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionSignal {
    /// Measured velocity times remaining latency will overrun the margin
    /// before the in-flight compaction can land.
    Starvation {
        deficit_tokens: u64,
        /// The [`MarginLaw`] latency EMA, half-up rounded — not
        /// `remaining_latency`.
        measured_latency_ms: u64,
        /// The [`MarginLaw`] velocity EMA, half-up rounded.
        measured_velocity_tps: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactionState {
    Idle,
    /// A background compaction is in flight; the session keeps working.
    Compacting {
        watermark: CompactionWatermark,
    },
}

/// The pure plan a finished compaction produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapPlan {
    pub epoch: u64,
    pub summary_id: EntityId,
    /// `accumulated`, DEFINED by the host as every message-log entry after
    /// the watermark — including messages that arrived while the backend ran.
    /// The host assembles it once; `integrate` never derives a second tail.
    pub retained_tail: Vec<CompactionWindowMessage>,
}

/// One session's compaction driver.
///
/// Owned by the session/host runtime: the engine supplies the state machine
/// and the arithmetic, the host supplies the async runtime and the message
/// log. `byoa` profiles never construct one.
pub struct CompactionDriver {
    backend: Arc<dyn CompactionBackend>,
    margin: MarginLaw,
    state: CompactionState,
    /// Resolved copy of the profile that produced this driver.
    profile: MemoryProfile,
}

impl std::fmt::Debug for CompactionDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionDriver")
            .field("backend_key", &self.backend.backend_key())
            .field("margin", &self.margin)
            .field("state", &self.state)
            .field("profile", &self.profile)
            .finish()
    }
}

impl CompactionDriver {
    /// Constructs a driver for an `engine`-owned profile.
    ///
    /// A `byoa` profile answers `Ok(None)`: exclusion by CONSTRUCTION, not a
    /// runtime check sprinkled at call sites. With no driver there is nothing
    /// to observe, request, or integrate, so the engine cannot compact that
    /// window even by mistake.
    pub fn for_profile(
        profile: &MemoryProfile,
        registry: &CompactionBackendRegistry,
    ) -> Result<Option<Self>> {
        match profile.compaction {
            CompactionOwnership::Byoa => Ok(None),
            CompactionOwnership::Engine => Ok(Some(Self {
                backend: registry.resolve(profile)?,
                margin: MarginLaw::new(),
                state: CompactionState::Idle,
                profile: profile.clone(),
            })),
        }
    }

    /// The backend this driver resolved.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn CompactionBackend> {
        &self.backend
    }

    /// The margin law's current state — the measured EMAs, never a constant.
    #[must_use]
    pub const fn margin(&self) -> &MarginLaw {
        &self.margin
    }

    /// True while a background compaction is in flight.
    #[must_use]
    pub const fn is_compacting(&self) -> bool {
        matches!(self.state, CompactionState::Compacting { .. })
    }

    /// The soft threshold: `max(budget - margin, ceil(budget / 2))`.
    ///
    /// The floor is what keeps a degenerate `margin >= budget` from asking a
    /// session to compact at zero used tokens.
    #[must_use]
    pub fn compact_at(&self) -> u64 {
        let budget = self.profile.window_token_budget;
        let floor = ceil_non_negative(budget as f64 * COMPACT_AT_FLOOR_FRACTION);
        budget
            .saturating_sub(self.margin.margin_tokens())
            .max(floor)
    }

    /// Production wiring for measured token velocity.
    ///
    /// The driver is the entry: the [`MarginLaw`] inside it is private, so a
    /// velocity sample cannot reach the law except through a live driver.
    pub fn observe_velocity(&mut self, tokens_per_second: f64) {
        self.margin.observe_velocity(tokens_per_second);
    }

    /// The production consumer contract (ONE-1687 §8): the host applies
    /// `memory_profile(..)` at builder construction, produces a REAL
    /// [`SerializedContextPack`] through
    /// [`crate::ContextPackBuilder::run_serialized_with_stats`], and passes it
    /// here after every serialized assembly.
    ///
    /// Deliberately serialized-only: a raw `ContextPackBuilder::run()` product
    /// documents `PackTokenStats::default()`, so it cannot truthfully drive a
    /// token threshold and is not accepted.
    pub fn observe_serialized_pack(
        &mut self,
        vault: &Vault,
        pack: &SerializedContextPack,
    ) -> Result<CompactionDirective> {
        self.observe_from_context_build(vault, pack.stats.tokens.total_tokens as u64)
    }

    /// The shared integer seam behind [`Self::observe_serialized_pack`].
    pub fn observe_from_context_build(
        &mut self,
        vault: &Vault,
        used_tokens: u64,
    ) -> Result<CompactionDirective> {
        self.directive(vault, used_tokens)
    }

    /// Explicit driver-callable evaluation (host sweep, turn boundary, test
    /// driver). Same threshold, same watermark read, same state machine.
    pub fn evaluate_now(
        &mut self,
        vault: &Vault,
        used_tokens: u64,
    ) -> Result<CompactionDirective> {
        self.directive(vault, used_tokens)
    }

    /// ONE threshold, ONE watermark read, ONE state transition.
    ///
    /// Every observation entry funnels here, so a second crossing while a
    /// compaction is in flight is `Quiet` — not a queue. One compaction stays
    /// in flight by construction.
    fn directive(&mut self, vault: &Vault, used_tokens: u64) -> Result<CompactionDirective> {
        match self.state {
            CompactionState::Compacting { .. } => Ok(CompactionDirective::Quiet),
            CompactionState::Idle if used_tokens >= self.compact_at() => {
                let watermark = snapshot_watermark(vault)?;
                self.state = CompactionState::Compacting { watermark };
                Ok(CompactionDirective::Begin { watermark })
            }
            CompactionState::Idle => Ok(CompactionDirective::Quiet),
        }
    }

    /// Builds the compaction job for the in-flight crossing.
    ///
    /// Legal only in `Compacting`: outside it the recorded watermark has no
    /// referent, so the call is a typed refusal rather than a guess. The HOST
    /// supplies `window` from its own message log — the engine never holds the
    /// log — and then runs `backend.compact(&request)` on its own runtime.
    ///
    /// The span START is read DURABLY from the session's prior epoch
    /// summaries (prior `turn_end + 1`, or the window's first turn for the
    /// first epoch). Epoch NUMBER is deliberately absent from this request:
    /// it is minted only inside [`Self::integrate`]'s write transaction.
    pub fn request_for(
        &self,
        vault: &Vault,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
    ) -> Result<CompactionRequest> {
        let CompactionState::Compacting { watermark } = self.state else {
            return Err(Error::InvariantViolation(
                "request_for is legal only while compacting",
            ));
        };
        let Some(first) = window.first() else {
            return Err(Error::InvariantViolation(
                "compaction window carries no messages",
            ));
        };
        let first_window_turn = window.iter().map(|m| m.turn).min().unwrap_or(first.turn);

        let rtxn = vault.store.env.read_txn()?;
        let prior = prior_epoch_in_txn(&vault.store, &rtxn, session_ref)?;
        drop(rtxn);
        let turn_start = prior.map_or(first_window_turn, |prior| prior.turn_end.saturating_add(1));

        Ok(CompactionRequest {
            session_ref: *session_ref,
            summary_token_budget: self.summary_token_budget(),
            window,
            turn_start,
            watermark,
        })
    }

    /// `budget_split.summaries * window_token_budget`, or the module's named
    /// [`DEFAULT_SUMMARY_BUDGET_FRACTION`] of it when the profile carries no
    /// split.
    ///
    /// Half-up rounding, not `ceil`: a stored `f32` fraction of `0.4` widens
    /// to `0.4000000059…` in `f64`, and ceiling that would answer 401 tokens
    /// for a 40% share of 1000 — an arithmetic artifact, not a budget.
    fn summary_token_budget(&self) -> u64 {
        let fraction = self
            .profile
            .budget_split
            .map_or(DEFAULT_SUMMARY_BUDGET_FRACTION, |split| {
                f64::from(split.summaries)
            });
        round_half_up(self.profile.window_token_budget as f64 * fraction)
    }

    /// Whether the in-flight compaction is losing the race against the live
    /// session, and by how much.
    ///
    /// `None` in `Idle`, because with no compaction in flight
    /// `remaining_latency` has no referent. In `Compacting` a signal is
    /// raised iff either arm holds:
    ///
    /// * DEGENERACY — `margin_tokens() >= window_token_budget` with a
    ///   non-zero measured velocity: the law itself is asking for more room
    ///   than the window has.
    /// * OVERRUN — `velocity_ema x remaining_latency > headroom_tokens`: the
    ///   session will out-write the remaining compaction time.
    ///
    /// Emitting is the whole response. The session-facing API keeps accepting
    /// messages either way.
    #[must_use]
    pub fn starvation_check(
        &self,
        remaining_latency: Duration,
        headroom_tokens: u64,
    ) -> Option<CompactionSignal> {
        if !self.is_compacting() {
            return None;
        }
        let velocity = self.margin.velocity_ema_tps();
        let budget = self.profile.window_token_budget;
        let margin = self.margin.margin_tokens();
        let degenerate = margin >= budget && velocity > 0.0;
        let projected = velocity * remaining_latency.as_secs_f64();
        let overrun = projected > headroom_tokens as f64;
        if !degenerate && !overrun {
            return None;
        }
        let deficit_tokens = if overrun {
            ceil_non_negative(projected - headroom_tokens as f64)
        } else {
            margin.saturating_sub(budget)
        };
        Some(CompactionSignal::Starvation {
            deficit_tokens,
            measured_latency_ms: self.margin.measured_latency_ms(),
            measured_velocity_tps: self.margin.measured_velocity_tps(),
        })
    }

    /// Backend-failure exit.
    ///
    /// Legal only in `Compacting`; returns to `Idle` WITHOUT minting, so the
    /// next threshold crossing emits `Begin` again. The host calls it on a
    /// typed backend error.
    pub fn abandon(&mut self) {
        self.state = CompactionState::Idle;
    }

    /// Integrates a finished compaction: mints the epoch summary and returns
    /// the swap plan.
    ///
    /// THIS is the moment the epoch increments — integration, when the
    /// compaction result is used, not when the work began (owner unification
    /// line). `request` is authoritative for the covered TURN ids and the turn
    /// range; backend-returned range metadata is never accepted.
    ///
    /// One vault write transaction carries the H-S3 probe, the epoch
    /// derivation, the SUMMARY put, its pending-embedding marker and the
    /// capped `DerivedFrom` edge set. The session's message-log splice
    /// (prefix out, summary in, `accumulated` replayed on top) is the caller's
    /// in-memory step: the engine never holds the session's log.
    pub fn integrate(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        byline: WriteActor,
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
    ) -> Result<SwapPlan> {
        if !self.is_compacting() {
            return Err(Error::InvariantViolation(
                "integrate is legal only while compacting",
            ));
        }
        let (epoch, summary_id) = mint_epoch_summary(vault, session_ref, byline, request, &product)?;
        self.margin.observe_latency(product.latency);
        self.state = CompactionState::Idle;
        Ok(SwapPlan {
            epoch,
            summary_id,
            retained_tail: accumulated.to_vec(),
        })
    }
}

/// Reads the trigger-time durable watermark through the Dreamer's existing
/// public surface (S-11, ONE-1793 v2).
///
/// The compound position is read whole: `last_learned_at` alone cannot
/// separate two turns sharing one second. `DreamerConsolidationScope::Micro`
/// names the Dreamer lane's OWN finest consolidation cursor — it is that
/// lane's enum variant, not a summary-tier name. Epoch summaries mint at the
/// unbounded integer `level` 0 and this module coins no tier vocabulary of
/// its own.
fn snapshot_watermark(vault: &Vault) -> Result<CompactionWatermark> {
    let watermark = crate::dreamer_consolidation::read_watermark(
        vault,
        crate::dreamer_runner::DreamerConsolidationScope::Micro,
    )?;
    Ok(CompactionWatermark {
        learned_at: watermark.last_learned_at,
        turn_id: watermark.last_turn_id,
    })
}

// ─── The EPOCH SUMMARY: the cached-prefix keyframe ──────────────────────

/// Pinned body keys for an epoch summary, in encode order.
///
/// `actor` is LAST: the dreamer/loom byline is persisted as the final key, so
/// authorship closes the record rather than opening it.
pub const EPOCH_SUMMARY_BODY_KEYS: [&str; 8] = [
    "v",
    "session",
    "epoch",
    "turn_start",
    "turn_end",
    "level",
    "text",
    "actor",
];

/// Current epoch-summary body codec version.
pub const EPOCH_SUMMARY_BODY_VERSION: u64 = 1;

/// `SUMMARY.level` an epoch summary mints at.
///
/// Storage truth is an UNBOUNDED integer (owner comment `9d06995b`). There is
/// no tier ladder here and no tier vocabulary anywhere in this module: names
/// for grains are display-layer property owned elsewhere.
pub const EPOCH_SUMMARY_LEVEL: u64 = 0;

/// Hard cap on the `DerivedFrom` edges one epoch summary emits.
///
/// The body's full turn RANGE remains truth; capped edges are provenance
/// accelerators, never the fence oracle. The mint's H-S3 probe reads every
/// covered turn regardless of this cap.
pub const EPOCH_SUMMARY_MAX_DERIVED_EDGES: usize = 256;

const KEY_EPOCH_V: &str = EPOCH_SUMMARY_BODY_KEYS[0];
const KEY_EPOCH_SESSION: &str = EPOCH_SUMMARY_BODY_KEYS[1];
const KEY_EPOCH_EPOCH: &str = EPOCH_SUMMARY_BODY_KEYS[2];
const KEY_EPOCH_TURN_START: &str = EPOCH_SUMMARY_BODY_KEYS[3];
const KEY_EPOCH_TURN_END: &str = EPOCH_SUMMARY_BODY_KEYS[4];
const KEY_EPOCH_LEVEL: &str = EPOCH_SUMMARY_BODY_KEYS[5];
const KEY_EPOCH_TEXT: &str = EPOCH_SUMMARY_BODY_KEYS[6];
const KEY_EPOCH_ACTOR: &str = EPOCH_SUMMARY_BODY_KEYS[7];

/// The typed epoch-summary body — the CB-A render contract.
///
/// CB-A (ONE-1701 keyframe render, ONE-1797 board tail) decodes an epoch
/// summary by calling the re-exported [`decode_epoch_summary_body`]. The body
/// deliberately does NOT ride `serialize.rs` SUMMARY field profiles
/// (`txt`/`lvl`/`at`/`src`): the typed codec IS the contract, so a render
/// cannot drift with a field-profile table it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EpochSummaryBody {
    /// Codec version, currently [`EPOCH_SUMMARY_BODY_VERSION`].
    pub v: u64,
    /// 32-hex ref of the SESSION this epoch belongs to.
    pub session: String,
    /// 1-based. The next epoch number derives from the session's existing
    /// epoch summaries — durable entities ARE the counter, crash-safe by
    /// append-only lineage — never from a mutable session row.
    pub epoch: u64,
    pub turn_start: u64,
    pub turn_end: u64,
    /// Storage-truth ladder integer, unbounded and never named.
    pub level: u64,
    pub text: String,
    /// 32-hex ref of the host-stamped [`WriteActor`] passed to
    /// [`CompactionDriver::integrate`]. Guest-supplied authorship is
    /// unrepresentable: the writer stamps this, never the body's author.
    pub actor: String,
}

/// Encodes an epoch-summary body into its pinned-key MessagePack form.
pub fn encode_epoch_summary_body(body: &EpochSummaryBody) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (Value::from(KEY_EPOCH_V), Value::from(body.v)),
        (
            Value::from(KEY_EPOCH_SESSION),
            Value::from(body.session.as_str()),
        ),
        (Value::from(KEY_EPOCH_EPOCH), Value::from(body.epoch)),
        (
            Value::from(KEY_EPOCH_TURN_START),
            Value::from(body.turn_start),
        ),
        (Value::from(KEY_EPOCH_TURN_END), Value::from(body.turn_end)),
        (Value::from(KEY_EPOCH_LEVEL), Value::from(body.level)),
        (Value::from(KEY_EPOCH_TEXT), Value::from(body.text.as_str())),
        (
            Value::from(KEY_EPOCH_ACTOR),
            Value::from(body.actor.as_str()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("MessagePack encode failed"))?;
    Ok(out)
}

/// Strictly decodes an epoch-summary body.
///
/// Trailing bytes, non-map values, non-string keys, unknown keys and
/// duplicate keys are all refused — the same discipline the AGENT_DEF and
/// SKILL codecs enforce, so a host cannot smuggle a field into the keyframe.
pub fn decode_epoch_summary_body(bytes: &[u8]) -> Result<EpochSummaryBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvariantViolation("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvariantViolation("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvariantViolation("body must be a MessagePack map"));
    };

    let mut integers: [Option<u64>; EPOCH_SUMMARY_BODY_KEYS.len()] = [None; 8];
    let mut session = None;
    let mut text = None;
    let mut actor = None;
    let mut seen = [false; EPOCH_SUMMARY_BODY_KEYS.len()];

    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvariantViolation("body keys must be strings"));
        };
        let Some(index) = EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvariantViolation(
                "body key is not in the pinned EPOCH_SUMMARY_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvariantViolation("duplicate body key"));
        }
        seen[index] = true;
        match EPOCH_SUMMARY_BODY_KEYS[index] {
            KEY_EPOCH_SESSION => session = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_ACTOR => actor = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_TEXT => {
                text = Some(
                    value
                        .as_str()
                        .ok_or(Error::InvariantViolation("text must be a UTF-8 string"))?
                        .to_owned(),
                );
            }
            _ => {
                integers[index] = Some(value.as_u64().ok_or(Error::InvariantViolation(
                    "numeric body keys must be unsigned integers",
                ))?);
            }
        }
    }

    let missing = || Error::InvariantViolation("missing required body key");
    let body = EpochSummaryBody {
        v: integers[0].ok_or_else(missing)?,
        session: session.ok_or_else(missing)?,
        epoch: integers[2].ok_or_else(missing)?,
        turn_start: integers[3].ok_or_else(missing)?,
        turn_end: integers[4].ok_or_else(missing)?,
        level: integers[5].ok_or_else(missing)?,
        text: text.ok_or_else(missing)?,
        actor: actor.ok_or_else(missing)?,
    };
    if body.v != EPOCH_SUMMARY_BODY_VERSION {
        return Err(Error::InvariantViolation(
            "unsupported epoch summary codec version",
        ));
    }
    if body.turn_end < body.turn_start {
        return Err(Error::InvariantViolation("turn_end precedes turn_start"));
    }
    Ok(body)
}

/// A 32-hex entity ref, validated as one rather than accepted as any string.
fn epoch_summary_hex_ref(value: &Value) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvariantViolation(
        "entity refs must be 32-hex strings",
    ))?;
    EntityId::from_hex(text)
        .map_err(|_| Error::InvariantViolation("entity refs must be 32-hex strings"))?;
    Ok(text.to_owned())
}

/// One durable prior epoch of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PriorEpoch {
    epoch: u64,
    turn_end: u64,
}

/// Reads the session's highest durable epoch summary.
///
/// The DURABLE entities are the counter: a crash between two compactions can
/// never desynchronize an epoch number from the rows that justify it, because
/// there is no separate mutable counter to desynchronize.
///
/// Rows whose body is not an epoch-summary record are SKIPPED, not refused: an
/// ordinary witness SUMMARY is a different kind of row that happens to share
/// the type byte, and it carries no epoch to compare.
fn prior_epoch_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    session_ref: &EntityId,
) -> Result<Option<PriorEpoch>> {
    let session = session_ref.to_hex();
    let mut best: Option<PriorEpoch> = None;
    for row in store.entities.iter(rtxn)? {
        let (_, raw) = row?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SUMMARY || raw.len() <= ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let Ok(body) = decode_epoch_summary_body(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            continue;
        };
        if body.session != session {
            continue;
        }
        if best.is_none_or(|prior| body.epoch > prior.epoch) {
            best = Some(PriorEpoch {
                epoch: body.epoch,
                turn_end: body.turn_end,
            });
        }
    }
    Ok(best)
}

/// Mints ONE session-kind SUMMARY entity for a finished compaction.
///
/// Everything that decides what the row IS happens inside a single write
/// transaction: the H-S3 probe over every covered turn, the epoch derivation
/// from durable prior summaries, the body encode, the put, its
/// pending-embedding marker and the capped `DerivedFrom` edge set. A refusal
/// on any axis rolls the whole transaction back, so a half-minted keyframe
/// cannot exist.
///
/// The row is BYTE-STABLE from this moment: this module exposes no update
/// path, which is what lets CB-A cache the rendered prefix.
fn mint_epoch_summary(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
) -> Result<(u64, EntityId)> {
    if request.session_ref != *session_ref {
        return Err(Error::InvariantViolation(
            "request session_ref does not match the integrated session",
        ));
    }
    let Some(turn_end) = request.window.iter().map(|message| message.turn).max() else {
        return Err(Error::InvariantViolation(
            "compaction window carries no messages",
        ));
    };
    let turn_start = request.turn_start.min(turn_end);

    // `DerivedFrom` targets come from the REQUEST's window, deduplicated in
    // first-seen order and hard-capped. The body's turn range stays truth.
    let mut derived: Vec<EntityId> = Vec::new();
    for message in &request.window {
        if derived.len() >= EPOCH_SUMMARY_MAX_DERIVED_EDGES {
            break;
        }
        if !derived.contains(&message.turn_id) {
            derived.push(message.turn_id);
        }
    }

    // The keyframe's temporal position IS the compaction moment: the recorded
    // watermark. Wall-clock would make an otherwise byte-stable row depend on
    // when it happened to be minted.
    let at = request.watermark.learned_at.max(1);
    let summary_id = EntityId::now();

    let epoch = vault.with_write_txn(|wtxn| {
        refuse_overlay_derived_mint(&vault.store, &request.window)?;
        let epoch = prior_epoch_in_txn(&vault.store, &*wtxn, session_ref)?
            .map_or(1, |prior| prior.epoch.saturating_add(1));
        let body = encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: session_ref.to_hex(),
            epoch,
            turn_start,
            turn_end,
            level: EPOCH_SUMMARY_LEVEL,
            text: product.summary_text.clone(),
            actor: byline.entity_ref().to_hex(),
        })?;
        let mut batch = vault.batch_in().put(
            &summary_id,
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: at, end: at },
            at,
            &body,
        );
        for target in &derived {
            batch = batch.edge(&summary_id, EdgeKind::DerivedFrom, target, 1.0);
        }
        batch.apply(wtxn)?;
        // Explicitly scheduled for embedding inside the mint transaction, so
        // the ratified "vector-indexed, RAPTOR-retrievable" contract is a
        // durable fact of the mint rather than a later sweep's guess.
        vault
            .store
            .mark_pending_embedding(wtxn, &summary_id, &body)?;
        Ok(epoch)
    })?;
    Ok((epoch, summary_id))
}

// ─── H-S3: creation-time refusal under the ARCH-0052 overlay model ──────

/// H-S3 (ARCH-0052 P6): refuses a base epoch-summary mint whose window covers
/// a turn that is still a LIVE session-overlay member.
///
/// Under the overlay model there is no durable fence row to write and no
/// fenced base row to suppress: an off-record turn lives in the room's own
/// [`crate::session_overlay::SessionOverlay`] and never reaches base at all
/// (ONE-1731/ONE-1732 removed the durable off-record contract outright). So
/// "fenced at creation" reads, at this head, as REFUSED at creation: the
/// engine will not mint a base keyframe derived from room content, and the
/// refusal is the landed [`Error::OffRecordTaintedBaseWrite`] the K4 taint
/// guard already raises for the same class of write.
///
/// The probe covers EVERY covered turn, so it is independent of
/// [`EPOCH_SUMMARY_MAX_DERIVED_EDGES`]: a room turn at window position 1000
/// refuses the mint even though no edge is emitted for it. Membership is read
/// from live registry state INSIDE the applying transaction, which is the
/// state the transaction applies against — the same TOCTOU-free discipline
/// the K4 guard uses.
fn refuse_overlay_derived_mint(store: &Store, window: &[CompactionWindowMessage]) -> Result<()> {
    if !store.off_record_sessions.has_overlay_entities()? {
        return Ok(());
    }
    for message in window {
        if store.off_record_sessions.contains_entity(&message.turn_id)? {
            return Err(Error::OffRecordTaintedBaseWrite {
                entity_ref: message.turn_id.to_hex(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
