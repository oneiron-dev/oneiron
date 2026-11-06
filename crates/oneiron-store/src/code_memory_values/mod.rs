//! Symbol-anchored memory values, deterministic union rules and row codecs.

pub mod pull_result;
pub use pull_result::CodeMemoryPullResult;

use crate::code_document_values::CodeSpanAnchor;
use crate::side_table;
use crate::side_table::codec::RawValue;
use crate::write_envelope::WriteActor;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Width of the actor-scoped dedupe digest (SHA-256, matching the
/// code-symbol module's digest convention).
pub const CODE_MEMORY_CONTENT_HASH_LEN: usize = 32;

/// Maximum encoded slot-name length.
pub const CODE_MEMORY_SLOT_NAME_MAX_BYTES: usize = 128;

/// The most live values one named slot body encodes: its value count is one
/// `u16` field, a field bound and no count refusal. A value past it is a
/// typed capacity error that leaves the stored slot byte-identical. Past
/// 256 values a slot write keeps every value and raises the
/// `code_memory_slot_values` scan check (FIX 8562).
pub const CODE_MEMORY_MAX_VALUES_PER_SLOT: usize = 65_535;

/// The distinct `(symbol, slot, payload)` always-on contract keys PER SYMBOL
/// past which a registration or transfer raises the
/// `code_memory_always_on_contracts` scan check and keeps every contract
/// (FIX 8562; once refused past it). Pull imposes no global cut.
pub const CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS: usize = 8;

/// PPR expansion depth for an L2 pull.
///
/// Alpha `0.15` and `SeedWeighting::Specificity` are copied verbatim from
/// the landed code-symbol PPR entry; depth is fixed HERE because that entry
/// parameterizes it and its sole landed caller supplies `2`. There is
/// deliberately no request-level tuning knob.
pub const CODE_MEMORY_PPR_DEPTH: u32 = 2;

/// Default caller note limit.
pub const CODE_MEMORY_DEFAULT_PULL_LIMIT: usize = 32;

/// The seed count, note limit and threshold-passing symbol count past which
/// an L2 pull raises its scan checks and serves the whole request (FIX 9690,
/// FIX 10008, FIX 10210; once refused or cut past it).
pub const CODE_MEMORY_MAX_PULL_LIMIT: usize = 256;

impl RawValue for CodeMemorySlot {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::codec::CodecError> {
        Ok(encode_slot(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::codec::CodecError> {
        Ok(decode_slot(bytes)?)
    }
}

impl RawValue for (CodeMemoryLocator, EntityId) {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::codec::CodecError> {
        Ok(encode_attachment_row(&self.0, self.1))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::codec::CodecError> {
        Ok(decode_attachment_row(bytes)?)
    }
}

impl RawValue for AlwaysOnCodeMemoryContract {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::codec::CodecError> {
        Ok(encode_always_on(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::codec::CodecError> {
        Ok(decode_always_on(bytes)?)
    }
}

impl RawValue for AnchorTransferRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::codec::CodecError> {
        Ok(encode_transfer_record(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::codec::CodecError> {
        Ok(decode_transfer_record(bytes)?)
    }
}

/// Record version leading every encoded body in this module.
const CODE_MEMORY_RECORD_VERSION: u8 = 1;

/// NUL separator between variable-width key segments. Slot names reject
/// control characters, so this byte can never occur inside one.
const KEY_SEPARATOR: u8 = 0;

const PAYLOAD_TAG_NOTE_ENTITY: u8 = 0;
const PAYLOAD_TAG_CLAIM: u8 = 1;

const TRANSFER_TAG_RENAME: u8 = 0;
const TRANSFER_TAG_COPY: u8 = 1;

const CONTRACT_TAG_INTERFACE: u8 = 0;
const CONTRACT_TAG_POLICY: u8 = 1;

/// The most bytes one encoded document cursor of a locator holds: one
/// encoded field's bound.
pub const CODE_MEMORY_CURSOR_MAX_BYTES: usize = 1024;

/// Domain separator for the deterministic transfer-receipt key digest.
const TRANSFER_DIGEST_DOMAIN: &[u8] = b"oneiron.code_memory.transfer.v1\0";

/// An opaque reference to durable L2 material already resident in the vault.
///
/// The tag tells ATTACHMENT POLICY whether a ref denotes a note entity or a
/// claim payload. It neither defines nor decodes either payload schema: NOTE
/// and CLAIM bodies stay opaque to this module in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeMemoryPayloadRef {
    NoteEntity(EntityId),
    Claim(EntityId),
}

impl CodeMemoryPayloadRef {
    /// The referenced entity id, whatever the tag.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        match self {
            Self::NoteEntity(id) | Self::Claim(id) => id,
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::NoteEntity(_) => PAYLOAD_TAG_NOTE_ENTITY,
            Self::Claim(_) => PAYLOAD_TAG_CLAIM,
        }
    }

    pub fn from_tag(tag: u8, id: EntityId) -> Result<Self> {
        match tag {
            PAYLOAD_TAG_NOTE_ENTITY => Ok(Self::NoteEntity(id)),
            PAYLOAD_TAG_CLAIM => Ok(Self::Claim(id)),
            _ => Err(record_error()),
        }
    }
}

/// Revision locator for an attachment: a cursor-anchored span on the
/// symbol's file document, at the document version it was taken at
/// (ARCH-0050, amended under RD-23; FIX 7810). LOCATOR ONLY — no API in this
/// module resolves attachment identity from any of these fields. A rename is
/// an op on the document, so the span follows it with no transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryLocator {
    /// The document and the encoded cursors that find the span on it.
    pub span: CodeSpanAnchor,
    /// The document's canonical Loro version vector the span was taken at.
    pub version: Vec<(u64, i32)>,
    pub validity: TimeRange,
}

impl CodeMemoryLocator {
    /// Validates the locator's own bounded structure. Deliberately does NOT
    /// check that the locator "belongs to" a symbol: locators are
    /// caller-asserted values, never identity.
    pub fn validate(&self) -> Result<()> {
        for cursor in [&self.span.start, &self.span.end] {
            if cursor.is_empty() || cursor.len() > CODE_MEMORY_CURSOR_MAX_BYTES {
                return Err(Error::Code(CodeError::CodeMemoryInvalidAnchor {
                    reason: "locator cursors must be non-empty and within the encoded cursor bound",
                }));
            }
        }
        validate_time_range(self.validity, "locator validity")
    }
}

/// A note's anchor. `symbol_id` is the SOLE identity anchor; `locator` is
/// metadata that travels with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryAnchor {
    pub symbol_id: EntityId,
    pub locator: CodeMemoryLocator,
}

/// One decoded attachment-index row: which payload is attached to which
/// `(symbol, slot)`, under which locator, with which provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryAttachment {
    pub anchor: CodeMemoryAnchor,
    pub slot: CodeMemorySlotName,
    pub payload: CodeMemoryPayloadRef,
    pub provenance_claim_id: EntityId,
}

// ---------------------------------------------------------------------------
// Section 2 — multi-writer slots: actor-scoped dedupe, union merge, visible
// conflict
// ---------------------------------------------------------------------------

/// A validated slot name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeMemorySlotName(pub String);

impl CodeMemorySlotName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_slot_name(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One durable value in a slot. Actor and time are preserved PER VALUE and
/// are never collapsed by a merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemorySlotValue {
    pub payload: CodeMemoryPayloadRef,
    /// Actor entity ref — the value carried by [`WriteActor::entity_ref`].
    /// There is no separate canonical-actor-id vocabulary in this crate.
    pub actor_id: EntityId,
    pub valid_time: TimeRange,
    pub recorded_at: u64,
    /// Actor-scoped dedupe digest. Hashed by the NOTE/L2 owner (or a caller
    /// with authorized read access) BEFORE the body is reduced to an opaque
    /// ref; this module never decodes a payload to recompute it.
    pub content_hash: [u8; CODE_MEMORY_CONTENT_HASH_LEN],
    pub provenance_claim_id: EntityId,
}

impl CodeMemorySlotValue {
    pub fn validate(&self) -> Result<()> {
        validate_time_range(self.valid_time, "slot value valid time")
    }

    /// The dedupe INDEX for this value. Not value identity: two actors
    /// submitting the same bytes produce different keys and stay separate.
    pub fn dedupe_key(&self) -> ActorScopedContentKey {
        ActorScopedContentKey {
            actor_id: self.actor_id,
            content_hash: self.content_hash,
        }
    }

    /// The canonical-minimum total order used to pick the survivor of an
    /// actor-scoped collision: `(recorded_at, valid_time.start,
    /// valid_time.end, provenance_claim_id, payload kind, payload id)`.
    /// Order-independent, so `insert_multi_value` and `merge_union` agree.
    pub fn canonical_min_key(&self) -> (u64, u64, u64, EntityId, u8, EntityId) {
        (
            self.recorded_at,
            self.valid_time.start,
            self.valid_time.end,
            self.provenance_claim_id,
            self.payload.tag(),
            self.payload.entity_id(),
        )
    }

    /// Total order used for the slot's deterministic on-disk ordering.
    pub fn sort_key(
        &self,
    ) -> (
        EntityId,
        [u8; CODE_MEMORY_CONTENT_HASH_LEN],
        u64,
        u64,
        u64,
        EntityId,
        u8,
        EntityId,
    ) {
        let (recorded_at, valid_start, valid_end, provenance, tag, payload) =
            self.canonical_min_key();
        (
            self.actor_id,
            self.content_hash,
            recorded_at,
            valid_start,
            valid_end,
            provenance,
            tag,
            payload,
        )
    }
}

/// Internal dedupe index only. It is NOT value identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ActorScopedContentKey {
    pub actor_id: EntityId,
    pub content_hash: [u8; CODE_MEMORY_CONTENT_HASH_LEN],
}

/// A named multi-value slot on one symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemorySlot {
    pub name: CodeMemorySlotName,
    pub values: Vec<CodeMemorySlotValue>,
    /// DATA, not an error and not an instruction to pick a winner: two or
    /// more live values remain after actor-scoped dedupe.
    pub conflict_visible: bool,
}

/// Outcome of one ordinary slot write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotInsertOutcome {
    Inserted,
    DeduplicatedWithinActor,
}

impl CodeMemorySlot {
    #[must_use]
    pub fn empty(name: CodeMemorySlotName) -> Self {
        Self {
            name,
            values: Vec::new(),
            conflict_visible: false,
        }
    }

    /// Appends or actor-scope-dedupes one value. NEVER replaces the slot.
    ///
    /// `Inserted` appends. `DeduplicatedWithinActor` keeps exactly one
    /// canonical-minimum survivor for the `(actor, content hash)` collision,
    /// replacing the incumbent only when the incoming value is canonically
    /// smaller — so arrival order cannot change the result. Only the encoded
    /// field bound [`CODE_MEMORY_MAX_VALUES_PER_SLOT`] returns the typed
    /// capacity error, leaving `self` untouched; a slot's count is observed
    /// where it is written, never refused.
    pub fn insert_multi_value(&mut self, value: CodeMemorySlotValue) -> Result<SlotInsertOutcome> {
        value.validate()?;
        let key = value.dedupe_key();
        let existing = self
            .values
            .iter()
            .position(|candidate| candidate.dedupe_key() == key);

        let outcome = match existing {
            Some(index) => {
                if value.canonical_min_key() < self.values[index].canonical_min_key() {
                    self.values[index] = value;
                }
                SlotInsertOutcome::DeduplicatedWithinActor
            }
            None => {
                if self.values.len() >= CODE_MEMORY_MAX_VALUES_PER_SLOT {
                    return Err(Error::Code(CodeError::CodeMemoryLimitExceeded {
                        kind: "slot values",
                        limit: CODE_MEMORY_MAX_VALUES_PER_SLOT,
                    }));
                }
                self.values.push(value);
                SlotInsertOutcome::Inserted
            }
        };

        self.normalize();
        Ok(outcome)
    }

    /// Associative, commutative, idempotent union under actor-scoped dedupe.
    ///
    /// Set union first, then canonical-minimum reduction per
    /// `(actor, content hash)`, then a deterministic sort — so insertion
    /// order never participates and `min` composes across any bracketing.
    /// There is no overwrite branch and no last-write-wins fallback.
    pub fn merge_union(&self, other: &Self) -> Result<Self> {
        if self.name != other.name {
            return Err(Error::Code(CodeError::CodeMemoryInvalidAnchor {
                reason: "slot union requires the same slot name on both sides",
            }));
        }

        let mut survivors: BTreeMap<ActorScopedContentKey, CodeMemorySlotValue> = BTreeMap::new();
        for value in self.values.iter().chain(other.values.iter()) {
            value.validate()?;
            match survivors.entry(value.dedupe_key()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(value.clone());
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if value.canonical_min_key() < slot.get().canonical_min_key() {
                        slot.insert(value.clone());
                    }
                }
            }
        }

        if survivors.len() > CODE_MEMORY_MAX_VALUES_PER_SLOT {
            return Err(Error::Code(CodeError::CodeMemoryLimitExceeded {
                kind: "slot values",
                limit: CODE_MEMORY_MAX_VALUES_PER_SLOT,
            }));
        }

        let mut merged = Self {
            name: self.name.clone(),
            values: survivors.into_values().collect(),
            conflict_visible: false,
        };
        merged.normalize();
        Ok(merged)
    }

    /// The payload set present in the written body, in canonical order.
    pub fn payloads(&self) -> Vec<CodeMemoryPayloadRef> {
        let unique: BTreeSet<CodeMemoryPayloadRef> =
            self.values.iter().map(|value| value.payload).collect();
        unique.into_iter().collect()
    }

    /// Provenance of the canonical-minimum value among the surviving values
    /// naming `payload`.
    pub fn provenance_for_payload(&self, payload: CodeMemoryPayloadRef) -> Option<EntityId> {
        self.values
            .iter()
            .filter(|value| value.payload == payload)
            .min_by_key(|value| value.canonical_min_key())
            .map(|value| value.provenance_claim_id)
    }

    pub fn normalize(&mut self) {
        self.values.sort_by_key(CodeMemorySlotValue::sort_key);
        self.conflict_visible = self.values.len() >= 2;
    }
}

/// Input to the only ordinary attachment write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachCodeMemory {
    pub anchor: CodeMemoryAnchor,
    pub slot: CodeMemorySlotName,
    pub value: CodeMemorySlotValue,
}

/// Between two distinct symbols, Rename re-points and Copy clones. A file
/// rename needs neither: its symbols keep their document-based ids and
/// their notes (FIX 7810).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorTransferKind {
    Rename,
    Copy,
}

impl AnchorTransferKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Rename => TRANSFER_TAG_RENAME,
            Self::Copy => TRANSFER_TAG_COPY,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            TRANSFER_TAG_RENAME => Ok(Self::Rename),
            TRANSFER_TAG_COPY => Ok(Self::Copy),
            _ => Err(record_error()),
        }
    }
}

/// An EXPLICIT, already-reviewed rename/copy mapping. Path or fingerprint
/// resemblance never produces one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTransfer {
    pub kind: AnchorTransferKind,
    pub from_symbol_id: EntityId,
    pub to_symbol_id: EntityId,
    pub from_locator: CodeMemoryLocator,
    pub to_locator: CodeMemoryLocator,
    pub actor_id: EntityId,
    pub observed_at: u64,
    pub provenance_claim_id: EntityId,
}

/// What one applied transfer moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorTransferReceipt {
    /// Source slot-value cardinality measured BEFORE destination merge. A
    /// fully deduped transfer is legal and still reports a nonzero count.
    /// A legal CONTRACT-ONLY transfer reports zero: the count measures slot
    /// values, and always-on rows are a separate family.
    pub moved_attachments: usize,
}

/// Decoded, queryable transfer history. Raw metadata keys never cross the
/// public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTransferRecord {
    pub kind: AnchorTransferKind,
    pub from_symbol_id: EntityId,
    pub to_symbol_id: EntityId,
    pub from_locator: CodeMemoryLocator,
    pub to_locator: CodeMemoryLocator,
    pub actor_id: EntityId,
    pub observed_at: u64,
    pub provenance_claim_id: EntityId,
    pub moved_attachments: usize,
}

/// Authority context for the dedicated readiness-edge doors.
///
/// Deliberately built from the LIVE vocabulary — [`WriteActor`] for actor
/// identity/class and [`ClaimSource`] for host-stamped source trust. The
/// caller supplies no raw allow/deny boolean and no parallel trust enum.
#[derive(Debug, Clone, Copy)]
pub struct BlocksWriteContext<'a> {
    pub actor: &'a WriteActor,
    pub source: ClaimSource,
}

/// The bounded always-on subset: interface and policy contracts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMemoryContractKind {
    Interface,
    Policy,
}

impl CodeMemoryContractKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Interface => CONTRACT_TAG_INTERFACE,
            Self::Policy => CONTRACT_TAG_POLICY,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            CONTRACT_TAG_INTERFACE => Ok(Self::Interface),
            CONTRACT_TAG_POLICY => Ok(Self::Policy),
            _ => Err(record_error()),
        }
    }
}

/// One registered always-on interface/policy contract.
///
/// Always-on status is ATTACHMENT METADATA, not a NOTE payload field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlwaysOnCodeMemoryContract {
    pub symbol_id: EntityId,
    pub slot: CodeMemorySlotName,
    pub payload: CodeMemoryPayloadRef,
    pub kind: CodeMemoryContractKind,
    pub actor_id: EntityId,
    pub valid_time: TimeRange,
    pub recorded_at: u64,
    pub provenance_claim_id: EntityId,
}

/// What an L2 pull returns is DATA. There is deliberately no instruction or
/// executable material kind in this enum, and none may be added: an L2 note
/// is context a caller reasons about, never a command it obeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceMaterialKind {
    Data,
}

/// The provenance label carried by every pulled item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryProvenance {
    pub actor_id: EntityId,
    pub valid_time: TimeRange,
    pub recorded_at: u64,
    pub provenance_claim_id: EntityId,
}

/// A pulled item and its label. There is no unlabelled read surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceLabelled<T> {
    pub data: T,
    pub provenance: CodeMemoryProvenance,
    pub material_kind: ProvenanceMaterialKind,
}

/// An L2 pull request. PULL, never push: nothing in this module calls back
/// into a caller with memory it did not ask for.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeMemoryPullRequest {
    /// UNSCORED `CODE_SYMBOL` ids. PPR assigns relevance; callers do not.
    pub seed_symbols: Vec<EntityId>,
    /// Threshold on the inherited symbol relevance — the score type carried
    /// by `pipeline::ScoredEntity`.
    pub minimum_relevance: f32,
    /// Caller cut, applied EXACTLY ONCE and only to the note list.
    pub limit: usize,
    pub include_always_on_contracts: bool,
}

impl CodeMemoryPullRequest {
    /// A request over `seed_symbols` with the default note limit and no
    /// relevance floor.
    pub fn new(seed_symbols: Vec<EntityId>) -> Self {
        Self {
            seed_symbols,
            minimum_relevance: 0.0,
            limit: CODE_MEMORY_DEFAULT_PULL_LIMIT,
            include_always_on_contracts: true,
        }
    }
}

include!("codec.rs");
