//! ARCH-0050 R6 L2 memory-over-code attachment mechanics (ONE-1608).
//!
//! Five cohesive sections, in this order:
//!
//! 1. dual-anchor and opaque-note reference types;
//! 2. multi-writer slot types and union/dedupe logic;
//! 3. explicit anchor-transfer persistence;
//! 4. [`EdgeKind::Blocks`] validation and traversal policy;
//! 5. `ScopedRead`-clamped pull.
//!
//! The load-bearing rules, all enforced here:
//!
//! * IDENTITY IS THE SYMBOL. A durable note is keyed by a `CODE_SYMBOL`
//!   entity id. `path_at_revision`, commit/fork hash, and the validity
//!   interval are a revision LOCATOR — history and display, never identity.
//!   There is deliberately no `find_attachment_by_path`, no `attach_to_path`,
//!   and no path-derived key: path resemblance can never move an attachment.
//! * TRANSFER IS EXPLICIT. Rename re-points and Copy clones, but only through
//!   an [`AnchorTransfer`] a caller has already reviewed. Nothing in this
//!   module infers a target from a path or a fingerprint.
//! * SLOTS ARE MULTI-WRITER. Every value keeps its own actor and time. The
//!   content hash is an ACTOR-SCOPED dedupe index, never value identity, so
//!   two actors writing byte-identical content stay two values with conflict
//!   visible. Merge is a canonical-minimum union: associative, commutative,
//!   idempotent, and with NO last-write-wins path anywhere.
//! * READINESS EDGES ARE GATED. [`EdgeKind::Blocks`] (u8 24) is closed,
//!   authority-gated, `CODE_SYMBOL`-typed on BOTH endpoints, acyclic,
//!   non-decaying, never traversed by PPR, and local-only. Both generic
//!   public edge doors reject it.
//! * PULL, NOT PUSH. L2 reads are `ScopedRead`-clamped and return
//!   provenance-labelled DATA. There is no unlabelled read surface, no
//!   instruction material kind, and no injection callback.
//!
//! STORAGE. Everything rides namespaced `vault_meta` key-prefix row families,
//! the pattern documented in `store/short_id_alias.rs`: no new LMDB database,
//! no `Store` field, no storage-ABI change. NOTE/L2 payload bodies stay
//! opaque — this module stores refs and hashes and decodes neither.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use heed::{RoTxn, RwTxn};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimSource, ScopedRead};
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CodebaseForkHash};
use crate::edge::{EdgeActorClass, EdgeKind, encode_edge_value};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::ppr::{self, SeedWeighting, ppr_query_scoped_in_txn};
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_NOTE};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Section 1 — dual anchor: symbol identity plus revision locator
// ---------------------------------------------------------------------------

/// Width of the actor-scoped dedupe digest (SHA-256, matching the
/// code-symbol module's digest convention).
pub const CODE_MEMORY_CONTENT_HASH_LEN: usize = 32;

/// Maximum encoded slot-name length.
pub const CODE_MEMORY_SLOT_NAME_MAX_BYTES: usize = 128;

/// Maximum live values retained in one named slot. The 257th DISTINCT value
/// is a typed capacity error that leaves the stored slot byte-identical.
pub const CODE_MEMORY_MAX_VALUES_PER_SLOT: usize = 256;

/// Registration-side bound on distinct `(symbol, slot, payload)` always-on
/// contract keys PER SYMBOL. Pull imposes no second, global cut.
pub const CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS: usize = 8;

/// PPR expansion depth for an L2 pull.
///
/// Alpha `0.15` and [`SeedWeighting::Specificity`] are copied verbatim from
/// the landed code-symbol PPR entry; depth is fixed HERE because that entry
/// parameterizes it and its sole landed caller supplies `2`. There is
/// deliberately no request-level tuning knob.
pub const CODE_MEMORY_PPR_DEPTH: u32 = 2;

/// Restart probability for an L2 pull, copied from the landed code-symbol
/// PPR entry.
const CODE_MEMORY_PPR_ALPHA: f32 = 0.15;

/// Default caller note limit.
pub const CODE_MEMORY_DEFAULT_PULL_LIMIT: usize = 32;

/// Hard ceiling on the caller note limit, on seed cardinality, and on the
/// number of threshold-passing symbols an L2 pull will expand.
pub const CODE_MEMORY_MAX_PULL_LIMIT: usize = 256;

const ATTACHMENT_KEY_PREFIX: &[u8] = b"code_memory:attachment:v1:";
const SLOT_KEY_PREFIX: &[u8] = b"code_memory:slot:v1:";
const TRANSFER_KEY_PREFIX: &[u8] = b"code_memory:transfer:v1:";
const ALWAYS_ON_KEY_PREFIX: &[u8] = b"code_memory:always_on:v1:";

/// Record version leading every encoded body in this module.
const CODE_MEMORY_RECORD_VERSION: u8 = 1;

/// NUL separator between variable-width key segments. Slot names reject
/// control characters, so this byte can never occur inside one.
const KEY_SEPARATOR: u8 = 0;

const PAYLOAD_TAG_NOTE_ENTITY: u8 = 0;
const PAYLOAD_TAG_CLAIM: u8 = 1;

const REVISION_TAG_COMMIT: u8 = 0;
const REVISION_TAG_FORK_HASH: u8 = 1;

const TRANSFER_TAG_RENAME: u8 = 0;
const TRANSFER_TAG_COPY: u8 = 1;

const CONTRACT_TAG_INTERFACE: u8 = 0;
const CONTRACT_TAG_POLICY: u8 = 1;

const COMMIT_HASH_MAX_HEX_LEN: usize = 64;

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

    const fn tag(self) -> u8 {
        match self {
            Self::NoteEntity(_) => PAYLOAD_TAG_NOTE_ENTITY,
            Self::Claim(_) => PAYLOAD_TAG_CLAIM,
        }
    }

    fn from_tag(tag: u8, id: EntityId) -> Result<Self> {
        match tag {
            PAYLOAD_TAG_NOTE_ENTITY => Ok(Self::NoteEntity(id)),
            PAYLOAD_TAG_CLAIM => Ok(Self::Claim(id)),
            _ => Err(record_error()),
        }
    }
}

/// The revision half of a locator: exactly one commit OR one fork hash,
/// never neither and never both.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeMemoryRevision {
    /// Lowercase-hex commit hash, mirroring the `commit_hash: Option<String>`
    /// representation the code-symbol/codebase modules already carry.
    Commit(String),
    /// A filtered-snapshot fork hash (`codebase::CodebaseForkHash`).
    ForkHash(CodebaseForkHash),
}

impl CodeMemoryRevision {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Commit(commit) => {
                if commit.is_empty()
                    || commit.len() > COMMIT_HASH_MAX_HEX_LEN
                    || !commit
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err(Error::CodeMemoryInvalidAnchor {
                        reason: "locator commit must be non-empty lowercase hexadecimal",
                    });
                }
                Ok(())
            }
            Self::ForkHash(_) => Ok(()),
        }
    }
}

/// Revision locator for an attachment. LOCATOR ONLY — no API in this module
/// resolves attachment identity from any of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryLocator {
    pub path_at_revision: String,
    pub revision: CodeMemoryRevision,
    pub validity: TimeRange,
}

impl CodeMemoryLocator {
    /// Validates the locator's own bounded structure. Deliberately does NOT
    /// check that the locator "belongs to" a symbol: locators are
    /// caller-asserted values, never identity.
    pub fn validate(&self) -> Result<()> {
        validate_locator_path(&self.path_at_revision)?;
        self.revision.validate()?;
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
pub struct CodeMemorySlotName(String);

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
    fn validate(&self) -> Result<()> {
        validate_time_range(self.valid_time, "slot value valid time")
    }

    /// The dedupe INDEX for this value. Not value identity: two actors
    /// submitting the same bytes produce different keys and stay separate.
    fn dedupe_key(&self) -> ActorScopedContentKey {
        ActorScopedContentKey {
            actor_id: self.actor_id,
            content_hash: self.content_hash,
        }
    }

    /// The canonical-minimum total order used to pick the survivor of an
    /// actor-scoped collision: `(recorded_at, valid_time.start,
    /// valid_time.end, provenance_claim_id, payload kind, payload id)`.
    /// Order-independent, so `insert_multi_value` and `merge_union` agree.
    fn canonical_min_key(&self) -> (u64, u64, u64, EntityId, u8, EntityId) {
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
    fn sort_key(
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
    actor_id: EntityId,
    content_hash: [u8; CODE_MEMORY_CONTENT_HASH_LEN],
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
    /// smaller — so arrival order cannot change the result. Hitting
    /// [`CODE_MEMORY_MAX_VALUES_PER_SLOT`] returns the typed capacity error
    /// and leaves `self` untouched.
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
                    return Err(Error::CodeMemoryLimitExceeded {
                        kind: "slot values",
                        limit: CODE_MEMORY_MAX_VALUES_PER_SLOT,
                    });
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
            return Err(Error::CodeMemoryInvalidAnchor {
                reason: "slot union requires the same slot name on both sides",
            });
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
            return Err(Error::CodeMemoryLimitExceeded {
                kind: "slot values",
                limit: CODE_MEMORY_MAX_VALUES_PER_SLOT,
            });
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
    fn payloads(&self) -> Vec<CodeMemoryPayloadRef> {
        let unique: BTreeSet<CodeMemoryPayloadRef> =
            self.values.iter().map(|value| value.payload).collect();
        unique.into_iter().collect()
    }

    /// Provenance of the canonical-minimum value among the surviving values
    /// naming `payload`.
    fn provenance_for_payload(&self, payload: CodeMemoryPayloadRef) -> Option<EntityId> {
        self.values
            .iter()
            .filter(|value| value.payload == payload)
            .min_by_key(|value| value.canonical_min_key())
            .map(|value| value.provenance_claim_id)
    }

    fn normalize(&mut self) {
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

/// The only ordinary attachment write: it appends/merges, never replaces.
///
/// Validates the symbol anchor and locator, loads the named slot, applies
/// [`CodeMemorySlot::insert_multi_value`], then rewrites the slot body AND
/// re-derives the `(symbol, slot)` attachment-index rows FROM THE WRITTEN
/// BODY — so a payload that loses the actor-scoped dedupe never receives an
/// index row. All in the caller's one transaction.
///
/// The anchor's locator labels ONLY the payloads this attach introduces. A
/// payload already carrying an attachment row keeps the locator it was first
/// attached under: a later write into the same slot is not a relabelling of
/// the material already there.
pub fn attach_code_memory(
    store: &Store,
    txn: &mut RwTxn<'_>,
    input: AttachCodeMemory,
) -> Result<SlotInsertOutcome> {
    let AttachCodeMemory {
        anchor,
        slot: slot_name,
        value,
    } = input;
    validate_code_symbol_anchor(store, txn, &anchor.symbol_id)?;
    anchor.locator.validate()?;
    value.validate()?;

    let mut slot = read_slot(store, txn, &anchor.symbol_id, &slot_name)?
        .unwrap_or_else(|| CodeMemorySlot::empty(slot_name));
    let outcome = slot.insert_multi_value(value)?;

    write_slot(store, txn, &anchor.symbol_id, &slot)?;
    // Nothing is relabelled by an attach: a payload without a row is new and
    // takes this anchor's locator, and every other payload keeps its own.
    derive_attachment_rows(
        store,
        txn,
        &anchor.symbol_id,
        &slot,
        &anchor.locator,
        &BTreeSet::new(),
    )?;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Section 3 — explicit rename/copy anchor transfer
// ---------------------------------------------------------------------------

/// Rename re-points; Copy clones. Nothing else transfers an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorTransferKind {
    Rename,
    Copy,
}

impl AnchorTransferKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Rename => TRANSFER_TAG_RENAME,
            Self::Copy => TRANSFER_TAG_COPY,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
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

/// Applies one explicit anchor transfer in the caller's single transaction.
///
/// Order is fixed: validate both endpoints as live, distinct `CODE_SYMBOL`
/// entities; validate each locator's own bounded structure (never that a
/// locator "belongs to" a symbol); load source slots/always-on rows BY
/// SYMBOL ID and never by path; plan every destination merge and bound check
/// BEFORE any durable write; write destination state; upsert the
/// deterministic receipt; and only then, for `Rename`, retire the source
/// rows. `Copy` leaves the source untouched.
///
/// EITHER FAMILY QUALIFIES. Slot values and always-on contracts are moved
/// independently, so a symbol carrying only standalone contracts transfers
/// normally; only a source with neither is the typed refusal.
///
/// NOTHING AT THE DESTINATION IS OVERWRITTEN. Colliding slot values resolve
/// through `merge_union`, a colliding `(symbol, slot, payload)` contract
/// leaves the destination row exactly as registered, and destination-only
/// payloads keep their own attachment locators.
pub fn transfer_code_memory_anchor(
    store: &Store,
    txn: &mut RwTxn<'_>,
    transfer: &AnchorTransfer,
) -> Result<AnchorTransferReceipt> {
    if transfer.from_symbol_id == transfer.to_symbol_id {
        return Err(Error::CodeMemoryInvalidAnchorTransfer {
            from: transfer.from_symbol_id,
            to: transfer.to_symbol_id,
            reason: "transfer endpoints must be distinct symbols",
        });
    }
    for symbol in [&transfer.from_symbol_id, &transfer.to_symbol_id] {
        if entity_type_in_txn(store, txn, symbol)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchorTransfer {
                from: transfer.from_symbol_id,
                to: transfer.to_symbol_id,
                reason: "both transfer endpoints must be live CODE_SYMBOL entities",
            });
        }
    }
    transfer.from_locator.validate()?;
    transfer.to_locator.validate()?;

    // Step 3 — load by symbol id. `moved_attachments` is the SOURCE slot-value
    // cardinality measured here, before any destination merge, so the count
    // never depends on post-merge origin reconstruction.
    let source_slots = read_slots_for_symbol(store, txn, &transfer.from_symbol_id)?;
    let source_contracts = read_always_on_for_symbol(store, txn, &transfer.from_symbol_id)?;
    let moved_attachments: usize = source_slots.iter().map(|slot| slot.values.len()).sum();
    // A symbol carrying ONLY standalone always-on contracts is a legal
    // registration (`register_always_on_contract` never requires a slot
    // value), so it must be transferable too. The refusal is reserved for a
    // source that carries NOTHING on either family.
    if moved_attachments == 0 && source_contracts.is_empty() {
        return Err(Error::CodeMemoryInvalidAnchorTransfer {
            from: transfer.from_symbol_id,
            to: transfer.to_symbol_id,
            reason: "source symbol carries no slot value or always-on contract to transfer",
        });
    }

    // Step 4 — plan every destination write, enforcing both bounds before a
    // single durable byte moves. Each plan carries the payload set that
    // ORIGINATES IN THE SOURCE: those payloads, and only those, take this
    // transfer's `to_locator` at the destination.
    let mut planned_slots = Vec::with_capacity(source_slots.len());
    for source_slot in &source_slots {
        let destination = read_slot(store, txn, &transfer.to_symbol_id, &source_slot.name)?
            .unwrap_or_else(|| CodeMemorySlot::empty(source_slot.name.clone()));
        let moved_payloads: BTreeSet<CodeMemoryPayloadRef> =
            source_slot.payloads().into_iter().collect();
        planned_slots.push((destination.merge_union(source_slot)?, moved_payloads));
    }

    let planned_contracts =
        plan_transferred_contracts(store, txn, &transfer.to_symbol_id, &source_contracts)?;

    // Step 5 — destination rows are derived from the MERGED contents, never
    // from the incoming source stream.
    for (slot, moved_payloads) in &planned_slots {
        write_slot(store, txn, &transfer.to_symbol_id, slot)?;
        derive_attachment_rows(
            store,
            txn,
            &transfer.to_symbol_id,
            slot,
            &transfer.to_locator,
            moved_payloads,
        )?;
    }
    for contract in &planned_contracts {
        write_always_on(store, txn, contract)?;
    }

    // Step 6 — deterministic receipt. A byte-identical replay upserts its own
    // key; distinct transfers cannot collide.
    let record = AnchorTransferRecord {
        kind: transfer.kind,
        from_symbol_id: transfer.from_symbol_id,
        to_symbol_id: transfer.to_symbol_id,
        from_locator: transfer.from_locator.clone(),
        to_locator: transfer.to_locator.clone(),
        actor_id: transfer.actor_id,
        observed_at: transfer.observed_at,
        provenance_claim_id: transfer.provenance_claim_id,
        moved_attachments,
    };
    store.vault_meta.put(
        txn,
        &transfer_key(transfer),
        &encode_transfer_record(&record),
    )?;

    // Step 7 — Rename retires the source only after every target write and the
    // receipt succeeded. Copy leaves the source completely intact.
    if transfer.kind == AnchorTransferKind::Rename {
        delete_prefix(
            store,
            txn,
            &attachment_symbol_prefix(&transfer.from_symbol_id),
        )?;
        delete_prefix(store, txn, &slot_symbol_prefix(&transfer.from_symbol_id))?;
        delete_prefix(
            store,
            txn,
            &always_on_symbol_prefix(&transfer.from_symbol_id),
        )?;
    }

    Ok(AnchorTransferReceipt { moved_attachments })
}

/// Plans the destination always-on writes of one transfer. Read-only: it
/// decides what may be written and never writes.
///
/// A source contract whose `(symbol, slot, payload)` key ALREADY exists at
/// the destination is dropped from the plan. Contract collisions resolve
/// exactly like slot collisions do: the destination registration stands, its
/// kind/actor/time/provenance are never overwritten with the source's, and
/// there is no last-writer-wins path. The per-symbol bound therefore counts
/// only the keys this transfer genuinely adds.
fn plan_transferred_contracts(
    store: &Store,
    txn: &RoTxn<'_>,
    to_symbol_id: &EntityId,
    source_contracts: &[AlwaysOnCodeMemoryContract],
) -> Result<Vec<AlwaysOnCodeMemoryContract>> {
    let registered = read_always_on_for_symbol(store, txn, to_symbol_id)?;
    let mut keys: HashSet<Vec<u8>> = registered
        .into_iter()
        .map(|contract| always_on_key(to_symbol_id, &contract.slot, contract.payload))
        .collect();
    let mut planned = Vec::with_capacity(source_contracts.len());
    for contract in source_contracts {
        let mut moved = contract.clone();
        moved.symbol_id = *to_symbol_id;
        if !keys.insert(always_on_key(to_symbol_id, &moved.slot, moved.payload)) {
            continue;
        }
        if keys.len() > CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
            return Err(Error::CodeMemoryLimitExceeded {
                kind: "always-on contracts per symbol",
                limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS,
            });
        }
        planned.push(moved);
    }
    Ok(planned)
}

/// Decoded transfer history touching `of` on either endpoint.
pub(crate) fn read_transfer_records(
    store: &Store,
    txn: &RoTxn<'_>,
    of: &EntityId,
) -> Result<Vec<AnchorTransferRecord>> {
    let mut records = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, TRANSFER_KEY_PREFIX)? {
        let (_, value) = entry?;
        let record = decode_transfer_record(&value)?;
        if record.from_symbol_id == *of || record.to_symbol_id == *of {
            records.push(record);
        }
    }
    records.sort_by_key(|record| {
        (
            record.observed_at,
            record.from_symbol_id,
            record.to_symbol_id,
            record.kind.tag(),
        )
    });
    Ok(records)
}

// ---------------------------------------------------------------------------
// Section 4 — `EdgeKind::Blocks`: closed, gated, acyclic, durable, non-PPR
// ---------------------------------------------------------------------------

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

/// Binds the asserted actor class to the STORED actor entity type and clears
/// the host-stamped source, mirroring
/// `claim::put::validate_code_run_write_actor_binding_in_txn`.
///
/// Allowed iff the validated class is `Human` or `Agent` AND
/// `!source.requires_explicit_auto_permit()`. An unresolvable actor or a
/// forged class is the typed actor denial; a `System` actor is refused even
/// when it resolves cleanly.
fn authorize_blocks_write(
    store: &Store,
    txn: &RoTxn<'_>,
    context: BlocksWriteContext<'_>,
) -> Result<()> {
    let actor_type = entity_type_in_txn(store, txn, &context.actor.entity_ref())?.ok_or(
        Error::CodeMemoryBlocksActorDenied("write actor entity does not resolve"),
    )?;
    validate_actor_class(actor_type, context.actor.actor_class()).map_err(|_| {
        Error::CodeMemoryBlocksActorDenied(
            "asserted actor class is not bound to the actor entity type",
        )
    })?;
    if context.actor.actor_class() == EdgeActorClass::System {
        return Err(Error::CodeMemoryBlocksActorDenied(
            "readiness dependencies are a Human/Agent judgement",
        ));
    }
    if context.source.requires_explicit_auto_permit() {
        return Err(Error::CodeMemoryBlocksSourceUntrusted {
            source_kind: context.source.as_str(),
        });
    }
    Ok(())
}

/// Is `target` reachable from `start` over `Blocks` edges ONLY?
///
/// Kind-local by construction: the walk rides the landed kind-filtered,
/// cap-bounded peer scan, so a `child_of` / `derived_from` path between the
/// same endpoints can never fabricate a readiness cycle. Overflow is the
/// typed [`Error::IndexOverflow`], never a partial acyclicity proof.
pub(crate) fn blocks_path_exists(
    vault: &Vault,
    txn: &RoTxn<'_>,
    start: EntityId,
    target: EntityId,
) -> Result<bool> {
    let mut visited: HashSet<EntityId> = HashSet::from([start]);
    let mut frontier: VecDeque<EntityId> = VecDeque::from([start]);
    let mut traversed_steps = 0usize;

    while let Some(current) = frontier.pop_front() {
        let peers = vault.filtered_edge_peers(
            txn,
            &vault.store.edges_out,
            &current,
            EdgeKind::Blocks,
            None,
            "blocks readiness walk",
        )?;
        for peer in peers {
            if traversed_steps >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("blocks readiness walk"));
            }
            traversed_steps += 1;
            if peer == target {
                return Ok(true);
            }
            if visited.insert(peer) {
                frontier.push_back(peer);
            }
        }
    }

    Ok(false)
}

/// The ONLY `blocks` write door.
///
/// `from` blocks `to`. Authority, ENDPOINT TYPING, the acyclicity proof, both
/// index mutations, PPR invalidation, and the graph-version increment all
/// share the caller's ONE `RwTxn` — no `BatchBuilder` (which owns its own
/// commit) and no generic public edge door is involved.
///
/// Endpoints are typed the same way attach, transfer, and pull type theirs:
/// both must resolve to a LIVE `CODE_SYMBOL`. Readiness is a judgement about
/// code, so a ghost id or a live entity of any other type is the typed anchor
/// refusal and never a persisted edge.
pub(crate) fn insert_blocks_edge(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    from: EntityId,
    to: EntityId,
    context: BlocksWriteContext<'_>,
) -> Result<()> {
    authorize_blocks_write(&vault.store, txn, context)?;
    if from == to {
        return Err(Error::CodeMemoryBlocksCycle { from, to });
    }
    for endpoint in [&from, &to] {
        if entity_type_in_txn(&vault.store, txn, endpoint)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchor {
                reason: "readiness edge endpoints must be live CODE_SYMBOL entities",
            });
        }
    }
    if blocks_path_exists(vault, txn, to, from)? {
        return Err(Error::CodeMemoryBlocksCycle { from, to });
    }

    let weight = EdgeKind::Blocks
        .default_weight()
        .expect("Blocks has a canonical structural weight");
    let value = encode_edge_value(
        EdgeKind::Blocks,
        weight,
        crate::unix_seconds_now(),
        Vad::NEUTRAL,
        None,
    )?;
    // Identical bytes into both directions, mirroring `batch::edge_apply`.
    let key_out = Store::encode_edge_key(&from, EdgeKind::Blocks, &to);
    let key_in = Store::encode_edge_key(&to, EdgeKind::Blocks, &from);
    vault.store.edges_out.put(txn, &key_out, &value)?;
    vault.store.edges_in.put(txn, &key_in, &value)?;

    ppr::invalidate_ppr_for_edge(&vault.store, txn, &from, &to)?;
    ppr::increment_graph_version(&vault.store, txn)?;
    Ok(())
}

/// The ONLY `blocks` retirement door. Same authority steps, both index rows
/// deleted, same in-transaction side effects. Generic `Vault::delete_edge`
/// stays reserved-rejecting for this kind.
pub(crate) fn remove_blocks_edge(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    from: EntityId,
    to: EntityId,
    context: BlocksWriteContext<'_>,
) -> Result<bool> {
    authorize_blocks_write(&vault.store, txn, context)?;
    let key_out = Store::encode_edge_key(&from, EdgeKind::Blocks, &to);
    let key_in = Store::encode_edge_key(&to, EdgeKind::Blocks, &from);
    let existed_out = vault.store.edges_out.delete(txn, &key_out)?;
    let deleted_in = vault.store.edges_in.delete(txn, &key_in)?;
    if !existed_out {
        let _ = deleted_in;
        return Ok(false);
    }
    ppr::invalidate_ppr_for_edge(&vault.store, txn, &from, &to)?;
    ppr::increment_graph_version(&vault.store, txn)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Section 5 — pull read: ScopedRead clamp plus provenance-labelled DATA
// ---------------------------------------------------------------------------

/// The bounded always-on subset: interface and policy contracts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMemoryContractKind {
    Interface,
    Policy,
}

impl CodeMemoryContractKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Interface => CONTRACT_TAG_INTERFACE,
            Self::Policy => CONTRACT_TAG_POLICY,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
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

/// Provenance-labelled DATA returned by an L2 pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryPullResult {
    pub notes: Vec<ProvenanceLabelled<CodeMemorySlotValue>>,
    pub always_on_contracts: Vec<ProvenanceLabelled<AlwaysOnCodeMemoryContract>>,
}

/// ScopedRead-clamped L2 pull.
///
/// Read order is fixed and load-bearing:
///
/// 1. validate seeds / threshold / limit;
/// 2. ONE `RoTxn`: seeds must be live `CODE_SYMBOL`s, then the ACTOR-SCOPED,
///    compute-only PPR entry at [`CODE_MEMORY_PPR_DEPTH`], alpha `0.15`,
///    [`SeedWeighting::Specificity`] (`lambda_for_kind(Blocks) == None` keeps
///    readiness edges out of the walk). SCOPE BEFORE MASS: this `ScopedRead`
///    is the walk's node-visibility gate, so a seed the actor cannot read
///    carries no seed mass and no hop is taken through a node it cannot read
///    — a permitted symbol reachable only across a denied CLAIM bridge is
///    unreachable, in either edge direction, rather than merely unlabelled.
///    Clamping payloads after an unscoped ranking could not achieve that: the
///    mass had already crossed, so both membership and ORDER encoded graph
///    structure the actor may not see. Being compute-only is part of the same
///    boundary — the shared `ppr_cache` carries no actor, so this walk neither
///    reads nor writes it, and takes no dependency or graph-version write;
/// 3. keep every scored `CODE_SYMBOL` at or above `minimum_relevance` — the
///    caller's note limit is NOT applied to symbols;
/// 4. resolve slots and always-on registrations for those symbols in the same
///    transaction;
/// 5. `drop(rtxn)` BEFORE any [`ScopedRead::get_entity_parts`] call, which
///    opens its own read transaction (nested read transactions on one thread
///    are forbidden), and clamp every referenced entity. The walk gate above
///    admits the SYMBOLS a ranking may traverse; this clamp still decides each
///    PAYLOAD, and stays as defence in depth for both;
/// 6. sort surviving notes by descending inherited relevance then canonical
///    keys, and apply the caller limit exactly once, here;
/// 7. label everything `Data`.
pub fn pull_code_memory(
    vault: &Vault,
    scoped_read: &ScopedRead<'_>,
    request: CodeMemoryPullRequest,
) -> Result<CodeMemoryPullResult> {
    if request.seed_symbols.is_empty() {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "pull requires at least one CODE_SYMBOL seed",
        });
    }
    if request.seed_symbols.len() > CODE_MEMORY_MAX_PULL_LIMIT {
        return Err(Error::CodeMemoryLimitExceeded {
            kind: "pull seed symbols",
            limit: CODE_MEMORY_MAX_PULL_LIMIT,
        });
    }
    if !request.minimum_relevance.is_finite() || request.minimum_relevance < 0.0 {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "pull minimum relevance must be a finite non-negative score",
        });
    }
    if request.limit == 0 || request.limit > CODE_MEMORY_MAX_PULL_LIMIT {
        return Err(Error::CodeMemoryLimitExceeded {
            kind: "pull note limit",
            limit: CODE_MEMORY_MAX_PULL_LIMIT,
        });
    }

    let rtxn = vault.store.env.read_txn()?;
    for seed in &request.seed_symbols {
        if entity_type_in_txn(&vault.store, &rtxn, seed)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchor {
                reason: "every pull seed must be a live CODE_SYMBOL entity",
            });
        }
    }

    let scores = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &request.seed_symbols,
        CODE_MEMORY_PPR_DEPTH,
        CODE_MEMORY_PPR_ALPHA,
        SeedWeighting::Specificity,
        scoped_read,
    )?;

    let mut retained: Vec<ScoredEntity> = Vec::new();
    for score in scores {
        if retained.len() == CODE_MEMORY_MAX_PULL_LIMIT {
            break;
        }
        if score.score < request.minimum_relevance {
            continue;
        }
        if entity_type_in_txn(&vault.store, &rtxn, &score.id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
            retained.push(score);
        }
    }

    let mut candidate_notes: Vec<(f32, EntityId, CodeMemorySlotName, CodeMemorySlotValue)> =
        Vec::new();
    let mut candidate_contracts: Vec<AlwaysOnCodeMemoryContract> = Vec::new();
    for scored in &retained {
        for slot in read_slots_for_symbol(&vault.store, &rtxn, &scored.id)? {
            for value in slot.values {
                candidate_notes.push((scored.score, scored.id, slot.name.clone(), value));
            }
        }
        if request.include_always_on_contracts {
            candidate_contracts.extend(read_always_on_for_symbol(&vault.store, &rtxn, &scored.id)?);
        }
    }

    // The clamp opens its OWN read transaction; the outer one must be gone
    // first (landed short-lived-txn pattern, `code_symbol::code_symbol_ppr_neighbors`).
    drop(rtxn);

    let mut permitted_notes = Vec::new();
    for (score, symbol_id, slot_name, value) in candidate_notes {
        if scoped_read
            .get_entity_parts(&value.payload.entity_id())?
            .is_none()
        {
            continue;
        }
        permitted_notes.push((score, symbol_id, slot_name, value));
    }

    permitted_notes.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.sort_key().cmp(&right.3.sort_key()))
    });
    permitted_notes.truncate(request.limit);

    let notes = permitted_notes
        .into_iter()
        .map(|(_, _, _, value)| ProvenanceLabelled {
            provenance: CodeMemoryProvenance {
                actor_id: value.actor_id,
                valid_time: value.valid_time,
                recorded_at: value.recorded_at,
                provenance_claim_id: value.provenance_claim_id,
            },
            data: value,
            material_kind: ProvenanceMaterialKind::Data,
        })
        .collect();

    let mut always_on_contracts = Vec::new();
    if request.include_always_on_contracts {
        candidate_contracts.sort_by(|left, right| {
            (left.symbol_id, &left.slot, left.payload).cmp(&(
                right.symbol_id,
                &right.slot,
                right.payload,
            ))
        });
        for contract in candidate_contracts {
            if scoped_read
                .get_entity_parts(&contract.payload.entity_id())?
                .is_none()
            {
                continue;
            }
            always_on_contracts.push(ProvenanceLabelled {
                provenance: CodeMemoryProvenance {
                    actor_id: contract.actor_id,
                    valid_time: contract.valid_time,
                    recorded_at: contract.recorded_at,
                    provenance_claim_id: contract.provenance_claim_id,
                },
                data: contract,
                material_kind: ProvenanceMaterialKind::Data,
            });
        }
    }

    Ok(CodeMemoryPullResult {
        notes,
        always_on_contracts,
    })
}

/// Registers one always-on interface/policy contract.
///
/// Accepts ONLY a [`CodeMemoryPayloadRef::NoteEntity`] that resolves live to
/// `ENTITY_TYPE_NOTE` on a live `CODE_SYMBOL` anchor, under the per-symbol
/// bound of [`CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS`] distinct
/// `(symbol, slot, payload)` keys. Re-registering an existing key is an
/// idempotent upsert that does not consume a fresh slot.
///
/// POSITIVE NOTE TYPING (ARCH-0032 has landed, `ENTITY_TYPE_NOTE = 106`):
/// docs contracts outrank the blueprint's stale "no NOTE entity type exists
/// in v1" rule, so registration enforces the note type rather than the weaker
/// live-non-CLAIM predicate. The CLAIM clamp inside
/// `ScopedRead::get_entity_parts` is untouched and still governs reads.
pub fn register_always_on_contract(
    store: &Store,
    txn: &mut RwTxn<'_>,
    contract: AlwaysOnCodeMemoryContract,
) -> Result<()> {
    validate_code_symbol_anchor(store, txn, &contract.symbol_id)?;
    validate_time_range(contract.valid_time, "always-on contract valid time")?;
    let CodeMemoryPayloadRef::NoteEntity(note_id) = contract.payload else {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contracts accept only NoteEntity payload refs",
        ));
    };
    let payload_type = entity_type_in_txn(store, txn, &note_id)?;
    if payload_type.is_none() {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contract payload does not resolve to a live entity",
        ));
    }
    if payload_type != Some(ENTITY_TYPE_NOTE) {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contract payload must be a NOTE entity",
        ));
    }

    let key = always_on_key(&contract.symbol_id, &contract.slot, contract.payload);
    if store.vault_meta.get(txn, &key)?.is_none() {
        let registered = count_prefix(store, txn, &always_on_symbol_prefix(&contract.symbol_id))?;
        if registered >= CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
            return Err(Error::CodeMemoryLimitExceeded {
                kind: "always-on contracts per symbol",
                limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS,
            });
        }
    }
    write_always_on(store, txn, &contract)
}

// ---------------------------------------------------------------------------
// Keys, codecs, and row-family helpers (private: raw keys never cross the API)
// ---------------------------------------------------------------------------

fn record_error() -> Error {
    Error::CorruptedIndex("code memory record")
}

fn validate_slot_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > CODE_MEMORY_SLOT_NAME_MAX_BYTES {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "slot name must be non-empty and within the pinned length bound",
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "slot name must be trimmed and free of control characters",
        });
    }
    Ok(())
}

/// Mirrors the live code-symbol manifest path rule: repository-relative,
/// normalized, bounded by `CODEBASE_FILE_PATH_MAX_BYTES`.
fn validate_locator_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > CODEBASE_FILE_PATH_MAX_BYTES
        || path.trim() != path
        || path.chars().any(char::is_control)
    {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be non-empty, trimmed, bounded, and free of control characters",
        });
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be repository-relative",
        });
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be normalized and cannot contain . or .. segments",
        });
    }
    Ok(())
}

fn validate_time_range(range: TimeRange, field: &'static str) -> Result<()> {
    if range.start > range.end {
        return Err(Error::CodeMemoryInvalidAnchor { reason: field });
    }
    Ok(())
}

fn entity_type_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// The symbol anchor is the identity anchor. No path may be supplied in its
/// place, and nothing here derives a symbol from a locator.
fn validate_code_symbol_anchor(store: &Store, txn: &RoTxn<'_>, symbol_id: &EntityId) -> Result<()> {
    if entity_type_in_txn(store, txn, symbol_id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
        return Ok(());
    }
    Err(Error::CodeMemoryInvalidAnchor {
        reason: "code-memory anchors must name a live CODE_SYMBOL entity",
    })
}

fn key_with_symbol(prefix: &[u8], symbol_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN + 1);
    key.extend_from_slice(prefix);
    key.extend_from_slice(symbol_id.as_bytes());
    key.push(KEY_SEPARATOR);
    key
}

fn key_with_slot(prefix: &[u8], symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    let mut key = key_with_symbol(prefix, symbol_id);
    key.extend_from_slice(slot.as_str().as_bytes());
    key
}

fn key_with_payload(
    prefix: &[u8],
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    let mut key = key_with_slot(prefix, symbol_id, slot);
    key.push(KEY_SEPARATOR);
    key.push(payload.tag());
    key.extend_from_slice(payload.entity_id().as_bytes());
    key
}

fn slot_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(SLOT_KEY_PREFIX, symbol_id)
}

fn slot_key(symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    key_with_slot(SLOT_KEY_PREFIX, symbol_id, slot)
}

fn attachment_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(ATTACHMENT_KEY_PREFIX, symbol_id)
}

fn attachment_slot_prefix(symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    let mut key = key_with_slot(ATTACHMENT_KEY_PREFIX, symbol_id, slot);
    key.push(KEY_SEPARATOR);
    key
}

fn attachment_key(
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    key_with_payload(ATTACHMENT_KEY_PREFIX, symbol_id, slot, payload)
}

fn always_on_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(ALWAYS_ON_KEY_PREFIX, symbol_id)
}

fn always_on_key(
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    key_with_payload(ALWAYS_ON_KEY_PREFIX, symbol_id, slot, payload)
}

/// `TRANSFER_KEY_PREFIX + from + to + observed_at_be + sha256(canonical
/// transfer encoding)`: a byte-identical replay is an idempotent upsert of
/// its own key, while distinct transfers cannot collide.
fn transfer_key(transfer: &AnchorTransfer) -> Vec<u8> {
    let mut key = Vec::with_capacity(TRANSFER_KEY_PREFIX.len() + 16 + 16 + 8 + 32);
    key.extend_from_slice(TRANSFER_KEY_PREFIX);
    key.extend_from_slice(transfer.from_symbol_id.as_bytes());
    key.extend_from_slice(transfer.to_symbol_id.as_bytes());
    key.extend_from_slice(&transfer.observed_at.to_be_bytes());
    key.extend_from_slice(&sha256(&encode_transfer_identity(transfer)));
    key
}

fn sha256(bytes: &[u8]) -> [u8; CODE_MEMORY_CONTENT_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    push_u16(out, u16::try_from(text.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(text.as_bytes());
}

fn push_time_range(out: &mut Vec<u8>, range: TimeRange) {
    push_u64(out, range.start);
    push_u64(out, range.end);
}

fn push_payload(out: &mut Vec<u8>, payload: CodeMemoryPayloadRef) {
    out.push(payload.tag());
    out.extend_from_slice(payload.entity_id().as_bytes());
}

fn push_locator(out: &mut Vec<u8>, locator: &CodeMemoryLocator) {
    push_text(out, &locator.path_at_revision);
    match &locator.revision {
        CodeMemoryRevision::Commit(commit) => {
            out.push(REVISION_TAG_COMMIT);
            push_text(out, commit);
        }
        CodeMemoryRevision::ForkHash(fork_hash) => {
            out.push(REVISION_TAG_FORK_HASH);
            out.extend_from_slice(fork_hash);
        }
    }
    push_time_range(out, locator.validity);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(record_error)?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(record_error)?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| record_error())?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| record_error())?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| record_error())?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn entity_id(&mut self) -> Result<EntityId> {
        let bytes: [u8; ENTITY_ID_LEN] = self
            .take(ENTITY_ID_LEN)?
            .try_into()
            .map_err(|_| record_error())?;
        EntityId::from_bytes(bytes).map_err(|_| record_error())
    }

    fn content_hash(&mut self) -> Result<[u8; CODE_MEMORY_CONTENT_HASH_LEN]> {
        self.take(CODE_MEMORY_CONTENT_HASH_LEN)?
            .try_into()
            .map_err(|_| record_error())
    }

    fn text(&mut self, max_bytes: usize) -> Result<String> {
        let len = usize::from(self.u16()?);
        if len > max_bytes {
            return Err(record_error());
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| record_error())
    }

    fn time_range(&mut self) -> Result<TimeRange> {
        let start = self.u64()?;
        let end = self.u64()?;
        if start > end {
            return Err(record_error());
        }
        Ok(TimeRange { start, end })
    }

    fn payload(&mut self) -> Result<CodeMemoryPayloadRef> {
        let tag = self.u8()?;
        let id = self.entity_id()?;
        CodeMemoryPayloadRef::from_tag(tag, id)
    }

    fn locator(&mut self) -> Result<CodeMemoryLocator> {
        let path_at_revision = self.text(CODEBASE_FILE_PATH_MAX_BYTES)?;
        let revision = match self.u8()? {
            REVISION_TAG_COMMIT => CodeMemoryRevision::Commit(self.text(COMMIT_HASH_MAX_HEX_LEN)?),
            REVISION_TAG_FORK_HASH => {
                let fork_hash: CodebaseForkHash = self
                    .take(CODEBASE_FORK_HASH_LEN)?
                    .try_into()
                    .map_err(|_| record_error())?;
                CodeMemoryRevision::ForkHash(fork_hash)
            }
            _ => return Err(record_error()),
        };
        let validity = self.time_range()?;
        let locator = CodeMemoryLocator {
            path_at_revision,
            revision,
            validity,
        };
        locator.validate().map_err(|_| record_error())?;
        Ok(locator)
    }

    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(record_error())
        }
    }
}

fn encode_slot(slot: &CodeMemorySlot) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(u8::from(slot.conflict_visible));
    push_text(&mut out, slot.name.as_str());
    push_u16(
        &mut out,
        u16::try_from(slot.values.len()).unwrap_or(u16::MAX),
    );
    for value in &slot.values {
        push_payload(&mut out, value.payload);
        out.extend_from_slice(value.actor_id.as_bytes());
        push_time_range(&mut out, value.valid_time);
        push_u64(&mut out, value.recorded_at);
        out.extend_from_slice(&value.content_hash);
        out.extend_from_slice(value.provenance_claim_id.as_bytes());
    }
    out
}

fn decode_slot(bytes: &[u8]) -> Result<CodeMemorySlot> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let conflict_visible = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(record_error()),
    };
    let name = CodeMemorySlotName::new(reader.text(CODE_MEMORY_SLOT_NAME_MAX_BYTES)?)
        .map_err(|_| record_error())?;
    let count = usize::from(reader.u16()?);
    if count > CODE_MEMORY_MAX_VALUES_PER_SLOT {
        return Err(record_error());
    }
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<_> = None;
    let mut dedupe_keys = BTreeSet::new();
    for _ in 0..count {
        let value = CodeMemorySlotValue {
            payload: reader.payload()?,
            actor_id: reader.entity_id()?,
            valid_time: reader.time_range()?,
            recorded_at: reader.u64()?,
            content_hash: reader.content_hash()?,
            provenance_claim_id: reader.entity_id()?,
        };
        let sort_key = value.sort_key();
        if previous.as_ref().is_some_and(|prev| *prev >= sort_key) {
            return Err(record_error());
        }
        if !dedupe_keys.insert(value.dedupe_key()) {
            return Err(record_error());
        }
        previous = Some(sort_key);
        values.push(value);
    }
    reader.finish()?;
    if conflict_visible != (values.len() >= 2) {
        return Err(record_error());
    }
    Ok(CodeMemorySlot {
        name,
        values,
        conflict_visible,
    })
}

fn encode_attachment_row(locator: &CodeMemoryLocator, provenance_claim_id: EntityId) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    push_locator(&mut out, locator);
    out.extend_from_slice(provenance_claim_id.as_bytes());
    out
}

fn decode_attachment_row(bytes: &[u8]) -> Result<(CodeMemoryLocator, EntityId)> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let locator = reader.locator()?;
    let provenance_claim_id = reader.entity_id()?;
    reader.finish()?;
    Ok((locator, provenance_claim_id))
}

fn encode_always_on(contract: &AlwaysOnCodeMemoryContract) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(contract.kind.tag());
    out.extend_from_slice(contract.symbol_id.as_bytes());
    push_text(&mut out, contract.slot.as_str());
    push_payload(&mut out, contract.payload);
    out.extend_from_slice(contract.actor_id.as_bytes());
    push_time_range(&mut out, contract.valid_time);
    push_u64(&mut out, contract.recorded_at);
    out.extend_from_slice(contract.provenance_claim_id.as_bytes());
    out
}

fn decode_always_on(bytes: &[u8]) -> Result<AlwaysOnCodeMemoryContract> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let kind = CodeMemoryContractKind::from_tag(reader.u8()?)?;
    let symbol_id = reader.entity_id()?;
    let slot = CodeMemorySlotName::new(reader.text(CODE_MEMORY_SLOT_NAME_MAX_BYTES)?)
        .map_err(|_| record_error())?;
    let payload = reader.payload()?;
    let actor_id = reader.entity_id()?;
    let valid_time = reader.time_range()?;
    let recorded_at = reader.u64()?;
    let provenance_claim_id = reader.entity_id()?;
    reader.finish()?;
    Ok(AlwaysOnCodeMemoryContract {
        symbol_id,
        slot,
        payload,
        kind,
        actor_id,
        valid_time,
        recorded_at,
        provenance_claim_id,
    })
}

/// The canonical bytes hashed into a transfer receipt's key. Deliberately
/// EXCLUDES `moved_attachments`, which is derived, so a byte-identical replay
/// of the same declared transfer lands on the same key.
fn encode_transfer_identity(transfer: &AnchorTransfer) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TRANSFER_DIGEST_DOMAIN);
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(transfer.kind.tag());
    out.extend_from_slice(transfer.from_symbol_id.as_bytes());
    out.extend_from_slice(transfer.to_symbol_id.as_bytes());
    push_locator(&mut out, &transfer.from_locator);
    push_locator(&mut out, &transfer.to_locator);
    out.extend_from_slice(transfer.actor_id.as_bytes());
    push_u64(&mut out, transfer.observed_at);
    out.extend_from_slice(transfer.provenance_claim_id.as_bytes());
    out
}

fn encode_transfer_record(record: &AnchorTransferRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(record.kind.tag());
    out.extend_from_slice(record.from_symbol_id.as_bytes());
    out.extend_from_slice(record.to_symbol_id.as_bytes());
    push_locator(&mut out, &record.from_locator);
    push_locator(&mut out, &record.to_locator);
    out.extend_from_slice(record.actor_id.as_bytes());
    push_u64(&mut out, record.observed_at);
    out.extend_from_slice(record.provenance_claim_id.as_bytes());
    push_u32(
        &mut out,
        u32::try_from(record.moved_attachments).unwrap_or(u32::MAX),
    );
    out
}

fn decode_transfer_record(bytes: &[u8]) -> Result<AnchorTransferRecord> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let kind = AnchorTransferKind::from_tag(reader.u8()?)?;
    let from_symbol_id = reader.entity_id()?;
    let to_symbol_id = reader.entity_id()?;
    let from_locator = reader.locator()?;
    let to_locator = reader.locator()?;
    let actor_id = reader.entity_id()?;
    let observed_at = reader.u64()?;
    let provenance_claim_id = reader.entity_id()?;
    let moved_attachments = reader.u32()? as usize;
    reader.finish()?;
    Ok(AnchorTransferRecord {
        kind,
        from_symbol_id,
        to_symbol_id,
        from_locator,
        to_locator,
        actor_id,
        observed_at,
        provenance_claim_id,
        moved_attachments,
    })
}

fn read_slot(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
) -> Result<Option<CodeMemorySlot>> {
    let Some(raw) = store.vault_meta.get(txn, &slot_key(symbol_id, slot))? else {
        return Ok(None);
    };
    decode_slot(&raw).map(Some)
}

fn write_slot(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &slot_key(symbol_id, &slot.name), &encode_slot(slot))
}

pub(crate) fn read_slots_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<CodeMemorySlot>> {
    let mut slots = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &slot_symbol_prefix(symbol_id))?
    {
        let (_, value) = entry?;
        slots.push(decode_slot(&value)?);
    }
    slots.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    Ok(slots)
}

pub(crate) fn read_always_on_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<AlwaysOnCodeMemoryContract>> {
    let mut contracts = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &always_on_symbol_prefix(symbol_id))?
    {
        let (_, value) = entry?;
        contracts.push(decode_always_on(&value)?);
    }
    contracts.sort_by(|left, right| (&left.slot, left.payload).cmp(&(&right.slot, right.payload)));
    Ok(contracts)
}

fn write_always_on(
    store: &Store,
    txn: &mut RwTxn<'_>,
    contract: &AlwaysOnCodeMemoryContract,
) -> Result<()> {
    let key = always_on_key(&contract.symbol_id, &contract.slot, contract.payload);
    store.vault_meta.put(txn, &key, &encode_always_on(contract))
}

/// Attachment-index rows for `(symbol, slot)` are EXACTLY the payload set
/// present in the written slot body: a payload that lost the actor-scoped
/// dedupe never keeps a row.
///
/// THE LOCATOR HALF IS PER PAYLOAD, NOT PER OPERATION. `locator` is the
/// locator of the operation now running, and it labels ONLY the payloads in
/// `relabelled_payloads` (the source-originating set of a transfer) plus the
/// payloads this operation introduces — the ones that carry no row yet. Every
/// other surviving payload keeps the locator its own row already holds, so a
/// later attach in the same slot cannot restamp an older payload's
/// path/revision/validity and a transfer cannot restamp a destination-only
/// payload that was never moved. Identity remains the symbol either way; this
/// keeps the locator half of the dual anchor lossless.
fn derive_attachment_rows(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
    locator: &CodeMemoryLocator,
    relabelled_payloads: &BTreeSet<CodeMemoryPayloadRef>,
) -> Result<()> {
    // Read the surviving payloads' own locators BEFORE the prefix delete: the
    // rewrite below is the only place they could otherwise be lost.
    let mut retained: BTreeMap<CodeMemoryPayloadRef, CodeMemoryLocator> = BTreeMap::new();
    for payload in slot.payloads() {
        if relabelled_payloads.contains(&payload) {
            continue;
        }
        let Some(raw) = store
            .vault_meta
            .get(txn, &attachment_key(symbol_id, &slot.name, payload))?
        else {
            continue;
        };
        let (existing, _) = decode_attachment_row(&raw)?;
        retained.insert(payload, existing);
    }

    delete_prefix(store, txn, &attachment_slot_prefix(symbol_id, &slot.name))?;
    for payload in slot.payloads() {
        let Some(provenance) = slot.provenance_for_payload(payload) else {
            continue;
        };
        let row_locator = retained.get(&payload).unwrap_or(locator);
        store.vault_meta.put(
            txn,
            &attachment_key(symbol_id, &slot.name, payload),
            &encode_attachment_row(row_locator, provenance),
        )?;
    }
    Ok(())
}

pub(crate) fn read_attachments_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<CodeMemoryAttachment>> {
    let mut attachments = Vec::new();
    for slot in read_slots_for_symbol(store, txn, symbol_id)? {
        for payload in slot.payloads() {
            let key = attachment_key(symbol_id, &slot.name, payload);
            let Some(raw) = store.vault_meta.get(txn, &key)? else {
                continue;
            };
            let (locator, provenance_claim_id) = decode_attachment_row(&raw)?;
            attachments.push(CodeMemoryAttachment {
                anchor: CodeMemoryAnchor {
                    symbol_id: *symbol_id,
                    locator,
                },
                slot: slot.name.clone(),
                payload,
                provenance_claim_id,
            });
        }
    }
    Ok(attachments)
}

// ---------------------------------------------------------------------------
// Deletion lifecycle — no code-memory row outlives the entity it names
// ---------------------------------------------------------------------------

/// Deletes every code-memory row that NAMES `id`, inside the caller's
/// deletion transaction.
///
/// An entity can occupy this module's key space in two unrelated roles, and a
/// delete has to close both or a public reader keeps answering for something
/// that no longer exists:
///
/// * ANCHOR — `id` was the `CODE_SYMBOL` the rows hang off. Slot, attachment,
///   and always-on keys are `id`-prefixed; transfer receipts name it on
///   either endpoint. Without this sweep `code_memory_slots`,
///   `code_memory_attachments`, `code_memory_always_on_contracts`, and
///   `code_memory_transfers` all keep serving a dead anchor.
/// * PAYLOAD — `id` was the NOTE/CLAIM a slot value or an always-on
///   registration pointed AT. Those keys are prefixed by some OTHER symbol,
///   so only a payload-id sweep reaches them. Leaving them behind would keep
///   readers exposing dangling refs, and — because registration counts KEYS
///   rather than live entities — would let dead rows consume a live symbol's
///   [`CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS`] budget permanently.
///
/// Unconditional by design: the deindex door reaches this seam for ids whose
/// entity record is already gone (its index-only arm), where the anchor type
/// can no longer be read back. Corrupt rows stay a typed error rather than a
/// silent skip, exactly as every other codec site in this module.
pub(crate) fn delete_code_memory_rows_for_entity_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    delete_prefix(store, txn, &slot_symbol_prefix(id))?;
    delete_prefix(store, txn, &attachment_symbol_prefix(id))?;
    delete_prefix(store, txn, &always_on_symbol_prefix(id))?;
    delete_transfer_records_naming(store, txn, id)?;
    delete_attachment_and_always_on_rows_for_payload(store, txn, id)?;
    drop_payload_from_slot_bodies(store, txn, id)
}

/// Transfer receipts are keyed `from | to | observed_at | digest`
/// ([`transfer_key`]), so the `to` half is not prefix-addressable: the family
/// is scanned and both endpoint segments are compared on the RAW key. Reading
/// the key rather than decoding the body keeps an unrelated entity's deletion
/// independent of any one receipt's decodability.
fn delete_transfer_records_naming(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, TRANSFER_KEY_PREFIX)? {
        let (key, _) = entry?;
        let endpoints = &key[TRANSFER_KEY_PREFIX.len()..];
        if endpoints.len() < 2 * ENTITY_ID_LEN {
            continue;
        }
        if &endpoints[..ENTITY_ID_LEN] == symbol_id.as_bytes()
            || &endpoints[ENTITY_ID_LEN..2 * ENTITY_ID_LEN] == symbol_id.as_bytes()
        {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

/// Attachment and always-on keys both END in `tag | payload id`
/// ([`key_with_payload`]), so the trailing [`ENTITY_ID_LEN`] bytes ARE the
/// payload id: one suffix match reaches both payload tags under any owning
/// symbol and any slot name.
fn delete_attachment_and_always_on_rows_for_payload(
    store: &Store,
    txn: &mut RwTxn<'_>,
    payload_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for prefix in [ATTACHMENT_KEY_PREFIX, ALWAYS_ON_KEY_PREFIX] {
        for entry in store.vault_meta.prefix_iter(&*txn, prefix)? {
            let (key, _) = entry?;
            if key.len() > prefix.len() + ENTITY_ID_LEN && key.ends_with(payload_id.as_bytes()) {
                keys.push(key.to_vec());
            }
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

/// Slot BODIES carry their payload refs inside the encoded value, so every
/// slot in the vault is decoded and the surviving values are re-encoded in
/// place. `normalize` re-derives `conflict_visible` from the survivors — the
/// decoder rejects a body whose flag disagrees with its value count — and a
/// slot with no survivor loses its row rather than persisting as an empty
/// body.
fn drop_payload_from_slot_bodies(
    store: &Store,
    txn: &mut RwTxn<'_>,
    payload_id: &EntityId,
) -> Result<()> {
    let mut rewrites: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, SLOT_KEY_PREFIX)? {
        let (key, value) = entry?;
        let mut slot = decode_slot(&value)?;
        let before = slot.values.len();
        slot.values
            .retain(|value| value.payload.entity_id() != *payload_id);
        if slot.values.len() == before {
            continue;
        }
        slot.normalize();
        let replacement = (!slot.values.is_empty()).then(|| encode_slot(&slot));
        rewrites.push((key.to_vec(), replacement));
    }
    for (key, replacement) in rewrites {
        match replacement {
            Some(body) => store.vault_meta.put(txn, &key, &body)?,
            None => {
                store.vault_meta.delete(txn, &key)?;
            }
        }
    }
    Ok(())
}

fn count_prefix(store: &Store, txn: &RoTxn<'_>, prefix: &[u8]) -> Result<usize> {
    let mut count = 0usize;
    for entry in store.vault_meta.prefix_iter(txn, prefix)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn delete_prefix(store: &Store, txn: &mut RwTxn<'_>, prefix: &[u8]) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, prefix)? {
        let (key, _) = entry?;
        keys.push(key.to_vec());
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! In-module coverage is deliberately limited to codec/key construction,
    //! the PURE merge algebra, and crate-seam side-effect mirrors the public
    //! API cannot observe. Every behavioural contract test lives in
    //! `tests/code_memory.rs` and reaches only `Vault`.

    use super::*;
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::store::GRAPH_VERSION_KEY;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("valid entity id")
    }

    fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn slot_name() -> CodeMemorySlotName {
        CodeMemorySlotName::new("interface.contract").expect("valid slot name")
    }

    fn locator() -> CodeMemoryLocator {
        CodeMemoryLocator {
            path_at_revision: "crates/oneiron/src/code_memory.rs".to_owned(),
            revision: CodeMemoryRevision::Commit("abc123def456".to_owned()),
            validity: range(1_780_000_000),
        }
    }

    fn value(payload: u8, actor: u8, content: u8, recorded_at: u64) -> CodeMemorySlotValue {
        CodeMemorySlotValue {
            payload: CodeMemoryPayloadRef::NoteEntity(id(payload)),
            actor_id: id(actor),
            valid_time: range(recorded_at),
            recorded_at,
            content_hash: [content; CODE_MEMORY_CONTENT_HASH_LEN],
            provenance_claim_id: id(payload.wrapping_add(1)),
        }
    }

    fn slot_with(values: Vec<CodeMemorySlotValue>) -> CodeMemorySlot {
        let mut slot = CodeMemorySlot::empty(slot_name());
        for value in values {
            slot.insert_multi_value(value).expect("value fits");
        }
        slot
    }

    /// Codec: a slot round-trips exactly, and its encoding is CANONICAL — two
    /// slots holding the same value set encode to identical bytes whatever
    /// order the values arrived in.
    #[test]
    fn slot_encoding_round_trips_and_is_order_independent() {
        let first = value(0x21, 0x31, 0x41, 100);
        let second = value(0x22, 0x32, 0x43, 200);
        let forward = slot_with(vec![first.clone(), second.clone()]);
        let backward = slot_with(vec![second, first]);

        assert_eq!(encode_slot(&forward), encode_slot(&backward));
        let decoded = decode_slot(&encode_slot(&forward)).expect("slot decodes");
        assert_eq!(decoded, forward);
        assert!(decoded.conflict_visible);
    }

    /// Codec fail-closed: an unknown version byte, a truncated body, trailing
    /// garbage, and a lying conflict flag are all refused outright.
    #[test]
    fn slot_decoding_is_fail_closed() {
        let one = encode_slot(&slot_with(vec![value(0x23, 0x33, 0x45, 300)]));

        let mut wrong_version = one.clone();
        wrong_version[0] = CODE_MEMORY_RECORD_VERSION + 1;
        assert!(decode_slot(&wrong_version).is_err());
        assert!(decode_slot(&one[..one.len() - 1]).is_err());

        let mut trailing = one.clone();
        trailing.push(0);
        assert!(decode_slot(&trailing).is_err());
        assert!(decode_slot(&one).is_ok());

        let two = encode_slot(&slot_with(vec![
            value(0x24, 0x34, 0x46, 400),
            value(0x25, 0x35, 0x48, 500),
        ]));
        let mut lying = two.clone();
        lying[1] = 0;
        assert!(
            decode_slot(&lying).is_err(),
            "a false conflict flag beside two live values must never decode"
        );
        assert!(decode_slot(&two).is_ok());
    }

    /// Keys: identity is the SYMBOL. Every family is symbol-prefixed, the
    /// payload TAG participates so a note and a claim ref cannot collide, and
    /// no key construction takes a path at all.
    #[test]
    fn keys_are_symbol_prefixed_and_never_path_derived() {
        let symbol = id(0x51);
        let other = id(0x52);
        let note = CodeMemoryPayloadRef::NoteEntity(id(0x53));
        let claim = CodeMemoryPayloadRef::Claim(id(0x53));

        let mut symbol_prefixed = key_with_symbol(SLOT_KEY_PREFIX, &symbol);
        symbol_prefixed.pop();
        assert!(slot_key(&symbol, &slot_name()).starts_with(&symbol_prefixed));
        assert!(attachment_key(&symbol, &slot_name(), note).starts_with(ATTACHMENT_KEY_PREFIX));
        assert!(always_on_key(&symbol, &slot_name(), note).starts_with(ALWAYS_ON_KEY_PREFIX));

        assert_ne!(
            slot_key(&symbol, &slot_name()),
            slot_key(&other, &slot_name())
        );
        assert_ne!(
            always_on_key(&symbol, &slot_name(), note),
            always_on_key(&symbol, &slot_name(), claim)
        );

        // The whole dual-anchor rule in one assertion: the locator's path is
        // nowhere in the key that carries attachment identity.
        let path = locator().path_at_revision.into_bytes();
        let key = attachment_key(&symbol, &slot_name(), note);
        assert!(!key.windows(path.len()).any(|window| window == path));
    }

    /// A transfer receipt key is deterministic in the declared transfer, so a
    /// byte-identical replay upserts one row; any changed field moves it.
    #[test]
    fn transfer_keys_are_deterministic_and_collision_free() {
        let transfer = AnchorTransfer {
            kind: AnchorTransferKind::Rename,
            from_symbol_id: id(0x61),
            to_symbol_id: id(0x62),
            from_locator: locator(),
            to_locator: locator(),
            actor_id: id(0x63),
            observed_at: 1_780_000_100,
            provenance_claim_id: id(0x64),
        };
        let replay = transfer.clone();
        assert_eq!(transfer_key(&transfer), transfer_key(&replay));

        let mut copied = transfer;
        copied.kind = AnchorTransferKind::Copy;
        assert_ne!(transfer_key(&replay), transfer_key(&copied));
    }

    /// PURE merge algebra over the canonical encoded output: associative,
    /// commutative, and idempotent, including two actor/content-colliding
    /// values that differ only in `valid_time`.
    #[test]
    fn merge_union_is_associative_commutative_idempotent() {
        let mut colliding = value(0x26, 0x36, 0x4A, 600);
        colliding.valid_time = TimeRange {
            start: 600,
            end: 900,
        };
        let first = slot_with(vec![
            value(0x26, 0x36, 0x4A, 600),
            value(0x27, 0x37, 0x4C, 700),
        ]);
        let second = slot_with(vec![colliding]);
        let third = slot_with(vec![value(0x28, 0x38, 0x4E, 800)]);

        let left = first
            .merge_union(&second)
            .expect("merge")
            .merge_union(&third)
            .expect("merge");
        let right = first
            .merge_union(&second.merge_union(&third).expect("merge"))
            .expect("merge");
        assert_eq!(encode_slot(&left), encode_slot(&right), "associative");
        assert_eq!(
            encode_slot(&first.merge_union(&second).expect("merge")),
            encode_slot(&second.merge_union(&first).expect("merge")),
            "commutative"
        );
        assert_eq!(
            encode_slot(&left),
            encode_slot(&left.merge_union(&left).expect("merge")),
            "idempotent"
        );
    }

    /// Two actors, identical bytes: two values survive with actor, time, and
    /// provenance intact and conflict visible. Nothing elects a winner.
    #[test]
    fn equal_bytes_from_different_actors_never_collapse() {
        let merged = slot_with(vec![value(0x29, 0x39, 0x4F, 900)])
            .merge_union(&slot_with(vec![value(0x2A, 0x3A, 0x4F, 950)]))
            .expect("merge");

        assert_eq!(merged.values.len(), 2);
        assert!(merged.conflict_visible);
        let actors: BTreeSet<EntityId> = merged.values.iter().map(|value| value.actor_id).collect();
        assert_eq!(actors, BTreeSet::from([id(0x39), id(0x3A)]));
    }

    /// One actor, identical bytes: the canonical MINIMUM survives whatever
    /// order the values arrive in. This is the no-LWW guarantee at the
    /// algebra level — the LATER value is not the winner.
    #[test]
    fn actor_scoped_collision_keeps_the_canonical_minimum() {
        let older = value(0x2B, 0x3B, 0x4B, 1_000);
        let newer = value(0x2C, 0x3B, 0x4B, 2_000);

        for order in [
            vec![older.clone(), newer.clone()],
            vec![newer, older.clone()],
        ] {
            let mut slot = CodeMemorySlot::empty(slot_name());
            let outcomes: Vec<SlotInsertOutcome> = order
                .into_iter()
                .map(|value| slot.insert_multi_value(value).expect("insert"))
                .collect();
            assert_eq!(outcomes[0], SlotInsertOutcome::Inserted);
            assert_eq!(outcomes[1], SlotInsertOutcome::DeduplicatedWithinActor);
            assert_eq!(slot.values.len(), 1);
            assert_eq!(slot.values[0], older, "canonical minimum survives");
            assert!(!slot.conflict_visible);
        }
    }

    /// The capacity bound is transactional at the algebra level: the 257th
    /// DISTINCT value errors typed and leaves the encoded slot unchanged.
    #[test]
    fn slot_capacity_is_transactional() {
        let mut slot = CodeMemorySlot::empty(slot_name());
        for index in 0..CODE_MEMORY_MAX_VALUES_PER_SLOT {
            let mut candidate = value(0x2D, 0x3D, 0x4D, 1_100);
            candidate.content_hash[0] = u8::try_from(index % 251).expect("byte");
            candidate.content_hash[1] = u8::try_from(index / 251).expect("byte");
            slot.insert_multi_value(candidate).expect("value fits");
        }
        let before = encode_slot(&slot);

        let mut overflow = value(0x2E, 0x3D, 0x4D, 1_200);
        overflow.content_hash = [0xFE; CODE_MEMORY_CONTENT_HASH_LEN];
        let error = slot
            .insert_multi_value(overflow)
            .expect_err("the 257th distinct value must be refused");
        assert!(matches!(
            error,
            Error::CodeMemoryLimitExceeded {
                kind: "slot values",
                limit: CODE_MEMORY_MAX_VALUES_PER_SLOT
            }
        ));
        assert_eq!(encode_slot(&slot), before);
    }

    /// Attachment-index rows mirror the WRITTEN body exactly: the payload of
    /// a value that lost the actor-scoped dedupe keeps no row and no
    /// provenance.
    #[test]
    fn attachment_rows_never_reference_a_deduped_payload() {
        let survivor = value(0x2B, 0x3F, 0x49, 1_000);
        let loser = value(0x2C, 0x3F, 0x49, 2_000);
        let slot = slot_with(vec![survivor.clone(), loser.clone()]);

        assert_eq!(slot.payloads(), vec![survivor.payload]);
        assert_eq!(
            slot.provenance_for_payload(survivor.payload),
            Some(survivor.provenance_claim_id)
        );
        assert_eq!(slot.provenance_for_payload(loser.payload), None);
    }

    // -- crate-seam side-effect mirrors -----------------------------------

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        (dir, vault)
    }

    fn seed_symbol(vault: &Vault, byte: u8) -> EntityId {
        let symbol = id(byte);
        vault
            .put_entity(&symbol, ENTITY_TYPE_CODE_SYMBOL, range(1), 1, b"symbol")
            .expect("seed CODE_SYMBOL");
        symbol
    }

    fn graph_version(vault: &Vault) -> u64 {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let Some(raw) = vault
            .store
            .hnsw_meta
            .get(&rtxn, GRAPH_VERSION_KEY)
            .expect("graph version read")
        else {
            return 0;
        };
        let bytes: [u8; 8] = raw.as_ref().try_into().expect("u64 graph version");
        u64::from_le_bytes(bytes)
    }

    /// CRATE SEAM (invisible through `Vault`): one successful dedicated
    /// `Blocks` write puts IDENTICAL bytes into BOTH edge indexes and bumps
    /// the PPR graph version exactly once, mirroring the landed
    /// edge-mutation side effects.
    #[test]
    fn blocks_write_mirrors_edge_side_effects() {
        let (_dir, vault) = test_vault();
        let blocker = seed_symbol(&vault, 0x71);
        let blocked = seed_symbol(&vault, 0x72);
        let person = id(0x73);
        vault
            .put_entity(&person, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .expect("seed PERSON");
        let actor = WriteActor::new(person, EdgeActorClass::Human);

        let before = graph_version(&vault);
        vault
            .insert_blocks_edge(
                blocker,
                blocked,
                BlocksWriteContext {
                    actor: &actor,
                    source: ClaimSource::UserStated,
                },
            )
            .expect("a Human actor on a trusted source passes the dedicated door");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        let out = vault
            .store
            .edges_out
            .get(
                &rtxn,
                &Store::encode_edge_key(&blocker, EdgeKind::Blocks, &blocked),
            )
            .expect("edges_out read")
            .expect("outbound row");
        let inbound = vault
            .store
            .edges_in
            .get(
                &rtxn,
                &Store::encode_edge_key(&blocked, EdgeKind::Blocks, &blocker),
            )
            .expect("edges_in read")
            .expect("inbound row");
        assert_eq!(
            out.as_ref(),
            inbound.as_ref(),
            "both indexes agree bytewise"
        );
        drop(rtxn);

        assert_eq!(
            graph_version(&vault),
            before + 1,
            "graph version increments exactly once"
        );
    }

    /// CRATE SEAM: the acyclicity walk is KIND-LOCAL. An ordinary structural
    /// path between the same endpoints is invisible to it, so it can never
    /// fabricate a readiness cycle.
    #[test]
    fn blocks_reachability_walk_is_kind_local() {
        let (_dir, vault) = test_vault();
        let left = seed_symbol(&vault, 0x74);
        let right = seed_symbol(&vault, 0x75);
        vault
            .put_edge(&left, EdgeKind::DerivedFrom, &right, 0.2)
            .expect("an ordinary structural edge still writes through the generic door");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        assert!(!blocks_path_exists(&vault, &rtxn, left, right).expect("walk"));
    }

    /// CRATE SEAM (unreachable through `Vault`): the deindex door's INDEX-ONLY
    /// arm — the one that returns before it ever reads an entity record —
    /// sweeps this module's rows too.
    ///
    /// The public API cannot produce this state, because attaching requires a
    /// live `CODE_SYMBOL` anchor; a symbol whose entity row is already gone is
    /// exactly what that arm exists for, and the anchor TYPE is no longer
    /// readable there. Deleting the entity row directly is the only way to
    /// hand the arm L2 material to clean up.
    #[test]
    fn index_only_deindex_still_clears_code_memory_rows() {
        let (_dir, vault) = test_vault();
        let symbol = seed_symbol(&vault, 0x76);
        vault
            .attach_code_memory(AttachCodeMemory {
                anchor: CodeMemoryAnchor {
                    symbol_id: symbol,
                    locator: locator(),
                },
                slot: slot_name(),
                value: value(0x77, 0x78, 0x79, 100),
            })
            .expect("attach");

        vault
            .with_write_txn(|wtxn| {
                vault.store.entities.delete(wtxn, symbol.as_bytes())?;
                Ok(())
            })
            .expect("drop only the anchor entity row");

        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &symbol)
            })
            .expect("index-only deindex");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        let slots = read_slots_for_symbol(&vault.store, &rtxn, &symbol).expect("slots");
        let rows = read_attachments_for_symbol(&vault.store, &rtxn, &symbol).expect("rows");
        assert!(slots.is_empty(), "the index-only arm sweeps slot bodies");
        assert!(rows.is_empty(), "and the attachment index with them");
    }
}
