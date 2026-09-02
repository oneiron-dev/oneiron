use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ops::ControlFlow;

use heed::{RoTxn, RwTxn};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSource, ScopedRead};
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CodebaseForkHash};
use crate::edge::{EdgeActorClass, EdgeKind, encode_edge_value};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::ppr::{self, PprNodeVisibility, SeedWeighting, ppr_query_scoped_in_txn};
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_NOTE};
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

