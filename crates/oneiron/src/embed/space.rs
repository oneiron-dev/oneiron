//! Kind slots bound to declared embedding spaces (OF-370; ARCH-0019 `#kind-slots`, ARCH-0004
//! `#embedding-spaces`).
//!
//! Three input kinds — text, image, audio — each bind to a declared space. A space names its
//! `model@revision@where`, its width, the inputs it accepts and the query towers it has; a
//! binding is valid only when the space accepts that input, and a query enters a space only
//! through one of its towers. Text binds to the vault's own vector index by default; image and
//! audio bind to a declared media space, one shared space by default. The one-space preset
//! ([`Vault::bind_one_space_for_all`]) binds text to a declared space too, so text documents
//! and text queries go through that space's model instead of the vault's index.
//!
//! Media vectors live per space: every row is keyed by its space and carries its input kind, so
//! a search reads exactly one space and two spaces' vectors are never compared. Each space's
//! search is its own ranked list; fusion z-scores every list on its own scale.
//!
//! Declarations and bindings reach this vault's other devices as EMBEDDING_SETUP rows
//! ([`EmbeddingSetup`]), which every writer here publishes in its own write; each device then
//! embeds its own ASSETs with the pinned space's model. Vectors never travel.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
use crate::config::VectorEvidenceFloors;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::pipeline::ScoredEntity;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_EMBEDDING_SETUP;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable, SideTableDbs};
use crate::store::{decode_vector_row, encode_vector_row_v1};
use crate::temporal::TimeRange;

/// Longest declared space id.
pub const EMBEDDING_SPACE_ID_MAX_LEN: usize = 256;
/// Widest declared space.
pub const EMBEDDING_SPACE_MAX_DIMENSIONS: usize = 8192;
/// The learned (and occurred) time of every EMBEDDING_SETUP row: one fixed instant, so each row
/// lives in one window, `1970-01`, whenever it was last written.
pub const EMBEDDING_SETUP_LEARNED_AT: u64 = 0;

/// One input modality a kind slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Text,
    Image,
    Audio,
}

impl InputKind {
    /// Every kind slot, in slot order.
    pub const ALL: [Self; 3] = [Self::Text, Self::Image, Self::Audio];

    /// The media kind a stored media type carries: `image/*` or `audio/*`.
    #[must_use]
    pub fn for_media_type(media_type: &str) -> Option<Self> {
        let media_type = media_type.trim().to_ascii_lowercase();
        if media_type.starts_with("image/") {
            Some(Self::Image)
        } else if media_type.starts_with("audio/") {
            Some(Self::Audio)
        } else {
            None
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Text => 0,
            Self::Image => 1,
            Self::Audio => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Text),
            1 => Some(Self::Image),
            2 => Some(Self::Audio),
            _ => None,
        }
    }
}

/// A declared embedding space: its own pin, its own vector rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingSpace {
    /// `model@revision@where`: the whole document function this space's vectors come from.
    /// `where` is the place of the model's offer, the `[models]` provider key that binds it.
    pub id: String,
    pub dimensions: usize,
    /// The inputs the space's model embeds as documents.
    pub accepts: BTreeSet<InputKind>,
    /// The query kinds the space's model can encode into this space.
    pub query_towers: BTreeSet<InputKind>,
    /// RET-01's floors for this space's raw cosines (OF-370). A hit at or above `floor` is
    /// evidence that keeps a context pack from abstaining. `None` judges the space by the
    /// vault's own floors ([`Vault::vector_evidence`]); a pair a host set for one kind in this
    /// space ([`Vault::set_vector_evidence_for`]) still takes its place for that kind.
    #[serde(default, with = "evidence_floors")]
    pub evidence: Option<VectorEvidenceFloors>,
}

/// [`VectorEvidenceFloors`] as a space row stores it.
mod evidence_floors {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::config::VectorEvidenceFloors;

    #[derive(Serialize, Deserialize)]
    struct Row {
        floor: f32,
        strong: f32,
    }

    pub(super) fn serialize<S: Serializer>(
        floors: &Option<VectorEvidenceFloors>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        floors
            .map(|floors| Row {
                floor: floors.floor,
                strong: floors.strong,
            })
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<VectorEvidenceFloors>, D::Error> {
        Ok(
            Option::<Row>::deserialize(deserializer)?.map(|row| VectorEvidenceFloors {
                floor: row.floor,
                strong: row.strong,
            }),
        )
    }
}

impl EmbeddingSpace {
    /// Refuses an empty or malformed id, a zero or oversized width, a space that accepts
    /// nothing, or floors [`VectorEvidenceFloors::validate`] refuses.
    pub fn validate(&self) -> Result<()> {
        validate_space_id(&self.id)?;
        if self.dimensions == 0 || self.dimensions > EMBEDDING_SPACE_MAX_DIMENSIONS {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} width must be within 1..={EMBEDDING_SPACE_MAX_DIMENSIONS}, got {}",
                self.id, self.dimensions
            )));
        }
        if self.accepts.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} accepts no input kind",
                self.id
            )));
        }
        if let Some(floors) = &self.evidence {
            floors.validate()?;
        }
        Ok(())
    }

    /// Refuses a `kind` slot binding this space cannot serve: it must accept that input, and
    /// the text slot also needs a text query tower, since text queries enter where text binds.
    pub(super) fn admit_binding(&self, kind: InputKind) -> Result<()> {
        if !self.accepts.contains(&kind) {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} does not accept {kind:?} input",
                self.id
            )));
        }
        if kind == InputKind::Text && !self.query_towers.contains(&InputKind::Text) {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} has no Text query tower, so text queries could not enter it",
                self.id
            )));
        }
        Ok(())
    }

    /// Refuses a query this space has no tower for, or one of another width.
    pub fn admit_query(&self, kind: InputKind, vector: &[f32]) -> Result<()> {
        if !self.query_towers.contains(&kind) {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} has no {kind:?} query tower",
                self.id
            )));
        }
        if vector.len() != self.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.dimensions,
                got: vector.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(vector) {
            return Err(error);
        }
        Ok(())
    }

    fn key(&self) -> [u8; 16] {
        space_key(&self.id)
    }
}

/// Which declared space each kind slot binds to. An unbound text slot is the vault's own vector
/// index (`VaultConfig::embedding_model`), which is not a row here; a bound one is the one-space
/// preset ([`Vault::bind_one_space_for_all`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindSlotBindings {
    pub text: Option<String>,
    pub image: Option<String>,
    pub audio: Option<String>,
}

impl KindSlotBindings {
    /// The declared space a kind binds to; `None` for an unbound slot, and for text on the
    /// vault's own index.
    #[must_use]
    pub fn space_for(&self, kind: InputKind) -> Option<&str> {
        match kind {
            InputKind::Text => self.text.as_deref(),
            InputKind::Image => self.image.as_deref(),
            InputKind::Audio => self.audio.as_deref(),
        }
    }
}

/// One EMBEDDING_SETUP row (OF-370): a piece of this vault's embedding setup its other devices
/// need to embed the same inputs into the same spaces. A row's id derives from what it names,
/// so every device writes one row per space and one per kind slot. A retirement and a slot's
/// return to its default are rows too, never a missing one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EmbeddingSetup {
    /// A declared space.
    Space(EmbeddingSpace),
    /// A space retired here: its declaration and rows went.
    Retired { id: String },
    /// A kind slot's binding; `None` is the slot's default.
    Slot {
        kind: InputKind,
        space: Option<String>,
    },
}

impl EmbeddingSetup {
    fn id(&self) -> Result<EntityId> {
        let domain = crate::entity_id::derived_domains::EMBEDDING_SETUP;
        match self {
            Self::Space(EmbeddingSpace { id, .. }) | Self::Retired { id } => {
                EntityId::derive(domain, &[b"space".as_slice(), id.as_bytes()])
            }
            Self::Slot { kind, .. } => {
                EntityId::derive(domain, &[b"slot".as_slice(), &[kind.byte()]])
            }
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("embedding setup row encode"))
    }

    /// The row `data` holds, refused unless it is exactly the bytes its writer encodes.
    fn decode(data: &[u8]) -> Result<Self> {
        let setup: Self = rmp_serde::from_slice(data)
            .map_err(|_| refused_setup("the row does not decode".into()))?;
        if setup.encode()? != data {
            return Err(refused_setup(
                "the row is not in its canonical encoding".into(),
            ));
        }
        Ok(setup)
    }
}

fn refused_setup(reason: String) -> Error {
    Error::Artifact(ArtifactError::InvalidEmbeddingSetupBody(reason))
}

#[cfg(feature = "sync")]
fn setup_waits(reason: String) -> Error {
    Error::Artifact(ArtifactError::EmbeddingSetupDependencyPending(reason))
}

/// Whether a replicated EMBEDDING_SETUP body rests on another row of its window: a binding or a
/// retirement lands after the declarations beside it.
#[cfg(feature = "sync")]
pub(crate) fn embedding_setup_rests_on_sibling(data: &[u8]) -> bool {
    !matches!(EmbeddingSetup::decode(data), Ok(EmbeddingSetup::Space(_)))
}

/// Installs one replicated EMBEDDING_SETUP row of this vault into the side tables in `wtxn`,
/// under the checks its local writer makes. `id` must be the row's own derived id. A binding of
/// a space not declared here yet, a retirement of a space a slot here still binds, and a row
/// naming a slot a move here carries wait
/// ([`ArtifactError::EmbeddingSetupDependencyPending`]); anything else that fails a check is
/// refused ([`ArtifactError::InvalidEmbeddingSetupBody`]). Nothing is written then.
#[cfg(feature = "sync")]
pub(crate) fn install_replicated_embedding_setup_in_txn(
    store: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    let setup = EmbeddingSetup::decode(data)?;
    if setup.id()? != *id {
        return Err(refused_setup(format!(
            "row {} is not the row its contents name",
            id.to_hex()
        )));
    }
    let moving = |wtxn: &RwTxn<'_>, kind: InputKind| -> Result<()> {
        match super::space_move::moving_kind_in_txn(store, wtxn, kind)? {
            Some(candidate) => Err(setup_waits(format!(
                "the {kind:?} slot is moving to {candidate} here"
            ))),
            None => Ok(()),
        }
    };
    match setup {
        EmbeddingSetup::Space(space) => {
            space
                .validate()
                .map_err(|error| refused_setup(error.to_string()))?;
            if let Some(existing) = embedding_space_in_txn(store, wtxn, &space.id)?
                && existing.dimensions != space.dimensions
            {
                return Err(refused_setup(format!(
                    "embedding space {} is declared here at width {}",
                    space.id, existing.dimensions
                )));
            }
            EMBEDDING_SPACE.put(store, wtxn, &space.id.clone(), &space)?;
        }
        EmbeddingSetup::Retired { id: space_id } => {
            validate_space_id(&space_id).map_err(|error| refused_setup(error.to_string()))?;
            let bindings = kind_slot_bindings_in_txn(store, wtxn)?;
            if let Some(kind) = InputKind::ALL
                .into_iter()
                .find(|kind| bindings.space_for(*kind) == Some(space_id.as_str()))
            {
                return Err(setup_waits(format!(
                    "the {kind:?} slot here still binds {space_id}"
                )));
            }
            if super::space_move::open_move_names_in_txn(store, wtxn, &space_id)? {
                return Err(setup_waits(format!("an open move here names {space_id}")));
            }
            let key = space_key(&space_id);
            MEDIA_VECTOR.delete_from(store, wtxn, &key)?;
            MEDIA_REFUSED.delete_from(store, wtxn, &key)?;
            EMBEDDING_SPACE.delete(store, wtxn, &space_id)?;
        }
        EmbeddingSetup::Slot {
            kind,
            space: Some(space_id),
        } => {
            let Some(space) = embedding_space_in_txn(store, wtxn, &space_id)? else {
                return Err(setup_waits(format!(
                    "embedding space {space_id} is not declared here yet"
                )));
            };
            space
                .admit_binding(kind)
                .map_err(|error| refused_setup(error.to_string()))?;
            moving(wtxn, kind)?;
            EMBEDDING_SLOT.put(store, wtxn, &[kind.byte()], &space.id)?;
        }
        EmbeddingSetup::Slot { kind, space: None } => {
            moving(wtxn, kind)?;
            EMBEDDING_SLOT.delete(store, wtxn, &[kind.byte()])?;
        }
    }
    Ok(())
}

/// Declared spaces. Key: space id string.
const EMBEDDING_SPACE: SideTable<String, EmbeddingSpace, Named> =
    SideTable::new(&side_table::EMBEDDING_SPACE);
/// Kind slot → space id. Key: one input-kind byte.
const EMBEDDING_SLOT: SideTable<[u8; 1], String, Named> =
    SideTable::new(&side_table::EMBEDDING_SLOT);
/// One media vector per (space, entity). Key: space key16 + id16.
const MEDIA_VECTOR: SideTable<([u8; 16], EntityId), MediaVectorRow, Raw> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_VECTOR);
/// Documents a space's model refused by their content. Key: space key16 + id16.
const MEDIA_REFUSED: SideTable<([u8; 16], EntityId), MediaRefusal, Named> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_REFUSED);

/// Why a space's model refused one document, and which bytes it refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MediaRefusal {
    /// BLAKE3 of the refused bytes: other bytes are tried again.
    fingerprint: [u8; 32],
    reason: String,
    /// Vault seconds.
    at: u64,
}

/// Whether `space`'s model refused `id` at exactly these `bytes`.
pub(super) fn media_refused_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space: &EmbeddingSpace,
    id: &EntityId,
    bytes: &[u8],
) -> Result<bool> {
    Ok(MEDIA_REFUSED
        .get(store, txn, &(space.key(), *id))?
        .is_some_and(|row| row.fingerprint == *blake3::hash(bytes).as_bytes()))
}

/// Records that `space`'s model refused `id` at these `bytes`, for `reason`.
pub(super) fn put_media_refusal_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    space: &EmbeddingSpace,
    id: &EntityId,
    bytes: &[u8],
    reason: String,
    at: u64,
) -> Result<()> {
    MEDIA_REFUSED.put(
        store,
        txn,
        &(space.key(), *id),
        &MediaRefusal {
            fingerprint: *blake3::hash(bytes).as_bytes(),
            reason,
            at,
        },
    )
}

/// One document a space's model refused, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaRefused {
    pub id: EntityId,
    pub reason: String,
    /// Vault seconds.
    pub at: u64,
}

/// Forgets a refusal of `id` in `space`, once a vector of it lands there.
pub(super) fn clear_media_refusal_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    space: &EmbeddingSpace,
    id: &EntityId,
) -> Result<()> {
    MEDIA_REFUSED.delete(store, txn, &(space.key(), *id))?;
    Ok(())
}

/// Width of a text row's text hash.
const TEXT_HASH_LEN: usize = 32;

/// A stored media vector: its input kind byte, for a text row the hash of the text it embeds,
/// then the v1 vector row.
struct MediaVectorRow {
    kind: InputKind,
    /// A text row's text hash, so the backfill embeds a document again once its text moves.
    text_hash: [u8; TEXT_HASH_LEN],
    row: Vec<u8>,
}

impl RawValue for MediaVectorRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(self.row.len() + 1 + TEXT_HASH_LEN);
        out.push(self.kind.byte());
        if self.kind == InputKind::Text {
            out.extend_from_slice(&self.text_hash);
        }
        out.extend_from_slice(&self.row);
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (&kind, rest) = bytes
            .split_first()
            .ok_or(Error::CorruptedIndex("media vector row"))?;
        let kind = InputKind::from_byte(kind).ok_or(Error::CorruptedIndex("media vector kind"))?;
        let mut text_hash = [0_u8; TEXT_HASH_LEN];
        let row = if kind == InputKind::Text {
            let (hash, row) = rest
                .split_first_chunk::<TEXT_HASH_LEN>()
                .ok_or(Error::CorruptedIndex("media vector text hash"))?;
            text_hash = *hash;
            row
        } else {
            rest
        };
        Ok(Self {
            kind,
            text_hash,
            row: row.to_vec(),
        })
    }
}

/// The hash a text row keeps of the text it embeds.
pub(crate) fn text_hash(text: &str) -> [u8; TEXT_HASH_LEN] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

fn validate_space_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > EMBEDDING_SPACE_ID_MAX_LEN
        || !id.contains('@')
        || id.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::InvalidConfig(format!(
            "embedding space id must be a model@revision@where spelling of at most \
             {EMBEDDING_SPACE_ID_MAX_LEN} bytes without whitespace, got {id:?}"
        )));
    }
    Ok(())
}

fn space_key(id: &str) -> [u8; 16] {
    let hash = blake3::hash(id.as_bytes());
    let mut key = [0_u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub(crate) fn embedding_space_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &str,
) -> Result<Option<EmbeddingSpace>> {
    EMBEDDING_SPACE.get(store, txn, &id.to_owned())
}

/// Refuses a hand binding of a slot an open move carries: the move swaps it in, or is
/// abandoned first.
fn refuse_moving_slot_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    kind: InputKind,
) -> Result<()> {
    if let Some(candidate) = super::space_move::moving_kind_in_txn(store, txn, kind)? {
        return Err(Error::InvalidConfig(format!(
            "the {kind:?} slot is moving to {candidate}; approve or abandon that move first"
        )));
    }
    Ok(())
}

pub(crate) fn kind_slot_bindings_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<KindSlotBindings> {
    Ok(KindSlotBindings {
        text: EMBEDDING_SLOT.get(store, txn, &[InputKind::Text.byte()])?,
        image: EMBEDDING_SLOT.get(store, txn, &[InputKind::Image.byte()])?,
        audio: EMBEDDING_SLOT.get(store, txn, &[InputKind::Audio.byte()])?,
    })
}

pub(crate) fn has_media_vector_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space: &EmbeddingSpace,
    id: &EntityId,
) -> Result<bool> {
    MEDIA_VECTOR.contains(store, txn, &(space.key(), *id))
}

/// The text hash `id`'s text row in `space` was embedded from; `None` when it has no text row
/// there.
pub(crate) fn media_text_hash_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space: &EmbeddingSpace,
    id: &EntityId,
) -> Result<Option<[u8; TEXT_HASH_LEN]>> {
    Ok(MEDIA_VECTOR
        .get(store, txn, &(space.key(), *id))?
        .filter(|row| row.kind == InputKind::Text)
        .map(|row| row.text_hash))
}

/// Stages one media vector into `space`: its kind must be one the space accepts and fills
/// ([`super::space_move::space_fill_kinds_in_txn`]: bound to it, or moving to it), its width
/// the space's own. A text row carries the hash of the text it embeds.
#[expect(
    clippy::too_many_arguments,
    reason = "a staged row names its space, the kinds it fills, its entity, kind, text hash and vector"
)]
pub(crate) fn put_media_vector_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    space: &EmbeddingSpace,
    fills: &BTreeSet<InputKind>,
    id: &EntityId,
    kind: InputKind,
    text_hash: Option<[u8; TEXT_HASH_LEN]>,
    vector: &[f32],
) -> Result<()> {
    if !fills.contains(&kind) {
        return Err(Error::InvalidConfig(format!(
            "the {kind:?} slot neither binds nor moves to embedding space {}",
            space.id
        )));
    }
    let text_hash = match (kind, text_hash) {
        (InputKind::Text, Some(hash)) => hash,
        (InputKind::Text, None) => {
            return Err(Error::InvalidConfig(format!(
                "a text vector in embedding space {} names the text it embeds",
                space.id
            )));
        }
        _ => [0_u8; TEXT_HASH_LEN],
    };
    if !space.accepts.contains(&kind) {
        return Err(Error::InvalidConfig(format!(
            "embedding space {} does not accept {kind:?} input",
            space.id
        )));
    }
    if vector.len() != space.dimensions {
        return Err(Error::DimensionMismatch {
            expected: space.dimensions,
            got: vector.len(),
        });
    }
    let row = MediaVectorRow {
        kind,
        text_hash,
        row: encode_vector_row_v1(vector)?,
    };
    MEDIA_VECTOR.put(store, txn, &(space.key(), *id), &row)
}

/// Binds `kind`'s slot to `space_id`, or returns it to its default when `None`: the vault's
/// own index for text, nothing for a media kind. The caller has admitted the binding.
pub(super) fn set_kind_slot_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    kind: InputKind,
    space_id: Option<&str>,
) -> Result<()> {
    match space_id {
        Some(space_id) => EMBEDDING_SLOT.put(store, txn, &[kind.byte()], &space_id.to_owned()),
        None => EMBEDDING_SLOT
            .delete(store, txn, &[kind.byte()])
            .map(|_| ()),
    }
}

/// Drops `space_id`'s rows of `kinds`, and its declaration too once no slot binds it.
pub(super) fn drop_space_rows_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    space_id: &str,
    kinds: &BTreeSet<InputKind>,
) -> Result<()> {
    let key = space_key(space_id);
    let mut drop = Vec::new();
    for row in MEDIA_VECTOR.iter_from(store, txn, &key)? {
        let ((_, id), row) = row?;
        if kinds.contains(&row.kind) {
            drop.push(id);
        }
    }
    for id in drop {
        MEDIA_VECTOR.delete(store, txn, &(key, id))?;
    }
    let bindings = kind_slot_bindings_in_txn(store, txn)?;
    if !InputKind::ALL
        .iter()
        .any(|kind| bindings.space_for(*kind) == Some(space_id))
    {
        MEDIA_VECTOR.delete_from(store, txn, &key)?;
        MEDIA_REFUSED.delete_from(store, txn, &key)?;
        EMBEDDING_SPACE.delete(store, txn, &space_id.to_owned())?;
    }
    Ok(())
}

/// Removes `id`'s text rows from every declared space, as its text-index vector is dropped: a
/// vector of words the record no longer holds stops matching at once, and the backfill embeds
/// what is left. Its image and audio rows stay; a refusal of it is forgotten, so the backfill
/// tries it again.
pub(crate) fn delete_text_media_vectors_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let spaces: Vec<[u8; 16]> = EMBEDDING_SPACE
        .scan(store, txn)?
        .into_iter()
        .map(|(_, space)| space.key())
        .collect();
    for key in spaces {
        if MEDIA_VECTOR
            .get(store, txn, &(key, *id))?
            .is_some_and(|row| row.kind == InputKind::Text)
        {
            MEDIA_VECTOR.delete(store, txn, &(key, *id))?;
        }
        MEDIA_REFUSED.delete(store, txn, &(key, *id))?;
    }
    Ok(())
}

/// Removes `id`'s media vectors from every declared space; the delete door calls it beside the
/// text vector row.
pub(crate) fn delete_media_vectors_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let spaces: Vec<[u8; 16]> = EMBEDDING_SPACE
        .scan(store, txn)?
        .into_iter()
        .map(|(_, space)| space.key())
        .collect();
    for key in spaces {
        MEDIA_VECTOR.delete(store, txn, &(key, *id))?;
        MEDIA_REFUSED.delete(store, txn, &(key, *id))?;
    }
    Ok(())
}

/// One space's exact cosine search: every row of `kinds` (all kinds when empty) that `admit`
/// keeps, best first, at most `limit`. Rows of other spaces are never read.
pub(crate) fn search_media_space_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space: &EmbeddingSpace,
    query: &[f32],
    kinds: &[InputKind],
    limit: usize,
    mut admit: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<ScoredEntity>> {
    let query_norm = norm(query);
    if limit == 0 || query_norm == 0.0 {
        return Ok(Vec::new());
    }
    let mut scored = Vec::new();
    for row in MEDIA_VECTOR.iter_from(store, txn, &space.key())? {
        let ((_, id), row) = row?;
        if !kinds.is_empty() && !kinds.contains(&row.kind) {
            continue;
        }
        let vector = decode_vector_row(&row.row, space.dimensions)?;
        let vector_norm = norm(&vector);
        if vector_norm == 0.0 || !admit(&id)? {
            continue;
        }
        let dot: f32 = query.iter().zip(&vector).map(|(a, b)| a * b).sum();
        scored.push(ScoredEntity {
            id,
            score: (dot / (query_norm * vector_norm)).clamp(-1.0, 1.0),
        });
    }
    crate::fusion::sort_scored_entities_desc(&mut scored);
    scored.truncate(limit);
    Ok(scored)
}

fn norm(vector: &[f32]) -> f32 {
    vector.iter().map(|value| value * value).sum::<f32>().sqrt()
}

impl Vault {
    /// Writes, in `wtxn`, each EMBEDDING_SETUP row the side tables no longer match: one per
    /// declared space, a retirement of each space a row declares and the tables no longer do,
    /// and one per kind slot that is bound or has a row. Every writer of a declaration or a
    /// binding calls it last, and hands what it returns to
    /// [`Self::embedding_setup_committed`] once `wtxn` commits.
    pub(super) fn publish_embedding_setup_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        let mut held = BTreeMap::new();
        let ids = self
            .store
            .port_entity_ids_by_type(wtxn, ENTITY_TYPE_EMBEDDING_SETUP, None)?
            .collect::<Result<Vec<_>>>()?;
        for id in ids {
            if let Some(raw) = self.store.port_entity_raw(wtxn, &id)?
                && let Some(data) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                && let Ok(setup) = EmbeddingSetup::decode(data)
            {
                held.insert(id, setup);
            }
        }
        let mut wanted = BTreeMap::new();
        for (_, space) in EMBEDDING_SPACE.scan(&self.store, wtxn)? {
            let setup = EmbeddingSetup::Space(space);
            wanted.insert(setup.id()?, setup);
        }
        for (id, setup) in &held {
            if let EmbeddingSetup::Space(space) = setup
                && !wanted.contains_key(id)
            {
                wanted.insert(
                    *id,
                    EmbeddingSetup::Retired {
                        id: space.id.clone(),
                    },
                );
            }
        }
        let bindings = kind_slot_bindings_in_txn(&self.store, wtxn)?;
        for kind in InputKind::ALL {
            let space = bindings.space_for(kind).map(str::to_owned);
            let bound = space.is_some();
            let setup = EmbeddingSetup::Slot { kind, space };
            let id = setup.id()?;
            if bound || held.contains_key(&id) {
                wanted.insert(id, setup);
            }
        }
        let mut written = BTreeSet::new();
        let mut ops = Vec::new();
        for (id, setup) in wanted {
            if held.get(&id) == Some(&setup) {
                continue;
            }
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_EMBEDDING_SETUP,
                occurred: TimeRange {
                    start: EMBEDDING_SETUP_LEARNED_AT,
                    end: EMBEDDING_SETUP_LEARNED_AT,
                },
                learned_at: EMBEDDING_SETUP_LEARNED_AT,
                data: setup.encode()?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            written.insert(id);
        }
        if !ops.is_empty() {
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
        }
        Ok(written)
    }

    /// Hands the EMBEDDING_SETUP rows a committed write published to the live mirror, so they
    /// reach this vault's other devices, and wakes the media backfill: a space or a binding
    /// may have changed.
    pub(super) fn embedding_setup_committed(&self, rows: BTreeSet<EntityId>) {
        if rows.is_empty() {
            return;
        }
        self.store.notify_attempt_observers();
        #[cfg(feature = "sync")]
        self.note_committed_rows(rows);
        #[cfg(not(feature = "sync"))]
        drop(rows);
    }

    /// Declares (or re-declares) an embedding space. A re-declaration may widen its accepted
    /// inputs or towers but never change its width: a new width is a new space.
    pub fn declare_embedding_space(&self, space: EmbeddingSpace) -> Result<()> {
        space.validate()?;
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(existing) = embedding_space_in_txn(&self.store, &wtxn, &space.id)?
            && existing.dimensions != space.dimensions
        {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} is declared at width {}; a new width is a new space",
                space.id, existing.dimensions
            )));
        }
        EMBEDDING_SPACE.put(&self.store, &mut wtxn, &space.id.clone(), &space)?;
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// Every declared space, in id order.
    pub fn embedding_spaces(&self) -> Result<Vec<EmbeddingSpace>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(EMBEDDING_SPACE
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, space)| space)
            .collect())
    }

    /// The vault's text vector index as a space row: the configured model and width, text in
    /// and a text query tower. Not stored; the vault's own model pin is its identity.
    #[must_use]
    pub fn text_index_space(&self) -> EmbeddingSpace {
        EmbeddingSpace {
            id: self.config.embedding_model.clone().unwrap_or_default(),
            dimensions: self.config.dimensions,
            accepts: BTreeSet::from([InputKind::Text]),
            query_towers: BTreeSet::from([InputKind::Text]),
            evidence: None,
        }
    }

    /// The current kind slot bindings.
    pub fn kind_slot_bindings(&self) -> Result<KindSlotBindings> {
        let rtxn = self.store.env.read_txn()?;
        kind_slot_bindings_in_txn(&self.store, &rtxn)
    }

    /// Binds a kind slot to a declared space that accepts that input. Binding text moves text
    /// documents and text queries off the vault's own index onto that space, so the space also
    /// needs a text query tower ([`Self::bind_one_space_for_all`] binds every slot at once).
    /// A slot an open move carries is refused until the move ends.
    pub fn bind_kind_slot(&self, kind: InputKind, space_id: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(space) = embedding_space_in_txn(&self.store, &wtxn, space_id)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {space_id} is not declared"
            )));
        };
        space.admit_binding(kind)?;
        refuse_moving_slot_in_txn(&self.store, &wtxn, kind)?;
        EMBEDDING_SLOT.put(&self.store, &mut wtxn, &[kind.byte()], &space.id)?;
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// The one-space preset (OF-370; ARCH-0019 `#default-bindings`): binds every kind slot
    /// declared space `space_id` accepts to it, text included, in one write. Text documents then
    /// embed into the space through its media embedder ([`Self::reconcile_media_embeddings`]),
    /// and a server searches a text query there through the space's text tower, in place of the
    /// vault's own index. A declaration only: no stored vector moves, and unbinding the text
    /// slot ([`Self::unbind_kind_slot`]) returns text to the vault's index.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the space is undeclared, does not accept text, or has no
    /// text query tower, or an open move carries a slot it would bind.
    pub fn bind_one_space_for_all(&self, space_id: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(space) = embedding_space_in_txn(&self.store, &wtxn, space_id)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {space_id} is not declared"
            )));
        };
        space.admit_binding(InputKind::Text)?;
        for kind in &space.accepts {
            refuse_moving_slot_in_txn(&self.store, &wtxn, *kind)?;
        }
        for kind in InputKind::ALL {
            if space.accepts.contains(&kind) {
                EMBEDDING_SLOT.put(&self.store, &mut wtxn, &[kind.byte()], &space.id)?;
            }
        }
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// Clears a kind slot's binding; its space keeps its rows. An unbound text slot is the
    /// vault's own index again. A slot an open move carries is refused until the move ends.
    pub fn unbind_kind_slot(&self, kind: InputKind) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        refuse_moving_slot_in_txn(&self.store, &wtxn, kind)?;
        EMBEDDING_SLOT.delete(&self.store, &mut wtxn, &[kind.byte()])?;
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// Stores one host-computed media vector for `id` in `space_id`. A text vector is of the
    /// record's current text, as the text slot embeds it.
    pub fn put_media_vector(
        &self,
        space_id: &str,
        id: &EntityId,
        kind: InputKind,
        vector: &[f32],
    ) -> Result<()> {
        if let Some(error) = Error::invalid_vector_component(vector) {
            return Err(error);
        }
        let mut wtxn = self.store.env.write_txn()?;
        let Some(space) = embedding_space_in_txn(&self.store, &wtxn, space_id)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {space_id} is not declared"
            )));
        };
        if crate::ports::EntityStoreRead::port_entity_record(&self.store, &wtxn, id)?.is_none() {
            return Err(Error::EntityNotFound);
        }
        let text_hash = match kind {
            InputKind::Text => {
                let Some(text) = super::media::text_document_in_txn(self, &wtxn, id)? else {
                    return Err(Error::InvalidConfig(
                        "the record holds no text the text slot embeds".into(),
                    ));
                };
                Some(text_hash(&text))
            }
            InputKind::Image | InputKind::Audio => None,
        };
        let fills = super::space_move::space_fill_kinds_in_txn(&self.store, &wtxn, &space)?;
        put_media_vector_in_txn(
            &self.store,
            &mut wtxn,
            &space,
            &fills,
            id,
            kind,
            text_hash,
            vector,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Retires a declared space no slot binds and no open version move names: its rows and its
    /// declaration go.
    pub fn retire_embedding_space(&self, space_id: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let bindings = kind_slot_bindings_in_txn(&self.store, &wtxn)?;
        if InputKind::ALL
            .iter()
            .any(|kind| bindings.space_for(*kind) == Some(space_id))
        {
            return Err(Error::InvalidConfig(format!(
                "embedding space {space_id} is still bound to a kind slot"
            )));
        }
        if super::space_move::open_move_names_in_txn(&self.store, &wtxn, space_id)? {
            return Err(Error::InvalidConfig(format!(
                "an open embedding space move names {space_id}; conclude or abandon it first"
            )));
        }
        MEDIA_VECTOR.delete_from(&self.store, &mut wtxn, &space_key(space_id))?;
        MEDIA_REFUSED.delete_from(&self.store, &mut wtxn, &space_key(space_id))?;
        EMBEDDING_SPACE.delete(&self.store, &mut wtxn, &space_id.to_owned())?;
        let setup = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(())
    }

    /// How many documents each declared space's model refused, by space id; a space with none
    /// is absent.
    pub fn media_refusal_counts(&self) -> Result<BTreeMap<String, usize>> {
        let rtxn = self.store.env.read_txn()?;
        let mut counts = BTreeMap::new();
        for (id, space) in EMBEDDING_SPACE.scan(&self.store, &rtxn)? {
            let refused = MEDIA_REFUSED
                .scan_keys(&self.store, &rtxn, &space.key())?
                .len();
            if refused > 0 {
                counts.insert(id, refused);
            }
        }
        Ok(counts)
    }

    /// Every document `space_id`'s model refused, in id order.
    pub fn media_refusals(&self, space_id: &str) -> Result<Vec<MediaRefused>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(MEDIA_REFUSED
            .scan_from(&self.store, &rtxn, &space_key(space_id))?
            .into_iter()
            .map(|((_, id), row)| MediaRefused {
                id,
                reason: row.reason,
                at: row.at,
            })
            .collect())
    }

    /// Forgets `space_id`'s refusal of `id` by the owner's hand, so the backfill tries the
    /// same bytes again (a provider whose policy moved, a model swapped behind the rung).
    /// Returns whether a refusal was there.
    pub fn clear_media_refusal(&self, space_id: &str, id: &EntityId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let cleared = MEDIA_REFUSED.delete(&self.store, &mut wtxn, &(space_key(space_id), *id))?;
        wtxn.commit()?;
        Ok(cleared)
    }
}
