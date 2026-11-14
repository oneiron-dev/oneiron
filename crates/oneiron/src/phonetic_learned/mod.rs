//! The learned phonetic rung (CROSS-ARCH-0013 `#ladder` rung 2): a cross-script embedding of
//! each entity name, beside the code rung's postings and never mixed with them or with a text
//! space (ruling EG2-ONE-SPACE: phonetic search stays its own channel).
//!
//! The host binds the model behind [`PhoneticEmbedder`]; the engine names none. The engine reads
//! the names the code rung reads ([`crate::batch::phonetic_codes::names_for_body`], canon `#open`
//! Q3: names only) at the indexed frontier the code rung publishes, hands them to the model
//! outside any transaction ([`crate::Vault::reconcile_phonetic_embeddings`]), and keeps one
//! vector per name. A body change that rebuilds an entity's code postings, and every erasure,
//! drops its vectors in the same transaction, so an erased name leaves no vector.

mod reconcile;
pub(crate) mod tables;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::settings::ReadDestination;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, SideTableDbs};
use crate::store::embedding::EmbedderLocality;
use heed::RwTxn;
use oneiron_base::machine_destination::PeerMachine;

pub use oneiron_store::batch::phonetic_codes::NAMES_PER_ENTITY_CAP;

/// The widest vector a phonetic embedder may return (Symphonym v7 returns 128).
pub const PHONETIC_VECTOR_MAX_DIMENSIONS: usize = 1024;

/// One learned phonetic vector per entity name. Key: id16 + name BLAKE3-16.
pub(crate) const LEARNED_VECTOR: SideTable<(EntityId, [u8; 16]), LearnedVectorRow, Raw> =
    SideTable::new(&side_table::PHONETIC_LEARNED_VECTOR);

/// Host-bound model of the learned rung: names in, one vector per name out.
///
/// It reads raw Unicode (no G2P at run time); the engine sends each name NFC-normalized and
/// otherwise as written.
pub trait PhoneticEmbedder: Send + Sync {
    /// The model's id; a new id makes every stored vector stale.
    fn model_id(&self) -> &str;
    /// The width of every vector, 1..=[`PHONETIC_VECTOR_MAX_DIMENSIONS`].
    fn dimensions(&self) -> usize;
    /// Where the model runs relative to the vault owner.
    fn locality(&self) -> EmbedderLocality;
    /// Where this embedder reads toward: this device for an on-device model, else a destination
    /// nobody proved, as [`crate::store::embedding::Embedder::endpoint`].
    fn endpoint(&self) -> ReadDestination {
        match self.locality() {
            EmbedderLocality::OnDevice => ReadDestination::on_device(),
            EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty => {
                ReadDestination::toward(PeerMachine::Unknown)
            }
        }
    }
    /// One vector per name, in order.
    ///
    /// # Errors
    ///
    /// Any model or transport failure; the pass stores nothing then.
    fn embed_names(&self, names: &[&str]) -> Result<Vec<Vec<f32>>>;
}

/// What one reconcile pass did, counted in names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhoneticEmbedReport {
    /// Named entities read.
    pub scanned: usize,
    /// Names embedded and stored.
    pub embedded: usize,
    /// Names whose vector of this model is stored already.
    pub unchanged: usize,
    /// Names the host's egress gate keeps home, or a device-local world keeps; unsent.
    pub withheld: usize,
    /// Names past [`NAMES_PER_ENTITY_CAP`] of an entity; never embedded.
    pub over_name_cap: usize,
    /// Vectors dropped: of a name the entity no longer has, or replaced under a new model.
    pub removed: usize,
    /// Names that left their entity while the model ran; owed again on the next pass.
    pub vanished: usize,
}

/// A stored vector: the model it is of, and the v1 vector row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LearnedVectorRow {
    pub(crate) model: [u8; 16],
    pub(crate) row: Vec<u8>,
}

impl RawValue for LearnedVectorRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(16 + self.row.len());
        out.extend_from_slice(&self.model);
        out.extend_from_slice(&self.row);
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (model, row) = bytes
            .split_first_chunk::<16>()
            .ok_or(Error::CorruptedIndex("phonetic learned vector row"))?;
        Ok(Self {
            model: *model,
            row: row.to_vec(),
        })
    }
}

/// The key a model's vectors are stored under: BLAKE3-16 of its id and width, so a model whose
/// width changes is a new model.
pub(crate) fn model_key(model_id: &str, dimensions: usize) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron/phonetic_learned/model/v1\0");
    hasher.update(model_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(&u64::try_from(dimensions).unwrap_or(u64::MAX).to_le_bytes());
    first_16(hasher.finalize().as_bytes())
}

/// The key a name's vector is stored under: BLAKE3-16 of the name as it is sent.
pub(crate) fn name_key(name: &str) -> [u8; 16] {
    first_16(blake3::hash(name.as_bytes()).as_bytes())
}

fn first_16(hash: &[u8; 32]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

/// Drops every learned vector of `id`. The code rung's delete door calls it, so the vectors go
/// wherever the entity's code postings go: an erasure, a redaction, and each publication of a
/// changed body, whose names the next reconcile pass embeds again.
pub(crate) fn delete_phonetic_vectors_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<usize> {
    LEARNED_VECTOR.delete_from(store, txn, id.as_bytes())
}
