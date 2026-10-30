//! The vectors an off-record room's epoch summary and turns carry (ARCH-0052
//! K6). A room keeps no `pe:` queue, so its content embeds inline or has no
//! vector: the run's own pass embeds the accepted summary off the step loop,
//! the server pre-embeds a turn before the witness lands it, and each overlay
//! mint stages that vector with the row, in its one transaction. With no
//! embedder on this device, or one that fails, the summary or turn lands
//! searchable by its words alone: compaction and witness never wait on a
//! retrieval model, and a room's words never go to one off the device.

use std::sync::Arc;

use crate::batch::BatchOp;
use crate::embed::{
    Embedder, EmbedderLocality, EmbeddingProvenance, PendingEmbeddingInput, PendingEmbeddingPayload,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::gate::GatedCompaction;

/// Where an embedder must run to read an off-record room's summary (calls
/// review: room epoch vectors). A room's words stay on the device that holds
/// the room; one on any other locality leaves the summary unembedded.
const ROOM_EMBEDDER_LOCALITY: EmbedderLocality = EmbedderLocality::OnDevice;

/// Where a room's run finds the embedder its epoch summaries take vectors
/// from: the host's configured one.
pub trait EpochEmbedder: Send + Sync {
    /// The embedder serving now, once the vault has admitted its model and
    /// space; `None` while none is.
    fn serving(&self) -> Option<Arc<dyn Embedder>>;
}

/// One accepted summary's vector, and the device and runtime that computed
/// it. It rides the [`GatedCompaction`] whose prose it embeds, so it cannot
/// reach another summary's mint.
#[derive(Debug, Clone)]
pub(crate) struct EpochVector {
    vector: Vec<f32>,
    provenance: EmbeddingProvenance,
}

impl PartialEq for EpochVector {
    fn eq(&self, other: &Self) -> bool {
        self.provenance == other.provenance
            && self.vector.len() == other.vector.len()
            && self
                .vector
                .iter()
                .zip(&other.vector)
                .all(|(left, right)| left.to_bits() == right.to_bits())
    }
}

impl Eq for EpochVector {}

impl GatedCompaction {
    /// Embeds the accepted summary for a room's mint. Runs in the pass's own
    /// flight, never under a writer; a miss leaves the summary to land
    /// without a vector.
    pub(crate) fn embed_for_room(&mut self, embedder: &dyn EpochEmbedder) {
        match room_vector(
            embedder,
            &self.request.session_ref,
            &self.product.summary_text,
        ) {
            Ok(vector) => self.vector = vector,
            Err(error) => tracing::warn!(
                ?error,
                "a room's epoch summary was not embedded; it lands searchable by its words"
            ),
        }
    }
}

/// `text`'s vector from the serving embedder, when one serves on this
/// device. The input names the compaction session the summary is born into:
/// the row's own id is minted only with the row, and an on-device embedder
/// reads the payload alone.
fn room_vector(
    embedder: &dyn EpochEmbedder,
    session_ref: &EntityId,
    text: &str,
) -> Result<Option<EpochVector>> {
    let Some(embedder) = embedder.serving() else {
        return Ok(None);
    };
    if embedder.locality() != ROOM_EMBEDDER_LOCALITY {
        return Ok(None);
    }
    let mut answers = embedder
        .embed_marked(&[PendingEmbeddingInput {
            entity_id: *session_ref,
            payload: PendingEmbeddingPayload::SummaryText(text.to_owned()),
            pending_embedding_token: blake3::hash(text.as_bytes()).as_bytes().to_vec(),
        }])?
        .into_iter();
    let (Some((vector, provenance)), None) = (answers.next(), answers.next()) else {
        return Err(Error::InvariantViolation(
            "an embedder answered one room summary with other than one vector",
        ));
    };
    if vector.len() != embedder.dimensions() {
        return Err(Error::DimensionMismatch {
            expected: embedder.dimensions(),
            got: vector.len(),
        });
    }
    Ok(Some(EpochVector { vector, provenance }))
}

/// The overlay op staging `vector` as `summary_id`'s, beside its text. A
/// summary with a source withdrawn before the mint takes none: what its
/// words say must not turn findable by meaning once a source of them is
/// gone. The overlay's own staging holds the vault's width.
pub(super) fn room_vector_op(
    vector: Option<&EpochVector>,
    summary_id: EntityId,
    withdrawn: bool,
) -> Option<BatchOp> {
    let vector = vector.filter(|_| !withdrawn)?;
    Some(BatchOp::Vector {
        id: summary_id,
        vector: vector.vector.clone(),
        pending_embedding_token: None,
        provenance: Some(vector.provenance.clone()),
    })
}

// FIX 3817 (a): the room-turn twin of the epoch-summary path above. The
// server pre-embeds the turn's text and hands the witness an optional
// `TurnVector`; no server or error means `None`, and the turn lands
// searchable by its words alone.

/// One room turn's vector, and the device and runtime that computed it. The
/// mechanical twin of [`EpochVector`]: it rides the witness call it is handed
/// to, so it cannot reach another turn's mint.
#[derive(Debug, Clone)]
pub(crate) struct TurnVector {
    vector: Vec<f32>,
    provenance: EmbeddingProvenance,
}

/// `text`'s vector from the serving embedder, when one serves on this
/// device. The twin of `room_vector` for a room turn: `None` when the turn
/// holds nothing to embed, when no embedder serves, or when the serving
/// embedder runs anywhere but on this device. The input names the turn the
/// vector is staged under.
pub(crate) fn room_turn_vector(
    embedder: &dyn EpochEmbedder,
    turn_id: &EntityId,
    text: &str,
) -> Result<Option<TurnVector>> {
    if !text.chars().any(|c| !c.is_whitespace() && !c.is_control()) {
        return Ok(None);
    }
    let Some(embedder) = embedder.serving() else {
        return Ok(None);
    };
    if embedder.locality() != ROOM_EMBEDDER_LOCALITY {
        return Ok(None);
    }
    let mut answers = embedder
        .embed_marked(&[PendingEmbeddingInput {
            entity_id: *turn_id,
            payload: PendingEmbeddingPayload::TurnText(text.to_owned()),
            pending_embedding_token: blake3::hash(text.as_bytes()).as_bytes().to_vec(),
        }])?
        .into_iter();
    let (Some((vector, provenance)), None) = (answers.next(), answers.next()) else {
        return Err(Error::InvariantViolation(
            "an embedder answered one room turn with other than one vector",
        ));
    };
    if vector.len() != embedder.dimensions() {
        return Err(Error::DimensionMismatch {
            expected: embedder.dimensions(),
            got: vector.len(),
        });
    }
    Ok(Some(TurnVector { vector, provenance }))
}

/// The overlay op staging `vector` as `turn_id`'s, beside its text. The twin
/// of `room_vector_op` for a room turn, with no withdrawal input: exactly one
/// [`BatchOp::Vector`] when a vector was embedded. A turn's stale vector
/// hides behind its body's change until a fresh one lands, and the promote
/// re-mark replaces whatever rode up. The overlay's own staging holds the
/// vault's width.
pub(crate) fn turn_vector_op(vector: Option<&TurnVector>, turn_id: EntityId) -> Option<BatchOp> {
    let vector = vector?;
    Some(BatchOp::Vector {
        id: turn_id,
        vector: vector.vector.clone(),
        pending_embedding_token: None,
        provenance: Some(vector.provenance.clone()),
    })
}
