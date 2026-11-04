//! Embedding space, input, provenance and host-provider vocabulary.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::machine_destination::PeerMachine;
use crate::settings::ReadDestination;
use oneiron_base::config::VectorEvidenceFloors;

/// Longest declared space id.
pub const EMBEDDING_SPACE_ID_MAX_LEN: usize = 256;
/// Widest declared space.
pub const EMBEDDING_SPACE_MAX_DIMENSIONS: usize = 8192;
/// The learned (and occurred) time of every EMBEDDING_SETUP row: one fixed instant, so each row
/// lives in one window, `1970-01`, whenever it was last written.
pub const EMBEDDING_SETUP_LEARNED_AT: u64 = 0;

pub use oneiron_store::embedding_vocabulary::InputKind;

/// A declared embedding space: its own pin, its own vector rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[serde(default)]
    pub evidence: Option<VectorEvidenceFloors>,
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
    pub(crate) fn admit_binding(&self, kind: InputKind) -> Result<()> {
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

    pub(crate) fn key(&self) -> [u8; 16] {
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

pub(crate) fn space_key(id: &str) -> [u8; 16] {
    let hash = blake3::hash(id.as_bytes());
    let mut key = [0_u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub(crate) fn validate_space_id(id: &str) -> Result<()> {
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

pub(crate) use oneiron_store::embedding_vocabulary::TEXT_HASH_LEN;

/// Marker set atomically with the first model identity, consumed by cold attach.
pub(crate) const COLD_ATTACH_PENDING_KEY: &[u8] = b"cold_attach_pending";

pub use oneiron_store::embedding_vocabulary::{EmbeddingDevice, EmbeddingProvenance};

/// How many stored vectors one device and runtime computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbeddingProvenanceCount {
    pub device: EmbeddingDevice,
    pub runtime: String,
    pub vectors: u64,
}

/// A cosine is meaningful only in this exact model@revision@where space.
/// These are the floors the retrieval run actually used, before fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingMatchEvidence {
    pub space: String,
    pub embedding_kind: InputKind,
    pub query_kind: InputKind,
    pub score: f32,
    pub floor: f32,
    pub strong: f32,
    pub matched: bool,
}

/// Highest priority: a pending claim surfaced in user-visible retrieval.
pub const EMBED_PRIORITY_SURFACED_HOT: u8 = 0;
/// Server-originated sync materialization.
pub const EMBED_PRIORITY_SERVER: u8 = 1;
/// Local device write.
pub const EMBED_PRIORITY_DEVICE: u8 = 2;
/// Cold attach-embedder or model backfill.
pub const EMBED_PRIORITY_BACKFILL: u8 = 3;

/// Default pending-embedding lease duration.
#[cfg(feature = "sync")]
pub const DEFAULT_PENDING_EMBEDDING_LEASE_MS: u64 = 30_000;

/// Default lease window for remote-routed embed work (E2: remote rungs get
/// longer lease windows). 4x the local default.
#[cfg(feature = "sync")]
pub const DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS: u64 = 120_000;

/// Where an embedder runs relative to the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbedderLocality {
    /// Runs on the same device as the vault.
    OnDevice,
    /// Runs on infrastructure controlled by the vault owner.
    OwnerServer,
    /// Runs on a third-party service.
    ThirdParty,
}

/// Content supplied to an embedder and its egress predicate.
///
/// Match the variant before decoding: CLAIM carries its canonical record,
/// while an epoch SUMMARY and a TURN carry only their already-read text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingEmbeddingPayload {
    /// Canonical MessagePack CLAIM body bytes, without the entity header.
    ClaimBody(Vec<u8>),
    /// UTF-8 prose from a validated epoch-summary body, without framing keys.
    SummaryText(String),
    /// A TURN's text: its visible MESSAGE children's text in message order,
    /// one per line (ARCH-0004: the turn is the embedding unit).
    TurnText(String),
}

/// One pending entity supplied to a host-injected embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEmbeddingInput {
    pub entity_id: EntityId,
    pub payload: PendingEmbeddingPayload,
    /// Commits to the full stored body, not just the embedding payload.
    pub pending_embedding_token: Vec<u8>,
}

/// Host-injected retrieval embedder.
///
/// The engine owns queueing, leases, and vector storage. Implementations own
/// model execution and any locality-specific policy before returning vectors.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    fn locality(&self) -> EmbedderLocality;
    /// Where this embedder reads toward (FIX 5588): this device for an
    /// [`EmbedderLocality::OnDevice`] embedder, else a destination nobody
    /// proved. A host whose model sits behind a host-attested Mesh proof
    /// overrides this with that peer; locality alone never names one.
    fn endpoint(&self) -> ReadDestination {
        match self.locality() {
            EmbedderLocality::OnDevice => ReadDestination::on_device(),
            EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty => {
                ReadDestination::toward(PeerMachine::Unknown)
            }
        }
    }
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>>;
    /// The device and runtime that compute what [`Self::embed`] returns,
    /// stored beside each vector it fills. Unknown unless overridden.
    fn provenance(&self) -> EmbeddingProvenance {
        EmbeddingProvenance::unknown()
    }
    /// [`Self::embed`], each vector with the device and runtime that computed
    /// it. An embedder whose answers name their own (an endpoint that says)
    /// overrides this; any other marks each with [`Self::provenance`].
    fn embed_marked(
        &self,
        inputs: &[PendingEmbeddingInput],
    ) -> Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        let provenance = self.provenance();
        Ok(self
            .embed(inputs)?
            .into_iter()
            .map(|vector| (vector, provenance.clone()))
            .collect())
    }

    /// [`Self::embed_marked`] for an embedder off this device: `release`
    /// judges the rows of each request it sends right before that request
    /// leaves, and a refusal sends nothing and fails the embed. One that
    /// sends a single request needs no more than this default.
    fn embed_released(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[EntityId]) -> Result<()>,
    ) -> Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        let rows: Vec<EntityId> = inputs.iter().map(|input| input.entity_id).collect();
        release(&rows)?;
        self.embed_marked(inputs)
    }
}

/// Tri-state PII egress verdict for one pending entity (ONE-EMBED E6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny,
    NoVerdict,
}

/// Host-supplied egress gate. The OneiroNER PII head's verdict lives
/// host-side; the engine never knows what PII is. Consulted for EVERY
/// entity routed to a non-OnDevice embedder, including epoch summaries.
///
/// Host trait impls invoked under a held txn/lock must be non-blocking
/// cached lookups; hosts run arbitrary inference in the async phases the
/// engine exposes for it.
pub trait EgressPredicate: Send + Sync {
    /// Egress verdict for one typed payload. `Deny` and `NoVerdict` both
    /// route the entity to the local (OnDevice) embedder — fail-closed; a
    /// missing verdict can never send bytes off-device and never stalls
    /// the queue. On a primary rung, with no embedder on this device, they
    /// leave it pending and unsent instead
    /// ([`PendingEmbeddingReconciler::with_primary_rung`], FIX 10009).
    ///
    /// Called under a held write transaction: host trait impls invoked
    /// under a held txn/lock must be non-blocking cached lookups; hosts run
    /// arbitrary inference in the async phases the engine exposes for it.
    /// That transaction may be one group commit shared with other writes:
    /// `decide` must not call into the vault or wait on anything a vault
    /// caller can hold while it writes, or the vault's writer deadlocks.
    fn decide(&self, input: &PendingEmbeddingInput) -> EgressDecision;

    /// Egress verdict for one stored document a third-party media embedder
    /// would read: an ASSET's image or audio bytes, or a record's text
    /// (FIX 382, [`crate::Vault::reconcile_media_embeddings_admitted`]).
    /// Only `Allow` sends it; `Deny` and `NoVerdict` keep it home, unsent,
    /// for a later pass. The default gives no verdict, so a gate written for
    /// the text rung's rows keeps every stored document home.
    ///
    /// Called under a held read transaction: as [`Self::decide`], a
    /// non-blocking cached lookup that never calls into the vault.
    fn decide_media(&self, input: &MediaEmbeddingInput<'_>) -> EgressDecision {
        let _ = input;
        EgressDecision::NoVerdict
    }
}

/// A configured non-OnDevice rung.
#[cfg(feature = "sync")]
pub struct RemoteRung {
    pub embedder: std::sync::Arc<dyn Embedder>,
    pub predicate: std::sync::Arc<dyn EgressPredicate>,
    pub lease_duration_ms: u64,
    /// The full `model@place` route id minted for this rung at build time
    /// (FIX 11768 seam for L05): `None` when built without one (tests,
    /// fixtures, primary rungs), in which case [`Self::offer_id`] is empty
    /// and no ordered world admits it (fail-closed).
    pub offer_id: Option<String>,
}

#[cfg(feature = "sync")]
impl RemoteRung {
    /// Builds a rung with the default remote lease window
    /// ([`DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS`]).
    #[must_use]
    pub fn new(
        embedder: std::sync::Arc<dyn Embedder>,
        predicate: std::sync::Arc<dyn EgressPredicate>,
    ) -> Self {
        Self {
            embedder,
            predicate,
            lease_duration_ms: DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS,
            offer_id: None,
        }
    }

    /// The full `model@place` route id carried from build time (FIX 11768
    /// seam for L05), or empty when none was carried: an unidentified rung
    /// matches no ordered world (fail-closed).
    #[must_use]
    pub fn offer_id(&self) -> String {
        self.offer_id.clone().unwrap_or_default()
    }

    /// Where this rung reads toward (FIX 5588): its embedder's endpoint. The
    /// rung carries no proof of its own, so this never narrows past what the
    /// embedder reports.
    #[must_use]
    pub fn endpoint(&self) -> ReadDestination {
        self.embedder.endpoint()
    }
}

/// One stored media item handed to a media embedder.
#[derive(Debug, Clone, Copy)]
pub struct MediaEmbeddingInput<'a> {
    pub entity_id: EntityId,
    pub kind: InputKind,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
    /// The rows `bytes` are read from (FIX 7001): an ASSET's own row, or a
    /// text document's record and the messages a TURN's text joins. `None`
    /// when they are not known whole.
    pub source_rows: Option<&'a [EntityId]>,
}

impl MediaEmbeddingInput<'_> {
    /// Every row the input's bytes came from, or its own id when unknown.
    #[must_use]
    pub fn source_rows(&self) -> &[EntityId] {
        self.source_rows
            .unwrap_or(std::slice::from_ref(&self.entity_id))
    }
}

/// One document's answer from a media model: its vector with the device and runtime that
/// computed it, stored beside the vector outside the space identity (FIX 7796), or why the
/// model refused that document by its content.
pub type MediaOutcome = std::result::Result<(Vec<f32>, EmbeddingProvenance), String>;

/// A host model that embeds image and audio documents, and on the one-space preset text
/// documents, into one declared space.
pub trait MediaEmbedder: Send + Sync {
    /// The declared space this model's vectors belong to.
    fn space_id(&self) -> &str;
    /// The vector width the model emits; it must equal the space's.
    fn dimensions(&self) -> usize;
    /// Where the model runs. Media bytes leave for a third party from this door only as the
    /// host's egress gate admits each document ([`Vault::reconcile_media_embeddings_admitted`]).
    fn locality(&self) -> EmbedderLocality;
    /// Where this model reads toward (FIX 5588): this device for an
    /// [`EmbedderLocality::OnDevice`] model, else a destination nobody proved.
    /// A host whose model sits behind a host-attested Mesh proof overrides this with that
    /// peer; locality alone never names one.
    fn endpoint(&self) -> ReadDestination {
        match self.locality() {
            EmbedderLocality::OnDevice => ReadDestination::on_device(),
            EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty => {
                ReadDestination::toward(PeerMachine::Unknown)
            }
        }
    }
    /// One vector per input, in input order.
    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<Vec<f32>>>;
    /// One outcome per input, in input order: its vector with the device and runtime its
    /// answer names, or why the model refused that document by its content (a format it
    /// cannot read, a content filter), so the backfill skips it until its bytes change. An
    /// error refuses the whole call. The default refuses no single document and marks each
    /// vector unknown; a model whose answers name their device overrides it.
    fn embed_each(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<MediaOutcome>> {
        Ok(self
            .embed_media(inputs)?
            .into_iter()
            .map(|vector| Ok((vector, EmbeddingProvenance::unknown())))
            .collect())
    }

    /// [`Self::embed_each`] for a model at a third party: `release` judges the documents of
    /// each request right before that request leaves, and a refusal sends nothing more and
    /// fails the call. One that sends a single request needs no more than this default; one
    /// that sends a request per document asks for each.
    fn embed_each_released(
        &self,
        inputs: &[MediaEmbeddingInput<'_>],
        release: &(dyn Fn(&[EntityId]) -> Result<()> + Sync),
    ) -> Result<Vec<MediaOutcome>> {
        let rows: Vec<EntityId> = inputs
            .iter()
            .flat_map(MediaEmbeddingInput::source_rows)
            .copied()
            .collect();
        release(&rows)?;
        self.embed_each(inputs)
    }
}

/// What one media backfill pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaEmbedReport {
    /// ASSETs and text documents read.
    pub scanned: usize,
    /// Vectors stored this pass.
    pub embedded: usize,
    /// Items that already had a vector in the space, a text document one of its current text.
    pub already_embedded: usize,
    /// ASSETs whose media kind is not bound to the embedder's space.
    pub unbound: usize,
    /// ASSETs holding no inline image or audio bytes, and text documents holding no text to
    /// embed.
    pub no_media: usize,
    /// Items deleted, or text documents whose text moved, before their vector landed.
    pub vanished: usize,
    /// Documents the space's model refused by their content, this pass or before at the same
    /// bytes; the backfill skips them until their bytes change.
    pub refused: usize,
    /// Documents a third-party model was not sent: the host's egress gate gave no `Allow`, or
    /// a device-local world keeps them (FIX 382). They stay unsent, for a later pass.
    pub withheld: usize,
}
