//! The recall verb as every server transport runs it.
//!
//! One place builds recall's execution inputs, so the HTTP facade and the
//! WebSocket read RPC run the same recall for the same request: above light
//! effort the query is embedded whenever the vault's embedder is serving, and
//! the caller's `as_of` rides along. Both doors read as the bound principal
//! under the slip it presented (ONE-1187-D6).
//! A vault with no embedder, or one still loading its model, recalls on its
//! sparse signals and says so (`sparse: true`). On the one-space preset the
//! text kind slot binds a declared space, and the query embeds through that
//! space's `ai.embed` rung instead of the vault's own text index (OF-370).
//!
//! A request with a deadline (call mode, or its own `deadline_ms`) is a hard
//! cut here: the async door stops waiting when the answer is due and answers
//! with the best pack ready, so a slow stage, a writer it waits on or a busy
//! blocking pool never holds the turn (retrieval hub #call-mode).
//!
//! High, xhigh and max rerank on the `[models]` reranker under the recall's
//! own budget line ([`super::recall_rerank`]). Without a reranker route they
//! run unreranked and say so; with one, nothing stands in for it.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::authority::VerifiedSlip;
use oneiron::claim::CallerLocality;
use oneiron::embed::InputKind;
use oneiron::memory::{
    Effort, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryPack, MemoryResult, ProducerRows,
    RecallEffort,
};
use oneiron::retrieval_depth::RecallQueryVectors;
use oneiron::task_verb::sdk::{RecallDoor, RecallRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::core::SyncServer;
use crate::api::DecodedMediaQuery;
use crate::embedder::EmbedQueryRefusal;

/// Whether a light recall (call mode included) embeds a request's `media`
/// (OF-370). Light makes no model call (ARCH-0044 S6), so it refuses media
/// rather than recall without it.
const LIGHT_RECALL_EMBEDS_MEDIA: bool = false;

impl SyncServer {
    /// Runs `recall` for `memory` with the server's execution inputs.
    ///
    /// Blocking: it may embed the query and it reads the vault. Async callers
    /// take [`Self::recall_off_runtime`]; a synchronous caller that may sit on
    /// a runtime worker wraps it in [`blocking`].
    pub(crate) fn recall(
        &self,
        memory: &Memory<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        let effort = input.effort.map_or(Effort::Medium, RecallEffort::level);
        let rerank = self.door_rerank(effort, actor, class)?;
        let media = self.recall_media(&input)?;
        let refused = Mutex::new(None);
        let embed = self.recall_embed_media(input.effort, media, &refused);
        let door = RecallDoor {
            rerank: rerank.engine(),
            ..RecallDoor::now()
        };
        let pack = oneiron::task_verb::sdk::recall_at_door_seeded(memory, input, embed, &door);
        media_refused(refused)?;
        pack
    }

    /// A recall's `media` (OF-370), decoded before any work, as the context
    /// pack decodes its own: the space, the tower its MIME picks and the
    /// bytes. Light effort refuses it ([`LIGHT_RECALL_EMBEDS_MEDIA`]), as does
    /// a `kinds` filter, which recall's per-space list does not read.
    fn recall_media(&self, input: &RecallRequest) -> MemoryResult<Option<DecodedMediaQuery>> {
        let Some(media) = input.media.as_ref() else {
            return Ok(None);
        };
        if input.effort.map_or(Effort::Medium, RecallEffort::level) == Effort::Light
            && !LIGHT_RECALL_EMBEDS_MEDIA
        {
            return Err(MemoryError::bad_request_with(
                "vault.recall: media needs an ai.embed call, which light effort and call mode never make",
                &["Recall media at medium effort or above."],
            ));
        }
        if !media.kinds.is_empty() {
            return Err(MemoryError::bad_request_with(
                "vault.recall: media.kinds is not read here; a recall's media list keeps every kind its space holds",
                &["Leave out media.kinds, or narrow with scope.kinds."],
            ));
        }
        crate::api::ContextPackMediaQuery::from(media.clone())
            .decode(self.config.limits.retrieval_query_bytes)
            .map(Some)
            .map_err(media_refusal)
    }

    /// [`Self::recall_embed`] plus the request's decoded `media`, embedded
    /// into its declared space through the context pack's shared seed
    /// embedding once the request is admitted, as the query is. A refused
    /// embedding is kept in `refused` for the door to answer with: the recall
    /// never answers without its media.
    fn recall_embed_media<'a>(
        &'a self,
        effort: Option<RecallEffort>,
        media: Option<DecodedMediaQuery>,
        refused: &'a Mutex<Option<MemoryError>>,
    ) -> impl FnOnce(&str) -> RecallQueryVectors + 'a {
        let embed = self.recall_embed(effort);
        move |query| {
            let mut vectors = embed(query);
            if let Some(media) = media {
                match self.recall_media_vectors(media) {
                    Ok(seeds) => vectors.media.extend(seeds),
                    Err(refusal) => {
                        if let Ok(mut slot) = refused.lock() {
                            *slot = Some(refusal);
                        }
                    }
                }
            }
            vectors
        }
    }

    /// The media's vectors in its declared space, driven on
    /// [`Self::recall_embed_runtime`].
    fn recall_media_vectors(
        &self,
        media: DecodedMediaQuery,
    ) -> MemoryResult<Vec<(String, InputKind, Vec<f32>)>> {
        let Ok(runtime) = self.recall_embed_runtime() else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "vault.recall: no runtime drives the media embedder",
                &["Recall media through the server's async doors."],
            ));
        };
        let seeds = runtime
            .block_on(crate::api::embed_media_seeds(self, Some(media), None))
            .map_err(media_refusal)?;
        Ok(seeds
            .into_iter()
            .map(|seed| (seed.space, seed.kind, seed.vector))
            .collect())
    }

    /// The query embedder recall runs with. Light is pure retrieval with no
    /// model call (ARCH-0044 S6); every other effort embeds the query. When
    /// the text kind slot binds a declared space (the one-space preset), the
    /// query goes through that space's text tower, and the vault's own text
    /// index, which no text search reads then, gets no vector. Otherwise it
    /// embeds on the vault's embedder when that serves.
    fn recall_embed(
        &self,
        effort: Option<RecallEffort>,
    ) -> impl FnOnce(&str) -> RecallQueryVectors + '_ {
        let embeds = effort.map_or(Effort::Medium, RecallEffort::level) != Effort::Light;
        move |query| {
            if !embeds {
                return RecallQueryVectors::default();
            }
            match self.vault.kind_slot_bindings() {
                Ok(bindings) => {
                    if let Some(space) = bindings.text {
                        let vector = self.recall_slot_vector(&space, query);
                        return RecallQueryVectors {
                            text_index: None,
                            media: vector
                                .map(|vector| (space, InputKind::Text, vector))
                                .into_iter()
                                .collect(),
                        };
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "recall reads the text index: the kind slots did not read");
                }
            }
            RecallQueryVectors {
                text_index: self.recall_query_vector(query),
                media: Vec::new(),
            }
        }
    }

    /// The runtime a blocking recall drives its `ai.embed` calls on: the
    /// multi-thread runtime this thread belongs to, else the server's own
    /// call runtime (a current-thread host's blocking work runs on a thread
    /// outside it, and a caller outside any runtime has none).
    fn recall_embed_runtime(&self) -> MemoryResult<tokio::runtime::Handle> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                Ok(handle)
            }
            _ => self.rerank_runtime.handle(),
        }
    }

    /// The query's vector in declared space `space`, through the text tower
    /// of the `ai.embed` rung its id names, driven on
    /// [`Self::recall_embed_runtime`]; `None` when it does not embed, so
    /// recall runs sparse.
    fn recall_slot_vector(&self, space: &str, query: &str) -> Option<Vec<f32>> {
        let runtime = match self.recall_embed_runtime() {
            Ok(handle) => handle,
            Err(error) => {
                tracing::debug!(%space, %error, "recall runs sparse: no runtime drives the text slot's embedder");
                return None;
            }
        };
        let embedded = self.media_embedder(space).and_then(|embedder| {
            runtime.block_on(embedder.embed_query(
                InputKind::Text,
                "text/plain",
                query.as_bytes().to_vec(),
            ))
        });
        match embedded {
            Ok(vector) => Some(vector),
            Err(refusal) => {
                tracing::debug!(%space, %refusal, "recall runs sparse: the query did not embed into the text slot's space");
                None
            }
        }
    }

    /// [`Self::recall`] for `actor` under the slip it presented, from where
    /// its connection sits, on the blocking pool. When the request names a
    /// room turn, every read recall makes runs inside that room (ARCH-0067
    /// §8).
    ///
    /// A request with a deadline answers by it whatever the blocking work is
    /// doing: past it, the door returns the last pack recall published (before
    /// retrieval, no items; once assembled, the items before the scope census;
    /// both `partial`, under the reader's receipt), and the cut work stops at
    /// its next checkpoint.
    pub(crate) async fn recall_off_runtime(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        room: Option<EntityId>,
        input: RecallRequest,
    ) -> MemoryResult<MemoryPack> {
        self.recall_off_runtime_listing(actor, class, proof, locality, room, input)
            .await
            .0
    }

    /// [`Self::recall_off_runtime`], with each row the pack is derived from
    /// without naming it (a reaction claim a line counts) as recall read it,
    /// for a door that judges the pack again before it leaves this device
    /// (DEC-0005). A pack cut at its deadline comes with the rows read by then.
    pub(crate) async fn recall_off_runtime_listing(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        room: Option<EntityId>,
        input: RecallRequest,
    ) -> (MemoryResult<MemoryPack>, Vec<EntityId>) {
        let producers = Arc::new(ProducerRows::default());
        let listing = Arc::clone(&producers);
        let pack: MemoryResult<MemoryPack> = async move {
            let arrived = Instant::now();
            let (effort, budget) = oneiron::memory::resolve_recall_dial(
                input.effort,
                input.deadline_ms,
                self.vault.call_mode_deadline(),
            )?;
            let rerank = self.door_rerank(effort, actor, class)?;
            let media = self.recall_media(&input)?;
            let ready = CutSlot::default();
            let publish = ready.clone();
            let server = Arc::clone(self);
            let task = tokio::task::spawn_blocking(move || {
                let publish = move |pack| publish.put(pack);
                let door = RecallDoor {
                    arrived,
                    on_cut: budget.map(|_| &publish as &(dyn Fn(MemoryPack) + Sync)),
                    rerank: rerank.engine(),
                };
                let memory = reader(&server.vault, actor, class, proof.as_ref())
                    .at(locality)
                    .listing_producers(&listing);
                let refused = Mutex::new(None);
                let embed = server.recall_embed_media(input.effort, media, &refused);
                let answer = match room {
                    Some(room) => memory
                        .for_room_turn(room)?
                        .recall_at_door_seeded(input, embed, &door),
                    None => {
                        oneiron::task_verb::sdk::recall_at_door_seeded(&memory, input, embed, &door)
                    }
                };
                media_refused(refused)?;
                answer
            });
            let joined = match budget {
                None => task.await,
                Some(budget) => {
                    let due = tokio::time::Instant::from_std(arrived + budget);
                    match tokio::time::timeout_at(due, task).await {
                        Ok(joined) => joined,
                        Err(_) => return ready.take(),
                    }
                }
            };
            joined.unwrap_or_else(|error| {
                tracing::warn!(panicked = error.is_panic(), "recall task failed to join");
                Err(recall_did_not_finish())
            })
        }
        .await;
        (pack, producers.take())
    }

    /// [`Self::recall`] for `actor` at a synchronous door (the WebSocket read
    /// RPC), which has no runtime to stop waiting on. A light recall under a
    /// deadline (call mode, or light effort with its own `deadline_ms`) reads
    /// on a thread of its own, and the door waits for it only until the
    /// answer is due, then answers with the last pack recall published. Above
    /// light the query embeds on the server's embedder first, so such a
    /// deadline keeps the engine's cooperative cut.
    ///
    /// Beside the pack come the rows it is derived from without naming them,
    /// as [`Self::recall_off_runtime_listing`] lists them.
    pub(crate) fn recall_at_sync_door(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        input: RecallRequest,
    ) -> (MemoryResult<MemoryPack>, Vec<EntityId>) {
        let producers = Arc::new(ProducerRows::default());
        let pack =
            self.recall_at_sync_door_listing(actor, class, proof, locality, input, &producers);
        (pack, producers.take())
    }

    fn recall_at_sync_door_listing(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        input: RecallRequest,
        producers: &Arc<ProducerRows>,
    ) -> MemoryResult<MemoryPack> {
        let arrived = Instant::now();
        let (effort, budget) = oneiron::memory::resolve_recall_dial(
            input.effort,
            input.deadline_ms,
            self.vault.call_mode_deadline(),
        )?;
        // A recall naming media takes the embedding door, which answers it.
        let Some(budget) = budget.filter(|_| effort == Effort::Light && input.media.is_none())
        else {
            let memory = reader(&self.vault, actor, class, proof.as_ref())
                .at(locality)
                .listing_producers(producers);
            return blocking(|| self.recall(&memory, actor, class, input));
        };
        let ready = CutSlot::default();
        let publish = ready.clone();
        let vault = Arc::clone(&self.vault);
        let listing = Arc::clone(producers);
        let (sender, answer) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("oneiron-recall".to_owned())
            .spawn(move || {
                let publish = move |pack| publish.put(pack);
                let door = RecallDoor {
                    arrived,
                    on_cut: Some(&publish),
                    rerank: oneiron::memory::RecallRerank::Required,
                };
                let memory = reader(&vault, actor, class, proof.as_ref())
                    .at(locality)
                    .listing_producers(&listing);
                // Light effort embeds no query (ARCH-0044 S6).
                let answer =
                    oneiron::task_verb::sdk::recall_at_door(&memory, input, |_| None, &door);
                // The door may have stopped waiting; a closed slot is moot.
                let _ = sender.send(answer);
            })
            .map_err(|_| recall_did_not_finish())?;
        // The wait counts down to the due instant from wherever it starts.
        let due = arrived + budget;
        match blocking(move || answer.recv_timeout(due.saturating_duration_since(Instant::now()))) {
            Ok(answer) => answer,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => ready.take(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(recall_did_not_finish()),
        }
    }

    /// The query's vector, or `None` when no embedder is serving.
    fn recall_query_vector(&self, query: &str) -> Option<Vec<f32>> {
        match self.embedder.as_ref()?.embed_query(query) {
            Ok(vector) => Some(vector),
            // The model is still loading; the worker logs its own progress.
            Err(EmbedQueryRefusal::NotReady | EmbedQueryRefusal::NotConfigured) => None,
            Err(EmbedQueryRefusal::Failed) => {
                tracing::debug!("recall runs sparse: the query did not embed");
                None
            }
        }
    }
}

/// The refusal a recall's media embedding kept, which the door answers with
/// in place of the pack.
fn media_refused(refused: Mutex<Option<MemoryError>>) -> MemoryResult<()> {
    refused.into_inner().ok().flatten().map_or(Ok(()), Err)
}

/// A media query's refusal in the facade's vocabulary: the caller's mistake
/// is `BAD_REQUEST`, a policy refusal `FORBIDDEN`, a space no rung serves
/// `MODEL_UNAVAILABLE`.
fn media_refusal(error: crate::error::ApiError) -> MemoryError {
    use crate::error::ErrorCode;
    let code = match error.code() {
        ErrorCode::BadRequest => MEMORY_CODE_BAD_REQUEST,
        ErrorCode::Forbidden => MEMORY_CODE_FORBIDDEN,
        ErrorCode::EmbedderUnavailable => MEMORY_CODE_MODEL_UNAVAILABLE,
        _ => MEMORY_CODE_INTERNAL,
    };
    let suggestions: Vec<&str> = error.suggestions().iter().map(String::as_str).collect();
    MemoryError::new(
        code,
        format!("vault.recall: {}", error.message()),
        &suggestions,
    )
}

/// `actor`'s memory facade, reading under the slip it presented.
fn reader<'a>(
    vault: &'a oneiron::Vault,
    actor: EntityId,
    class: EdgeActorClass,
    proof: Option<&VerifiedSlip>,
) -> Memory<'a> {
    let memory = vault.memory(actor, class);
    match proof {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    }
}

/// The last pack a recall published for its door to answer with when the
/// deadline comes due; a later pack replaces an earlier one.
#[derive(Clone, Default)]
struct CutSlot(Arc<Mutex<Option<MemoryPack>>>);

impl CutSlot {
    fn put(&self, pack: MemoryPack) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(pack);
        }
    }

    /// The pack the door answers with at the deadline. The read had not
    /// started, so there is not even an empty pack under the reader's receipt.
    fn take(&self) -> MemoryResult<MemoryPack> {
        self.0
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "recall reached its deadline before it could read",
                    &["Retry the call, or allow a longer deadline_ms."],
                )
            })
    }
}

fn recall_did_not_finish() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "recall did not finish",
        &["Retry the call."],
    )
}

/// Runs blocking work from a synchronous caller that may sit on a runtime
/// worker. On a multi-thread runtime worker the worker hands its other tasks
/// to another thread first; inside a current-thread runtime the work runs on
/// a thread of its own, outside the async context; anywhere else it simply
/// runs. Not for use inside a `LocalSet`; [`crate::build_app`] asks hosts
/// not to serve from one.
pub(crate) fn blocking<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(work)
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }),
        Err(_) => work(),
    }
}
