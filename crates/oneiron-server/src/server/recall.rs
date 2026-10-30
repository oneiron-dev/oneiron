//! The recall verb as every server transport runs it.
//!
//! One place builds recall's execution inputs, so the facade's doors (on
//! HTTP and on a held socket alike), a pumped run's host row and the
//! synchronous door run the same recall for the same request: above light
//! effort the query is embedded whenever the vault's embedder is serving, and
//! the caller's `as_of` rides along. Every door reads as the bound principal
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
use oneiron::llm::run_admission::PayerPerson;
use oneiron::memory::{
    Effort, HomeRecallAsk, HomeRecallCaller, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN,
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryPack,
    MemoryResult, ProducerRows, RecallEffort, complete_with_home,
};
use oneiron::retrieval_depth::RecallQueryVectors;
use oneiron::settings::ReadDestination;
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
    /// Runs `recall` for `memory` with the server's execution inputs. Its
    /// `ai.embed` calls bill `payer`, the funding of the run that recalls
    /// (FIX 805); `None` is the vault owner's.
    ///
    /// Blocking: it may embed the query and it reads the vault. Async callers
    /// take [`Self::recall_off_runtime_listing`]; a synchronous caller that
    /// may sit on a runtime worker wraps it in [`blocking`].
    pub(crate) fn recall(
        &self,
        memory: &Memory<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        input: RecallRequest,
        payer: Option<&PayerPerson>,
    ) -> MemoryResult<MemoryPack> {
        let effort = input.effort.map_or(Effort::Medium, RecallEffort::level);
        let rerank = self.door_rerank(effort, actor, class)?;
        let media = self.recall_media(&input)?;
        let embed = self.recall_embed_media(input.effort, media, payer);
        let arrived = Instant::now();
        let (_, budget) = oneiron::memory::resolve_recall_dial(
            input.effort,
            input.deadline_ms,
            self.vault.call_mode_deadline(),
        )?;
        let hyde =
            self.hyde_host
                .expander(memory, effort, budget.map(|budget| arrived + budget))?;
        let door = RecallDoor {
            arrived,
            hyde: hyde.as_ref().map(|hyde| hyde.binding()),
            rerank: rerank.engine(),
            ..RecallDoor::now()
        };
        oneiron::task_verb::sdk::recall_at_door_seeded(memory, input, embed, &door)
    }

    /// A recall's `media` (OF-370), decoded before any work, as the context
    /// pack decodes its own: the space, the tower its MIME picks and the
    /// bytes. Light effort refuses it ([`LIGHT_RECALL_EMBEDS_MEDIA`]). The
    /// request's kind filter stays on its media-space seed.
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
        crate::api::ContextPackMediaQuery::from(media.clone())
            .decode(self.config.limits.retrieval_query_bytes)
            .map(Some)
            .map_err(media_refusal)
    }

    /// [`Self::recall_embed`] plus the request's decoded `media`, embedded
    /// into its declared space through the context pack's shared seed
    /// embedding once the request is admitted, as the query is. A refused
    /// embedding is the recall's answer at once, before any list runs: the
    /// recall never answers without its media (FIX 2160). Each call bills
    /// `payer`.
    fn recall_embed_media<'a>(
        &'a self,
        effort: Option<RecallEffort>,
        media: Option<DecodedMediaQuery>,
        payer: Option<&'a PayerPerson>,
    ) -> impl FnOnce(&str) -> MemoryResult<RecallQueryVectors> + 'a {
        let embed = self.recall_embed(effort, payer);
        move |query| {
            let mut vectors = embed(query);
            if let Some(media) = media {
                let seeds = self.recall_media_vectors(media, payer)?;
                vectors.media.extend(seeds);
            }
            Ok(vectors)
        }
    }

    /// The media's vectors in its declared space, driven on
    /// [`Self::recall_embed_runtime`], billed to `payer`.
    fn recall_media_vectors(
        &self,
        media: DecodedMediaQuery,
        payer: Option<&PayerPerson>,
    ) -> MemoryResult<Vec<(String, InputKind, Vec<f32>, Vec<InputKind>)>> {
        let Ok(runtime) = self.recall_embed_runtime() else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "vault.recall: no runtime drives the media embedder",
                &["Recall media through the server's async doors."],
            ));
        };
        let seeds = runtime
            .block_on(crate::api::embed_media_seeds_for(
                self,
                Some(media),
                None,
                payer,
            ))
            .map_err(media_refusal)?;
        Ok(seeds
            .into_iter()
            .map(|seed| (seed.space, seed.kind, seed.vector, seed.kinds))
            .collect())
    }

    /// The query embedder recall runs with. Light is pure retrieval with no
    /// model call (ARCH-0044 S6); every other effort embeds the query. When
    /// the text kind slot binds a declared space (the one-space preset), the
    /// query goes through that space's text tower, and the vault's own text
    /// index, which no text search reads then, gets no vector. Otherwise it
    /// embeds on the vault's embedder when that serves. A space's call bills
    /// `payer`.
    fn recall_embed<'a>(
        &'a self,
        effort: Option<RecallEffort>,
        payer: Option<&'a PayerPerson>,
    ) -> impl FnOnce(&str) -> RecallQueryVectors + 'a {
        let embeds = effort.map_or(Effort::Medium, RecallEffort::level) != Effort::Light;
        move |query| {
            if !embeds {
                return RecallQueryVectors::default();
            }
            match self.vault.kind_slot_bindings() {
                Ok(bindings) => {
                    if let Some(space) = bindings.text {
                        let vector = self.recall_slot_vector(&space, query, payer);
                        return RecallQueryVectors {
                            text_index: None,
                            media: vector
                                .map(|vector| (space, InputKind::Text, vector, Vec::new()))
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
    /// [`Self::recall_embed_runtime`], billed to `payer`; `None` when it does
    /// not embed, so recall runs sparse.
    fn recall_slot_vector(
        &self,
        space: &str,
        query: &str,
        payer: Option<&PayerPerson>,
    ) -> Option<Vec<f32>> {
        let runtime = match self.recall_embed_runtime() {
            Ok(handle) => handle,
            Err(error) => {
                tracing::debug!(%space, %error, "recall runs sparse: no runtime drives the text slot's embedder");
                return None;
            }
        };
        let embedded = self.media_embedder(space).and_then(|embedder| {
            runtime.block_on(embedder.funded_by(payer.cloned()).embed_query(
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

    /// [`Self::recall`] for `actor` under the slip it presented, toward
    /// where its connection sits, on the blocking pool. When the request
    /// names a room turn, every read recall makes runs inside that room
    /// (ARCH-0067 §8).
    ///
    /// A request with a deadline answers by it whatever the blocking work is
    /// doing: past it, the door returns the last pack recall published (before
    /// retrieval, no items; once assembled, the items before the scope census;
    /// both `partial`, under the reader's receipt), and the cut work stops at
    /// its next checkpoint.
    ///
    /// Beside the pack come the rows it is derived from without naming them
    /// (a reaction claim a line counts) as recall read them, for a door that
    /// judges the pack again before it leaves this device (DEC-0005). A pack
    /// cut at its deadline comes with the rows read by then.
    /// It asks no home: an opened device's pack says it answered alone. Its
    /// reads go to `destination` (FIX 4937): a locality alone is a
    /// destination nobody proved, as before.
    pub(crate) async fn recall_off_runtime_listing(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        destination: impl Into<ReadDestination>,
        room: Option<EntityId>,
        input: RecallRequest,
    ) -> (MemoryResult<MemoryPack>, Vec<EntityId>) {
        self.recall_home_listing(
            actor,
            class,
            proof,
            destination,
            room,
            input,
            HomeRecallCaller::none(),
        )
        .await
    }

    /// [`Self::recall_off_runtime_listing`] that also asks this device's
    /// home, when it syncs only what it opened (FIX 2905): once the local
    /// pack is ready, and before its deadline, the home is asked for the
    /// references it holds that the pack does not, under `home`, the caller
    /// as its ingress admitted it, and within the residence RPC timeout and
    /// what is left of the deadline. Its hits ride in `residence`, apart
    /// from the local items, which stay as ranked. A pack cut at its
    /// deadline or a refused recall asks nothing; a home out of reach, or a
    /// recall the home cannot answer, leaves the pack local-only and
    /// `partial`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the recall door's parameters plus the caller it asks the home for"
    )]
    pub(crate) async fn recall_home_listing(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        destination: impl Into<ReadDestination>,
        room: Option<EntityId>,
        input: RecallRequest,
        home: HomeRecallCaller,
    ) -> (MemoryResult<MemoryPack>, Vec<EntityId>) {
        let destination: ReadDestination = destination.into();
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
            let ask = HomeRecallAsk::new(&input, room.is_some());
            let ready = CutSlot::default();
            let publish = ready.clone();
            let server = Arc::clone(self);
            // SCAN C030: a recall its door answers at the deadline counts
            // among its caller's deadline jobs until its work ends; past the
            // row it runs on and raises the row's check.
            let job = budget.map(|_| self.vault.admit_deadline_job(actor));
            let work = move || {
                let _job = job;
                let publish = move |pack| publish.put(pack);
                let memory = reader(&server.vault, actor, class, proof.as_ref())
                    .for_destination(&destination)
                    .listing_producers(&listing);
                let hyde = server.hyde_host.expander(
                    &memory,
                    effort,
                    budget.map(|budget| arrived + budget),
                )?;
                let door = RecallDoor {
                    arrived,
                    on_cut: budget.map(|_| &publish as &(dyn Fn(MemoryPack) + Sync)),
                    rerank: rerank.engine(),
                    hyde: hyde.as_ref().map(|hyde| hyde.binding()),
                };
                // A door's own recall is the owner's: no run funds it.
                let embed = server.recall_embed_media(input.effort, media, None);
                match room {
                    Some(room) => memory
                        .for_room_turn(room)?
                        .recall_at_door_seeded(input, embed, &door),
                    None => {
                        oneiron::task_verb::sdk::recall_at_door_seeded(&memory, input, embed, &door)
                    }
                }
            };
            let joined = if effort.requires_rerank() {
                let task = super::recall_hyde::spawn_hyde_recall_oneshot(work);
                match budget {
                    None => task.await.map_err(|error| {
                        tracing::warn!(%error, "recall task failed to join");
                    }),
                    Some(budget) => {
                        let due = tokio::time::Instant::from_std(arrived + budget);
                        match tokio::time::timeout_at(due, task).await {
                            Ok(answer) => answer.map_err(|error| {
                                tracing::warn!(%error, "recall task failed to join");
                            }),
                            Err(_) => return ready.take(),
                        }
                    }
                }
            } else {
                let task = tokio::task::spawn_blocking(work);
                match budget {
                    None => task.await.map_err(|error| {
                        tracing::warn!(%error, "recall task failed to join");
                    }),
                    Some(budget) => {
                        let due = tokio::time::Instant::from_std(arrived + budget);
                        match tokio::time::timeout_at(due, task).await {
                            Ok(answer) => answer.map_err(|error| {
                                tracing::warn!(%error, "recall task failed to join");
                            }),
                            Err(_) => return ready.take(),
                        }
                    }
                }
            };
            let mut pack = joined.unwrap_or_else(|_| Err(recall_did_not_finish()))?;
            let due = budget.map(|budget| arrived + budget);
            if due.is_none_or(|due| Instant::now() < due) {
                complete_with_home(&self.vault, &mut pack, &ask, &home, due).await;
            }
            Ok(pack)
        }
        .await;
        (pack, producers.take())
    }

    /// [`Self::recall`] for `actor` at a synchronous door, which has no
    /// runtime to stop waiting on. A light recall under a
    /// deadline (call mode, or light effort with its own `deadline_ms`) reads
    /// on a thread of its own, and the door waits for it only until the
    /// answer is due, then answers with the last pack recall published. Above
    /// light the query embeds on the server's embedder first, so such a
    /// deadline keeps the engine's cooperative cut.
    ///
    /// Beside the pack come the rows it is derived from without naming them,
    /// as [`Self::recall_off_runtime_listing`] lists them.
    // FIX 11469: kept as the sync door FIX 2060 ruled; no production host calls it yet.
    #[allow(dead_code)]
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

    // FIX 11469: the sync door's own read, kept with it.
    #[allow(dead_code)]
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
            return blocking(|| self.recall(&memory, actor, class, input, None));
        };
        let ready = CutSlot::default();
        let publish = ready.clone();
        let vault = Arc::clone(&self.vault);
        let listing = Arc::clone(producers);
        let (sender, answer) = std::sync::mpsc::sync_channel(1);
        // SCAN C030: the read counts among its caller's deadline jobs until
        // it ends, past the door's answer too; past the row it runs on.
        let job = self.vault.admit_deadline_job(actor);
        std::thread::Builder::new()
            .name("oneiron-recall".to_owned())
            .spawn(move || {
                let _job = job;
                let publish = move |pack| publish.put(pack);
                let door = RecallDoor {
                    arrived,
                    on_cut: Some(&publish),
                    rerank: oneiron::memory::RecallRerank::Required,
                    hyde: None,
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

/// A media query's refusal in the facade's vocabulary: the caller's mistake
/// is `BAD_REQUEST`, a policy refusal `FORBIDDEN`, a space no rung serves
/// `MODEL_UNAVAILABLE`.
fn media_refusal(error: crate::error::ApiError) -> MemoryError {
    use crate::error::ErrorCode;
    let code = match error.code() {
        ErrorCode::BadRequest => MEMORY_CODE_BAD_REQUEST,
        ErrorCode::Forbidden => MEMORY_CODE_FORBIDDEN,
        // The engine's own refusal codes keep their name (FIX 6032).
        code @ (ErrorCode::HostActionRequiresSupportGrant | ErrorCode::OwnerBindingRequired) => {
            code.as_str()
        }
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
