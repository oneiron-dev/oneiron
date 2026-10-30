//! Recall at high, xhigh and max through a host's reranker (ARCH-0004
//! #rerank: a cross-encoder refines the fused set and never replaces the
//! blend).
//!
//! The engine runs no model under a vault transaction, so a paid recall runs
//! twice. The first pass stops at the rerank stage and keeps the exact block
//! it would rerank: the admitted top-N candidates with their scores, ranks and
//! claim bodies, and the revision each was read at, the one its item is
//! served at (a MESSAGE recall returns as its TURN keeps that TURN's too).
//! A row with no revision that holds its words (a MESSAGE whose words live
//! in its entity document, a TURN whose messages show none) is not
//! reranked: it follows the reranked rows in its first-stage order.
//! Each candidate's text is then read at that revision through the
//! reader's own scoped read, a claim's too, so nothing the reader may no
//! longer read leaves, and the exact text that would leave is judged by the
//! write door once more: a TURN's messages can pass one by one and refuse
//! together. A block none of whose texts holds a word makes no call. The
//! host scores those texts outside every transaction, under its own
//! admission and lease, and runs the device-only verdict again before each
//! request it sends: once it keeps a row that would leave with words,
//! nothing more leaves and the recall ranks by fusion. The second pass runs
//! with the scores as a prepared reranker, which applies them, in its own
//! transaction and before it serves or records anything, only to the same
//! block at the same revisions: a block or a row that changed in between
//! takes none of the scores, and the door scores the new block once more
//! before it refuses. A rerank that stopped short scored a prefix of the
//! block: those scores apply, and the unscored rest stays below them in its
//! fusion order (FIX 11772).
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::selection::RecallPin;
use super::{Effort, MemoryPack, RecallScope};
use crate::batch::export::write_door_refuses_body;
use crate::claim::{ClaimBody, ClaimReadStatus};
use crate::entity_id::EntityId;
use crate::llm::BudgetLease;
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::rerank::crossencoder::PreparedCrossEncoder;
use crate::rerank::{RerankCandidate, Reranker};
use crate::retrieval_depth::{RecallExecution, RecallMediaSeed, RetrievalDeadline};
use crate::task_verb::sdk::{RecallDoor, RecallRequest};

mod lineage;

/// How many times a door scores a block that changed while it was scored
/// before it refuses the recall.
const RERANK_CALLS: u32 = 2;

/// The longest model name a pack repeats from the endpoint that answered.
const SERVED_MODEL_MAX_LEN: usize = 200;

#[cfg(test)]
thread_local! {
    /// A test's write landing once the second pass takes the prepared scores,
    /// before the pack is hydrated: the pass signals the first channel and
    /// waits on the second.
    pub(crate) static PREPARED_SCORES_TAKEN: std::cell::RefCell<
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    > = const { std::cell::RefCell::new(None) };
}

/// How a recall door serves high, xhigh and max.
#[derive(Clone, Copy, Default)]
pub enum RecallRerank<'a> {
    /// The engine's own rule: a paid effort without a lease and a prepared
    /// reranker is refused.
    #[default]
    Required,
    /// The host serves no reranker. A paid effort runs its expansion without
    /// the rerank stage, needs no lease, and its pack says the rerank was
    /// skipped.
    Unavailable,
    /// The host's reranker, under the lease it admitted the recall on.
    Host(&'a dyn RecallRerankHost),
}

/// A host's reranker for paid recall. The engine hands it the block a recall
/// would rerank, outside every vault transaction; the host makes the model
/// call under its own admission and settles it.
pub trait RecallRerankHost: Sync {
    /// The lease the host admitted this recall on.
    fn lease(&self) -> &BudgetLease;

    /// One score per document, in order, higher meaning more relevant to
    /// `query`. `answer_at` is when the recall's door answers, if it has a
    /// deadline. Before each request it sends, a fallback's too, the host
    /// asks `egress` whether the texts may still leave
    /// ([`RerankEgress::holds`]), and sends nothing more once it says no. A
    /// refusal is the recall's: nothing stands in for the model.
    fn score(
        &self,
        query: &str,
        documents: &[RerankDocument<'_>],
        egress: &RerankEgress<'_>,
        answer_at: Option<Instant>,
    ) -> MemoryResult<RerankScores>;

    /// Whether every model `score` can reach runs on this device, in this
    /// process. Only then is it sent the words of a row a device-only world
    /// keeps; any other host is sent such a row empty. A host that cannot
    /// say runs elsewhere.
    fn runs_on_device(&self) -> bool {
        false
    }
}

/// One candidate as its reranker reads it.
pub struct RerankDocument<'a> {
    pub id: EntityId,
    pub text: &'a str,
    /// The rows `text` is read from (FIX 7001): the record, the records it
    /// supersedes and a TURN's messages. `None` when they are not known
    /// whole; an empty text is read from none.
    pub sources: Option<&'a [EntityId]>,
}

/// The rows a block sends with words, judged again before each request a
/// host sends. A request that left before a flag committed stays sent. Once
/// the device-only verdict, run again, keeps any of those rows (its world was
/// flagged since, or it was placed in a flagged world since), nothing more
/// leaves, and the recall ranks by fusion.
pub struct RerankEgress<'a> {
    vault: &'a crate::Vault,
    /// The routes the sent rows' carried worlds allow, in their owner's order.
    model_routes: crate::authority::WorldModelRoutes,
    /// Each row sent with words, and the world its item names at the
    /// revision scored; `None` when the host's model runs on this device,
    /// which is sent every row.
    sent: Option<Vec<(EntityId, Option<EntityId>)>>,
    refused: AtomicBool,
}

impl RerankEgress<'_> {
    /// The model routes the worlds of the rows sent with words allow.
    #[must_use]
    pub fn model_routes(&self) -> &crate::authority::WorldModelRoutes {
        &self.model_routes
    }

    /// Whether the block's texts may still leave this device: the device-only
    /// verdict, run again now, keeps none of the rows sent with words. It
    /// reads as the first verdict did, under the store's flag lock and
    /// outside every transaction; a verdict that cannot be read refuses. Once
    /// it refuses, it refuses for the rest of the call.
    pub fn holds(&self) -> bool {
        let Some(sent) = &self.sent else {
            return true;
        };
        if self.refused() {
            return false;
        }
        let holds = kept_on_device(self.vault, sent).is_ok_and(|kept| kept.is_empty());
        if !holds {
            self.refused.store(true, Ordering::Relaxed);
        }
        holds
    }

    /// Whether [`Self::holds`] has said no.
    pub fn refused(&self) -> bool {
        self.refused.load(Ordering::Relaxed)
    }
}

/// A host's scores for one block, and the model that gave them.
pub struct RerankScores {
    /// One score per candidate, in block order: all of them, or the prefix
    /// a call that stopped short scored (FIX 11772).
    pub scores: Vec<f32>,
    /// The model the host routed the call to.
    pub model: String,
    /// The model the endpoint said answered, when it said.
    pub served_model: Option<String>,
}

/// What the rerank stage of a recall at high, xhigh or max did. Absent below
/// high.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RerankReport {
    /// The host's reranker scored the top block, or the prefix of it a call
    /// that stopped short scored, and the block is in its order, the
    /// unscored rest below in fusion order (FIX 11772).
    Applied {
        /// The model the host routed the call to.
        model: String,
        /// The model the endpoint said answered, when it said.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        served_model: Option<String>,
        /// Candidates scored.
        candidates: usize,
        /// Scoring calls made: two when the block changed during the first.
        calls: u32,
    },
    /// The block is in the engine's own order.
    Skipped { reason: RerankSkip },
}

/// Why a paid recall did not rerank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RerankSkip {
    /// The server serves no reranker.
    NoReranker,
    /// Retrieval found nothing to rerank.
    NoCandidates,
    /// The deadline came before the rerank stage.
    Deadline,
    /// A row sent with words became one a device-only world keeps while the
    /// reranker was called, so nothing more was sent ([`RerankEgress`]). Only
    /// a caller on this device reads this reason; one off it reads the skip
    /// of a pack with nothing to rerank.
    DeviceOnly,
}

/// One block candidate, owned past the transaction that ranked it.
struct BlockCandidate {
    id: EntityId,
    score: f32,
    rank: u32,
    claim: Option<ClaimBody>,
    revision: Option<crate::vault::RevisionRef>,
    turn: Option<(EntityId, crate::vault::RevisionRef)>,
}

impl BlockCandidate {
    fn borrowed(&self) -> RerankCandidate<'_> {
        RerankCandidate {
            id: self.id,
            score: self.score,
            rank: self.rank,
            claim: self.claim.as_ref(),
            revision: self.revision,
            turn: self.turn,
        }
    }
}

/// The first pass's reranker: it keeps the block and stops the recall there,
/// before anything past ranking runs or is written.
#[derive(Default)]
struct BlockCapture {
    block: Mutex<Option<Vec<BlockCandidate>>>,
}

impl BlockCapture {
    fn take(&self) -> Option<Vec<BlockCandidate>> {
        self.block.lock().ok().and_then(|mut block| block.take())
    }
}

impl Reranker for BlockCapture {
    fn id(&self) -> &str {
        "recall-block-capture"
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
    ) -> crate::error::Result<Vec<f32>> {
        let block = candidates
            .iter()
            .map(|candidate| BlockCandidate {
                id: candidate.id,
                score: candidate.score,
                rank: candidate.rank,
                claim: candidate.claim.cloned(),
                revision: candidate.revision,
                turn: candidate.turn,
            })
            .collect();
        if let Ok(mut slot) = self.block.lock() {
            *slot = Some(block);
        }
        Err(crate::error::Error::InvalidConfig(
            "the rerank block is captured; the recall stops here".to_owned(),
        ))
    }

    fn binds_words(&self) -> bool {
        true
    }
}

/// The second pass's reranker: the prepared scores, and whether the recall
/// took them or refused them for a changed block.
struct PreparedBlock {
    prepared: PreparedCrossEncoder,
    applied: AtomicBool,
    stale: AtomicBool,
}

impl Reranker for PreparedBlock {
    fn id(&self) -> &str {
        self.prepared.id()
    }

    fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
    ) -> crate::error::Result<Vec<f32>> {
        let scores = self.prepared.rerank(query, candidates);
        #[cfg(test)]
        if scores.is_ok()
            && let Some((taken, written)) = PREPARED_SCORES_TAKEN.with_borrow_mut(Option::take)
        {
            let _ = taken.send(());
            let _ = written.recv();
        }
        let flag = if scores.is_ok() {
            &self.applied
        } else {
            &self.stale
        };
        flag.store(true, Ordering::Relaxed);
        scores
    }

    fn binds_words(&self) -> bool {
        self.prepared.binds_words()
    }
}

impl Memory<'_> {
    /// A recall at high, xhigh or max whose door brought a reranker; see the
    /// module doc. Every pass reads the one `as_of`, so recency and time
    /// words score both alike, and the one query vector. `pin` is the
    /// door's, which its cut pack and hyde ready pack share (FIX 6693).
    #[expect(
        clippy::too_many_arguments,
        reason = "the door's resolved request: its dial, deadline and query vectors beside it"
    )]
    pub(crate) fn recall_reranked_at_door(
        &self,
        input: &RecallRequest,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        budget: Option<Duration>,
        embedding: Option<&[f32]>,
        media: &[RecallMediaSeed<'_>],
        query_affect: Option<crate::affect::Vad>,
        door: &RecallDoor<'_>,
        fallback: Option<&MemoryPack>,
        host: &dyn RecallRerankHost,
        pin: &RecallPin,
    ) -> MemoryResult<MemoryPack> {
        let as_of = input.as_of.unwrap_or_else(crate::unix_seconds_now);
        let format = input.format.as_deref();
        // Every pass renders under the one budget the request resolves to
        // (FIX 9962).
        let render_budget =
            Some(self.recall_render_budget(input.token_budget, input.reader_agent_ref.as_deref()));
        // Every pass, retry and text read of this recall narrows by the one
        // selection its first pass resolves (FIX 5006), or the door's cut
        // and ready packs before it (FIX 6693).
        let answered = |deadline: Option<&RetrievalDeadline>| {
            fallback.filter(|_| deadline.is_some_and(RetrievalDeadline::answer_due))
        };
        // A pack a door answers with when it stops waiting is partial: the
        // deadline came before the rerank stage. An opened device's
        // residence mark is no such cut (FIX 2905).
        let unreranked = |pack: &MemoryPack| RerankReport::Skipped {
            reason: if pack.cut_short() {
                RerankSkip::Deadline
            } else {
                RerankSkip::NoCandidates
            },
        };
        let cut_first = door.on_cut.map(|on_cut| {
            move |mut pack: MemoryPack| {
                pack.retrieval_meta.rerank = Some(unreranked(&pack));
                on_cut(pack);
            }
        });
        // The paid expansion without its rerank stage.
        let by_fusion = |deadline: Option<&RetrievalDeadline>| {
            self.recall_routed(
                None,
                &input.query,
                effort,
                scope,
                limit,
                format,
                Some(host.lease()),
                None,
                &RecallExecution {
                    hyde: door.hyde,
                    telemetry: input.telemetry.as_ref(),
                    deadline,
                    embedding,
                    media,
                    as_of: Some(as_of),
                    query_affect,
                    on_cut: cut_first
                        .as_ref()
                        .map(|on_cut| on_cut as &(dyn Fn(MemoryPack) + Sync)),
                    door_fallback: fallback,
                    rerank_unavailable: true,
                    render_budget,
                    ..Default::default()
                },
                Some(pin),
            )
        };
        for call in 1..=RERANK_CALLS {
            let deadline = budget.map(|budget| RetrievalDeadline::hard(door.arrived, budget));
            let capture = BlockCapture::default();
            let first = self.recall_routed(
                None,
                &input.query,
                effort,
                scope,
                limit,
                format,
                Some(host.lease()),
                None,
                &RecallExecution {
                    hyde: door.hyde,
                    telemetry: input.telemetry.as_ref(),
                    deadline: deadline.as_ref(),
                    reranker: Some(&capture),
                    embedding,
                    media,
                    as_of: Some(as_of),
                    query_affect,
                    on_cut: cut_first
                        .as_ref()
                        .map(|on_cut| on_cut as &(dyn Fn(MemoryPack) + Sync)),
                    door_fallback: fallback,
                    render_budget,
                    ..Default::default()
                },
                Some(pin),
            );
            let block = match (first, capture.take()) {
                (_, Some(block)) => block,
                // The recall finished without its rerank stage: the deadline
                // came first, or there was nothing to rerank.
                (Ok(mut pack), None) => {
                    pack.retrieval_meta.rerank = Some(unreranked(&pack));
                    return Ok(pack);
                }
                (Err(error), None) => return Err(error),
            };
            let (texts, sources, egress) =
                self.rerank_documents(scope, pin, &block, host.runs_on_device())?;
            if texts.iter().all(String::is_empty) {
                let mut pack = by_fusion(deadline.as_ref())?;
                pack.retrieval_meta.rerank = Some(unreranked(&pack));
                return Ok(pack);
            }
            let documents: Vec<RerankDocument<'_>> = block
                .iter()
                .zip(&texts)
                .zip(&sources)
                .map(|((candidate, text), sources)| RerankDocument {
                    id: candidate.id,
                    text,
                    sources: sources.as_deref(),
                })
                .collect();
            let mut scored = match host.score(
                &input.query,
                &documents,
                &egress,
                deadline.as_ref().map(RetrievalDeadline::answer_at),
            ) {
                Ok(scored) => RerankScores {
                    served_model: scored.served_model.filter(|name| reported_model(name)),
                    ..scored
                },
                Err(_) if egress.refused() => {
                    let mut pack = by_fusion(deadline.as_ref())?;
                    // Only a caller on this device is told why: one off it
                    // reads no hint of a device-local row (DEC-0005).
                    let told = self.locality() == crate::claim::CallerLocality::OnDevice;
                    pack.retrieval_meta.rerank = Some(if pack.cut_short() || !told {
                        unreranked(&pack)
                    } else {
                        RerankReport::Skipped {
                            reason: RerankSkip::DeviceOnly,
                        }
                    });
                    return Ok(pack);
                }
                Err(error) => match answered(deadline.as_ref()) {
                    Some(fallback) => return Ok(fallback.clone()),
                    None => return Err(error),
                },
            };
            // FIX 11772: a call that stopped short scored a prefix of the
            // block; its finished scores apply.
            let scored_count = scored.scores.len();
            if scored_count == 0 || scored_count > block.len() {
                return Err(MemoryError::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    "the reranker's scores do not fit the candidates",
                    &["Check the reranker route's endpoint, or recall at medium."],
                ));
            }
            // A row sent empty was sent nothing to judge: it scores last,
            // whatever the model made of no words.
            for (score, text) in scored.scores.iter_mut().zip(&texts) {
                if text.is_empty() {
                    *score = f32::MIN;
                }
            }
            rank_unscored_below(&mut scored.scores, &texts);
            let candidates: Vec<RerankCandidate<'_>> =
                block.iter().map(BlockCandidate::borrowed).collect();
            let prepared = PreparedBlock {
                prepared: PreparedCrossEncoder::from_scores(
                    &scored.model,
                    &input.query,
                    &candidates,
                    scored.scores,
                )
                .map_err(|_| {
                    MemoryError::new(
                        MEMORY_CODE_MODEL_UNAVAILABLE,
                        "the reranker answered with a score that is not a number",
                        &["Check the reranker route's endpoint, or recall at medium."],
                    )
                })?,
                applied: AtomicBool::new(false),
                stale: AtomicBool::new(false),
            };
            let report = &|pack: &MemoryPack| {
                if prepared.applied.load(Ordering::Relaxed) {
                    RerankReport::Applied {
                        model: scored.model.clone(),
                        served_model: scored.served_model.clone(),
                        candidates: scored_count,
                        calls: call,
                    }
                } else {
                    unreranked(pack)
                }
            };
            // A door that stops waiting during the census answers with this
            // pass's items: they carry the rerank they took.
            let on_cut = door.on_cut.map(|on_cut| {
                move |mut pack: MemoryPack| {
                    pack.retrieval_meta.rerank = Some(report(&pack));
                    on_cut(pack);
                }
            });
            let deadline = budget.map(|budget| RetrievalDeadline::hard(door.arrived, budget));
            let second = self.recall_routed(
                None,
                &input.query,
                effort,
                scope,
                limit,
                format,
                Some(host.lease()),
                None,
                &RecallExecution {
                    hyde: door.hyde,
                    telemetry: input.telemetry.as_ref(),
                    deadline: deadline.as_ref(),
                    reranker: Some(&prepared),
                    embedding,
                    media,
                    as_of: Some(as_of),
                    query_affect,
                    on_cut: on_cut
                        .as_ref()
                        .map(|on_cut| on_cut as &(dyn Fn(MemoryPack) + Sync)),
                    door_fallback: fallback,
                    render_budget,
                    ..Default::default()
                },
                Some(pin),
            );
            match second {
                Ok(mut pack) => {
                    pack.retrieval_meta.rerank = Some(report(&pack));
                    return Ok(pack);
                }
                Err(_) if prepared.stale.load(Ordering::Relaxed) => {
                    if let Some(fallback) = answered(deadline.as_ref()) {
                        return Ok(fallback.clone());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the recall's candidates changed while the reranker scored them",
            &["Retry the recall; the vault was being written to as it ran."],
        ))
    }

    /// Each block candidate's text as this reader's recall shows it, clipped
    /// as its item is, read now through the reader's own scoped read at the
    /// revision the block holds it at: a claim as its predicate and redacted
    /// value, any other row as its words. A row that read no longer admits,
    /// or with no revision to read it at, is sent empty and scores last, as
    /// is a text the write door refuses whole; nothing it holds leaves. So is
    /// a row a device-only world keeps (the vault's own flag, whoever reads),
    /// unless the host's model runs on this device (`on_device`). With the
    /// texts come the rows each is read from (FIX 7001), and the rows that
    /// leave with words, to be judged again. It reads through the recall's
    /// pinned selection (`pin`); the model routes meet the carried worlds
    /// of the rows sent with words (FIX 12313).
    fn rerank_documents(
        &self,
        scope: &RecallScope,
        pin: &RecallPin,
        block: &[BlockCandidate],
        on_device: bool,
    ) -> MemoryResult<(Vec<String>, lineage::DocumentSources, RerankEgress<'_>)> {
        let worlds = self.pinned_recall_worlds(scope, pin)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let lane = match worlds {
            Some(worlds) => lane.within_worlds(worlds),
            None => lane,
        };
        let mut receipt = lane.read_receipt(None, 0)?;
        let mut texts = Vec::with_capacity(block.len());
        let mut sources = Vec::with_capacity(block.len());
        let mut pinned_worlds = Vec::with_capacity(block.len());
        for candidate in block {
            // The block sets a row with no pin aside before it is taken; its
            // words, read now, would be whatever they had become.
            let Some(revision) = candidate.revision else {
                texts.push(String::new());
                sources.push(Some(Vec::new()));
                pinned_worlds.push(None);
                continue;
            };
            let mode = crate::vault::ReadMode::Pinned(revision);
            let item =
                match self.memory_item_for(&lane, &candidate.id, None, mode, &[], &mut receipt) {
                    Ok(item) => item,
                    Err(error) if error.code == MEMORY_CODE_NOT_FOUND => None,
                    Err(error) => return Err(error),
                };
            pinned_worlds.push(
                item.as_ref()
                    .and_then(|item| item.world.as_deref())
                    .and_then(|world| EntityId::from_hex(world).ok()),
            );
            sources.push(match &item {
                Some(item) => lineage::item_source_rows(item),
                None => Some(Vec::new()),
            });
            let text = item.map_or_else(String::new, |item| match item.predicate {
                Some(predicate) => format!("{predicate}: {}", item.value_text),
                None => item.value_text,
            });
            texts.push(if write_door_refuses_body(text.as_bytes()) {
                String::new()
            } else {
                text
            });
        }
        let sent = if on_device {
            None
        } else {
            let with_words: Vec<(EntityId, Option<EntityId>)> = block
                .iter()
                .zip(&pinned_worlds)
                .zip(&texts)
                .filter(|(_, text)| !text.is_empty())
                .map(|((candidate, world), _)| (candidate.id, *world))
                .collect();
            let kept = kept_on_device(self.vault, &with_words)?;
            for (candidate, text) in block.iter().zip(&mut texts) {
                if kept.contains(&candidate.id) {
                    text.clear();
                }
            }
            Some(
                with_words
                    .into_iter()
                    .filter(|(id, _)| !kept.contains(id))
                    .collect(),
            )
        };
        // Only the carried worlds of texts the host actually reads decide its rungs:
        // rows sent empty are no model input, base reality inherits, and an
        // unknown carried world fails closed under an ordered route.
        let rtxn = self.vault.store.env.read_txn()?;
        let mut carried = crate::settings::CarriedWorlds::default();
        for (candidate, text) in block.iter().zip(&texts) {
            if text.is_empty() {
                continue;
            }
            let worlds =
                crate::settings::carried_worlds_in(&self.vault.store, &rtxn, &candidate.id)?;
            carried.absorb(&worlds);
        }
        let mut model_routes = self
            .vault
            .world_model_routes_in_txn(&rtxn, carried.worlds.iter().copied())?;
        if carried.unknown && matches!(&model_routes, crate::authority::WorldModelRoutes::Ordered(_))
        {
            model_routes = crate::authority::WorldModelRoutes::Ordered(Vec::new());
        }
        let egress = RerankEgress {
            vault: self.vault,
            model_routes,
            sent,
            refused: AtomicBool::new(false),
        };
        Ok((texts, sources, egress))
    }
}

/// The rows a device-only world keeps, of `rows`: each a row and the world
/// its item names at the revision scored. Kept is one the judge every read
/// door asks keeps from a caller off this device (a live row a flag
/// withholds, or one whose world cannot be read), or one whose item names a
/// flagged world. A flag commits under
/// the write side of the store's flag lock and this verdict reads under the
/// read side, as a sync release's does, so a flag committed before the
/// verdict is one it read. It only reads the store while it holds the lock:
/// a scoped read can take the writer, which a flag commit holds while it
/// waits.
fn kept_on_device(
    vault: &crate::Vault,
    rows: &[(EntityId, Option<EntityId>)],
) -> crate::Result<BTreeSet<EntityId>> {
    let store = &vault.store;
    let _flags = store
        .device_only_flag_lock
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    let rtxn = store.env.read_txn()?;
    // The reranker sits off this device: a host on it never asks.
    let flagged = crate::settings::device_local_worlds_at(
        vault,
        &rtxn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    let mut kept = BTreeSet::new();
    for (id, world) in rows {
        if world.is_some_and(|world| flagged.contains(&world))
            || crate::settings::device_local_keeps_among(store, &rtxn, &flagged, id)?
        {
            kept.insert(*id);
        }
    }
    Ok(kept)
}

/// Scores for the candidates a rerank that stopped short left unscored
/// (FIX 11772), after the prefix it scored: each below every score the
/// reranker gave and above the empty rows, in fusion order, so the block
/// keeps that order for them; a row sent empty scores last, as a scored
/// one does.
fn rank_unscored_below(scores: &mut Vec<f32>, texts: &[String]) {
    let mut next = scores
        .iter()
        .copied()
        .filter(|score| score.is_finite() && *score > f32::MIN)
        .reduce(f32::min)
        .unwrap_or(0.0);
    for text in texts.iter().skip(scores.len()) {
        if text.is_empty() {
            scores.push(f32::MIN);
        } else {
            next = next.next_down();
            scores.push(next);
        }
    }
}

/// Whether an endpoint's name for the model that answered is one a pack
/// repeats: printable ASCII with no spaces, at most [`SERVED_MODEL_MAX_LEN`]
/// bytes. Anything else is dropped, as though it named none.
fn reported_model(name: &str) -> bool {
    (1..=SERVED_MODEL_MAX_LEN).contains(&name.len())
        && name.bytes().all(|byte| byte.is_ascii_graphic())
}
