//! The recall door: when a recall's clock starts, what it answers when its
//! door stops waiting, and how it serves high, xhigh and max.
use super::sdk::{RecallRequest, VAULT_RECALL_LIMIT_DEFAULT};
use crate::memory::{Memory, MemoryResult};
use crate::retrieval_depth::RecallQueryVectors;

/// When a recall's clock started and what its door does if it stops waiting.
/// A door that can stop waiting at the deadline (an async server door) starts
/// the clock when the request arrives, and answers with the last pack
/// `on_cut` received: the empty one before the query embeds and retrieval
/// runs, then the assembled one before the scope census. Given `on_cut`, the
/// recall takes it that its door answers at the deadline: past it, the recall
/// stops at its next check and returns that first, empty pack, so it burns no
/// time on an answer no one reads.
///
/// `rerank` is how the door serves high, xhigh and max. It is the host's
/// alone: no field of the request names a lease or a reranker.
pub struct RecallDoor<'a> {
    pub arrived: std::time::Instant,
    pub on_cut: Option<&'a (dyn Fn(crate::memory::MemoryPack) + Sync)>,
    pub rerank: crate::memory::RecallRerank<'a>,
}

impl RecallDoor<'_> {
    /// A door that waits for the answer, starts the clock now and refuses a
    /// paid effort, having no reranker to offer it.
    #[must_use]
    pub fn now() -> Self {
        Self {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Required,
        }
    }
}

/// `vault.recall` with a host's query vector. Every SDK door lands here: the
/// generated [`vault.recall`](super::sdk::vault_recall) embeds nothing, and a server
/// whose embedder is serving embeds the query. `embed` runs only once the
/// request is admitted: a request recall refuses (a paid effort, an unknown
/// format or kind, a deadline out of range) costs no vector.
pub fn recall_with_vector(
    memory: &Memory<'_>,
    input: RecallRequest,
    embed: impl FnOnce(&str) -> Option<Vec<f32>>,
) -> MemoryResult<crate::memory::MemoryPack> {
    recall_at_door(memory, input, embed, &RecallDoor::now())
}

/// What a host that embeds nothing says to a recall naming `media`.
pub const RECALL_MEDIA_UNSERVED: &str = "vault.recall: this host serves no ai.embed rung, so it cannot search media; retry without media or recall on a server";

/// `vault.recall` on a host that embeds nothing (an embedded handle): its
/// query recalls as [`recall_with_vector`] with no vector does, and a request
/// naming `media` is refused with the typed `MODEL_UNAVAILABLE`, since no
/// `ai.embed` rung serves its space here. Media is never dropped.
pub fn recall_unembedded(
    memory: &Memory<'_>,
    input: RecallRequest,
) -> MemoryResult<crate::memory::MemoryPack> {
    if input.media.is_some() {
        return Err(crate::memory::MemoryError::new(
            crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
            RECALL_MEDIA_UNSERVED,
            &[
                "Recall media through a server that serves the space's rung under [models.media.embed].",
            ],
        ));
    }
    recall_with_vector(memory, input, |_| None)
}

/// [`recall_with_vector`] whose deadline counts from `door.arrived`. A
/// request with a deadline (call mode, or its own `deadline_ms`) runs under
/// it as a hard cut: the stages yield at it, and the answer holds what was
/// ready, marked partial.
///
/// High, xhigh and max run as `door.rerank` says: refused without a lease
/// and reranker, unreranked and saying so when the host serves none, or
/// reranked by the host's reranker, whose scores apply only to the block
/// they scored (see [`crate::memory::RecallRerankHost`]).
///
/// A limit past [`MAX_SEARCH_LIMIT`](crate::memory::caps::MAX_SEARCH_LIMIT)
/// is served at it, and every pack the door answers with, a cut one
/// included, says so in `retrieval_meta.limit_clamped`.
pub fn recall_at_door(
    memory: &Memory<'_>,
    input: RecallRequest,
    embed: impl FnOnce(&str) -> Option<Vec<f32>>,
    door: &RecallDoor<'_>,
) -> MemoryResult<crate::memory::MemoryPack> {
    recall_at_door_seeded(
        memory,
        input,
        |query| RecallQueryVectors {
            text_index: embed(query),
            media: Vec::new(),
        },
        door,
    )
}

/// [`recall_at_door`] whose host may also embed the query into declared
/// embedding spaces: on the one-space preset the text slot's space, whose
/// list recall then searches for every kind of item it holds (OF-370).
/// `embed` runs only once the request is admitted, as there.
pub fn recall_at_door_seeded(
    memory: &Memory<'_>,
    mut input: RecallRequest,
    embed: impl FnOnce(&str) -> RecallQueryVectors,
    door: &RecallDoor<'_>,
) -> MemoryResult<crate::memory::MemoryPack> {
    let (limit, clamped) =
        crate::memory::caps::clamp_search_limit(input.limit.unwrap_or(VAULT_RECALL_LIMIT_DEFAULT));
    if !clamped {
        return recall_within_ceiling(memory, input, embed, door);
    }
    input.limit = Some(limit);
    let stamp = |mut pack: crate::memory::MemoryPack| {
        pack.retrieval_meta.limit_clamped = true;
        pack
    };
    let on_cut = door
        .on_cut
        .map(|on_cut| move |pack: crate::memory::MemoryPack| on_cut(stamp(pack)));
    let stamped = RecallDoor {
        arrived: door.arrived,
        on_cut: on_cut
            .as_ref()
            .map(|on_cut| on_cut as &(dyn Fn(crate::memory::MemoryPack) + Sync)),
        rerank: door.rerank,
    };
    recall_within_ceiling(memory, input, embed, &stamped).map(stamp)
}

/// [`recall_at_door`] for a limit at or under the ceiling.
fn recall_within_ceiling(
    memory: &Memory<'_>,
    input: RecallRequest,
    embed: impl FnOnce(&str) -> RecallQueryVectors,
    door: &RecallDoor<'_>,
) -> MemoryResult<crate::memory::MemoryPack> {
    use crate::memory::{RecallRerank, RecallRerankHost, RerankReport, RerankSkip};
    let (effort, budget) = crate::memory::resolve_recall_dial(
        input.effort,
        input.deadline_ms,
        memory.call_mode_deadline(),
    )?;
    let scope = input.scope.clone().unwrap_or_default();
    let limit = input.limit.unwrap_or(VAULT_RECALL_LIMIT_DEFAULT);
    crate::memory::caps::check_query(&input.query)?;
    crate::memory::caps::check_limit_nonzero(limit)?;
    // Refused before the query embeds, as every free check is.
    let query_affect = input
        .query_affect
        .map(super::sdk::QueryAffect::vad)
        .transpose()?;
    let host = match door.rerank {
        RecallRerank::Host(host) if effort.requires_rerank() => Some(host),
        _ => None,
    };
    let unreranked = effort.requires_rerank() && matches!(door.rerank, RecallRerank::Unavailable);
    // The host's scores arrive later, for the block they score.
    let preflight = PreflightReranker;
    crate::memory::check_recall_request(
        effort,
        &scope,
        limit,
        input.format.as_deref(),
        host.map(RecallRerankHost::lease),
        &crate::retrieval_depth::RecallExecution {
            as_of: input.as_of,
            query_affect,
            reranker: host.map(|_| &preflight as &dyn crate::rerank::Reranker),
            rerank_unavailable: unreranked,
            ..Default::default()
        },
    )?;
    let deadline =
        budget.map(|budget| crate::retrieval_depth::RetrievalDeadline::hard(door.arrived, budget));
    // A paid effort's packs say what its rerank stage did; one cut before
    // that stage did not rerank.
    let cut_report = if host.is_some() {
        Some(RerankReport::Skipped {
            reason: RerankSkip::Deadline,
        })
    } else {
        unreranked.then_some(RerankReport::Skipped {
            reason: RerankSkip::NoReranker,
        })
    };
    // Before the query embeds: a door whose deadline comes due during the
    // embedding still answers.
    let fallback = door
        .on_cut
        .map(|on_cut| {
            let mut pack = memory.recall_cut_pack(&scope)?;
            pack.retrieval_meta.rerank.clone_from(&cut_report);
            on_cut(pack.clone());
            Ok::<_, crate::memory::MemoryError>(pack)
        })
        .transpose()?;
    let vectors = embed(&input.query);
    let embedding = vectors.text_index.as_deref();
    let media = vectors.media_seeds();
    if let Some(host) = host {
        return memory.recall_reranked_at_door(
            &input,
            effort,
            &scope,
            limit,
            budget,
            embedding,
            &media,
            query_affect,
            door,
            fallback.as_ref(),
            host,
        );
    }
    // A host with no reranker runs the paid expansion unreranked, and every
    // pack it answers with says so.
    let skipped = |pack: &mut crate::memory::MemoryPack| {
        if unreranked {
            pack.retrieval_meta.rerank.clone_from(&cut_report);
        }
    };
    let on_cut = door.on_cut.map(|on_cut| {
        move |mut pack: crate::memory::MemoryPack| {
            skipped(&mut pack);
            on_cut(pack);
        }
    });
    let mut pack = memory.recall_with_execution(
        &input.query,
        effort,
        &scope,
        limit,
        input.format.as_deref(),
        None,
        &crate::retrieval_depth::RecallExecution {
            deadline: deadline.as_ref(),
            embedding,
            media: &media,
            as_of: input.as_of,
            query_affect,
            on_cut: on_cut
                .as_ref()
                .map(|on_cut| on_cut as &(dyn Fn(crate::memory::MemoryPack) + Sync)),
            door_fallback: fallback.as_ref(),
            rerank_unavailable: unreranked,
            ..Default::default()
        },
    )?;
    skipped(&mut pack);
    Ok(pack)
}

/// The reranker a paid request is checked against before it embeds.
struct PreflightReranker;

impl crate::rerank::Reranker for PreflightReranker {
    fn id(&self) -> &str {
        "recall-preflight"
    }

    fn rerank(
        &self,
        _query: &str,
        _candidates: &[crate::rerank::RerankCandidate<'_>],
    ) -> crate::error::Result<Vec<f32>> {
        Err(crate::error::Error::InvalidConfig(
            "the preflight reranker scores nothing".to_owned(),
        ))
    }
}
