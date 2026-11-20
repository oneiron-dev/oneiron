//! `scorecard run --arm world-scoped`: the retrieval ruler as a world-scoped
//! reader ([SCORECARD-WORLD-SCOPED-ARM]).
//!
//! Each corpus gets its own vault in which a seeded share of the records
//! lands as the owner's claims in a second world and the rest in the base
//! world, and each query runs as an agent whose one Grant reads the base
//! world. The arm grades the scoped text channel alone: BM25 under the
//! agent's world scope through the native credential read, with no vectors
//! and no recency blend, under the eval clock; every claim of a corpus is
//! stamped at the corpus's earliest session, so claim-age decay reorders no
//! hit. So a change to what the agent's term statistics count (#10062:
//! document frequency counts only postings of rows the reader may read)
//! moves its numbers, and an unscoped arm's do not. The run is graded on the readable records alone (see
//! [`partition::grading_view`]); a second-world record served to the agent
//! fails the run. Run it on the search or held_out slice, with the same
//! `--hidden-share` and `--partition-seed` on both builds, then compare the
//! two cards: their pack digests match when the partitions do.

mod fixture;
mod partition;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use oneiron::authority::VerifiedSlip;
use oneiron::pipeline::{BlendWeightsSource, RetrievalEvalSpec};
use oneiron::{EntityId, Vault};
use oneiron_ruler::pack::{LoadedPack, Query};
use oneiron_ruler::scorecard::{
    Hit, QueryRun, RepeatRun, RunHeader, build_keyword_scorecard, write_scorecard,
};
use sha2::Digest;

use crate::scorecard::ScorecardFailure;
use crate::scorecard::run::{flag_u32, pack_time};

use fixture::{AgentVault, Placed};

/// The retriever the card names in place of an embedding model.
const RETRIEVER: &str = "world-scoped-text";

/// The domain of the arm's params digest.
const PARAMS_DOMAIN: &str = "oneiron-bench.scorecard.world-scoped.v1";

/// The default hidden share, per mille: half the records.
const DEFAULT_HIDDEN_SHARE: u32 = 500;

/// The refusal of the sealed slice: the arm measures a statistic change
/// between two builds; it is not a tuning campaign.
pub(super) fn sealed_refusal() -> ScorecardFailure {
    ScorecardFailure::Input(
        "the world-scoped arm runs on the search and held_out slices only".to_owned(),
    )
}

/// The arm's partition flags.
struct Settings {
    /// Per mille of the records that land in the second world (0..=999).
    hidden_share: u32,
    /// The partition seed.
    partition_seed: u32,
}

impl Settings {
    /// `--hidden-share` (default 500) and `--partition-seed` (default 0).
    fn parse(flags: &BTreeMap<String, String>) -> Result<Self, ScorecardFailure> {
        Ok(Self {
            hidden_share: flag_u32(
                flags.get("hidden-share").map(String::as_str),
                "hidden-share",
                DEFAULT_HIDDEN_SHARE,
                0,
                999,
            )?,
            partition_seed: flag_u32(
                flags.get("partition-seed").map(String::as_str),
                "partition-seed",
                0,
                0,
                u32::MAX,
            )?,
        })
    }

    /// The card's params digest: sha256 (hex) over the arm, its retriever and
    /// its partition.
    fn digest(&self) -> String {
        let (share, seed) = (self.hidden_share, self.partition_seed);
        let text = format!(
            "{PARAMS_DOMAIN}\nretriever={RETRIEVER}\n\
             hidden_share_permille={share}\npartition_seed={seed}\n"
        );
        oneiron_hex::encode(&sha2::Sha256::digest(text.as_bytes()))
    }
}

/// Replay one loaded slice through the world-scoped arm into a scorecard
/// file, and report the summary.
pub(super) fn replay(
    loaded: &LoadedPack,
    flags: &BTreeMap<String, String>,
    engine_commit: &str,
    budget_rows: u32,
    repeats: u32,
    out: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    let settings = Settings::parse(flags)?;
    let view = partition::grading_view(
        &loaded.slice,
        settings.partition_seed,
        settings.hidden_share,
    )?;
    let mut ordinal_of: BTreeMap<&str, usize> = BTreeMap::new();
    for (ordinal, record) in loaded.slice.records.iter().enumerate() {
        ordinal_of.insert(record.record_id.as_str(), ordinal);
    }
    let mut queries_by_corpus: BTreeMap<&str, Vec<&Query>> = BTreeMap::new();
    for query in &view.slice.queries {
        queries_by_corpus
            .entry(query.corpus_id.as_str())
            .or_default()
            .push(query);
    }
    let limit = usize::try_from(budget_rows).unwrap_or(usize::MAX);
    let mut repeats_of: BTreeMap<&str, Vec<RepeatRun>> = BTreeMap::new();
    let mut records_written = 0usize;
    // Every corpus is written and its claims checked, also one no kept
    // query reads; only the queries run per graded corpus.
    for corpus in &loaded.slice.corpora {
        // The second world exists from the corpus's earliest session on, and
        // every claim of the corpus is stamped then.
        let mut created_at: Option<u64> = None;
        for session in &corpus.sessions {
            let moment = pack_time(&session.time).map_err(ScorecardFailure::Input)?;
            created_at = Some(created_at.map_or(moment, |earliest| earliest.min(moment)));
        }
        let created_at = created_at.unwrap_or_default();
        let agent_vault = AgentVault::open(created_at)?;
        let placed = agent_vault.ingest(loaded, corpus, &ordinal_of, &view.hidden, created_at)?;
        records_written += placed.len();
        let Some(wanted) = queries_by_corpus.get(corpus.corpus_id.as_str()) else {
            continue;
        };
        let slip = agent_vault.pair_agent()?;
        for _ in 0..repeats {
            for query in wanted {
                let repeat = run_query(agent_vault.vault(), &slip, query, &placed, limit)?;
                repeats_of
                    .entry(query.query_id.as_str())
                    .or_default()
                    .push(repeat);
            }
        }
    }
    let mut runs = Vec::with_capacity(view.slice.queries.len());
    for query in &view.slice.queries {
        runs.push(QueryRun {
            query_id: query.query_id.clone(),
            repeats: repeats_of
                .remove(query.query_id.as_str())
                .unwrap_or_default(),
        });
    }
    let header = RunHeader {
        engine_commit: engine_commit.to_owned(),
        params_digest: settings.digest(),
        budget_rows,
    };
    let scorecard =
        build_keyword_scorecard(&view.slice, &view.pack_digest, &header, &runs, RETRIEVER)
            .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    write_scorecard(Path::new(out), &scorecard)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let metrics = serde_json::to_value(&scorecard.metrics)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    Ok(serde_json::json!({
        "scorecard": out,
        "slice": loaded.slice.slice.as_str(),
        "arm": "world-scoped",
        "retriever": RETRIEVER,
        "hidden_share_permille": settings.hidden_share,
        "partition_seed": settings.partition_seed,
        "partition_digest": view.partition_digest,
        "records_readable": view.readable_count,
        "records_hidden": view.hidden.len(),
        "records_written": records_written,
        "queries_dropped": view.dropped_queries,
        "source_pack_digest": loaded.pack_digest,
        "pack_digest": view.pack_digest,
        "params_digest": scorecard.params_digest,
        "engine_commit": scorecard.engine_commit,
        "query_count": scorecard.query_count,
        "repeats": scorecard.repeats,
        "repeat_digest_equal": scorecard.repeat_digest_equal,
        "metrics": metrics,
    }))
}

/// Run one query once as the agent: its native credential read under the
/// eval clock, text only, no recency blend. Only the read is timed. A
/// second-world record served, or an id outside the corpus, fails the run.
fn run_query(
    vault: &Vault,
    slip: &VerifiedSlip,
    query: &Query,
    placed: &BTreeMap<EntityId, Placed>,
    limit: usize,
) -> Result<RepeatRun, ScorecardFailure> {
    let now = pack_time(&query.now).map_err(ScorecardFailure::Input)?;
    let spec = RetrievalEvalSpec {
        now,
        weights: BlendWeightsSource::LearnedTable,
    };
    let started = Instant::now();
    let scored = vault
        .with_credential_raw_read(slip, |read| {
            read.query(|builder| {
                builder
                    .eval_spec(spec.clone())
                    // A learned-table spec sets no weight override, the one
                    // step of `eval_spec` that can refuse.
                    .expect("a learned-table eval spec is never refused")
                    .search_text(&query.text, limit)
                    .boost_recency(0.0)
                    .limit(limit)
            })
        })
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let search_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let mut hits = Vec::with_capacity(scored.len());
    for row in scored {
        let Some(record) = placed.get(&row.id) else {
            let found = row.id.to_hex();
            return Err(ScorecardFailure::Run(format!(
                "the agent was served an id outside the corpus: {found}"
            )));
        };
        if record.hidden {
            let (query_id, record_id) = (&query.query_id, &record.record_id);
            return Err(ScorecardFailure::Run(format!(
                "query {query_id}: the agent was served a second-world record: {record_id}"
            )));
        }
        hits.push(Hit {
            record_id: record.record_id.clone(),
            score_bits: row.score.to_bits(),
        });
    }
    Ok(RepeatRun { hits, search_us })
}
