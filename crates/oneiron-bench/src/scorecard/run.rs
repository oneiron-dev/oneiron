//! `scorecard run`: replay one pack slice through fresh throwaway vaults, grade the run.
//!
//! Each corpus gets its own vault, each query runs `--repeats` times under the
//! eval clock and weights, and the run is graded into a scorecard file. The
//! sealed slice runs once per experiment: its claim is spent before the slice
//! is opened, so a crash spends it.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use oneiron::pipeline::{BlendWeightsSource, RetrievalEvalSpec};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_ruler::pack::{Corpus, LoadedPack, Slice, load_slice};
use oneiron_ruler::proposal::ProposalStore;
use oneiron_ruler::scorecard::{
    Hit, QueryRun, RepeatRun, RunHeader, build_scorecard, write_scorecard,
};
use oneiron_ruler::sealed::{
    ExperimentIdentity, SealedError, claim_incumbent_once, claim_sealed_once,
};
use sha2::Digest;

use super::{ScorecardFailure, campaign, params, parse_flags, parse_slice, required_flag};

/// The flags `scorecard run` takes.
const KNOWN_FLAGS: &[&str] = &[
    "pack-dir",
    "slice",
    "engine-commit",
    "out",
    "params",
    "budget-rows",
    "repeats",
    "sealed-ledger",
    "campaign",
    "proposal",
    "proposals",
    "incumbent",
];

/// The text field staged beside each TURN body for the text index.
const TEXT_FIELD: &str = "txt";

/// The speaker key of the staged TURN body.
const SPEAKER_FIELD: &str = "spkr";

/// Records committed per batch while filling a pack vault.
const COMMIT_BATCH: usize = 512;

/// The LMDB map of a pack vault: 256 MiB holds any slice with room to spare.
const MAP_SIZE: usize = 256 * 1024 * 1024;

/// Which sealed run this is: the campaign incumbent's once, or a proposal's once.
#[derive(Clone, Copy)]
enum SealedMode<'a> {
    /// The campaign's one incumbent sealed run.
    Incumbent,
    /// A proposal's one sealed run.
    Proposal {
        /// The proposal id.
        id: &'a str,
        /// The proposals dir.
        dir: &'a str,
    },
}

/// Replay one slice into a scorecard file, and report the summary.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let slice_name = required_flag(&flags, "slice")?;
    let slice = parse_slice(slice_name)?;
    if slice == Slice::Sealed {
        return run_sealed(&flags);
    }
    for name in [
        "sealed-ledger",
        "campaign",
        "proposal",
        "proposals",
        "incumbent",
    ] {
        if flags.contains_key(name) {
            return Err(ScorecardFailure::Input(
                "only the sealed slice takes --sealed-ledger/--campaign/--proposal/--incumbent"
                    .to_owned(),
            ));
        }
    }
    let engine_commit = required_flag(&flags, "engine-commit")?;
    check_commit(engine_commit)?;
    let (pack_dir, out, budget_rows, repeats) = replay_flags(&flags)?;
    let loaded = load_slice(Path::new(pack_dir), slice)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let resolved = params::resolve(flags.get("params").map(String::as_str))?;
    replay(&loaded, engine_commit, &resolved, budget_rows, repeats, out)
}

/// Run the sealed slice once, spending its claim before the slice is opened.
fn run_sealed(flags: &BTreeMap<String, String>) -> Result<serde_json::Value, ScorecardFailure> {
    let ledger = required_flag(flags, "sealed-ledger")?;
    let campaign_path = required_flag(flags, "campaign")?;
    let mode = sealed_mode(flags)?;
    let engine_commit = required_flag(flags, "engine-commit")?;
    check_commit(engine_commit)?;
    let resolved = params::resolve(flags.get("params").map(String::as_str))?;
    let campaign = campaign::load_campaign(campaign_path)?;
    let identity = ExperimentIdentity {
        engine_commit: engine_commit.to_owned(),
        params_digest: resolved.digest.clone(),
        pack_digest: campaign.splits.sealed.revision.clone(),
    };
    let (pack_dir, out, budget_rows, repeats) = replay_flags(flags)?;
    if let SealedMode::Proposal { id, dir } = mode {
        let store = ProposalStore::open(Path::new(dir))
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        let listing = store
            .get(id)
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        if listing.sealed.is_some() {
            return Err(ScorecardFailure::Input(
                "proposal already has its sealed outcome".to_owned(),
            ));
        }
        if listing.held_out.campaign_id != campaign.campaign_id {
            return Err(ScorecardFailure::Input(
                "proposal is for another campaign".to_owned(),
            ));
        }
        if listing.held_out.candidate.engine_commit != engine_commit
            || listing.held_out.candidate.params_digest != resolved.digest
        {
            return Err(ScorecardFailure::Input(
                "this run is not the proposal's candidate".to_owned(),
            ));
        }
    }
    let claim = match mode {
        SealedMode::Incumbent => {
            claim_incumbent_once(Path::new(ledger), &campaign.campaign_id, &identity)
        }
        SealedMode::Proposal { .. } => claim_sealed_once(Path::new(ledger), &identity),
    }
    .map_err(map_sealed_error)?;
    let loaded = load_slice(Path::new(pack_dir), Slice::Sealed).map_err(|error| {
        ScorecardFailure::Run(format!(
            "sealed slice load failed: {error}; the sealed run was spent"
        ))
    })?;
    if loaded.pack_digest != campaign.splits.sealed.revision
        || loaded.slice.pack_id != campaign.splits.sealed.dataset_id
    {
        return Err(ScorecardFailure::Run(
            "sealed pack does not match the campaign: the sealed run was spent".to_owned(),
        ));
    }
    if loaded.vectors.is_none() {
        return Err(ScorecardFailure::Run(
            "sealed pack has no vectors: the sealed run was spent".to_owned(),
        ));
    }
    let mut summary = replay(&loaded, engine_commit, &resolved, budget_rows, repeats, out)?;
    if let serde_json::Value::Object(map) = &mut summary {
        map.insert(
            "sealed_claim".to_owned(),
            serde_json::Value::from(claim.path.to_string_lossy().into_owned()),
        );
    }
    Ok(summary)
}

/// Which sealed run the flags ask for: exactly one of `--incumbent` or `--proposal` with `--proposals`.
fn sealed_mode(flags: &BTreeMap<String, String>) -> Result<SealedMode<'_>, ScorecardFailure> {
    let incumbent = flags.get("incumbent").map(String::as_str);
    let proposal = flags.get("proposal").map(String::as_str);
    let proposals = flags.get("proposals").map(String::as_str);
    match (incumbent, proposal, proposals) {
        (Some(value), None, None) => {
            if value != "true" {
                return Err(ScorecardFailure::Input(format!(
                    "--incumbent takes only true, got {value:?}"
                )));
            }
            Ok(SealedMode::Incumbent)
        }
        (None, Some(id), Some(dir)) => Ok(SealedMode::Proposal { id, dir }),
        (None, Some(_), None) => Err(ScorecardFailure::Input(
            "--proposal needs --proposals".to_owned(),
        )),
        (None, None, Some(_)) => Err(ScorecardFailure::Input(
            "--proposals needs --proposal".to_owned(),
        )),
        (None, None, None) => Err(ScorecardFailure::Input(
            "sealed run needs --incumbent true or --proposal ID with --proposals D".to_owned(),
        )),
        _ => Err(ScorecardFailure::Input(
            "sealed run takes exactly one of --incumbent true or --proposal ID with --proposals D"
                .to_owned(),
        )),
    }
}

/// Map a claim failure: a spent run is bad input, IO is a run failure.
fn map_sealed_error(error: SealedError) -> ScorecardFailure {
    let message = error.to_string();
    if matches!(
        error,
        SealedError::AlreadySpent { .. } | SealedError::IncumbentAlreadyMeasured { .. }
    ) {
        ScorecardFailure::Input(message)
    } else {
        ScorecardFailure::Run(message)
    }
}

/// The replay flags every slice takes: pack dir, out path, budget rows, repeats.
fn replay_flags(
    flags: &BTreeMap<String, String>,
) -> Result<(&str, &str, u32, u32), ScorecardFailure> {
    let pack_dir = required_flag(flags, "pack-dir")?;
    let out = required_flag(flags, "out")?;
    let budget_rows = flag_u32(
        flags.get("budget-rows").map(String::as_str),
        "budget-rows",
        20,
        1,
        u32::MAX,
    )?;
    let repeats = flag_u32(
        flags.get("repeats").map(String::as_str),
        "repeats",
        2,
        1,
        10,
    )?;
    Ok((pack_dir, out, budget_rows, repeats))
}

/// Replay one loaded slice into a scorecard file, and report the summary.
fn replay(
    loaded: &LoadedPack,
    engine_commit: &str,
    resolved: &params::ResolvedParams,
    budget_rows: u32,
    repeats: u32,
    out: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    if loaded.vectors.is_none() {
        return Err(ScorecardFailure::Input("run pack-embed first".to_owned()));
    }
    let Some(pin) = loaded.slice.embedding.as_ref() else {
        return Err(ScorecardFailure::Input("run pack-embed first".to_owned()));
    };
    let dims = usize::try_from(pin.dims).map_err(|_| {
        let got = pin.dims;
        ScorecardFailure::Run(format!("pack dims do not fit: {got}"))
    })?;
    let mut ordinal_of: BTreeMap<&str, usize> = BTreeMap::new();
    for (ordinal, record) in loaded.slice.records.iter().enumerate() {
        ordinal_of.insert(record.record_id.as_str(), ordinal);
    }
    let mut queries_by_corpus: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, query) in loaded.slice.queries.iter().enumerate() {
        queries_by_corpus
            .entry(query.corpus_id.as_str())
            .or_default()
            .push(index);
    }
    let mut repeats_of: Vec<Vec<RepeatRun>> = Vec::new();
    repeats_of.resize_with(loaded.slice.queries.len(), Vec::new);
    let limit = usize::try_from(budget_rows).unwrap_or(usize::MAX).max(20);
    for corpus in &loaded.slice.corpora {
        let dir = tempfile::tempdir().map_err(|error| {
            ScorecardFailure::Run(format!("pack vault tempdir failed: {error}"))
        })?;
        let mut config = VaultConfig::device();
        config.dimensions = dims;
        config.embedding_model = Some(pin.model_id.clone());
        config.map_size = MAP_SIZE;
        let vault = Vault::open(dir.path(), config)
            .map_err(|error| ScorecardFailure::Run(format!("pack vault open failed: {error}")))?;
        let ids = ingest(&vault, loaded, corpus, &ordinal_of)?;
        let Some(wanted) = queries_by_corpus.get(corpus.corpus_id.as_str()) else {
            continue;
        };
        for _ in 0..repeats {
            for &query_index in wanted {
                let repeat = run_query(&vault, loaded, query_index, &ids, &resolved.source, limit)?;
                repeats_of[query_index].push(repeat);
            }
        }
    }
    let mut runs = Vec::with_capacity(loaded.slice.queries.len());
    for (index, query) in loaded.slice.queries.iter().enumerate() {
        runs.push(QueryRun {
            query_id: query.query_id.clone(),
            repeats: std::mem::take(&mut repeats_of[index]),
        });
    }
    let header = RunHeader {
        engine_commit: engine_commit.to_owned(),
        params_digest: resolved.digest.clone(),
        budget_rows,
    };
    let scorecard = build_scorecard(&loaded.slice, &loaded.pack_digest, &header, &runs)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    write_scorecard(Path::new(out), &scorecard)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let metrics = serde_json::to_value(&scorecard.metrics)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let slice = loaded.slice.slice.as_str();
    Ok(serde_json::json!({
        "scorecard": out,
        "slice": slice,
        "pack_digest": loaded.pack_digest,
        "params_digest": scorecard.params_digest,
        "engine_commit": scorecard.engine_commit,
        "query_count": scorecard.query_count,
        "repeats": scorecard.repeats,
        "repeat_digest_equal": scorecard.repeat_digest_equal,
        "metrics": metrics,
    }))
}

/// Parse an optional u32 flag with its default and range.
fn flag_u32(
    raw: Option<&str>,
    name: &str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, ScorecardFailure> {
    let Some(text) = raw else {
        return Ok(default);
    };
    let parsed = text.parse::<u32>().map_err(|_| {
        ScorecardFailure::Input(format!("--{name} must be an integer, got {text:?}"))
    })?;
    if !(min..=max).contains(&parsed) {
        return Err(ScorecardFailure::Input(format!(
            "--{name} must be {min}..={max}, got {text:?}"
        )));
    }
    Ok(parsed)
}

/// Refuse an engine commit that is not 40 lowercase hex.
pub(crate) fn check_commit(commit: &str) -> Result<(), ScorecardFailure> {
    let hex = commit.len() == 40
        && commit
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if hex {
        Ok(())
    } else {
        Err(ScorecardFailure::Input(format!(
            "engine commit must be 40 lowercase hex, got {commit:?}"
        )))
    }
}

/// Fill one pack vault with a corpus: every record of every session as a TURN.
fn ingest(
    vault: &Vault,
    loaded: &LoadedPack,
    corpus: &Corpus,
    ordinal_of: &BTreeMap<&str, usize>,
) -> Result<BTreeMap<EntityId, String>, ScorecardFailure> {
    let mut ids = BTreeMap::new();
    let mut batch = vault.batch();
    let mut staged = 0;
    for session in &corpus.sessions {
        let moment = pack_time(&session.time).map_err(ScorecardFailure::Input)?;
        for record_id in &session.record_ids {
            let Some(ordinal) = ordinal_of.get(record_id.as_str()).copied() else {
                let corpus_id = &corpus.corpus_id;
                return Err(ScorecardFailure::Run(format!(
                    "corpus {corpus_id} names a record outside the pack: {record_id}"
                )));
            };
            let record = &loaded.slice.records[ordinal];
            let Some(vector) = loaded.record_vector(ordinal) else {
                return Err(ScorecardFailure::Run(format!(
                    "record {record_id} has no vector"
                )));
            };
            let id = entity_id(record_id)?;
            if let Some(first) = ids.get(&id)
                && first != record_id
            {
                return Err(ScorecardFailure::Run(format!(
                    "record id hash collision: {first} and {record_id}"
                )));
            }
            ids.insert(id, record_id.clone());
            let body = BTreeMap::from([
                (TEXT_FIELD, record.text.as_str()),
                (SPEAKER_FIELD, record.speaker.as_str()),
            ]);
            let bytes = rmp_serde::to_vec_named(&body).map_err(|error| {
                ScorecardFailure::Run(format!("record {record_id} body failed: {error}"))
            })?;
            batch = batch
                .put(
                    &id,
                    ENTITY_TYPE_TURN,
                    TimeRange {
                        start: moment,
                        end: moment,
                    },
                    moment,
                    &bytes,
                )
                .text(&id, &[(TEXT_FIELD, record.text.as_str())])
                .vector(&id, vector);
            staged += 1;
            if staged >= COMMIT_BATCH {
                batch.commit().map_err(|error| {
                    ScorecardFailure::Run(format!("pack vault commit failed: {error}"))
                })?;
                batch = vault.batch();
                staged = 0;
            }
        }
    }
    if staged > 0 {
        batch
            .commit()
            .map_err(|error| ScorecardFailure::Run(format!("pack vault commit failed: {error}")))?;
    }
    Ok(ids)
}

/// The vault id of a record: the first 16 bytes of sha256 over its record id.
fn entity_id(record_id: &str) -> Result<EntityId, ScorecardFailure> {
    let digest = sha2::Sha256::digest(record_id.as_bytes());
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(raw)
        .map_err(|error| ScorecardFailure::Run(format!("record {record_id} id failed: {error}")))
}

/// Run one query once: the eval spec first, then the shipped text and vector
/// stages at the Light effort. Only the build-and-run is timed.
fn run_query(
    vault: &Vault,
    loaded: &LoadedPack,
    query_index: usize,
    ids: &BTreeMap<EntityId, String>,
    weights: &BlendWeightsSource,
    limit: usize,
) -> Result<RepeatRun, ScorecardFailure> {
    let query = &loaded.slice.queries[query_index];
    let now = pack_time(&query.now).map_err(ScorecardFailure::Input)?;
    let spec = RetrievalEvalSpec {
        now,
        weights: weights.clone(),
    };
    let Some(vector) = loaded.query_vector(query_index) else {
        let query_id = &query.query_id;
        return Err(ScorecardFailure::Run(format!(
            "query {query_id} has no vector"
        )));
    };
    let started = Instant::now();
    let scored = vault
        .query()
        .eval_spec(spec)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?
        .search_text(&query.text, limit)
        .search_vector(vector, limit)
        .retrieval_effort(oneiron::memory::Effort::Light, &[])
        .limit(limit)
        .run()
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let search_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let mut hits = Vec::with_capacity(scored.len());
    for row in scored {
        let Some(record_id) = ids.get(&row.id) else {
            let found = row.id.to_hex();
            return Err(ScorecardFailure::Run(format!(
                "vault returned an id outside the pack: {found}"
            )));
        };
        hits.push(Hit {
            record_id: record_id.clone(),
            score_bits: row.score.to_bits(),
        });
    }
    Ok(RepeatRun { hits, search_us })
}

/// Parse pack time (`YYYY-MM-DDTHH:MM:SSZ`) into unix seconds.
fn pack_time(text: &str) -> Result<u64, String> {
    let bad = || format!("bad pack time: {text}");
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(bad());
    }
    for position in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[position].is_ascii_digit() {
            return Err(bad());
        }
    }
    let two = |high: usize, low: usize| -> i64 {
        i64::from(bytes[high] - b'0') * 10 + i64::from(bytes[low] - b'0')
    };
    let year = i64::from(bytes[0] - b'0') * 1000 + i64::from(bytes[1] - b'0') * 100 + two(2, 3);
    let month = two(5, 6);
    let day = two(8, 9);
    let hour = two(11, 12);
    let minute = two(14, 15);
    let second = two(17, 18);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad());
    }
    let total = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(total).map_err(|_| bad())
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted = if month <= 2 { year - 1 } else { year };
    let era = adjusted.div_euclid(400);
    let year_of_era = adjusted.rem_euclid(400);
    let month_prime = (month + 9).rem_euclid(12);
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
