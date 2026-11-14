//! `scorecard convert-trec`: TREC-shaped collections into pack slices.
//!
//! The manifest names every split's topics, qrels and passages with their
//! sha256; each split converts into its slice, unpinned.

use std::collections::BTreeMap;

use oneiron_ruler::longmemeval::PackMeta;
use oneiron_ruler::pack::{Slice, slice_file_name, write_slice};
use oneiron_ruler::trec_collection::{
    Fill, TrecError, TrecSplit, convert, default_slice, parse_passages, parse_qrels, parse_topics,
    split_digest,
};

use super::{ScorecardFailure, parse_flags, required_flag};

/// The flags `scorecard convert-trec` takes.
const KNOWN_FLAGS: &[&str] = &["manifest", "out-dir", "fill-seed", "fill-per-corpus"];

/// The contract string every TREC collection manifest carries.
const MANIFEST_CONTRACT: &str = "oneiron.trec_collection_manifest.v1";

/// One manifest split: its names, its time, and its three files with their sha256.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSplit {
    collection: String,
    language: String,
    split: String,
    time: String,
    topics: String,
    topics_sha256: String,
    qrels: String,
    qrels_sha256: String,
    passages: String,
    passages_sha256: String,
}

/// A TREC collection manifest.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    contract: String,
    pack_id: String,
    revision: String,
    dataset: String,
    license: String,
    splits: Vec<ManifestSplit>,
}

/// Convert every manifest split into its slice, and report the rows.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let manifest_path = required_flag(&flags, "manifest")?;
    let out_dir = required_flag(&flags, "out-dir")?;
    let fill = parse_fill(&flags)?;
    let manifest_bytes = std::fs::read(manifest_path)
        .map_err(|error| ScorecardFailure::Input(format!("manifest read failed: {error}")))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ScorecardFailure::Input(format!("manifest parse failed: {error}")))?;
    let contract = manifest.contract.as_str();
    if contract != MANIFEST_CONTRACT {
        return Err(ScorecardFailure::Input(format!(
            "wrong contract: {contract}"
        )));
    }
    if manifest.splits.is_empty() {
        return Err(ScorecardFailure::Input("manifest has no splits".to_owned()));
    }
    let manifest_dir = std::path::Path::new(manifest_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let mut splits = Vec::with_capacity(manifest.splits.len());
    for entry in &manifest.splits {
        let slice =
            default_slice(entry.collection.as_str(), entry.split.as_str()).ok_or_else(|| {
                let collection = entry.collection.as_str();
                let split = entry.split.as_str();
                ScorecardFailure::Input(format!("split {collection}/{split} maps to no slice"))
            })?;
        let topics_bytes = read_named(
            manifest_dir,
            entry.topics.as_str(),
            entry.topics_sha256.as_str(),
            "topics",
        )?;
        let qrels_bytes = read_named(
            manifest_dir,
            entry.qrels.as_str(),
            entry.qrels_sha256.as_str(),
            "qrels",
        )?;
        let passages_bytes = read_named(
            manifest_dir,
            entry.passages.as_str(),
            entry.passages_sha256.as_str(),
            "passages",
        )?;
        let topics = parse_topics(&topics_bytes).map_err(map_trec)?;
        let qrels = parse_qrels(&qrels_bytes).map_err(map_trec)?;
        let passages = parse_passages(&passages_bytes).map_err(map_trec)?;
        splits.push(TrecSplit {
            slice,
            collection: entry.collection.clone(),
            language: entry.language.clone(),
            split: entry.split.clone(),
            time: entry.time.clone(),
            topics,
            qrels,
            passages,
        });
    }
    let meta = PackMeta {
        pack_id: manifest.pack_id.clone(),
        revision: manifest.revision.clone(),
        dataset: manifest.dataset.clone(),
        dataset_sha256: oneiron_ruler::pack::sha256_hex(&manifest_bytes),
        license: manifest.license.clone(),
    };
    let split_sha256 = split_digest(&splits).map_err(map_trec)?;
    let out_path = std::path::Path::new(out_dir);
    std::fs::create_dir_all(out_path)
        .map_err(|error| ScorecardFailure::Run(format!("out dir create failed: {error}")))?;
    let mut rows = Vec::new();
    for slice in Slice::ALL {
        if !splits.iter().any(|split| split.slice == slice) {
            continue;
        }
        let converted = convert(&splits, slice, &meta, fill).map_err(map_trec)?;
        let pack = converted.pack;
        let pack_digest = write_slice(out_path, &pack, None)
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        rows.push(serde_json::json!({
            "slice": slice.as_str(),
            "path": out_path.join(slice_file_name(slice)).display().to_string(),
            "queries": pack.queries.len(),
            "records": pack.records.len(),
            "corpora": pack.corpora.len(),
            "pack_digest": pack_digest,
            "left_out": converted.left_out,
        }));
    }
    Ok(serde_json::json!({
        "split_sha256": split_sha256,
        "slices": rows,
    }))
}

/// Read one manifest file: relative, inside the manifest dir, matching its sha256.
fn read_named(
    manifest_dir: &std::path::Path,
    name: &str,
    expected: &str,
    what: &str,
) -> Result<Vec<u8>, ScorecardFailure> {
    let relative = std::path::Path::new(name);
    if relative.is_absolute() {
        return Err(ScorecardFailure::Input(format!(
            "{what} path is absolute: {name}"
        )));
    }
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ScorecardFailure::Input(format!(
            "{what} path leaves the manifest dir: {name}"
        )));
    }
    let path = manifest_dir.join(relative);
    let bytes = std::fs::read(&path).map_err(|error| {
        let display = path.display().to_string();
        ScorecardFailure::Input(format!("{what} read failed at {display}: {error}"))
    })?;
    let found = oneiron_ruler::pack::sha256_hex(&bytes);
    if found != expected {
        let display = path.display().to_string();
        return Err(ScorecardFailure::Input(format!(
            "{what} sha256 mismatch at {display}"
        )));
    }
    Ok(bytes)
}

/// The `--fill-seed`/`--fill-per-corpus` pair: both or neither.
fn parse_fill(flags: &BTreeMap<String, String>) -> Result<Option<Fill>, ScorecardFailure> {
    let seed = flags.get("fill-seed").map(String::as_str);
    let per_corpus = flags.get("fill-per-corpus").map(String::as_str);
    match (seed, per_corpus) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(ScorecardFailure::Input(
            "--fill-seed needs --fill-per-corpus".to_owned(),
        )),
        (None, Some(_)) => Err(ScorecardFailure::Input(
            "--fill-per-corpus needs --fill-seed".to_owned(),
        )),
        (Some(seed), Some(per_corpus)) => {
            let seed = seed.parse::<u64>().map_err(|_| {
                ScorecardFailure::Input(format!(
                    "--fill-seed must be an unsigned integer, got {seed:?}"
                ))
            })?;
            let per_corpus = per_corpus.parse::<usize>().map_err(|_| {
                ScorecardFailure::Input(format!(
                    "--fill-per-corpus must be an unsigned integer, got {per_corpus:?}"
                ))
            })?;
            Ok(Some(Fill { seed, per_corpus }))
        }
    }
}

/// Map a TREC failure: every collection read or conversion failure is bad input.
fn map_trec(error: TrecError) -> ScorecardFailure {
    ScorecardFailure::Input(error.to_string())
}
