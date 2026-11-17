//! `scorecard convert`: LongMemEval-S JSON into pack slices and their split file.
//!
//! The dataset is split by seed, the split is written beside the slices, and
//! each wanted slice converts and writes unpinned.

use std::collections::BTreeMap;

use oneiron_ruler::longmemeval::{
    PackMeta, SliceCounts, convert, draw_split, parse_dataset, split_digest,
};
use oneiron_ruler::pack::{Slice, slice_file_name, write_slice};

use super::{ScorecardFailure, parse_flags, required_flag};

/// The flags `scorecard convert` takes.
const KNOWN_FLAGS: &[&str] = &[
    "dataset",
    "out-dir",
    "seed",
    "search",
    "held-out",
    "sealed",
    "slice",
    "first-of-each-category",
    "pack-id",
    "revision",
];

/// The pack id when `--pack-id` is omitted.
const DEFAULT_PACK_ID: &str = "longmemeval-s";

/// The pack revision when `--revision` is omitted.
const DEFAULT_REVISION: &str = "r1";

/// The source dataset every conversion reads.
const DATASET: &str = "LongMemEval-S";

/// The license the converted manifests carry.
const LICENSE: &str = "MIT";

/// Split the dataset, write the split, and convert each wanted slice.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let dataset = required_flag(&flags, "dataset")?;
    let out_dir = required_flag(&flags, "out-dir")?;
    let seed = required_u64(&flags, "seed")?;
    let counts = SliceCounts {
        search: required_usize(&flags, "search")?,
        held_out: required_usize(&flags, "held-out")?,
        sealed: required_usize(&flags, "sealed")?,
    };
    let slice_arg = flags.get("slice").map_or("all", String::as_str);
    let wanted: Option<Slice> = match slice_arg {
        "all" => None,
        "search" => Some(Slice::Search),
        "held_out" => Some(Slice::HeldOut),
        "sealed" => Some(Slice::Sealed),
        other => {
            return Err(ScorecardFailure::Input(format!("unknown slice: {other}")));
        }
    };
    let categories = flags.get("first-of-each-category").map(String::as_str);
    if categories.is_some() && wanted.is_none() {
        return Err(ScorecardFailure::Input(
            "--first-of-each-category needs a single --slice".to_owned(),
        ));
    }
    let pack_id = flags.get("pack-id").map_or(DEFAULT_PACK_ID, String::as_str);
    let revision = flags
        .get("revision")
        .map_or(DEFAULT_REVISION, String::as_str);
    let bytes = std::fs::read(dataset)
        .map_err(|error| ScorecardFailure::Input(format!("dataset read failed: {error}")))?;
    let dataset_sha256 = oneiron_ruler::pack::sha256_hex(&bytes);
    let questions =
        parse_dataset(&bytes).map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let split = draw_split(&questions, DATASET, &dataset_sha256, seed, counts)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let split_sha256 =
        split_digest(&split).map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let out_path = std::path::Path::new(out_dir);
    std::fs::create_dir_all(out_path)
        .map_err(|error| ScorecardFailure::Run(format!("out dir create failed: {error}")))?;
    let split_path = out_path.join("split.json");
    let mut split_bytes = serde_json::to_vec_pretty(&split)
        .map_err(|error| ScorecardFailure::Run(format!("split encode failed: {error}")))?;
    split_bytes.push(b'\n');
    std::fs::write(&split_path, split_bytes)
        .map_err(|error| ScorecardFailure::Run(format!("split write failed: {error}")))?;
    let meta = PackMeta {
        pack_id: pack_id.to_owned(),
        revision: revision.to_owned(),
        dataset: DATASET.to_owned(),
        dataset_sha256,
        license: LICENSE.to_owned(),
    };
    let slices: Vec<Slice> = match wanted {
        Some(one) => vec![one],
        None => Slice::ALL.to_vec(),
    };
    let mut rows = Vec::with_capacity(slices.len());
    for slice in slices {
        let only: Option<Vec<String>> = match categories {
            Some(list) => {
                let names: Vec<&str> = list.split(',').map(str::trim).collect();
                let found = split.first_of_each_category(slice, &names);
                if found.is_empty() {
                    return Err(ScorecardFailure::Input(format!(
                        "--first-of-each-category matched nothing in slice {slice}"
                    )));
                }
                Some(found)
            }
            None => None,
        };
        let pack = convert(&questions, &split, slice, &meta, only.as_deref())
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        let pack_digest = write_slice(out_path, &pack, None)
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        rows.push(serde_json::json!({
            "slice": slice.as_str(),
            "path": out_path.join(slice_file_name(slice)).display().to_string(),
            "queries": pack.queries.len(),
            "records": pack.records.len(),
            "corpora": pack.corpora.len(),
            "pack_digest": pack_digest,
        }));
    }
    Ok(serde_json::json!({
        "split": split_path.display().to_string(),
        "split_sha256": split_sha256,
        "slices": rows,
    }))
}

/// Parse a required u64 flag.
fn required_u64(flags: &BTreeMap<String, String>, name: &str) -> Result<u64, ScorecardFailure> {
    let raw = required_flag(flags, name)?;
    raw.parse::<u64>().map_err(|_| {
        ScorecardFailure::Input(format!("--{name} must be an unsigned integer, got {raw:?}"))
    })
}

/// Parse a required usize flag.
fn required_usize(flags: &BTreeMap<String, String>, name: &str) -> Result<usize, ScorecardFailure> {
    let raw = required_flag(flags, name)?;
    raw.parse::<usize>().map_err(|_| {
        ScorecardFailure::Input(format!("--{name} must be an unsigned integer, got {raw:?}"))
    })
}
