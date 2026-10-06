//! The frozen held-out rule. The adapter sets `split`; the bench recomputes
//! it here and refuses any record whose split disagrees.
//!
//! The split unit is the vault unit, so no unit is ever half seen: a shared
//! corpus (`corpus_ref.corpus_id`: a BEAM chat, a LoCoMo conversation, a
//! LongMemEval-S haystack) or, for an inline corpus, the question itself.
//!
//! ```text
//! digest = blake3("oneiron-bench.split.v1" 0x00 dataset.id 0x00 unit 0x00 salt)
//! bucket = (first 8 digest bytes as big-endian u64 * 100) >> 64     // 0..=99
//! split  = dev if bucket < dev_percent(dataset.id) else heldout
//! ```
//!
//! The salt and shares are committed here and mirrored byte-for-byte in
//! oneiron-eval `oneiron_eval/split.py`. Changing either is a new rule id.
use super::report_model::{ContractSplit, RunContractRecord};
use super::{BeamResult, util::invalid_run_jsonl};
use std::path::Path;

pub(super) const SPLIT_RULE_ID: &str = "oneiron-bench.split.v1";
pub(super) const SPLIT_SALT: &str = "oneiron-bench/heldout-salt/2026-10-06";
pub(super) const DEFAULT_DEV_PERCENT: u64 = 20;
/// Sets whose dev share is not 20% (plan section 5).
const DEV_PERCENT_OVERRIDES: &[(&str, u64)] = &[("memoryagentbench-conflict", 25)];

pub(super) fn dev_percent(dataset_id: &str) -> u64 {
    DEV_PERCENT_OVERRIDES
        .iter()
        .find(|(id, _)| *id == dataset_id)
        .map_or(DEFAULT_DEV_PERCENT, |(_, percent)| *percent)
}

/// The unit's bucket in `0..100`.
pub(super) fn split_bucket(dataset_id: &str, unit: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    for (index, part) in [SPLIT_RULE_ID, dataset_id, unit, SPLIT_SALT]
        .iter()
        .enumerate()
    {
        if index > 0 {
            hasher.update(&[0]);
        }
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    ((u128::from(u64::from_be_bytes(head)) * 100) >> 64) as u64
}

pub(super) fn expected_split(dataset_id: &str, unit: &str) -> ContractSplit {
    if split_bucket(dataset_id, unit) < dev_percent(dataset_id) {
        ContractSplit::Dev
    } else {
        ContractSplit::Heldout
    }
}

/// The leak-proof unit a record's split is drawn over.
pub(super) fn split_unit(record: &RunContractRecord) -> &str {
    record
        .corpus_ref
        .as_ref()
        .map_or(record.question_id.as_str(), |corpus_ref| {
            corpus_ref.corpus_id.as_str()
        })
}

/// Refuses a record whose declared split is not the frozen rule's.
pub(super) fn recheck_split(
    path: &Path,
    line: usize,
    record: &RunContractRecord,
) -> BeamResult<()> {
    let Some(declared) = record.split else {
        return Ok(());
    };
    let unit = split_unit(record);
    let expected = expected_split(&record.dataset.id, unit);
    if declared != expected {
        return Err(invalid_run_jsonl(
            path,
            line,
            format!(
                "split `{}` disagrees with the frozen rule {SPLIT_RULE_ID}: dataset `{}` unit `{unit}` is `{}` (bucket {} of 100, dev below {})",
                declared.as_str(),
                record.dataset.id,
                expected.as_str(),
                split_bucket(&record.dataset.id, unit),
                dev_percent(&record.dataset.id)
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language vectors: oneiron-eval tests/test_split.py asserts the
    /// same buckets.
    #[test]
    fn frozen_rule_vectors_match_the_eval_mirror() {
        assert_eq!(split_bucket("locomo", "conv-26"), 90);
        assert_eq!(split_bucket("locomo", "conv-42"), 8);
        assert_eq!(split_bucket("locomo", "conv-50"), 3);
        let dev: Vec<_> = [
            "conv-26", "conv-30", "conv-41", "conv-42", "conv-43", "conv-44", "conv-47", "conv-48",
            "conv-49", "conv-50",
        ]
        .into_iter()
        .filter(|unit| expected_split("locomo", unit) == ContractSplit::Dev)
        .collect();
        assert_eq!(
            dev,
            ["conv-42", "conv-50"],
            "2 of 10 LoCoMo conversations are dev"
        );
    }

    #[test]
    fn dev_share_is_twenty_percent_with_set_overrides() {
        assert_eq!(dev_percent("longmemeval-s"), 20);
        assert_eq!(dev_percent("memoryagentbench-conflict"), 25);
        let dev = (0..10_000)
            .filter(|n| expected_split("longmemeval-s", &format!("q{n}")) == ContractSplit::Dev)
            .count();
        assert!((1_800..2_200).contains(&dev), "{dev} of 10000");
    }
}
