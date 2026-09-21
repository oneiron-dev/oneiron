//! Strict E1 selection-receipt and evaluation-cohort schemas. Host claims, parsed hard.
//!
//! These types parse evidence the host hands over; they never claim a bake-off
//! ran, that the corpus audio was real meetings, or that consent was checked.
//! A scorer output over fixture tokens (see `metrics.rs`) is not a measured
//! receipt, and parsing a receipt is not running the evaluation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::metrics::{WerCounts, aggregate_wer};
use super::{AudioError, AudioResult};

/// One E1 arm: a candidate model id plus its exact per-language WER counts.
/// Keys are opaque language tags from the corpus manifest; the engine never
/// invents an arm for a language the corpus did not score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E1Arm {
    pub model_id: String,
    pub model_revision: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub wer_by_lang: HashMap<String, WerCountsSerde>,
}

/// Exact per-language WER counts in receipt form. Integer counts only; a
/// float WER ratio is not accepted because rounding hides the arm sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WerCountsSerde {
    pub substitutions: u64,
    pub deletions: u64,
    pub insertions: u64,
    pub reference_len: u64,
}

impl From<WerCountsSerde> for WerCounts {
    fn from(counts: WerCountsSerde) -> Self {
        Self {
            substitutions: counts.substitutions,
            deletions: counts.deletions,
            insertions: counts.insertions,
            reference_len: counts.reference_len,
        }
    }
}

/// Strict E1 batch-default selection receipt. `corpus_sha256` binds the exact
/// corpus manifest the arms were scored on; `winner` must name one of `arms`.
/// Unknown JSON fields are rejected so a producer cannot smuggle in an
/// unauthenticated model-selection authority beside the pinned receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E1SelectionReceipt {
    pub corpus_id: String,
    pub corpus_sha256: String,
    pub arms: Vec<E1Arm>,
    pub winner: String,
}

impl E1SelectionReceipt {
    /// Parse and strictly validate one receipt document. Blanks, an empty arm
    /// list, a winner naming no arm, a non-hex corpus hash, and an arm with no
    /// language entry all fail. Cross-corpus binding is the caller's next
    /// check: compare [`E1SelectionReceipt::corpus_sha256`] against the hash of
    /// the corpus manifest actually scored before trusting `winner`.
    pub fn parse(json: &str) -> AudioResult<Self> {
        let receipt: Self =
            serde_json::from_str(json).map_err(|_| AudioError::InvalidEvaluationReceipt)?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> AudioResult<()> {
        if self.corpus_id.trim().is_empty()
            || self.winner.trim().is_empty()
            || self.arms.is_empty()
            || !is_lower_hex_sha256(&self.corpus_sha256)
        {
            return Err(AudioError::InvalidEvaluationReceipt);
        }
        let mut seen_models = std::collections::HashSet::new();
        let mut winner_arms = 0;
        for arm in &self.arms {
            if arm.model_id.trim().is_empty()
                || arm.model_revision.trim().is_empty()
                || !is_lower_hex_sha256(&arm.model_sha256)
                || !is_lower_hex_sha256(&arm.runtime_sha256)
                || arm.wer_by_lang.is_empty()
                || arm.wer_by_lang.len() > 256
                || !seen_models.insert(arm.model_id.as_str())
            {
                return Err(AudioError::InvalidEvaluationReceipt);
            }
            for (lang, counts) in &arm.wer_by_lang {
                if lang.trim().is_empty()
                    || counts.reference_len == 0
                    || u128::from(counts.substitutions) + u128::from(counts.deletions)
                        > u128::from(counts.reference_len)
                    || counts.reference_len > u64::MAX / 256
                {
                    return Err(AudioError::InvalidEvaluationReceipt);
                }
                // Reject absurd receipts whose error counts could not fit a
                // saturating aggregate; computed in u128 so the check itself
                // cannot overflow on hostile input.
                let errors = u128::from(counts.substitutions)
                    + u128::from(counts.deletions)
                    + u128::from(counts.insertions);
                if errors > u128::from(u64::MAX / 256) {
                    return Err(AudioError::InvalidEvaluationReceipt);
                }
            }
            if arm.model_id == self.winner {
                winner_arms += 1;
            }
        }
        if winner_arms != 1 {
            return Err(AudioError::InvalidEvaluationReceipt);
        }
        Ok(())
    }

    /// Exact aggregate WER counts for the winning arm across its languages.
    pub fn winner_totals(&self) -> AudioResult<WerCounts> {
        self.validate()?;
        let arm = self
            .arms
            .iter()
            .find(|arm| arm.model_id == self.winner)
            .ok_or(AudioError::InvalidEvaluationReceipt)?;
        Ok(aggregate_wer(
            &arm.wer_by_lang
                .values()
                .map(|counts| WerCounts::from(*counts))
                .collect::<Vec<_>>(),
        ))
    }
    /// Data binding only; this does not authenticate an OF-133 selection act.
    pub fn validate_for_cohort(&self, cohort: &CohortManifest) -> AudioResult<()> {
        self.validate()?;
        cohort.validate()?;
        if self.corpus_id != cohort.corpus_id || self.corpus_sha256 != cohort.cohort_sha256 {
            return Err(AudioError::InvalidEvaluationReceipt);
        }
        let baseline = &self.arms[0].wer_by_lang;
        for arm in &self.arms {
            if arm.wer_by_lang.len() != baseline.len()
                || baseline.iter().any(|(lang, counts)| {
                    arm.wer_by_lang
                        .get(lang)
                        .is_none_or(|other| other.reference_len != counts.reference_len)
                })
            {
                return Err(AudioError::InvalidEvaluationReceipt);
            }
        }
        Ok(())
    }
}

/// One labelled E3 cohort file: source audio hash, reference transcript hash,
/// and the consent record the host checked before scoring. The engine binds
/// hashes; consent itself stays a host-side record referenced, never attested,
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortFile {
    pub file_id: String,
    pub audio_sha256: String,
    pub reference_sha256: String,
    pub consent_ref: String,
}

/// Strict evaluation-cohort manifest. `cohort_sha256` binds the exact file
/// list; an E1 receipt names this manifest hash in its `corpus_sha256` when
/// the bake-off actually scored this cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortManifest {
    pub corpus_id: String,
    pub cohort_sha256: String,
    pub files: Vec<CohortFile>,
}

impl CohortManifest {
    /// Parse and strictly validate one cohort manifest. Blank ids, an empty
    /// file list, duplicate file ids, and non-hex hashes all fail.
    pub fn parse(json: &str) -> AudioResult<Self> {
        let manifest: Self =
            serde_json::from_str(json).map_err(|_| AudioError::InvalidCohortManifest)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn computed_hash(&self) -> AudioResult<String> {
        use sha2::{Digest, Sha256};
        let mut files: Vec<_> = self.files.iter().collect();
        files.sort_by(|a, b| a.file_id.cmp(&b.file_id));
        let bytes = serde_json::to_vec(&(&self.corpus_id, files))
            .map_err(|_| AudioError::InvalidCohortManifest)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    fn validate(&self) -> AudioResult<()> {
        if self.corpus_id.trim().is_empty()
            || !is_lower_hex_sha256(&self.cohort_sha256)
            || self.files.is_empty()
            || self.files.len() > 4096
            || self.cohort_sha256 != self.computed_hash()?
        {
            return Err(AudioError::InvalidCohortManifest);
        }
        let mut seen = std::collections::HashSet::new();
        for file in &self.files {
            if file.file_id.trim().is_empty()
                || file.consent_ref.trim().is_empty()
                || !is_lower_hex_sha256(&file.audio_sha256)
                || !is_lower_hex_sha256(&file.reference_sha256)
                || !seen.insert(file.file_id.as_str())
            {
                return Err(AudioError::InvalidCohortManifest);
            }
        }
        Ok(())
    }
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
