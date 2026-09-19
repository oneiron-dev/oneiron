//! Offline evaluation of recorded outputs. Never runs inference or grants a default.
use super::{
    AudioError, AudioResult, CohortManifest, E1Arm, E1SelectionReceipt, E3Score, WerCountsSerde,
    e3_score, wer_counts,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
const MAX_ARMS: usize = 16;
const MAX_WORDS: usize = 20_000;
const MAX_ALIGNMENT_CELLS: usize = 4_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceDocument {
    pub file_id: String,
    pub json: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordCluster {
    pub word_id: String,
    pub cluster: String,
}
/// Tokenization and word correspondence are corpus data, not guessed by the scorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelledReference {
    pub language: String,
    pub tokenizer: String,
    pub tokens: Vec<String>,
    pub speakers: Vec<WordCluster>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedFile {
    pub file_id: String,
    pub tokens: Vec<String>,
    pub speakers: Vec<WordCluster>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedArm {
    pub model_id: String,
    pub model_revision: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub files: Vec<RecordedFile>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeakerScore {
    pub correct: u64,
    pub wrong_speaker: u64,
    pub missing_words: u64,
    pub extra_words: u64,
}
impl From<E3Score> for SpeakerScore {
    fn from(score: E3Score) -> Self {
        Self {
            correct: score.correct,
            wrong_speaker: score.wrong_speaker,
            missing_words: score.missing_words,
            extra_words: score.extra_words,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEvaluation {
    /// Always offline_recorded_outputs_v1, never native inference qualification.
    pub evidence_kind: String,
    /// Hash of the exact canonical recorded arm inputs, not a transcript assertion.
    pub hypotheses_sha256: String,
    pub e1: E1SelectionReceipt,
    /// A separate global anonymous-cluster mapping per complete meeting, never per chunk.
    pub e3: BTreeMap<String, BTreeMap<String, SpeakerScore>>,
}
fn invalid() -> AudioError {
    AudioError::InvalidEvaluationReceipt
}
fn tokens_valid(tokens: &[String]) -> bool {
    tokens.len() <= MAX_WORDS
        && tokens
            .iter()
            .all(|word| !word.is_empty() && word.len() <= 4096)
}
fn labels(words: &[WordCluster]) -> AudioResult<HashMap<String, String>> {
    if words.len() > MAX_WORDS {
        return Err(invalid());
    }
    let mut map = HashMap::new();
    for word in words {
        if word.word_id.is_empty()
            || word.word_id.len() > 256
            || word.cluster.is_empty()
            || word.cluster.len() > 256
            || map
                .insert(word.word_id.clone(), word.cluster.clone())
                .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(map)
}
/// Scores supplied hypotheses against exact reference bytes in a cohort.
/// It verifies neither audio inference nor consent. Those stay host obligations.
/// Lowest aggregate WER wins the evidence comparison; ties use model id, not
/// input order. A winner here still needs an authenticated OF-133 selection act.
pub fn evaluate_recorded_audio(
    cohort: &CohortManifest,
    references: &[ReferenceDocument],
    arms: &[RecordedArm],
) -> AudioResult<RecordedEvaluation> {
    let cohort = CohortManifest::parse(&serde_json::to_string(cohort).map_err(|_| invalid())?)?;
    if arms.is_empty() || arms.len() > MAX_ARMS || references.len() != cohort.files.len() {
        return Err(invalid());
    }
    let mut truth = BTreeMap::new();
    for source in references {
        if source.json.len() > 8 * 1024 * 1024 || truth.contains_key(&source.file_id) {
            return Err(invalid());
        }
        let file = cohort
            .files
            .iter()
            .find(|file| file.file_id == source.file_id)
            .ok_or_else(invalid)?;
        if format!("{:x}", Sha256::digest(source.json.as_bytes())) != file.reference_sha256 {
            return Err(invalid());
        }
        let reference: LabelledReference =
            serde_json::from_str(&source.json).map_err(|_| invalid())?;
        if reference.language.trim().is_empty()
            || reference.tokenizer.trim().is_empty()
            || reference.tokens.is_empty()
            || !tokens_valid(&reference.tokens)
        {
            return Err(invalid());
        }
        labels(&reference.speakers)?;
        truth.insert(source.file_id.clone(), reference);
    }
    let mut sorted = arms.to_vec();
    sorted.sort_by(|a, b| a.model_id.cmp(&b.model_id));
    let mut e1_arms = Vec::new();
    let mut e3 = BTreeMap::new();
    let mut seen_models = BTreeSet::new();
    for arm in &mut sorted {
        if !seen_models.insert(arm.model_id.clone()) || arm.files.len() != truth.len() {
            return Err(invalid());
        }
        arm.files.sort_by(|a, b| a.file_id.cmp(&b.file_id));
        let mut seen_files = BTreeSet::new();
        let mut scores = BTreeMap::new();
        let mut counts: HashMap<String, WerCountsSerde> = HashMap::new();
        for file in &mut arm.files {
            if !seen_files.insert(&file.file_id) || !tokens_valid(&file.tokens) {
                return Err(invalid());
            }
            let reference = truth.get(&file.file_id).ok_or_else(invalid)?;
            if reference
                .tokens
                .len()
                .checked_mul(file.tokens.len())
                .is_none_or(|cells| cells > MAX_ALIGNMENT_CELLS)
            {
                return Err(invalid());
            }
            let expected: Vec<_> = reference.tokens.iter().map(String::as_str).collect();
            let actual: Vec<_> = file.tokens.iter().map(String::as_str).collect();
            let score = wer_counts(&expected, &actual);
            let total = counts
                .entry(reference.language.clone())
                .or_insert(WerCountsSerde {
                    substitutions: 0,
                    deletions: 0,
                    insertions: 0,
                    reference_len: 0,
                });
            total.substitutions += score.substitutions;
            total.deletions += score.deletions;
            total.insertions += score.insertions;
            total.reference_len += score.reference_len;
            file.speakers.sort_by(|a, b| a.word_id.cmp(&b.word_id));
            let actual = labels(&file.speakers)?;
            let reference = labels(&reference.speakers)?;
            if reference.is_empty() && !actual.is_empty() {
                return Err(invalid());
            }
            if !reference.is_empty() {
                scores.insert(file.file_id.clone(), e3_score(&actual, &reference)?.into());
            }
        }
        e3.insert(arm.model_id.clone(), scores);
        e1_arms.push(E1Arm {
            model_id: arm.model_id.clone(),
            model_revision: arm.model_revision.clone(),
            model_sha256: arm.model_sha256.clone(),
            runtime_sha256: arm.runtime_sha256.clone(),
            wer_by_lang: counts,
        });
    }
    // Each arm scored exactly the same reference cohort; integer error totals
    // have the same denominator. No float rounding or cross-language averaging.
    let winner = e1_arms
        .iter()
        .min_by_key(|arm| {
            arm.wer_by_lang
                .values()
                .map(|c| c.substitutions + c.deletions + c.insertions)
                .sum::<u64>()
        })
        .ok_or_else(invalid)?
        .model_id
        .clone();
    let e1 = E1SelectionReceipt {
        corpus_id: cohort.corpus_id,
        corpus_sha256: cohort.cohort_sha256,
        arms: e1_arms,
        winner,
    };
    let validated = E1SelectionReceipt::parse(&serde_json::to_string(&e1).map_err(|_| invalid())?)?;
    let hypotheses_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&sorted).map_err(|_| invalid())?)
    );
    Ok(RecordedEvaluation {
        evidence_kind: "offline_recorded_outputs_v1".into(),
        hypotheses_sha256,
        e1: validated,
        e3,
    })
}
