//! Offline evaluation of recorded outputs. Never runs inference or grants a default.
//!
//! No count of arms, files, tokens, speaker entries or alignment cells is
//! refused: the full input is kept, and [`RecordedEvaluationRun`] scores it a
//! step at a time, stopping only at a caller's deadline (to continue on the
//! next call) or when memory for a step's working state cannot be had.
use super::{
    AudioError, AudioResult, CohortManifest, E1Arm, E1SelectionReceipt, E3Assignment, E3Score,
    WerAlignment, WerCountsSerde,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

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
    tokens
        .iter()
        .all(|word| !word.is_empty() && word.len() <= 4096)
}
fn labels(words: &[WordCluster]) -> AudioResult<HashMap<String, String>> {
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

/// Where scoring of the current file stands.
#[derive(Debug, Clone)]
enum FileStage {
    Start,
    Words(WerAlignment),
    Speakers(E3Assignment),
}

/// A recorded evaluation in progress: its validated inputs, kept whole, and
/// how far scoring has got, arm by arm and file by file in id order.
#[derive(Debug, Clone)]
pub struct RecordedEvaluationRun {
    cohort: CohortManifest,
    truth: BTreeMap<String, LabelledReference>,
    arms: Vec<RecordedArm>,
    arm: usize,
    file: usize,
    stage: FileStage,
    counts: HashMap<String, WerCountsSerde>,
    scores: BTreeMap<String, SpeakerScore>,
    e1_arms: Vec<E1Arm>,
    e3: BTreeMap<String, BTreeMap<String, SpeakerScore>>,
}

impl RecordedEvaluationRun {
    /// Validates every input against the cohort and the exact reference
    /// bytes before any scoring starts.
    ///
    /// # Errors
    /// A malformed or unbound cohort, reference or arm; never a count.
    pub fn new(
        cohort: &CohortManifest,
        references: &[ReferenceDocument],
        arms: &[RecordedArm],
    ) -> AudioResult<Self> {
        let cohort = CohortManifest::parse(&serde_json::to_string(cohort).map_err(|_| invalid())?)?;
        if arms.is_empty() || references.len() != cohort.files.len() {
            return Err(invalid());
        }
        let mut truth = BTreeMap::new();
        for source in references {
            if truth.contains_key(&source.file_id) {
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
        let mut seen_models = BTreeSet::new();
        for arm in &mut sorted {
            if !seen_models.insert(arm.model_id.clone()) || arm.files.len() != truth.len() {
                return Err(invalid());
            }
            arm.files.sort_by(|a, b| a.file_id.cmp(&b.file_id));
            let mut seen_files = BTreeSet::new();
            for file in &mut arm.files {
                if !seen_files.insert(file.file_id.clone()) || !tokens_valid(&file.tokens) {
                    return Err(invalid());
                }
                let reference = truth.get(&file.file_id).ok_or_else(invalid)?;
                file.speakers.sort_by(|a, b| a.word_id.cmp(&b.word_id));
                let actual = labels(&file.speakers)?;
                if reference.speakers.is_empty() && !actual.is_empty() {
                    return Err(invalid());
                }
            }
        }
        Ok(Self {
            cohort,
            truth,
            arms: sorted,
            arm: 0,
            file: 0,
            stage: FileStage::Start,
            counts: HashMap::new(),
            scores: BTreeMap::new(),
            e1_arms: Vec::new(),
            e3: BTreeMap::new(),
        })
    }

    /// Scores until the evaluation is complete, or `deadline` has passed
    /// after at least one step. The evaluation once complete; `None` while
    /// work remains, to continue on the next call. `None` as the deadline
    /// runs it whole.
    ///
    /// # Errors
    /// [`AudioError::ResourceFloor`] when a file's working state cannot be
    /// allocated; the run stays where it was.
    pub fn advance(
        &mut self,
        deadline: Option<Instant>,
    ) -> AudioResult<Option<RecordedEvaluation>> {
        while let Some(arm) = self.arms.get(self.arm) {
            let Some(file) = arm.files.get(self.file) else {
                self.e3
                    .insert(arm.model_id.clone(), std::mem::take(&mut self.scores));
                self.e1_arms.push(E1Arm {
                    model_id: arm.model_id.clone(),
                    model_revision: arm.model_revision.clone(),
                    model_sha256: arm.model_sha256.clone(),
                    runtime_sha256: arm.runtime_sha256.clone(),
                    wer_by_lang: std::mem::take(&mut self.counts),
                });
                self.arm += 1;
                self.file = 0;
                continue;
            };
            let reference = self.truth.get(&file.file_id).ok_or_else(invalid)?;
            let next = match &mut self.stage {
                FileStage::Start => FileStage::Words(WerAlignment::new(
                    reference.tokens.len(),
                    file.tokens.len(),
                )?),
                FileStage::Words(alignment) => {
                    let expected: Vec<_> = reference.tokens.iter().map(String::as_str).collect();
                    let actual: Vec<_> = file.tokens.iter().map(String::as_str).collect();
                    let Some(score) = alignment.advance(&expected, &actual, deadline) else {
                        return Ok(None);
                    };
                    // Every fallible step comes before the counts are added,
                    // so a retry after a resource floor adds them once.
                    let reference_labels = labels(&reference.speakers)?;
                    let speakers = if reference_labels.is_empty() {
                        None
                    } else {
                        Some(E3Assignment::new(
                            &labels(&file.speakers)?,
                            &reference_labels,
                        )?)
                    };
                    let total =
                        self.counts
                            .entry(reference.language.clone())
                            .or_insert(WerCountsSerde {
                                substitutions: 0,
                                deletions: 0,
                                insertions: 0,
                                reference_len: 0,
                            });
                    total.substitutions = total.substitutions.saturating_add(score.substitutions);
                    total.deletions = total.deletions.saturating_add(score.deletions);
                    total.insertions = total.insertions.saturating_add(score.insertions);
                    total.reference_len = total.reference_len.saturating_add(score.reference_len);
                    match speakers {
                        Some(assignment) => FileStage::Speakers(assignment),
                        None => {
                            self.file += 1;
                            FileStage::Start
                        }
                    }
                }
                FileStage::Speakers(assignment) => {
                    let Some(score) = assignment.advance(deadline) else {
                        return Ok(None);
                    };
                    self.scores.insert(file.file_id.clone(), score.into());
                    self.file += 1;
                    FileStage::Start
                }
            };
            self.stage = next;
            if deadline.is_some_and(|at| Instant::now() >= at) {
                return Ok(None);
            }
        }
        self.finish().map(Some)
    }

    /// The evaluation from every arm's scores. Lowest aggregate WER wins the
    /// evidence comparison; ties use model id, not input order.
    fn finish(&self) -> AudioResult<RecordedEvaluation> {
        // Each arm scored exactly the same reference cohort; integer error totals
        // have the same denominator. No float rounding or cross-language averaging.
        let winner = self
            .e1_arms
            .iter()
            .min_by_key(|arm| {
                arm.wer_by_lang
                    .values()
                    .map(|c| {
                        u128::from(c.substitutions)
                            + u128::from(c.deletions)
                            + u128::from(c.insertions)
                    })
                    .fold(0u128, u128::saturating_add)
            })
            .ok_or_else(invalid)?
            .model_id
            .clone();
        let e1 = E1SelectionReceipt {
            corpus_id: self.cohort.corpus_id.clone(),
            corpus_sha256: self.cohort.cohort_sha256.clone(),
            arms: self.e1_arms.clone(),
            winner,
        };
        let validated =
            E1SelectionReceipt::parse(&serde_json::to_string(&e1).map_err(|_| invalid())?)?;
        let hypotheses_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&self.arms).map_err(|_| invalid())?)
        );
        Ok(RecordedEvaluation {
            evidence_kind: "offline_recorded_outputs_v1".into(),
            hypotheses_sha256,
            e1: validated,
            e3: self.e3.clone(),
        })
    }
}

/// Scores supplied hypotheses against exact reference bytes in a cohort, whole
/// ([`RecordedEvaluationRun`] with no deadline).
/// It verifies neither audio inference nor consent. Those stay host obligations.
/// Lowest aggregate WER wins the evidence comparison; ties use model id, not
/// input order. A winner here still needs an authenticated OF-133 selection act.
pub fn evaluate_recorded_audio(
    cohort: &CohortManifest,
    references: &[ReferenceDocument],
    arms: &[RecordedArm],
) -> AudioResult<RecordedEvaluation> {
    let mut run = RecordedEvaluationRun::new(cohort, references, arms)?;
    loop {
        if let Some(evaluation) = run.advance(None)? {
            return Ok(evaluation);
        }
    }
}
