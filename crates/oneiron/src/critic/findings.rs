//! Findings merge on a checkable flaw identity (LEARN-CRITIC Q1 = B): one
//! target, one flaw kind, one location. A critique that names no flaw is a
//! finding of its own. Calibration never counts repeated critic output twice.
use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MergedFinding {
    /// Its critiques' [`finding_key`].
    pub key: String,
    /// The most cautious verdict its critiques give: discard, then revise,
    /// then accept.
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    /// The posterior mean of the critics that give [`Self::verdict`].
    pub confidence: f64,
    pub artifact_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    /// The first edit, by artifact id, of a critique that gives
    /// [`Self::verdict`]; each critique keeps its own.
    pub suggested_edit: Option<String>,
    pub auto_resolved: bool,
    /// Its critiques give more than one verdict: it shows the most cautious
    /// one and never resolves without a person. A finding stored before
    /// findings merged on flaw identity held one verdict, and reads `false`.
    #[serde(default)]
    pub conflict: bool,
}

/// One critique's opinion, for votes: its verdict, evidence and edit. A
/// critic's repeated opinion in one cell counts once.
pub(super) fn opinion_key(critique: &CritiqueArtifact) -> String {
    let mut evidence = critique.evidence_refs.clone();
    evidence.sort();
    evidence.dedup();
    let edit = critique
        .suggested_edit
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let bytes =
        serde_json::to_vec(&(critique.verdict, evidence, edit)).expect("string serialization");
    blake3::hash(&bytes).to_hex().to_string()
}

/// A finding's key: [`flaw_key`] of the critique's target and flaw when it
/// names one, else the critique's own artifact id, so a critique that names
/// no flaw merges with no other. An artifact id holds no colon, so the two
/// kinds of key never meet.
pub(crate) fn finding_key(critique: &CritiqueArtifact) -> String {
    match &critique.flaw {
        Some(flaw) => flaw_key(&critique.candidate_ref, flaw),
        None => critique.artifact_id.clone(),
    }
}

/// The key of `flaw` in target `candidate_ref`: `flaw:` and the hash of both.
pub(crate) fn flaw_key(candidate_ref: &str, flaw: &FlawIdentity) -> String {
    let bytes = serde_json::to_vec(&("critic_flaw_v1", candidate_ref, &flaw.kind, &flaw.location))
        .expect("flaw identity serialization");
    format!("flaw:{}", blake3::hash(&bytes).to_hex())
}

/// How cautious a verdict is: discard, then revise, then accept.
const fn caution(verdict: CritiqueVerdict) -> u8 {
    match verdict {
        CritiqueVerdict::Accept => 0,
        CritiqueVerdict::Revise => 1,
        CritiqueVerdict::Discard => 2,
    }
}

fn posterior<'a>(
    critique: &CritiqueArtifact,
    rows: &'a [CriticReliability],
) -> Option<&'a CriticReliability> {
    rows.iter().find(|row| row.cell == critique.calibration)
}

pub(super) fn merge_findings(
    critiques: &[CritiqueArtifact],
    rows: &[CriticReliability],
    threshold: f64,
) -> Vec<MergedFinding> {
    let mut groups: BTreeMap<String, Vec<&CritiqueArtifact>> = BTreeMap::new();
    for critique in critiques.iter().filter(|row| !row.out_of_scope) {
        groups
            .entry(finding_key(critique))
            .or_default()
            .push(critique);
    }
    let mut findings = Vec::new();
    for (key, mut group) in groups {
        group.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
        let verdict = group
            .iter()
            .map(|row| row.verdict)
            .max_by_key(|verdict| caution(*verdict))
            .unwrap_or(CritiqueVerdict::Accept);
        let conflict = group.iter().any(|row| row.verdict != verdict);
        let supporting = group
            .iter()
            .copied()
            .filter(|row| row.verdict == verdict)
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        let (mut alpha, mut beta) = (0.0, 0.0);
        for critique in &supporting {
            if !seen.insert((
                &critique.provenance.critic_ref,
                critique.calibration.digest(),
            )) {
                continue;
            }
            let row = posterior(critique, rows);
            let (a, b) = row.map_or((1.0, 1.0), CriticReliability::beta_parameters);
            alpha += a;
            beta += b;
        }
        let confidence = alpha / (alpha + beta);
        findings.push(MergedFinding {
            key,
            verdict,
            severity: group
                .iter()
                .map(|row| row.severity)
                .max()
                .unwrap_or(CritiqueSeverity::Info),
            confidence,
            artifact_ids: group
                .iter()
                .map(|row| row.artifact_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            evidence_refs: group
                .iter()
                .flat_map(|row| row.evidence_refs.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            suggested_edit: supporting.iter().find_map(|row| row.suggested_edit.clone()),
            auto_resolved: !conflict && confidence >= threshold,
            conflict,
        });
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| a.key.cmp(&b.key))
    });
    findings
}
pub(super) fn verdict_confidence(
    critiques: &[CritiqueArtifact],
    rows: &[CriticReliability],
    verdict: CritiqueVerdict,
) -> f64 {
    let mut seen = BTreeSet::new();
    let (mut agreeing, mut total) = (0.0, 0.0);
    for row in critiques.iter().filter(|row| !row.out_of_scope) {
        if !seen.insert((
            &row.provenance.critic_ref,
            row.calibration.digest(),
            opinion_key(row),
        )) {
            continue;
        }
        let confidence = posterior(row, rows).map_or(0.5, CriticReliability::posterior_mean);
        total += 1.0;
        if row.verdict == verdict {
            agreeing += confidence;
        }
    }
    if total == 0.0 { 0.0 } else { agreeing / total }
}
