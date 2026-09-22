//! Deterministic duplicate consolidation; calibration never counts repeated critic output twice.
use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MergedFinding {
    pub key: String,
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    pub confidence: f64,
    pub artifact_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub suggested_edit: Option<String>,
    pub auto_resolved: bool,
}

pub(super) fn finding_key(critique: &CritiqueArtifact) -> String {
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
fn posterior<'a>(
    critique: &CritiqueArtifact,
    rows: &'a [CriticReliability],
) -> Option<&'a CriticReliability> {
    rows.iter()
        .find(|row| row.lens_id == critique.lens_id && row.domain == critique.domain)
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
        let first = group[0];
        let mut seen = BTreeSet::new();
        let (mut alpha, mut beta) = (0.0, 0.0);
        for critique in &group {
            if !seen.insert((
                &critique.provenance.critic_ref,
                &critique.lens_id,
                &critique.domain,
            )) {
                continue;
            }
            let row = posterior(critique, rows);
            alpha += row.map_or(1.0, |row| row.alpha);
            beta += row.map_or(1.0, |row| row.beta);
        }
        let confidence = alpha / (alpha + beta);
        findings.push(MergedFinding {
            key,
            verdict: first.verdict,
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
            suggested_edit: first.suggested_edit.clone(),
            auto_resolved: confidence >= threshold,
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
            &row.lens_id,
            &row.domain,
            finding_key(row),
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
