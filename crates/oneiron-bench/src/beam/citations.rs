//! Evidence-backed per-number citations. Unknown axes never become main-table wins.
use super::{BeamResult, comparability::CitationDisposition};
use serde::Serialize;
use serde_json::Value;
#[derive(Debug, Serialize)]
pub(super) struct CitationNumber {
    pub disposition: CitationDisposition,
    pub evidence: Value,
}
#[derive(Debug, Serialize)]
pub(super) struct CitationCorpus {
    pub comparison_basis: &'static str,
    pub main_table: Vec<CitationNumber>,
    pub appendix: Vec<CitationNumber>,
    pub dropped: Vec<CitationNumber>,
    pub infra_status: String,
}
pub(super) fn corpus() -> BeamResult<CitationCorpus> {
    let source: Value =
        serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json"))?;
    let mut result = CitationCorpus {
        comparison_basis: "aggregate-tier; D9 dual-column",
        main_table: Vec::new(),
        appendix: Vec::new(),
        dropped: Vec::new(),
        infra_status: source["vector_db_infra_walled_reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    };
    for group in [
        "beam_paper_baselines",
        "honcho",
        "competitors",
        "dropped_or_unverifiable",
    ] {
        let rows = match &source[group] {
            Value::Array(rows) => rows.clone(),
            Value::Object(_) => vec![source[group].clone()],
            _ => Vec::new(),
        };
        for row in rows {
            let named = row["disposition"].as_str().unwrap_or("walled appendix");
            let incomplete = [
                "tier",
                "backbone",
                "judge",
                "retrieval_k",
                "regime",
                "in_family_judge",
            ]
            .iter()
            .any(|key| {
                row.get(key)
                    .is_none_or(|v| v.is_null() || v.as_str() == Some("unknown"))
            });
            let disposition = if named.contains("drop") || group == "dropped_or_unverifiable" {
                CitationDisposition::Dropped
            } else if row["scale"].as_str() != Some("0-1")
                || incomplete
                || row["regime"] == "oracle"
                || row["in_family_judge"] == true
                || named.contains("wall")
            {
                CitationDisposition::WalledAppendix
            } else if named.contains("caveat") || row["provenance"] == "self" {
                CitationDisposition::CiteWithCaveat
            } else {
                CitationDisposition::Cite
            };
            let number = CitationNumber {
                disposition,
                evidence: row,
            };
            match disposition {
                CitationDisposition::Cite | CitationDisposition::CiteWithCaveat => {
                    result.main_table.push(number)
                }
                CitationDisposition::WalledAppendix => result.appendix.push(number),
                CitationDisposition::Dropped => result.dropped.push(number),
            }
        }
    }
    Ok(result)
}
