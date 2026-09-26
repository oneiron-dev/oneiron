//! Evidence-backed per-number citations. Unknown axes never become main-table wins.
use super::{BeamError, BeamResult, comparability::CitationDisposition};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
#[derive(Debug, Serialize)]
pub(super) struct CitationNumber {
    pub disposition: CitationDisposition,
    pub evidence: Value,
}
#[derive(Debug, Serialize)]
pub(super) struct CitationCorpus {
    /// References to the published floor, not claims of matched-tier parity.
    pub published_baseline_cards: Vec<BaselineCardReference>,
    pub comparison_basis: &'static str,
    pub main_table: Vec<CitationNumber>,
    pub appendix: Vec<CitationNumber>,
    pub dropped: Vec<CitationNumber>,
    pub infra_status: String,
}
#[derive(Debug, Serialize)]
pub(super) struct BaselineCardReference {
    pub card_id: String,
    pub disposition: CitationDisposition,
}
pub(super) fn corpus() -> BeamResult<CitationCorpus> {
    from_source(serde_json::from_str(include_str!(
        "../../fixtures/beam_citation_corpus.v1.json"
    ))?)
}
fn from_source(source: Value) -> BeamResult<CitationCorpus> {
    let mut result = CitationCorpus {
        comparison_basis: "aggregate-tier; D9 dual-column",
        published_baseline_cards: Vec::new(),
        main_table: Vec::new(),
        appendix: Vec::new(),
        dropped: Vec::new(),
        infra_status: source["vector_db_infra_walled_reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    };
    let mut card_ids = BTreeSet::new();
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
            let baseline = group == "beam_paper_baselines" || group == "honcho";
            let card_id = row["card_id"].as_str().unwrap_or_default();
            if baseline
                && (card_id.trim().is_empty()
                    || !card_ids.insert(card_id.to_owned())
                    || row["evidence"]["ref"].as_str().is_none_or(str::is_empty)
                    || row["evidence"]["quote"].as_str().is_none_or(str::is_empty))
            {
                return Err(BeamError::Comparability {
                    reason: "published baselines require unique card ids and cited evidence".into(),
                });
            }
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
            if baseline {
                result.published_baseline_cards.push(BaselineCardReference {
                    card_id: card_id.to_owned(),
                    disposition,
                });
            }
            let number = CitationNumber {
                disposition,
                evidence: row,
            };
            match disposition {
                CitationDisposition::Cite | CitationDisposition::CiteWithCaveat => {
                    result.main_table.push(number);
                }
                CitationDisposition::WalledAppendix => result.appendix.push(number),
                CitationDisposition::Dropped => result.dropped.push(number),
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_floor_has_stable_cited_cards_and_walls_unknown_axes() {
        let report = corpus().unwrap();
        let ids: BTreeSet<_> = report
            .published_baseline_cards
            .iter()
            .map(|r| r.card_id.as_str())
            .collect();
        assert_eq!(ids.len(), report.published_baseline_cards.len());
        for id in [
            "honcho-beam-100k-nugget-mean-v1",
            "beam-paper-10m-rag-llama4-maverick-v1",
        ] {
            assert!(ids.contains(id));
            assert!(
                report
                    .appendix
                    .iter()
                    .chain(&report.main_table)
                    .any(|row| row.evidence["card_id"] == id)
            );
        }
        assert!(
            report
                .published_baseline_cards
                .iter()
                .any(|row| row.card_id == "honcho-beam-100k-nugget-mean-v1"
                    && row.disposition == CitationDisposition::WalledAppendix)
        );
        assert!(!report.infra_status.is_empty());
    }

    #[test]
    fn chroma_run_receipt_resolves_published_rows_without_claiming_public_parity() {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../results/beam-chroma-fixture-2026-09-27.json"
        ))
        .unwrap();
        let corpus = corpus().unwrap();
        assert!(receipt["scope"].as_str().unwrap().contains("fixture-only"));
        assert_eq!(receipt["chroma_card_id"], "vanilla-rag");
        assert_eq!(receipt["retrieval_card_ids"].as_array().unwrap().len(), 2);
        let points = receipt["observed_fixture_points"].as_array().unwrap();
        for effort in ["light", "medium"] {
            for arm in ["deterministic", "vanilla_rag"] {
                assert!(
                    points
                        .iter()
                        .any(|point| { point["effort"] == effort && point["arm"] == arm })
                );
            }
        }
        for reference in receipt["cited_published_reference_rows"]
            .as_array()
            .unwrap()
        {
            let card_id = reference["card_id"].as_str().unwrap();
            assert!(
                corpus
                    .published_baseline_cards
                    .iter()
                    .any(|row| row.card_id == card_id)
            );
            let row = corpus
                .main_table
                .iter()
                .chain(&corpus.appendix)
                .find(|row| row.evidence["card_id"] == card_id)
                .unwrap();
            assert_eq!(row.evidence["value"], reference["value"]);
            assert_eq!(row.evidence["tier"], reference["tier"]);
            assert_eq!(row.evidence["evidence"]["ref"], reference["source"]);
            assert_eq!(
                serde_json::to_value(row.disposition).unwrap(),
                reference["disposition"]
            );
        }
    }

    #[test]
    fn missing_or_duplicate_published_evidence_fails_closed() {
        let source: Value =
            serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json"))
                .unwrap();
        for field in ["card_id", "evidence"] {
            let mut invalid = source.clone();
            invalid["honcho"][0].as_object_mut().unwrap().remove(field);
            assert!(matches!(
                from_source(invalid),
                Err(BeamError::Comparability { .. })
            ));
        }
        let mut duplicate = source;
        duplicate["honcho"][1]["card_id"] = duplicate["honcho"][0]["card_id"].clone();
        assert!(matches!(
            from_source(duplicate),
            Err(BeamError::Comparability { .. })
        ));
    }
}
