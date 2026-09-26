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
    let groups = [
        "beam_paper_baselines",
        "honcho",
        "competitors",
        "dropped_or_unverifiable",
    ];
    let all_rows: Vec<Value> = groups
        .iter()
        .flat_map(|group| match &source[*group] {
            Value::Array(rows) => rows.clone(),
            Value::Object(_) => vec![source[*group].clone()],
            _ => Vec::new(),
        })
        .collect();
    for group in groups {
        let rows = match &source[group] {
            Value::Array(rows) => rows.clone(),
            Value::Object(_) => vec![source[group].clone()],
            _ => Vec::new(),
        };
        for row in rows {
            let disposition = disposition(&row, &all_rows, group == "dropped_or_unverifiable");
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

fn disclosed(row: &Value, key: &str) -> bool {
    row[key]
        .as_str()
        .is_some_and(|value| !value.trim().is_empty() && !value.trim().starts_with("unknown"))
}

fn disposition(row: &Value, all_rows: &[Value], dropped_group: bool) -> CitationDisposition {
    let named = row["disposition"].as_str().unwrap_or_default();
    if named == "dropped" || dropped_group {
        return CitationDisposition::Dropped;
    }
    let pairing = row["backbone_solo_pairing"].as_str();
    let paired = pairing.is_some_and(|system| {
        all_rows.iter().any(|solo| {
            solo["system"] == system
                && solo["benchmark"] == row["benchmark"]
                && solo["tier"] == row["tier"]
                && solo["backbone"] == row["backbone"]
                && solo["backbone_solo"] == true
                && solo["system"] != row["system"]
        })
    });
    // A published disposition cannot override a missing axis or a non-comparable regime.
    if ![
        "system",
        "benchmark",
        "tier",
        "metric",
        "backbone",
        "judge",
        "answerer",
        "provenance",
        "card_caveat",
    ]
    .iter()
    .all(|key| disclosed(row, key))
        || row["retrieval_k"].as_u64().is_none()
        || !paired
        || row["in_family_judge"] != false
        || row["regime"] != "full"
        || row["benchmark"] != "BEAM"
        || row["scale"] != "0-1"
        || row["metric"] != "nugget_mean"
        || !row["value"].is_number()
        || row["comparison_basis"] != "aggregate_tier"
        || !matches!(
            row["provenance"].as_str(),
            Some("self" | "independent" | "our_rerun")
        )
        || !matches!(named, "cite" | "cite-with-caveat")
    {
        CitationDisposition::WalledAppendix
    } else if named == "cite-with-caveat" || row["provenance"] == "self" {
        CitationDisposition::CiteWithCaveat
    } else {
        CitationDisposition::Cite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_disposition_map_cards_every_row_and_pairs_known_backbones() {
        let source: Value =
            serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json"))
                .unwrap();
        for group in ["beam_paper_baselines", "honcho", "competitors"] {
            for row in source[group].as_array().unwrap() {
                assert!(row.get("disposition").is_some(), "{group}: {row}");
                assert!(row.get("card_caveat").is_some(), "{group}: {row}");
                assert!(row.get("backbone_solo_pairing").is_some(), "{group}: {row}");
            }
        }
        let rows = corpus().unwrap();
        assert!(
            rows.main_table
                .iter()
                .all(|row| { row.evidence["backbone_solo_pairing"].as_str().is_some() })
        );
        assert!(rows.appendix.iter().any(|row| {
            row.evidence["system"] == "BEAM paper (LIGHT, Llama-4-Maverick)"
                && row.evidence["tier"] == "10M"
                && row.evidence["in_family_judge"] == "unknown"
        }));
        assert!(rows.appendix.iter().any(|row| {
            row.evidence["system"] == "WorldDB" && row.evidence["regime"] == "oracle"
        }));
        assert!(rows.appendix.iter().any(|row| {
            row.evidence["system"] == "HydraDB" && row.evidence["in_family_judge"] == true
        }));
        assert!(rows.dropped.iter().any(|row| {
            row.evidence["system"] == "Hindsight" && row.evidence["benchmark"] == "LongMemEval-S"
        }));
    }

    #[test]
    fn corpus_gate_walls_each_missing_axis_or_missing_solo_and_oracle_judge_rows() {
        let source: Value =
            serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json"))
                .unwrap();
        let mut paper = source["beam_paper_baselines"][0].clone();
        let rows = source["beam_paper_baselines"].as_array().unwrap();
        // Published in-family status is unknown. A verified external judge can clear this axis.
        paper["in_family_judge"] = Value::Bool(false);
        assert_eq!(disposition(&paper, rows, false), CitationDisposition::Cite);
        for key in [
            "benchmark",
            "tier",
            "regime",
            "scale",
            "backbone",
            "backbone_solo_pairing",
            "judge",
            "in_family_judge",
            "retrieval_k",
            "provenance",
        ] {
            let mut row = paper.clone();
            row.as_object_mut().unwrap().remove(key);
            assert_eq!(
                disposition(&row, rows, false),
                CitationDisposition::WalledAppendix,
                "{key}"
            );
        }
        for (key, value) in [
            ("regime", serde_json::json!("oracle")),
            ("in_family_judge", serde_json::json!(true)),
        ] {
            let mut row = paper.clone();
            row[key] = value;
            assert_eq!(
                disposition(&row, rows, false),
                CitationDisposition::WalledAppendix
            );
        }
        let mut undisclosed_judge = paper.clone();
        undisclosed_judge["judge"] = serde_json::json!("unknown (not named)");
        assert_eq!(
            disposition(&undisclosed_judge, rows, false),
            CitationDisposition::WalledAppendix
        );
        paper["backbone_solo_pairing"] = serde_json::json!("nonexistent solo");
        assert_eq!(
            disposition(&paper, rows, false),
            CitationDisposition::WalledAppendix
        );
    }
}
