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
    /// Published floors are references, not same-tier measurements.
    pub published_baseline_cards: Vec<BaselineCardReference>,
    pub comparison_basis: &'static str,
    pub main_table: Vec<CitationNumber>,
    pub appendix: Vec<CitationNumber>,
    pub dropped: Vec<CitationNumber>,
    pub infra_status: String,
    pub infra_cost_framing: Vec<super::infra::InfraRow>,
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
        infra_status: source["vector_db_infra_status"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        infra_cost_framing: super::infra::carded_rows()?,
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
    let mut card_ids = BTreeSet::new();
    for group in groups {
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
            let disposition = disposition(&row, &all_rows, group == "dropped_or_unverifiable");
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
    let pairing = &row["backbone_solo_pairing"];
    let paired = match pairing["status"].as_str() {
        Some("solo") => row["citation_id"].as_str().is_some_and(|id| !id.is_empty()),
        Some("paired") => pairing["row_id"].as_str().is_some_and(|id| {
            all_rows.iter().any(|solo| {
                solo["citation_id"] == id
                    && solo["backbone_solo_pairing"]["status"] == "solo"
                    && solo["benchmark"] == row["benchmark"]
                    && solo["tier"] == row["tier"]
                    && solo["backbone"] == row["backbone"]
                    && solo["system"] != row["system"]
            })
        }),
        _ => false,
    };
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
        assert!(rows.main_table.iter().all(|row| {
            row.evidence["backbone_solo_pairing"]["status"] == "paired"
                || row.evidence["backbone_solo_pairing"]["status"] == "solo"
        }));
        assert!(rows.main_table.iter().any(|row| {
            row.evidence["system"] == "BEAM paper (LIGHT, Llama-4-Maverick)"
                && row.evidence["tier"] == "10M"
                && row.evidence["in_family_judge"] == false
                && row.disposition == CitationDisposition::CiteWithCaveat
        }));
        assert!(rows.appendix.iter().any(|row| {
            row.evidence["system"] == "BEAM paper (RAG, GPT-4.1-nano)"
                && row.evidence["in_family_judge"] == true
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
        assert_eq!(
            disposition(&paper, rows, false),
            CitationDisposition::CiteWithCaveat
        );
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
        paper["backbone_solo_pairing"] =
            serde_json::json!({"status":"paired", "row_id":"nonexistent solo"});
        assert_eq!(
            disposition(&paper, rows, false),
            CitationDisposition::WalledAppendix
        );
    }
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
    fn chroma_run_receipt_links_scored_support_and_no_evidence_control() {
        use sha2::{Digest, Sha256};

        let receipt: Value = serde_json::from_str(include_str!(
            "../../results/beam-chroma-fixture-2026-09-27.json"
        ))
        .unwrap();
        let corpus = corpus().unwrap();
        assert!(receipt["scope"].as_str().unwrap().contains("fixture"));
        assert_eq!(receipt["chroma_card_id"], "vanilla-rag");
        assert_eq!(receipt["retrieval_card_ids"].as_array().unwrap().len(), 2);
        let reports = [
            (
                "supported",
                include_str!("../../results/beam-chroma-supported.raw.json"),
                "observed_fixture_points",
            ),
            (
                "no_evidence",
                include_str!("../../results/beam-chroma-no-evidence.raw.json"),
                "negative_control_points",
            ),
        ];
        for (kind, raw, key) in reports {
            let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            assert_eq!(
                receipt["runtime"][format!("{kind}_raw_report_sha256")],
                digest
            );
            let run: Value = serde_json::from_str(raw).unwrap();
            assert_eq!(run["chroma_card_id"], "vanilla-rag");
            assert_eq!(run["retrieval_cards"].as_object().unwrap().len(), 2);
            let recorded = receipt[key].as_array().unwrap();
            for effort in ["light", "medium"] {
                for arm in ["deterministic", "vanilla_rag", "backbone_solo"] {
                    let point = run["points"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|point| point["effort"] == effort && point["arm"] == arm)
                        .unwrap();
                    let row = run["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["effort"] == effort && row["arm"] == arm)
                        .unwrap();
                    let summary = recorded
                        .iter()
                        .find(|row| row["effort"] == effort && row["arm"] == arm)
                        .unwrap();
                    assert_eq!(point["accuracy"], summary["scorer_value"]);
                    assert_eq!(row["answer"], summary["answer"]);
                    assert_eq!(
                        row["scoring"]["beam"]["aggregate"]["officialIntCast"],
                        point["accuracy"]
                    );
                    let supported = kind == "supported" && arm != "backbone_solo";
                    assert_eq!(point["accuracy"], if supported { 1.0 } else { 0.0 });
                    assert_eq!(row["answer"], if supported { "tulip" } else { "unknown" });
                }
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
        for card in receipt["infra_cost_framing_cards"].as_array().unwrap() {
            assert!(
                corpus
                    .infra_cost_framing
                    .iter()
                    .any(|row| row.card_id == card["card_id"]
                        && row.source == card["source"]
                        && serde_json::to_value(&row.measurement).unwrap() == card["measurement"])
            );
        }
        assert_eq!(
            receipt["infra_cost_framing_cards"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
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
