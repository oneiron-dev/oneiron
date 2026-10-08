//! Evidence-backed per-number citations. Unknown axes never become main-table wins.
use super::{BeamError, BeamResult, comparability::CitationDisposition};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum BackboneSoloPairing {
    Paired { row_id: String },
    Solo,
    Unavailable { reason: String },
}

fn citation_rows(source: &Value) -> impl Iterator<Item = &Value> {
    ["beam_paper_baselines", "honcho", "competitors"]
        .into_iter()
        .filter_map(|group| source[group].as_array())
        .flatten()
}

fn validate_pairings(source: &Value) -> BeamResult<()> {
    for group in [
        "beam_paper_baselines",
        "honcho",
        "competitors",
        "dropped_or_unverifiable",
    ] {
        if !source[group].is_array() {
            return Err(BeamError::Comparability {
                reason: format!("citation group {group} must be an array"),
            });
        }
    }
    let mut solo = HashMap::new();
    for row in citation_rows(source) {
        if matches!(parse_pairing(row)?, BackboneSoloPairing::Solo) {
            let id = row["citation_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| BeamError::Comparability {
                    reason: "solo row requires citation_id".into(),
                })?;
            if solo.insert(id, row).is_some() {
                return Err(BeamError::Comparability {
                    reason: format!("duplicate solo row {id}"),
                });
            }
        }
    }
    for row in citation_rows(source) {
        if let BackboneSoloPairing::Paired { row_id } = parse_pairing(row)? {
            let companion = solo
                .get(row_id.as_str())
                .ok_or_else(|| BeamError::Comparability {
                    reason: format!("unknown backbone-solo row {row_id}"),
                })?;
            if ["benchmark", "tier", "backbone", "scale"]
                .iter()
                .any(|axis| row[axis].is_null() || row[axis] != companion[*axis])
            {
                return Err(BeamError::Comparability {
                    reason: format!(
                        "backbone-solo row {row_id} has mismatched benchmark, tier, backbone or scale"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn disclosed(row: &Value, key: &str) -> bool {
    row[key]
        .as_str()
        .is_some_and(|value| !value.trim().is_empty() && !value.trim().starts_with("unknown"))
}

// A published label never overrides the independent seven-axis publication gate.
fn clears_publication_axes(row: &Value) -> bool {
    [
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
        && row["retrieval_k"].as_u64().is_some()
        && row["in_family_judge"] == false
        && row["regime"] == "full"
        && row["benchmark"] == "BEAM"
        && row["scale"] == "0-1"
        && row["metric"] == "nugget_mean"
        && row["value"].is_number()
        && row["comparison_basis"] == "aggregate_tier"
        && matches!(
            row["provenance"].as_str(),
            Some("self" | "independent" | "our_rerun")
        )
}

fn parse_pairing(row: &Value) -> BeamResult<BackboneSoloPairing> {
    let pairing: BackboneSoloPairing =
        serde_json::from_value(row["backbone_solo_pairing"].clone())?;
    if matches!(&pairing, BackboneSoloPairing::Unavailable { reason } if reason.trim().is_empty()) {
        return Err(BeamError::Comparability {
            reason: "unavailable solo pairing requires a reason".into(),
        });
    }
    Ok(pairing)
}
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
    let source: Value =
        serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json"))?;
    corpus_from_source(&source)
}

fn corpus_from_source(source: &Value) -> BeamResult<CitationCorpus> {
    validate_pairings(source)?;
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
    let mut baseline_ids = BTreeSet::new();
    for group in [
        "beam_paper_baselines",
        "honcho",
        "competitors",
        "dropped_or_unverifiable",
    ] {
        let rows = source[group]
            .as_array()
            .expect("citation groups validated as arrays")
            .clone();
        for row in rows {
            let baseline = group == "beam_paper_baselines" || group == "honcho";
            let card_id = row["card_id"].as_str().unwrap_or_default();
            if baseline
                && (card_id.trim().is_empty()
                    || !baseline_ids.insert(card_id.to_owned())
                    || row["evidence"]["ref"].as_str().is_none_or(str::is_empty)
                    || row["evidence"]["quote"].as_str().is_none_or(str::is_empty))
            {
                return Err(BeamError::Comparability {
                    reason: "published baselines require unique card ids and cited evidence".into(),
                });
            }
            let named = row["disposition"].as_str().unwrap_or("walled appendix");
            let unpaired = group != "dropped_or_unverifiable"
                && matches!(
                    parse_pairing(&row)?,
                    BackboneSoloPairing::Unavailable { .. }
                );
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
            let disposition = if named == "dropped" || group == "dropped_or_unverifiable" {
                CitationDisposition::Dropped
            } else if !clears_publication_axes(&row)
                || incomplete
                || unpaired
                || row["regime"] == "oracle"
                || row["in_family_judge"] == true
                || !matches!(named, "cite" | "cite-with-caveat")
            {
                CitationDisposition::WalledAppendix
            } else if named == "cite-with-caveat" || row["provenance"] == "self" {
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

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../fixtures/beam_citation_corpus.v1.json")).unwrap()
    }

    #[test]
    fn corpus_refuses_missing_fabricated_or_wrong_tier_solo_pairings() {
        let mut source = fixture();
        source["competitors"][4]["backbone_solo_pairing"]["row_id"] = "missing".into();
        assert!(corpus_from_source(&source).is_err());
        let mut source = fixture();
        source["competitors"][4]["backbone_solo_pairing"]["row_id"] = "beam-10m-llama-solo".into();
        assert!(corpus_from_source(&source).is_err());
        let mut source = fixture();
        source["competitors"][4]
            .as_object_mut()
            .unwrap()
            .remove("backbone_solo_pairing");
        assert!(corpus_from_source(&source).is_err());
        let mut source = fixture();
        source["honcho"][0]["backbone_solo_pairing"]["reason"] = " ".into();
        assert!(corpus_from_source(&source).is_err());
        let mut source = fixture();
        source["honcho"] = source["honcho"][0].clone();
        assert!(corpus_from_source(&source).is_err());
    }

    #[test]
    fn seven_axis_gate_walls_missing_or_incomparable_cards() {
        for key in [
            "benchmark",
            "tier",
            "regime",
            "scale",
            "backbone",
            "judge",
            "answerer",
            "in_family_judge",
            "retrieval_k",
            "provenance",
            "metric",
            "comparison_basis",
        ] {
            let mut source = fixture();
            source["beam_paper_baselines"][0]
                .as_object_mut()
                .unwrap()
                .remove(key);
            match corpus_from_source(&source) {
                Ok(corpus) => assert!(
                    corpus.appendix.iter().any(|number| {
                        number.evidence["system"] == "BEAM paper (LIGHT, Llama-4-Maverick)"
                            && number.evidence["tier"] == source["beam_paper_baselines"][0]["tier"]
                    }),
                    "{key}"
                ),
                Err(_) => assert!(
                    matches!(key, "benchmark" | "tier" | "backbone" | "scale"),
                    "{key}"
                ),
            }
        }
        for (key, value) in [
            ("regime", serde_json::json!("oracle")),
            ("in_family_judge", serde_json::json!(true)),
            ("judge", serde_json::json!("unknown (not named)")),
            ("disposition", serde_json::json!("unreviewed")),
        ] {
            let mut source = fixture();
            source["beam_paper_baselines"][0][key] = value;
            let corpus = corpus_from_source(&source).unwrap();
            assert!(
                corpus.appendix.iter().any(|number| {
                    number.evidence["system"] == "BEAM paper (LIGHT, Llama-4-Maverick)"
                        && number.evidence["tier"] == "10M"
                }),
                "{key}"
            );
        }
    }

    #[test]
    fn published_light_and_rag_cards_keep_distinct_retrieval_budgets() {
        let corpus = corpus().unwrap();
        let numbers = corpus.main_table.iter().chain(&corpus.appendix);
        let light = numbers
            .clone()
            .filter(|number| {
                number.evidence["system"]
                    .as_str()
                    .is_some_and(|system| system.starts_with("BEAM paper (LIGHT"))
            })
            .collect::<Vec<_>>();
        assert_eq!(light.len(), 4);
        for number in light {
            assert_eq!(
                number.evidence["retrieval_k"], 15,
                "{}",
                number.evidence["system"]
            );
            let caveat = number.evidence["card_caveat"].as_str().unwrap();
            assert!(caveat.contains("scratchpad") && caveat.contains("working memory"));
        }
        let rag = numbers
            .filter(|number| {
                number.evidence["system"]
                    .as_str()
                    .is_some_and(|system| system.starts_with("BEAM paper (RAG"))
            })
            .collect::<Vec<_>>();
        assert_eq!(rag.len(), 5);
        for number in rag {
            assert_eq!(
                number.evidence["retrieval_k"], 5,
                "{}",
                number.evidence["system"]
            );
        }
        assert!(corpus.main_table.iter().any(|number| {
            number.evidence["system"] == "BEAM paper (LIGHT, Qwen2.5-32B)"
                && number.evidence["tier"] == "1M"
                && number.evidence["retrieval_k"] == 15
        }));
    }
}
