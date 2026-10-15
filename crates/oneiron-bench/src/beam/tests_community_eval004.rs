//! Community and EVAL-004 tests.

#[cfg(test)]
pub(super) const CONTRACT_MANIFEST_JSON: &str =
    include_str!("../../fixtures/beam_128k_contract.run.json");

#[cfg(test)]
pub(super) const CONTRACT_RUN_JSONL: &str =
    include_str!("../../fixtures/beam_128k_contract.run.jsonl");

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;

    pub(crate) fn find_arm(report: &BeamReport, kind: ArmKind) -> &ArmReport {
        report.cases[0]
            .arms
            .iter()
            .find(|arm| arm.arm == kind)
            .expect("arm report exists")
    }

    pub(crate) fn eval004_record_json(id: &str, timestamp: u64, text: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "entityType": oneiron::registry::ENTITY_TYPE_SUMMARY,
            "occurred": {
                "start": timestamp,
                "end": timestamp
            },
            "learnedAt": timestamp,
            "fields": {
                "txt": text,
                "lvl": "eval004",
                "at": format!("eval004-t{timestamp}")
            },
            "text": [
                {
                    "field": "txt",
                    "value": text
                }
            ]
        })
    }

    pub(crate) fn budget_score(scores: &[AbilityScoreReport]) -> &AbilityScoreReport {
        scores
            .iter()
            .find(|score| score.ability == AbilityKind::BudgetDiscipline)
            .expect("budget discipline score exists")
    }

    pub(crate) fn empty_pack_stats_report() -> PackStatsReport {
        PackStatsReport {
            candidates_considered: 0,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            total_tokens: 0,
            section_tokens: Vec::new(),
            item_tokens: Vec::new(),
            items_truncated: 0,
            items_truncated_reasons: Vec::new(),
            items_dropped: 0,
            items_dropped_reasons: Vec::new(),
        }
    }
}
