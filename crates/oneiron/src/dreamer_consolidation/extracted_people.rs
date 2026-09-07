//! Explicit PERSON outputs from the production extraction response.
//!
//! Subject ids alone never imply PERSON. Only typed person outputs backed by
//! admissible turns in this extraction's working set may mint a new row. The
//! mint door stamps Generated provenance and refuses existing/deleted ids.

use super::support::invalid_consolidation;
use super::watermark::read_turn_facts_in_txn;
use crate::Vault;
use crate::claim::ClaimSource;
use crate::dreamer_runner::{dreamer_extraction_role_admissible, dreamer_turn_role};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::{ContentPart, LlmResponse};
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

pub(super) fn extraction_response_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "candidates": {"type": "array", "items": {"type": "object"}},
            "persons": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "name", "evidence_turn_refs"],
                    "properties": {
                        "id": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"},
                        "name": {"type": "string", "minLength": 1},
                        "evidence_turn_refs": {
                            "type": "array", "minItems": 1,
                            "items": {"type": "string", "pattern": "^[0-9a-fA-F]{32}$"}
                        }
                    }
                }
            }
        }
    })
}

pub(super) fn mint_extracted_people(
    vault: &Vault,
    response: &LlmResponse,
    working_set: &[EntityId],
    now: u64,
) -> Result<()> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|_| invalid_consolidation("extraction response must be JSON"))?;
    let Some(people) = parsed.get("persons").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    vault.with_write_txn(|txn| {
        for person in people {
            let Some(id) = person
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| EntityId::from_hex(id).ok())
            else {
                continue;
            };
            let Some(name) = person
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
            else {
                continue;
            };
            let Some(evidence) = person
                .get("evidence_turn_refs")
                .and_then(serde_json::Value::as_array)
                .filter(|refs| !refs.is_empty())
            else {
                continue;
            };
            let mut admissible = true;
            let mut mentioned = false;
            for reference in evidence {
                let Some(turn) = reference
                    .as_str()
                    .and_then(|id| EntityId::from_hex(id).ok())
                else {
                    admissible = false;
                    break;
                };
                if !working_set.contains(&turn)
                    || !matches!(
                        live_entity_row_in_txn(&vault.store, txn, &turn)?,
                        LiveEntityRow::Live {
                            entity_type: ENTITY_TYPE_TURN,
                            ..
                        }
                    )
                {
                    admissible = false;
                    break;
                }
                let facts = read_turn_facts_in_txn(vault, txn, &turn)?;
                if !dreamer_extraction_role_admissible(dreamer_turn_role(facts.speaker.as_deref()))
                {
                    admissible = false;
                    break;
                }
                mentioned |= facts
                    .text
                    .as_deref()
                    .is_some_and(|text| text.contains(name));
            }
            if !admissible || !mentioned {
                continue;
            }
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
            )
            .map_err(|_| invalid_consolidation("extracted person body"))?;
            vault.put_extraction_minted_person_in_txn(
                txn,
                &id,
                ClaimSource::Generated,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )?;
        }
        Ok(())
    })
}
