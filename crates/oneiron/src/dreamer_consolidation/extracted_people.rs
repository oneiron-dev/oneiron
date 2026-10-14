//! Explicit PERSON outputs from the production extraction response.
//!
//! Subject ids alone never imply PERSON. Only typed person outputs backed by
//! admissible turns in this extraction's working set may mint a new row. The
//! mint door stamps Generated provenance and refuses existing/deleted ids.

use super::resources::ConsolidationFence;
use super::support::invalid_consolidation;
use super::watermark::read_turn_facts_in_txn;
use crate::Vault;
use crate::analyzer::normalize::{casefold, nfkc};
use crate::claim::ClaimSource;
use crate::dreamer_runner::{dreamer_extraction_role_admissible, dreamer_turn_role};
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::LlmResponse;
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

pub(super) fn mint_extracted_people(
    vault: &Vault,
    response: &LlmResponse,
    working_set: &[EntityId],
    scope: &crate::llm::Scope,
    now: u64,
    deadline: Option<&WakePassDeadline>,
    fence: Option<&ConsolidationFence>,
) -> Result<()> {
    let people = super::executor::extraction::extraction_reply(response)?.persons;
    if people.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        // Check before the first write. Once admitted, the gated write is not
        // interrupted mid-transaction by the wake clock.
        if deadline.is_some_and(WakePassDeadline::expired) {
            return Err(invalid_consolidation(
                "wake pass expired before person mint",
            ));
        }
        if let Some((binding, actor)) = fence.and_then(ConsolidationFence::fallback) {
            let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
            if !crate::llm::verified_step_consolidation_eligible_in_txn(
                vault,
                txn,
                &policy,
                binding.step,
                actor,
                binding.response_hash,
            )
            .map_err(|_| invalid_consolidation("invalid extraction fallback checkpoint"))?
            {
                return Err(invalid_consolidation(
                    "extraction fallback eligibility revoked",
                ));
            }
        }
        // A branch's names are checked against the text its model saw, so
        // the whole branch fence must still hold before the first mint.
        // Grants are judged at this writer's own clock, never a stale floor.
        if let Some(fence) = fence
            && !people.is_empty()
        {
            crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            fence.validate_in_txn(vault, txn)?;
        }
        for person in &people {
            let Ok(id) = EntityId::from_hex(&person.id) else {
                continue;
            };
            let name = person.name.trim();
            if name.is_empty() {
                continue;
            }
            let normalized_name = normalize_name_span(name);
            if !normalized_name.chars().any(char::is_alphabetic) {
                continue;
            }
            let mut admissible = true;
            let mut mentioned = false;
            for reference in &person.evidence_turn_refs {
                let Ok(turn) = EntityId::from_hex(reference) else {
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
                let raw = vault
                    .get_raw_in(txn, &turn)?
                    .ok_or_else(|| invalid_consolidation("extraction source disappeared"))?;
                let resource = super::resources::document_version(
                    turn,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                );
                if !scope.allows_read(&resource) {
                    return Err(invalid_consolidation(
                        "extraction source version is not in scope",
                    ));
                }
                let facts = read_turn_facts_in_txn(vault, txn, &turn)?;
                if !dreamer_extraction_role_admissible(dreamer_turn_role(
                    facts.speaker.as_deref(),
                    &vault.config.assistant_display_names,
                )) {
                    admissible = false;
                    break;
                }
                let text = match fence {
                    Some(fence) => fence.turn_text(&turn)?.map(str::to_owned),
                    None => facts.text,
                };
                mentioned |= text
                    .as_deref()
                    .is_some_and(|text| has_name_span(text, &normalized_name));
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

// Normalize spelling and whitespace, but never strip punctuation or accents:
// separate words must not collapse into evidence for a different name.
fn normalize_name_span(text: &str) -> String {
    let normalized = nfkc(text);
    casefold(&normalized)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn has_name_span(text: &str, normalized_name: &str) -> bool {
    if normalized_name.is_empty() {
        return false;
    }
    let text = normalize_name_span(text);
    text.match_indices(normalized_name).any(|(start, span)| {
        text[..start]
            .chars()
            .next_back()
            .is_none_or(name_span_boundary)
            && text[start + span.len()..]
                .chars()
                .next()
                .is_none_or(name_span_boundary)
    })
}

// Fail closed on unknown separators, combining marks, identifiers, and name
// continuations such as apostrophes or hyphens (Ann is not Ann-Marie).
fn name_span_boundary(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '.' | ','
                | '!'
                | '?'
                | ';'
                | ':'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '"'
                | '“'
                | '”'
                | '«'
                | '»'
        )
}
