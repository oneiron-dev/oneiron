//! Explicit PERSON outputs from the production extraction response.
//!
//! Subject ids alone never imply PERSON. Only typed person outputs backed by
//! admissible turns in this extraction's working set, or by the NOTE a
//! review read, may mint a new row. The id is the engine's, bound once per
//! reply (`bindings`, FIX 7506), never the reply's. The mint door stamps
//! Generated provenance and refuses existing/deleted ids.

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
use crate::llm::ScopeResource;
use crate::registry::{ENTITY_TYPE_NOTE, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

mod bindings;
pub(super) use bindings::{MintNamespace, PersonBindings, bind_people};

pub(super) fn mint_extracted_people(
    vault: &Vault,
    people: &PersonBindings,
    working_set: &[EntityId],
    scope: &crate::llm::Scope,
    now: u64,
    deadline: Option<&WakePassDeadline>,
    fence: Option<&ConsolidationFence>,
) -> Result<()> {
    let people: Vec<_> = people.bound().collect();
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
            for &turn in &person.sources {
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
            put_person(vault, txn, &person.id, name, now)?;
        }
        Ok(())
    })
}

/// The NOTE a review read, as its people are minted from it: its id, the
/// stored version the review read, and the projected markdown its call
/// showed.
pub(super) struct NoteSource<'n> {
    pub(super) id: EntityId,
    pub(super) version: &'n ScopeResource,
    pub(super) markdown: &'n str,
}

/// The people a NOTE review's reply declared (FIX 7506), each from the NOTE
/// itself: written only while that NOTE is live at the version the review
/// read and its projected markdown names them, under the writer's own name
/// rules. A NOTE changed since is the next review's to read.
pub(super) fn mint_note_people(
    vault: &Vault,
    people: &PersonBindings,
    note: &NoteSource<'_>,
    now: u64,
) -> Result<()> {
    let people: Vec<_> = people
        .bound()
        .filter(|person| person.sources == [note.id])
        .collect();
    if people.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        let current = match live_entity_row_in_txn(&vault.store, txn, &note.id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_NOTE,
                ..
            } => vault.get_raw_in(txn, &note.id)?.map(|raw| {
                super::resources::document_version(
                    note.id,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
            }),
            _ => None,
        };
        if current.as_ref() != Some(note.version) {
            return Ok(());
        }
        for person in &people {
            let name = person.name.trim();
            let normalized_name = normalize_name_span(name);
            if name.is_empty()
                || !normalized_name.chars().any(char::is_alphabetic)
                || !has_name_span(note.markdown, &normalized_name)
            {
                continue;
            }
            put_person(vault, txn, &person.id, name, now)?;
        }
        Ok(())
    })
}

/// Writes one extracted PERSON named `name` under `id`, Generated; the door
/// refuses an existing or deleted id.
fn put_person(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    name: &str,
    now: u64,
) -> Result<()> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .map_err(|_| invalid_consolidation("extracted person body"))?;
    vault.put_extraction_minted_person_in_txn(
        txn,
        id,
        ClaimSource::Generated,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &body,
    )?;
    Ok(())
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
