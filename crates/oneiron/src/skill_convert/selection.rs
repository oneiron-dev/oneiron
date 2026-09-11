//! Reading the selected conversation and the nearest existing skills the refiner must
//! diff against.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use crate::skill::SkillLifecycle;

use super::door::validate_text;
use super::types::{
    CONVERT_HINT_MAX_BYTES, CONVERT_MAX_NEIGHBORS, CONVERT_MAX_SOURCE_MESSAGES, ConvertRequest,
    ConvertUtterance, SkillNeighbor,
};
use crate::error::ArtifactError;

/// How many SKILL rows the neighbour retrieval reads before it stops.
const CONVERT_NEIGHBOR_SCAN_LIMIT: usize = 1024;

/// Shortest token that participates in neighbour matching. One- and two-letter
/// tokens match everything and therefore rank nothing.
const CONVERT_TOKEN_MIN_CHARS: usize = 3;

/// Resolves the selection into utterances, refusing anything that must not be
/// read: a non-conversational ref, a fenced one, or a selection with no words.
///
/// Every id whose WORDS enter the brief is fence-probed: the MESSAGE children a
/// witnessed turn carries, AND the turn a directly-selected message belongs to.
/// The fence is about the content, and containment cuts both ways — a clear turn
/// container says nothing about its children, and a clear child row says nothing
/// about the fenced turn it sits inside.
pub(super) fn resolve_selection(
    vault: &Vault,
    request: &ConvertRequest,
) -> Result<Vec<ConvertUtterance>> {
    if request.message_refs.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "conversion needs at least one selected message",
        )));
    }
    if request.message_refs.len() > CONVERT_MAX_SOURCE_MESSAGES {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "conversion selects at most 64 messages",
        )));
    }
    let mut selected = BTreeSet::new();
    for reference in &request.message_refs {
        if !selected.insert(*reference) {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "conversion selects each message at most once",
            )));
        }
    }
    if let Some(hint) = &request.hint {
        validate_text(
            hint,
            CONVERT_HINT_MAX_BYTES,
            "hint must be a non-empty string at most 4096 bytes",
        )?;
    }

    let mut said = Vec::new();
    for reference in &request.message_refs {
        // ARCH-0052 P6: no off-record probe. A live room's turns and messages
        // are overlay rows, and this conversion holds a canonical `&Vault`
        // that cannot address them — so a selection naming one fails here as
        // `EntityNotFound`, before the refiner tier is reached, without a
        // per-call membership test.
        match entity_type(vault, reference)? {
            ENTITY_TYPE_TURN => match utterance(vault, reference, "spkr", "txt")? {
                Some(spoken) if spoken.text.is_some() => said.push(spoken),
                // A witness TURN may carry only its speaker stamp; its words
                // remain in MESSAGE children and must be read in scan order.
                _ => said.extend(witnessed_words(vault, reference)?),
            },
            ENTITY_TYPE_MESSAGE => {
                said.extend(utterance(vault, reference, "author", "content")?);
            }
            _ => {
                return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                    "conversion selects TURN or MESSAGE entities",
                )));
            }
        }
    }
    if said.iter().all(|spoken| spoken.text.is_none()) {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "the selection carries no words to refine",
        )));
    }
    Ok(said)
}

fn entity_type(vault: &Vault, id: &EntityId) -> Result<u8> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .get_entity_type_in_txn(&rtxn, id)?
        .ok_or(Error::EntityNotFound)
}

/// The decoded body map of an entity, or `None` when it is absent, truncated,
/// or not a map. The one decode prelude every body read in this module shares.
fn body_entries(vault: &Vault, id: &EntityId) -> Result<Option<Vec<(Value, Value)>>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.entities.get(&rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    Ok(
        match rmpv::decode::read_value(&mut std::io::Cursor::new(body)) {
            Ok(Value::Map(entries)) => Some(entries),
            _ => None,
        },
    )
}

/// Reads one utterance from an entity body, or `None` when it carries no words.
///
/// Both documented spellings of each key are accepted (`spkr`/`speaker`,
/// `txt`/`text`), the tolerance `dreamer_consolidation` and the `actor.*`
/// distiller read turns with; an undecodable body simply says nothing.
fn utterance(
    vault: &Vault,
    id: &EntityId,
    speaker_key: &str,
    text_key: &str,
) -> Result<Option<ConvertUtterance>> {
    let Some(entries) = body_entries(vault, id)? else {
        return Ok(None);
    };
    let mut speaker = None;
    let mut text = None;
    for (key, value) in entries {
        let Some(key) = key.as_str() else { continue };
        if (key == speaker_key || key == "speaker") && speaker.is_none() {
            speaker = value.as_str().map(str::to_owned);
        } else if (key == text_key || key == "text") && text.is_none() {
            text = value.as_str().map(str::to_owned);
        }
    }
    Ok(
        (speaker.is_some() || text.is_some()).then_some(ConvertUtterance {
            source: *id,
            speaker,
            text,
        }),
    )
}

/// The witnessed words of a turn: its MESSAGE children, in `(order, id)`.
fn witnessed_words(vault: &Vault, turn: &EntityId) -> Result<Vec<ConvertUtterance>> {
    // `edges_in` reports the FAR end in `target`, so these are the messages
    // that named this turn as their part-of container.
    let messages: Vec<EntityId> = vault
        .edges_in(turn)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target)
        .collect();

    let mut said: Vec<(u64, EntityId, ConvertUtterance)> = Vec::new();
    for message in messages {
        if entity_type(vault, &message)? != ENTITY_TYPE_MESSAGE {
            continue;
        }
        if let Some(spoken) = utterance(vault, &message, "author", "content")? {
            said.push((message_order(vault, &message)?, message, spoken));
        }
    }
    said.sort_by_key(|(order, id, _)| (*order, *id));
    Ok(said.into_iter().map(|(_, _, spoken)| spoken).collect())
}

/// A witnessed message's position inside its turn; absent reads as first.
fn message_order(vault: &Vault, message: &EntityId) -> Result<u64> {
    let Some(entries) = body_entries(vault, message)? else {
        return Ok(0);
    };
    Ok(entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("order"))
        .and_then(|(_, value)| value.as_u64())
        .unwrap_or(0))
}

/// The nearest existing skills by name/description, nearest first.
///
/// Retrieval is over the SELECTED WORDS, because the refined name and
/// description do not exist yet — the shortlist has to be in the brief the
/// refiner reads, and a second refinement pass to earn a better query would
/// double the ticket's only LLM cost to re-rank eight rows.
///
/// Superseded revisions are excluded: they are frozen history, and a proposal
/// against one could never be admitted.
pub(super) fn nearest_skills(
    vault: &Vault,
    said: &[ConvertUtterance],
    hint: Option<&str>,
) -> Result<Vec<SkillNeighbor>> {
    let mut query = BTreeSet::new();
    for spoken in said {
        if let Some(text) = &spoken.text {
            collect_tokens(text, &mut query);
        }
    }
    if let Some(hint) = hint {
        collect_tokens(hint, &mut query);
    }
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let mut scored: Vec<(usize, EntityId, SkillNeighbor)> = Vec::new();
    for entity in
        vault.entities_by_type_page(ENTITY_TYPE_SKILL, None, CONVERT_NEIGHBOR_SCAN_LIMIT)?
    {
        let record = match vault.get_skill_record(&entity) {
            Ok(Some(record)) => record,
            // A body that cannot be decoded cannot be diffed against, so it is
            // not a neighbour. One unreadable legacy row must not deny the
            // whole retrieval.
            Ok(None) | Err(_) => continue,
        };
        if record.lifecycle_status == SkillLifecycle::Superseded {
            continue;
        }
        let mut tokens = BTreeSet::new();
        collect_tokens(&record.skill_id, &mut tokens);
        collect_tokens(&record.desc, &mut tokens);
        let score = query.intersection(&tokens).count();
        if score == 0 {
            continue;
        }
        scored.push((
            score,
            entity,
            SkillNeighbor {
                entity,
                skill_id: record.skill_id,
                desc: record.desc,
            },
        ));
    }
    // Score descending, then entity id: a tie resolves the same way on every
    // replica, so two vaults hand their refiners the same shortlist.
    scored.sort_by_key(|(score, entity, _)| (Reverse(*score), *entity));
    scored.truncate(CONVERT_MAX_NEIGHBORS);
    Ok(scored
        .into_iter()
        .map(|(_, _, neighbor)| neighbor)
        .collect())
}

fn collect_tokens(text: &str, out: &mut BTreeSet<String>) {
    for token in text.split(|character: char| !character.is_alphanumeric()) {
        if token.chars().count() >= CONVERT_TOKEN_MIN_CHARS {
            out.insert(token.to_lowercase());
        }
    }
}
