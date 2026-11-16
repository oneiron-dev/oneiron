//! Mints joined people once and binds only the rows the engine actually returned.

use std::collections::BTreeSet;

use oneiron_remote::OneironClient;
use serde_json::{Value, json};

use crate::extraction_reply::{
    BoundExtractionReply, BoundExtractionSubject, SkippedExtractionCandidate,
};

use super::inputs::{Turn, require_turn};
use super::join::{Joined, PersonKey};
use super::{Error, PersonResult, SkippedCandidate, wire};

/// Holds the reply after person binding and its complete skip tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct Bound {
    /// Holds only Listed candidates and no person declarations.
    pub reply: BoundExtractionReply,
    /// Preserves every decoder skip or refused person's reason tokens.
    pub skipped: Vec<SkippedCandidate>,
}

/// Builds the single person batch with exact served versions in served order.
///
/// # Errors
///
/// Rejects a naming TURN absent from the attempt's served inputs before any call.
pub fn person_request(people: &[PersonKey], turns: &[Turn]) -> Result<Value, Error> {
    let mut cited = BTreeSet::new();
    let mut items = Vec::with_capacity(people.len());
    for (key, person) in people.iter().enumerate() {
        let mut evidence = Vec::with_capacity(person.turns.len());
        for turn in &person.turns {
            require_turn(turn, turns)?;
            cited.insert(turn.as_str());
            evidence.push(json!({"stored": turn}));
        }
        items.push(json!({
            "kind": "person",
            "spec": { "local": format!("person-{key}"), "name": person.name, "evidence": evidence },
        }));
    }
    let mut sources = Vec::new();
    for turn in turns {
        if cited.remove(turn.turn.as_str()) {
            sources.push(turn.version.clone());
        }
    }
    Ok(json!({"items": items, "sources": sources}))
}

/// Commits all person keys in one batch, or makes no call when none exists.
pub(super) fn mint(
    client: &OneironClient,
    people: &[PersonKey],
    turns: &[Turn],
) -> Result<Vec<PersonResult>, Error> {
    if people.is_empty() {
        return Ok(Vec::new());
    }
    let request = person_request(people, turns)?;
    wire::commit(client, request, people.len())?
        .into_iter()
        .enumerate()
        .map(|(key, view)| {
            let id = if view.landed {
                Some(view.rows.first().cloned().ok_or_else(|| Error::Decode {
                    verb: wire::COMMIT,
                    message: "a landed person item names no PERSON row".to_owned(),
                })?)
            } else {
                None
            };
            Ok(PersonResult { key, id, view })
        })
        .collect()
}

/// Replaces declared subjects only with a landed person's returned id.
///
/// Refusals remove their candidates and preserve every item token. The reply's
/// single-string skip mirror carries a JSON array for that refusal; `skipped`
/// retains the original tokens without joining, rewording or parsing them.
///
/// # Errors
///
/// Rejects a missing person result or a landed result without an identifier.
pub fn bind(joined: Joined, people: &[PersonResult]) -> Result<Bound, Error> {
    let mut bound = Bound {
        reply: joined.reply,
        skipped: joined.skipped,
    };
    let mut candidates = Vec::with_capacity(bound.reply.candidates.len());
    for mut candidate in bound.reply.candidates {
        if matches!(&candidate.subject, BoundExtractionSubject::Declared(_)) {
            let key = joined
                .bindings
                .iter()
                .find(|binding| binding.index == candidate.index)
                .map(|binding| binding.key)
                .ok_or_else(|| binding_error("a declared candidate has no joined person key"))?;
            let person = people
                .iter()
                .find(|person| person.key == key)
                .ok_or_else(|| binding_error("a joined person key has no commit result"))?;
            if person.view.landed {
                let id = person
                    .id
                    .as_ref()
                    .ok_or_else(|| binding_error("a landed person has no identifier"))?;
                candidate.subject = BoundExtractionSubject::Listed(id.clone());
            } else {
                bound.reply.skipped.push(SkippedExtractionCandidate {
                    index: candidate.index,
                    reason: json!(person.view.reasons).to_string(),
                });
                bound.skipped.push(SkippedCandidate {
                    index: candidate.index,
                    reasons: person.view.reasons.clone(),
                });
                continue;
            }
        }
        candidates.push(candidate);
    }
    bound.reply.candidates = candidates;
    bound.reply.persons.clear();
    Ok(bound)
}

/// Names malformed person binding data as the commit stage's decoding failure.
fn binding_error(message: &str) -> Error {
    Error::Decode {
        verb: wire::COMMIT,
        message: message.to_owned(),
    }
}
