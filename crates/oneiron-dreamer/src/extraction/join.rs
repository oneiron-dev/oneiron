//! Joins reply-local indexes and declaration bindings without client calls.

use std::collections::BTreeMap;

use crate::extraction_reply::{
    BoundExtractionReply, BoundExtractionSubject, SkippedExtractionCandidate,
};

use super::SkippedCandidate;

/// Identifies one person's trimmed name and sorted, distinct naming TURNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonKey {
    /// Holds the name after trimming leading and trailing whitespace.
    pub name: String,
    /// Holds the sorted set of naming TURN ids.
    pub turns: Vec<String>,
}

/// Maps a joined candidate or skip to its unchanged reply-local origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOrigin {
    /// Names the entry in joined numbering.
    pub index: usize,
    /// Names its reply in extraction completion order.
    pub reply: usize,
    /// Names the entry in that reply's numbering.
    pub original_index: usize,
}

/// Binds a surviving declared candidate to one person key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredBinding {
    /// Names the candidate in joined numbering.
    pub index: usize,
    /// Names its person key in first-seen order.
    pub key: usize,
}

/// Holds the pure join before any person item has been committed.
#[derive(Debug, Clone, PartialEq)]
pub struct Joined {
    /// Holds candidates and decoder skips with globally rebased indexes.
    pub reply: BoundExtractionReply,
    /// Holds distinct person keys in first-seen order.
    pub people: Vec<PersonKey>,
    /// Preserves every joined entry's reply-local origin.
    pub origins: Vec<CandidateOrigin>,
    /// Maps every surviving declared candidate to its own reply's declaration.
    pub bindings: Vec<DeclaredBinding>,
    /// Preserves skips with their reasons as separate, unchanged tokens.
    pub skipped: Vec<SkippedCandidate>,
}

/// Joins candidates in reply order without changing their claim fields or evidence.
///
/// Candidates and skips share the model's candidate numbering. Each reply's
/// indexes advance by that reply's greatest index plus one, including skips.
/// Person numbers remain local; only their separate binding map crosses replies.
#[must_use]
pub fn join_replies(replies: &[BoundExtractionReply]) -> Joined {
    let mut joined = Joined {
        reply: BoundExtractionReply {
            candidates: Vec::new(),
            persons: Vec::new(),
            skipped: Vec::new(),
        },
        people: Vec::new(),
        origins: Vec::new(),
        bindings: Vec::new(),
        skipped: Vec::new(),
    };
    let mut offset = 0;
    for (reply_index, reply) in replies.iter().enumerate() {
        let mut declared = BTreeMap::new();
        for person in &reply.persons {
            let mut turns = person.turns.clone();
            turns.sort();
            turns.dedup();
            let key = PersonKey {
                name: person.name.trim().to_owned(),
                turns,
            };
            let position = joined
                .people
                .iter()
                .position(|person| person == &key)
                .unwrap_or_else(|| {
                    let position = joined.people.len();
                    joined.people.push(key);
                    position
                });
            declared.insert(person.declared, position);
        }
        for candidate in &reply.candidates {
            let mut candidate = candidate.clone();
            let original_index = candidate.index;
            candidate.index += offset;
            joined.origins.push(CandidateOrigin {
                index: candidate.index,
                reply: reply_index,
                original_index,
            });
            if let BoundExtractionSubject::Declared(number) = &candidate.subject {
                let Some(key) = declared.get(number) else {
                    let reason = "declared subject has no person in its own reply".to_owned();
                    joined.reply.skipped.push(SkippedExtractionCandidate {
                        index: candidate.index,
                        reason: reason.clone(),
                    });
                    joined.skipped.push(SkippedCandidate {
                        index: candidate.index,
                        reasons: vec![reason],
                    });
                    continue;
                };
                joined.bindings.push(DeclaredBinding {
                    index: candidate.index,
                    key: *key,
                });
            }
            joined.reply.candidates.push(candidate);
        }
        for skipped in &reply.skipped {
            let index = skipped.index + offset;
            joined.origins.push(CandidateOrigin {
                index,
                reply: reply_index,
                original_index: skipped.index,
            });
            joined.reply.skipped.push(SkippedExtractionCandidate {
                index,
                reason: skipped.reason.clone(),
            });
            joined.skipped.push(SkippedCandidate {
                index,
                reasons: vec![skipped.reason.clone()],
            });
        }
        offset += reply
            .candidates
            .iter()
            .map(|candidate| candidate.index)
            .chain(reply.skipped.iter().map(|skipped| skipped.index))
            .max()
            .map_or(0, |index| index + 1);
    }
    joined
}
