//! Mirrors one bound extraction reply and builds its verdict operands.
//!
//! A bound reply is an extraction answer whose labels are already bound: each
//! candidate names a listed subject id or a person the reply declares, cites
//! turns with the versions the job read, and carries the proposals the verdict
//! shows the model. The mirror types read that reply as JSON, with entity ids
//! as 32 lowercase hexadecimal digits and values as JSON, and refuse unknown
//! fields. [`verdict_operands`] builds the listed candidates' `CandidateOperand`
//! JSON for one `ai.verdict` call, following the engine's `CandidateOperand`,
//! `TurnEvidence`, `SourceVersion` and `EvidenceRange` serialization.

use serde::Deserialize;
use serde_json::{Value, json};

/// Holds one extraction reply with its labels bound: the candidates the job
/// proposes, the people the reply declares, and the candidates skipped with
/// their reasons.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundExtractionReply {
    /// Holds the reply's candidates in reply order, listed and declared.
    pub candidates: Vec<BoundExtractionCandidate>,
    /// Holds the people the reply declares, each with its reply-local number.
    pub persons: Vec<BoundExtractionPerson>,
    /// Holds the candidates skipped in reply order, each with its reason.
    pub skipped: Vec<SkippedExtractionCandidate>,
}

/// Represents one bound candidate: its reply index, its subject, its claim
/// proposal, and the turns it cites.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundExtractionCandidate {
    /// Holds the candidate's index in the reply's candidates, in order.
    pub index: usize,
    /// Names the candidate's subject: a listed entity id or a declared person number.
    pub subject: BoundExtractionSubject,
    /// Holds the proposed predicate in claim grammar.
    pub predicate: String,
    /// Holds the proposed value as JSON, shown to the model and never trusted.
    pub value: Value,
    /// Holds the proposed confidence from 0 to 1.
    pub confidence: f64,
    /// Holds the lexical hints the reply offers for the candidate, in order.
    pub prospective_queries: Vec<String>,
    /// Holds the arbitrary relationship proposal as JSON, when the reply names one;
    /// the caller reads it, and [`verdict_operands`] leaves it off the operand.
    #[serde(default)]
    pub rel: Option<Value>,
    /// Holds the proposed topic as JSON, when the reply names one; the engine's
    /// `CandidateOperand` names it `topic`, and [`verdict_operands`] leaves it
    /// off the operand.
    #[serde(default)]
    pub topic_key: Option<Value>,
    /// Holds the source turns the candidate cites, each with its served version
    /// and quoted span.
    pub evidence: Vec<BoundTurnEvidence>,
}

/// Represents a bound candidate's subject: a listed entity or a person the reply declares.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundExtractionSubject {
    /// Names a listed subject's entity id as 32 lowercase hexadecimal digits.
    Listed(String),
    /// Names a declared person's reply-local number, the `n` in its `new:P<n>` id.
    Declared(usize),
}

/// Represents one person the reply declares: its reply-local number, its name
/// as written, and the turns naming it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundExtractionPerson {
    /// Holds the person's reply-local number, the `n` in its `new:P<n>` id.
    pub declared: usize,
    /// Holds the person's name as the reply writes it.
    pub name: String,
    /// Holds the turns naming the person, each as 32 lowercase hexadecimal digits.
    pub turns: Vec<String>,
}

/// Represents one skipped candidate: its reply index and why it was skipped.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedExtractionCandidate {
    /// Holds the skipped candidate's index in the reply's candidates.
    pub index: usize,
    /// Tells why the candidate was skipped, as a named result.
    pub reason: String,
}

/// Represents one source turn a candidate cites: the turn with the version
/// read and the quoted span.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundTurnEvidence {
    /// Names the source turn as 32 lowercase hexadecimal digits.
    pub turn: String,
    /// Holds the version the job read the turn at, as the engine's `SourceVersion`
    /// serializes it.
    pub version: BoundSourceVersion,
    /// Holds the quoted byte span in TURN coordinates, including the served start.
    pub span: BoundEvidenceRange,
}

/// Mirrors one source row's version as a scoped read served it, following the
/// engine's `SourceVersion`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundSourceVersion {
    /// Names the source row as 32 lowercase hexadecimal digits.
    pub entity: String,
    /// Holds the row's entity type code.
    pub entity_type: u8,
    /// Records when the vault learned the revision read.
    pub learned_at: u64,
    /// Holds the domain-separated evidence hash of the logical body read, as
    /// `blake3:<hex>`.
    pub revision: String,
    /// Holds the turn's projection hash as `blake3:<hex>`, when the source is a
    /// turn; absent for any other row.
    #[serde(default)]
    pub projection: Option<String>,
}

/// Mirrors one byte range over a turn's projected text, following the engine's
/// `EvidenceRange`.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundEvidenceRange {
    /// Marks the first byte, inclusive.
    pub start: u64,
    /// Marks the end, exclusive.
    pub end: u64,
}

/// Builds the listed candidates' `CandidateOperand` JSON, in reply order, for
/// one `ai.verdict` call.
///
/// Each operand carries its subject, predicate, value and evidence, with each
/// turn's version and span as the engine serializes them; a version without a
/// projection omits it, as the engine does. Declared-subject candidates stay
/// off: the verdict reads listed subjects only. The candidates' `rel` and
/// `topic_key` proposals stay on the reply for the caller.
#[must_use]
pub fn verdict_operands(reply: &BoundExtractionReply) -> Vec<Value> {
    let mut operands = Vec::new();
    for candidate in &reply.candidates {
        let BoundExtractionSubject::Listed(subject) = &candidate.subject else {
            continue;
        };
        let mut evidence = Vec::new();
        for cited in &candidate.evidence {
            let mut version = json!({
                "entity": cited.version.entity,
                "entity_type": cited.version.entity_type,
                "learned_at": cited.version.learned_at,
                "revision": cited.version.revision,
            });
            if let Some(projection) = &cited.version.projection {
                version["projection"] = json!(projection);
            }
            evidence.push(json!({
                "turn": cited.turn,
                "version": version,
                "span": {
                    "start": cited.span.start,
                    "end": cited.span.end,
                },
            }));
        }
        operands.push(json!({
            "subject": subject,
            "predicate": candidate.predicate,
            "value": candidate.value,
            "evidence": evidence,
        }));
    }
    operands
}

/// Holds complete listed-subject operands and their positions in the decoded reply.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionOperands {
    /// Holds operands in listed-subject reply order.
    pub operands: Vec<Value>,
    /// Maps each operand position to the candidate's original reply index.
    pub candidate_indexes: Vec<usize>,
}

/// Builds complete decision operands without binding declared subjects.
///
/// Preserves the existing evidence serialization, validates relationships as
/// the engine's string array, and carries `topic_key` under the wire name `topic`.
///
/// # Errors
///
/// Rejects a relationship proposal that is not an array of strings.
pub fn decision_operands(
    reply: &BoundExtractionReply,
) -> Result<ExtractionOperands, serde_json::Error> {
    let mut operands = verdict_operands(reply);
    let listed = reply
        .candidates
        .iter()
        .filter(|candidate| matches!(&candidate.subject, BoundExtractionSubject::Listed(_)));
    let mut candidate_indexes = Vec::with_capacity(operands.len());
    for (operand, candidate) in operands.iter_mut().zip(listed) {
        if let Some(rel) = &candidate.rel {
            let rel: Vec<String> = serde_json::from_value(rel.clone())?;
            operand["rel"] = json!(rel);
        }
        if let Some(topic) = &candidate.topic_key {
            operand["topic"] = topic.clone();
        }
        candidate_indexes.push(candidate.index);
    }
    Ok(ExtractionOperands {
        operands,
        candidate_indexes,
    })
}

#[cfg(test)]
mod tests {
    //! Tests the reply's decoding and operands over owen and yuki fixtures.

    use super::*;
    use serde_json::{Value, json};

    /// Holds Owen's listed subject id in the fixtures, as 32 lowercase hex digits.
    const OWEN_HEX: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

    /// Holds the cited turn's id in the fixtures, as 32 lowercase hex digits.
    const TURN_HEX: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";

    /// Holds the turn revision the fixtures cite, as `blake3:<hex>`.
    const REVISION: &str =
        "blake3:d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";

    /// Holds the turn projection the fixtures cite when one is present, as
    /// `blake3:<hex>`.
    const PROJECTION: &str =
        "blake3:e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4";

    /// Returns one bound reply as JSON: two listed owen candidates, one declared
    /// yuki candidate, yuki's declaration, and one skipped candidate.
    fn bound_reply_value() -> Value {
        json!({
            "candidates": [
                {
                    "index": 0,
                    "subject": { "listed": OWEN_HEX },
                    "predicate": "likes",
                    "value": "tea",
                    "confidence": 0.9,
                    "prospective_queries": ["owen tea"],
                    "rel": ["fond_of"],
                    "topic_key": { "topic": "drinks" },
                    "evidence": [
                        {
                            "turn": TURN_HEX,
                            "version": {
                                "entity": TURN_HEX,
                                "entity_type": 1,
                                "learned_at": 1_720_000_000_000_u64,
                                "revision": REVISION,
                                "projection": PROJECTION,
                            },
                            "span": { "start": 0, "end": 4 },
                        },
                    ],
                },
                {
                    "index": 1,
                    "subject": { "listed": OWEN_HEX },
                    "predicate": "dislikes",
                    "value": "coffee",
                    "confidence": 0.7,
                    "prospective_queries": [],
                    "evidence": [
                        {
                            "turn": TURN_HEX,
                            "version": {
                                "entity": TURN_HEX,
                                "entity_type": 1,
                                "learned_at": 1_720_000_000_000_u64,
                                "revision": REVISION,
                            },
                            "span": { "start": 5, "end": 11 },
                        },
                    ],
                },
                {
                    "index": 2,
                    "subject": { "declared": 1 },
                    "predicate": "likes",
                    "value": "tea",
                    "confidence": 0.6,
                    "prospective_queries": ["yuki tea"],
                    "evidence": [
                        {
                            "turn": TURN_HEX,
                            "version": {
                                "entity": TURN_HEX,
                                "entity_type": 1,
                                "learned_at": 1_720_000_000_000_u64,
                                "revision": REVISION,
                                "projection": PROJECTION,
                            },
                            "span": { "start": 0, "end": 4 },
                        },
                    ],
                },
            ],
            "persons": [
                { "declared": 1, "name": "yuki", "turns": [TURN_HEX] },
            ],
            "skipped": [
                { "index": 3, "reason": "quote_not_found" },
            ],
        })
    }

    /// A bound reply decodes with its candidates, people and skipped entries.
    #[test]
    fn decodes_a_bound_reply() {
        let reply: BoundExtractionReply =
            serde_json::from_value(bound_reply_value()).expect("the fixture decodes");
        assert_eq!(reply.candidates.len(), 3);
        assert_eq!(reply.persons.len(), 1);
        assert_eq!(reply.skipped.len(), 1);
        assert!(matches!(
            reply.candidates[0].subject,
            BoundExtractionSubject::Listed(_)
        ));
        assert!(matches!(
            reply.candidates[2].subject,
            BoundExtractionSubject::Declared(1)
        ));
        assert_eq!(reply.candidates[0].predicate, "likes");
        assert_eq!(reply.candidates[0].value, json!("tea"));
        assert_eq!(reply.candidates[0].rel, Some(json!(["fond_of"])));
        assert_eq!(
            reply.candidates[0].topic_key,
            Some(json!({ "topic": "drinks" }))
        );
        assert_eq!(reply.candidates[1].rel, None);
        assert_eq!(reply.candidates[1].topic_key, None);
        assert_eq!(
            reply.candidates[0].evidence[0].version.projection,
            Some(PROJECTION.to_owned())
        );
        assert_eq!(reply.candidates[1].evidence[0].version.projection, None);
        assert_eq!(reply.persons[0].name, "yuki");
        assert_eq!(reply.skipped[0].reason, "quote_not_found");
    }

    /// The operands hold the listed candidates in reply order, without the
    /// declared one.
    #[test]
    fn verdict_operands_keep_listed_candidates_only() {
        let reply: BoundExtractionReply =
            serde_json::from_value(bound_reply_value()).expect("the fixture decodes");
        let operands = verdict_operands(&reply);
        assert_eq!(operands.len(), 2);
        assert_eq!(operands[0]["subject"], json!(OWEN_HEX));
        assert_eq!(operands[0]["predicate"], json!("likes"));
        assert_eq!(operands[0]["value"], json!("tea"));
        assert_eq!(operands[1]["predicate"], json!("dislikes"));
        assert_eq!(operands[1]["value"], json!("coffee"));
        assert_eq!(operands[0]["evidence"][0]["turn"], json!(TURN_HEX));
        assert_eq!(operands[0]["evidence"][0]["span"]["start"], json!(0_u64));
        assert_eq!(operands[0]["evidence"][0]["span"]["end"], json!(4_u64));
    }

    /// Each operand's versions carry the served fields, omitting a missing
    /// projection.
    #[test]
    fn verdict_operands_follow_version_serialization() {
        let reply: BoundExtractionReply =
            serde_json::from_value(bound_reply_value()).expect("the fixture decodes");
        let operands = verdict_operands(&reply);
        assert_eq!(operands.len(), 2);
        let first = &operands[0]["evidence"][0]["version"];
        assert_eq!(first["entity"], json!(TURN_HEX));
        assert_eq!(first["entity_type"], json!(1_u8));
        assert_eq!(first["learned_at"], json!(1_720_000_000_000_u64));
        assert_eq!(first["revision"], json!(REVISION));
        assert_eq!(first["projection"], json!(PROJECTION));
        let second = &operands[1]["evidence"][0]["version"];
        assert_eq!(second["entity"], json!(TURN_HEX));
        assert!(second.get("projection").is_none());
    }

    /// A candidate with an unknown field does not decode.
    #[test]
    fn refuses_unknown_fields() {
        let mut reply = bound_reply_value();
        let candidate = reply
            .get_mut("candidates")
            .expect("the fixture has candidates")
            .get_mut(0)
            .expect("the fixture has a first candidate");
        let object = candidate
            .as_object_mut()
            .expect("the fixture candidate is an object");
        assert!(object.insert("bogus".to_owned(), json!(1)).is_none());
        assert!(serde_json::from_value::<BoundExtractionReply>(reply).is_err());
    }
}
