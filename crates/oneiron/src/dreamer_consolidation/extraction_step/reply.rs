//! Checks and decodes a bound reply through the native wire and quote binder.

use std::collections::BTreeSet;

use oneiron_model::llm::LlmResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ExtractionStepPiece, PreparedExtractionStep};
use crate::dreamer_consolidation::call_labels::{
    CallLabelMap, CallSources, LabelKind, SourceShown, SubjectLabel, new_person,
};
use crate::dreamer_consolidation::executor::extraction::{
    ExtractedPerson, authored_fallback, check_extraction_reply, decode_ref, extraction_reply,
    prospective_queries,
};
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::{EvidenceRange, SourceVersion};

/// Holds the decoded candidates, declarations and candidate skips of one bound reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundExtractionReply {
    /// Holds the candidates whose labels and TURN quotes bound.
    candidates: Vec<BoundExtractionCandidate>,
    /// Retains every person declaration without deriving an entity identifier.
    persons: Vec<BoundExtractionPerson>,
    /// Explains each candidate the bound wire did not take.
    skipped: Vec<SkippedExtractionCandidate>,
}

/// Holds one candidate with evidence in its TURN's coordinates.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundExtractionCandidate {
    /// Holds the candidate's zero-based position in the model reply.
    index: usize,
    /// Names a listed entity or a person declared by this reply.
    subject: BoundExtractionSubject,
    /// Holds the predicate in claim grammar.
    predicate: String,
    /// Holds the proposed non-null value without writing it.
    value: Value,
    /// Holds the model's confidence between zero and one.
    confidence: f64,
    /// Holds the native normalized prospective query hints.
    prospective_queries: Vec<String>,
    /// Retains the optional relationship proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rel: Option<Value>,
    /// Retains the optional topic proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    topic_key: Option<Value>,
    /// Holds the bound TURN quotes and their checked source versions.
    evidence: Vec<BoundTurnEvidence>,
}

/// Names a subject without minting a declared person.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum BoundExtractionSubject {
    /// Names an entity the call listed, as lowercase hexadecimal digits.
    Listed(String),
    /// Names the reply-local declaration number of a person.
    Declared(usize),
}

/// Retains one person declaration and the TURNs its labels name.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundExtractionPerson {
    /// Holds the reply-local declaration number.
    declared: usize,
    /// Retains the name as the declaration wrote it.
    name: String,
    /// Holds the declared source TURNs as lowercase hexadecimal digits.
    turns: Vec<String>,
}

/// Explains why one candidate was not decoded into the bound wire.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkippedExtractionCandidate {
    /// Holds the candidate's zero-based position in the model reply.
    index: usize,
    /// Holds the candidate's skip reason.
    reason: String,
}

/// Holds a quoted TURN range and the version checked with its served words.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundTurnEvidence {
    /// Names the TURN as lowercase hexadecimal digits.
    turn: String,
    /// Holds the checked source version, not a version supplied by the model.
    version: SourceVersion,
    /// Holds the quote range in TURN coordinates, including the served start.
    span: EvidenceRange,
}

/// Supplies native quote binding with exactly the words this bound call showed.
struct BoundReplySources<'p> {
    /// Borrows the labels assigned when the transcript was prepared.
    labels: &'p CallLabelMap,
    /// Borrows the single served piece and source pin for each TURN.
    pieces: &'p [ExtractionStepPiece],
    /// Borrows the frozen Entity ids whose step scope holds a correctable claim.
    correctable: &'p BTreeSet<EntityId>,
}

impl CallSources for BoundReplySources<'_> {
    /// Returns the labels assigned by this bound call.
    fn labels(&self) -> &CallLabelMap {
        self.labels
    }

    /// Returns the TURN's served words without person-mint project authority.
    fn shown(&self, turn: EntityId) -> Option<SourceShown<'_>> {
        let piece = self.pieces.iter().find(|piece| piece.turn == turn)?;
        Some(SourceShown {
            text: Some(&piece.text),
            project: None,
        })
    }
}

/// Separates decode skips from quote faults that refuse a model reply.
enum CandidateReplyFault {
    /// Leaves a candidate that decode cannot take as a skip.
    Skipped(String),
    /// Refuses an otherwise decoded candidate whose quote bound
    /// nothing, with its Listed subject when it has one.
    Unbound(&'static str, Option<EntityId>),
}

impl BoundReplySources<'_> {
    /// Retains every contract-checked declaration without binding or minting a person.
    fn declared_people(
        &self,
        persons: &[ExtractedPerson],
    ) -> Result<Vec<BoundExtractionPerson>, String> {
        persons
            .iter()
            .map(|person| {
                let declared = new_person(&person.id)
                    .ok_or_else(|| "extraction response breaks its contract".to_owned())?;
                let mut turns: Vec<_> = person
                    .evidence_turn_refs
                    .iter()
                    .filter_map(|label| self.labels.resolve_as(LabelKind::Turn, label))
                    .collect();
                turns.sort_unstable();
                turns.dedup();
                Ok(BoundExtractionPerson {
                    declared,
                    name: person.name.clone(),
                    turns: turns.into_iter().map(|turn| turn.to_hex()).collect(),
                })
            })
            .collect()
    }

    /// Resolves a listed entity or a declared person without deriving any identifier.
    fn subject(
        &self,
        item: &Value,
        persons: &[ExtractedPerson],
    ) -> Result<BoundExtractionSubject, CandidateReplyFault> {
        let label = item
            .get("subject")
            .and_then(Value::as_str)
            .and_then(SubjectLabel::parse);
        match label {
            Some(SubjectLabel::Listed(label)) if label.kind() == LabelKind::Entity => self
                .labels
                .resolve(label)
                .map(|id| BoundExtractionSubject::Listed(id.to_hex()))
                .ok_or_else(|| {
                    CandidateReplyFault::Skipped(
                        "extracted candidate names an unlisted subject".to_owned(),
                    )
                }),
            Some(SubjectLabel::NewPerson(number)) => {
                let person = persons
                    .iter()
                    .find(|person| new_person(&person.id) == Some(number));
                let available = person.is_some_and(|person| {
                    !person.name.trim().is_empty()
                        && person.evidence_turn_refs.iter().all(|label| {
                            self.labels
                                .resolve_as(LabelKind::Turn, label)
                                .and_then(|turn| self.shown(turn))
                                .is_some()
                        })
                });
                if available {
                    Ok(BoundExtractionSubject::Declared(number))
                } else {
                    Err(CandidateReplyFault::Skipped(
                        "extracted candidate names an unavailable declared person".to_owned(),
                    ))
                }
            }
            _ => Err(CandidateReplyFault::Skipped(
                "extracted candidate names an unlisted subject".to_owned(),
            )),
        }
    }

    /// Reads a candidate's fields and binds each quote through the native decoder.
    fn read_bound_candidate(
        &self,
        index: usize,
        item: &Value,
        persons: &[ExtractedPerson],
        authored: bool,
    ) -> Result<BoundExtractionCandidate, CandidateReplyFault> {
        let refs = item
            .get("evidence_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CandidateReplyFault::Skipped("candidate evidence_refs must be an array".to_owned())
            })?;
        let raw_subject = item
            .get("subject")
            .and_then(Value::as_str)
            .is_some_and(|subject| SubjectLabel::parse(subject).is_none());
        let authored_refs = refs.iter().any(|cited| {
            ["source_id", "byte_range", "claim_id"]
                .iter()
                .any(|key| cited.get(key).is_some())
        });
        if authored && (raw_subject || authored_refs) {
            return Err(CandidateReplyFault::Skipped(
                "the bound wire carries labels and TURN quotes only; authored raw-id subjects and authored references are not carried".to_owned(),
            ));
        }
        let subject = self.subject(item, persons)?;
        let subject_id = match &subject {
            BoundExtractionSubject::Listed(hex) => EntityId::from_hex(hex).ok(),
            BoundExtractionSubject::Declared(_) => None,
        };
        let predicate = item
            .get("predicate")
            .and_then(Value::as_str)
            .filter(|predicate| crate::claim::validate_predicate(predicate, false).is_ok())
            .ok_or_else(|| {
                CandidateReplyFault::Skipped(
                    "extracted candidate's predicate breaks the claim grammar".to_owned(),
                )
            })?
            .to_owned();
        let value = item
            .get("value")
            .filter(|value| !value.is_null())
            .ok_or_else(|| {
                CandidateReplyFault::Skipped("extracted candidate names no value".to_owned())
            })?
            .clone();
        let confidence = item
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or_else(|| {
                CandidateReplyFault::Skipped("extracted candidate names no confidence".to_owned())
            })?;
        let prospective_queries = prospective_queries(item)
            .map_err(|error| CandidateReplyFault::Skipped(error.to_string()))?;
        let mut evidence = Vec::with_capacity(refs.len());
        for cited in refs {
            let bound = decode_ref(cited, self)
                .map_err(|error| CandidateReplyFault::Skipped(error.to_string()))?;
            let locator = bound
                .locator
                .map_err(|fault| CandidateReplyFault::Unbound(fault.name(), subject_id))?;
            let reference = locator.reference();
            let piece = self
                .pieces
                .iter()
                .find(|piece| piece.turn == reference.source_id)
                .ok_or_else(|| {
                    CandidateReplyFault::Skipped(
                        "the bound wire carries labels and TURN quotes only".to_owned(),
                    )
                })?;
            let (start, end) = reference.byte_range.ok_or_else(|| {
                CandidateReplyFault::Skipped(
                    "the bound wire carries labels and TURN quotes only".to_owned(),
                )
            })?;
            evidence.push(BoundTurnEvidence {
                turn: piece.turn.to_hex(),
                version: piece.version.clone(),
                span: EvidenceRange {
                    start: piece.start + start as u64,
                    end: piece.start + end as u64,
                },
            });
        }
        Ok(BoundExtractionCandidate {
            index,
            subject,
            predicate,
            value,
            confidence,
            prospective_queries,
            rel: item.get("rel").filter(|value| !value.is_null()).cloned(),
            topic_key: item
                .get("topic_key")
                .filter(|value| !value.is_null())
                .cloned(),
            evidence,
        })
    }

    /// Decodes accepted candidates and declarations while preserving candidate skips.
    fn decode(&self, response: &LlmResponse) -> Result<BoundExtractionReply, String> {
        let reply = extraction_reply(response).map_err(|error| error.to_string())?;
        let authored = authored_fallback(response);
        let mut decoded = BoundExtractionReply {
            candidates: Vec::new(),
            persons: self.declared_people(&reply.persons)?,
            skipped: Vec::new(),
        };
        for (index, item) in reply.candidates.iter().enumerate() {
            let reason = match self.read_bound_candidate(index, item, &reply.persons, authored) {
                Ok(candidate) => {
                    decoded.candidates.push(candidate);
                    continue;
                }
                Err(CandidateReplyFault::Skipped(reason)) => reason,
                Err(CandidateReplyFault::Unbound(reason, _)) if authored => reason.to_owned(),
                Err(CandidateReplyFault::Unbound(reason, Some(id)))
                    if self.correctable.contains(&id) =>
                {
                    format!(
                        "quote unbound ({reason}); the subject holds a correctable claim, skipped like native"
                    )
                }
                Err(CandidateReplyFault::Unbound(reason, _)) => {
                    return Err(format!(
                        "extraction candidate {index} cites outside its source: {reason}",
                    ));
                }
            };
            decoded
                .skipped
                .push(SkippedExtractionCandidate { index, reason });
        }
        Ok(decoded)
    }
}

/// Owns a checked call's labels, pieces and correctable set so the
/// durable check can outlive this borrow.
pub(super) fn check_bound_reply(
    prepared: &PreparedExtractionStep,
) -> impl Fn(&LlmResponse) -> Result<(), String> + Send + Sync + 'static {
    let labels = prepared.labels.clone();
    let pieces = prepared.pieces.clone();
    let correctable = prepared.correctable.clone();
    move |response| {
        check_extraction_reply(response)?;
        if authored_fallback(response) {
            return Ok(());
        }
        BoundReplySources {
            labels: &labels,
            pieces: &pieces,
            correctable: &correctable,
        }
        .decode(response)
        .map(|_| ())
    }
}

/// Decodes a finished response against the same checked pieces on fresh and memo submits.
pub(super) fn decode_bound_reply(
    response: &LlmResponse,
    prepared: &PreparedExtractionStep,
) -> MemoryResult<Value> {
    let reply = BoundReplySources {
        labels: &prepared.labels,
        pieces: &prepared.pieces,
        correctable: &prepared.correctable,
    }
    .decode(response)
    .map_err(MemoryError::bad_request)?;
    serde_json::to_value(reply).map_err(|error| MemoryError::bad_request(error.to_string()))
}
