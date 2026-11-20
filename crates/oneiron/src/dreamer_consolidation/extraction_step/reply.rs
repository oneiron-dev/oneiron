//! Checks and decodes a bound reply through the native wire and quote binder.
//!
//! A candidate cites served TURN words by quote and, as a native reply may,
//! a listed claim by its label. The decoded candidate carries each cited
//! claim as a pin at the version the step's request names, the form the
//! verdict operand takes.

use std::collections::BTreeMap;

use oneiron_model::llm::LlmResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ExtractionStepPiece, ListedHead, PreparedExtractionStep};
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
use crate::verbs::PinnedClaim;

/// Holds the decoded candidates, declarations and candidate skips of one bound reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundExtractionReply {
    /// Holds the candidates whose labels, TURN quotes and claim citations bound.
    candidates: Vec<BoundExtractionCandidate>,
    /// Retains every person declaration without deriving an entity identifier.
    persons: Vec<BoundExtractionPerson>,
    /// Explains each candidate the bound wire did not take.
    skipped: Vec<SkippedExtractionCandidate>,
}

/// Holds one candidate with its quotes in TURN coordinates and its cited claims pinned.
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
    /// Holds each listed claim the candidate cites, once, at the version the
    /// step's request names, not a version supplied by the model. Absent
    /// when the candidate cites no claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claim_evidence: Vec<PinnedClaim>,
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
    /// Borrows each frozen Entity id whose step scope holds a correctable
    /// claim, with those claims.
    correctable: &'p BTreeMap<EntityId, Vec<EntityId>>,
    /// Borrows the frozen prior heads behind the call's claim labels.
    heads: &'p BTreeMap<EntityId, ListedHead>,
    /// Borrows the versions the request names, a cited claim's among them
    /// when the job's read serves that claim.
    inputs: &'p [SourceVersion],
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

/// Holds one candidate decode took, with what the reply check judges it by.
struct ReadCandidate {
    /// Holds the candidate with every quote and claim citation that bound.
    candidate: BoundExtractionCandidate,
    /// Holds the Listed subject, when the candidate names one.
    subject: Option<EntityId>,
    /// Holds each listed claim the candidate cites, once.
    cited: Vec<EntityId>,
    /// Names the first quote or label that bound nothing.
    unbound: Option<&'static str>,
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
    ) -> Result<BoundExtractionSubject, String> {
        let label = item
            .get("subject")
            .and_then(Value::as_str)
            .and_then(SubjectLabel::parse);
        match label {
            Some(SubjectLabel::Listed(label)) if label.kind() == LabelKind::Entity => self
                .labels
                .resolve(label)
                .map(|id| BoundExtractionSubject::Listed(id.to_hex()))
                .ok_or_else(|| "extracted candidate names an unlisted subject".to_owned()),
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
                    Err("extracted candidate names an unavailable declared person".to_owned())
                }
            }
            _ => Err("extracted candidate names an unlisted subject".to_owned()),
        }
    }

    /// Reads a candidate's fields and binds each quote and claim label
    /// through the native decoder.
    ///
    /// Every reference is read, as the native reader reads it: a quote or
    /// label that bound nothing is remembered by its first named result
    /// while the others still bind. A cited claim is carried only at a
    /// version the request names, so a claim the job's read does not serve
    /// leaves its candidate a skip.
    ///
    /// # Errors
    ///
    /// The reason decode skips this candidate.
    fn read_bound_candidate(
        &self,
        index: usize,
        item: &Value,
        persons: &[ExtractedPerson],
        authored: bool,
    ) -> Result<ReadCandidate, String> {
        let refs = item
            .get("evidence_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| "candidate evidence_refs must be an array".to_owned())?;
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
            return Err(
                "the bound wire carries labels, TURN quotes and listed claims only; authored raw-id subjects and authored references are not carried".to_owned(),
            );
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
            .ok_or_else(|| "extracted candidate's predicate breaks the claim grammar".to_owned())?
            .to_owned();
        let value = item
            .get("value")
            .filter(|value| !value.is_null())
            .ok_or_else(|| "extracted candidate names no value".to_owned())?
            .clone();
        let confidence = item
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or_else(|| "extracted candidate names no confidence".to_owned())?;
        let prospective_queries = prospective_queries(item).map_err(|error| error.to_string())?;
        let mut evidence = Vec::with_capacity(refs.len());
        let mut claim_evidence = Vec::new();
        let mut cited_claims = Vec::new();
        let mut unbound = None;
        for cited in refs {
            let bound = decode_ref(cited, self).map_err(|error| error.to_string())?;
            let locator = match bound.locator {
                Ok(locator) => locator,
                Err(fault) => {
                    unbound.get_or_insert(fault.name());
                    continue;
                }
            };
            let reference = locator.reference();
            if let Some(claim) = reference.claim_id {
                let version = self
                    .inputs
                    .iter()
                    .find(|version| version.entity == claim)
                    .ok_or_else(|| {
                        "extracted candidate cites a listed claim the job's read does not serve"
                            .to_owned()
                    })?;
                if !cited_claims.contains(&claim) {
                    cited_claims.push(claim);
                    claim_evidence.push(PinnedClaim {
                        claim: claim.to_hex(),
                        version: version.clone(),
                    });
                }
                continue;
            }
            let piece = self
                .pieces
                .iter()
                .find(|piece| piece.turn == reference.source_id)
                .ok_or_else(|| {
                    "the bound wire carries labels, TURN quotes and listed claims only".to_owned()
                })?;
            let (start, end) = reference.byte_range.ok_or_else(|| {
                "the bound wire carries labels, TURN quotes and listed claims only".to_owned()
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
        Ok(ReadCandidate {
            candidate: BoundExtractionCandidate {
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
                claim_evidence,
            },
            subject: subject_id,
            cited: cited_claims,
            unbound,
        })
    }

    /// Tells whether a correction is asked about `read`, by native's rule:
    /// its Listed subject holds a correctable claim the candidate does not
    /// restate. A candidate restates a head it cites when it carries the
    /// head's predicate and value (FIX 8295).
    fn asked(&self, read: &ReadCandidate) -> bool {
        let Some(claims) = read
            .subject
            .and_then(|subject| self.correctable.get(&subject))
        else {
            return false;
        };
        claims.iter().any(|claim| {
            let restated = read.cited.contains(claim)
                && self.heads.get(claim).is_some_and(|head| {
                    head.predicate == read.candidate.predicate && head.value == read.candidate.value
                });
            !restated
        })
    }

    /// Names why verification refuses one of `cited`: a head that is no
    /// evidence under GATE-11. A cited claim the branch holds no prior head
    /// for stays the verdict's to judge.
    fn claim_fault(&self, cited: &[EntityId]) -> Option<&'static str> {
        cited
            .iter()
            .any(|claim| self.heads.get(claim).is_some_and(|head| !head.admissible))
            .then_some("generated claim cannot corroborate")
    }

    /// Decodes accepted candidates and declarations while preserving candidate skips.
    ///
    /// A candidate no correction is asked about surely reaches verification,
    /// so its first quote or label that bound nothing, or else a cited head
    /// that is no evidence, refuses the whole reply, as the native citation
    /// check refuses it. A candidate a correction is asked about is skipped
    /// for an unbound quote and kept with a cited head that is no evidence:
    /// the verdict judges that head. An authored fallback's reply is never
    /// refused here.
    ///
    /// # Errors
    ///
    /// A reply that breaks the extraction contract, and the refusal above.
    fn decode(&self, response: &LlmResponse) -> Result<BoundExtractionReply, String> {
        let reply = extraction_reply(response).map_err(|error| error.to_string())?;
        let authored = authored_fallback(response);
        let mut decoded = BoundExtractionReply {
            candidates: Vec::new(),
            persons: self.declared_people(&reply.persons)?,
            skipped: Vec::new(),
        };
        for (index, item) in reply.candidates.iter().enumerate() {
            let read = match self.read_bound_candidate(index, item, &reply.persons, authored) {
                Ok(read) => read,
                Err(reason) => {
                    decoded
                        .skipped
                        .push(SkippedExtractionCandidate { index, reason });
                    continue;
                }
            };
            let asked = self.asked(&read);
            let reason = match (read.unbound, self.claim_fault(&read.cited)) {
                (Some(reason), _) if authored => reason.to_owned(),
                (Some(reason), _) if asked => format!(
                    "quote unbound ({reason}); the subject holds a correctable claim, skipped like native"
                ),
                (Some(reason), _) => {
                    return Err(format!(
                        "extraction candidate {index} cites outside its source: {reason}",
                    ));
                }
                (None, Some(reason)) if !authored && !asked => {
                    return Err(format!(
                        "extraction candidate {index} cites outside its source: {reason}",
                    ));
                }
                (None, _) => {
                    decoded.candidates.push(read.candidate);
                    continue;
                }
            };
            decoded
                .skipped
                .push(SkippedExtractionCandidate { index, reason });
        }
        Ok(decoded)
    }
}

/// Owns a checked call's labels, pieces, correctable claims, listed heads
/// and input versions so the durable check can outlive this borrow.
pub(super) fn check_bound_reply(
    prepared: &PreparedExtractionStep,
) -> impl Fn(&LlmResponse) -> Result<(), String> + Send + Sync + 'static {
    let labels = prepared.labels.clone();
    let pieces = prepared.pieces.clone();
    let correctable = prepared.correctable.clone();
    let heads = prepared.heads.clone();
    let inputs = prepared.inputs.clone();
    move |response| {
        check_extraction_reply(response)?;
        if authored_fallback(response) {
            return Ok(());
        }
        BoundReplySources {
            labels: &labels,
            pieces: &pieces,
            correctable: &correctable,
            heads: &heads,
            inputs: &inputs,
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
        heads: &prepared.heads,
        inputs: &prepared.inputs,
    }
    .decode(response)
    .map_err(MemoryError::bad_request)?;
    serde_json::to_value(reply).map_err(|error| MemoryError::bad_request(error.to_string()))
}
