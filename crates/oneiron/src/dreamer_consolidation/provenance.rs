use rmpv::Value;

use super::support::invalid_consolidation;
use super::watermark::entity_ref_from_value;
use crate::Vault;
use crate::claim::{ClaimSource, claim_evidence_taint};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;

// ---------------------------------------------------------------------------
// Promotion candidate (D7 shape) — DEFINED here (the producer);
// dreamer_promotion (ONE-1290) re-exports it.
// ---------------------------------------------------------------------------

/// One typed hop of a consolidation provenance chain (ONE-1710).
///
/// The kinds are ADDRESSING roles, not trust classes: a chain says which
/// stored entities a candidate descends from, and `evidence_chain_source`
/// separately folds those into the D10 meet. `EntityId` carries no
/// `Serialize`/`Deserialize` (entity_id.rs), so the chain rides the crate's
/// hand-rolled rmpv codec below rather than serde derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsolidationProvenanceHopKind {
    /// The stored peer-answer TURN.
    AnswerTurn,
    /// The synced consult TASK that elicited the answer.
    ConsultTask,
    /// The answering peer CONNECTION actor (never the vendor/harness label).
    PeerActor,
    /// An optional durable result artifact carried by the answer.
    ResultArtifact,
}

impl ConsolidationProvenanceHopKind {
    /// The pinned on-disk string for this hop kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnswerTurn => "answer_turn",
            Self::ConsultTask => "consult_task",
            Self::PeerActor => "peer_actor",
            Self::ResultArtifact => "result_artifact",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "answer_turn" => Some(Self::AnswerTurn),
            "consult_task" => Some(Self::ConsultTask),
            "peer_actor" => Some(Self::PeerActor),
            "result_artifact" => Some(Self::ResultArtifact),
            _ => None,
        }
    }
}

/// One hop: what it is, which entity it names, and (optionally) the actor
/// behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationProvenanceHop {
    pub kind: ConsolidationProvenanceHopKind,
    pub entity_ref: EntityId,
    pub actor_ref: Option<EntityId>,
}

/// The refs a peer answer binds together, as the caller knows them BEFORE
/// [`peer_answer_provenance_chain`] validates and orders them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAnswerLineage {
    pub answer_turn_ref: EntityId,
    pub consult_task_ref: EntityId,
    pub peer_actor_ref: EntityId,
    pub result_artifact_ref: Option<EntityId>,
}

/// One consolidated belief candidate handed to the promotion writer
/// (`dreamer_promotion::promote_consolidated_claims`, ONE-1290).
#[derive(Debug, Clone, PartialEq)]
pub struct PromotionCandidate {
    /// Caller-minted, write-once claim id.
    pub claim_id: EntityId,
    pub candidate: ClaimCandidate,
    /// TURN entities only (GATE-11): the writer drops refs resolving to
    /// evidence-inadmissible CLAIM entities.
    pub evidence_turn_refs: Vec<EntityId>,
    /// Ordered typed lineage (ONE-1710). Empty for candidates with no
    /// external chain; a peer-derived candidate carries at least one
    /// `AnswerTurn` hop and one `ConsultTask` hop.
    pub provenance_chain: Vec<ConsolidationProvenanceHop>,
    /// At most ONE prior head (multi-claim contradictions route to the gap
    /// scan, never a multi-supersede).
    pub supersedes: Option<EntityId>,
    /// Lattice meet over every source read (GATE-05); `Generated` when no
    /// external reads happened. NEVER caller-chosen as a trust label: it is
    /// computed from evidence (`evidence_chain_source`), and the promotion
    /// writer stamps it as both `src` and `scope.evidence_taint`.
    pub evidence_meet: ClaimSource,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// The structured evidence payload a promoted consolidation claim stores:
/// the post-admission refs, the typed chain, and the computed meet — all
/// machine-readable after promotion, never a display string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationEvidenceEnvelope {
    pub refs: Vec<EntityId>,
    pub chain: Vec<ConsolidationProvenanceHop>,
    pub source_meet: ClaimSource,
}

const EVIDENCE_ENVELOPE_REFS_KEY: &str = "refs";
const EVIDENCE_ENVELOPE_CHAIN_KEY: &str = "chain";
const EVIDENCE_ENVELOPE_SOURCE_MEET_KEY: &str = "source_meet";
const PROVENANCE_HOP_KIND_KEY: &str = "kind";
const PROVENANCE_HOP_ENTITY_REF_KEY: &str = "entity_ref";
const PROVENANCE_HOP_ACTOR_REF_KEY: &str = "actor_ref";

fn encode_provenance_hop(hop: &ConsolidationProvenanceHop) -> Value {
    let mut entries = vec![
        (
            Value::from(PROVENANCE_HOP_KIND_KEY),
            Value::from(hop.kind.as_str()),
        ),
        (
            Value::from(PROVENANCE_HOP_ENTITY_REF_KEY),
            Value::Binary(hop.entity_ref.as_bytes().to_vec()),
        ),
    ];
    if let Some(actor) = hop.actor_ref {
        entries.push((
            Value::from(PROVENANCE_HOP_ACTOR_REF_KEY),
            Value::Binary(actor.as_bytes().to_vec()),
        ));
    }
    Value::Map(entries)
}

fn decode_provenance_hop(value: &Value) -> Result<ConsolidationProvenanceHop> {
    let Value::Map(entries) = value else {
        return Err(invalid_consolidation("provenance hop must be a map"));
    };
    let mut kind = None;
    let mut entity_ref = None;
    let mut actor_ref = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(PROVENANCE_HOP_KIND_KEY) => {
                kind = value
                    .as_str()
                    .and_then(ConsolidationProvenanceHopKind::parse);
            }
            Some(PROVENANCE_HOP_ENTITY_REF_KEY) => entity_ref = entity_ref_from_value(value),
            Some(PROVENANCE_HOP_ACTOR_REF_KEY) => actor_ref = entity_ref_from_value(value),
            _ => {}
        }
    }
    Ok(ConsolidationProvenanceHop {
        kind: kind.ok_or_else(|| invalid_consolidation("provenance hop kind is unknown"))?,
        entity_ref: entity_ref
            .ok_or_else(|| invalid_consolidation("provenance hop entity ref is malformed"))?,
        actor_ref,
    })
}

/// Encodes the evidence envelope stored in the promoted claim's `evid`
/// payload. The pairing decoder is [`decode_consolidation_evidence`].
#[must_use]
pub fn encode_consolidation_evidence(evidence: &ConsolidationEvidenceEnvelope) -> Value {
    Value::Map(vec![
        (
            Value::from(EVIDENCE_ENVELOPE_REFS_KEY),
            Value::Array(
                evidence
                    .refs
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            Value::from(EVIDENCE_ENVELOPE_CHAIN_KEY),
            Value::Array(evidence.chain.iter().map(encode_provenance_hop).collect()),
        ),
        (
            Value::from(EVIDENCE_ENVELOPE_SOURCE_MEET_KEY),
            Value::from(evidence.source_meet.as_str()),
        ),
    ])
}

/// Reads back a stored consolidation evidence envelope. `Ok(None)` when the
/// payload is not one (a legacy bare-array evidence stamp, say); a structural
/// break inside a well-keyed envelope is a typed error, never a silent drop.
pub fn decode_consolidation_evidence(
    value: &Value,
) -> Result<Option<ConsolidationEvidenceEnvelope>> {
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    let mut refs = None;
    let mut chain = None;
    let mut source_meet = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(EVIDENCE_ENVELOPE_REFS_KEY) => {
                let Value::Array(items) = value else {
                    return Err(invalid_consolidation("evidence refs must be an array"));
                };
                refs = Some(
                    items
                        .iter()
                        .map(|item| {
                            entity_ref_from_value(item)
                                .ok_or_else(|| invalid_consolidation("evidence ref is malformed"))
                        })
                        .collect::<Result<Vec<EntityId>>>()?,
                );
            }
            Some(EVIDENCE_ENVELOPE_CHAIN_KEY) => {
                let Value::Array(items) = value else {
                    return Err(invalid_consolidation("evidence chain must be an array"));
                };
                chain = Some(
                    items
                        .iter()
                        .map(decode_provenance_hop)
                        .collect::<Result<Vec<ConsolidationProvenanceHop>>>()?,
                );
            }
            Some(EVIDENCE_ENVELOPE_SOURCE_MEET_KEY) => {
                source_meet = value.as_str().and_then(ClaimSource::parse);
            }
            _ => {}
        }
    }
    let (Some(refs), Some(chain)) = (refs, chain) else {
        return Ok(None);
    };
    Ok(Some(ConsolidationEvidenceEnvelope {
        refs,
        chain,
        source_meet: source_meet
            .ok_or_else(|| invalid_consolidation("evidence source meet is unknown"))?,
    }))
}

/// Builds the ordered, VALIDATED provenance chain for one peer answer
/// (ONE-1710 · ARCH-0067 §7).
///
/// Validation is structural, never a trust gate — the answer TURN has
/// already landed by the time this runs (§1: storage is the ledger):
///
/// * the answer ref resolves to a stored TURN;
/// * the consult ref resolves to a stored TASK that has SETTLED `Completed`
///   with a `result_ref` binding back to this answer (or to the carried
///   result artifact) — read through `task_verb`'s read-only settled-result
///   query, so no TASK writer is touched;
/// * the peer actor passes the existing `provenance::validate_actor_class`
///   rules as an Agent actor. Peer identity keys on the CONNECTION; the
///   vendor/harness label is metadata and never appears here.
pub fn peer_answer_provenance_chain(
    vault: &Vault,
    lineage: PeerAnswerLineage,
) -> Result<Vec<ConsolidationProvenanceHop>> {
    let answer_type = vault
        .get_entity_type(&lineage.answer_turn_ref)?
        .ok_or_else(|| invalid_consolidation("peer answer turn does not resolve"))?;
    if answer_type != ENTITY_TYPE_TURN {
        return Err(invalid_consolidation("peer answer ref is not a TURN"));
    }

    let task_type = vault
        .get_entity_type(&lineage.consult_task_ref)?
        .ok_or_else(|| invalid_consolidation("consult task does not resolve"))?;
    if task_type != ENTITY_TYPE_TASK {
        return Err(invalid_consolidation("consult ref is not a TASK"));
    }
    let (disposition, result_ref) =
        crate::task_verb::settled_task_result_binding(vault, lineage.consult_task_ref)?
            .ok_or_else(|| invalid_consolidation("consult task carries no settled result"))?;
    if disposition != crate::task_verb::TaskTerminalDisposition::Completed {
        return Err(invalid_consolidation("consult task did not complete"));
    }
    if result_ref != lineage.answer_turn_ref && Some(result_ref) != lineage.result_artifact_ref {
        return Err(invalid_consolidation(
            "peer answer does not bind back to the consult task result",
        ));
    }

    let actor_type = vault
        .get_entity_type(&lineage.peer_actor_ref)?
        .ok_or_else(|| invalid_consolidation("peer actor does not resolve"))?;
    crate::provenance::validate_actor_class(actor_type, EdgeActorClass::Agent)?;

    let mut chain = vec![
        ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::AnswerTurn,
            entity_ref: lineage.answer_turn_ref,
            actor_ref: Some(lineage.peer_actor_ref),
        },
        ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::ConsultTask,
            entity_ref: lineage.consult_task_ref,
            actor_ref: Some(lineage.peer_actor_ref),
        },
        ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::PeerActor,
            entity_ref: lineage.peer_actor_ref,
            actor_ref: Some(lineage.peer_actor_ref),
        },
    ];
    if let Some(artifact) = lineage.result_artifact_ref {
        chain.push(ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::ResultArtifact,
            entity_ref: artifact,
            actor_ref: Some(lineage.peer_actor_ref),
        });
    }
    Ok(chain)
}

/// Folds a candidate's whole evidence surface into one D10 meet — the ONLY
/// input to a consolidation claim's stored source (§3: callers never choose
/// it).
///
/// Classification, most-restrictive-wins from the Dreamer's own `Generated`
/// floor (the same start `evidence_trust_meet` uses):
///
/// * a ref named by an `AnswerTurn` hop is peer TOOL OUTPUT — `ToolOutput`;
/// * any other stored TURN contributes the Dreamer floor `Generated` (a
///   `UserStated` turn cannot lift a meet that already starts at the floor);
/// * a CLAIM ref contributes its own stored source folded with its recorded
///   evidence taint, so a tainted prior cannot launder itself upward;
/// * an unresolvable ref fails closed at `Imported`, the lattice bottom.
pub fn evidence_chain_source(
    vault: &Vault,
    chain: &[ConsolidationProvenanceHop],
    evidence_refs: &[EntityId],
) -> Result<ClaimSource> {
    let mut meet = ClaimSource::Generated;
    for hop in chain {
        if hop.kind == ConsolidationProvenanceHopKind::AnswerTurn {
            meet = source_meet(meet, ClaimSource::ToolOutput);
        }
    }
    for entry in evidence_refs {
        let answered_by_peer = chain.iter().any(|hop| {
            hop.kind == ConsolidationProvenanceHopKind::AnswerTurn && hop.entity_ref == *entry
        });
        if answered_by_peer {
            meet = source_meet(meet, ClaimSource::ToolOutput);
            continue;
        }
        let Some(entity_type) = vault.get_entity_type(entry)? else {
            meet = source_meet(meet, ClaimSource::Imported);
            continue;
        };
        if entity_type == ENTITY_TYPE_CLAIM {
            let Some(body) = vault.get_claim(entry)? else {
                meet = source_meet(meet, ClaimSource::Imported);
                continue;
            };
            meet = source_meet(meet, body.source.unwrap_or(ClaimSource::Imported));
            if let Some(taint) = claim_evidence_taint(&body) {
                meet = source_meet(meet, taint);
            }
            continue;
        }
        if entity_type != ENTITY_TYPE_TURN {
            meet = source_meet(meet, ClaimSource::Imported);
        }
    }
    Ok(meet)
}

/// ONE awareness line for a landed/conflicting peer answer (§6). It is a
/// DIGEST row, not a consent step: no pending claim, inbox group, or owner
/// decision is created anywhere on this path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTrustDigestLine {
    pub consult_task_ref: EntityId,
    pub answer_turn_ref: EntityId,
    pub claim_ref: EntityId,
    /// Present when the landing left an unresolved contradiction standing;
    /// names the `core.conflict.open` marker, never a review state.
    pub conflict_open_ref: Option<EntityId>,
}

/// Where a digest line goes. The production sink forwards to the existing
/// human digest/outbound public API; `outbound.rs` and `delivery_window.rs`
/// are consumed, never edited.
pub trait PeerTrustDigestSink {
    fn push(&mut self, line: PeerTrustDigestLine) -> Result<()>;
}

/// Surfaces exactly one digest line for a peer-answer landing.
///
/// Deliberately trivial: the awareness surface must not grow a decision. A
/// caller that wants a conflict mentioned passes `conflict_open_ref`; there
/// is no second "approve" line to emit.
pub fn surface_peer_answer_digest(
    sink: &mut dyn PeerTrustDigestSink,
    line: PeerTrustDigestLine,
) -> Result<()> {
    sink.push(line)
}

/// Where surviving candidates go. ONE-1290's promotion writer is the real
/// implementation; tests stub it. This module never writes claims.
pub trait ConsolidationSink {
    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()>;
}

/// Lattice meet (most restrictive wins) over the D10 order
/// `UserStated > Observed > Inferred = Generated > ToolOutput > Imported`.
/// ONE-1385 hardens/pins this as the boundary contract.
///
/// `pub(crate)` for ONE-1710 only: `dreamer_promotion` folds the superseded
/// head's taint into the candidate meet through THIS helper rather than
/// keeping a second copy of the lattice.
pub(crate) fn source_meet(left: ClaimSource, right: ClaimSource) -> ClaimSource {
    const fn rank(source: ClaimSource) -> u8 {
        match source {
            ClaimSource::UserStated => 4,
            ClaimSource::Observed => 3,
            ClaimSource::Inferred | ClaimSource::Generated => 2,
            ClaimSource::ToolOutput => 1,
            ClaimSource::Imported => 0,
        }
    }
    if rank(right) < rank(left) {
        right
    } else {
        left
    }
}
