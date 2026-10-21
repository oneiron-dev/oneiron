//! What an Arc is written from (FIX 7509 P8, SUMMARY-SOURCE = A): the
//! current summary of each closed sitting with turns in the Arc's scope, and
//! of each its lines, read in the planner's writer.
//!
//! A line whose every cited TURN stands in the Arc's scope, from a summary
//! still as it was generated and still valid, is the Arc's input as written,
//! with its refs. Any other line is replaced by the Arc's own TURNs it cites,
//! which are read again in its place: a line is never admitted whole on one
//! overlapping ref, and never dropped while a TURN it cites stands in the
//! Arc. A line citing none of the Arc's TURNs belongs to another Arc. A
//! sitting still open is not yet below the Arc; a closed sitting whose
//! summary is still owed keeps the Arc owed, never smaller.

use super::codec::invalid;
use super::doors::{ScopeSources, scope_sources_in_txn};
use super::purpose::SummaryPurpose;
use super::request::{ScopeSummaryPlan, ScopeSummaryRequest, ScopeSummaryTarget};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::conversation_dag::ScopeSelector;
use crate::error::{Error, Result};
use crate::{EntityId, Vault, WriteActor};
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The purpose a sitting's summary takes (`super::session`'s).
const SESSION_PURPOSE: &str = "session_recap";
const SOURCE_SET_DOMAIN: &[u8] = b"oneiron:arc-summary-sources:v1";

/// An Arc's sources as read in one writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArcSources {
    /// Each closed sitting's current summary below the Arc, in the order
    /// its first turn stands in the scope.
    pub(crate) lower: Vec<LowerSummary>,
    /// Every TURN of the Arc a lower line cites, in the scope's order.
    pub(crate) turns: Vec<EntityId>,
    /// Closed sittings below the Arc whose summary is still owed.
    pub(crate) owed: Vec<EntityId>,
    /// The source set: every lower summary, its state and its lines with
    /// their refs, and every owed sitting, under one domain-separated hash.
    pub(crate) source_set: [u8; 32],
}

/// One sitting's current summary as the Arc reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LowerSummary {
    pub(crate) summary: EntityId,
    pub(crate) session: EntityId,
    /// Its words are no longer its lines as generated: edited, or no longer
    /// valid. Its lines are then read again from their turns.
    pub(crate) rewritten: bool,
    /// Its lines that cite the Arc's TURNs, in their order.
    pub(crate) lines: Vec<LowerLine>,
}

/// One line of a sitting's summary that cites the Arc's TURNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LowerLine {
    /// The line's words as generated.
    pub(crate) words: String,
    /// The Arc's TURNs the line cites, in citation order.
    pub(crate) turns: Vec<EntityId>,
    /// Every TURN it cites stands in the Arc and its summary is as
    /// generated: the line is input as written. Otherwise its `turns` are
    /// read again in its place.
    pub(crate) whole: bool,
}

/// What one sitting below the Arc holds for it.
enum Lower {
    /// Not ended, or not a sitting: not yet below the Arc.
    Open,
    /// Closed with no summary to come: it retained no words.
    Empty,
    /// Closed, its summary still owed.
    Owed,
    Summary(LowerSummary),
}

/// An Arc's plan (FIX 7509 P8): its sources, read in this writer, and the
/// options the declaration carries. No editor text: an Arc is never written
/// from its own earlier body.
pub(super) fn plan_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    input: &Value,
    request: &ScopeSummaryRequest,
    scope: &ScopeSelector,
    (purpose, previous, keep, editor_frontier): (
        SummaryPurpose,
        Option<EntityId>,
        String,
        Option<Vec<u8>>,
    ),
) -> Result<ScopeSummaryPlan> {
    let (members, arc) = sources_in_txn(vault, txn, scope, request.requester)?;
    Ok(ScopeSummaryPlan {
        input: super::derivation::encode(input)?,
        scope: Some(scope.clone()),
        session: None,
        members,
        sources: arc.turns.clone(),
        land_on: None,
        as_record: false,
        requester: request.requester,
        purpose,
        previous,
        keep,
        editor_text: None,
        editor_frontier,
        policy_frontier: crate::gate::resolve_policy_manifest(&vault.store, txn)?
            .read_frontier_hash()?,
        arc: Some(arc),
    })
}

/// The scope's members and the Arc's sources, read in `txn`.
pub(super) fn sources_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    scope: &ScopeSelector,
    requester: WriteActor,
) -> Result<(Vec<EntityId>, ArcSources)> {
    let ScopeSources { members, sources } = scope_sources_in_txn(vault, txn, scope)?;
    let order: BTreeMap<EntityId, usize> = sources
        .iter()
        .enumerate()
        .map(|(index, turn)| (*turn, index))
        .collect();
    let mut sessions = Vec::new();
    let mut seen = BTreeSet::new();
    for turn in &sources {
        if let Some(session) =
            crate::compaction::turn_session_membership_in_txn(&vault.store, txn, turn)?
            && seen.insert(session)
        {
            sessions.push(session);
        }
    }
    let mut lower = Vec::new();
    let mut owed = Vec::new();
    let mut cited = BTreeSet::new();
    for session in sessions {
        match lower_in_txn(vault, txn, &session, requester, &order)? {
            Lower::Open | Lower::Empty => {}
            Lower::Owed => owed.push(session),
            Lower::Summary(summary) => {
                for line in &summary.lines {
                    cited.extend(line.turns.iter().copied());
                }
                lower.push(summary);
            }
        }
    }
    let mut turns: Vec<EntityId> = cited.into_iter().collect();
    turns.sort_by_key(|turn| order.get(turn).copied().unwrap_or(usize::MAX));
    let source_set = source_set_id(&lower, &owed);
    Ok((
        members,
        ArcSources {
            lower,
            turns,
            owed,
            source_set,
        },
    ))
}

/// What `session` holds for the Arc whose scope's TURNs `order` indexes.
fn lower_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    session: &EntityId,
    requester: WriteActor,
    order: &BTreeMap<EntityId, usize>,
) -> Result<Lower> {
    let Some(record) = vault.session_lifecycle_record_in_txn(txn, session)? else {
        return Ok(Lower::Open);
    };
    if record.ended_at.is_none() {
        return Ok(Lower::Open);
    }
    // A sitting's projection is keyed by its sitting alone; the requester
    // only fills the request.
    let request = ScopeSummaryRequest {
        target: ScopeSummaryTarget::Session { session: *session },
        requester,
    };
    let Some(summary) = super::derivation::current_in_txn(vault, txn, &request, SESSION_PURPOSE)?
    else {
        // A sitting that closed with none queued, or whose attempt completed
        // with none (it retained no words), has none to come.
        let Some(attempt) = record.summary_attempt else {
            return Ok(Lower::Empty);
        };
        let row = AttemptQueue::from_store(&vault.store)
            .get_in_txn(txn, AttemptId::from_bytes(&attempt)?)?;
        return Ok(
            if row.is_some_and(|row| matches!(row.state, AttemptState::Completed)) {
                Lower::Empty
            } else {
                Lower::Owed
            },
        );
    };
    let meta = crate::entity_doc::summary_meta_in_txn(vault, txn, &summary)?;
    let Some(line_sources) = meta.derivation.line_sources else {
        return Err(invalid("a sitting's summary has no lines"));
    };
    let row = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &summary)?
        .ok_or(Error::EntityNotFound)?;
    let logical = crate::entity_doc::resolve_record_body(&vault.store, txn, &summary, &row.body)?;
    let generated = super::decode_scope_summary_body(&logical)?.text;
    let current = crate::entity_doc::summary_text_in_txn(vault, txn, &summary)?;
    let rewritten = super::doors::summary_in_txn(vault, txn, &summary).is_err()
        || blake3::hash(generated.as_bytes()).as_bytes() != &meta.derivation.generated_text_hash
        || blake3::hash(current.as_bytes()).as_bytes() != &meta.derivation.generated_text_hash;
    // Each line's offsets count Unicode scalars of the generated text.
    let bounds: Vec<usize> = generated
        .char_indices()
        .map(|(at, _)| at)
        .chain(std::iter::once(generated.len()))
        .collect();
    let mut lines = Vec::new();
    for line in line_sources {
        let words = bounds
            .get(line.output_start)
            .zip(bounds.get(line.output_end))
            .filter(|(start, end)| start <= end)
            .and_then(|(start, end)| generated.get(*start..*end))
            .ok_or_else(|| invalid("a sitting's summary line is not in its text"))?;
        let mut cites = Vec::with_capacity(line.turn_refs.len());
        for turn in &line.turn_refs {
            cites.push(EntityId::from_hex(turn)?);
        }
        let turns: Vec<EntityId> = cites
            .iter()
            .copied()
            .filter(|turn| order.contains_key(turn))
            .collect();
        if turns.is_empty() {
            continue;
        }
        lines.push(LowerLine {
            words: words.to_owned(),
            whole: !rewritten && turns.len() == cites.len(),
            turns,
        });
    }
    Ok(Lower::Summary(LowerSummary {
        summary,
        session: *session,
        rewritten,
        lines,
    }))
}

/// The source set's id: each lower summary in order, whether its words are
/// still its lines, and each of its lines with its words and refs; then each
/// owed sitting. The same sources are the same id.
fn source_set_id(lower: &[LowerSummary], owed: &[EntityId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_SET_DOMAIN);
    let mut part = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    for summary in lower {
        part(summary.summary.as_bytes());
        part(summary.session.as_bytes());
        part(&[u8::from(summary.rewritten)]);
        for line in &summary.lines {
            part(line.words.as_bytes());
            part(&[u8::from(line.whole)]);
            for turn in &line.turns {
                part(turn.as_bytes());
            }
        }
        part(&[]);
    }
    part(b"owed");
    for session in owed {
        part(session.as_bytes());
    }
    *hasher.finalize().as_bytes()
}
