//! One refresh's execution path (FIX 8914, pure moves from `refresh.rs`).

use super::super::arrival;
use super::super::backfill::{BackfillAtKey, QUESTION_BACKFILL_AT};
use super::super::graph_ask;
use super::super::reader_authority::question_lane;
use super::super::records::*;
use super::super::store::*;
use super::asker;
use super::{
    Answered, Prepared, Proposed, SourceRow, UnitAnswer, land, source, validate_decided,
    validate_proposal,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::llm::decision::{DecisionReceipt, TypedDecision};
use crate::side_table::SideKey;
use crate::{EntityId, Error, Result, Vault};

pub(super) fn refresh_with(
    vault: &Vault,
    writer: asker::RefreshWriter,
    principal: EntityId,
    question: EntityId,
    trigger: RefreshTrigger,
    now: u64,
    answerer: &mut UnitAnswer<'_>,
) -> Result<Vec<AnswerRecord>> {
    let (record, head, units, arrival_marker, backfill_marker) = {
        let txn = vault.store.env.read_txn()?;
        let head = owned_head(vault, &txn, principal, question)?;
        let record = QUESTION_VERSION
            .get(
                &vault.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            .ok_or(Error::EntityNotFound)?;
        record.definition.validate()?;
        if head.paused {
            return Ok(Vec::new());
        }
        let mut arrival_marker = None;
        let mut backfill_marker = None;
        let units = match trigger {
            RefreshTrigger::Manual => record.definition.units.clone(),
            RefreshTrigger::Backfill => {
                let key = BackfillAtKey(question);
                match QUESTION_BACKFILL_AT.get(&vault.store, &txn, &key)? {
                    Some(backfill) if backfill.version == head.version => {}
                    _ => return Ok(Vec::new()),
                }
                backfill_marker = QUESTION_BACKFILL_AT.get_bytes(&vault.store, &txn, &key)?;
                let answered: std::collections::BTreeSet<EntityId> = QUESTION_ANSWER
                    .scan_from(&vault.store, &txn, &family_prefix(question, b"answer"))?
                    .into_iter()
                    .filter(|(_, answer)| answer.decision.receipt.question_version == head.version)
                    .map(|(_, answer)| answer.unit)
                    .collect();
                record
                    .definition
                    .units
                    .iter()
                    .copied()
                    .filter(|unit| !answered.contains(unit))
                    .collect()
            }
            RefreshTrigger::Schedule => {
                let Some(interval) = record.definition.refresh.every_seconds else {
                    return Ok(Vec::new());
                };
                if now
                    < head
                        .last_refresh
                        .unwrap_or(record.created_at)
                        .saturating_add(interval)
                {
                    return Ok(Vec::new());
                }
                record.definition.units.clone()
            }
            RefreshTrigger::Arrival(unit) => {
                if !record.definition.refresh.on_arrival || !record.definition.units.contains(&unit)
                {
                    return Ok(Vec::new());
                }
                arrival_marker =
                    arrival::PENDING.get_bytes(&vault.store, &txn, &(question, unit))?;
                if arrival_marker.is_none() {
                    return Ok(Vec::new());
                }
                vec![unit]
            }
        };
        (record, head, units, arrival_marker, backfill_marker)
    };
    // The answers are written under the record's class; the reads keep the
    // runner's own, as before (FIX 1588: no read narrows).
    let (actor, reader) = (writer.for_record(&record), writer.reader());
    let mut prepared = Vec::new();
    for unit in units {
        let snapshot = {
            let txn = vault.store.env.read_txn()?;
            source(vault, &txn, principal, reader, unit)?
        };
        let Some(SourceRow {
            kind,
            raw,
            frontier,
        }) = snapshot
        else {
            continue;
        };
        let Some(Answered { proposal, context }) =
            answerer(&record, unit, kind, &raw[ENTITY_METADATA_HEADER_LEN..])?
        else {
            continue;
        };
        match &proposal {
            Proposed::Proposal(proposal) => validate_proposal(&record, proposal)?,
            Proposed::Decision(decision) => validate_decided(&record, principal, decision)?,
        }
        prepared.push(Prepared {
            unit,
            frontier,
            proposal,
            context,
            arrival_marker: {
                let txn = vault.store.env.read_txn()?;
                arrival::PENDING.get_bytes(&vault.store, &txn, &(question, unit))?
            },
        });
    }
    // Grant status is judged at the authorization clock, observed before the
    // write snapshot opens.
    if prepared.iter().any(|p| p.context.is_some()) {
        vault.store.authorization_now()?;
    }
    vault.with_write_txn_grouped(|txn| {
        let current = owned_head(vault, txn, principal, question)?;
        if current.version != head.version
            || current.paused
            || current.last_refresh != head.last_refresh
        {
            return Err(Error::ConcurrentWrite(
                "standing question changed during refresh",
            ));
        }
        if let RefreshTrigger::Arrival(unit) = trigger
            && arrival::PENDING.get_bytes(&vault.store, txn, &(question, unit))? != arrival_marker
        {
            return Err(Error::ConcurrentWrite("standing question arrival consumed"));
        }
        // Every input is checked before the first write. A batch is all-or-nothing.
        // A graph context's neighbours and every source it showed are read
        // again through the principal's lane in this snapshot.
        let lane = if prepared.iter().any(|p| p.context.is_some()) {
            let key = graph_ask::asker_reader_in_txn(vault, txn, principal)?;
            Some(question_lane(vault, key))
        } else {
            None
        };
        let mut inputs = Vec::new();
        for p in &prepared {
            let Some(row) = source(vault, txn, principal, reader, p.unit)? else {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            };
            if row.frontier != p.frontier {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            }
            let rows = match (&p.context, &lane) {
                (Some(context), Some(lane)) => {
                    if !graph_ask::neighbors_unchanged_in_txn(lane, txn, context)? {
                        return Err(Error::ConcurrentWrite("standing question source changed"));
                    }
                    let Some(rows) = graph_ask::sources_unchanged_in_txn(lane, txn, context)?
                    else {
                        return Err(Error::ConcurrentWrite("standing question source changed"));
                    };
                    Some(rows)
                }
                _ => None,
            };
            inputs.push((row, rows));
        }
        let mut answers = Vec::new();
        for (
            p,
            (
                SourceRow {
                    kind,
                    raw,
                    frontier,
                },
                rows,
            ),
        ) in prepared.iter().zip(inputs)
        {
            let decision = match &p.proposal {
                Proposed::Proposal(proposal) => TypedDecision {
                    answer: proposal.answer.clone(),
                    probability: proposal.probability,
                    evidence: p.context.as_ref().map_or_else(
                        || vec![p.unit],
                        |context| context.sources.iter().map(|s| s.id).collect(),
                    ),
                    in_band: proposal
                        .probability
                        .is_some_and(|v| record.definition.dial.band.contains(v)),
                    receipt: DecisionReceipt {
                        question,
                        question_version: head.version,
                        principal,
                        providers: proposal.providers.clone(),
                        band: record.definition.dial.band,
                        band_version: 0,
                        evidence_versions: p
                            .context
                            .as_ref()
                            .map(graph_ask::source_versions)
                            .unwrap_or_default(),
                        cost_per_thousand: None,
                        paired: proposal.paired.clone(),
                        person: Vec::new(),
                        time: None,
                        images: Vec::new(),
                        think_row: None,
                        person_row: None,
                        rule: proposal.rule.clone(),
                        asked: None,
                        state_cut: None,
                    },
                    human_ask: None,
                },
                Proposed::Decision(decision) => (**decision).clone(),
            };
            let answer = AnswerRecord {
                claim: EntityId::now(),
                unit: p.unit,
                decision,
                frontier,
                source_kind: kind,
                answered_at: now,
                omitted: p
                    .context
                    .as_ref()
                    .map(|context| context.omitted.clone())
                    .unwrap_or_default(),
            };
            land(vault, txn, actor, principal, &answer, &raw, rows.as_deref())?;
            arrival::watch_sources(
                &vault.store,
                txn,
                question,
                answer.unit,
                &answer.decision.evidence,
            )?;
            super::super::ask_history::put_graph_answer_in_txn(
                vault, txn, question, principal, &answer,
            )?;
            answers.push(answer);
        }
        if matches!(trigger, RefreshTrigger::Schedule) {
            let mut updated = current;
            updated.last_refresh = Some(now);
            updated.retry_at = None;
            consume_arrivals(vault, txn, question, &prepared)?;
            QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question), &updated)?;
        }
        // A backfill runs once: its schedule is consumed unless it was set
        // again during the work. It leaves the refresh clock alone.
        if matches!(trigger, RefreshTrigger::Backfill) {
            consume_arrivals(vault, txn, question, &prepared)?;
            let key = BackfillAtKey(question);
            if backfill_marker.is_some()
                && QUESTION_BACKFILL_AT.get_bytes(&vault.store, txn, &key)? == backfill_marker
            {
                QUESTION_BACKFILL_AT.delete(&vault.store, txn, &key)?;
            }
        }
        // A held unit keeps its marker, so the pump answers it once its
        // owner has answered.
        if let RefreshTrigger::Arrival(unit) = trigger
            && crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                txn,
                &unit,
                crate::gate::ConsolidationReader::QuestionRefreshSource,
            )?
        {
            arrival::PENDING.delete(&vault.store, txn, &(question, unit))?;
        }
        Ok(answers)
    })
}

/// Clears each answered unit's arrival marker that is still the one read
/// before its answer: an arrival during the work keeps its own.
fn consume_arrivals(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    prepared: &[Prepared],
) -> Result<()> {
    for p in prepared {
        let pending = (question, p.unit);
        if p.arrival_marker.is_some()
            && arrival::PENDING.get_bytes(&vault.store, txn, &pending)? == p.arrival_marker
        {
            arrival::PENDING.delete(&vault.store, txn, &pending)?;
        }
    }
    Ok(())
}
