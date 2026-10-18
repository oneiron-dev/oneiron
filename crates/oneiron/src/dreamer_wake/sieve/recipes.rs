//! Durable model-rung inputs, queue spending and unbiased retained-span samples.

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::claim::ScopedReadActorKey;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
};
use crate::llm::{Scope, ScopeResource};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::recipes::WakeRecipePolicy;
use super::{QUEUE, QueueKey, READ, SPANS, SieveSpan, SpanBand, chunks, policy};

pub(crate) const RUNG_ATTEMPT: &str = "dreamer.sieve.rungs";
/// Original cheap reading survives spending for later expensive-path audits.
const HISTORY: SideTable<(EntityId, [u8; 32]), SieveSpan, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_HISTORY);
const AUDIT: SideTable<AttemptId, SieveAudit, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_AUDIT);
const CONSUMED: SideTable<(AttemptId, [u8; 32]), SieveConsumeReceipt, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_CONSUMED);

/// One span the nightly spending consumed: its ref, the attempt that spent
/// it and when. The original reading stays in the retained history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SieveConsumeReceipt {
    pub span: [u8; 32],
    pub turn: EntityId,
    pub source: EntityId,
    pub start: u64,
    pub end: u64,
    pub kind: super::SpanKind,
    pub score: u32,
    pub attempt: AttemptId,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RungInput {
    pub(crate) span: SieveSpan,
    pub(crate) audit: bool,
    pub(crate) policy: WakeRecipePolicy,
}

/// A sampled rule reading and the expensive path's label, kept by receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SieveAudit {
    pub sampled: bool,
    pub span: [u8; 32],
    pub turn: EntityId,
    pub source: EntityId,
    pub source_digest: [u8; 32],
    pub expected_kind: super::SpanKind,
    pub actual_kind: super::SpanKind,
    pub expected_entity: Option<EntityId>,
    pub actual_entity: Option<EntityId>,
    pub novel: bool,
    pub confidence: u8,
    pub agrees: bool,
    pub at: u64,
    pub completed_units: u64,
    pub step_hashes: Vec<[u8; 32]>,
}

pub(crate) fn queue_key(span: &SieveSpan) -> QueueKey {
    ((u32::MAX - span.score).to_be_bytes(), span.id)
}

pub(super) fn remember_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
) -> Result<()> {
    HISTORY.put(store, txn, &(span.turn, span.id), span)
}

pub(super) fn forget_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    let keys = HISTORY.scan_keys(store, txn, turn.as_bytes())?;
    for key in keys {
        HISTORY.delete(store, txn, &key)?;
    }
    let audits = AUDIT
        .iter_from(store, txn, &[])?
        .filter_map(|row| match row {
            Ok((id, audit)) if audit.turn == *turn => Some(Ok(id)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;
    for id in audits {
        AUDIT.delete(store, txn, &id)?;
    }
    let consumed = CONSUMED
        .iter_from(store, txn, &[])?
        .filter_map(|row| match row {
            Ok((key, receipt)) if receipt.turn == *turn => Some(Ok(key)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;
    for key in consumed {
        CONSUMED.delete(store, txn, &key)?;
    }
    Ok(())
}

pub(crate) fn recipe_spans_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
) -> Result<Vec<SieveSpan>> {
    let rows = QUEUE
        .iter_from(&vault.store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let pairs = rows
        .iter()
        .map(|(_, span)| (span.turn, span.source))
        .collect::<Vec<_>>();
    let admission = chunks::admissions_in_txn(vault, txn, &pairs)?;
    Ok(rows
        .into_iter()
        .zip(admission)
        .filter_map(|((_, span), admission)| {
            (admission == chunks::Admission::Readable).then_some(span)
        })
        .take(limit)
        .collect())
}

pub(crate) fn spend_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
) -> Result<()> {
    let key = queue_key(span);
    QUEUE.delete(store, txn, &key)?;
    SPANS.delete(store, txn, &(span.turn, key))?;
    Ok(())
}

/// Spends `span` as consumed work: its receipt lands in the same
/// transaction that takes it out of the queue, so a span is never both
/// queued and receipted, and never spent twice.
pub(crate) fn spend_consumed_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
    attempt: AttemptId,
    now: u64,
) -> Result<()> {
    CONSUMED.put(
        store,
        txn,
        &(attempt, span.id),
        &SieveConsumeReceipt {
            span: span.id,
            turn: span.turn,
            source: span.source,
            start: span.start,
            end: span.end,
            kind: span.kind,
            score: span.score,
            attempt,
            at: now,
        },
    )?;
    spend_in_txn(store, txn, span)
}

pub(crate) fn enqueue_rungs_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAdmittedAttempt,
    span: &SieveSpan,
    audit: bool,
    now: u64,
) -> Result<()> {
    let policy = super::super::recipes::policy_in_txn(store.vault(), txn)?;
    let input = serde_json::to_string(&RungInput {
        span: span.clone(),
        audit,
        policy,
    })
    .map_err(|_| Error::InvalidConfig("sieve rung input encoding".into()))?;
    let key = if audit {
        format!(
            "sieve:audit:{}:{}",
            crate::entity_id::bytes_to_hex_lower(parent.status.attempt.id.as_bytes()),
            crate::entity_id::bytes_to_hex_lower(&span.id)
        )
    } else {
        format!("sieve:rungs:{}", blake3::hash(input.as_bytes()).to_hex())
    };
    store.enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: RUNG_ATTEMPT.into(),
            input: Value::from(input),
            parent_attempt: Some(parent.status.attempt.id),
        },
        Some(key),
        parent.status.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

pub(crate) fn audit_sample_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: AttemptId,
    policy: &WakeRecipePolicy,
) -> Result<Vec<SieveSpan>> {
    if policy.audit_percent == 0 || policy.audit_spans == 0 {
        return Ok(Vec::new());
    }
    let mut sampled = Vec::new();
    for row in HISTORY.iter_from(&vault.store, txn, &[])? {
        let (_, span) = row?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:sieve:audit-sample:v1");
        hash.update(seed.as_bytes());
        hash.update(&span.id);
        let rank = *hash.finalize().as_bytes();
        let draw = u64::from_be_bytes(rank[..8].try_into().expect("eight bytes"));
        if u128::from(draw) * 100 < (u128::from(u64::MAX) + 1) * u128::from(policy.audit_percent) {
            sampled.push((rank, span));
        }
    }
    sampled.sort_by_key(|(rank, _)| *rank);
    let pairs = sampled
        .iter()
        .map(|(_, span)| (span.turn, span.source))
        .collect::<Vec<_>>();
    let admitted = chunks::admissions_in_txn(vault, txn, &pairs)?;
    Ok(sampled
        .into_iter()
        .zip(admitted)
        .filter_map(|((_, span), admission)| {
            (admission == chunks::Admission::Readable).then_some(span)
        })
        .take(policy.audit_spans as usize)
        .collect())
}

pub(crate) fn retained_conversations_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut conversations = BTreeSet::new();
    let rows = READ
        .iter_from(&vault.store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for row in rows {
        let (turn, _) = row;
        if let Some(conversation) =
            crate::dreamer_consolidation::redirty::conversation_in_txn(vault, txn, &turn)?
        {
            // A canonical scope without a HEAD has no retained DAG to summarize.
            let scope = crate::conversation_dag::ScopeSelector {
                conversation,
                session: None,
                path: crate::conversation_dag::ScopePath::Canonical,
                include_forks: true,
            };
            if !crate::conversation_dag::resolve_in_txn(vault, txn, &scope)?
                .records
                .is_empty()
            {
                conversations.insert(conversation);
            }
        }
    }
    Ok(conversations)
}

/// Text and exact source grants for a rung. A changed reading never labels
/// a new source version with the old span's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RungEvidence {
    pub(crate) text: String,
    pub(crate) entities: Vec<EntityId>,
    pub(crate) scope: Scope,
}

pub(crate) fn rung_evidence(vault: &Vault, input: &RungInput) -> Result<Option<RungEvidence>> {
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    rung_evidence_in_txn(vault, &txn, input)
}

fn rung_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &RungInput,
) -> Result<Option<RungEvidence>> {
    let span = &input.span;
    if !input.audit && QUEUE.get(&vault.store, txn, &queue_key(span))?.as_ref() != Some(span) {
        return Ok(None);
    }
    let Some(text) = chunks::chunk_text_in_txn(vault, txn, &span.turn, &span.source)? else {
        return Ok(None);
    };
    let digest = *blake3::Hasher::new()
        .update(b"oneiron:dreamer-sieve:chunk:v1")
        .update(text.as_bytes())
        .finalize()
        .as_bytes();
    if digest != span.source_digest {
        return Ok(None);
    }
    let (Ok(start), Ok(end)) = (usize::try_from(span.start), usize::try_from(span.end)) else {
        return Ok(None);
    };
    let Some(quote) = text.get(start..end) else {
        return Ok(None);
    };
    let actor = crate::WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        crate::EdgeActorClass::System,
    );
    let key = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or(Error::InvalidConfig("sieve read actor".into()))?;
    let read = vault.scoped_read(key);
    let mut scope = Scope::default();
    for id in BTreeSet::from([span.turn, span.source]) {
        let Some(raw) = read.entity_raw_live_in(txn, &id)? else {
            return Ok(None);
        };
        scope.readable.insert(ScopeResource::DocumentVersion {
            document: id,
            version: format!(
                "blake3:{}",
                crate::entity_id::bytes_to_hex_lower(
                    &crate::dreamer_consolidation::swarm_evidence_content_hash(
                        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]
                    )
                )
            ),
        });
    }
    let mut ids = BTreeSet::new();
    for kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG, ENTITY_TYPE_PLACE] {
        ids.extend(vault.lookup_identity_key_in_txn(txn, kind, quote)?);
    }
    if let super::SpanOrigin::SavedTag { envelope, index } = span.origin {
        if let Some(tags) = crate::tagging::readable_view_in_txn(&vault.store, txn, &span.turn)?
            && super::read::envelope_digest(&tags.envelope) == envelope
            && let Some(mention) = usize::try_from(index)
                .ok()
                .and_then(|index| tags.mentions.get(index))
        {
            ids.extend(mention.link.entities());
        }
    }
    let mut entities = Vec::new();
    for id in ids {
        if let Some(raw) = read.entity_raw_live_in(txn, &id)? {
            scope.readable.insert(ScopeResource::DocumentVersion {
                document: id,
                version: format!(
                    "blake3:{}",
                    crate::entity_id::bytes_to_hex_lower(
                        &crate::dreamer_consolidation::swarm_evidence_content_hash(
                            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]
                        )
                    )
                ),
            });
            entities.push(id);
        }
    }
    Ok(Some(RungEvidence {
        text,
        entities,
        scope,
    }))
}

pub(crate) fn finish_rungs(
    vault: &Vault,
    attempt: AttemptId,
    input: &RungInput,
    evidence: &RungEvidence,
    kind: super::SpanKind,
    entity: Option<EntityId>,
    novel: bool,
    confidence: u8,
    typing_owed: bool,
    completed_units: u64,
    step_hashes: Vec<[u8; 32]>,
    now: u64,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        if rung_evidence_in_txn(vault, txn, input)?.as_ref() != Some(evidence) {
            return Ok(false);
        }
        if let Some(id) = entity
            && !evidence.entities.contains(&id)
        {
            return Err(Error::InvalidConfig(
                "sieve entity was not a supplied candidate".into(),
            ));
        }
        AUDIT.put(
            &vault.store,
            txn,
            &attempt,
            &SieveAudit {
                sampled: input.audit,
                span: input.span.id,
                turn: input.span.turn,
                source: input.span.source,
                source_digest: input.span.source_digest,
                expected_kind: input.span.kind,
                actual_kind: kind,
                expected_entity: input.span.entity,
                actual_entity: entity,
                novel,
                confidence,
                agrees: kind == input.span.kind && entity == input.span.entity,
                at: now,
                completed_units,
                step_hashes,
            },
        )?;
        if !input.audit {
            let policy = policy::policy_in_txn(vault, txn)?;
            let mut updated = input.span.clone();
            updated.kind = kind;
            updated.entity = entity;
            updated.novel = Some(novel);
            updated.confidence = confidence;
            updated.band = if confidence < policy.uncertain_low {
                SpanBand::Low
            } else if confidence < policy.uncertain_high {
                SpanBand::Uncertain
            } else {
                SpanBand::Sure
            };
            updated.score = match kind {
                super::SpanKind::Date => policy.date_interest,
                super::SpanKind::Name => policy.name_interest,
            }
            .saturating_mul(u32::from(confidence));
            if !novel {
                updated.score = 0;
            }
            updated.policy_digest = policy.digest()?;
            updated.owed = if typing_owed {
                vec![super::SieveRung::Typing]
            } else {
                Vec::new()
            };
            spend_in_txn(&vault.store, txn, &input.span)?;
            let key = queue_key(&updated);
            QUEUE.put(&vault.store, txn, &key, &updated)?;
            SPANS.put(&vault.store, txn, &(updated.turn, key), &())?;
        }
        Ok(true)
    })
}

impl Vault {
    /// The retained original span readings, in turn then span order.
    /// Spending never removes a reading: a consumed span stays here.
    pub fn sieve_retained(&self, limit: usize) -> Result<Vec<SieveSpan>> {
        let txn = self.store.env.read_txn()?;
        let mut spans = Vec::new();
        if limit == 0 {
            return Ok(spans);
        }
        for row in HISTORY.iter_from(&self.store, &txn, &[])? {
            let (_, span) = row?;
            spans.push(span);
            if spans.len() >= limit {
                break;
            }
        }
        Ok(spans)
    }

    /// The spans nightly spending has consumed, oldest attempt first.
    pub fn sieve_consumed(&self, limit: usize) -> Result<Vec<SieveConsumeReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut receipts = Vec::new();
        if limit == 0 {
            return Ok(receipts);
        }
        for row in CONSUMED.iter_from(&self.store, &txn, &[])? {
            let (_, receipt) = row?;
            receipts.push(receipt);
            if receipts.len() >= limit {
                break;
            }
        }
        Ok(receipts)
    }

    pub fn sieve_audits(&self, limit: usize) -> Result<Vec<SieveAudit>> {
        let txn = self.store.env.read_txn()?;
        let mut audits = Vec::new();
        if limit == 0 {
            return Ok(audits);
        }
        for row in AUDIT.iter_from(&self.store, &txn, &[])? {
            let (_, audit) = row?;
            if audit.sampled {
                audits.push(audit);
            }
            if audits.len() >= limit {
                break;
            }
        }
        Ok(audits)
    }
}

pub(crate) fn rung_result_units(vault: &Vault, attempt: AttemptId) -> Result<Option<u64>> {
    let result = {
        let txn = vault.store.env.read_txn()?;
        AUDIT.get(&vault.store, &txn, &attempt)?
    };
    let Some(result) = result else {
        return Ok(None);
    };
    let store = DreamerRunnerStore::new(vault);
    let mut paid = !result.step_hashes.is_empty();
    for hash in &result.step_hashes {
        paid &= store.checkpoint_step_charged(attempt, hash)?;
    }
    Ok(Some(if paid { 0 } else { result.completed_units }))
}

pub(crate) fn rung_superseded(vault: &Vault, input: &RungInput) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    if input.audit {
        Ok(HISTORY
            .get(&vault.store, &txn, &(input.span.turn, input.span.id))?
            .as_ref()
            != Some(&input.span))
    } else {
        Ok(QUEUE
            .get(&vault.store, &txn, &queue_key(&input.span))?
            .as_ref()
            != Some(&input.span))
    }
}

pub(crate) fn interest_left_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    QUEUE
        .iter_from(&vault.store, txn, &[])?
        .next()
        .transpose()
        .map(|row| row.is_some())
}

pub(super) fn retire_history_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    HISTORY.delete_from(store, txn, turn.as_bytes()).map(|_| ())
}
