//! Outcome windows the question pump closes (OF-516). A bound answer's window
//! ends `horizon` seconds after the answer; the first pass after that records,
//! once, how it closed. No model runs and no fact is invented: a window no fact
//! labelled takes the binding's silence label only where the binding maps one.

use super::{
    arrival,
    records::*,
    store::{
        HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL, QUESTION_VERSION, VersionKey,
        decode_family, family_prefix, secret_scan_before_put,
    },
};
use crate::claim::ScopedReadActorKey;
use crate::gate::PolicyManifestResolution;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// The outcome value a binding maps to label a window that closed with no
/// fact: "a reply, a meeting or silence" (ARCH-0076). A binding without it
/// closes such a window unknown.
pub const SILENCE_OUTCOME: &str = "silence";

/// Key of one answer's closed window. Family: `window`, suffix: id16(claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowKey {
    pub(super) question: EntityId,
    pub(super) claim: EntityId,
}

impl SideKey for WindowKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.question, b"window"));
        out.extend_from_slice(self.claim.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, suffix) = decode_family(bytes, b"window")?;
        Some(Self {
            question,
            claim: EntityId::from_bytes(suffix.try_into().ok()?).ok()?,
        })
    }
}

pub(super) const QUESTION_WINDOW: SideTable<WindowKey, OutcomeWindowClose, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

/// One bound answer whose window has not closed.
struct OpenWindow {
    question: EntityId,
    answer: AnswerRecord,
    ends_at: u64,
}

/// Every learning, bound answer's open window, across each question's past
/// versions: an answer keeps the binding of the version it answered.
fn open_windows(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<OpenWindow>> {
    let mut open = Vec::new();
    // Several row families share the declaration; decode only exact head keys.
    for row in QUESTION_HEAD.iter_raw_from(&vault.store, txn, &[])? {
        let (key, _) = row?;
        let Some(HeadKey(question)) = HeadKey::decode_key(&key) else {
            continue;
        };
        let mut horizons: BTreeMap<u32, Option<u64>> = BTreeMap::new();
        for (_, answer) in
            QUESTION_ANSWER.scan_from(&vault.store, txn, &family_prefix(question, b"answer"))?
        {
            let version = answer.decision.receipt.question_version;
            let horizon = match horizons.get(&version) {
                Some(horizon) => *horizon,
                None => {
                    let horizon = QUESTION_VERSION
                        .get(
                            &vault.store,
                            txn,
                            &VersionKey {
                                id: question,
                                version,
                            },
                        )?
                        .filter(|record| record.definition.learning)
                        .and_then(|record| record.definition.binding.map(|b| b.horizon));
                    horizons.insert(version, horizon);
                    horizon
                }
            };
            let Some(horizon) = horizon else {
                continue;
            };
            let key = WindowKey {
                question,
                claim: answer.claim,
            };
            if QUESTION_WINDOW.contains(&vault.store, txn, &key)? {
                continue;
            }
            let ends_at = answer.answered_at.saturating_add(horizon);
            open.push(OpenWindow {
                question,
                answer,
                ends_at,
            });
        }
    }
    Ok(open)
}

/// The first instant an open outcome window is due to close, in unix
/// seconds; `None` when no bound answer's window is open.
pub fn next_outcome_window_close_at(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    Ok(open_windows(vault, &txn)?
        .iter()
        .map(|window| window.ends_at.saturating_add(1))
        .min())
}

/// Closes every outcome window that ended before `now`, once each, and
/// returns how many it closed. Stored facts are projected for those
/// questions first: a fact written before its answer, with an event time
/// inside the window, never met the answer at arrival. Each close then
/// records an observed fact, the binding's silence label, or unknown.
pub fn close_due_outcome_windows(vault: &Vault, now: u64) -> Result<usize> {
    let due: Vec<OpenWindow> = {
        let txn = vault.store.env.read_txn()?;
        open_windows(vault, &txn)?
            .into_iter()
            .filter(|window| window.ends_at < now)
            .collect()
    };
    if due.is_empty() {
        return Ok(0);
    }
    let questions: BTreeSet<EntityId> = due.iter().map(|window| window.question).collect();
    let facts = {
        let txn = vault.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &vault.store,
            &txn,
            crate::registry::ENTITY_TYPE_CLAIM,
            None,
        )?
        .collect::<Result<BTreeSet<_>>>()?
    };
    vault.with_write_txn_grouped(|txn| {
        arrival::project_questions_in_txn(&vault.store, txn, &facts, &questions)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        let mut closed = 0;
        for window in &due {
            let key = WindowKey {
                question: window.question,
                claim: window.answer.claim,
            };
            if QUESTION_WINDOW.contains(&vault.store, txn, &key)? {
                continue;
            }
            let version = window.answer.decision.receipt.question_version;
            let Some(record) = QUESTION_VERSION.get(
                &vault.store,
                txn,
                &VersionKey {
                    id: window.question,
                    version,
                },
            )?
            else {
                continue;
            };
            let close = OutcomeWindowClose {
                answer: window.answer.claim,
                question_version: version,
                ends_at: window.ends_at,
                closed_at: now,
                outcome: window_outcome(&vault.store, txn, &policy, &record, &window.answer)?,
            };
            secret_scan_before_put(&close)?;
            QUESTION_WINDOW.put(&vault.store, txn, &key, &close)?;
            closed += 1;
        }
        Ok(closed)
    })
}

/// The closed windows of `principal`'s standing question, across its
/// versions; none when the question is not theirs.
pub fn closed_outcome_windows(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<OutcomeWindowClose>> {
    let txn = vault.store.env.read_txn()?;
    super::store::owned_head(vault, &txn, principal, question)?;
    Ok(QUESTION_WINDOW
        .scan_from(&vault.store, &txn, &family_prefix(question, b"window"))?
        .into_iter()
        .map(|(_, close)| close)
        .collect())
}

/// How `answer`'s lapsed window closes: observed when a stored fact still
/// labels it, its binding's silence label when none does and the answer
/// still stands, and unknown otherwise.
fn window_outcome(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    record: &QuestionRecord,
    answer: &AnswerRecord,
) -> Result<WindowOutcome> {
    if fact_labelled(store, txn, policy, record, answer)? {
        return Ok(WindowOutcome::Observed);
    }
    let silence = record
        .definition
        .binding
        .as_ref()
        .and_then(|binding| binding.mapping.get(SILENCE_OUTCOME).copied());
    Ok(match silence {
        Some(label) if silence_stands(store, txn, policy, record, answer)? => {
            WindowOutcome::Silence(label)
        }
        _ => WindowOutcome::Unknown,
    })
}

/// Whether a stored fact label on `answer` still holds: its fact is
/// evaluated again exactly as a calibration read evaluates it.
pub(super) fn fact_labelled(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    record: &QuestionRecord,
    answer: &AnswerRecord,
) -> Result<bool> {
    let question = record.definition.question.id;
    let mut prefix = family_prefix(question, b"label");
    prefix.extend_from_slice(answer.claim.as_bytes());
    for (_, label) in QUESTION_LABEL.scan_from(store, txn, &prefix)? {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &label.fact)?
        else {
            continue;
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("outcome fact header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        let fact = arrival::Fact {
            id: label.fact,
            body: &body,
            occurred_at: header.occurred_start,
        };
        if arrival::evaluate_fact(store, txn, policy, record, answer, &fact)?.as_ref()
            == Some(&label)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a silence label may stand on `answer`: its version still matches
/// the receipt and learns, and the answer and its unit still read as its
/// principal's, as a fact's label requires of them.
pub(super) fn silence_stands(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    record: &QuestionRecord,
    answer: &AnswerRecord,
) -> Result<bool> {
    if record.schema_version != 1
        || record.definition.question.id != answer.decision.receipt.question
        || record.definition.question.version != answer.decision.receipt.question_version
        || record.principal != answer.decision.receipt.principal
        || !record.definition.learning
        || !record.definition.units.contains(&answer.unit)
    {
        return Ok(false);
    }
    let actor = ScopedReadActorKey::new(record.principal.to_hex()).expect("canonical principal");
    Ok(arrival::readable(store, txn, policy, &actor, &answer.unit)?
        && arrival::answer_live(store, txn, policy, &actor, answer)?)
}

/// The value hash a silence label pins in place of a fact's.
pub(super) fn silence_hash() -> Result<[u8; 32]> {
    arrival::value_hash(&rmpv::Value::from(SILENCE_OUTCOME))
}
