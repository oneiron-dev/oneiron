//! The verdict ledger, and the `Gate` receipts projected from it.

use super::*;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

// ---------------------------------------------------------------------------
// The verdict ledger
// ---------------------------------------------------------------------------

pub(super) fn record_verdict_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: &HeldOutVerdict,
) -> Result<()> {
    if verdict.measurements.is_some() != verdict.judge_revision.is_some() {
        return Err(invalid("judged verdict requires a judge revision"));
    }
    if let Some(measurements) = &verdict.measurements {
        validate_measurements(measurements, verdict.held_out_count)?;
    } else if verdict.disposition != SkillEditDisposition::RefusedStaleTarget
        || verdict.accepted_verdict.is_some()
    {
        return Err(invalid(
            "a judged skill edit verdict must carry measurements",
        ));
    }
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(VERDICT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROPOSAL),
            Value::from(verdict.proposal.to_hex()),
        ),
        (Value::from(KEY_SKILL), Value::from(verdict.skill.to_hex())),
        (Value::from(KEY_BEFORE), Value::F32(verdict.before)),
        (Value::from(KEY_AFTER), Value::F32(verdict.after)),
        (
            Value::from(KEY_DISPOSITION),
            Value::from(verdict.disposition.as_str()),
        ),
        (Value::from(KEY_CYCLE), Value::from(verdict.cycle.as_str())),
        (
            Value::from(KEY_HELD_OUT),
            Value::Array(
                verdict
                    .held_out_receipts
                    .iter()
                    .map(|receipt| Value::from(receipt.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_HELD_OUT_COUNT),
            Value::from(verdict.held_out_count),
        ),
        (
            Value::from(KEY_HELD_OUT_DIGEST),
            Value::from(verdict.held_out_digest.as_str()),
        ),
        (
            Value::from(KEY_HELD_OUT_TRUNCATED),
            Value::Boolean(verdict.held_out_truncated),
        ),
        (
            Value::from(KEY_PROPOSAL_DIGEST),
            Value::from(verdict.proposal_digest.as_str()),
        ),
        (
            Value::from(KEY_TARGET_DIGEST),
            Value::from(verdict.target_digest.as_str()),
        ),
        (
            Value::from(KEY_PROPOSAL_TIER),
            verdict
                .proposal_tier
                .map_or(Value::Nil, |tier| Value::from(tier.as_str())),
        ),
        (
            Value::from(KEY_ACCEPTED_VERDICT),
            verdict
                .accepted_verdict
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_MISSING_SOURCES),
            Value::Array(
                verdict
                    .missing_sources
                    .iter()
                    .map(|source| Value::from(source.to_hex()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_MEASUREMENTS),
            match &verdict.measurements {
                Some(measurements) => Value::from(
                    serde_json::to_string(measurements)
                        .map_err(|_| invalid("judge measurement encode failed"))?,
                ),
                None => Value::Nil,
            },
        ),
        (
            Value::from(KEY_JUDGE_REVISION),
            verdict
                .judge_revision
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_AT), Value::from(verdict.at)),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &row)
        .map_err(|_| invalid("skill edit verdict MessagePack encode failed"))?;
    VERDICTS.put(&vault.store, wtxn, &verdict.id, &encoded)?;
    Ok(())
}

fn decode_verdict(id: EntityId, raw: &[u8]) -> Result<HeldOutVerdict> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let Value::Map(entries) = &value else {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    if field(KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(VERDICT_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let entity = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
    };
    let score = |name: &str| match field(name) {
        Some(&Value::F32(score)) => Ok(score),
        _ => Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    // STRICT, entry by entry: a row whose array holds a non-string member is a
    // corrupt row, not a shorter one. Dropping the member silently would hand
    // a reader an evidence list that no longer matches the COUNT and DIGEST
    // standing beside it in the same row — a verdict that still binds, still
    // admits, and no longer says what it was ruled over.
    let strings = |name: &str| -> Result<Vec<String>> {
        let Some(Value::Array(entries)) = field(name) else {
            return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
        };
        entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            })
            .collect()
    };
    let disposition = field(KEY_DISPOSITION)
        .and_then(Value::as_str)
        .and_then(SkillEditDisposition::parse)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let text = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            .map(str::to_owned)
    };
    let held_out_count = field(KEY_HELD_OUT_COUNT)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let measurements = match field(KEY_MEASUREMENTS) {
        Some(Value::Nil) => None,
        Some(value) => {
            let decoded: JudgeMeasurements = serde_json::from_str(
                value
                    .as_str()
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            )
            .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
            validate_measurements(&decoded, held_out_count)
                .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
            Some(decoded)
        }
        None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    if measurements.is_none()
        && (disposition != SkillEditDisposition::RefusedStaleTarget
            || field(KEY_ACCEPTED_VERDICT) != Some(&Value::Nil))
    {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let scored = measurements.is_some();
    Ok(HeldOutVerdict {
        before: score(KEY_BEFORE)?,
        after: score(KEY_AFTER)?,
        measurements,
        accepted: disposition.admits(),
        judge_revision: match field(KEY_JUDGE_REVISION) {
            Some(Value::Nil) if !scored => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?
                    .to_owned(),
            ),
            None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
        },
        displaced_by_revision: None,
        id,
        proposal: entity(KEY_PROPOSAL)?,
        skill: entity(KEY_SKILL)?,
        disposition,
        cycle: text(KEY_CYCLE)?,
        held_out_receipts: strings(KEY_HELD_OUT)?,
        held_out_count,
        held_out_digest: text(KEY_HELD_OUT_DIGEST)?,
        held_out_truncated: field(KEY_HELD_OUT_TRUNCATED)
            .and_then(Value::as_bool)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        proposal_digest: text(KEY_PROPOSAL_DIGEST)?,
        target_digest: text(KEY_TARGET_DIGEST)?,
        // Nil is AMBIGUOUS or basis-less, and both are unadmittable; an absent
        // key is a row from another schema, and an unparseable tier is
        // corruption. Only the explicit spellings decode.
        proposal_tier: match field(KEY_PROPOSAL_TIER) {
            None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
            Some(Value::Nil) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(SkillGovernanceTier::parse)
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        // Nil is the ordinary shape: only a post-score refusal names the
        // acceptance it answers. A present-but-unreadable id is corruption,
        // not absence — reading it as "no reference" would quietly turn a
        // derived refusal back into the orphan row this field exists to end.
        accepted_verdict: match field(KEY_ACCEPTED_VERDICT) {
            Some(Value::Nil) | None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        // Strict on both axes, for the reason above: an id that does not parse
        // is corruption, and a source refusal that quietly lost the very id it
        // refuses over is an audit record that cannot be audited.
        missing_sources: strings(KEY_MISSING_SOURCES)?
            .iter()
            .map(|hex| {
                EntityId::from_hex(hex).map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))
            })
            .collect::<Result<Vec<EntityId>>>()?,
        at: field(KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
    })
}

fn decode_verdict_with_marker(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<HeldOutVerdict> {
    let mut verdict = decode_verdict(id, raw)?;
    verdict.displaced_by_revision = DISPLACED_VERDICT
        .get(&vault.store, txn, &verdict.id)?
        .map(|mark| mark.0);
    Ok(verdict)
}

pub(super) fn verdict_rows_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<HeldOutVerdict>> {
    VERDICTS
        .scan(&vault.store, rtxn)?
        .into_iter()
        .map(|(id, raw)| decode_verdict_with_marker(vault, rtxn, id, &raw))
        .collect()
}

/// Every gate verdict this vault has ruled, in ruling order.
///
/// The typed read model: `before` and `after` are `f32` here, not prose and not
/// a hash, so a reader can compare the pair the gate compared.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdicts(vault: &Vault) -> Result<Vec<HeldOutVerdict>> {
    let rtxn = vault.store.env.read_txn()?;
    verdict_rows_in_txn(vault, &rtxn)
}

/// Every verdict ruled on one proposal, oldest first.
///
/// More than one is ordinary: a cap-deferred proposal is ruled again in a later
/// cycle, and both rulings are history.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdicts_for_proposal(
    vault: &Vault,
    proposal: &EntityId,
) -> Result<Vec<HeldOutVerdict>> {
    Ok(skill_edit_verdicts(vault)?
        .into_iter()
        .filter(|verdict| verdict.proposal == *proposal)
        .collect())
}

/// The gate's standing answer for one proposal: its most recent verdict.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdict(vault: &Vault, proposal: &EntityId) -> Result<Option<HeldOutVerdict>> {
    Ok(skill_edit_verdicts_for_proposal(vault, proposal)?.pop())
}

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a skill-edit gate verdict.
#[must_use]
pub fn is_skill_edit_verdict_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(SKILL_EDIT_RECEIPT_PREFIX)
}

/// The exclusive upper bound of the verdict keyspace.
///
/// Projects the verdict ledger as `Gate` receipts.
///
/// A gate verdict IS a gate decision, so it mints no kind of its own — the
/// `edit_distance::escalation` precedent, whose field class it copies down to
/// the discriminating key prefix. Opens its own read txn, as that projector
/// does.
///
/// The WALK is bounded as well as the result, following
/// `edit_distance::graduation::answer_receipts_in_txn`: the verdict ledger
/// never drains (every ruling appends, and the log is the audit trail), so a
/// receipt query with `limit = 1` must not decode a lifetime of rulings to
/// answer. These keys are row-id ordered, which for a UUIDv7 row id IS ruling
/// order, so walking them NEWEST-FIRST under
/// [`crate::receipt::MAX_RECEIPT_QUERY_SCAN`] spends the bound on exactly the
/// rulings a receipt reader asked for, and the newest `query.limit` of the
/// matches is still what [`retain_newest_receipt`] keeps. A `job_ref` query
/// stays exhaustive within the walk, as the sibling projectors do and for
/// their reason: that join runs after collection.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(crate) fn skill_edit_verdict_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    // One row PAST the cap is reached and never decoded: it is what separates a
    // ledger holding exactly the cap from one the cap truncated.
    for (scanned, row) in VERDICTS
        .iter_rev_from(&vault.store, &rtxn, &[])?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            note_verdict_scan_capped();
            break;
        }
        let (id, raw) = row?;
        let record =
            skill_edit_verdict_receipt(&decode_verdict_with_marker(vault, &rtxn, id, &raw)?);
        if !query.matches(&record) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(record);
        } else {
            retain_newest_receipt(&mut out, record, query.limit);
        }
    }
    Ok(out)
}

/// Surfaces a verdict-ledger scan that stopped at the receipt-family work cap.
///
/// The discarded remainder is unbounded by construction, so it is never
/// counted: the fact worth saying is that the answer is a bounded PREFIX of the
/// family rather than the family, which is exactly what
/// `edit_distance::graduation` says at its own cap.
fn note_verdict_scan_capped() {
    tracing::warn!(
        scan_cap = crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        "skill edit verdict scan hit the receipt-family work cap; older rulings were not projected"
    );
}

fn skill_edit_verdict_receipt(verdict: &HeldOutVerdict) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (
            FIELD_SKILL_EDIT_PROPOSAL.to_owned(),
            verdict.proposal.to_hex(),
        ),
        (FIELD_SKILL_EDIT_SKILL.to_owned(), verdict.skill.to_hex()),
        // Decimal numerals, not prose: the pair a reader has to be able to
        // compare survives the receipt family's string field ABI intact, and
        // `skill_edit_verdicts` serves the same two numbers already typed.
        (
            FIELD_SKILL_EDIT_SCORE_BEFORE.to_owned(),
            format!("{:.6}", verdict.before),
        ),
        (
            FIELD_SKILL_EDIT_SCORE_AFTER.to_owned(),
            format!("{:.6}", verdict.after),
        ),
        (FIELD_SKILL_EDIT_CYCLE.to_owned(), verdict.cycle.clone()),
        (
            FIELD_SKILL_EDIT_DISPOSITION.to_owned(),
            verdict.disposition.as_str().to_owned(),
        ),
        // The complete basis travels with every ruling, truncated display list
        // or not: a receipt that showed a window and said nothing about the
        // rest was claiming an evidence set it did not have.
        (
            FIELD_SKILL_EDIT_HELD_OUT_COUNT.to_owned(),
            verdict.held_out_count.to_string(),
        ),
        (
            FIELD_SKILL_EDIT_HELD_OUT_DIGEST.to_owned(),
            verdict.held_out_digest.clone(),
        ),
    ]);
    if let Some(judge) = &verdict.judge_revision {
        fields.insert(FIELD_SKILL_EDIT_JUDGE_REVISION.to_owned(), judge.clone());
    }
    if let Some(replacement) = &verdict.displaced_by_revision {
        fields.insert(
            FIELD_SKILL_EDIT_JUDGE_DISPLACED_BY.to_owned(),
            replacement.clone(),
        );
    }
    if let Some(measurements) = &verdict.measurements {
        fields.insert(
            FIELD_SKILL_EDIT_MEASUREMENTS.to_owned(),
            serde_json::to_string(measurements).expect("validated measurement serializes"),
        );
    }
    if !verdict.proposal_digest.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_PROPOSAL_DIGEST.to_owned(),
            verdict.proposal_digest.clone(),
        );
    }
    if !verdict.target_digest.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_TARGET_DIGEST.to_owned(),
            verdict.target_digest.clone(),
        );
    }
    if let Some(accepted) = verdict.accepted_verdict {
        fields.insert(
            FIELD_SKILL_EDIT_ACCEPTED_VERDICT.to_owned(),
            accepted.to_hex(),
        );
    }
    if verdict.held_out_truncated {
        fields.insert(
            FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED.to_owned(),
            "true".to_owned(),
        );
    }
    if !verdict.held_out_receipts.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS.to_owned(),
            verdict.held_out_receipts.join(","),
        );
    }
    if !verdict.missing_sources.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_MISSING_SOURCES.to_owned(),
            verdict
                .missing_sources
                .iter()
                .map(EntityId::to_hex)
                .collect::<Vec<String>>()
                .join(","),
        );
    }
    ReceiptRecord {
        receipt_id: format!("{SKILL_EDIT_RECEIPT_PREFIX}{}", verdict.id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: verdict.at,
        actor: None,
        on_behalf_of: None,
        outcome: verdict.disposition.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("skill_proposal:{}", verdict.proposal.to_hex())),
        policy_trace: vec![format!(
            "skill_optimize.gate.{}",
            verdict.disposition.as_str()
        )],
        fields,
    }
}

/// A candidate verdict retired with its judge: the replacement judge revision, keyed by the
/// verdict id. The verdict row itself stays as ruled.
const DISPLACED_VERDICT: SideTable<EntityId, VerdictDisplacement, Raw> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_DISPLACED_JUDGE);

/// The fence on a displaced candidate judge revision: the replacement revision, keyed by the
/// displaced revision's text.
const DISPLACED_REVISION: SideTable<String, JudgeDisplacement, Raw> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_DISPLACED_REVISION);

/// [`DISPLACED_VERDICT`]'s row: the replacement revision as UTF-8. A row that is not UTF-8 is
/// verdict-ledger corruption, as it always read.
struct VerdictDisplacement(String);

impl RawValue for VerdictDisplacement {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        String::from_utf8(bytes.to_vec())
            .map(Self)
            .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL).into())
    }
}

/// [`DISPLACED_REVISION`]'s row: the replacement revision as UTF-8.
struct JudgeDisplacement(String);

impl RawValue for JudgeDisplacement {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        String::from_utf8(bytes.to_vec())
            .map(Self)
            .map_err(|_| Error::CorruptedIndex("candidate judge displacement").into())
    }
}

pub(crate) fn validate_judge_revision(revision: &str) -> Result<()> {
    if revision.is_empty() || revision.len() > 256 || revision.chars().any(char::is_control) {
        return Err(invalid("invalid candidate judge revision"));
    }
    Ok(())
}

pub(crate) fn ensure_current_judge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision: &str,
) -> Result<()> {
    validate_judge_revision(revision)?;
    if DISPLACED_REVISION.contains(&vault.store, txn, &revision.to_owned())? {
        return Err(invalid("candidate judge revision was displaced"));
    }
    Ok(())
}

pub(crate) fn displaced_judge_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision: &str,
) -> Result<Option<String>> {
    Ok(DISPLACED_REVISION
        .get(&vault.store, txn, &revision.to_owned())?
        .map(|mark| mark.0))
}

/// Retire candidate-scoring judgments by their immutable judge revision.
/// Their scores and original verdict rows remain readable, while admissions
/// and repeat deliveries no longer treat their acceptances as standing.
pub fn supersede_skill_edit_judge(
    vault: &Vault,
    displaced: &str,
    replacement: &str,
) -> Result<Vec<EntityId>> {
    if displaced == replacement
        || displaced.is_empty()
        || replacement.is_empty()
        || displaced.len() > 256
        || replacement.len() > 256
        || displaced.chars().any(char::is_control)
        || replacement.chars().any(char::is_control)
    {
        return Err(invalid("invalid candidate judge replacement"));
    }
    vault.with_write_txn(|txn| {
        let revision_key = displaced.to_owned();
        if let Some(held) = DISPLACED_REVISION.get(&vault.store, txn, &revision_key)? {
            if held.0 != replacement {
                return Err(invalid(
                    "candidate judge revision already displaced by another judge",
                ));
            }
        } else {
            DISPLACED_REVISION.put(
                &vault.store,
                txn,
                &revision_key,
                &JudgeDisplacement(replacement.to_owned()),
            )?;
        }
        let mut ids = Vec::new();
        for verdict in verdict_rows_in_txn(vault, txn)? {
            if verdict.judge_revision.as_deref() != Some(displaced) {
                continue;
            }
            if let Some(held) = DISPLACED_VERDICT.get(&vault.store, txn, &verdict.id)? {
                if held.0 != replacement {
                    return Err(invalid(
                        "candidate verdict already displaced by another judge",
                    ));
                }
            } else {
                DISPLACED_VERDICT.put(
                    &vault.store,
                    txn,
                    &verdict.id,
                    &VerdictDisplacement(replacement.to_owned()),
                )?;
            }
            ids.push(verdict.id);
        }
        Ok(ids)
    })
}
