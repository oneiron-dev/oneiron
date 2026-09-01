//! The verdict ledger, and the `Gate` receipts projected from it.

use super::*;

// ---------------------------------------------------------------------------
// The verdict ledger
// ---------------------------------------------------------------------------

fn verdict_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(VERDICT_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(VERDICT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn record_verdict_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: &HeldOutVerdict,
) -> Result<()> {
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
        (Value::from(KEY_AT), Value::from(verdict.at)),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &row)
        .map_err(|_| invalid("skill edit verdict MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &verdict_key(&verdict.id), &encoded)?;
    Ok(())
}

fn decode_verdict(key: &[u8], raw: &[u8]) -> Result<HeldOutVerdict> {
    let id = key
        .get(VERDICT_PREFIX.len()..)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
        .and_then(|tail| parse_entity_id(tail, VERDICT_ROW_LABEL))?;
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
    let strings = |name: &str| {
        field(name)
            .and_then(|value| match value {
                Value::Array(entries) => Some(entries),
                _ => None,
            })
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_owned))
                    .collect::<Vec<String>>()
            })
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
    Ok(HeldOutVerdict {
        before: score(KEY_BEFORE)?,
        after: score(KEY_AFTER)?,
        accepted: disposition.admits(),
        id,
        proposal: entity(KEY_PROPOSAL)?,
        skill: entity(KEY_SKILL)?,
        disposition,
        cycle: text(KEY_CYCLE)?,
        held_out_receipts: strings(KEY_HELD_OUT)?,
        held_out_count: field(KEY_HELD_OUT_COUNT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
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
        missing_sources: strings(KEY_MISSING_SOURCES)?
            .iter()
            .filter_map(|hex| EntityId::from_hex(hex).ok())
            .collect(),
        at: field(KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
    })
}

pub(super) fn verdict_rows_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<HeldOutVerdict>> {
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(rtxn, VERDICT_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_verdict(&key, &raw)?);
    }
    Ok(out)
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

/// Projects the verdict ledger as `Gate` receipts.
///
/// A gate verdict IS a gate decision, so it mints no kind of its own — the
/// `edit_distance::escalation` precedent, whose field class it copies down to
/// the discriminating key prefix. Opens its own read txn, as that projector
/// does, and bounds the RESULT rather than the walk: these keys are ruling-
/// ordered, so the newest `query.limit` is exactly what cannot be dropped
/// without changing the caller's answer.
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
    for verdict in verdict_rows_in_txn(vault, &rtxn)? {
        let record = skill_edit_verdict_receipt(&verdict);
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
