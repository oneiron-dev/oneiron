//! Storage: vault_meta keyspace, the evidence-grounding door check, and MessagePack encode/decode.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::ManifestEntry;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::audit::AttributionAuditReport;
use super::types::{
    AttemptOutcome, AttributionJudgment, AttributionVerdict, OutcomeEvidence,
    SKILL_ATTRIBUTION_SCHEMA_VERSION, SkillEditProposal,
};

pub(super) const EVIDENCE_PREFIX: &[u8] = b"skill_attribution:evidence:v1:"; // + sequence(8 BE)

pub(super) const JUDGMENT_PREFIX: &[u8] = b"skill_attribution:judgment:v1:"; // + sequence(8 BE)

pub(super) const AUDIT_PREFIX: &[u8] = b"skill_attribution:audit:v1:"; // + at(8 BE) + seq(8 BE)

// + judgment sequence(8 BE): one proposal per discovery judgment, so a
// re-projection of the same evidence re-mints the same key rather than a
// duplicate proposal.
pub(super) const EDIT_PROPOSAL_PREFIX: &[u8] = b"skill_attribution:edit_proposal:v1:";

const EVIDENCE_SEQUENCE_KEY: &[u8] = b"skill_attribution:evidence_sequence:v1";

pub(super) const CURSOR_KEY: &[u8] = b"skill_attribution:cursor:v1";

pub(super) const SEQUENCE_LEN: usize = 8;

const KEY_SCHEMA_VERSION: &str = "schema_version";

const KEY_SEQUENCE: &str = "sequence";

const KEY_RECEIPT_REF: &str = "receipt_ref";

const KEY_ACTOR: &str = "actor";

const KEY_SKILL: &str = "skill";

const KEY_OUTCOME: &str = "outcome";

const KEY_FOLLOWED_SKILL: &str = "followed_skill";

const KEY_SKILL_COVERED_STEP: &str = "skill_covered_step";

const KEY_AT: &str = "at";

const KEY_VERDICT: &str = "verdict";

const KEY_SUBJECT: &str = "subject";

const KEY_EVIDENCE_RECEIPTS: &str = "evidence_receipts";

const KEY_TOTAL: &str = "total";

const KEY_PASSED: &str = "passed";

const KEY_ABSTAINED: &str = "abstained";

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Grounds one evidence row against the vault before it is recorded.
///
/// A verdict is only as good as its inputs. Evidence naming an actor that does
/// not exist, a skill that does not exist, or a receipt nobody stamped is a
/// FABRICATION: routing it would mint a judgment whose citation resolves to
/// nothing, and the layers above (ONE-1738's posterior, ONE-1739's `actor.*`
/// rows) would inherit it as fact. Every reference is resolved here, at the
/// door, so the projector downstream can trust what it reads.
pub(super) fn validate_evidence(vault: &Vault, evidence: &OutcomeEvidence) -> Result<()> {
    if evidence.receipt_ref.is_empty() {
        return Err(invalid("attribution evidence must cite a receipt"));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, &evidence.receipt_ref)? else {
        return Err(invalid("attribution evidence cites an unstamped receipt"));
    };
    if vault.get_raw(&evidence.actor)?.is_none() {
        return Err(invalid("attribution evidence names an unknown actor"));
    }
    let Some(skill) = evidence.skill else {
        return Ok(());
    };
    let Some(record) = vault.get_skill_record(&skill)? else {
        return Err(invalid("attribution evidence names an unknown skill"));
    };
    // The receipt's manifest is what the pack ACTUALLY loaded. A skill the
    // attempt never loaded cannot have caused its outcome, so admitting the
    // pair would be attribution by assertion. A receipt stamped before the
    // field-set existed carries no manifest and cannot answer the question —
    // that is an absent fact, not a failed check.
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return Ok(());
    };
    if !manifest
        .iter()
        .any(|entry| manifest_entry_names_skill(entry, &record.skill_id))
    {
        return Err(invalid(
            "attribution evidence names a skill absent from the receipt manifest",
        ));
    }
    Ok(())
}

/// A manifest wire form is `reference@version` and the reference of a SKILL
/// row is its `skill_id`. [`ManifestEntry::parse_wire_form`] owns the split.
fn manifest_entry_names_skill(wire_form: &str, skill_id: &str) -> bool {
    ManifestEntry::parse_wire_form(wire_form).is_some_and(|(reference, _)| reference == skill_id)
}

pub(super) fn sequenced_key(prefix: &[u8], sequence: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + SEQUENCE_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

pub(super) fn next_evidence_sequence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let current = match vault.store.vault_meta.get(wtxn, EVIDENCE_SEQUENCE_KEY)? {
        Some(raw) => decode_u64(&raw, "attribution evidence sequence")?,
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("attribution evidence sequence"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, EVIDENCE_SEQUENCE_KEY, &next.to_be_bytes())?;
    Ok(next)
}

pub(super) fn evidence_after(
    vault: &Vault,
    since_cursor: u64,
) -> Result<Vec<(u64, OutcomeEvidence)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, EVIDENCE_PREFIX)? {
        let (key, raw) = row?;
        let sequence = evidence_sequence_from_key(&key)?;
        if sequence <= since_cursor {
            continue;
        }
        out.push((sequence, decode_evidence(&raw)?));
    }
    // Big-endian sequence suffixes already sort in routing order; sorting keeps
    // the contract explicit rather than implied by the key encoding.
    out.sort_by_key(|(sequence, _)| *sequence);
    Ok(out)
}

fn evidence_sequence_from_key(key: &[u8]) -> Result<u64> {
    let suffix = key
        .get(EVIDENCE_PREFIX.len()..)
        .ok_or(invalid("attribution evidence key is truncated"))?;
    decode_u64(suffix, "attribution evidence key")
}

pub(super) fn decode_u64(raw: &[u8], _context: &'static str) -> Result<u64> {
    let bytes: [u8; SEQUENCE_LEN] = raw
        .try_into()
        .map_err(|_| invalid("attribution counter must be 8 bytes"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn optional_entity(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

fn optional_bool(flag: Option<bool>) -> Value {
    flag.map_or(Value::Nil, Value::Boolean)
}

pub(super) fn encode_evidence(evidence: &OutcomeEvidence, sequence: u64) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SEQUENCE), Value::from(sequence)),
        (
            Value::from(KEY_RECEIPT_REF),
            Value::from(evidence.receipt_ref.as_str()),
        ),
        (
            Value::from(KEY_ACTOR),
            Value::Binary(evidence.actor.as_bytes().to_vec()),
        ),
        (Value::from(KEY_SKILL), optional_entity(evidence.skill)),
        (
            Value::from(KEY_OUTCOME),
            Value::from(evidence.outcome.as_str()),
        ),
        (
            Value::from(KEY_FOLLOWED_SKILL),
            optional_bool(evidence.followed_skill),
        ),
        (
            Value::from(KEY_SKILL_COVERED_STEP),
            optional_bool(evidence.skill_covered_step),
        ),
        (Value::from(KEY_AT), Value::from(evidence.at)),
    ])
}

fn decode_evidence(raw: &[u8]) -> Result<OutcomeEvidence> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut receipt_ref = None;
    let mut actor = None;
    let mut skill = None;
    let mut outcome = None;
    let mut followed_skill = None;
    let mut skill_covered_step = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => {}
            KEY_RECEIPT_REF => receipt_ref = value.as_str().map(str::to_owned),
            KEY_ACTOR => actor = Some(decode_entity(value)?),
            KEY_SKILL => skill = decode_optional_entity(value)?,
            KEY_OUTCOME => outcome = value.as_str().and_then(AttemptOutcome::parse),
            KEY_FOLLOWED_SKILL => followed_skill = value.as_bool(),
            KEY_SKILL_COVERED_STEP => skill_covered_step = value.as_bool(),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution evidence key is not pinned")),
        }
    }
    Ok(OutcomeEvidence {
        receipt_ref: receipt_ref.ok_or(invalid("attribution evidence missing receipt"))?,
        actor: actor.ok_or(invalid("attribution evidence missing actor"))?,
        skill,
        outcome: outcome.ok_or(invalid("attribution evidence missing outcome"))?,
        followed_skill,
        skill_covered_step,
        at: at.ok_or(invalid("attribution evidence missing timestamp"))?,
    })
}

pub(super) fn encode_judgment(judgment: &AttributionJudgment) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SEQUENCE), Value::from(judgment.sequence)),
        (
            Value::from(KEY_VERDICT),
            Value::from(judgment.verdict.as_str()),
        ),
        (
            Value::from(KEY_SUBJECT),
            Value::Binary(judgment.subject.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_EVIDENCE_RECEIPTS),
            Value::Array(
                judgment
                    .evidence_receipts
                    .iter()
                    .map(|receipt| Value::from(receipt.as_str()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_AT), Value::from(judgment.at)),
    ])
}

pub(super) fn decode_judgment(raw: &[u8]) -> Result<AttributionJudgment> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut sequence = None;
    let mut verdict = None;
    let mut subject = None;
    let mut evidence_receipts = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => sequence = value.as_u64(),
            KEY_VERDICT => verdict = value.as_str().and_then(AttributionVerdict::parse),
            KEY_SUBJECT => subject = Some(decode_entity(value)?),
            KEY_EVIDENCE_RECEIPTS => evidence_receipts = Some(decode_receipt_array(value)?),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution judgment key is not pinned")),
        }
    }
    Ok(AttributionJudgment {
        sequence: sequence.ok_or(invalid("attribution judgment missing sequence"))?,
        verdict: verdict.ok_or(invalid("attribution judgment missing verdict"))?,
        subject: subject.ok_or(invalid("attribution judgment missing subject"))?,
        evidence_receipts: evidence_receipts
            .ok_or(invalid("attribution judgment missing evidence"))?,
        at: at.ok_or(invalid("attribution judgment missing timestamp"))?,
    })
}

fn decode_receipt_array(value: &Value) -> Result<Vec<String>> {
    let rows = value
        .as_array()
        .ok_or(invalid("attribution evidence citation must be an array"))?;
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        receipts.push(
            row.as_str()
                .ok_or(invalid("attribution evidence citation must be strings"))?
                .to_owned(),
        );
    }
    Ok(receipts)
}

pub(super) fn encode_edit_proposal(proposal: &SkillEditProposal) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SEQUENCE),
            Value::from(proposal.judgment_sequence),
        ),
        (
            Value::from(KEY_SUBJECT),
            Value::Binary(proposal.skill.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_EVIDENCE_RECEIPTS),
            Value::Array(
                proposal
                    .evidence_receipts
                    .iter()
                    .map(|receipt| Value::from(receipt.as_str()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_AT), Value::from(proposal.at)),
    ])
}

pub(super) fn decode_edit_proposal(raw: &[u8]) -> Result<SkillEditProposal> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut judgment_sequence = None;
    let mut skill = None;
    let mut evidence_receipts = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => judgment_sequence = value.as_u64(),
            KEY_SUBJECT => skill = Some(decode_entity(value)?),
            KEY_EVIDENCE_RECEIPTS => evidence_receipts = Some(decode_receipt_array(value)?),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("skill edit proposal key is not pinned")),
        }
    }
    Ok(SkillEditProposal {
        judgment_sequence: judgment_sequence
            .ok_or(invalid("skill edit proposal missing judgment sequence"))?,
        skill: skill.ok_or(invalid("skill edit proposal missing skill"))?,
        evidence_receipts: evidence_receipts
            .ok_or(invalid("skill edit proposal missing evidence"))?,
        at: at.ok_or(invalid("skill edit proposal missing timestamp"))?,
    })
}

pub(super) fn encode_audit(report: &AttributionAuditReport) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TOTAL), Value::from(report.total as u64)),
        (Value::from(KEY_PASSED), Value::from(report.passed as u64)),
        (
            Value::from(KEY_ABSTAINED),
            Value::from(report.abstained as u64),
        ),
        (Value::from(KEY_AT), Value::from(report.at)),
    ])
}

pub(super) fn decode_audit(raw: &[u8]) -> Result<AttributionAuditReport> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut total = None;
    let mut passed = None;
    let mut abstained = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_TOTAL => total = value.as_u64(),
            KEY_PASSED => passed = value.as_u64(),
            KEY_ABSTAINED => abstained = value.as_u64(),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution audit key is not pinned")),
        }
    }
    let count = |value: Option<u64>| -> Result<usize> {
        usize::try_from(value.ok_or(invalid("attribution audit missing count"))?)
            .map_err(|_| invalid("attribution audit count exceeds usize"))
    };
    Ok(AttributionAuditReport {
        total: count(total)?,
        passed: count(passed)?,
        abstained: count(abstained)?,
        at: at.ok_or(invalid("attribution audit missing timestamp"))?,
    })
}

fn require_schema_version(value: &Value) -> Result<()> {
    if value.as_u64() == Some(SKILL_ATTRIBUTION_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(invalid("unsupported skill attribution schema"))
}

fn decode_entity(value: &Value) -> Result<EntityId> {
    let bytes: [u8; 16] = value
        .as_slice()
        .ok_or(invalid("attribution entity ref must be binary"))?
        .try_into()
        .map_err(|_| invalid("attribution entity ref must be 16 bytes"))?;
    EntityId::from_bytes(bytes)
}

fn decode_optional_entity(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_entity(value).map(Some)
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid("skill attribution MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut Cursor::new(raw))
        .map_err(|_| invalid("skill attribution MessagePack decode failed"))
}

fn expect_map(value: &Value) -> Result<&Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid("skill attribution row must be a MessagePack map")),
    }
}

fn expect_key(key: &Value) -> Result<&str> {
    key.as_str()
        .ok_or(invalid("skill attribution keys must be strings"))
}
