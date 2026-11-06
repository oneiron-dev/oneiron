//! Storage: vault_meta keyspace, the evidence-grounding door check, and MessagePack encode/decode.

use std::io::Cursor;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::write_envelope::skill_record::record::SkillRecord;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;

use oneiron_skill_attribution::types::AttemptOutcome;
use oneiron_skill_attribution::types::AttributionJudgment;
use oneiron_skill_attribution::types::AttributionVerdict;
use oneiron_skill_attribution::types::DeviationCause;
use oneiron_skill_attribution::types::FollowedState;
use oneiron_skill_attribution::types::OutcomeEvidence;
use oneiron_skill_attribution::types::SKILL_ATTRIBUTION_SCHEMA_VERSION;
use oneiron_skill_attribution::types::SkillEditProposal;

impl RawValue for AttributionJudgment {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_value(&encode_judgment(self)?)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_judgment(bytes)?)
    }
}

impl RawValue for SkillEditProposal {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_value(&encode_edit_proposal(self)?)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_edit_proposal(bytes)?)
    }
}

pub const KEY_SCHEMA_VERSION: &str = "schema_version";

pub const KEY_SEQUENCE: &str = "sequence";

pub const KEY_AT: &str = "at";

pub const KEY_VERDICT: &str = "verdict";

pub const KEY_SUBJECT: &str = "subject";

pub const KEY_EVIDENCE_RECEIPTS: &str = "evidence_receipts";

pub const KEY_ROW_ID: &str = "row_id";

pub const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub fn optional_entity(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

pub fn encode_judgment(judgment: &AttributionJudgment) -> Result<Value> {
    let position = rmpv::ext::to_value(&judgment.read_position)
        .map_err(|_| invalid("attribution judgment position encode failed"))?;
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SEQUENCE), Value::from(judgment.sequence)),
        (
            Value::from(KEY_ROW_ID),
            Value::Binary(judgment.row_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_VERDICT),
            Value::from(judgment.verdict.as_str()),
        ),
        (Value::from(KEY_SUBJECT), optional_entity(judgment.subject)),
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
        (Value::from("read_position"), position),
    ]))
}

pub fn decode_judgment(raw: &[u8]) -> Result<AttributionJudgment> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut sequence = None;
    let mut row_id = None;
    let mut verdict = None;
    let mut subject = None;
    let mut evidence_receipts = None;
    let mut at = None;
    let mut read_position = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => sequence = value.as_u64(),
            KEY_ROW_ID => row_id = Some(decode_entity(value)?),
            KEY_VERDICT => verdict = value.as_str().and_then(AttributionVerdict::parse),
            KEY_SUBJECT => subject = Some(decode_optional_entity(value)?),
            KEY_EVIDENCE_RECEIPTS => evidence_receipts = Some(decode_receipt_array(value)?),
            KEY_AT => at = value.as_u64(),
            "read_position" => {
                read_position = Some(
                    rmpv::ext::from_value(value.clone())
                        .map_err(|_| invalid("attribution judgment position decode failed"))?,
                );
            }
            _ => return Err(invalid("attribution judgment key is not pinned")),
        }
    }
    Ok(AttributionJudgment {
        sequence: sequence.ok_or(invalid("attribution judgment missing sequence"))?,
        row_id: row_id.ok_or(invalid("attribution judgment missing row id"))?,
        verdict: verdict.ok_or(invalid("attribution judgment missing verdict"))?,
        subject: subject.ok_or(invalid("attribution judgment missing subject"))?,
        evidence_receipts: evidence_receipts
            .ok_or(invalid("attribution judgment missing evidence"))?,
        at: at.ok_or(invalid("attribution judgment missing timestamp"))?,
        read_position: read_position.ok_or(invalid("attribution judgment missing position"))?,
    })
}

pub fn decode_receipt_array(value: &Value) -> Result<Vec<String>> {
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

pub fn encode_edit_proposal(proposal: &SkillEditProposal) -> Result<Value> {
    let position = rmpv::ext::to_value(&proposal.read_position)
        .map_err(|_| invalid("skill edit proposal position encode failed"))?;
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SEQUENCE),
            Value::from(proposal.judgment_sequence),
        ),
        (
            Value::from(KEY_ROW_ID),
            Value::Binary(proposal.row_id.as_bytes().to_vec()),
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
        (Value::from("read_position"), position),
    ]))
}

pub fn decode_edit_proposal(raw: &[u8]) -> Result<SkillEditProposal> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut judgment_sequence = None;
    let mut row_id = None;
    let mut skill = None;
    let mut evidence_receipts = None;
    let mut at = None;
    let mut read_position = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => judgment_sequence = value.as_u64(),
            KEY_ROW_ID => row_id = Some(decode_entity(value)?),
            KEY_SUBJECT => skill = Some(decode_entity(value)?),
            KEY_EVIDENCE_RECEIPTS => evidence_receipts = Some(decode_receipt_array(value)?),
            KEY_AT => at = value.as_u64(),
            "read_position" => {
                read_position = Some(
                    rmpv::ext::from_value(value.clone())
                        .map_err(|_| invalid("skill edit proposal position decode failed"))?,
                );
            }
            _ => return Err(invalid("skill edit proposal key is not pinned")),
        }
    }
    Ok(SkillEditProposal {
        judgment_sequence: judgment_sequence
            .ok_or(invalid("skill edit proposal missing judgment sequence"))?,
        row_id: row_id.ok_or(invalid("skill edit proposal missing row id"))?,
        skill: skill.ok_or(invalid("skill edit proposal missing skill"))?,
        evidence_receipts: evidence_receipts
            .ok_or(invalid("skill edit proposal missing evidence"))?,
        at: at.ok_or(invalid("skill edit proposal missing timestamp"))?,
        read_position: read_position.ok_or(invalid("skill edit proposal missing position"))?,
    })
}

pub fn require_schema_version(value: &Value) -> Result<()> {
    if value.as_u64() == Some(SKILL_ATTRIBUTION_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(invalid("unsupported skill attribution schema"))
}

pub fn decode_entity(value: &Value) -> Result<EntityId> {
    let bytes: [u8; 16] = value
        .as_slice()
        .ok_or(invalid("attribution entity ref must be binary"))?
        .try_into()
        .map_err(|_| invalid("attribution entity ref must be 16 bytes"))?;
    EntityId::from_bytes(bytes)
}

pub fn decode_optional_entity(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_entity(value).map(Some)
}

pub fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid("skill attribution MessagePack encode failed"))?;
    Ok(encoded)
}

pub fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut Cursor::new(raw))
        .map_err(|_| invalid("skill attribution MessagePack decode failed"))
}

pub fn expect_map(value: &Value) -> Result<&Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid("skill attribution row must be a MessagePack map")),
    }
}

pub fn expect_key(key: &Value) -> Result<&str> {
    key.as_str()
        .ok_or(invalid("skill attribution keys must be strings"))
}
