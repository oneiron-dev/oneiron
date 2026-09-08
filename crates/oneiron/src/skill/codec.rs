//! MessagePack encode and decode for SKILL bodies and dependencies.

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::identity::SkillContentHash;
use super::lifecycle::{SkillGovernanceTier, SkillLifecycle};
use super::record::{
    KEY_APPROVAL_STATUS, KEY_CONFIDENCE, KEY_CONTENT_HASH, KEY_DEP_MIN_VERSION, KEY_DEP_SKILL_ID,
    KEY_DEPENDENCIES, KEY_DESC, KEY_FORKED_FROM, KEY_GENERATED, KEY_GOVERNANCE_TIER,
    KEY_HUMAN_AUTHORED, KEY_LIFECYCLE_STATUS, KEY_PROVENANCE, KEY_SKILL_ID, KEY_SOURCE,
    KEY_VERSION, SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES,
    SKILL_MAX_DEPENDENCIES, SKILL_RECORD_BODY_KEYS, SKILL_VERSION_MAX_BYTES, SkillDependency,
    SkillRecord,
};
use super::validate::{validate_skill_record, validate_text_field};

pub fn encode_skill_record(record: &SkillRecord) -> Result<Vec<u8>> {
    validate_skill_record(record)?;
    let mut entries = vec![
        (
            Value::from(KEY_SKILL_ID),
            Value::from(record.skill_id.as_str()),
        ),
        (Value::from(KEY_DESC), Value::from(record.desc.as_str())),
        (
            Value::from(KEY_VERSION),
            Value::from(record.version.as_str()),
        ),
        (
            Value::from(KEY_APPROVAL_STATUS),
            Value::from(record.approval_status.as_str()),
        ),
        (
            Value::from(KEY_LIFECYCLE_STATUS),
            Value::from(record.lifecycle_status.as_str()),
        ),
        (Value::from(KEY_SOURCE), Value::from(record.source.as_str())),
        (Value::from(KEY_CONFIDENCE), Value::F32(record.confidence)),
        (Value::from(KEY_GENERATED), Value::Boolean(record.generated)),
        (
            Value::from(KEY_HUMAN_AUTHORED),
            Value::Boolean(record.human_authored),
        ),
        (
            Value::from(KEY_DEPENDENCIES),
            Value::Array(
                record
                    .dependencies
                    .iter()
                    .map(encode_skill_dependency)
                    .collect(),
            ),
        ),
        (Value::from(KEY_PROVENANCE), record.provenance.clone()),
    ];
    // Elide-the-default (the claim `world`/`stale` pattern): absent means
    // "not computed" / "not a fork"; when present the shape is strict.
    if let Some(content_hash) = &record.content_hash {
        entries.push((
            Value::from(KEY_CONTENT_HASH),
            Value::from(content_hash.to_hex()),
        ));
    }
    if let Some(parent) = &record.forked_from {
        entries.push((Value::from(KEY_FORKED_FROM), Value::from(parent.to_hex())));
    }
    // Absent means "unmarked", which is a DIFFERENT fact from `standard` and
    // must stay tellable apart on the wire (ONE-1448's fail-closed default).
    if let Some(tier) = &record.governance_tier {
        entries.push((Value::from(KEY_GOVERNANCE_TIER), Value::from(tier.as_str())));
    }
    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("SKILL record MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_skill_record(bytes: &[u8]) -> Result<SkillRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidSkillBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidSkillBody("trailing bytes after body map"));
    }
    decode_skill_record_value(&value)
}

fn decode_skill_record_value(value: &Value) -> Result<SkillRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody("body must be a MessagePack map"));
    };

    let mut skill_id = None;
    let mut desc = None;
    let mut version = None;
    let mut approval_status = None;
    let mut lifecycle_status = None;
    let mut source = None;
    let mut confidence = None;
    let mut generated = None;
    let mut human_authored = None;
    let mut dependencies = None;
    let mut provenance = None;
    let mut content_hash = None;
    let mut forked_from = None;
    let mut governance_tier = None;
    let mut seen = [false; SKILL_RECORD_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("body keys must be strings"));
        };
        let Some(index) = SKILL_RECORD_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidSkillBody(
                "body key is not in the pinned SKILL_RECORD_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody("duplicate body key"));
        }
        seen[index] = true;

        match SKILL_RECORD_BODY_KEYS[index] {
            KEY_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    SKILL_ID_MAX_BYTES,
                    "skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DESC => {
                desc = Some(text_value(
                    value,
                    SKILL_DESC_MAX_BYTES,
                    "desc must be a non-empty UTF-8 string at most 4096 bytes",
                )?);
            }
            KEY_VERSION => {
                version = Some(text_value(
                    value,
                    SKILL_VERSION_MAX_BYTES,
                    "version must be a non-empty UTF-8 string at most 128 bytes",
                )?);
            }
            KEY_APPROVAL_STATUS => {
                approval_status = Some(value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidSkillBody(
                        "approvalStatus must be one of auto|proposed|approved|rejected",
                    ),
                )?);
            }
            KEY_LIFECYCLE_STATUS => {
                lifecycle_status = Some(value.as_str().and_then(SkillLifecycle::parse).ok_or(
                    Error::InvalidSkillBody(
                        "lifecycleStatus must be one of candidate|active|stale|quarantined|superseded",
                    ),
                )?);
            }
            KEY_SOURCE => {
                source =
                    Some(
                        value
                            .as_str()
                            .and_then(ClaimSource::parse)
                            .ok_or(Error::InvalidSkillBody(
                                "source must be one of user_stated|observed|inferred|imported|tool_output|generated",
                            ))?,
                    );
            }
            KEY_CONFIDENCE => {
                confidence = Some(crate::claim::unit_interval_f32(value).ok_or(
                    Error::InvalidSkillBody("confidence must be finite in [0, 1]"),
                )?);
            }
            KEY_GENERATED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidSkillBody("generated must be a boolean"));
                };
                generated = Some(*flag);
            }
            KEY_HUMAN_AUTHORED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidSkillBody("humanAuthored must be a boolean"));
                };
                human_authored = Some(*flag);
            }
            KEY_DEPENDENCIES => dependencies = Some(decode_skill_dependencies(value)?),
            KEY_PROVENANCE => provenance = Some(value.clone()),
            KEY_CONTENT_HASH => {
                let hex = value.as_str().ok_or(Error::InvalidSkillBody(
                    "contentHash must be 64 lowercase hex characters",
                ))?;
                content_hash = Some(SkillContentHash::parse_hex(hex)?);
            }
            KEY_FORKED_FROM => {
                let hex = value.as_str().ok_or(Error::InvalidSkillBody(
                    "forkedFrom must be a 32-char entity id hex string",
                ))?;
                forked_from = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::InvalidSkillBody("forkedFrom must be a 32-char entity id hex string")
                })?);
            }
            KEY_GOVERNANCE_TIER => {
                governance_tier = Some(value.as_str().and_then(SkillGovernanceTier::parse).ok_or(
                    Error::InvalidSkillBody(
                        "governanceTier must be one of identity|alignment|standard",
                    ),
                )?);
            }
            _ => unreachable!("index resolved from SKILL_RECORD_BODY_KEYS"),
        }
    }

    let record = SkillRecord {
        skill_id: skill_id.ok_or(Error::InvalidSkillBody("missing required key skillId"))?,
        desc: desc.ok_or(Error::InvalidSkillBody("missing required key desc"))?,
        version: version.ok_or(Error::InvalidSkillBody("missing required key version"))?,
        approval_status: approval_status.ok_or(Error::InvalidSkillBody(
            "missing required key approvalStatus",
        ))?,
        lifecycle_status: lifecycle_status.ok_or(Error::InvalidSkillBody(
            "missing required key lifecycleStatus",
        ))?,
        source: source.ok_or(Error::InvalidSkillBody("missing required key source"))?,
        confidence: confidence.ok_or(Error::InvalidSkillBody("missing required key confidence"))?,
        generated: generated.ok_or(Error::InvalidSkillBody("missing required key generated"))?,
        human_authored: human_authored.ok_or(Error::InvalidSkillBody(
            "missing required key humanAuthored",
        ))?,
        dependencies: dependencies
            .ok_or(Error::InvalidSkillBody("missing required key dependencies"))?,
        provenance: provenance.ok_or(Error::InvalidSkillBody("missing required key provenance"))?,
        // Optional identity/lineage layer: absent on pre-ONE-1735 bodies
        // and on records whose canonical tree is not materialized.
        content_hash,
        forked_from,
        // Absent on every body minted before ONE-1448, and on every record
        // whose owner has not ruled: the tier resolver, not the codec,
        // decides what an absent mark means.
        governance_tier,
    };
    validate_skill_record(&record)?;
    Ok(record)
}

fn encode_skill_dependency(dependency: &SkillDependency) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DEP_SKILL_ID),
            Value::from(dependency.skill_id.as_str()),
        ),
        (
            Value::from(KEY_DEP_MIN_VERSION),
            dependency
                .min_version
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_skill_dependencies(value: &Value) -> Result<Vec<SkillDependency>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidSkillBody(
            "dependencies must be a MessagePack array",
        ));
    };
    if values.len() > SKILL_MAX_DEPENDENCIES {
        return Err(Error::InvalidSkillBody(
            "dependencies must contain at most 64 entries",
        ));
    }
    values.iter().map(decode_skill_dependency).collect()
}

fn decode_skill_dependency(value: &Value) -> Result<SkillDependency> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody(
            "dependency must be a MessagePack map",
        ));
    };

    let mut skill_id = None;
    let mut min_version = None;
    let mut seen = [false; SKILL_DEPENDENCY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("dependency keys must be strings"));
        };
        let Some(index) = SKILL_DEPENDENCY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidSkillBody(
                "dependency key must be skillId|minVersion",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody("duplicate dependency key"));
        }
        seen[index] = true;
        match SKILL_DEPENDENCY_KEYS[index] {
            KEY_DEP_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    SKILL_ID_MAX_BYTES,
                    "dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DEP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        SKILL_VERSION_MAX_BYTES,
                        "dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from SKILL_DEPENDENCY_KEYS"),
        }
    }

    Ok(SkillDependency {
        skill_id: skill_id.ok_or(Error::InvalidSkillBody(
            "missing required dependency key skillId",
        ))?,
        min_version: min_version.ok_or(Error::InvalidSkillBody(
            "missing required dependency key minVersion",
        ))?,
    })
}

pub(crate) fn validate_skill_record_bytes(bytes: &[u8]) -> Result<()> {
    decode_skill_record(bytes).map(|_| ())
}

pub(crate) fn is_legacy_opaque_skill_body(bytes: &[u8]) -> bool {
    let mut cursor = bytes;
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return true;
    };
    !matches!(value, Value::Map(_))
}

pub(super) fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvalidSkillBody(context))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}
