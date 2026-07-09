use std::collections::HashSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::temporal::TimeRange;

pub const SKILL_RECORD_BODY_KEYS: [&str; 11] = [
    "skillId",
    "desc",
    "version",
    "approvalStatus",
    "lifecycleStatus",
    "source",
    "confidence",
    "generated",
    "humanAuthored",
    "dependencies",
    "provenance",
];
pub const SKILL_DEPENDENCY_KEYS: [&str; 2] = ["skillId", "minVersion"];

pub const SKILL_ID_MAX_BYTES: usize = 256;
pub const SKILL_VERSION_MAX_BYTES: usize = 128;
pub const SKILL_DESC_MAX_BYTES: usize = 4096;
pub const SKILL_MAX_DEPENDENCIES: usize = 64;

const KEY_SKILL_ID: &str = SKILL_RECORD_BODY_KEYS[0];
const KEY_DESC: &str = SKILL_RECORD_BODY_KEYS[1];
const KEY_VERSION: &str = SKILL_RECORD_BODY_KEYS[2];
const KEY_APPROVAL_STATUS: &str = SKILL_RECORD_BODY_KEYS[3];
const KEY_LIFECYCLE_STATUS: &str = SKILL_RECORD_BODY_KEYS[4];
const KEY_SOURCE: &str = SKILL_RECORD_BODY_KEYS[5];
const KEY_CONFIDENCE: &str = SKILL_RECORD_BODY_KEYS[6];
const KEY_GENERATED: &str = SKILL_RECORD_BODY_KEYS[7];
const KEY_HUMAN_AUTHORED: &str = SKILL_RECORD_BODY_KEYS[8];
const KEY_DEPENDENCIES: &str = SKILL_RECORD_BODY_KEYS[9];
const KEY_PROVENANCE: &str = SKILL_RECORD_BODY_KEYS[10];

const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];
const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

impl SkillDependency {
    #[must_use]
    pub fn new(skill_id: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(skill_id: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: Some(min_version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SkillRecord {
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: ClaimLifecycleStatus,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillDependency>,
    pub provenance: Value,
}

impl SkillRecord {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors the pinned SKILL record fields"
    )]
    #[must_use]
    pub fn new(
        skill_id: impl Into<String>,
        desc: impl Into<String>,
        version: impl Into<String>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: ClaimLifecycleStatus,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        dependencies: Vec<SkillDependency>,
        provenance: Value,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            desc: desc.into(),
            version: version.into(),
            approval_status,
            lifecycle_status,
            source,
            confidence,
            generated,
            human_authored,
            dependencies,
            provenance,
        }
    }
}

pub fn encode_skill_record(record: &SkillRecord) -> Result<Vec<u8>> {
    validate_skill_record(record)?;
    let value = Value::Map(vec![
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
    ]);
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

pub(crate) fn validate_skill_update(prior: &SkillRecord, updated: &SkillRecord) -> Result<()> {
    validate_skill_record(updated)?;
    if prior == updated {
        return Ok(());
    }
    if prior.skill_id != updated.skill_id {
        return Err(Error::InvalidSkillBody("skillId cannot change on update"));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::InvalidSkillBody(
            "authorship flags cannot change on update",
        ));
    }
    if prior.source != updated.source {
        return Err(Error::InvalidSkillBody("source cannot change on update"));
    }
    if prior.version == updated.version {
        return Err(Error::InvalidSkillBody(
            "version must change when updating skill body",
        ));
    }
    Ok(())
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
                lifecycle_status =
                    Some(value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                        Error::InvalidSkillBody(
                            "lifecycleStatus must be one of active|superseded|retracted",
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

fn validate_skill_record(record: &SkillRecord) -> Result<()> {
    validate_text_field(
        &record.skill_id,
        SKILL_ID_MAX_BYTES,
        "skillId must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    validate_text_field(
        &record.desc,
        SKILL_DESC_MAX_BYTES,
        "desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text_field(
        &record.version,
        SKILL_VERSION_MAX_BYTES,
        "version must be a non-empty UTF-8 string at most 128 bytes",
    )?;
    if !record.confidence.is_finite() || !(0.0..=1.0).contains(&record.confidence) {
        return Err(Error::InvalidSkillBody(
            "confidence must be finite in [0, 1]",
        ));
    }
    if record.generated == record.human_authored {
        return Err(Error::InvalidSkillBody(
            "exactly one of generated or humanAuthored must be true",
        ));
    }
    if record.generated != (record.source == ClaimSource::Generated) {
        return Err(Error::InvalidSkillBody(
            "generated flag must match generated source",
        ));
    }
    validate_provenance(&record.provenance)?;
    validate_dependencies(&record.skill_id, &record.dependencies)?;
    Ok(())
}

fn validate_provenance(provenance: &Value) -> Result<()> {
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    };
    if entries.is_empty() {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    }
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("provenance keys must be strings"));
        };
        if key.trim().is_empty() {
            return Err(Error::InvalidSkillBody(
                "provenance keys must be non-empty strings",
            ));
        }
        if !seen.insert(key) {
            return Err(Error::InvalidSkillBody("duplicate provenance key"));
        }
    }
    Ok(())
}

fn validate_dependencies(skill_id: &str, dependencies: &[SkillDependency]) -> Result<()> {
    if dependencies.len() > SKILL_MAX_DEPENDENCIES {
        return Err(Error::InvalidSkillBody(
            "dependencies must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for dependency in dependencies {
        validate_text_field(
            &dependency.skill_id,
            SKILL_ID_MAX_BYTES,
            "dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if dependency.skill_id == skill_id {
            return Err(Error::InvalidSkillBody("skill must not depend on itself"));
        }
        if !seen.insert(dependency.skill_id.as_str()) {
            return Err(Error::InvalidSkillBody("duplicate skill dependency"));
        }
        if let Some(min_version) = &dependency.min_version {
            validate_text_field(
                min_version,
                SKILL_VERSION_MAX_BYTES,
                "dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvalidSkillBody(context))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

impl Vault {
    pub fn put_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        self.put_entity(id, ENTITY_TYPE_SKILL, occurred, learned_at, &data)
    }

    pub fn update_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_skill_record_in_txn(&wtxn, id)?;
        validate_skill_update(&existing, record)?;
        self.apply_skill_record_body(&mut wtxn, id, occurred, learned_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_skill_record(&self, id: &EntityId) -> Result<Option<SkillRecord>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn read_skill_record_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<SkillRecord> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_skill_record_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}

#[cfg(test)]
mod tests;
