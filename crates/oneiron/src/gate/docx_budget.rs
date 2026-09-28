//! Native DOCX archive workload policy. Policy lives in the vault; the
//! standalone document engine only consumes a data-only effective limit.

use oneiron_docedit::ArchiveLimits;
use rmpv::Value;

use crate::entity_id::EntityId;

use super::constants::POLICY_DOCX_ARCHIVE_LIMITS_KEY;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DocxArchivePolicy {
    pub(in crate::gate) vault: ArchiveLimits,
    pub(in crate::gate) holders: Vec<(EntityId, ArchiveLimits)>,
}

impl DocxArchivePolicy {
    /// Exact actor rows can only narrow their own vault row. Folding trusted
    /// manifests applies another field-wise minimum; no last-writer override.
    pub(super) fn for_holder(&self, actor: Option<EntityId>) -> ArchiveLimits {
        let mut limits = self.vault;
        for (holder, row) in &self.holders {
            if actor == Some(*holder) {
                limits = limits.narrow(*row);
            }
        }
        limits
    }
}

pub(super) fn default_entry() -> (Value, Value) {
    let limits = ArchiveLimits::DEFAULT;
    (
        Value::from(POLICY_DOCX_ARCHIVE_LIMITS_KEY),
        Value::Map(vec![
            (Value::from("vault"), limits_value(limits)),
            (Value::from("holders"), Value::Array(Vec::new())),
        ]),
    )
}

fn limits_value(limits: ArchiveLimits) -> Value {
    Value::Map(vec![
        (
            Value::from("max_entries"),
            Value::from(limits.max_entries as u64),
        ),
        (
            Value::from("max_part_bytes"),
            Value::from(limits.max_part_bytes),
        ),
        (
            Value::from("max_total_bytes"),
            Value::from(limits.max_total_bytes),
        ),
    ])
}

/// Strict nested row: absent dimensions inherit the containing ceiling.
/// Duplicate/unknown keys, zero or above-ceiling values reject the manifest.
fn parse_limits(value: &Value, ceiling: ArchiveLimits, partial: bool) -> Option<ArchiveLimits> {
    let Value::Map(entries) = value else {
        return None;
    };
    let (mut count, mut part, mut total) = (None, None, None);
    for (key, value) in entries {
        let slot = match key.as_str()? {
            "max_entries" => &mut count,
            "max_part_bytes" => &mut part,
            "max_total_bytes" => &mut total,
            _ => return None,
        };
        if slot.replace(value.as_u64()?).is_some() {
            return None;
        }
    }
    if !partial && (count.is_none() || part.is_none() || total.is_none()) {
        return None;
    }
    if partial && count.is_none() && part.is_none() && total.is_none() {
        return None;
    }
    let limits = ArchiveLimits {
        max_entries: usize::try_from(count.unwrap_or(ceiling.max_entries as u64)).ok()?,
        max_part_bytes: part.unwrap_or(ceiling.max_part_bytes),
        max_total_bytes: total.unwrap_or(ceiling.max_total_bytes),
    };
    (limits.is_valid()
        && limits.max_entries <= ceiling.max_entries
        && limits.max_part_bytes <= ceiling.max_part_bytes
        && limits.max_total_bytes <= ceiling.max_total_bytes)
        .then_some(limits)
}

pub(super) fn parse(value: &Value) -> Option<DocxArchivePolicy> {
    let Value::Map(entries) = value else {
        return None;
    };
    let (mut vault, mut holders) = (None, None);
    for (key, value) in entries {
        let slot = match key.as_str()? {
            "vault" => &mut vault,
            "holders" => &mut holders,
            _ => return None,
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    let vault = parse_limits(vault?, ArchiveLimits::DEFAULT, false)?;
    let mut parsed = Vec::new();
    if let Some(value) = holders {
        let Value::Array(rows) = value else {
            return None;
        };
        for row in rows {
            let Value::Map(entries) = row else {
                return None;
            };
            let (mut actor, mut fields) = (None, Vec::new());
            for (key, value) in entries {
                if key.as_str()? == "actor" {
                    if actor.replace(value.as_str()?).is_some() {
                        return None;
                    }
                } else {
                    fields.push((key.clone(), value.clone()));
                }
            }
            let actor_text = actor?;
            let actor = EntityId::from_hex(actor_text).ok()?;
            if actor.to_hex() != actor_text {
                return None;
            }
            let limits = parse_limits(&Value::Map(fields), vault, true)?;
            if parsed.iter().any(|(existing, _)| *existing == actor) {
                return None;
            }
            parsed.push((actor, limits));
        }
    }
    Some(DocxArchivePolicy {
        vault,
        holders: parsed,
    })
}
