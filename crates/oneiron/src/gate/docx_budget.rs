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
    /// Exact actor rows can only narrow their own vault row. Folding the
    /// selected trusted manifests (an owner's rows, else the shipped one)
    /// applies another field-wise minimum; no last-writer override.
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

/// Strict nested row. A vault row (`ceiling` None) is complete and bounded by
/// nothing shipped: the trusted owner's row replaces the default (FIX 8763).
/// A holder row is partial: absent dimensions inherit its vault row, and it
/// may only narrow it. Duplicate/unknown keys, zero, incoherent or
/// above-ceiling values reject the manifest. A count wider than this machine
/// holds is kept saturated: it is an observation, never a refusal.
fn parse_limits(
    value: &Value,
    ceiling: Option<ArchiveLimits>,
    partial: bool,
) -> Option<ArchiveLimits> {
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
    let inherited =
        |own: Option<u64>, field: fn(ArchiveLimits) -> u64| own.or_else(|| ceiling.map(field));
    let limits = ArchiveLimits {
        max_entries: usize::try_from(inherited(count, |row| row.max_entries as u64)?)
            .unwrap_or(usize::MAX),
        max_part_bytes: inherited(part, |row| row.max_part_bytes)?,
        max_total_bytes: inherited(total, |row| row.max_total_bytes)?,
    };
    (limits.is_valid()
        && ceiling.is_none_or(|ceiling| {
            limits.max_entries <= ceiling.max_entries
                && limits.max_part_bytes <= ceiling.max_part_bytes
                && limits.max_total_bytes <= ceiling.max_total_bytes
        }))
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
    let vault = parse_limits(vault?, None, false)?;
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
            let limits = parse_limits(&Value::Map(fields), Some(vault), true)?;
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
