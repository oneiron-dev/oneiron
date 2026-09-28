//! Vault-resident confidence floors for carry-forward Auto admission.
//! Subtypes are fixed; the numbers and precedence are policy data.
use crate::entity_id::EntityId;
use crate::write_envelope::carry_forward::CarryForwardKind;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const KEY: &str = "carry_forward_confidence";
/// Shipped policy defaults. An authenticated vault row may change either value.
pub(crate) const DEFAULT_ORDINARY: f32 = 0.7;
pub(crate) const DEFAULT_CARE: f32 = 0.9;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Floors {
    pub(crate) ordinary: f32,
    pub(crate) care: f32,
}
impl Default for Floors {
    fn default() -> Self {
        Self {
            ordinary: 0.7,
            care: 0.9,
        }
    }
}
impl Floors {
    pub(crate) fn for_kind(self, kind: CarryForwardKind) -> f32 {
        match kind {
            CarryForwardKind::CareCheckIn => self.care,
            _ => self.ordinary,
        }
    }
    fn restrict(self, other: Self) -> Self {
        Self {
            ordinary: self.ordinary.max(other.ordinary),
            care: self.care.max(other.care),
        }
    }
    fn parse(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 2 {
            return None;
        }
        let mut ordinary = None;
        let mut care = None;
        for (key, value) in entries {
            let number = value.as_f64()? as f32;
            if !number.is_finite() || !(0.0..=1.0).contains(&number) {
                return None;
            }
            match key.as_str()? {
                "ordinary" if ordinary.replace(number).is_none() => {}
                "care" if care.replace(number).is_none() => {}
                _ => return None,
            }
        }
        let result = Self {
            ordinary: ordinary?,
            care: care?,
        };
        (result.care > result.ordinary).then_some(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Precedence {
    #[default]
    NestedNarrowing,
    HolderOverrideCapped,
}
impl Precedence {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_override_capped" => Some(Self::HolderOverrideCapped),
            _ => None,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::HolderOverrideCapped => "holder_override_capped",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HolderRow {
    pub(crate) actor: EntityId,
    pub(crate) parent: Option<EntityId>,
    pub(crate) floors: Floors,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct CarryForwardPolicy {
    pub(crate) vault: Floors,
    pub(crate) precedence: Precedence,
    pub(crate) holders: Vec<HolderRow>,
}
impl CarryForwardPolicy {
    /// Full optional manifest row. Absent fields use shipped defaults; malformed rows fail closed.
    pub(super) fn parse(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let mut policy = Self::default();
        let mut seen = BTreeSet::new();
        for (key, value) in entries {
            let key = key.as_str()?;
            if !seen.insert(key) {
                return None;
            }
            match key {
                "vault" => policy.vault = Floors::parse(value)?,
                "precedence" => policy.precedence = Precedence::parse(value)?,
                "holders" => {
                    let Value::Array(rows) = value else {
                        return None;
                    };
                    if rows.len() > 256 {
                        return None;
                    }
                    let mut actors = BTreeSet::new();
                    for row in rows {
                        let Value::Map(fields) = row else {
                            return None;
                        };
                        if fields.len() < 2 || fields.len() > 3 {
                            return None;
                        }
                        let mut actor = None;
                        let mut parent = None;
                        let mut floors = None;
                        let mut fields_seen = BTreeSet::new();
                        for (name, field) in fields {
                            let name = name.as_str()?;
                            if !fields_seen.insert(name) {
                                return None;
                            }
                            match name {
                                "actor_ref" => {
                                    actor = Some(EntityId::from_hex(field.as_str()?).ok()?);
                                }
                                "parent_ref" => {
                                    parent = Some(EntityId::from_hex(field.as_str()?).ok()?);
                                }
                                "floors" => floors = Some(Floors::parse(field)?),
                                _ => return None,
                            }
                        }
                        let actor = actor?;
                        if !actors.insert(actor) || parent == Some(actor) {
                            return None;
                        }
                        policy.holders.push(HolderRow {
                            actor,
                            parent,
                            floors: floors?,
                        });
                    }
                }
                _ => return None,
            }
        }
        policy.valid().then_some(policy)
    }
    fn valid(&self) -> bool {
        let rows: BTreeMap<_, _> = self.holders.iter().map(|row| (row.actor, row)).collect();
        self.holders.iter().all(|row| {
            let mut visited = BTreeSet::new();
            let mut cursor = row.parent;
            while let Some(parent) = cursor {
                if !visited.insert(parent) {
                    return false;
                }
                let Some(ancestor) = rows.get(&parent) else {
                    return false;
                };
                cursor = ancestor.parent;
            }
            true
        })
    }
    /// Trusted manifest rows can only narrow one another. Conflicting precedence is malformed.
    pub(crate) fn restrict(&mut self, other: Self) -> bool {
        if self.precedence != other.precedence {
            return false;
        }
        self.vault = self.vault.restrict(other.vault);
        for row in other.holders {
            if let Some(existing) = self
                .holders
                .iter_mut()
                .find(|candidate| candidate.actor == row.actor)
            {
                if existing.parent != row.parent {
                    return false;
                }
                existing.floors = existing.floors.restrict(row.floors);
            } else {
                self.holders.push(row);
            }
        }
        self.valid()
    }
    pub(crate) fn floor(&self, kind: CarryForwardKind, actor: Option<EntityId>) -> f32 {
        let mut floor = self.vault.for_kind(kind);
        let mut row = actor.and_then(|id| self.holders.iter().find(|row| row.actor == id));
        while let Some(holder) = row {
            floor = floor.max(holder.floors.for_kind(kind));
            row = match self.precedence {
                Precedence::NestedNarrowing => holder
                    .parent
                    .and_then(|parent| self.holders.iter().find(|row| row.actor == parent)),
                Precedence::HolderOverrideCapped => None,
            };
        }
        floor
    }
}
