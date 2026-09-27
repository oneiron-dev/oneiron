//! Manifest-owned room working-set policy with restrictive composition.
use crate::EntityId;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoomThreadFill {
    Recency,
    NudgeDue,
    Stage,
}
impl RoomThreadFill {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Recency => "recency",
            Self::NudgeDue => "nudge_due",
            Self::Stage => "stage",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoomThreadSettings {
    pub(crate) fresh_for: u64,
    pub(crate) rows_per_list: usize,
    pub(crate) tokens_per_list: usize,
    pub(crate) fill: RoomThreadFill,
    pub(crate) waits_per_thread: usize,
}
impl Default for RoomThreadSettings {
    fn default() -> Self {
        Self {
            fresh_for: 7 * 86_400,
            rows_per_list: 8,
            tokens_per_list: 512,
            fill: RoomThreadFill::Stage,
            waits_per_thread: 8,
        }
    }
}
impl RoomThreadSettings {
    pub(crate) fn restrict(self, other: Self) -> Self {
        Self {
            fresh_for: self.fresh_for.min(other.fresh_for),
            rows_per_list: self.rows_per_list.min(other.rows_per_list),
            tokens_per_list: self.tokens_per_list.min(other.tokens_per_list),
            // Fill orders are alternatives, not an authority lattice. The
            // selected child/holder row names its rank explicitly.
            fill: other.fill,
            waits_per_thread: self.waits_per_thread.min(other.waits_per_thread),
        }
    }
    pub(crate) fn capped(mut self, ceiling: Self) -> Self {
        self.fresh_for = self.fresh_for.min(ceiling.fresh_for);
        self.rows_per_list = self.rows_per_list.min(ceiling.rows_per_list);
        self.tokens_per_list = self.tokens_per_list.min(ceiling.tokens_per_list);
        self.waits_per_thread = self.waits_per_thread.min(ceiling.waits_per_thread);
        self
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if entries.len() != 5 {
            return None;
        }
        let get = |name: &str| {
            let mut fields = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
            let value = &fields.next()?.1;
            fields.next().is_none().then_some(value)
        };
        let fresh_for = get("fresh_for_secs")?.as_u64()?;
        let rows_per_list = usize::try_from(get("rows_per_list")?.as_u64()?).ok()?;
        let tokens_per_list = usize::try_from(get("tokens_per_list")?.as_u64()?).ok()?;
        let waits_per_thread = usize::try_from(get("waits_per_thread")?.as_u64()?).ok()?;
        let fill = match get("fill")?.as_str()? {
            "recency" => RoomThreadFill::Recency,
            "nudge_due" => RoomThreadFill::NudgeDue,
            "stage" => RoomThreadFill::Stage,
            _ => return None,
        };
        if rows_per_list == 0
            || rows_per_list > 100_000
            || tokens_per_list == 0
            || tokens_per_list > 1_000_000
            || waits_per_thread == 0
            || waits_per_thread > 100_000
            || entries.iter().any(|(key, _)| {
                !matches!(
                    key.as_str(),
                    Some(
                        "fresh_for_secs"
                            | "rows_per_list"
                            | "tokens_per_list"
                            | "fill"
                            | "waits_per_thread"
                    )
                )
            })
        {
            return None;
        }
        Some(Self {
            fresh_for,
            rows_per_list,
            tokens_per_list,
            fill,
            waits_per_thread,
        })
    }
}

/// Manifest chooses how child and holder rows compose. A category like fill
/// cannot be ordered by its enum discriminant; specificity chooses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoomPrecedence {
    NestedNarrowing,
    HolderOverride,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomThreadManifest {
    base: RoomThreadSettings,
    vault_ceiling: RoomThreadSettings,
    precedence: RoomPrecedence,
    allowed_fills: BTreeSet<RoomThreadFill>,
    holders: BTreeMap<EntityId, RoomThreadSettings>,
}
impl Default for RoomThreadManifest {
    fn default() -> Self {
        Self {
            base: RoomThreadSettings::default(),
            vault_ceiling: RoomThreadSettings {
                fresh_for: 30 * 86_400,
                rows_per_list: 1_000,
                tokens_per_list: 65_536,
                waits_per_thread: 128,
                ..Default::default()
            },
            precedence: RoomPrecedence::NestedNarrowing,
            allowed_fills: BTreeSet::from([
                RoomThreadFill::Recency,
                RoomThreadFill::NudgeDue,
                RoomThreadFill::Stage,
            ]),
            holders: BTreeMap::new(),
        }
    }
}
fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut rows = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
    let row = &rows.next()?.1;
    rows.next().is_none().then_some(row)
}
impl RoomThreadManifest {
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if entries.len() != 5
            || entries.iter().any(|(key, _)| {
                !matches!(
                    key.as_str(),
                    Some("base" | "vault_ceiling" | "precedence" | "holder_rows" | "allowed_fills")
                )
            })
        {
            return None;
        }
        let base = RoomThreadSettings::decode(field(entries, "base")?)?;
        let vault_ceiling = RoomThreadSettings::decode(field(entries, "vault_ceiling")?)?;
        let precedence = match field(entries, "precedence")?.as_str()? {
            "nested_narrowing" => RoomPrecedence::NestedNarrowing,
            "holder_override" => RoomPrecedence::HolderOverride,
            _ => return None,
        };
        let fills = field(entries, "allowed_fills")?.as_array()?;
        let mut allowed_fills = BTreeSet::new();
        for fill in fills {
            let fill = match fill.as_str()? {
                "recency" => RoomThreadFill::Recency,
                "nudge_due" => RoomThreadFill::NudgeDue,
                "stage" => RoomThreadFill::Stage,
                _ => return None,
            };
            if !allowed_fills.insert(fill) {
                return None;
            }
        }
        if allowed_fills.is_empty() || !allowed_fills.contains(&base.fill) {
            return None;
        }
        let mut holders = BTreeMap::new();
        let rows = field(entries, "holder_rows")?.as_array()?;
        if rows.len() > 1_000 {
            return None;
        }
        for entry in rows {
            let fields = entry.as_map()?;
            if fields.len() != 2
                || fields
                    .iter()
                    .any(|(key, _)| !matches!(key.as_str(), Some("actor_ref" | "settings")))
            {
                return None;
            }
            let id = EntityId::from_hex(field(fields, "actor_ref")?.as_str()?).ok()?;
            let settings = RoomThreadSettings::decode(field(fields, "settings")?)?;
            if !allowed_fills.contains(&settings.fill) || holders.insert(id, settings).is_some() {
                return None;
            }
        }
        Some(Self {
            base,
            vault_ceiling,
            precedence,
            allowed_fills,
            holders,
        })
    }
    /// Multiple trusted packs narrow numerics and the set of allowed fills.
    /// Conflicting precedence is not silently resolved by scan order.
    pub(crate) fn restrict(mut self, other: Self) -> Option<Self> {
        if self.precedence != other.precedence {
            return None;
        }
        self.base = self.base.restrict(other.base);
        self.vault_ceiling = self.vault_ceiling.restrict(other.vault_ceiling);
        self.allowed_fills = self
            .allowed_fills
            .intersection(&other.allowed_fills)
            .copied()
            .collect();
        if !self.allowed_fills.contains(&self.base.fill) {
            return None;
        }
        for (actor, settings) in other.holders {
            self.holders
                .entry(actor)
                .and_modify(|current| *current = current.restrict(settings))
                .or_insert(settings);
        }
        self.holders
            .values()
            .all(|row| self.allowed_fills.contains(&row.fill))
            .then_some(self)
    }
    pub(crate) fn effective(&self, actor: EntityId) -> RoomThreadSettings {
        let base = self.base.capped(self.vault_ceiling);
        let Some(holder) = self.holders.get(&actor) else {
            return base;
        };
        match self.precedence {
            RoomPrecedence::NestedNarrowing => base.restrict(*holder).capped(self.vault_ceiling),
            RoomPrecedence::HolderOverride => holder.capped(self.vault_ceiling),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_decode_is_closed_and_child_settings_narrow() {
        let row = |fresh, rows, tokens, fill| {
            Value::Map(vec![
                (Value::from("fresh_for_secs"), Value::from(fresh)),
                (Value::from("rows_per_list"), Value::from(rows)),
                (Value::from("tokens_per_list"), Value::from(tokens)),
                (Value::from("fill"), Value::from(fill)),
                (Value::from("waits_per_thread"), Value::from(8)),
            ])
        };
        let parent = RoomThreadSettings::decode(&row(100, 8, 512, "stage")).unwrap();
        let child = RoomThreadSettings::decode(&row(20, 2, 128, "recency")).unwrap();
        let folded = parent.restrict(child);
        assert_eq!(folded, child);
        assert_eq!(child.restrict(parent).fresh_for, child.fresh_for);
        assert_eq!(child.restrict(parent).fill, parent.fill);
        let mut duplicate = row(20, 2, 128, "recency");
        if let Value::Map(fields) = &mut duplicate {
            fields.push((Value::from("fill"), Value::from("stage")));
        }
        assert!(RoomThreadSettings::decode(&duplicate).is_none());
        assert!(RoomThreadSettings::decode(&row(20, 0, 128, "stage")).is_none());
        assert!(RoomThreadSettings::decode(&row(20, 2, 128, "unknown")).is_none());
    }
}

#[cfg(test)]
mod precedence_tests {
    use super::*;
    #[test]
    fn trusted_owner_and_holder_select_precedence_with_vault_ceiling() {
        let actor = EntityId::from_bytes([0xA1; 16]).unwrap();
        let settings = |fresh, rows, fill| {
            Value::Map(vec![
                (Value::from("fresh_for_secs"), Value::from(fresh)),
                (Value::from("rows_per_list"), Value::from(rows)),
                (Value::from("tokens_per_list"), Value::from(512)),
                (Value::from("waits_per_thread"), Value::from(8)),
                (Value::from("fill"), Value::from(fill)),
            ])
        };
        let manifest = |precedence| {
            Value::Map(vec![
                (Value::from("base"), settings(7 * 86_400, 8, "stage")),
                (
                    Value::from("vault_ceiling"),
                    settings(21 * 86_400, 16, "stage"),
                ),
                (Value::from("precedence"), Value::from(precedence)),
                (
                    Value::from("allowed_fills"),
                    Value::Array(vec![Value::from("stage"), Value::from("recency")]),
                ),
                (
                    Value::from("holder_rows"),
                    Value::Array(vec![Value::Map(vec![
                        (Value::from("actor_ref"), Value::from(actor.to_hex())),
                        (
                            Value::from("settings"),
                            settings(30 * 86_400, 20, "recency"),
                        ),
                    ])]),
                ),
            ])
        };
        let nested = RoomThreadManifest::decode(&manifest("nested_narrowing")).unwrap();
        assert_eq!(nested.effective(actor).fresh_for, 7 * 86_400);
        assert_eq!(nested.effective(actor).rows_per_list, 8);
        assert_eq!(nested.effective(actor).fill, RoomThreadFill::Recency);
        let override_row = RoomThreadManifest::decode(&manifest("holder_override")).unwrap();
        assert_eq!(override_row.effective(actor).fresh_for, 21 * 86_400);
        assert_eq!(override_row.effective(actor).rows_per_list, 16);
        assert_eq!(override_row.effective(actor).fill, RoomThreadFill::Recency);
        assert!(nested.restrict(override_row).is_none());
        let owner = RoomThreadManifest::decode(&manifest("nested_narrowing")).unwrap();
        let mut child = owner.clone();
        child.base.fresh_for = 2 * 86_400;
        child.vault_ceiling.fresh_for = 10 * 86_400;
        let folded = owner.restrict(child).unwrap();
        assert_eq!(folded.effective(actor).fresh_for, 2 * 86_400);
        assert_eq!(
            folded
                .effective(EntityId::from_bytes([0xA2; 16]).unwrap())
                .fresh_for,
            2 * 86_400
        );
        assert_eq!(
            RoomThreadSettings::decode(&settings(14 * 86_400, 8, "stage"))
                .unwrap()
                .fresh_for,
            14 * 86_400
        );
    }
}
