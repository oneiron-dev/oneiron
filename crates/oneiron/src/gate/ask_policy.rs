//! Manifest-owned operating policy for cross-vault ask confirmation.
use crate::EntityId;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_GUEST_WIRE_REFS: u64 = 64;
const MAX_RETRY_PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AskPolicySurface {
    Card,
    None,
}
impl AskPolicySurface {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::None => "none",
        }
    }
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "card" => Some(Self::Card),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskPolicyPrecedence {
    NestedNarrowing,
    HolderCapped,
}
impl AskPolicyPrecedence {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_capped" => Some(Self::HolderCapped),
            _ => None,
        }
    }
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::HolderCapped => "holder_capped",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskHolderPolicy {
    pub(crate) guest_fact_limit: Option<u16>,
    pub(crate) retry_page_limit: Option<u16>,
    pub(crate) surface: Option<AskPolicySurface>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskOperationalPolicy {
    pub(crate) guest_fact_limit: u16,
    pub(crate) retry_page_limit: u16,
    pub(crate) default_surface: AskPolicySurface,
    pub(crate) allowed_surfaces: BTreeSet<AskPolicySurface>,
    pub(crate) precedence: AskPolicyPrecedence,
    pub(crate) holder_overrides: BTreeMap<EntityId, AskHolderPolicy>,
}
impl Default for AskOperationalPolicy {
    fn default() -> Self {
        Self {
            guest_fact_limit: 16,
            retry_page_limit: 64,
            default_surface: AskPolicySurface::Card,
            allowed_surfaces: BTreeSet::from([AskPolicySurface::Card, AskPolicySurface::None]),
            precedence: AskPolicyPrecedence::NestedNarrowing,
            holder_overrides: BTreeMap::new(),
        }
    }
}
impl AskOperationalPolicy {
    pub(crate) fn default_manifest_value() -> Value {
        Value::Map(vec![
            ("guest_fact_limit".into(), Value::from(16)),
            ("retry_page_limit".into(), Value::from(64)),
            ("default_surface".into(), "card".into()),
            (
                "allowed_surfaces".into(),
                Value::Array(vec!["card".into(), "none".into()]),
            ),
            ("precedence".into(), "nested_narrowing".into()),
            ("holder_overrides".into(), Value::Array(vec![])),
        ])
    }
    pub(crate) fn guest_limit_for(&self, holder: EntityId, class: Option<u16>) -> Option<usize> {
        if class.is_some_and(|limit| limit == 0 || limit > self.guest_fact_limit) {
            return None;
        }
        let override_limit = self
            .holder_overrides
            .get(&holder)
            .and_then(|row| row.guest_fact_limit);
        Some(usize::from(
            self.guest_fact_limit
                .min(class.unwrap_or(self.guest_fact_limit))
                .min(override_limit.unwrap_or(self.guest_fact_limit)),
        ))
    }
    pub(crate) fn retry_limit(&self, requested: usize) -> usize {
        requested.min(usize::from(self.retry_page_limit))
    }
    pub(crate) fn surface_for(
        &self,
        holder: EntityId,
        class: Option<AskPolicySurface>,
    ) -> Option<AskPolicySurface> {
        let holder_surface = self
            .holder_overrides
            .get(&holder)
            .and_then(|row| row.surface);
        let candidate = match self.precedence {
            AskPolicyPrecedence::NestedNarrowing => class.or(holder_surface),
            AskPolicyPrecedence::HolderCapped => holder_surface.or(class),
        }
        .unwrap_or(self.default_surface);
        self.allowed_surfaces
            .contains(&candidate)
            .then_some(candidate)
    }
    /// Restrictive fold across trusted packs. A differing precedence is
    /// ambiguous and invalid; every holder override remains under the vault cap.
    pub(crate) fn restrict(&mut self, other: &Self) -> Option<()> {
        if self.precedence != other.precedence {
            return None;
        }
        self.guest_fact_limit = self.guest_fact_limit.min(other.guest_fact_limit);
        self.retry_page_limit = self.retry_page_limit.min(other.retry_page_limit);
        self.allowed_surfaces = self
            .allowed_surfaces
            .intersection(&other.allowed_surfaces)
            .copied()
            .collect();
        if self.allowed_surfaces.is_empty() {
            return None;
        }
        self.default_surface = if self.allowed_surfaces.contains(&AskPolicySurface::Card)
            && (self.default_surface == AskPolicySurface::Card
                || other.default_surface == AskPolicySurface::Card)
        {
            AskPolicySurface::Card
        } else {
            *self.allowed_surfaces.iter().next()?
        };
        for (holder, row) in &other.holder_overrides {
            let existing = self
                .holder_overrides
                .entry(*holder)
                .or_insert_with(|| row.clone());
            existing.guest_fact_limit = Some(
                existing
                    .guest_fact_limit
                    .unwrap_or(self.guest_fact_limit)
                    .min(row.guest_fact_limit.unwrap_or(self.guest_fact_limit)),
            );
            existing.retry_page_limit = Some(
                existing
                    .retry_page_limit
                    .unwrap_or(self.retry_page_limit)
                    .min(row.retry_page_limit.unwrap_or(self.retry_page_limit)),
            );
            if existing.surface != row.surface
                && row.surface.is_some()
                && existing.surface.is_some()
            {
                return None;
            }
            existing.surface = existing.surface.or(row.surface);
        }
        for row in self.holder_overrides.values_mut() {
            row.guest_fact_limit = row.guest_fact_limit.map(|n| n.min(self.guest_fact_limit));
            row.retry_page_limit = row.retry_page_limit.map(|n| n.min(self.retry_page_limit));
            if row
                .surface
                .is_some_and(|surface| !self.allowed_surfaces.contains(&surface))
            {
                row.surface = None;
            }
        }
        Some(())
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let fields = map(
            value,
            &[
                "guest_fact_limit",
                "retry_page_limit",
                "default_surface",
                "allowed_surfaces",
                "precedence",
                "holder_overrides",
            ],
        )?;
        let guest_fact_limit = limit(fields[0]?, MAX_GUEST_WIRE_REFS)?;
        let retry_page_limit = limit(fields[1]?, MAX_RETRY_PAGE)?;
        let default_surface = AskPolicySurface::parse(fields[2]?)?;
        let Value::Array(surfaces) = fields[3]? else {
            return None;
        };
        let mut allowed_surfaces = BTreeSet::new();
        for surface in surfaces {
            if !allowed_surfaces.insert(AskPolicySurface::parse(surface)?) {
                return None;
            }
        }
        if allowed_surfaces.is_empty() || !allowed_surfaces.contains(&default_surface) {
            return None;
        }
        let precedence = AskPolicyPrecedence::parse(fields[4]?)?;
        let Value::Array(rows) = fields[5]? else {
            return None;
        };
        if rows.len() > 256 {
            return None;
        }
        let mut holder_overrides = BTreeMap::new();
        for row in rows {
            let cells = map(
                row,
                &[
                    "holder_ref",
                    "guest_fact_limit",
                    "retry_page_limit",
                    "surface",
                ],
            )?;
            let holder = EntityId::from_hex(cells[0]?.as_str()?).ok()?;
            if holder.to_hex() != cells[0]?.as_str()? {
                return None;
            }
            let guest = match cells[1] {
                Some(value) => Some(limit(value, u64::from(guest_fact_limit))?),
                None => None,
            };
            let retry = match cells[2] {
                Some(value) => Some(limit(value, u64::from(retry_page_limit))?),
                None => None,
            };
            let surface = match cells[3] {
                Some(value) => Some(AskPolicySurface::parse(value)?),
                None => None,
            };
            if surface.is_some_and(|s| !allowed_surfaces.contains(&s))
                || (guest.is_none() && retry.is_none() && surface.is_none())
            {
                return None;
            }
            if holder_overrides
                .insert(
                    holder,
                    AskHolderPolicy {
                        guest_fact_limit: guest,
                        retry_page_limit: retry,
                        surface,
                    },
                )
                .is_some()
            {
                return None;
            }
        }
        Some(Self {
            guest_fact_limit,
            retry_page_limit,
            default_surface,
            allowed_surfaces,
            precedence,
            holder_overrides,
        })
    }
}
fn limit(value: &Value, max: u64) -> Option<u16> {
    let n = value.as_u64()?;
    if n == 0 || n > max {
        return None;
    }
    u16::try_from(n).ok()
}
fn map<'a>(value: &'a Value, names: &[&str]) -> Option<Vec<Option<&'a Value>>> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut found = vec![None; names.len()];
    for (key, value) in entries {
        let index = names.iter().position(|name| Some(*name) == key.as_str())?;
        if found[index].replace(value).is_some() {
            return None;
        }
    }
    Some(found)
}
