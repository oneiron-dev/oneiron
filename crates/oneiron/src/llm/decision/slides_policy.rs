//! Manifest-backed operating limits for the artifact judgment adapter.
//!
//! A vault policy row and optional holder rows may only narrow the shipped
//! budget. The precedence is itself a row; neither a host nor a model may
//! widen a vault limit through a per-run request.

use super::DecisionRung;
use crate::EntityId;
use rmpv::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlideReviewLimits {
    pub batch_size: usize,
    pub max_units: usize,
    pub max_text_bytes: usize,
    pub max_image_bytes: usize,
}

impl Default for SlideReviewLimits {
    fn default() -> Self {
        Self {
            batch_size: 8,
            max_units: 4096,
            max_text_bytes: 1_048_576,
            max_image_bytes: 16 * 1024 * 1024,
        }
    }
}

impl SlideReviewLimits {
    pub fn valid(self) -> bool {
        let hard = Self::default();
        self.batch_size > 0
            && self.batch_size <= hard.batch_size
            && self.max_units > 0
            && self.max_units <= hard.max_units
            && self.max_text_bytes > 0
            && self.max_text_bytes <= hard.max_text_bytes
            && self.max_image_bytes > 0
            && self.max_image_bytes <= hard.max_image_bytes
    }
    #[must_use]
    pub fn restrict(self, other: Self) -> Self {
        Self {
            batch_size: self.batch_size.min(other.batch_size),
            max_units: self.max_units.min(other.max_units),
            max_text_bytes: self.max_text_bytes.min(other.max_text_bytes),
            max_image_bytes: self.max_image_bytes.min(other.max_image_bytes),
        }
    }
    fn decode(fields: &[(Value, Value)]) -> Option<Self> {
        let field = |key| {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .and_then(|(_, v)| v.as_u64())
                .and_then(|v| usize::try_from(v).ok())
        };
        let result = Self {
            batch_size: field("batch_size")?,
            max_units: field("max_units")?,
            max_text_bytes: field("max_text_bytes")?,
            max_image_bytes: field("max_image_bytes")?,
        };
        result.valid().then_some(result)
    }
    fn fields(self, scope: &str) -> Vec<(Value, Value)> {
        vec![
            ("scope".into(), scope.into()),
            ("batch_size".into(), (self.batch_size as u64).into()),
            ("max_units".into(), (self.max_units as u64).into()),
            ("max_text_bytes".into(), (self.max_text_bytes as u64).into()),
            (
                "max_image_bytes".into(),
                (self.max_image_bytes as u64).into(),
            ),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlideReviewPrecedence {
    NestedNarrowing,
    HolderOverrideCappedAtVault,
}

/// Owner route range; a holder may choose a narrower range, not widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlideReviewRoute {
    pub first: DecisionRung,
    pub ceiling: DecisionRung,
}

impl Default for SlideReviewRoute {
    fn default() -> Self {
        Self {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::Big,
        }
    }
}
impl SlideReviewRoute {
    fn valid(self) -> bool {
        self.first <= self.ceiling && self.ceiling <= DecisionRung::Big
    }
    fn restrict(self, other: Self) -> Option<Self> {
        let route = Self {
            first: self.first.max(other.first),
            ceiling: self.ceiling.min(other.ceiling),
        };
        route.valid().then_some(route)
    }
    fn rung(value: &str) -> Option<DecisionRung> {
        match value {
            "rule" => Some(DecisionRung::Rule),
            "local" => Some(DecisionRung::Local),
            "system_one" => Some(DecisionRung::SystemOne),
            "big" => Some(DecisionRung::Big),
            _ => None,
        }
    }
    fn name(value: DecisionRung) -> &'static str {
        match value {
            DecisionRung::Rule => "rule",
            DecisionRung::Local => "local",
            DecisionRung::SystemOne => "system_one",
            DecisionRung::Big => "big",
            DecisionRung::Human => "human",
        }
    }
    fn decode(fields: &[(Value, Value)]) -> Option<Self> {
        let field = |key| {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))?
                .1
                .as_str()
        };
        let route = Self {
            first: Self::rung(field("first")?)?,
            ceiling: Self::rung(field("ceiling")?)?,
        };
        route.valid().then_some(route)
    }
    fn fields(self, scope: &str) -> Vec<(Value, Value)> {
        vec![
            ("scope".into(), scope.into()),
            ("first".into(), Self::name(self.first).into()),
            ("ceiling".into(), Self::name(self.ceiling).into()),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlideReviewPolicy {
    pub precedence: SlideReviewPrecedence,
    vault: SlideReviewLimits,
    holders: BTreeMap<EntityId, SlideReviewLimits>,
    route: SlideReviewRoute,
    holder_routes: BTreeMap<EntityId, SlideReviewRoute>,
}

impl Default for SlideReviewPolicy {
    fn default() -> Self {
        Self {
            precedence: SlideReviewPrecedence::NestedNarrowing,
            vault: SlideReviewLimits::default(),
            holders: BTreeMap::new(),
            route: SlideReviewRoute::default(),
            holder_routes: BTreeMap::new(),
        }
    }
}

impl SlideReviewPolicy {
    /// Shipped manifest rows. Missing rows have this same conservative meaning.
    pub fn default_rows() -> Value {
        Self::default().rows()
    }

    /// Strictly decode behavior rows; an unknown value refuses the manifest.
    pub fn decode(value: &Value) -> Option<Self> {
        let Value::Array(rows) = value else {
            return None;
        };
        if rows.is_empty() || rows.len() > 1024 {
            return None;
        }
        let mut policy = Self::default();
        let mut precedence_seen = false;
        let mut vault_seen = false;
        let mut route_seen = false;
        for row in rows {
            let Value::Map(fields) = row else {
                return None;
            };
            let mut keys = std::collections::BTreeSet::new();
            for (key, _) in fields {
                if !keys.insert(key.as_str()?) {
                    return None;
                }
            }
            let get = |key| {
                fields
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .map(|(_, v)| v)
            };
            match get("scope")?.as_str()? {
                "precedence" => {
                    if precedence_seen || keys.len() != 2 {
                        return None;
                    }
                    precedence_seen = true;
                    policy.precedence = match get("value")?.as_str()? {
                        "nested_narrowing" => SlideReviewPrecedence::NestedNarrowing,
                        "holder_override_capped_at_vault" => {
                            SlideReviewPrecedence::HolderOverrideCappedAtVault
                        }
                        _ => return None,
                    };
                }
                "vault" => {
                    if vault_seen || keys.len() != 5 {
                        return None;
                    }
                    vault_seen = true;
                    policy.vault = SlideReviewLimits::decode(fields)?;
                }
                "route" => {
                    if route_seen || keys.len() != 3 {
                        return None;
                    }
                    route_seen = true;
                    policy.route = SlideReviewRoute::decode(fields)?;
                }
                "holder_route" => {
                    if keys.len() != 4 {
                        return None;
                    }
                    let text = get("holder")?.as_str()?;
                    let holder = EntityId::from_hex(text).ok()?;
                    if holder.to_hex() != text
                        || policy
                            .holder_routes
                            .insert(holder, SlideReviewRoute::decode(fields)?)
                            .is_some()
                    {
                        return None;
                    }
                }
                "holder" => {
                    if keys.len() != 6 {
                        return None;
                    }
                    let text = get("holder")?.as_str()?;
                    let holder = EntityId::from_hex(text).ok()?;
                    if holder.to_hex() != text
                        || policy
                            .holders
                            .insert(holder, SlideReviewLimits::decode(fields)?)
                            .is_some()
                    {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        (precedence_seen && vault_seen).then_some(policy)
    }

    /// Restrictive fold across trusted policy manifests; a holder's optional
    /// override cannot exceed either manifest's vault bound.
    pub fn restrict(&mut self, other: Self) -> bool {
        let Some(route) = self.route.restrict(other.route) else {
            return false;
        };
        self.route = route;
        if self
            .holder_routes
            .values()
            .any(|holder| self.route.restrict(*holder).is_none())
        {
            return false;
        }
        self.vault = self.vault.restrict(other.vault);
        for (holder, holder_route) in other.holder_routes {
            let route = match self.holder_routes.get(&holder) {
                Some(current) => match current.restrict(holder_route) {
                    Some(route) => route,
                    None => return false,
                },
                None => holder_route,
            };
            if self.route.restrict(route).is_none() {
                return false;
            }
            self.holder_routes.insert(holder, route);
        }
        for (holder, limits) in other.holders {
            self.holders
                .entry(holder)
                .and_modify(|current| *current = current.restrict(limits))
                .or_insert(limits);
        }
        if other.precedence == SlideReviewPrecedence::NestedNarrowing {
            self.precedence = SlideReviewPrecedence::NestedNarrowing;
        }
        true
    }

    #[must_use]
    pub fn resolve(&self, holder: EntityId) -> SlideReviewLimits {
        // Both permitted precedence modes cap holder choices at the vault.
        self.holders
            .get(&holder)
            .map_or(self.vault, |row| self.vault.restrict(*row))
    }

    /// The effective route is the intersection of the vault and holder rows.
    #[must_use]
    pub fn resolve_route(&self, holder: EntityId) -> SlideReviewRoute {
        self.holder_routes
            .get(&holder)
            .and_then(|route| self.route.restrict(*route))
            .unwrap_or(self.route)
    }

    /// Deterministic projection for the policy frontier and shipped default.
    pub fn rows(&self) -> Value {
        let mode = match self.precedence {
            SlideReviewPrecedence::NestedNarrowing => "nested_narrowing",
            SlideReviewPrecedence::HolderOverrideCappedAtVault => "holder_override_capped_at_vault",
        };
        let mut rows = vec![
            Value::Map(vec![
                ("scope".into(), "precedence".into()),
                ("value".into(), mode.into()),
            ]),
            Value::Map(self.vault.fields("vault")),
            Value::Map(self.route.fields("route")),
        ];
        for (holder, limits) in &self.holders {
            let mut fields = limits.fields("holder");
            fields.push(("holder".into(), holder.to_hex().into()));
            rows.push(Value::Map(fields));
        }
        for (holder, route) in &self.holder_routes {
            let mut fields = route.fields("holder_route");
            fields.push(("holder".into(), holder.to_hex().into()));
            rows.push(Value::Map(fields));
        }
        Value::Array(rows)
    }
}
