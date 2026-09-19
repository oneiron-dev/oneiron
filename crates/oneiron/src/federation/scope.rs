//! One Scope: six-axis audience lattice with explicit bottom on every wire axis.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

/// Canonical entity id used by the world, facet, and project axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(pub EntityId);
impl Serialize for ScopeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_hex())
    }
}
impl<'de> Deserialize<'de> for ScopeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let id = EntityId::from_hex(&value).map_err(serde::de::Error::custom)?;
        if id.to_hex() != value {
            return Err(serde::de::Error::custom(
                "scope ids are canonical lower hex",
            ));
        }
        Ok(Self(id))
    }
}

/// Powerset axis. Empty sets normalize to bottom, never to all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", content = "values", rename_all = "snake_case")]
pub enum ScopeAxis<T: Ord> {
    #[default]
    Bottom,
    All,
    Some(BTreeSet<T>),
}
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum AxisWire<T: Ord> {
    Bottom,
    All,
    Some(BTreeSet<T>),
}
impl<'de, T: Ord + Deserialize<'de>> Deserialize<'de> for ScopeAxis<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Ok(match AxisWire::deserialize(deserializer)? {
            AxisWire::Bottom => Self::Bottom,
            AxisWire::All => Self::All,
            AxisWire::Some(values) if values.is_empty() => Self::Bottom,
            AxisWire::Some(values) => Self::Some(values),
        })
    }
}
impl<T: Ord + Clone> ScopeAxis<T> {
    #[must_use]
    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom) || matches!(self, Self::Some(values) if values.is_empty())
    }
    #[must_use]
    pub fn contains(&self, value: &T) -> bool {
        match self {
            Self::Bottom => false,
            Self::All => true,
            Self::Some(values) => values.contains(value),
        }
    }
    #[must_use]
    pub fn is_narrowing_of(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return true;
        }
        match (self, other) {
            (_, Self::All) => true,
            (Self::Some(a), Self::Some(b)) => a.is_subset(b),
            _ => false,
        }
    }
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::Bottom;
        }
        match (self, other) {
            (Self::All, rhs) => rhs.clone(),
            (lhs, Self::All) => lhs.clone(),
            (Self::Some(a), Self::Some(b)) => {
                let values: BTreeSet<_> = a.intersection(b).cloned().collect();
                if values.is_empty() {
                    Self::Bottom
                } else {
                    Self::Some(values)
                }
            }
            _ => Self::Bottom,
        }
    }
}

/// Content sensitivity. This is not criticality or a hardware assurance tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Private,
    Sensitive,
    Restricted,
}

impl Sensitivity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Sensitive => "sensitive",
            Self::Restricted => "restricted",
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            "sensitive" => Some(Self::Sensitive),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

/// A channel's maximum sensitivity; bottom permits no content, even public.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SensitivityCeiling {
    #[default]
    Bottom,
    AtMost(Sensitivity),
}
impl SensitivityCeiling {
    #[must_use]
    pub fn permits(self, band: Sensitivity) -> bool {
        matches!(self, Self::AtMost(max) if band <= max)
    }
    #[must_use]
    pub fn is_narrowing_of(self, other: Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (Self::AtMost(a), Self::AtMost(b)) => a <= b,
            _ => false,
        }
    }
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::AtMost(a), Self::AtMost(b)) => Self::AtMost(a.min(b)),
            _ => Self::Bottom,
        }
    }
}

/// Canonical six-axis Scope. Missing axes deny; callers select `top()` explicitly.
/// Kind bands contain type bytes, not ordinal storage ranges. Audience is project.
/// Verb values are class names, not individual tool names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scope {
    pub worlds: ScopeAxis<ScopeId>,
    pub facets: ScopeAxis<ScopeId>,
    pub bands: ScopeAxis<u8>,
    pub audience: ScopeAxis<ScopeId>,
    pub verbs: ScopeAxis<String>,
    pub sensitivity: SensitivityCeiling,
}
impl Scope {
    #[must_use]
    pub fn top() -> Self {
        Self {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
            audience: ScopeAxis::All,
            verbs: ScopeAxis::All,
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
        }
    }
    #[must_use]
    pub fn is_narrowing_of(&self, other: &Self) -> bool {
        self.worlds.is_narrowing_of(&other.worlds)
            && self.facets.is_narrowing_of(&other.facets)
            && self.bands.is_narrowing_of(&other.bands)
            && self.audience.is_narrowing_of(&other.audience)
            && self.verbs.is_narrowing_of(&other.verbs)
            && self.sensitivity.is_narrowing_of(other.sensitivity)
    }
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            worlds: self.worlds.meet(&other.worlds),
            facets: self.facets.meet(&other.facets),
            bands: self.bands.meet(&other.bands),
            audience: self.audience.meet(&other.audience),
            verbs: self.verbs.meet(&other.verbs),
            sensitivity: self.sensitivity.meet(other.sensitivity),
        }
    }
    /// All three conjuncts bind the caller's record, credential and channel.
    #[must_use]
    pub fn admits(&self, verb_class: &str, record: &Scope, channel: &Scope) -> bool {
        !record.worlds.is_bottom()
            && !record.bands.is_bottom()
            && !record.audience.is_bottom()
            && record.sensitivity != SensitivityCeiling::Bottom
            && self.verbs.contains(&verb_class.to_owned())
            && record.disclosure_narrows(self)
            && record.disclosure_narrows(channel)
    }
    // Facets are provenance/relevance masks, never capability boundaries.
    fn disclosure_narrows(&self, ceiling: &Self) -> bool {
        self.worlds.is_narrowing_of(&ceiling.worlds)
            && self.bands.is_narrowing_of(&ceiling.bands)
            && self.audience.is_narrowing_of(&ceiling.audience)
            && self.verbs.is_narrowing_of(&ceiling.verbs)
            && self.sensitivity.is_narrowing_of(ceiling.sensitivity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_scope_and_empty_axis_decode_to_bottom() {
        let scope: Scope = serde_json::from_str("{}").unwrap();
        assert_eq!(scope, Scope::default());
        let empty: ScopeAxis<ScopeId> =
            serde_json::from_str(r#"{"kind":"some","values":[]}"#).unwrap();
        assert_eq!(empty, ScopeAxis::Bottom);
        assert!(!scope.admits("read", &Scope::top(), &Scope::top()));
        assert!(serde_json::from_str::<Scope>(r#"{"worlds":null}"#).is_err());
    }
    #[test]
    fn six_axis_meet_and_narrowing_laws() {
        let top = Scope::top();
        let bottom = Scope::default();
        let one = ScopeId(EntityId::from_bytes([1; 16]).unwrap());
        let mut samples = vec![top.clone(), bottom];
        for axis in 0..6 {
            let mut scope = top.clone();
            match axis {
                0 => scope.worlds = ScopeAxis::Some(BTreeSet::from([one])),
                1 => scope.facets = ScopeAxis::Some(BTreeSet::from([one])),
                2 => scope.bands = ScopeAxis::Some(BTreeSet::from([4])),
                3 => scope.audience = ScopeAxis::Some(BTreeSet::from([one])),
                4 => scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".into()])),
                _ => scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private),
            }
            samples.push(scope);
        }
        for a in &samples {
            assert_eq!(&a.meet(a), a);
            assert!(a.is_narrowing_of(&top));
            let bytes = serde_json::to_vec(a).unwrap();
            assert_eq!(serde_json::from_slice::<Scope>(&bytes).unwrap(), *a);
            for b in &samples {
                assert_eq!(a.meet(b), b.meet(a));
                assert!(a.meet(b).is_narrowing_of(a));
                for c in &samples {
                    assert_eq!(a.meet(b).meet(c), a.meet(&b.meet(c)));
                }
            }
        }
    }
    #[test]
    fn disjoint_worlds_meet_at_bottom_not_base() {
        let a = ScopeAxis::Some(BTreeSet::from([ScopeId(
            EntityId::from_bytes([1; 16]).unwrap(),
        )]));
        let b = ScopeAxis::Some(BTreeSet::from([ScopeId(
            EntityId::from_bytes([2; 16]).unwrap(),
        )]));
        assert_eq!(a.meet(&b), ScopeAxis::Bottom);
    }
}
