//! Action manifest, typed `$state` schema and patch rules, card lifecycle, and the interactivity gate.

use super::GeneratedUiNode;
use crate::lens::atom::{FiniteF64, LensAtom, LensNode, LensText};
use crate::lens::self_ui::{SelfUiAction, SelfUiValue};
use crate::lens::validate::validate_lens_collection_len;
use crate::lens::wire_ids::{
    LensAtomId, LensRenderId, SelfUiActionId, SelfUiOptionValue, SelfUiStateKey,
};
use crate::lens::wire_limits::{deserialize_limited_vec, serialize_tagged};
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::{BTreeMap, HashMap, HashSet};

/// JSON-Pointer prefix that addresses the flattened `$state` snapshot. State keys
/// are lens tokens (ASCII alnum, `.`, `_`, `-`), so no pointer escaping is possible
/// and a `/values/` wrapper segment can never appear.
const GENERATED_UI_STATE_POINTER_PREFIX: &str = "/$state/";

/// Ruled interaction tiers (ONEIRON-ARCH-0048 G2). Deterministic and model tiers
/// yield triggers only; execution stays behind the host-stamped write chokepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiActionTier {
    Local,
    DeterministicTool,
    ModelRoundTrip,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiActionDeclaration {
    pub element_id: LensAtomId,
    pub action_id: SelfUiActionId,
    pub tier: GeneratedUiActionTier,
    pub action: SelfUiAction,
}

impl GeneratedUiActionDeclaration {
    pub(super) fn validate(&self) -> Result<()> {
        self.action.validate()?;
        if self.tier == GeneratedUiActionTier::Local
            && self
                .action
                .args
                .iter()
                .any(|arg| matches!(arg, SelfUiValue::Handle(_)))
        {
            return Err(Error::InvalidConfig(
                "generated-ui local actions must not declare host handle arguments".to_string(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GeneratedUiActionDeclaration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiActionDeclarationWire {
            element_id: LensAtomId,
            action_id: SelfUiActionId,
            tier: GeneratedUiActionTier,
            action: SelfUiAction,
        }

        let wire = GeneratedUiActionDeclarationWire::deserialize(deserializer)?;
        let declaration = Self {
            element_id: wire.element_id,
            action_id: wire.action_id,
            tier: wire.tier,
            action: wire.action,
        };
        declaration.validate().map_err(de::Error::custom)?;
        Ok(declaration)
    }
}

/// Client-authored interaction event. It names *what was touched* and nothing else:
/// no command, actor, source, approval, or authority field exists on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiActionEvent {
    pub card_id: LensRenderId,
    pub element_id: LensAtomId,
    pub action_id: SelfUiActionId,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub patch: Vec<GeneratedUiStatePatch>,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SelfUiStateValue {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
}

impl SelfUiStateValue {
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::Text(_) => "text",
            Self::Token(_) => "token",
        }
    }

    fn has_same_type(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Serialize for SelfUiStateValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool(value) => serialize_tagged(serializer, "type", "bool", "value", value),
            Self::Number(value) => serialize_tagged(serializer, "type", "number", "value", value),
            Self::Text(value) => serialize_tagged(serializer, "type", "text", "value", value),
            Self::Token(value) => serialize_tagged(serializer, "type", "token", "value", value),
        }
    }
}

/// The closed set of control properties a `$bind` descriptor may drive. There is no
/// expression language: a binding names one state key and one property, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUiBindableProperty {
    Checked,
    Selected,
    Value,
    Text,
}

impl SelfUiBindableProperty {
    fn accepts(self, value: &SelfUiStateValue) -> bool {
        match self {
            Self::Checked => matches!(value, SelfUiStateValue::Bool(_)),
            Self::Selected => matches!(value, SelfUiStateValue::Token(_)),
            Self::Text => matches!(value, SelfUiStateValue::Text(_)),
            Self::Value => matches!(
                value,
                SelfUiStateValue::Number(_) | SelfUiStateValue::Text(_)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfUiBinding {
    pub state_key: SelfUiStateKey,
    pub property: SelfUiBindableProperty,
}

/// Typed `$state` snapshot. The wire shape is the map itself — `{"$state":{"<key>":…}}`
/// — so `/$state/<key>` addresses an entry with no `values` wrapper segment.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GeneratedUiStateSnapshot {
    values: BTreeMap<SelfUiStateKey, SelfUiStateValue>,
}

impl GeneratedUiStateSnapshot {
    #[must_use]
    pub fn values(&self) -> &BTreeMap<SelfUiStateKey, SelfUiStateValue> {
        &self.values
    }

    #[must_use]
    pub fn get(&self, key: &SelfUiStateKey) -> Option<&SelfUiStateValue> {
        self.values.get(key)
    }
}

impl FromIterator<(SelfUiStateKey, SelfUiStateValue)> for GeneratedUiStateSnapshot {
    fn from_iter<I: IntoIterator<Item = (SelfUiStateKey, SelfUiStateValue)>>(iter: I) -> Self {
        Self {
            values: iter.into_iter().collect(),
        }
    }
}

impl Serialize for GeneratedUiStateSnapshot {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GeneratedUiStateSnapshot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<SelfUiStateKey, SelfUiStateValue>::deserialize(deserializer)?;
        validate_lens_collection_len("generated-ui $state entries", values.len())
            .map_err(de::Error::custom)?;
        Ok(Self { values })
    }
}

/// JSON-Pointer patch over `/$state/`. Paths are exact and never healed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiStatePatch {
    Add {
        path: String,
        value: SelfUiStateValue,
    },
    Replace {
        path: String,
        value: SelfUiStateValue,
    },
    Remove {
        path: String,
    },
}

impl GeneratedUiStatePatch {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Add { path, .. } | Self::Replace { path, .. } | Self::Remove { path } => path,
        }
    }
}

/// Canonical card lifecycle. `completed`/`expired` are archive *reasons*, not phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiCardPhase {
    Generating,
    Active,
    Responded,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiArchiveReason {
    Completed,
    Expired,
    Dismissed,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardLifecycle {
    pub phase: GeneratedUiCardPhase,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_reason: Option<GeneratedUiArchiveReason>,
}

impl GeneratedUiCardLifecycle {
    /// The phase a completed tree emits in `card_state_update`.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            phase: GeneratedUiCardPhase::Active,
            revision: 0,
            archive_reason: None,
        }
    }

    pub fn new(
        phase: GeneratedUiCardPhase,
        revision: u64,
        archive_reason: Option<GeneratedUiArchiveReason>,
    ) -> Result<Self> {
        let lifecycle = Self {
            phase,
            revision,
            archive_reason,
        };
        lifecycle.validate()?;
        Ok(lifecycle)
    }

    /// Advance the lifecycle. Phases are totally ordered, so this admits exactly the
    /// forward edges of `generating → active → responded → archived`, rejects
    /// backwards and self transitions, and makes `archived` terminal.
    pub fn transition(
        &self,
        next: GeneratedUiCardPhase,
        archive_reason: Option<GeneratedUiArchiveReason>,
    ) -> Result<Self> {
        if next <= self.phase {
            return Err(Error::InvalidConfig(format!(
                "generated-ui card lifecycle must advance: {:?} cannot become {next:?}",
                self.phase
            )));
        }
        let revision = self.revision.checked_add(1).ok_or_else(|| {
            Error::InvalidConfig("generated-ui card lifecycle revision overflowed".to_string())
        })?;
        Self::new(next, revision, archive_reason)
    }

    pub(super) fn validate(&self) -> Result<()> {
        match (self.phase, self.archive_reason) {
            (GeneratedUiCardPhase::Archived, None) => Err(Error::InvalidConfig(
                "generated-ui archived cards must carry an archive reason".to_string(),
            )),
            (phase, Some(_)) if phase != GeneratedUiCardPhase::Archived => {
                Err(Error::InvalidConfig(
                    "generated-ui archive reasons are only valid on archived cards".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCardLifecycle {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardLifecycleWire {
            phase: GeneratedUiCardPhase,
            revision: u64,
            #[serde(default)]
            archive_reason: Option<GeneratedUiArchiveReason>,
        }

        let wire = GeneratedUiCardLifecycleWire::deserialize(deserializer)?;
        Self::new(wire.phase, wire.revision, wire.archive_reason).map_err(de::Error::custom)
    }
}

/// One addressable element of a card, in either the authored tree or the lowered
/// flat render. Interactivity validation is shape-agnostic across the two.
pub(in crate::lens) struct LensElementRef<'a> {
    id: &'a LensAtomId,
    atom: &'a LensAtom,
    state_bindings: &'a [SelfUiBinding],
}

impl<'a> LensElementRef<'a> {
    pub(super) fn collect_tree(root: &'a LensNode) -> Vec<Self> {
        let mut elements = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            elements.push(Self {
                id: &node.id,
                atom: &node.atom,
                state_bindings: &node.state_bindings,
            });
            stack.extend(node.children.iter());
        }
        elements
    }

    pub(in crate::lens) fn collect_flat(nodes: &'a [GeneratedUiNode]) -> Vec<Self> {
        nodes
            .iter()
            .map(|node| Self {
                id: &node.id,
                atom: &node.atom,
                state_bindings: &node.state_bindings,
            })
            .collect()
    }
}

/// The single interactivity gate: every card, render, and reconstructed segment stream
/// proves its manifest and `$bind` descriptors against its own elements and `$state`.
pub(super) fn validate_generated_ui_interactivity(
    elements: &[LensElementRef<'_>],
    actions: &[GeneratedUiActionDeclaration],
    state: &GeneratedUiStateSnapshot,
) -> Result<()> {
    validate_lens_collection_len("generated-ui action declarations", actions.len())?;

    let by_id = elements
        .iter()
        .map(|element| (element.id.as_str(), element))
        .collect::<HashMap<_, _>>();

    let mut declared_actions = HashSet::with_capacity(actions.len());
    let mut declared_elements = HashSet::with_capacity(actions.len());
    for declaration in actions {
        declaration.validate()?;
        if !declared_actions.insert(declaration.action_id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui action ids must be declared exactly once".to_string(),
            ));
        }
        if !declared_elements.insert(declaration.element_id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui elements must declare at most one action".to_string(),
            ));
        }
        let element = by_id.get(declaration.element_id.as_str()).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui action declarations must reference a declared element".to_string(),
            )
        })?;
        let LensAtom::SelfUi(control) = element.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui action declarations must reference a self.ui control".to_string(),
            ));
        };
        if control.action() != &declaration.action {
            return Err(Error::InvalidConfig(
                "generated-ui element action must match its manifest declaration".to_string(),
            ));
        }
    }

    // A result set declares no action of its own; its action bar is an eligibility
    // allowlist over the manifest above. Membership is proved here so an undeclared,
    // local, or model-round-trip id can never reach a rendered action bar, and so one
    // id cannot be allowlisted by two different result sets in the same card.
    let mut allowlisted = HashSet::new();
    for element in elements {
        let Some(result_set) = element.atom.result_set_payload() else {
            continue;
        };
        result_set.validate_against_actions(actions)?;
        for action_id in &result_set.action_bar {
            if !allowlisted.insert(action_id.as_str()) {
                return Err(Error::InvalidConfig(
                    "generated-ui result set action ids must be allowlisted by at most one atom"
                        .to_string(),
                ));
            }
        }
    }

    validate_generated_ui_state_bindings(elements, state)
}

/// Prove every `$bind` descriptor against a `$state` snapshot. This runs at card
/// assembly *and* after every accepted patch, so the domain a control declares for
/// itself is the same domain a client patch has to land inside.
pub(in crate::lens) fn validate_generated_ui_state_bindings(
    elements: &[LensElementRef<'_>],
    state: &GeneratedUiStateSnapshot,
) -> Result<()> {
    for element in elements {
        validate_lens_collection_len(
            "generated-ui $bind descriptors",
            element.state_bindings.len(),
        )?;
        if element.state_bindings.is_empty() {
            continue;
        }
        let LensAtom::SelfUi(control) = element.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui $bind descriptors are only valid on self.ui controls".to_string(),
            ));
        };
        let mut bound_properties = HashSet::with_capacity(element.state_bindings.len());
        for binding in element.state_bindings {
            if !bound_properties.insert(binding.property) {
                return Err(Error::InvalidConfig(
                    "generated-ui $bind must bind each control property at most once".to_string(),
                ));
            }
            let value = state.get(&binding.state_key).ok_or_else(|| {
                Error::InvalidConfig(
                    "generated-ui $bind must reference a declared $state key".to_string(),
                )
            })?;
            if !binding.property.accepts(value) {
                return Err(Error::InvalidConfig(format!(
                    "generated-ui $bind property {:?} does not accept a {} value",
                    binding.property,
                    value.type_name()
                )));
            }
            control.accepts_bound_value(binding.property, value)?;
        }
    }

    Ok(())
}

/// Resolve `/$state/<key>` to its key. Exact match only — no healing, no nesting, and
/// no `/values/` segment can survive because state keys are lens tokens.
fn generated_ui_state_patch_key(path: &str) -> Result<SelfUiStateKey> {
    let key = path
        .strip_prefix(GENERATED_UI_STATE_POINTER_PREFIX)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "generated-ui state patch path must be an exact {GENERATED_UI_STATE_POINTER_PREFIX}<key> pointer"
            ))
        })?;
    SelfUiStateKey::new(key)
}

/// Apply a client patch to the current snapshot under the card's declared schema.
/// The declared snapshot is the closed key space *and* the type schema: undeclared
/// keys and type changes are rejected before any trigger is returned.
pub(in crate::lens) fn apply_generated_ui_state_patch(
    schema: &GeneratedUiStateSnapshot,
    current: &GeneratedUiStateSnapshot,
    patch: &[GeneratedUiStatePatch],
) -> Result<GeneratedUiStateSnapshot> {
    validate_lens_collection_len("generated-ui state patch", patch.len())?;

    for (key, value) in current.values() {
        let declared = schema.get(key).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui card state must not contain undeclared $state keys".to_string(),
            )
        })?;
        if !declared.has_same_type(value) {
            return Err(Error::InvalidConfig(
                "generated-ui card state must not change a declared $state type".to_string(),
            ));
        }
    }

    let mut next = current.clone();
    for op in patch {
        let key = generated_ui_state_patch_key(op.path())?;
        let declared = schema.get(&key).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui state patch must address a declared $state key".to_string(),
            )
        })?;
        if !matches!(op, GeneratedUiStatePatch::Add { .. }) && !next.values.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "generated-ui state patch must address a present $state key".to_string(),
            ));
        }
        match op {
            GeneratedUiStatePatch::Add { value, .. }
            | GeneratedUiStatePatch::Replace { value, .. } => {
                if !declared.has_same_type(value) {
                    return Err(Error::InvalidConfig(format!(
                        "generated-ui state patch must not change {} to {}",
                        declared.type_name(),
                        value.type_name()
                    )));
                }
                next.values.insert(key, value.clone());
            }
            GeneratedUiStatePatch::Remove { .. } => {
                next.values.remove(&key);
            }
        }
    }

    Ok(next)
}
