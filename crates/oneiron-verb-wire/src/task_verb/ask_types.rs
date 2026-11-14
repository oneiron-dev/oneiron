//! Moved from `crates/oneiron/src/task_verb/ask_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::task_ask_handle::TaskAskHandle;
pub use crate::disclosure::task_ask_default::TaskAskDefault;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Selects a scope, never its authority holders. Holders come from live grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AskAuthorityScopeWire", into = "AskAuthorityScopeWire")]
pub struct AskAuthorityScope {
    pub class: ActionClass,
    pub envelope: ActionEnvelope,
}

impl schemars::JsonSchema for AskAuthorityScope {
    fn schema_name() -> String {
        "AskAuthorityScope".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        AskAuthorityScopeWire::json_schema(generator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskGuest {
    pub companion_ref: EntityId,
    /// Reference to the person's live, owner-stamped standing disclosure grant.
    pub disclosure_grant_ref: String,
    /// The public key (64 hex) the guest generated on their own device for
    /// the companion's slip, when the ask's producer has it (FIX-LIST 1978):
    /// the guest grant keeps it, and the owner's slip mint binds it without
    /// asking the owner for it. Absent, the owner supplies one at the mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<String>,
}

/// One offered option: its display label and what happens if it is picked.
/// `then: None` means no consequence was stated, not a false action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskOption {
    pub label: String,
    pub then: Option<String>,
}

impl TaskAskOption {
    /// The option carrying `label` with no stated consequence.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            then: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskElectorate {
    #[default]
    Any,
    People(BTreeSet<EntityId>),
}

impl TaskAskElectorate {
    pub fn seats(&self, who: &BTreeSet<EntityId>) -> MemoryResult<BTreeSet<EntityId>> {
        let seats = match self {
            Self::Any => who.clone(),
            Self::People(people) => people.clone(),
        };
        if seats.is_empty() || !seats.is_subset(who) {
            return Err(MemoryError::bad_request(
                "ask electorate must be inside who",
            ));
        }
        Ok(seats)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskNeed {
    pub count: u16,
    #[serde(default)]
    pub of: TaskAskElectorate,
}

impl Default for TaskAskNeed {
    fn default() -> Self {
        Self {
            count: 1,
            of: TaskAskElectorate::Any,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskProvisional {
    #[default]
    Inform,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskBranch {
    #[default]
    Hold,
    Proceed,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSurface {
    #[default]
    Card,
    None,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskDisagree {
    pub branch: TaskAskBranch,
    pub surface: TaskAskSurface,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskAuthorityScopeWire {
    class: String,
    selectors: Vec<String>,
    target: Option<String>,
    budget: Option<u64>,
    receipt_required: bool,
}

impl TryFrom<AskAuthorityScopeWire> for AskAuthorityScope {
    type Error = oneiron_base::error::Error;

    fn try_from(wire: AskAuthorityScopeWire) -> oneiron_base::error::Result<Self> {
        let mut envelope = ActionEnvelope::new(wire.selectors)?;
        if let Some(target) = wire.target {
            envelope = envelope.with_target(target)?;
        }
        if let Some(budget) = wire.budget {
            envelope = envelope.with_budget(budget);
        }
        Ok(Self {
            class: ActionClass::new(wire.class)?,
            envelope: envelope.with_receipt_required(wire.receipt_required),
        })
    }
}

impl From<AskAuthorityScope> for AskAuthorityScopeWire {
    fn from(scope: AskAuthorityScope) -> Self {
        Self {
            class: scope.class.as_str().to_owned(),
            selectors: scope.envelope.selectors().to_vec(),
            target: scope.envelope.target().map(str::to_owned),
            budget: scope.envelope.budget(),
            receipt_required: scope.envelope.receipt_required(),
        }
    }
}
