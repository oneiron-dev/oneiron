//! Moved from `crates/oneiron/src/gate/owner_policy_mutation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The row's exact scope. A vault row has neither scope key on disk.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum PolicyRowScope {
    Vault,
    World(String),
    Project(String),
    WorldProject { world: String, project: String },
}

/// The allowed row actions, with the same spellings as the manifest decoder.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRowAction {
    Warn,
    Reword,
    Block,
    RouteToHelp,
}

impl PolicyRowAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Reword => "reword",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }
}

/// Provenance of optional explanatory text. Model-authored drafts are never
/// allowed to replace an owner's own reason.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyWhySource {
    Owner,
    Drafted,
}

impl PolicyWhySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Drafted => "drafted",
        }
    }
}

/// An exact-key edit: add refuses an occupied key, edit/remove refuse a missing key.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum PolicyRowChange {
    Add {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
    },
    Edit {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
    },
    Remove {
        row_ref: String,
        scope: PolicyRowScope,
    },
    /// An add/edit with an explicit owner reason in the same receipt.
    AddWithWhy {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
        why: String,
    },
    EditWithWhy {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
        why: String,
    },
    /// A model suggestion is explicitly marked and never outranks an owner reason.
    DraftWhy {
        row_ref: String,
        scope: PolicyRowScope,
        why: String,
    },
}

impl PolicyRowChange {
    /// Exact row reference targeted by this change.
    #[must_use]
    pub fn row_ref(&self) -> &str {
        target(self).0
    }

    /// Exact scope targeted by this change.
    #[must_use]
    pub fn scope(&self) -> &PolicyRowScope {
        target(self).1
    }
}

pub fn target(change: &PolicyRowChange) -> (&str, &PolicyRowScope) {
    match change {
        PolicyRowChange::Add { row_ref, scope, .. }
        | PolicyRowChange::Edit { row_ref, scope, .. }
        | PolicyRowChange::Remove { row_ref, scope }
        | PolicyRowChange::AddWithWhy { row_ref, scope, .. }
        | PolicyRowChange::EditWithWhy { row_ref, scope, .. }
        | PolicyRowChange::DraftWhy { row_ref, scope, .. } => (row_ref, scope),
    }
}
