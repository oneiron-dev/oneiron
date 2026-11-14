//! Moved from `crates/oneiron/src/verbs/root_requests.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::RootChange;
use serde::Deserialize;
use serde::Serialize;

/// `vault.roots.requests.cancel`'s input: the root request to cancel, as
/// the route's body names it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootRequestCancelRequest {
    /// The request's signed authority-log entry, 64 lower-case hex: its
    /// receipt's `request`.
    pub request: String,
}

/// `vault.roots.requests.create`'s input: the root change the owner decides
/// for one install, as `POST /v1/owner/roots/requests` names it. Ids only.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootRequestCreateRequest {
    /// The install that is to make the change, 32 hex.
    pub target: String,
    /// `pin`, `activate`, `restore` or `anchor`.
    pub change: String,
    /// The root the change binds, 64 lower-case hex: every change but
    /// `activate`.
    #[serde(default)]
    pub root: Option<String>,
    /// The machine an `anchor` marks, 32 hex.
    #[serde(default)]
    pub machine: Option<String>,
}

/// One root change as a surface shows it: its kind, and the ids it binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootChangeView {
    /// `pin`, `activate`, `restore` or `anchor`.
    pub change: String,
    /// The root it binds, 64 lower-case hex; `None` for `activate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// The machine an `anchor` marks, 32 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

impl From<RootChange> for RootChangeView {
    fn from(change: RootChange) -> Self {
        let machine = match change {
            RootChange::Anchor { machine, .. } => Some(machine.to_hex()),
            RootChange::Pin { .. } | RootChange::Activate | RootChange::Restore { .. } => None,
        };
        Self {
            change: change.as_str().to_owned(),
            root: change
                .root()
                .map(|root| oneiron_contracts::entity_id::bytes_to_hex_lower(&root.0)),
            machine,
        }
    }
}

/// `vault.owner_work.get`'s input: one owner work request, by its signed
/// authority-log entry.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerWorkGetRequest {
    /// The request's entry, 64 lower-case hex: its receipt's `request`.
    pub request: String,
}
