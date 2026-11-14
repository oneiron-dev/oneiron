//! Moved from `crates/oneiron/src/consent/registry.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::RepoAccessBounds;
use oneiron_authority::federation::Scope;
use oneiron_authority::federation::ScopeAxis;
use oneiron_authority::federation::Sensitivity;
use oneiron_authority::federation::SensitivityCeiling;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::BoundEnvelope;
use oneiron_store::consent_bound::BoundSubject;

// ---------------------------------------------------------------------------
// The registry surface (invariant 9 surface (b))
// ---------------------------------------------------------------------------

/// Query for the unified consent registry — surface (b).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ConsentRegistryQuery {
    /// Maximum rows returned.
    pub limit: usize,
    /// Include revoked rows (audit view) as well as active ones.
    #[serde(default)]
    pub include_revoked: bool,
}

impl ConsentRegistryQuery {
    /// Builds a registry query.
    #[must_use]
    pub const fn new(limit: usize, include_revoked: bool) -> Self {
        Self {
            limit,
            include_revoked,
        }
    }
}

/// An owner's agent grant as the registry shows it (FIX 5628): the agent it
/// names, the owner who granted it, its expiry (absent: it stands until
/// revoked), the repo bounds he gave it (FIX 6894), the verb classes it
/// names beside its exact verbs (FIX 8735), the host wallet its funded work
/// draws on (FIX 7766) and whether its scope confers now. Its exact scope is
/// the row's `scope`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRegistryAgentGrant {
    /// The agent principal granted.
    pub agent: EntityId,
    /// The owner PERSON who granted it.
    pub delegated_by: EntityId,
    /// When it stops conferring (Unix seconds); absent: durable until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The one repo, its refs and its read and edit globs the owner gave
    /// the agent, as the mint answer shows them; absent on a general grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_bounds: Option<RepoAccessBounds>,
    /// The verb classes the owner named beside its exact verbs, each
    /// resolved when a door judges a verb; absent when it names none.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub verb_classes: std::collections::BTreeSet<String>,
    /// The host wallet the owner named for the work the grant funds; absent
    /// when it names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_ref: Option<oneiron_authority::federation::WalletRef>,
    /// The one owner working view, and its account, the grant edits alone
    /// (row 6 WORKING-VIEW-EDIT); absent on a grant bound to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_view_bounds: Option<oneiron_authority::federation::WorkingViewEditBounds>,
    /// Whether it confers now: unexpired, with `read` among its verbs (or
    /// admitted by a class it names) and no empty world, band, audience or
    /// sensitivity axis.
    pub confers: bool,
}

/// A support grant's delegation as the registry shows it (OF-606): why the
/// customer let support in, who approved it, the wall deadline it ends at
/// and whom the support credential may address (FIX 5059), with where the
/// grant stands now.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRegistryDelegation {
    pub purpose: String,
    pub ticket_ref: Option<String>,
    /// The approving owner PERSON (hex).
    pub approved_by: String,
    pub wall_expires_at: u64,
    pub status: crate::authority::support_grant::SupportGrantStatus,
    /// The support credential's effective comm reach (FIX 5059).
    pub comm: oneiron_authority::authority::CommReach,
}

/// The one-tap revoke command carried by every registry row.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRevokeAction {
    /// Pinned command name.
    pub command: String,
    /// The row this command revokes.
    pub grant_ref: String,
}

/// A pre-filled owner re-grant of a revoked connector witness-read grant.
/// Invoking it still runs the command's full owner-proof grant flow.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRegrantAction {
    /// Pinned command name.
    pub command: String,
    /// The stored agent principal, in the grant command's input shape.
    pub agent: String,
    /// The stored conversation, in the grant command's input shape.
    pub conversation: String,
}

/// Pinned one-tap revoke command for a consent registry row.
pub const CONSENT_REVOKE_COMMAND: &str = "vault.consent.revoke";

/// A live issued slip of a named agent that no Grant has ever named, as the
/// owner's registry lists it (FIX AGENT-GRANTLESS-VISIBLE; Engine RULING
/// GRANTLESS-SHAPE Q8 = A): an agent paired before the owner's Grants, or on
/// a link with no owner proof. No Grant stands behind it, so it has no Grant
/// id and no revoke. It leaves the list once a counted mint names its
/// holder.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct GrantlessAgentRow {
    /// The named agent's PERSON the slip names as its holder.
    pub holder: EntityId,
    /// The slip's id (64 hex).
    pub slip_ref: String,
    /// When its mint issued it (Unix seconds).
    pub issued_at: u64,
    /// When it stops (Unix seconds).
    pub expires_at: u64,
    /// The Scope its mint logged. A presented copy may carry narrower
    /// caveats its holder added.
    pub scope: Scope,
    /// The named secret and repository bounds it carries beside its Scope.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub records: std::collections::BTreeSet<String>,
    /// The credential-door effectors it names beside its Scope.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub channels: std::collections::BTreeSet<String>,
    /// Whom its holder may message; absent: the vault-wide reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<oneiron_authority::authority::CommReach>,
    /// The owner's conversion of this slip into its holder's default read
    /// Grants.
    pub convert_action: GrantlessAgentConvertAction,
}

/// The owner's conversion of a grantless slip and its argument.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct GrantlessAgentConvertAction {
    /// Pinned command name: `vault.agents.grants.from_slip`.
    pub command: String,
    /// The slip it converts (64 hex).
    pub slip_ref: String,
}

/// The class a support grant's registry row shows (OF-606).
pub const SUPPORT_GRANT_CLASS: &str = "support";

/// The class an owner's agent grant's registry row shows (FIX 5628).
pub const AGENT_GRANT_CLASS: &str = "agent_grant";

pub fn render_subject(subject: &BoundSubject) -> String {
    match subject {
        BoundSubject::Actor(actor) => match actor.actor_class() {
            Some(class) => format!("{}/{}", actor.actor_ref(), class),
            None => actor.actor_ref().to_owned(),
        },
        BoundSubject::Audience(audience) => audience.members().join(", "),
    }
}

pub fn render_selectors(envelope: &BoundEnvelope) -> Vec<String> {
    match envelope {
        BoundEnvelope::Disclosure(envelope) => match envelope.scope() {
            Some(scope) => render_scope(scope),
            None => envelope.selectors().to_vec(),
        },
        BoundEnvelope::Action(envelope) => {
            let mut selectors = envelope.selectors().to_vec();
            if let Some(target) = envelope.target() {
                selectors.push(format!("target:{target}"));
            }
            if let Some(budget) = envelope.budget() {
                selectors.push(format!("budget:{budget}"));
            }
            selectors
        }
    }
}

// Display only: the typed Scope above remains the authority and is available
// to hosts as structured data. Facets are deliberately omitted because they
// do not grant or deny disclosure.
pub fn render_scope(scope: &Scope) -> Vec<String> {
    vec![
        format!("worlds:{}", render_axis(&scope.worlds, |id| id.0.to_hex())),
        format!(
            "projects:{}",
            render_axis(&scope.audience, |id| id.0.to_hex())
        ),
        format!("bands:{}", render_axis(&scope.bands, ToString::to_string)),
        format!("verbs:{}", render_axis(&scope.verbs, Clone::clone)),
        format!(
            "sensitivity:{}",
            match scope.sensitivity {
                SensitivityCeiling::Bottom => "bottom",
                SensitivityCeiling::AtMost(Sensitivity::Public) => "public",
                SensitivityCeiling::AtMost(Sensitivity::Private) => "private",
                SensitivityCeiling::AtMost(Sensitivity::Sensitive) => "sensitive",
                SensitivityCeiling::AtMost(Sensitivity::Restricted) => "restricted",
            }
        ),
    ]
}

pub fn render_axis<T: Ord>(axis: &ScopeAxis<T>, display: impl Fn(&T) -> String) -> String {
    match axis {
        ScopeAxis::Bottom => "bottom".to_owned(),
        ScopeAxis::All => "*".to_owned(),
        ScopeAxis::Some(values) => values.iter().map(display).collect::<Vec<_>>().join(","),
    }
}
