//! One scoped grant row of a policy manifest, as the manifest fold decodes it.

use rmpv::Value;

/// One scoped grant row of a policy manifest: who it names, the effector it
/// covers, and the scope it reads under.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyScopedGrant {
    /// The actor class the grant names, if any.
    pub actor_class: Option<String>,
    /// The actor ref the grant names, if any.
    pub actor_ref: Option<String>,
    /// The effector the grant covers.
    pub effector: String,
    /// Purpose-specific selectors; these can only narrow `authority_scope`.
    pub scope: Option<Value>,
    /// The scope the grant reads under.
    pub authority_scope: oneiron_authority::federation::Scope,
    /// The grant's budget row, if any.
    pub budget: Option<Value>,
    /// Whether a read under the grant needs a receipt.
    pub receipt_required: bool,
}
