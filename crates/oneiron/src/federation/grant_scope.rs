//! Scope authority shared by the purpose-specific stored grant envelopes.
use super::{Scope, ScopeAxis, ScopeId};
use std::collections::BTreeSet;
/// Old purpose-specific doors can prove a verb and base/default audience only.
/// A narrower content grant is evaluated by record-aware doors, never widened here.
pub(crate) fn admits_preset(scope: &Scope, verb: &str) -> bool {
    let mut record = Scope::top();
    record.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]));
    record.audience = ScopeAxis::Some(BTreeSet::from([
        ScopeId(crate::claim::default_project_id()),
    ]));
    record.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
    scope.admits(verb, &record, &Scope::top())
}

/// The verbs a Steward's grant can carry, and the shipped default gives it:
/// read and derive across its vault root, archive inside its grant, delete
/// in scope.
pub(crate) const STEWARD_VERBS: [&str; 4] = ["read", "derive", "archive", "delete"];

pub(crate) fn membership_preset(role: super::FederationGrantRole) -> Scope {
    match role {
        super::FederationGrantRole::Owner => Scope::top(),
        // The ADMIN ceiling is structural. Which named powers it starts with
        // is chosen by vault-resident manifest rows at the minting writer. A
        // Deputy holds Admin's powers; its delegated Owner powers are a
        // separate Grant.
        super::FederationGrantRole::Deputy | super::FederationGrantRole::Admin => Scope::top(),
        // The non-vault Delegate constructor keeps its historical narrow
        // ceiling; the vault minting writer resolves the policy row instead.
        super::FederationGrantRole::Delegate => super::scope_codec::read_preset(),
        // The Steward's ceiling (ARCH-0043, owner 9 Nov): read and derive
        // across the vault root, archive inside its grant, delete in scope.
        // It names no admin power and no `write`, so no vault or holder row
        // can raise a Steward to membership acts or general content writes.
        super::FederationGrantRole::Steward => {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(
                STEWARD_VERBS
                    .iter()
                    .map(|verb| (*verb).to_owned())
                    .collect(),
            );
            scope
        }
        super::FederationGrantRole::Member => {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
            scope
        }
        super::FederationGrantRole::Guest => Scope::default(),
        super::FederationGrantRole::Viewer => super::scope_codec::read_preset(),
    }
}
