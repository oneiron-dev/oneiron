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

pub(crate) fn membership_preset(role: super::FederationGrantRole) -> Scope {
    match role {
        super::FederationGrantRole::Owner | super::FederationGrantRole::Admin => Scope::top(),
        super::FederationGrantRole::Member => {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
            scope
        }
        _ => super::scope_codec::read_preset(),
    }
}
