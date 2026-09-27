//! Four-axis branch scope and exact readable/writable resource identities.
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeResource {
    Bucket {
        key: String,
    },
    DocumentVersion {
        #[serde(with = "crate::serialize::entity_ref")]
        document: EntityId,
        version: String,
    },
    Projection {
        key: String,
    },
}

/// The scope itself rides the call envelope. Empty resource sets grant no
/// access; optional axes do not turn them into a wildcard permission.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(with = "crate::serialize::entity_ref::optional")]
    pub world: Option<EntityId>,
    #[serde(with = "crate::serialize::entity_ref::optional")]
    pub facet: Option<EntityId>,
    #[serde(with = "crate::serialize::entity_ref::optional")]
    pub relationship: Option<EntityId>,
    #[serde(with = "crate::serialize::entity_ref::optional")]
    pub project: Option<EntityId>,
    pub readable: BTreeSet<ScopeResource>,
    pub writable: BTreeSet<ScopeResource>,
}
impl Scope {
    pub fn allows_read(&self, resource: &ScopeResource) -> bool {
        self.readable.contains(resource)
    }
    pub fn allows_write(&self, resource: &ScopeResource) -> bool {
        self.writable.contains(resource)
    }
    /// A child branch names one subproject slice and can only remove resource
    /// rights or narrow an unconstrained axis. It cannot erase a parent axis.
    pub fn attenuate(&self, child: Self) -> Result<Self> {
        let axes = [
            (self.world, child.world),
            (self.facet, child.facet),
            (self.relationship, child.relationship),
            (self.project, child.project),
        ];
        if axes
            .into_iter()
            .any(|(parent, child)| parent.is_some() && parent != child)
            || !child.readable.is_subset(&self.readable)
            || !child.writable.is_subset(&self.writable)
        {
            return Err(Error::InvalidConfig(
                "branch scope cannot widen its parent".into(),
            ));
        }
        Ok(child)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four_axes_and_resource_sets_roundtrip_on_the_call_envelope() {
        let id = EntityId::now();
        let bucket = ScopeResource::Bucket {
            key: "subject:predicate".into(),
        };
        let document = ScopeResource::DocumentVersion {
            document: id,
            version: "sha256:revision".into(),
        };
        let projection = ScopeResource::Projection {
            key: "summary:revision".into(),
        };
        let scope = Scope {
            world: Some(id),
            facet: Some(id),
            relationship: Some(id),
            project: Some(id),
            readable: BTreeSet::from([bucket, document]),
            writable: BTreeSet::from([projection.clone()]),
        };
        let envelope = super::super::CallEnvelope {
            scope: scope.clone(),
            purpose: super::super::CallPurpose::Consolidation,
            class: super::super::CallClass::BestEffort,
            tier: super::super::TierPrecedence {
                per_seat: None,
                vault_policy: None,
                purpose_default: None,
                global_default: super::super::ModelTierRef("background".into()),
            },
            response_format: super::super::ResponseFormat::Text,
            locality: super::super::ModelLocality::OnDevice,
        };
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let decoded: super::super::CallEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.scope, scope);
        assert!(decoded.scope.allows_write(&projection));
        assert!(!decoded.scope.allows_read(&projection));
        let mut widened = scope.clone();
        widened.project = None;
        assert!(scope.attenuate(widened).is_err());
        let mut narrowed = scope.clone();
        narrowed.writable.clear();
        assert!(scope.attenuate(narrowed).is_ok());
    }
}
