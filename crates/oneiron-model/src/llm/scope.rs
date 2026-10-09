//! Four-axis branch scope and exact readable/writable resource identities.
use oneiron_contracts::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeResource {
    Bucket {
        key: String,
    },
    DocumentVersion {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
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
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    pub world: Option<EntityId>,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    pub facet: Option<EntityId>,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    pub relationship: Option<EntityId>,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
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
