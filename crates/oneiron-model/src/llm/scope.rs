//! Four-axis branch scope and exact readable/writable resource identities.
use oneiron_contracts::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeResource {
    Bucket {
        key: String,
    },
    DocumentVersion {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        document: EntityId,
        version: String,
    },
    Projection {
        key: String,
    },
}

/// The scope itself rides the call envelope. Empty resource sets grant no
/// access; optional axes do not turn them into a wildcard permission.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
    pub world: Option<EntityId>,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
    pub facet: Option<EntityId>,
    /// The relationship exposure the branch may serve: `None` is unbound,
    /// `Some(empty)` the explicit empty set, otherwise exactly these
    /// relationships.
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional_set")]
    #[schemars(with = "Option<Vec<String>>")]
    pub relationship: Option<BTreeSet<EntityId>>,
    #[serde(with = "oneiron_contracts::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
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
    /// A set project stays that project here; [`Self::attenuate_with`] also
    /// admits a proven descendant.
    pub fn attenuate(&self, child: Self) -> Result<Self> {
        self.attenuate_with(child, |_, _| Ok(false))
    }

    /// [`Self::attenuate`], where a set parent project also admits a child
    /// project that `project_descends_from(child_project, parent_project)`
    /// proves descends from it (FIX 8626). The caller owns that proof (this
    /// crate holds no project graph); it is asked only once every other axis
    /// and both resource sets already narrow, and its error is the result.
    /// World, facet and relationship stay exact, and an unset parent project
    /// still narrows to any child project.
    pub fn attenuate_with(
        &self,
        child: Self,
        mut project_descends_from: impl FnMut(EntityId, EntityId) -> Result<bool>,
    ) -> Result<Self> {
        let widens = || Error::InvalidConfig("branch scope cannot widen its parent".into());
        let axes = [(self.world, child.world), (self.facet, child.facet)];
        if axes
            .into_iter()
            .any(|(parent, child)| parent.is_some() && parent != child)
            || (self.relationship.is_some() && self.relationship != child.relationship)
            || !child.readable.is_subset(&self.readable)
            || !child.writable.is_subset(&self.writable)
        {
            return Err(widens());
        }
        let project_narrows = match (self.project, child.project) {
            (Some(parent), Some(project)) => {
                parent == project || project_descends_from(project, parent)?
            }
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !project_narrows {
            return Err(widens());
        }
        Ok(child)
    }
}
