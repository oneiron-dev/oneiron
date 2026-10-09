//! Project-axis selection for corpus queries.
//!
//! A corpus is a PROJECT entity with role corpus, not a separate claim
//! dimension. Claims carry their project in the required `scopeProjectId`
//! stamp; the opaque `scope` map has no corpus entry.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Project-axis selection for one corpus query. The caller supplies project
/// ids (including any scope-set members it wants to union); the engine does
/// not infer membership from topic, provenance, or collection edges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorpusScope {
    /// No project restriction.
    #[default]
    All,
    /// Only claims in the vault's default project.
    Unscoped,
    /// Claims stamped with this project's id.
    Corpus(EntityId),
    /// Union of claims stamped with any of these project ids.
    AnyOf(Vec<EntityId>),
}

impl CorpusScope {
    pub(crate) fn canonicalize(self) -> Result<Self> {
        match self {
            Self::AnyOf(mut ids) => {
                if ids.is_empty() {
                    return Err(Error::InvalidConfig(
                        "corpus scope AnyOf must name at least one project".to_owned(),
                    ));
                }
                ids.sort_unstable();
                ids.dedup();
                Ok(Self::AnyOf(ids))
            }
            scope => Ok(scope),
        }
    }

    pub(crate) fn matches(&self, project: EntityId) -> bool {
        match self {
            Self::All => true,
            Self::Unscoped => project == crate::claim::default_project_id(),
            Self::Corpus(id) => project == *id,
            Self::AnyOf(ids) => ids.contains(&project),
        }
    }
}
