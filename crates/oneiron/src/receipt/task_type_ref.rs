//! Versioned task-type references retained with receipt attribution.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The root node of the task-type tree. An outcome with no task (a chat turn,
/// a channel actor's health) and every unsure placement carries it.
pub const ROOT_TYPE_NODE: &str = "root";

/// A task type: the node and the tree version it was placed in.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct TypeRef {
    pub node_id: String,
    pub tree_version: u64,
}

impl TypeRef {
    /// The root node of tree `tree_version`.
    #[must_use]
    pub fn root(tree_version: u64) -> Self {
        Self {
            node_id: ROOT_TYPE_NODE.to_owned(),
            tree_version,
        }
    }

    /// Whether this is a root placement.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.node_id == ROOT_TYPE_NODE
    }

    /// The `node@version` display and key form.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{}@{}", self.node_id, self.tree_version)
    }

    /// Structural check: a non-empty lower-case node id without `@`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] on a malformed node id.
    pub fn validate(&self) -> Result<()> {
        let ok = !self.node_id.is_empty()
            && self.node_id.len() <= 128
            && self.node_id.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'_' | b'-' | b'.' | b'/')
            });
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "a typeRef node id is 1..=128 bytes of [a-z0-9_./-]",
            ))
        }
    }
}
