//! A retained document frontier's opaque reference (`RevisionRef`), the
//! revision a manifest entry and a materialization mirror name. Document
//! revision tracking (`vault::entity_revision`) mints, parses and compares
//! it; the store's attempt manifest and materialization rows carry it.
use serde::{Deserialize, Serialize};

/// Opaque singular reference to one retained document frontier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct RevisionRef(pub [u8; 16]);
