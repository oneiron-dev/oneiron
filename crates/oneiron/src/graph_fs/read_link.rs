//! Link resolution with the actual scoped point-read receipt.

use crate::error::Result;
use crate::ports::PointRead;
use oneiron_contracts::claim::ScopedReadReceipt;

use super::GraphFsResolver;
use super::readdir::{normalize_path, parse_entity_id, path_components};

/// A link target and the actual scoped point-read receipt, when a read ran.
/// Unmatched paths and snapshot mounts make no scoped read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsLinkRead {
    pub value: Option<String>,
    pub receipt: Option<ScopedReadReceipt>,
}

impl GraphFsResolver<'_, '_> {
    /// Resolves the same link while preserving its point-read receipt,
    /// including a read whose target is absent or withheld.
    pub fn read_link_with_receipt(&self, path: &str) -> Result<GraphFsLinkRead> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        let no_read = GraphFsLinkRead {
            value: None,
            receipt: None,
        };
        if self.snapshot.is_some() {
            return Ok(no_read);
        }
        let [component] = components.as_slice() else {
            return Ok(no_read);
        };
        let Some(claim_hex) = component
            .strip_prefix("[[claim:")
            .and_then(|rest| rest.strip_suffix("]]"))
        else {
            return Ok(no_read);
        };
        let claim_id = parse_entity_id(claim_hex)?;
        let read = self
            .scoped_read
            .read(&[PointRead::id(claim_id)], None)?
            .single();
        Ok(GraphFsLinkRead {
            value: read
                .value
                .is_some()
                .then(|| format!("/claims/{}", claim_id.to_hex())),
            receipt: Some(read.receipt),
        })
    }
}
