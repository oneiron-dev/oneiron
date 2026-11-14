//! Moved from `crates/oneiron/src/verbs/revisions_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::revision_ref::RevisionRef;
use oneiron_store::vault::entity_view::EntityView;
use serde::Deserialize;
use serde::Serialize;

/// `vault.revisions.read`'s input: the refs to read with their live revisions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionsReadRequest {
    /// Record refs to read: short ids or 32-hex ids, each optionally pinned
    /// as `<ref>@<revision>` like `vault.hydrate`. The row is read at the pin
    /// when one is named; the revision answered is always the live one.
    pub refs: Vec<String>,
    /// The caller's retrieval filter: it only narrows what the refs read.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

impl RevisionsReadRequest {
    /// Refuses an empty or over-long list, and a ref that is blank or longer
    /// than a record ref may be. Parsing is the lane's read.
    pub fn validate(&self) -> MemoryResult<()> {
        if self.refs.is_empty() {
            return Err(MemoryError::bad_request("refs must not be empty"));
        }
        oneiron_base::request_limits::check_batch_len("refs", self.refs.len())?;
        for reference in &self.refs {
            let reference = reference.trim();
            if reference.is_empty()
                || reference.len() > oneiron_base::request_limits::RECORD_REF_MAX_BYTES
            {
                return Err(MemoryError::bad_request_with(
                    format!(
                        "a record ref is 1 to {} bytes",
                        oneiron_base::request_limits::RECORD_REF_MAX_BYTES
                    ),
                    &[
                        "Pass the ref the engine issued: a short id or a 32-hex id, optionally `@<revision>`.",
                    ],
                ));
            }
        }
        Ok(())
    }
}

/// One revision entry: what `vault.get` shows of the row, with the LIVE
/// revision of its record in the read's snapshot. The revision is live even
/// when the ref pinned the row's body: it names whether the words read still
/// stand, not the pin. A record that keeps no revisions answers no revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevisionEntry {
    /// The row as `vault.get` shows it.
    pub view: EntityView,
    /// The record's LIVE revision in the read's snapshot, when it keeps revisions.
    pub revision: Option<RevisionRef>,
}
