//! `vault.revisions.read`: each ref's entity view with its live revision,
//! under the caller's lane and a live Grant naming the verb.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadResult;
use crate::memory::{EntityView, Memory, MemoryError, MemoryResult};
use crate::vault::RevisionRef;

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
    pub filter: Option<crate::memory::ReadFilterInput>,
}

impl RevisionsReadRequest {
    /// Refuses an empty or over-long list, and a ref that is blank or longer
    /// than a record ref may be. Parsing is the lane's read.
    pub fn validate(&self) -> MemoryResult<()> {
        if self.refs.is_empty() {
            return Err(MemoryError::bad_request("refs must not be empty"));
        }
        crate::memory::caps::check_batch_len("refs", self.refs.len())?;
        for reference in &self.refs {
            let reference = reference.trim();
            if reference.is_empty() || reference.len() > crate::request_limits::RECORD_REF_MAX_BYTES
            {
                return Err(MemoryError::bad_request_with(
                    format!(
                        "a record ref is 1 to {} bytes",
                        crate::request_limits::RECORD_REF_MAX_BYTES
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

/// `vault.revisions.read` on a handle: each ref's entity view with its live
/// revision under the caller's lane. The lane read refuses a caller with no
/// live owner Grant naming the verb, in the serving snapshot itself; a row
/// outside the caller's lane answers `None`, never an error.
pub fn vault_revisions_read_embedded(
    memory: &Memory<'_>,
    input: RevisionsReadRequest,
) -> MemoryResult<ScopedReadResult<Vec<Option<RevisionEntry>>>> {
    input.validate()?;
    let bound = memory.with_read_filter(input.filter.as_ref());
    let read = bound.revisions_read(&input.refs)?;
    Ok(ScopedReadResult {
        value: read
            .value
            .into_iter()
            .map(|slot| slot.map(|(view, revision)| RevisionEntry { view, revision }))
            .collect(),
        receipt: read.receipt,
    })
}
