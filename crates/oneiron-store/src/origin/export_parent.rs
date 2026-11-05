//! CALL G "import export parents" (FIX 6869, G4 PR1): the Git parents of
//! an import-bound tested revision's projection.
//!
//! Engine commits never pretend to keep original object ids. An import-
//! bound revision's first projection takes the nearest already-exported
//! engine ancestor in its own verified chain, whose Git history must reach
//! the admitted original commit; with none, that admitted commit itself, so
//! a checked Baseline exports as a child of `source_commit`, never as an
//! unrelated root. Once mapped, a revision keeps its stored projection's
//! parent: a repeat re-reads it and requires it to be one this chain
//! allows, rather than choosing again because a later ancestor exported
//! since. The engine `parent_revision_id` stays the tested chain's parent,
//! distinct from Git parentage. No live ref, compare-and-swap value or
//! automatic ancestor export stands in. A tested revision of an unbound
//! chain whose own seal consumed a push completely takes that push's
//! incoming tip as its parent too (FIX 7540). Every other revision keeps
//! the export's own immediate-parent rule, unchanged.
use crate::git_wire::ids::GitOid;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The `parent` headers of one raw commit object, in order.
pub fn commit_parents(raw: &[u8]) -> Result<Vec<GitOid>> {
    let mut parents = Vec::new();
    for line in raw.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(oid) = line.strip_prefix(b"parent ") {
            let oid = std::str::from_utf8(oid)
                .map_err(|_| Error::InvariantViolation("a commit parent is not hex"))?;
            parents.push(GitOid::parse_hex(oid)?);
        }
    }
    Ok(parents)
}
