//! Structural checks for proposal-only output. These checks grant no permission.

use crate::claim::validate_predicate;
use crate::error::{Error, Result};

use super::super::{MAX_EVIDENCE_REFS, validate_ref};
use super::{RepairOperation, RepairProposal};

pub(crate) fn validate_repair_proposal(proposal: &RepairProposal, session_tag: &str) -> Result<()> {
    validate_ref(&proposal.session_tag)?;
    if proposal.session_tag != session_tag {
        return Err(Error::InvariantViolation("repair session mismatch"));
    }
    // Claimed actor/source are disclosure only, including unknown actor labels.
    // They must not participate in authority or criticality recomputation.
    // Reserved namespaces may be DISCLOSED, never written by this module.
    validate_predicate(&proposal.target_predicate, true)?;
    if proposal.diagnostic_refs.is_empty() || proposal.diagnostic_refs.len() > MAX_EVIDENCE_REFS {
        return Err(Error::InvariantViolation("repair diagnostic ref count"));
    }
    match &proposal.operation {
        RepairOperation::Reindex { scope_ref } => validate_ref(scope_ref),
        RepairOperation::Rescore { .. } => Ok(()),
        RepairOperation::Retry { run_ref } => validate_ref(run_ref),
        RepairOperation::NarrowPolicy { predicate, .. }
        | RepairOperation::ProposeClaim { predicate, .. } => {
            // A harmless display target must not mask another predicate in the intent.
            if predicate != &proposal.target_predicate {
                return Err(Error::InvariantViolation(
                    "repair target predicate mismatch",
                ));
            }
            Ok(())
        }
        RepairOperation::SkillEdit { patch_ref, .. } => validate_ref(patch_ref),
        RepairOperation::DevPatch {
            repo_ref,
            patch_ref,
        } => {
            validate_ref(repo_ref)?;
            validate_ref(patch_ref)
        }
        RepairOperation::SchemaPatch {
            schema_ref,
            patch_ref,
        } => {
            validate_ref(schema_ref)?;
            validate_ref(patch_ref)
        }
    }
}
