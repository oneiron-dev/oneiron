//! Two-phase staging: stage, commit-prepared, recovery, and keep-ref naming.

use crate::git_wire::config::GIT_WIRE_KEEP_REF_PREFIX;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefExpectation;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::ids::GitRefPublication;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::plan::GitWirePlannedOid;
use crate::git_wire::record::GitWireCommitOutcome;
use crate::git_wire::record::GitWirePrepared;
use crate::git_wire::record::GitWireReceipt;
use crate::git_wire::record::GitWireRecordState;
use crate::git_wire::record::hex_lower;
use crate::git_wire::record::new_record;
use crate::git_wire::record::prepared_from_stored;
use crate::git_wire::record::receipt_from_stored;
use crate::git_wire::record::rejection_from_stored;
use crate::git_wire::record::stage_record_key;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use crate::scan_kind::EngineScan;
use oneiron_base::error::Result;

pub fn stage_keep_ref_names(
    key: &[u8; 32],
    publications: &[GitRefPublication],
) -> Result<Vec<GitRefName>> {
    let scope = hex_lower(key);
    let mut names = Vec::with_capacity(publications.len());
    for index in 0..publications.len() {
        names.push(GitRefName::parse_full(format!(
            "{GIT_WIRE_KEEP_REF_PREFIX}stage/{scope}/{index}"
        ))?);
    }
    Ok(names)
}

pub fn object_keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", oid.as_str()))
}
