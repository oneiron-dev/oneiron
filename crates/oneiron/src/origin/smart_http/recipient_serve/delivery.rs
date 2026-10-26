//! The fresh real-byte delivery of a granted Git exchange (FIX 7608
//! pre-flip, FIX 9328; CALL GIT-REVEAL-OPT-IN).
//!
//! Before an upload-pack exchange sends any object of a recipient's
//! granted copy, each file its plan releases is delivered through the
//! shipped file reveal ([`Vault::repo_file_sight`]): the reader's own
//! reason is logged, the grant's use and every reveal row commit, and only
//! then may the file's stored bytes leave. A delivery is never kept or
//! reused: the next exchange delivers again. A file whose grant is gone,
//! or whose stored bytes are not the ones its marks were kept under, is
//! not delivered and is masked in the copy the exchange then reads, never
//! a refusal of the read. An advertisement plans and delivers nothing.

use std::collections::BTreeSet;

use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::origin::secret_projection::git::RepoGitReleasePlan;
use crate::secret_custody::RepoFileSight;

/// `plan` with only the files a fresh delivery to its recipient, for
/// `why`, committed: each read from the canonical store `canonical` and
/// checked against its marks first.
///
/// # Errors
/// A store or git failure, or the file check's own.
pub(crate) fn prepare_repo_git_delivery(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    plan: RepoGitReleasePlan,
    why: &str,
) -> Result<RepoGitReleasePlan> {
    let asker = plan.binding().asker();
    let mut delivered: BTreeSet<(Vec<u8>, GitOid)> = BTreeSet::new();
    for file in plan.files() {
        let raw_blake3 = wire
            .read_object_to_spool(canonical, &file.blob)?
            .content_blake3();
        // Bytes the marks were not kept under are no file this check names.
        if file.marks.raw_blake3() != Some(raw_blake3) {
            continue;
        }
        let target = file.target(plan.binding());
        if let RepoFileSight::Delivered(delivery) =
            vault.repo_file_sight(&asker, &target, &raw_blake3, &file.keys(), why)?
        {
            // The committed delivery must name the very blob read.
            if delivery.target().blob() == file.blob.as_str()
                && *delivery.raw_blake3() == raw_blake3
            {
                delivered.insert((file.path.clone(), file.blob.clone()));
            }
        }
    }
    Ok(plan.retain(|file| delivered.contains(&(file.path.clone(), file.blob.clone()))))
}
