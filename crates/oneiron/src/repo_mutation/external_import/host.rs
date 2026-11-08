//! The per-call transport an outside import borrows (FIX 6871): built by
//! the serving host from the credential it verified for this one call, and
//! lent to a [`crate::memory::Memory`] handle for that call only.
//!
//! A host carries transport and custody, never authority: the engine
//! judges the caller, the Grant and every receive record itself, and the
//! door's own receive admission decides each send again. No global, no
//! startup hook, no serializer and no owner fallback exist for it.

use super::{ExternalImportLookup, ExternalImportSource};
use crate::Vault;
use crate::error::Result;
use crate::federation::GitPushCaller;
use crate::git_wire::{
    FetchedExternalGit, GitImportFetchOutcome, GitImportPushOutcome, GitOid, GitRefName, GitWire,
};
use crate::origin::lfs::{LfsOid, LfsTransferReport};

/// One authenticated call's Git transport for an outside import.
pub trait ExternalGitSourceHost: Send + Sync {
    /// The pusher the host authenticated for this call.
    fn caller(&self) -> &GitPushCaller;

    /// Judges the call's credential again, now.
    ///
    /// # Errors
    /// A credential that no longer stands.
    fn revalidate(&self) -> Result<()>;

    /// Fetches exactly the normalized `source` into a private scratch store
    /// (`GitWire::fetch_external_exact`), with the credential of the custody
    /// secret `binding` when one is named, which only the credential broker
    /// installs (OSH-3, `GitWire::fetch_external_exact_via_relay`): only to
    /// the source's own https host, never a fallback. A redirect off that
    /// host is a refusal naming its target.
    ///
    /// # Errors
    /// A custody refusal, or a process or store failure.
    fn fetch_exact(
        &self,
        wire: &GitWire<'_>,
        source: &ExternalImportSource,
        binding: Option<&str>,
    ) -> Result<GitImportFetchOutcome>;

    /// Fetches each of `objects`, the Git-LFS objects the normalized
    /// `source`'s fetched history names that `vault` lacks, from the
    /// source's own batch API, and installs each through `vault`'s LFS
    /// upload door at `now` (`crate::origin::lfs::download_lfs_objects`).
    /// Every batch call and object action goes through the credential
    /// broker (OSH-3, FIX 19876), each judged again first (the call's
    /// credential, and the binding when one is named): a batch call under
    /// the credential of the custody secret `binding`, which only the broker
    /// installs, or under none when no binding is named; an object action
    /// with the headers its batch answer named, as given. Never a fallback.
    /// Answers the objects that did not arrive (or the batch failure that
    /// stopped the fetch), how the broker is kept apart from this process,
    /// and how many credential echoes it rewrote.
    fn fetch_lfs_objects(
        &self,
        vault: &Vault,
        source: &ExternalImportSource,
        binding: Option<&str>,
        objects: &[(LfsOid, u64)],
        now: u64,
    ) -> LfsTransferReport;

    /// Pushes exactly `commit` from `fetched` to `name` through this call's
    /// own authenticated door route `lookup` names, leased on `expected`.
    /// The outcome is a transport hint, never a receipt.
    ///
    /// # Errors
    /// A relay that cannot start, or a process failure.
    fn push_exact(
        &self,
        wire: &GitWire<'_>,
        fetched: &FetchedExternalGit,
        lookup: &ExternalImportLookup,
        name: &GitRefName,
        expected: Option<&GitOid>,
        commit: &GitOid,
    ) -> Result<GitImportPushOutcome>;
}
