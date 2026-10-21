//! The per-call transport an outside import borrows (FIX 6871): built by
//! the serving host from the credential it verified for this one call, and
//! lent to a [`crate::memory::Memory`] handle for that call only.
//!
//! A host carries transport and custody, never authority: the engine
//! judges the caller, the Grant and every receive record itself, and the
//! door's own receive admission decides each send again. No global, no
//! startup hook, no serializer and no owner fallback exist for it.

use super::{ExternalImportLookup, ExternalImportSource};
use crate::error::Result;
use crate::federation::GitPushCaller;
use crate::git_wire::{
    FetchedExternalGit, GitImportFetchOutcome, GitImportPushOutcome, GitOid, GitRefName, GitWire,
};

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
    /// (`GitWire::fetch_external_exact`), with the `Authorization` header
    /// of the custody secret `binding` when one is named: only to the
    /// source's own https host, never a fallback. A redirect off that host
    /// is a refusal naming its target.
    ///
    /// # Errors
    /// A custody refusal, or a process or store failure.
    fn fetch_exact(
        &self,
        wire: &GitWire<'_>,
        source: &ExternalImportSource,
        binding: Option<&str>,
    ) -> Result<GitImportFetchOutcome>;

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
