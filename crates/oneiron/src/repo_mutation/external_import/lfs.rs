//! An outside import's Git-LFS objects (FIX 7596): after the exact fetch
//! and before any send, every object the fetched history's pointers name
//! that this vault does not hold yet comes from the source's own batch API,
//! under the import's binding and the same host rule as the fetch, and is
//! installed through the vault-LFS upload door (its scan, SHA-256 and size
//! checks), so the door's tip LFS pairing admits the pointers it publishes.
//! An object that does not arrive is left to the door, which refuses a tip
//! naming an absent object as it refuses any push; nothing here holds.
//!
//! The call's host sends every batch call and object action through its
//! credential broker (OSH-3, FIX 19876), which alone installs the binding's
//! credential when the import names one; an unbound import's go with none.
//! Before the first LFS request goes out, the import records that route;
//! once the requests ended, what the broker did (its isolation and how many
//! credential echoes it rewrote). The receipt shows both. A route that
//! cannot be recorded sends nothing.
use super::ImportCall;
use super::source::{ImportOutcome, ImportStep, LfsTransferRecord, ObservationRecord};
use super::types::{ExternalImportRequest, NormalizedSource};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::FetchedExternalGit;
use crate::origin::lfs::LfsOid;

impl Vault {
    /// Installs the Git-LFS objects `fetched`'s history names that this
    /// vault lacks. A transfer that fails is logged and left to the door.
    ///
    /// # Errors
    /// A store or object store failure reading what the history names, or
    /// one recording the transfer's route or end.
    pub(super) fn install_external_import_lfs(
        &self,
        call: &ImportCall<'_>,
        request: &ExternalImportRequest,
        normalized: &NormalizedSource,
        fetched: &FetchedExternalGit,
    ) -> Result<()> {
        let tips = [fetched.base().clone(), fetched.head().clone()];
        let (complete, objects) =
            crate::origin::history_lfs_objects(&call.wire, fetched.repo(), &tips)?;
        if !complete {
            tracing::warn!("an outside import's LFS census did not read its whole history");
        }
        let mut absent: Vec<(LfsOid, u64)> = Vec::new();
        for (oid, size) in objects {
            if !self.has_lfs_object(oid, size)? {
                absent.push((oid, size));
            }
        }
        if absent.is_empty() {
            return Ok(());
        }
        // The binding reaches the source's own https host alone.
        let source = &normalized.source;
        if !source
            .repository
            .starts_with(&format!("{}/", source.host.trim_end_matches('/')))
        {
            tracing::warn!("an outside import's repository is off its host; no LFS fetch");
            return Ok(());
        }
        self.observe(
            call,
            ImportStep::Lfs,
            ImportOutcome::Brokered,
            "git_lfs_broker",
        )?;
        let now = self.now_recorded_at();
        let report = call.host.fetch_lfs_objects(
            self,
            source,
            request.source_binding.as_deref(),
            &absent,
            now,
        );
        match &report.missing {
            Ok(missing) if missing.is_empty() => {}
            Ok(missing) => tracing::warn!(
                missing = missing.len(),
                "an outside import's LFS objects did not all arrive; the door judges its pointers"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an outside import's LFS fetch failed; the door judges its pointers"
            ),
        }
        let ended = ObservationRecord::new(
            call.import,
            call.attempt,
            ImportStep::Lfs,
            ImportOutcome::Brokered,
            self.now_recorded_at(),
        )
        .because("git_lfs_broker_ended")
        .with_lfs_transfer(LfsTransferRecord {
            broker_isolation: report.broker_isolation,
            credential_rewrites: report.credential_rewrites,
        });
        self.put_external_import_observation(call.import, &ended)
    }
}
