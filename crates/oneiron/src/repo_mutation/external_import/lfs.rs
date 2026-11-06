//! An outside import's Git-LFS objects (FIX 7596): after the exact fetch
//! and before any send, every object the fetched history's pointers name
//! that this vault does not hold yet comes from the source's own batch API,
//! under the import's binding and the same host rule as the fetch, and is
//! installed through the vault-LFS upload door (its scan, SHA-256 and size
//! checks), so the door's tip LFS pairing admits the pointers it publishes.
//! An object that does not arrive is left to the door, which refuses a tip
//! naming an absent object as it refuses any push; nothing here holds.
use super::types::{ExternalImportRequest, NormalizedSource};
use super::{EXTERNAL_IMPORT_FETCH_EFFECTOR, ImportCall};
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::FetchedExternalGit;
use crate::origin::lfs::{LfsBatchRemote, LfsOid};

impl Vault {
    /// Installs the Git-LFS objects `fetched`'s history names that this
    /// vault lacks. A transfer that fails is logged and left to the door.
    ///
    /// # Errors
    /// A store or object store failure reading what the history names.
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
        let remote = LfsBatchRemote::of(&source.repository)?;
        let now = self.now_recorded_at();
        let missing = match request.source_binding.as_deref() {
            None => remote.download(self, None, &absent, now),
            Some(binding) => {
                let mut answer = Err(Error::InvariantViolation("an import LFS fetch never ran"));
                let door = self.inject_secret_at_door(
                    binding,
                    EXTERNAL_IMPORT_FETCH_EFFECTOR,
                    &mut |value: &[u8]| {
                        let Ok(text) = std::str::from_utf8(value) else {
                            answer = Err(Error::Refused("binding_not_a_header".to_owned()));
                            return Ok(());
                        };
                        let header = zeroize::Zeroizing::new(text.trim().to_owned());
                        answer = remote.download(self, Some(header.as_str()), &absent, now);
                        Ok(())
                    },
                );
                door.and(answer)
            }
        };
        match missing {
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
        Ok(())
    }
}
