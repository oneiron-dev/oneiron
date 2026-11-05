//! Refresh of a standing manifest's refs (FIX 6870 phase 1, rulings 7-8).
//!
//! Refs are single-writer: the host holding the repo's origin authority
//! rewrites `visible_refs`, `lfs_pointers` and `epoch` from what the origin
//! advertises (the checked publication projection and the LFS pointers its
//! publications require). While no authority row is configured, the
//! machine that minted the id writes instead, at epoch 0. Every other vault
//! keeps the copy it received. The visible-ref writers live outside this
//! lane's files, so refresh runs from the two doors that are ours: right
//! after an ensure, and from every origin mirror pass, which every
//! published-ref move wakes (`note_origin_ref_moved`).

use std::collections::BTreeSet;

use super::{BY_CODE, MANIFESTS, MINTED, RepoPortableId};
use crate::Vault;
use crate::authority::OriginCutStanding;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitOid, GitRefName, GitWire};
use crate::origin::lfs::LfsOid;
use crate::origin::publication::OriginPublicationStatus;
use crate::origin::residence::OriginHostAuthority;

impl Vault {
    /// Rewrites the standing manifest of CODE entity `code` from the origin
    /// rows this host advertises, when this host is its refs writer (module
    /// docs). A manifest that does not stand for `code`, names no served
    /// repo, or names one this host does not serve is left as it stands.
    pub(super) fn refresh_repo_manifest(
        &self,
        code: EntityId,
        portable: RepoPortableId,
    ) -> Result<()> {
        let (manifest, minted) = {
            let txn = self.store.env.read_txn()?;
            if BY_CODE.get(&self.store, &txn, &code)?.as_ref() != Some(&portable.0) {
                return Ok(());
            }
            let Some(manifest) = MANIFESTS.get(&self.store, &txn, &portable.0)? else {
                return Ok(());
            };
            let minted = MINTED.contains(&self.store, &txn, &portable.0)?;
            (manifest, minted)
        };
        if manifest.code != code {
            return Ok(());
        }
        let Some(origin_name) = manifest.origin_name else {
            return Ok(());
        };
        let dir = crate::origin::smart_http::origin_repo_dir(self, &origin_name)?;
        if !dir.exists() {
            return Ok(());
        }
        // The carried name alone does not prove this store is the CODE
        // anchor's: two vaults can serve different repos under one name,
        // and the authority and publications below are the local store's,
        // so anything else leaves the imported manifest as it stands.
        if !self.code_serves_dir(code, &dir)? {
            return Ok(());
        }
        // The writer standing is read here and the write lands below: an
        // authority change in between lets one stale-epoch write through,
        // which the next mirror pass corrects.
        let held = match self.origin_host_authority(&origin_name)? {
            OriginHostAuthority::Held(lease) => Some(lease.epoch()),
            OriginHostAuthority::Unconfigured if minted => None,
            _ => return Ok(()),
        };
        // The epoch every device can prove (FIX 15740): the owner's cut in
        // force, where it names this machine and this host holds the repo at
        // that very epoch; before any cut, the bootstrap 0. A host the cut
        // does not name, or one whose cuts are unresolved here, leaves the
        // manifest as it stands.
        let (standing, machine) = {
            let txn = self.store.env.read_txn()?;
            (
                self.authority_view_readonly_in_txn(&txn)?
                    .origin_cut_standing(portable.as_bytes())?,
                crate::store::install_identity::read_machine_id_in_txn(self, &txn)?,
            )
        };
        let epoch = match standing {
            OriginCutStanding::InForce(cut)
                if held == Some(cut.epoch) && machine == Some(cut.writer) =>
            {
                cut.epoch
            }
            OriginCutStanding::NoCut => 0,
            _ => return Ok(()),
        };
        let wire = GitWire::new(self)?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&wire.repository_identity(&dir)?.as_hex())?;
        let publications = self.origin_visible_ref_rows(&repo_id)?;
        let advertised: BTreeSet<(String, String)> = if publications.is_empty() {
            BTreeSet::new()
        } else {
            let Some(handle) = self.mirror_handle(&wire, repo_id, &dir)? else {
                return Ok(());
            };
            self.published_origin_refs(&wire, repo_id, &handle)?
                .into_iter()
                .map(|(name, oid)| (name.as_str().to_owned(), oid.as_str().to_owned()))
                .collect()
        };
        let mut refs = Vec::new();
        let mut pointers = BTreeSet::new();
        for publication in publications {
            let Some(record) = self.origin_publication(publication)? else {
                continue;
            };
            if record.repo_id != repo_id || record.status != OriginPublicationStatus::Published {
                continue;
            }
            let key = (
                record.ref_name.as_str().to_owned(),
                record.new_oid.as_str().to_owned(),
            );
            if advertised.contains(&key) {
                refs.push(key);
                pointers.extend(record.required_lfs_oids.iter().map(|(oid, _)| *oid));
            }
        }
        // Only what a peer's decode would take is stored: a publication row
        // naming no full ref or commit id never poisons the manifest, and
        // one name stands once.
        refs.retain(|(name, oid)| {
            GitRefName::parse_full(name).is_ok() && GitOid::parse_hex(oid).is_ok()
        });
        refs.sort();
        refs.dedup_by(|next, kept| next.0 == kept.0);
        let pointers: Vec<LfsOid> = pointers.into_iter().collect();
        let changed = self.with_write_txn_grouped(|txn| {
            let Some(mut current) = MANIFESTS.get(&self.store, txn, &portable.0)? else {
                return Ok(false);
            };
            if current.code != code
                || BY_CODE.get(&self.store, txn, &code)?.as_ref() != Some(&portable.0)
                || (current.visible_refs == refs
                    && current.lfs_pointers == pointers
                    && current.epoch == epoch)
            {
                return Ok(false);
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            current.version = super::REPO_MANIFEST_VERSION;
            current.visible_refs = refs;
            current.lfs_pointers = pointers;
            current.epoch = epoch;
            // A lamport tick: a refresh inside the held copy's millisecond
            // still replaces it under rule 7's (epoch, updated_at) order.
            current.updated_at = now.max(current.updated_at.saturating_add(1));
            // The refs writer signs what it wrote (FIX 12765).
            self.sign_repo_manifest_in_txn(txn, &mut current)?;
            MANIFESTS.put(&self.store, txn, &portable.0, &current)?;
            Ok(true)
        })?;
        if changed {
            self.note_repo_manifest_written(code);
        }
        Ok(())
    }

    /// Whether CODE entity `code`'s stored local path names the served
    /// store `dir` (`bind_served_repo_anchor`): only then are that store's
    /// authority and publications the anchor's.
    fn code_serves_dir(&self, code: EntityId, dir: &std::path::Path) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, &txn, &code)?
        else {
            return Ok(false);
        };
        let Some(crate::store::code_snapshot::RepoRef::LocalFolder { path, .. }) =
            crate::code_artifact::decode_code_artifact_body(&body)
                .ok()
                .and_then(|artifact| {
                    crate::store::code_snapshot::RepoRef::parse(&artifact.repo_ref).ok()
                })
        else {
            return Ok(false);
        };
        Ok(std::path::Path::new(&path)
            .canonicalize()
            .is_ok_and(|stored| stored == dir))
    }

    /// The authority key of the repo `manifest` names, where this host
    /// serves that repo for its CODE anchor (FIX 12765): its origin
    /// authority row, read in the transaction that would replace the
    /// manifest, names the one refs writer a carried copy must come from
    /// here. `None` where this host serves no such repo.
    #[cfg(feature = "sync")]
    pub(super) fn served_origin_repo_id(
        &self,
        manifest: &super::RepoManifest,
    ) -> Result<Option<EntityId>> {
        let Some(name) = manifest.origin_name.as_deref() else {
            return Ok(None);
        };
        let Ok(dir) = crate::origin::smart_http::origin_repo_dir(self, name) else {
            return Ok(None);
        };
        if !dir.exists() || !self.code_serves_dir(manifest.code, &dir)? {
            return Ok(None);
        }
        self.served_repo_id(&dir).map(Some)
    }

    /// The portable ids served repo `origin_name` stands under here, each
    /// with its CODE anchor (FIX 15740): every standing manifest that names
    /// that served name and whose CODE anchor's stored path is the served
    /// store `dir` (`code_serves_dir`, as refresh judges it). The owner's cut
    /// of the repo is signed once for each.
    pub(in crate::origin) fn served_repo_portable_ids(
        &self,
        origin_name: &str,
        dir: &std::path::Path,
    ) -> Result<Vec<(EntityId, RepoPortableId)>> {
        let mut bound = Vec::new();
        for manifest in self.standing_repo_manifests(|_| true)? {
            if manifest.origin_name.as_deref() == Some(origin_name)
                && self.code_serves_dir(manifest.code, dir)?
            {
                bound.push((manifest.code, manifest.portable));
            }
        }
        Ok(bound)
    }

    /// Whether each of `bound` ([`Self::served_repo_portable_ids`]) still
    /// stands in `txn` as it was resolved: its CODE's standing id, naming
    /// served repo `origin_name`.
    pub(in crate::origin) fn served_repo_portable_ids_stand_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        origin_name: &str,
        bound: &[(EntityId, RepoPortableId)],
    ) -> Result<bool> {
        for (code, portable) in bound {
            if BY_CODE.get(&self.store, txn, code)?.as_ref() != Some(&portable.0) {
                return Ok(false);
            }
            let Some(manifest) = MANIFESTS.get(&self.store, txn, &portable.0)? else {
                return Ok(false);
            };
            if manifest.code != *code || manifest.origin_name.as_deref() != Some(origin_name) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Refreshes each standing manifest that names served repo
    /// `origin_name`: the origin mirror pass's hook (ruling 8). It never
    /// fails its caller; a fault is logged and the next pass retries.
    pub(in crate::origin) fn refresh_repo_manifests_for_origin(&self, origin_name: &str) {
        let standing = match self.standing_repo_manifests(|_| true) {
            Ok(standing) => standing,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "repo manifests not read for refresh");
                return;
            }
        };
        for manifest in standing {
            if manifest.origin_name.as_deref() != Some(origin_name) {
                continue;
            }
            if let Err(error) = self.refresh_repo_manifest(manifest.code, manifest.portable) {
                tracing::warn!(
                    code = %manifest.code.to_hex(),
                    kind = ?error.kind(),
                    "repo manifest not refreshed"
                );
            }
        }
    }
}
