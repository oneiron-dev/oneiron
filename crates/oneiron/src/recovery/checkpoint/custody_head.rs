//! Custody heads at the vault's surface (KS-4A1, FIX 5685): publishing a
//! vault's exterior key custody beside its backups, the owner's status read
//! of it, the self-host anchor door, and the restore that recovers custody
//! from a head on a host that lacks it.
//!
//! The head always publishes, sealed and recovery-wrapped, to the folder
//! beside the backups; the anchor is the one optional step (Engine 10-20
//! 04:0x). A restore that keeps its image's custody where that custody is
//! not on this host takes one of three routes: a head the image names is
//! admitted (fail-closed against a configured anchor; used as it is, and
//! said so, with none) and landed beside the destination; an image that
//! names no head drops and names its claim-bound rows whose keys stayed on
//! the old host; and everything else restores as before. Archive targets
//! and the kit share the one source and validator: only the opener differs,
//! the data key the backup unlocked with or the kit's recovery root.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use oneiron_crypto::HybridSecretKey;
use serde::Serialize;

use super::{
    CheckpointKey, Custody, RestoreReason, RestoreReport, codec_error, read_image_required,
    write_budget,
};
use crate::store::{
    AnchorAdvance, AnchorStore, CUSTODY_HEAD_WRAP_CONTEXT, CustodyRecipients, CustodyRoute,
    CustodySourceAt, FileAnchor, FolderTarget, Publication, PublicationState, route_custody,
};
use crate::{Result, Vault, VaultConfig};

/// The owner's status read's names for where a vault's custody publication
/// stands.
pub const CUSTODY_NONE: &str = "custody_none";
pub const CUSTODY_PUBLISHED: &str = "custody_published";
pub const CUSTODY_TARGET_PENDING: &str = "custody_target_pending";
pub const CUSTODY_ANCHOR_PENDING: &str = "custody_anchor_pending";
pub const CUSTODY_FENCED: &str = "custody_fenced";

/// Where one vault's custody publication stands: the status read's state
/// name, the positions it compared (writer epoch, log sequence numbers;
/// public structure, never a key) and why a step is pending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyStatus {
    /// One of [`CUSTODY_NONE`], [`CUSTODY_PUBLISHED`],
    /// [`CUSTODY_TARGET_PENDING`], [`CUSTODY_ANCHOR_PENDING`] (the
    /// anchor root is not set up, missing, or behind) or [`CUSTODY_FENCED`]
    /// (another install took the custody over in a disaster recovery).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchored_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CustodyStatus {
    fn of(publication: Publication) -> Self {
        Self {
            state: match publication.state {
                PublicationState::Nothing => CUSTODY_NONE,
                PublicationState::Published => CUSTODY_PUBLISHED,
                PublicationState::TargetPending => CUSTODY_TARGET_PENDING,
                PublicationState::AnchorPending => CUSTODY_ANCHOR_PENDING,
                PublicationState::Fenced => CUSTODY_FENCED,
            },
            writer_epoch: publication.local.map(|local| local.epoch.get()),
            log_seq: publication.local.map(|local| local.seq),
            published_seq: publication.published.map(|published| published.seq),
            anchored_seq: publication.anchored.map(|anchored| anchored.seq),
            detail: publication.detail,
        }
    }
}

/// Where a restore on a host without its image's custody finds the head:
/// the folder beside the backup (`<folder>/oneiron-custody/`), the anchor
/// root when one is configured, and the kit's recovery root when the
/// restore was unlocked with the kit.
pub struct CustodyRecovery<'a> {
    folder: PathBuf,
    anchor_root: Option<PathBuf>,
    root: Option<&'a HybridSecretKey>,
}

impl<'a> CustodyRecovery<'a> {
    /// The head published beside the backup file at `backup`.
    pub fn beside(backup: &Path) -> Self {
        Self {
            folder: backup
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
            anchor_root: None,
            root: None,
        }
    }

    /// Checked against the anchor in `root`, when one is configured (CALLS
    /// CUSTODY_ANCHOR_ROOT); `None` uses the head as it is, and the restore
    /// says rollback is not proven.
    pub fn anchored_at(mut self, root: Option<PathBuf>) -> Self {
        self.anchor_root = root;
        self
    }

    /// Opened with the kit's recovery root as well as the backup's data
    /// key: every compartment, the owner-only ones too.
    pub fn with_kit(mut self, root: &'a HybridSecretKey) -> Self {
        self.root = Some(root);
        self
    }
}

impl Vault {
    /// Who this vault's custody heads are wrapped to: its pinned recovery
    /// root (the kit keeps only its seed), and its data key's custody
    /// subkey while the key is held. Neither is a reason to refuse: a pass
    /// with neither stays pending.
    fn custody_recipients(&self) -> Result<CustodyRecipients> {
        let data_key = self
            .unlock_vault_key()
            .and_then(|()| self.vault_subkey(CUSTODY_HEAD_WRAP_CONTEXT))
            .ok();
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let root = self
            .pinned_root_recipient_in_txn(&txn, &fold)?
            .map(|root| (root.id.0, root.key));
        Ok(CustodyRecipients { root, data_key })
    }

    /// One publication pass of this vault's custody: its keyless log and
    /// latest sealed head to the folder target `folder` (the backups'
    /// directory), then the anchor in `anchor_root` when one is configured
    /// (CALLS CUSTODY_ANCHOR_ROOT). A step that does not go through stays
    /// pending by name in the status; nothing is refused for it. The anchor
    /// root must lie outside the vault and its custody.
    pub fn publish_custody(
        &self,
        folder: &Path,
        anchor_root: Option<&Path>,
    ) -> Result<CustodyStatus> {
        if let Some(root) = anchor_root {
            self.refuse_anchor_inside(root)?;
        }
        let recipients = self.custody_recipients()?;
        let target = FolderTarget::at(folder.to_path_buf());
        let anchor = anchor_root.map(|root| FileAnchor::at(root.to_path_buf()));
        Ok(CustodyStatus::of(self.store.publish_custody(
            &recipients,
            &target,
            anchor.as_ref().map(|anchor| anchor as &dyn AnchorStore),
        )?))
    }

    /// Where this vault's custody publication stands, from the last pass:
    /// the owner's status read.
    pub fn custody_status(&self) -> Result<CustodyStatus> {
        Ok(CustodyStatus::of(self.store.custody_publication()?))
    }

    /// An anchor kept inside the vault, or beside it in its custody, rolls
    /// back with what it should prove current.
    fn refuse_anchor_inside(&self, root: &Path) -> Result<()> {
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let home = self.store.env.path();
        let custody = home.with_file_name(format!(
            ".{}.key-custody",
            home.file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default()
        ));
        if root.starts_with(home) || root.starts_with(&custody) {
            return Err(crate::Error::InvalidConfig(
                "the custody anchor root must lie outside the vault and its key custody".into(),
            ));
        }
        Ok(())
    }

    /// [`Vault::restore_checkpoint_finishing`], recovering the image's key
    /// custody from `recovery` when it is not on this host. An image that
    /// names a custody head is admitted from the head beside the backup:
    /// against the configured anchor, refused when that anchor is missing
    /// or stale, or the head's seal, chain or coverage is bad; with no anchor
    /// configured, used as it is, and the report's `custody_note` says
    /// rollback is not proven. Its custody lands beside `destination` in the
    /// image's own namespace, every retirement first, at the next writer
    /// epoch, which the anchor's advance fences before the vault is kept. An
    /// image that names no head, restored where its custody is not, drops
    /// its claim-bound rows whose keys stayed on the old host and names them
    /// in `dropped_gate_decisions`. A restore whose custody is on this host
    /// restores as before.
    pub fn restore_checkpoint_recovering(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        restored_at: u64,
        recovery: &CustodyRecovery<'_>,
        finish: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_keeping_custody(
            path,
            key,
            destination,
            config,
            (RestoreReason::Restore, restored_at),
            Some(recovery),
            finish,
        )
    }

    /// Every restore that keeps its image's custody. With no `recovery`, an
    /// image whose head-named custody is not on this host refuses; a wake
    /// or a migration never drops a row.
    pub(super) fn restore_keeping_custody(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        (reason, restored_at): (RestoreReason, u64),
        recovery: Option<&CustodyRecovery<'_>>,
        finish: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<(Self, RestoreReport)> {
        let (mut image, checkpoint_id, bodies, required) = read_image_required(path, key)?;
        image.drop_machine_identity();
        let source = recovery.map(|recovery| CustodySourceAt {
            folder: &recovery.folder,
            anchor_root: recovery.anchor_root.as_deref(),
            root: recovery.root,
        });
        let route = route_custody(
            image
                .databases
                .get_mut("vault_meta")
                .ok_or_else(codec_error)?,
            required.as_ref(),
            &std::path::absolute(destination)?,
            key.custody_wrap(),
            source.as_ref(),
        )?;
        let (custody, landing) = match route {
            CustodyRoute::Local => (Custody::Keep, None),
            CustodyRoute::Landed(landing) => (Custody::Keep, Some(landing)),
            CustodyRoute::Absent if reason == RestoreReason::Restore => (Custody::NewHost, None),
            CustodyRoute::Absent => (Custody::Keep, None),
        };
        let (made, forked, mut vault, mut report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            reason,
            restored_at,
            custody,
            &BTreeSet::new(),
            &write_budget::Unfloored,
        )?;
        finish(&vault)?;
        if let Some(landing) = &landing {
            landing.fence()?;
            report.custody_note = landing.note().map(str::to_owned);
        }
        forked.keep();
        made.keep(&mut vault);
        if let Some(landing) = landing {
            landing.keep();
        }
        Ok((vault, report))
    }
}

/// The self-host anchor door (`/v1/owner/custody-anchor`): keyless read and
/// compare-and-swap advance of a lineage's record in an owner-selected
/// anchor root. The store checks that an advance extends the anchored
/// position; the reader checks the record's tag under its head's control
/// secret.
pub struct CustodyAnchorRoot {
    anchor: FileAnchor,
}

impl CustodyAnchorRoot {
    pub fn at(root: PathBuf) -> Self {
        Self {
            anchor: FileAnchor::at(root),
        }
    }

    /// The current record of the lineage `namespace` of vault `vault`, if
    /// it has one.
    pub fn read(&self, vault: [u8; 32], namespace: [u8; 16]) -> Result<Option<Vec<u8>>> {
        self.anchor.read_raw(vault, namespace)
    }

    /// Makes `record` its lineage's current one while the current one is
    /// still the one whose BLAKE3 is `expected` (`None`: none yet). `false`
    /// when another writer moved it first.
    pub fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> Result<bool> {
        Ok(self.anchor.advance(expected, record)? == AnchorAdvance::Advanced)
    }
}
