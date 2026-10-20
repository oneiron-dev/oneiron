//! Custody heads at the vault's surface (KS-4A1/KS-4A2, FIX 5685):
//! publishing a vault's exterior key custody to every required target, the
//! owner's status read of it and of its retirements, the self-host anchor
//! door, the drivers that publish on their own channel, and the restore that
//! recovers custody from a head on a host that lacks it.
//!
//! The head always publishes, sealed and recovery-wrapped, to the folder
//! beside the backups and to every other member of the required target set;
//! the anchor is the one optional step (Engine 10-20 04:0x). A restore that
//! keeps its image's custody where that custody is not on this host takes
//! one of three routes: a head the image names is admitted (fail-closed
//! against a configured anchor; used as it is, and said so, with none) and
//! landed beside the destination; an image for which no head is found (none
//! named, none beside the backup with no anchor to owe one, or an entry
//! point that reads none: a wake, a migration, an engine restore), or one
//! carrying only the legacy untyped marker, drops and names its claim-bound
//! rows whose keys stayed on the old host; and everything else restores as
//! before. Archive targets and the kit share the one source and validator:
//! only the opener differs, the data key the backup unlocked with or the
//! kit's recovery root.

mod status;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heed::RoTxn;
use oneiron_crypto::HybridSecretKey;

pub use self::status::{
    CUSTODY_ANCHOR_PENDING, CUSTODY_FENCED, CUSTODY_NONE, CUSTODY_PUBLISHED,
    CUSTODY_RETIREMENT_COMPLETE, CUSTODY_RETIREMENT_PENDING, CUSTODY_TARGET_PENDING,
    CustodyPendingStep, CustodyRetirement, CustodyStatus, CustodyTargetState, DeclaredTarget,
};
use super::{
    CheckpointKey, Custody, RestoreReason, RestoreReport, codec_error, read_image_required,
    write_budget,
};
use crate::store::custody_protocol::{
    AckRecord, AnchorAdvance, AnchorStore, CustodyBatch, CustodyNamespace, CustodyTarget,
    CustodyVaultId, HostedKind, TargetId, TargetKind, TargetPending, TargetSpec,
};
use crate::store::{
    CUSTODY_HEAD_WRAP_CONTEXT, CustodyKind, CustodyRecipients, CustodyRoute, CustodySourceAt,
    FileAnchor, FolderTarget, OutboxTarget, Publication, route_custody,
    standing_retirements_in_txn,
};
use crate::{Result, Vault, VaultConfig};

/// Where a restore on a host without its image's custody finds the head:
/// the folder beside the backup (`<folder>/oneiron-custody/`), the anchor
/// when one is configured (a root or a door), and the kit's recovery root
/// when the restore was unlocked with the kit.
pub struct CustodyRecovery<'a> {
    folder: PathBuf,
    anchor: Option<Box<dyn AnchorStore + 'a>>,
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
            anchor: None,
            root: None,
        }
    }

    /// Checked against the anchor in `root`, when one is configured (CALLS
    /// CUSTODY_ANCHOR_ROOT); `None` uses the head as it is, and the restore
    /// says rollback is not proven.
    pub fn anchored_at(mut self, root: Option<PathBuf>) -> Self {
        if let Some(root) = root {
            self.anchor = Some(Box::new(FileAnchor::at(root)));
        }
        self
    }

    /// Checked against `anchor`, another install's anchor door or a hosted
    /// one (FIX 5788).
    pub fn anchored_by(mut self, anchor: Box<dyn AnchorStore + 'a>) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// Opened with the kit's recovery root as well as the backup's data
    /// key: every compartment, the owner-only ones too.
    pub fn with_kit(mut self, root: &'a HybridSecretKey) -> Self {
        self.root = Some(root);
        self
    }

    fn anchor(&self) -> Option<&dyn AnchorStore> {
        self.anchor
            .as_deref()
            .map(|anchor| anchor as &dyn AnchorStore)
    }

    /// Where the head is read, its anchor and what opens it.
    pub(super) fn source(&self) -> CustodySourceAt<'_> {
        CustodySourceAt {
            folder: &self.folder,
            anchor: self.anchor(),
            root: self.root,
        }
    }
}

/// The Hypnos outbox a managed vault's hosted custody ships through (FIX
/// 5899): `custody/` under the escrow outbox its supervisor names, and the
/// vault's name as the supervisor gave it. A declared `outbox:` member is
/// staged there, one exact batch at a time, and acknowledged by the control
/// plane's ack Hypnos writes back; without one it stays `no_adapter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyOutbox {
    root: PathBuf,
    vault_name: String,
}

impl CustodyOutbox {
    /// The outbox at `root`, which the engine makes when missing, for the
    /// vault named `vault_name`.
    pub fn at(root: PathBuf, vault_name: String) -> Self {
        Self { root, vault_name }
    }
}

impl Vault {
    /// Who this vault's custody heads are wrapped to: its pinned recovery
    /// root (the kit keeps only its seed), and its data key's custody
    /// subkey while the key is held. Neither is a reason to refuse: a pass
    /// with neither stays pending.
    pub(crate) fn custody_recipients(&self) -> Result<CustodyRecipients> {
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
    /// directory), every folder member registered before, and every
    /// `declared` member (a hosted holder this build has no adapter for
    /// stays pending as `no_adapter`); then `anchor` when one is configured
    /// (CALLS CUSTODY_ANCHOR_ROOT), once every member acknowledged the head;
    /// then the completion watermark. A step that does not go through stays
    /// pending by name in the status; nothing is refused for it.
    pub fn publish_custody(
        &self,
        folder: &Path,
        declared: &[TargetSpec],
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<CustodyStatus> {
        let folder = FolderTarget::at(folder.to_path_buf());
        self.publish_custody_claiming(folder, declared, None, anchor)
    }

    /// [`Vault::publish_custody`] with the folder's frames and head claimed
    /// on `room` first, the floor a backup's landing disk keeps (FIX 5858):
    /// a claim the floor refuses leaves the folder pending by name.
    pub fn publish_custody_within(
        &self,
        folder: &Path,
        declared: &[TargetSpec],
        anchor: Option<&dyn AnchorStore>,
        room: Box<dyn super::RecoveryWriteBudget>,
    ) -> Result<CustodyStatus> {
        let folder = FolderTarget::at(folder.to_path_buf()).claiming(room);
        self.publish_custody_claiming(folder, declared, None, anchor)
    }

    /// [`Vault::publish_custody_within`], every declared `outbox:` member
    /// shipped through `outbox` (FIX 5899): its acknowledged batch taken in,
    /// then, once none is outstanding, the batch staged there. Its bulk
    /// writes belong in a background pass, never a backup's response.
    pub fn publish_custody_shipping(
        &self,
        folder: &Path,
        declared: &[TargetSpec],
        outbox: &CustodyOutbox,
        anchor: Option<&dyn AnchorStore>,
        room: Box<dyn super::RecoveryWriteBudget>,
    ) -> Result<CustodyStatus> {
        let folder = FolderTarget::at(folder.to_path_buf()).claiming(room);
        self.publish_custody_claiming(folder, declared, Some(outbox), anchor)
    }

    fn publish_custody_claiming(
        &self,
        folder: FolderTarget,
        declared: &[TargetSpec],
        outbox: Option<&CustodyOutbox>,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<CustodyStatus> {
        let recipients = self.custody_recipients()?;
        let shipped: Vec<OutboxTarget> = declared
            .iter()
            .filter(|spec| spec.kind() == TargetKind::Hosted(HostedKind::HypnosOutbox))
            .filter_map(|spec| {
                let outbox = outbox?;
                Some(OutboxTarget::new(
                    outbox.root.clone(),
                    outbox.vault_name.clone(),
                    spec.clone(),
                ))
            })
            .collect();
        let declared: Vec<DeclaredTarget> = declared
            .iter()
            .filter(|spec| !shipped.iter().any(|target| target.id() == spec.id()))
            .cloned()
            .map(DeclaredTarget::new)
            .collect();
        let mut targets: Vec<&dyn CustodyTarget> = vec![&folder];
        targets.extend(shipped.iter().map(|target| target as &dyn CustodyTarget));
        targets.extend(declared.iter().map(|target| target as &dyn CustodyTarget));
        let outboxes: Vec<&OutboxTarget> = shipped.iter().collect();
        let publication = self
            .store
            .publish_custody(&recipients, &targets, &outboxes, anchor)?;
        self.custody_status_of(publication)
    }

    /// Where this vault's custody publication and retirements stand, from
    /// the last pass and the journal: the owner's status read.
    pub fn custody_status(&self) -> Result<CustodyStatus> {
        self.custody_status_of(self.store.custody_publication()?)
    }

    /// What an activation reports about the custody it forked (FIX 6033),
    /// from its publication status, as a restore reports its landing's:
    /// rollback is not proven while no anchor is configured. A status that
    /// cannot be read is logged and left out; it never fails the
    /// activation it rides on.
    pub(super) fn activation_custody_note(&self) -> Option<String> {
        match self.store.custody_publication() {
            Ok(publication) => status::rollback_note(&publication).map(str::to_owned),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "an activation's custody note could not be read");
                None
            }
        }
    }

    fn custody_status_of(&self, publication: Publication) -> Result<CustodyStatus> {
        let standing = standing_retirements_in_txn(&self.store, &self.store.env.read_txn()?)?;
        let retirement =
            status::retirement(self.store.custody_retirement()?, standing, &publication);
        Ok(CustodyStatus::of(publication, retirement))
    }

    /// The self-host anchor in `root`, refused when it lies inside the vault
    /// or beside it in its custody: such an anchor rolls back with what it
    /// should prove current.
    pub fn custody_anchor_root(&self, root: &Path) -> Result<CustodyAnchorRoot> {
        let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let home = self.store.env.path();
        let custody = home.with_file_name(format!(
            ".{}.key-custody",
            home.file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default()
        ));
        if canonical.starts_with(home) || canonical.starts_with(custody) {
            return Err(crate::Error::InvalidConfig(
                "the custody anchor root must lie outside the vault and its key custody".into(),
            ));
        }
        Ok(CustodyAnchorRoot::at(root.to_path_buf()))
    }

    /// For a member that publishes on its own channel (a hosted adapter):
    /// registers `spec` in the required set before its first exposure and,
    /// when it is behind the local log position, seals a batch for it.
    /// `None` when it is current or nothing is in custody.
    pub fn custody_batch_for(&self, spec: &TargetSpec) -> Result<Option<CustodyBatch>> {
        let recipients = self.custody_recipients()?;
        self.store.custody_batch_for(spec, &recipients)
    }

    /// Accepts a member's acknowledgement of `batch`, once it names exactly
    /// that batch: stored durably in the journal.
    pub fn accept_custody_ack(&self, batch: &CustodyBatch, ack: &AckRecord) -> Result<()> {
        self.store.accept_custody_ack(batch, ack)
    }

    /// Records why `target` is still pending, by name on the status read.
    pub fn note_custody_pending(&self, target: &TargetId, pending: &TargetPending) -> Result<()> {
        self.store.note_custody_pending(target, pending)
    }

    /// The custody steps an erase of the records `erased` (their 16-byte
    /// ids) still owes, for its receipt's read: `None` when none of their
    /// keys was ever in custody here. Their claim keys, the body instances
    /// the erase retired or owes (KS-2A) and a custody record's known-value
    /// history (KS-3) count alike. Each
    /// handed-off retirement is complete once the watermark passed it;
    /// until then, every member behind it and the anchor are owed (with no
    /// anchor configured, every member's ack completes it, rollback not
    /// proven). An intent not handed off yet is `custody_retirement_pending`,
    /// and a body another holder still keeps is `body_shared_owner_retained`.
    pub(crate) fn erase_custody_in_txn(
        &self,
        txn: &RoTxn<'_>,
        erased: &[[u8; 16]],
    ) -> Result<Option<(&'static str, Vec<String>, Option<&'static str>)>> {
        let mut owed = EraseOwed::default();
        for record in erased {
            let Some(subject) = self
                .store
                .custody_subject(CustodyKind::ClaimDecision, record)?
            else {
                return Ok(None);
            };
            owed.subject(&self.store, txn, &subject)?;
            if let Some(history) = self
                .store
                .custody_subject(CustodyKind::KnownValueEntry, record)?
            {
                owed.subject(&self.store, txn, &history)?;
            }
            #[cfg(unix)]
            for instance in self
                .store
                .erased_body_instances_in_txn(txn, &crate::EntityId::from_bytes(*record)?)?
            {
                owed.found = true;
                if self
                    .store
                    .body_erase_waits_on_holder_in_txn(txn, &instance)?
                {
                    owed.step(BODY_SHARED_OWNER_RETAINED);
                    continue;
                }
                if let Some(binding) = self.store.body_custody() {
                    let id = crate::store::instance_id(&binding, &instance)?;
                    owed.subject(&self.store, txn, id.subject())?;
                }
            }
        }
        let publication = self.store.custody_publication()?;
        if let Some(newest) = owed.newest
            && let Some(progress) = self.store.custody_retirement()?
            && progress
                .completed
                .is_none_or(|completed| completed < newest)
        {
            owed.steps
                .extend(status::owed(&progress, &publication, newest));
        }
        Ok(owed.found.then(|| {
            (
                if owed.steps.is_empty() {
                    CUSTODY_RETIREMENT_COMPLETE
                } else {
                    CUSTODY_RETIREMENT_PENDING
                },
                owed.steps.iter().map(CustodyPendingStep::name).collect(),
                status::rollback_note(&publication),
            )
        }))
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
    /// image for which no head is found, restored where its custody is not,
    /// drops its claim-bound rows whose keys stayed on the old host and names
    /// them in `dropped_gate_decisions`. A restore whose custody is on this
    /// host restores as before.
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

    /// Every restore that keeps its image's custody. With no `recovery` (a
    /// wake, a migration, an engine restore), an image whose custody is not
    /// on this host drops and names its claim-bound rows whose keys stayed
    /// behind, and completes; none refuses for it (Engine 10-20 05:2x).
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
        let anchor = recovery.and_then(|recovery| recovery.anchor());
        let source = recovery.map(CustodyRecovery::source);
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
            CustodyRoute::Absent => (Custody::NewHost, None),
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
            landing.fence(anchor)?;
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

/// The self-host anchor (`/v1/owner/custody-anchor`, and an install that
/// anchors to a directory it mounts): keyless read and compare-and-swap
/// advance of a lineage's record in an owner-selected anchor root. The
/// store checks that an advance extends the anchored position; the reader
/// checks the record's tag under its head's control secret.
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
        self.anchor.read(
            CustodyVaultId::from_bytes(vault),
            CustodyNamespace::from_bytes(namespace),
        )
    }

    /// Makes `record` its lineage's current one while the current one is
    /// still the one whose BLAKE3 is `expected` (`None`: none yet). `false`
    /// when another writer moved it first.
    pub fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> Result<bool> {
        Ok(self.anchor.advance(expected, record)? == AnchorAdvance::Advanced)
    }
}

impl AnchorStore for CustodyAnchorRoot {
    fn read(&self, vault: CustodyVaultId, namespace: CustodyNamespace) -> Result<Option<Vec<u8>>> {
        self.anchor.read(vault, namespace)
    }

    fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> Result<AnchorAdvance> {
        self.anchor.advance(expected, record)
    }
}

/// An erased body whose instance another holder still keeps: its key
/// retires with that holder's release (KS-2A).
pub const BODY_SHARED_OWNER_RETAINED: &str = "body_shared_owner_retained";

/// What an erase's receipt read has found its keys still owe.
#[derive(Default)]
struct EraseOwed {
    found: bool,
    steps: Vec<CustodyPendingStep>,
    newest: Option<u64>,
}

impl EraseOwed {
    /// Notes `state` once.
    fn step(&mut self, state: &'static str) {
        if self.steps.iter().all(|step| step.state != state) {
            self.steps.push(CustodyPendingStep {
                state,
                target_id: None,
                reason: None,
            });
        }
    }

    /// Notes what `subject`'s retirement still owes: an intent not handed
    /// off, or the newest obligation not complete.
    fn subject(
        &mut self,
        store: &crate::store::Store,
        txn: &RoTxn<'_>,
        subject: &crate::store::CustodySubject,
    ) -> Result<()> {
        if crate::store::retirement_in_txn(store, txn, subject)?.is_some() {
            self.found = true;
            self.step(CUSTODY_RETIREMENT_PENDING);
        }
        for (seq, done) in store.custody_obligations_of(subject)? {
            self.found = true;
            if !done {
                self.newest = self.newest.max(Some(seq));
            }
        }
        Ok(())
    }
}
