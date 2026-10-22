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
//! only the opener differs, the data key the backup unlocked with, the
//! kit's recovery root, or an admitted machine's key (FIX 9178): a world's
//! pads open only with the kit or a machine that world admits.

mod pad_worlds;
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
    CustodyVaultId, HostedKind, PendingCode, TargetId, TargetKind, TargetPending, TargetSpec,
};
use crate::store::{
    CUSTODY_HEAD_WRAP_CONTEXT, CustodyKind, CustodyRecipients, CustodyRoute, CustodySourceAt,
    FileAnchor, FolderTarget, OutboxTarget, Publication, TargetRecipients, route_custody,
    standing_retirements_in_txn,
};
use crate::{EntityId, Result, Vault, VaultConfig};

/// Where a restore on a host without its image's custody finds the head:
/// the folder beside the backup (`<folder>/oneiron-custody/`), the anchor
/// when one is configured (a root or a door), the kit's recovery root when
/// the restore was unlocked with the kit, and an admitted machine's key when
/// one is given.
pub struct CustodyRecovery<'a> {
    folder: PathBuf,
    anchor: Option<Box<dyn AnchorStore + 'a>>,
    root: Option<&'a HybridSecretKey>,
    machine: Option<(EntityId, &'a HybridSecretKey)>,
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
            machine: None,
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
    /// key: every compartment, the owner-only ones too, but a world's whose
    /// current key is not wrapped to that root (FIX 9178).
    pub fn with_kit(mut self, root: &'a HybridSecretKey) -> Self {
        self.root = Some(root);
        self
    }

    /// Opened with the key of `machine`, one of the owner's machines, as
    /// well (FIX 9178): the pad compartments of the worlds that admit it,
    /// nothing else. It admits no machine; a key the head names no wrap for
    /// opens nothing.
    pub fn with_machine(mut self, machine: EntityId, secret: &'a HybridSecretKey) -> Self {
        self.machine = Some((machine, secret));
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
            machine: self.machine,
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

/// Why a custody publication pass stays pending before its policy is noted,
/// any head sealed or anything shipped (FIX 8825). Local writes and content
/// backups go on; the next pass reads the policy then current again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CustodyPublicationPending {
    /// The worlds whose pads stay off a head did not read: no head is sealed
    /// under a guessed, stale or empty exclusion set.
    PadEligibilityUnreadable { error_kind: crate::ErrorKind },
}

impl CustodyPublicationPending {
    /// The status read's words for it, naming no secret: what failed, its
    /// kind, and the owner's repair and retry.
    fn detail(self) -> String {
        match self {
            Self::PadEligibilityUnreadable { error_kind } => format!(
                "custody_pad_eligibility_unreadable ({error_kind:?}): which worlds' pads stay \
                 off a head did not read, so no head was sealed; repair the world policy, and \
                 the next publication pass retries under the policy then current"
            ),
        }
    }
}

impl Vault {
    /// Who this vault's custody heads are wrapped to: its pinned recovery
    /// root (the kit keeps only its seed), and its data key's custody
    /// subkey while the key is held. Neither is a reason to refuse: a pass
    /// with neither stays pending. `hosted`: the head goes to a hosted
    /// member, which the pads of some worlds stay off (KS-5); a lookup of
    /// those worlds that faults leaves the pass pending (FIX 8825), never an
    /// empty exclusion set.
    pub(crate) fn custody_recipients(
        &self,
        hosted: bool,
    ) -> Result<std::result::Result<CustodyRecipients, CustodyPublicationPending>> {
        let pad_worlds_kept_local = match self.pad_worlds_kept_local(hosted) {
            Ok(kept) => kept,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a custody head's pad eligibility could not be read; the pass stays pending"
                );
                return Ok(Err(CustodyPublicationPending::PadEligibilityUnreadable {
                    error_kind: error.kind(),
                }));
            }
        };
        // KS-6: the credentials whose keys may ride a head; a lookup that
        // faults keeps every credential's in this machine's custody, where
        // they all stay today.
        let credentials_eligible = crate::secret_custody::credentials_eligible_for_heads(self)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a custody head's credential eligibility could not be read; every \
                     credential's keys stay local"
                );
                Default::default()
            });
        let data_key = self
            .unlock_vault_key()
            .and_then(|()| self.vault_subkey(CUSTODY_HEAD_WRAP_CONTEXT))
            .ok();
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let root = self
            .pinned_root_recipient_in_txn(&txn, &fold)?
            .map(|root| (root.id.0, root.key));
        // Each world's admitted machines and roots (FIX 9178), which alone
        // its pad compartment is wrapped to.
        let pad_worlds = self.pad_world_recipients_in_txn(&txn, &fold, &pad_worlds_kept_local);
        Ok(Ok(CustodyRecipients {
            root,
            data_key,
            pad_worlds_kept_local,
            credentials_eligible,
            pad_worlds,
        }))
    }

    /// [`Self::custody_recipients`] for each kind of member (KS-5, FIX
    /// 7191): a hosted member's head apart from a folder's or the residence
    /// home's, so a hosted head never strips a pad a folder may keep. Either
    /// kind's pending leaves the whole pass pending (FIX 8825).
    fn custody_target_recipients(
        &self,
    ) -> Result<std::result::Result<TargetRecipients, CustodyPublicationPending>> {
        let own = match self.custody_recipients(false)? {
            Ok(own) => own,
            Err(pending) => return Ok(Err(pending)),
        };
        Ok(self
            .custody_recipients(true)?
            .map(|hosted| TargetRecipients { own, hosted }))
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

    /// One publication pass, then, once its locks are released, the final
    /// receipt row of every erase whose last custody retirement it completed
    /// (FIX 5844): the pass never fails for that row.
    fn publish_custody_claiming(
        &self,
        folder: FolderTarget,
        declared: &[TargetSpec],
        outbox: Option<&CustodyOutbox>,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<CustodyStatus> {
        let status = self.publish_custody_pass(folder, declared, outbox, anchor)?;
        self.finish_redaction_erases_logged();
        Ok(status)
    }

    fn publish_custody_pass(
        &self,
        folder: FolderTarget,
        declared: &[TargetSpec],
        outbox: Option<&CustodyOutbox>,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<CustodyStatus> {
        // The policy each head follows is read, journaled when it changed
        // and sealed under one lock held for the pass: no pass seals an
        // older policy at a newer log position (KS-5, FIX 7191).
        let _policy = self.store.custody_policy_guard()?;
        let recipients = match self.custody_target_recipients()? {
            Ok(recipients) => recipients,
            // Nothing is noted, sealed or shipped under a policy this pass
            // could not read: it stays pending by name (FIX 8825).
            Err(pending) => {
                let publication = self.store.note_publication_pending(&pending.detail())?;
                return self.custody_status_of(publication);
            }
        };
        self.store.note_custody_policy(&recipients)?;
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
    /// `None` when it is current or nothing is in custody, and when the
    /// policy did not read (FIX 8825): then nothing is sealed, the member is
    /// noted pending by name and the next call reads the policy again.
    pub fn custody_batch_for(&self, spec: &TargetSpec) -> Result<Option<CustodyBatch>> {
        // As a publication pass: the policy read, journaled when it changed
        // and sealed under the policy lock (KS-5, FIX 7191).
        let _policy = self.store.custody_policy_guard()?;
        let recipients = match self.custody_target_recipients()? {
            Ok(recipients) => recipients,
            Err(pending) => {
                let why = TargetPending {
                    code: PendingCode::Failed,
                    detail: pending.detail(),
                };
                self.store.note_custody_pending(spec.id(), &why)?;
                return Ok(None);
            }
        };
        self.store.note_custody_policy(&recipients)?;
        self.store.custody_batch_for(spec, recipients.of(spec))
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
    /// history (KS-3) count alike, and so do an erased credential's
    /// discovery and every key its id names (KS-6 part 2): its discovery
    /// owed reads pending, even with nothing in custody here. Each
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
                // Unbound: no key was ever in custody here, but an erased
                // credential's owed discovery still reads pending.
                for record in erased {
                    owed.credential(&self.store, txn, record);
                }
                let pending = owed.steps.iter().map(CustodyPendingStep::name).collect();
                return Ok(owed
                    .found
                    .then_some((CUSTODY_RETIREMENT_PENDING, pending, None)));
            };
            owed.subject(&self.store, txn, &subject)?;
            owed.credential(&self.store, txn, record);
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
            CustodyRoute::Landed(landing) => (Custody::Landed, Some(landing)),
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

    /// Notes what erased credential `record` still owes (KS-6 part 2): its
    /// discovery while owed, and each key its id names. A read that faults
    /// is warned and reads pending, never complete.
    fn credential(&mut self, store: &crate::store::Store, txn: &RoTxn<'_>, record: &[u8; 16]) {
        let read = (|| -> Result<()> {
            let credential = EntityId::from_bytes(*record)?;
            let Some((discovery_owed, subjects)) =
                store.credential_erase_debt_in_txn(txn, &credential)?
            else {
                return Ok(());
            };
            if discovery_owed {
                self.found = true;
                self.step(CUSTODY_RETIREMENT_PENDING);
            }
            for subject in &subjects {
                self.subject(store, txn, subject)?;
            }
            Ok(())
        })();
        if let Err(error) = read {
            tracing::warn!(
                kind = ?error.kind(),
                "an erased credential's custody did not read; its erase reads pending"
            );
            self.found = true;
            self.step(CUSTODY_RETIREMENT_PENDING);
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
