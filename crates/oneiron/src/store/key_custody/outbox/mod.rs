//! The Hypnos outbox target (FIX 5899): a managed vault's hosted custody
//! holder. The engine stages each exact batch in the outbox its supervisor
//! names, Hypnos ships it to the control plane, and the control plane's
//! acknowledgement comes back as a file the engine takes in.
//!
//! `<outbox>/<namespace hex>.<vault hex>/<target id hex>/` is one member's
//! slot. It holds at most one outstanding batch, `b.<operation id>.r<set
//! revision>/` ([`files`]): its `meta.json`, the exact sealed `head`, the
//! keyless `log/f<seq hex16>` frames the member lacks with their
//! `frames.jsonl` inventory, and `READY`, written last. Hypnos ships a
//! batch once it is READY and writes the control plane's `ack.json` beside
//! it (or an optional `pending.json`). Newer changes wait for the next
//! batch: the outstanding one is never replaced, and no queue fills.
//!
//! A keyless record of the outstanding batch is kept in the lineage's
//! journal before a byte is staged ([`replay`]), so a restart takes the
//! original batch's ack in without sealing it again. A pass takes an ack in
//! before it reads the acks: checked against that record, the record keeps
//! it, every local copy of the batch is removed and synced, and only then
//! does the journal accept it. Everything that does not go through stays
//! pending by name; nothing here refuses a save, backup, restore or start.

mod files;
mod replay;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use self::replay::{Found, Retained, examine, keep, load, release};
use super::anchor::extends;
use super::files::open_dir;
use super::folder::newer_head;
use super::log::Journal;
use super::protocol::{
    CustodyBatch, CustodySource, CustodyTarget, Lineage, PendingCode, TargetId, TargetPending,
    TargetPublication, TargetSpec, hex,
};

/// What a member whose batch waits on the control plane reads.
const AWAITING: &str = "awaiting CP custody acknowledgement";

/// One Hypnos outbox member, staged under its managed host's outbox.
pub(crate) struct OutboxTarget {
    /// `<escrow outbox>/custody`, which the engine makes itself.
    root: PathBuf,
    /// The vault's name as its supervisor gave it (`--vault-name`), which
    /// each batch's metadata carries; Hypnos fences it again.
    vault_name: String,
    spec: TargetSpec,
}

impl OutboxTarget {
    /// The member `spec`, staged under `root` for the vault the supervisor
    /// names `vault_name`.
    pub(crate) fn new(root: PathBuf, vault_name: String, spec: TargetSpec) -> Self {
        Self {
            root,
            vault_name,
            spec,
        }
    }

    pub(crate) fn id(&self) -> &TargetId {
        self.spec.id()
    }

    /// The member's slot for `lineage`, each directory made owner-only when
    /// missing.
    fn open_slot(&self, lineage: Lineage) -> Result<PathBuf> {
        let (vault, namespace) = lineage.to_hex();
        let dir = self.root.join(format!("{namespace}.{vault}"));
        let slot = dir.join(hex(self.id().as_str().as_bytes()));
        for path in [&self.root, &dir, &slot] {
            open_dir(path, true, None)?;
        }
        Ok(slot)
    }

    /// Stages `batch` in the member's slot, unless one is outstanding there.
    fn stage(&self, journal: &Journal, batch: &CustodyBatch) -> Result<TargetPublication> {
        let slot = self.open_slot(batch.lineage())?;
        let _lock = files::lock(&slot)?;
        if let Some(retained) = load(journal, self.id())? {
            // One batch at a time: what changed since waits for the next.
            return Ok(TargetPublication::Pending(
                self.outstanding(journal, &slot, &retained)?,
            ));
        }
        let position = batch.position();
        let held = journal
            .acks()?
            .remove(self.id())
            .and_then(|ack| ack.position.position());
        // Under the slot lock, through the staging: once a newer batch's ack
        // is taken in, an older pass's batch is never staged after it. It is
        // covered, not pending (FIX 6394).
        if let Some(held) = held.filter(|held| !extends(held, &position)) {
            return Ok(newer_head(&held, batch));
        }
        // The control plane holds every frame through the position it
        // acknowledged in this epoch.
        let after = held
            .filter(|held| held.epoch == position.epoch)
            .map_or(0, |held| held.seq);
        // Nothing this journal does not record stays for Hypnos to ship.
        files::sweep(&slot)?;
        let facts = batch.facts();
        keep(journal, self.id(), &facts, None)?;
        let meta = files::meta(&self.vault_name, &self.spec, &facts)?;
        if let Err(error) = files::write_batch(&slot, &self.spec, batch, after, &meta) {
            // Nothing half-staged is left, and the next pass seals afresh.
            let _ = files::sweep(&slot);
            let _ = release(journal, self.id());
            return Err(error);
        }
        Ok(TargetPublication::Pending(pending(
            PendingCode::Offline,
            AWAITING,
        )))
    }

    /// Why the member's outstanding batch is not acknowledged yet.
    fn outstanding(
        &self,
        journal: &Journal,
        slot: &Path,
        retained: &Retained,
    ) -> Result<TargetPending> {
        if retained.ack.is_some() {
            return Ok(pending(
                PendingCode::Failed,
                "the CP acknowledged the custody batch, but its local outbox copy is not removed \
                 or the journal has not taken the ack yet; the next pass retries",
            ));
        }
        Ok(match examine(journal, slot, &self.spec, &retained.facts)? {
            Found::Gone => pending(
                PendingCode::Offline,
                "the custody batch left the outbox before the CP acknowledged it; the next pass \
                 stages it again",
            ),
            Found::Unmarked | Found::Waiting(None) => pending(PendingCode::Offline, AWAITING),
            Found::Waiting(Some(note)) => note,
            Found::Acked(_) => pending(
                PendingCode::Offline,
                "the CP acknowledged the custody batch; the next pass takes it in",
            ),
            Found::Refused(why) => pending(PendingCode::Failed, why),
        })
    }
}

fn pending(code: PendingCode, detail: &str) -> TargetPending {
    TargetPending {
        code,
        detail: detail.to_owned(),
    }
}

/// An outbox the pass cannot use: missing, full, read-only or not the
/// vault's own. Pending by name, never a refusal.
fn unusable(error: &Error) -> TargetPending {
    let Error::Io(io) = error else {
        return pending(PendingCode::Failed, &error.to_string());
    };
    match io.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem => pending(
            PendingCode::Locked,
            "the custody outbox is not writable; the next pass retries",
        ),
        std::io::ErrorKind::StorageFull => pending(
            PendingCode::Locked,
            "the custody outbox's disk is full; the next pass retries",
        ),
        std::io::ErrorKind::NotFound => pending(
            PendingCode::Offline,
            "the custody outbox is not there; the next pass retries",
        ),
        _ => pending(
            PendingCode::Offline,
            "the custody outbox is not reachable; the next pass retries",
        ),
    }
}

/// The control plane is no restore source through the outbox.
impl CustodySource for OutboxTarget {
    fn head(&self, _: Lineage) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn frame(&self, _: Lineage, _: u64) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

impl CustodyTarget for OutboxTarget {
    fn spec(&self) -> TargetSpec {
        self.spec.clone()
    }

    /// Stages `batch` and answers pending until the control plane's ack is
    /// taken in by a later pass ([`OutboxTarget::take_in`]).
    fn publish(&self, batch: &CustodyBatch) -> Result<TargetPublication> {
        let journal = Journal::of_batch(batch);
        Ok(self
            .stage(&journal, batch)
            .unwrap_or_else(|error| TargetPublication::Pending(unusable(&error))))
    }
}
