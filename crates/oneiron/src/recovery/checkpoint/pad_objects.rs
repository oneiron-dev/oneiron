//! The home's current pad objects on a restore beside its source, a restore
//! over or keeping a live vault's authority, and an activation (PAD-1, the
//! L02 half of L03 pack 02A; FIX 7106 copy half, 9362/10323 CurrentProvider
//! half). The source's objects, sealed and opaque, are captured in the
//! transaction its custody is read in (`store` `PadObjectsCapture`), then
//! installed over the copy's own once its rows landed, while the copy still
//! holds what it read there, and read back in the install's transaction and
//! again after it committed. A kept generation whose object is still not
//! whole here takes its bytes from that capture when it carries the same
//! object ([`refill_pad_object`], its current provider source).
//!
//! An install never brings back a generation the copy does not keep, never
//! touches a bundle, and never stands for a pad: a world key pad lands only
//! through `pad_custody`, and the epoch's pad debt is reconciled apart by
//! the shared resolver. An erase's rewrite the source holds takes the place
//! of the copy's older object, so an exact key the source's erase retired
//! does not come back from the copy's (restricts, ruled). Every new fault
//! keeps what the copy holds, with a value-free note: never a refusal.

#[cfg(feature = "sync")]
use std::collections::BTreeSet;

use super::{LiveCustody, RestoreReport, SideRestoreSource, Source};
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::store::UncapturedPadObjects;
use crate::store::{PadObjectsCapture, PadObjectsLanding};
#[cfg(feature = "sync")]
use crate::sync::residence::{
    CapturedPadObjects, CurrentPadObjects, PadObjectInstall, PadObjectRefillSource,
    capture_current_pad_objects_in_txn, index_in, pad_objects_identity_in_txn,
    read_back_captured_in_txn, read_back_generation_in, refill_pad_object, sealed_generation_hex,
};
use crate::world_keys::WorldKeyId;
use crate::{Error, Result, Vault};

/// What a pad object note names (CALLS: PAD-1 object note shape).
enum PadObjectNoteForm {
    /// Why the copy kept the objects it held, or a kept generation's id with
    /// its remedy: never an object's bytes, a grant, a key or a world.
    ReasonOrGenerationWithRemedy,
}

const PAD_OBJECT_NOTE_FORM: PadObjectNoteForm = PadObjectNoteForm::ReasonOrGenerationWithRemedy;

/// Where a restore or an activation refills a kept pad object whose bytes it
/// lacks (CALLS: PAD-1 refill provider selection).
#[cfg(feature = "sync")]
enum PadObjectRefillProvider {
    /// From the capture of its own source alone, for a generation the copy
    /// keeps whose object is not whole here and which the capture carries
    /// under the same digest; outside any writer, then that generation read
    /// back. No network, no wait, no other provider: what stays short is
    /// owed, named.
    SourceCaptureForKeptGenerationNotWholeSameDigest,
}

#[cfg(feature = "sync")]
const PAD_OBJECT_REFILL_PROVIDER: PadObjectRefillProvider =
    PadObjectRefillProvider::SourceCaptureForKeptGenerationNotWholeSameDigest;

/// What an object install says of the pads a restore owes (CALLS: PAD-1
/// object readiness).
#[cfg(feature = "sync")]
enum PadObjectReadiness {
    /// Nothing: objects read back apart from the epoch's pad debt. Once they
    /// installed, the shared resolver reconciles that debt again, in a writer
    /// of its own, against what the vault holds; an object never settles a
    /// pad reference.
    ObjectsReadBackApartFromPadDebt,
}

#[cfg(feature = "sync")]
const PAD_OBJECT_READINESS: PadObjectReadiness =
    PadObjectReadiness::ObjectsReadBackApartFromPadDebt;

/// The namespace hint a reference proof projects into: the proof reads the
/// key and the row id it derives, and never keeps the projected row.
const REFERENCE_PROOF_HINT: [u8; 16] = [0; 16];

/// What a restore or an activation says of its source's current pad objects
/// it did not carry, or carried and could not read back (PAD-1); empty when
/// it carried them all, or its source keeps none. Value free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PadObjectNote {
    /// Nothing was installed, for `reason`: the vault keeps the objects its
    /// image or archive held, as before.
    Kept { reason: String },
    /// The objects installed did not read back after their commit: read
    /// them again, or restore again.
    NotReadBack,
    /// A kept generation's pad object is not whole here, and its source did
    /// not give it whole: owed until a machine of the owner's refills it.
    Owed { generation: String },
}

impl std::fmt::Display for PadObjectNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match PAD_OBJECT_NOTE_FORM {
            PadObjectNoteForm::ReasonOrGenerationWithRemedy => {}
        }
        match self {
            Self::Kept { reason } => write!(
                f,
                "pad objects not carried ({reason}): the vault keeps the ones it held"
            ),
            Self::NotReadBack => write!(
                f,
                "pad objects installed from the source did not read back: read them again, or \
                 restore again"
            ),
            Self::Owed { generation } => write!(
                f,
                "pad object of generation {generation} not whole: owed until a machine of the \
                 owner's refills it"
            ),
        }
    }
}

#[cfg(feature = "sync")]
impl PadObjectNote {
    fn kept(reason: &str) -> Self {
        Self::Kept {
            reason: reason.to_owned(),
        }
    }
}

/// Why nothing was installed, as a note names it.
#[cfg(feature = "sync")]
mod kept {
    pub(super) const CURRENT_CHANGED: &str =
        "the vault's objects or the source's moved since they were read";
    pub(super) const NOT_WHOLE: &str = "a source object is not whole";
    pub(super) const NOT_READ_BACK: &str = "the install did not read back in its transaction";
    pub(super) const FAULT: &str = "a storage fault";
}

impl SideRestoreSource<'_> {
    /// The source's live custody state, read now, at a restore's start, with
    /// its home's current pad objects from the same read (PAD-1; moved here
    /// whole from the checkpoint module).
    pub(super) fn capture(&self) -> Result<LiveCustody> {
        match &self.0 {
            Source::Open(vault) => vault
                .store
                .live_custody(|txn| capture_open_in_txn(vault, txn)),
            Source::Disk {
                dir,
                first,
                page_seal,
                ..
            } => {
                let live = crate::store::read_live_custody(dir, page_seal.as_ref())?;
                if !first.same_vault(&live) {
                    return Err(Error::InvalidConfig(
                        "the vault read as this side restore's source has changed".into(),
                    ));
                }
                Ok(live)
            }
        }
    }
}

/// The current pad objects of `vault`, open in this process, captured in
/// `txn`, named for the vault and home that transaction reads
/// (`PAD_SOURCE_IDENTITY`). A fault leaves them not captured.
pub(super) fn capture_open_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> PadObjectsCapture {
    #[cfg(feature = "sync")]
    {
        match crate::store::PAD_SOURCE_IDENTITY {
            crate::store::PadSourceIdentity::OpenFoldInCustodyReadDiskUnproven => {}
        }
        let (vault_id, home) = match pad_objects_identity_in_txn(vault, txn) {
            Ok(identity) => identity,
            Err(error) => return not_captured(UncapturedPadObjects::IdentityUnread, &error),
        };
        match capture_current_pad_objects_in_txn(&vault.store, txn, vault_id, home) {
            Ok(captured) => PadObjectsCapture::Captured(captured),
            Err(error) => not_captured(UncapturedPadObjects::RowsUnread, &error),
        }
    }
    #[cfg(not(feature = "sync"))]
    {
        let _ = (vault, txn);
        PadObjectsCapture::NotCaptured {
            reason: crate::store::UncapturedPadObjects::NoSync,
        }
    }
}

/// Not captured for `reason`, warned value free (CALLS: PAD_CAPTURE_FAULT).
#[cfg(feature = "sync")]
fn not_captured(reason: UncapturedPadObjects, error: &Error) -> PadObjectsCapture {
    warn_fault(error, reason.as_str());
    PadObjectsCapture::NotCaptured { reason }
}

/// A new pad object fault: warned, value free, and today's path kept.
#[cfg(feature = "sync")]
fn warn_fault(error: &Error, what: &str) {
    match crate::world_keys::PAD_CAPTURE_FAULT {
        crate::world_keys::PadCaptureFault::WarnKeepExistingPathAndLeaveStrictClosureOpen => {}
    }
    tracing::warn!(kind = ?error.kind(), "{what}; the vault keeps the pad objects it held");
}

/// What `vault` holds of its pad objects now, before `capture` is installed
/// over them: `None` when there is nothing to install, or its index did not
/// read (warned; the install is not attempted).
pub(super) fn expected_of(
    vault: &Vault,
    capture: &PadObjectsCapture,
) -> Option<crate::store::ExpectedPadObjects> {
    #[cfg(feature = "sync")]
    if let PadObjectsCapture::Captured(captured) = capture
        && !captured.index().entries.is_empty()
    {
        let read = vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| index_in(vault, &txn));
        return read
            .inspect_err(|error| warn_fault(error, "a vault's pad object index did not read"))
            .ok();
    }
    let _ = (vault, capture);
    None
}

/// After a restore's rows landed in `vault` and it reopened: installs its
/// source's current pad objects `capture` over its own, reads them back,
/// refills what it keeps short, reconciles the epoch's pad debt once objects
/// installed, and says what it did not carry on `report`.
pub(super) fn land_on_restore(
    vault: &Vault,
    capture: &PadObjectsCapture,
    report: &mut RestoreReport,
) {
    let landing = match expected_of(vault, capture) {
        Some(expected) => vault
            .with_write_txn_grouped(|wtxn| {
                Ok(crate::store::install_source_pad_objects_in_txn(
                    &vault.store,
                    wtxn,
                    capture,
                    Some(&expected),
                ))
            })
            .unwrap_or_else(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a restore's pad object install did not commit; the vault keeps its own"
                );
                PadObjectsLanding::Fault
            }),
        None => PadObjectsLanding::NotAttempted,
    };
    if finish(vault, capture, landing, &mut report.pad_object_notes) {
        let epoch = super::epochs::latest_epoch_of(vault, &report.epoch.checkpoint_id);
        match epoch {
            Ok(Some((sequence, _))) => reconcile(vault, Some(sequence), report),
            Ok(None) => {}
            Err(error) => warn_debt_fault(&error),
        }
    }
}

/// After an activation committed and `vault` reopened live: reads back the
/// pad objects it installed before the archive lifted (`landing`), refills
/// what it keeps short, reconciles every epoch that still owes a pad once
/// objects installed, and says what it did not carry on `report`.
pub(super) fn finish_activation(
    vault: &Vault,
    capture: &PadObjectsCapture,
    landing: PadObjectsLanding,
    report: &mut RestoreReport,
) {
    if finish(vault, capture, landing, &mut report.pad_object_notes) {
        reconcile(vault, None, report);
    }
}

/// The notes `landing` comes to, the read back of what it installed and the
/// refill of what is still short; whether objects installed.
fn finish(
    vault: &Vault,
    capture: &PadObjectsCapture,
    landing: PadObjectsLanding,
    notes: &mut Vec<PadObjectNote>,
) -> bool {
    #[cfg(feature = "sync")]
    {
        let captured = match capture {
            PadObjectsCapture::Captured(captured) => captured,
            PadObjectsCapture::NotCaptured { reason } => {
                notes.push(PadObjectNote::kept(reason.as_str()));
                return false;
            }
        };
        if captured.index().entries.is_empty() {
            return false;
        }
        let installed = match landing {
            PadObjectsLanding::Installed(after) => {
                let read = vault
                    .store
                    .env
                    .read_txn()
                    .map_err(Error::from)
                    .and_then(|txn| {
                        read_back_captured_in_txn(&vault.store, &txn, &after, captured)
                    });
                if !matches!(read, Ok(true)) {
                    notes.push(PadObjectNote::NotReadBack);
                }
                true
            }
            PadObjectsLanding::CurrentChanged => {
                notes.push(PadObjectNote::kept(kept::CURRENT_CHANGED));
                false
            }
            PadObjectsLanding::Unavailable => {
                notes.push(PadObjectNote::kept(kept::NOT_WHOLE));
                false
            }
            PadObjectsLanding::NotReadBack => {
                notes.push(PadObjectNote::kept(kept::NOT_READ_BACK));
                false
            }
            PadObjectsLanding::NotAttempted | PadObjectsLanding::Fault => {
                notes.push(PadObjectNote::kept(kept::FAULT));
                false
            }
        };
        refill_short(vault, captured, notes);
        installed
    }
    #[cfg(not(feature = "sync"))]
    {
        let _ = (vault, capture, landing, notes);
        false
    }
}

/// Refills from `captured` each generation `vault` keeps whose pad object is
/// not whole here and which the capture carries under the same digest
/// ([`PAD_OBJECT_REFILL_PROVIDER`]), outside any writer, each read back
/// alone. What stays short is owed; a vault or source that moved stops it.
#[cfg(feature = "sync")]
fn refill_short(vault: &Vault, captured: &CapturedPadObjects, notes: &mut Vec<PadObjectNote>) {
    match PAD_OBJECT_REFILL_PROVIDER {
        PadObjectRefillProvider::SourceCaptureForKeptGenerationNotWholeSameDigest => {}
    }
    let (mut expected, short) = match short_generations(vault, captured) {
        Ok(found) => found,
        Err(error) => {
            warn_fault(&error, "a vault's pad objects did not read for a refill");
            return;
        }
    };
    for generation in short {
        let owed = PadObjectNote::Owed {
            generation: sealed_generation_hex(&generation),
        };
        let source = PadObjectRefillSource::CurrentProvider(captured);
        match refill_pad_object(vault, &expected, generation, source) {
            Ok(PadObjectInstall::Installed(after)) => {
                let read = vault
                    .store
                    .env
                    .read_txn()
                    .map_err(Error::from)
                    .and_then(|txn| read_back_generation_in(vault, &txn, &after, generation));
                if !matches!(read, Ok(Some(_))) {
                    notes.push(owed);
                }
                expected = after;
            }
            Ok(PadObjectInstall::CurrentChanged) => {
                notes.push(PadObjectNote::kept(kept::CURRENT_CHANGED));
                return;
            }
            Ok(PadObjectInstall::Unavailable(_)) => notes.push(owed),
            Err(error) => {
                warn_fault(&error, "a kept pad object did not refill");
                notes.push(owed);
            }
        }
    }
}

/// `vault`'s pad objects now, and each generation it keeps whose object is
/// not whole here and which `captured` carries under the same digest.
#[cfg(feature = "sync")]
fn short_generations(
    vault: &Vault,
    captured: &CapturedPadObjects,
) -> Result<(
    CurrentPadObjects,
    Vec<crate::world_keys::SealedBundleGeneration>,
)> {
    let txn = vault.store.env.read_txn()?;
    let current = index_in(vault, &txn)?;
    let mut short = Vec::new();
    for meta in &current.entries {
        let entry = &meta.entry;
        let carried = captured.index().entries.iter().any(|source| {
            source.entry.generation == entry.generation
                && source.entry.pads_digest == entry.pads_digest
        });
        if carried && read_back_generation_in(vault, &txn, &current, entry.generation)?.is_none() {
            short.push(entry.generation);
        }
    }
    Ok((current, short))
}

/// Reconciles the pad debt of the epoch `epoch` names, or of every epoch
/// that owes one with `None`, through the shared resolver in a writer of its
/// own ([`PAD_OBJECT_READINESS`]), and reports that epoch's state. A fault
/// leaves the debt as it was recorded.
fn reconcile(vault: &Vault, epoch: Option<u64>, report: &mut RestoreReport) {
    #[cfg(feature = "sync")]
    {
        match PAD_OBJECT_READINESS {
            PadObjectReadiness::ObjectsReadBackApartFromPadDebt => {}
        }
        if epoch.is_some() && report.epoch.pad_recovery.required_refs.is_empty() {
            return;
        }
        let reconciled = vault.with_write_txn_grouped(|txn| {
            super::reconcile_restore_pad_notes_in_txn(vault, txn, epoch, &BTreeSet::new())
        });
        match reconciled {
            Ok(states) => {
                if let Some(state) = epoch.and_then(|sequence| states.get(&sequence)) {
                    report.epoch.pad_recovery = state.clone();
                    report.pad_notes = state.remaining.clone();
                }
            }
            Err(error) => warn_debt_fault(&error),
        }
    }
    #[cfg(not(feature = "sync"))]
    {
        let _ = (vault, epoch, report);
    }
}

/// A fault reconciling a restore's pad debt: the debt stays as recorded.
fn warn_debt_fault(error: &Error) {
    tracing::warn!(
        kind = ?error.kind(),
        "a restore's pad debt did not reconcile after its objects installed; it stays as recorded"
    );
}

/// Whether the bare reference row `raw` an image carries under `row_key`
/// names exactly `key`, by the row id that key derives (PAD-1): the proof
/// binds the full id a restore plans and owes to its row. A row it does not
/// prove keeps today's plan, warned (CALLS: PAD_CAPTURE_FAULT).
pub(super) fn prove_reference(row_key: &[u8], raw: &[u8], key: &WorldKeyId) {
    let proven = <[u8; 16]>::try_from(row_key)
        .ok()
        .and_then(|bytes| EntityId::from_bytes(bytes).ok())
        .and_then(|id| {
            crate::world_keys::pad_reference_projection(&id, raw, &REFERENCE_PROOF_HINT).ok()
        })
        .and_then(|projection| projection.reference)
        .is_some_and(|reference| reference.key == *key);
    if !proven {
        tracing::warn!(
            "a pad reference an image carries did not prove its key by its row; it is planned as \
             before"
        );
    }
}
