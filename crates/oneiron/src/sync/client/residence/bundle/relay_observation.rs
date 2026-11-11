//! The last sealed bundle upkeep this process saw, per machine (FIX 4953;
//! CALLS "4953 relay report"): what the relay moved, with its counts of pad
//! objects still pending access and erases still held back, and when. The
//! upkeep runs as before and never waits on this record; it only notes each
//! result as it passes ([`observe_sealed_bundle_relay`]). A relay that did
//! not reach the home measured nothing and replaces no observation, and the
//! pending counts come only from a relay whose sweep counted them, and the
//! worlds awaiting a reader only from one that took or published. Before
//! that there is no observation, which is not zero. Nothing expires: a newer
//! measurement replaces the older one. Held in memory, keyed by this
//! install's machine as the host's connections are, so a restart starts
//! unobserved.
//!
//! Beside the relays, the one record of what each upload assembled here
//! carries unmerged (FIX 19525): both the slot's upload and an asked
//! publication note theirs as soon as it is assembled ([`observe_upload`]),
//! by the home it is for, and both owner reads, the upkeep and a
//! publication's diagnostics, read it. A tick or a take that assembles
//! nothing leaves it, and only a later upload for the same home replaces it.
//! An attempt a later pass finds committed restores it when this process
//! noted none for that home since ([`restore_upload`]), so neither a lost
//! acknowledgement nor a restart before the commit hides it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use super::SealedBundleRelay;
use super::attempt::BundleAttempt;
use crate::sync::transport::TransportError;
use crate::world_keys::{SealedBundleGeneration, UnmergedSection};
use crate::{EntityId, Vault};

/// The last upload this install assembled for one home, by an asked
/// publication or the slot's own (FIX 19525): the generation it seals and
/// each section of the home's newest generation it carries unchanged because
/// the section did not open, decode or merge here. The erased-actor cleanup
/// did not run on those; the owner repairs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmergedUpload {
    /// When it was assembled, or restored from its committed attempt, in
    /// recorded-clock seconds.
    pub at: u64,
    pub generation: SealedBundleGeneration,
    /// Empty when it merged every section this machine may read.
    pub sections: Vec<UnmergedSection>,
    /// Whether it came back from a committed attempt a later pass found,
    /// rather than from an assembly this process saw.
    pub restored: bool,
    /// When this install assembled it, as its attempt keeps it; `None` for
    /// an attempt row written before that was kept.
    pub assembled_at: Option<u64>,
}

/// What this process last saw of one machine's sealed bundle upkeep. Each
/// part is an observation with its recorded-clock time, never a promise:
/// `None` is unobserved.
#[derive(Debug, Clone, Default)]
pub struct SealedBundleRelayObservation {
    /// The last relay that reached the home, and when.
    pub relayed: Option<(u64, SealedBundleRelay)>,
    /// The last relay whose erase sweep ran, and when: the one whose
    /// `pending_pad_access` and `pending_erases` were counted.
    pub swept: Option<(u64, SealedBundleRelay)>,
    /// The last relay that took or published a generation, and when: the one
    /// whose `awaiting_reader` (and, for an upload, `incomplete_authority`)
    /// names what a kit restore of the home's newest copy still awaits
    /// (FIX-LIST 11944).
    pub generation: Option<(u64, SealedBundleRelay)>,
    /// The last relay that failed, and when, with its error. A later relay
    /// that finishes does not clear it: the times say which is newer.
    pub failed: Option<(u64, String)>,
    /// The last upload this install assembled for each home, keyed by the
    /// home when its proof stood here and `None` when it did not (FIX
    /// 19525). Only a later upload for the same home replaces one.
    pub uploads: BTreeMap<Option<EntityId>, UnmergedUpload>,
}

fn observations() -> &'static Mutex<HashMap<EntityId, SealedBundleRelayObservation>> {
    static OBSERVED: OnceLock<Mutex<HashMap<EntityId, SealedBundleRelayObservation>>> =
        OnceLock::new();
    OBSERVED.get_or_init(Mutex::default)
}

/// The last upkeep this process saw for `machine`; `None` when it saw none.
#[must_use]
pub fn sealed_bundle_relay_observation(machine: &EntityId) -> Option<SealedBundleRelayObservation> {
    observations().lock().ok()?.get(machine).cloned()
}

/// This install's machine, as the observations are keyed; `None` before the
/// vault is one.
fn local_machine(vault: &Vault) -> Option<EntityId> {
    vault
        .store
        .env
        .read_txn()
        .ok()
        .and_then(|txn| crate::identity::read_machine_id_in_txn(vault, &txn).ok())
        .flatten()
}

/// Notes the upload this install assembled for `home`, sealing `generation`
/// with `sections` carried unmerged (FIX 19525): it replaces the upload
/// noted for that home, with sections or none.
pub(super) fn observe_upload(
    vault: &Vault,
    home: Option<EntityId>,
    generation: SealedBundleGeneration,
    sections: &[UnmergedSection],
) {
    let (Some(machine), Ok(mut observed)) = (local_machine(vault), observations().lock()) else {
        return;
    };
    let upload = UnmergedUpload {
        at: vault.store.clock.peek_recorded_at(),
        generation,
        sections: sections.to_vec(),
        restored: false,
        assembled_at: Some(vault.store.clock.peek_recorded_at()),
    };
    observed
        .entry(machine)
        .or_default()
        .uploads
        .insert(home, upload);
}

/// Notes the upload of `attempt`, which a later pass found committed (FIX
/// 19525): after a lost acknowledgement or a restart, the owner still sees
/// what it carries unmerged. An upload assembled in this process is this
/// attempt's own or a later one, and stays. One restored from another
/// attempt gives way when this attempt was assembled after it, as both
/// attempts keep their assembly time; for rows written before that was
/// kept, when this one was sealed on top of that one's generation or for a
/// later slot. So the record names the newest upload whatever order a pass
/// reconciles attempts in.
pub(super) fn restore_upload(vault: &Vault, attempt: &BundleAttempt) {
    let (Some(machine), Ok(mut observed)) = (local_machine(vault), observations().lock()) else {
        return;
    };
    let uploads = &mut observed.entry(machine).or_default().uploads;
    let later = uploads.get(&attempt.home).is_none_or(|held| {
        held.restored
            && held.generation != attempt.generation
            && match (attempt.assembled_at, held.assembled_at) {
                // Strictly ordered among attempts stored together (persist).
                (Some(attempt_at), Some(held_at)) => attempt_at > held_at,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => {
                    attempt.parent == Some(held.generation)
                        || attempt.generation.slot > held.generation.slot
                }
            }
    });
    if later {
        uploads.insert(
            attempt.home,
            UnmergedUpload {
                at: vault.store.clock.peek_recorded_at(),
                generation: attempt.generation,
                sections: attempt.unmerged_sections.clone(),
                restored: true,
                assembled_at: attempt.assembled_at,
            },
        );
    }
}

/// Notes one upkeep relay's `result` for this install's machine and hands it
/// back unchanged. A relay with nothing to do (`InvalidPayload`) or that did
/// not reach the home is no observation; neither is a vault that is no
/// machine yet.
pub(crate) fn observe_sealed_bundle_relay(
    vault: &Vault,
    result: Result<SealedBundleRelay, TransportError>,
) -> Result<SealedBundleRelay, TransportError> {
    if matches!(
        result,
        Err(TransportError::InvalidPayload(_)) | Ok(SealedBundleRelay { reached: false, .. })
    ) {
        return result;
    }
    let (Some(machine), Ok(mut observed)) = (local_machine(vault), observations().lock()) else {
        return result;
    };
    let at = vault.store.clock.peek_recorded_at();
    let entry = observed.entry(machine).or_default();
    match &result {
        Ok(relay) => {
            if relay.swept {
                entry.swept = Some((at, relay.clone()));
            }
            if relay.moved_generation() {
                entry.generation = Some((at, relay.clone()));
            }
            entry.relayed = Some((at, relay.clone()));
        }
        Err(error) => entry.failed = Some((at, error.to_string())),
    }
    result
}
