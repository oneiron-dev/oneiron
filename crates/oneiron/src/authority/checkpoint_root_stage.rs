//! The home's countersign stage (FIX 4882, 5111): the image a linked machine
//! sends this home a part at a time to countersign
//! ([`Vault::stage_countersign_part`]), held in memory on the vault handle,
//! one image per machine, until it is whole.
//!
//! The host charges the room a stage holds ([`CountersignStageCharge`]) on
//! the line its other state kept between frames is charged to, before the
//! bytes are allocated, and the charge goes with the stage. A stage whose
//! line has no room is dropped, and its machine starts again on a later
//! pass: that line, the memory floor, is the one refusal. The image's size is
//! bounded only by the image cap. A stage no part reached for the idle bound
//! goes at the next part any machine sends, and a stage goes when the socket
//! that sent it closes ([`Vault::drop_countersign_stage`]), so a machine that
//! stops mid-upload holds nothing until its next start.

use std::collections::btree_map::Entry;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

use super::checkpoint_attest::attest_refused;
use super::checkpoint_root_attest::{linked_machine, peer_refused};
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::world_keys::CountersignStage;

/// How long a stage waits for its next part before it is dropped. Internal:
/// a machine sends its parts one after another on one socket, each within
/// its RPC timeout.
const CHECKPOINT_COUNTERSIGN_STAGE_IDLE: Duration = Duration::from_secs(10 * 60);

/// A host's charge for the room one countersign stage holds in memory (FIX
/// 5111). Dropping it gives the bytes back.
pub trait CountersignStageCharge: Send {
    /// Moves the charge to `bytes` now; `false` when the host's line has no
    /// room for them.
    fn resize(&mut self, bytes: usize) -> bool;
}

/// What one countersign part came to ([`Vault::stage_countersign_part`]).
pub enum CountersignStaged {
    /// The part is held; more are to come.
    Held,
    /// The image is whole: its bytes, and the charge that holds them until
    /// the caller drops it.
    Whole {
        image: Vec<u8>,
        charge: Box<dyn CountersignStageCharge>,
    },
    /// The host's line had no room for the part: the stage is dropped, and
    /// its machine starts again on a later pass.
    NoRoom,
}

/// Charges room for `more` bytes past those `stage` holds, before they are
/// allocated. The room grows by doubling, up to the image's length, so the
/// charge is the room the bytes take. `false` when the host's line has none.
fn reserve_charged(stage: &mut CountersignStage, more: usize) -> bool {
    let want = stage.bytes.len().saturating_add(more);
    let room = stage.bytes.capacity();
    if want <= room {
        return true;
    }
    let total = usize::try_from(stage.total).unwrap_or(usize::MAX);
    let room = want.max(room.saturating_mul(2)).min(total.max(want));
    if !stage.charge.resize(room) {
        return false;
    }
    stage.bytes.reserve_exact(room - stage.bytes.len());
    true
}

impl Vault {
    /// Takes part `part` at `offset` of image `image`, `total` bytes long,
    /// that the linked machine `peer` sends this home to countersign (FIX
    /// 4882): see the module notes. A part at offset zero starts the image
    /// again, under a new charge `charge` makes. Refused for any other peer,
    /// a part that is not the next one, and a length past the image size cap.
    pub fn stage_countersign_part(
        &self,
        peer: PeerMachine,
        image: [u8; 32],
        total: u64,
        offset: u64,
        part: &[u8],
        charge: impl FnOnce() -> Box<dyn CountersignStageCharge>,
    ) -> Result<CountersignStaged> {
        {
            let txn = self.store.env.read_txn()?;
            if !linked_machine(&self.authority_fold_readonly_in_txn(&txn)?, peer) {
                return Err(peer_refused());
            }
        }
        let PeerMachine::Proven { machine, .. } = peer else {
            return Err(peer_refused());
        };
        let end = offset.saturating_add(part.len() as u64);
        if part.is_empty()
            || part.len() > AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX
            || end > total
            || total > AUTHORITY_CHECKPOINT_V2_MAX_BYTES as u64
        {
            return Err(attest_refused("the countersign part is malformed"));
        }
        let mut stages = self
            .world_keys
            .checkpoint_countersign
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A stage no part reached for the idle bound goes, and its charge.
        stages.retain(|_, stage| stage.touched.elapsed() <= CHECKPOINT_COUNTERSIGN_STAGE_IDLE);
        if offset == 0 {
            stages.insert(
                machine,
                CountersignStage {
                    image,
                    total,
                    bytes: Vec::new(),
                    touched: Instant::now(),
                    charge: charge(),
                },
            );
        }
        let Entry::Occupied(mut held) = stages.entry(machine) else {
            return Err(attest_refused("the countersign part is not the next one"));
        };
        let stage = held.get_mut();
        if stage.image != image || stage.total != total || stage.bytes.len() as u64 != offset {
            held.remove();
            return Err(attest_refused("the countersign part is not the next one"));
        }
        if !reserve_charged(stage, part.len()) {
            held.remove();
            return Ok(CountersignStaged::NoRoom);
        }
        stage.bytes.extend_from_slice(part);
        stage.touched = Instant::now();
        if end < total {
            return Ok(CountersignStaged::Held);
        }
        let stage = held.remove();
        Ok(CountersignStaged::Whole {
            image: stage.bytes,
            charge: stage.charge,
        })
    }

    /// Drops the image the linked machine `machine` was sending this home to
    /// countersign, and its charge, if one is staged: the socket that sent it
    /// closed (FIX 5111).
    pub fn drop_countersign_stage(&self, machine: EntityId) {
        self.world_keys
            .checkpoint_countersign
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&machine);
    }
}
