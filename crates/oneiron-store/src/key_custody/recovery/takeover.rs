//! A recovery's takeover fence, published last (FIX 6782, Engine 06:2x).
//!
//! Every private step of a restore comes first: the caller's checks and
//! holds, the restored identity and data key, the once-only recipient spend
//! journaled in the landed custody at the takeover epoch, and the page
//! custody read back. Only then is the anchor's advance prepared, from the
//! landed custody's final local position at that epoch, never the stale
//! admitted one, and expecting the record admission read. The advance is
//! the last fallible publication: the landed custody is armed to stay
//! before it runs. A definitive refusal (the anchor moved) disarms it, and
//! the restore removes what it made. An advance that failed may still have
//! happened: everything stays, the restore says its destination is
//! uncertain, and nothing undoes, retries or releases again.

use crate::key_custody::log::CustodyPosition;
use crate::key_custody::protocol::AnchorAdvance;
use crate::key_custody::protocol::AnchorStore;
use crate::restore_admission::Rejected;
use crate::restore_admission::RestoreAdmissionReason as R;
use crate::restore_admission::because;
use oneiron_base::error::Error;

/// The anchor record a restore's takeover advances its lineage's anchor to,
/// and the record that advance expects there: what admission read.
pub struct PreparedTakeover {
    pub expected: [u8; 32],
    pub record: Vec<u8>,
}

impl PreparedTakeover {
    /// BLAKE3 of the record the advance writes, for the receipt.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.record).as_bytes()
    }
}

/// Why a takeover's advance did not publish.
pub enum TakeoverRefusal {
    /// The anchor is not this restore's: nothing was published, and what
    /// the restore made may go.
    Definitive(Rejected),
    /// Whether the anchor moved is not known: the destination, its custody
    /// and its mirror stay.
    Uncertain(Rejected),
}

impl TakeoverRefusal {
    /// The refusal, whichever it is.
    pub fn into_rejected(self) -> Rejected {
        match self {
            Self::Definitive(rejected) | Self::Uncertain(rejected) => rejected,
        }
    }
}
