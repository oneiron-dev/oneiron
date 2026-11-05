//! Released escrow recipients a cold managed restore retired (LC FIX
//! 5384/5385), kept in the lineage's exterior custody beside its key
//! retirements, so an older image never brings a released label back and
//! the debt outlives a crash.
//!
//! One keyless fact per recipient: its label, the BLAKE3 of its public key
//! and the vault's retirement receipt id; never a key, a wrap or a secret.
//! A restore journals each as one `RetireRecipient` frame at the takeover
//! writer epoch, with its fact in `<journal>/recipients/<fingerprint hex>`
//! and its obligation `obligations/r.rcpt.<fingerprint hex>`, each synced;
//! every head the lineage seals after carries the facts, a restore's
//! admission takes them from the head and the frames after it, and its
//! landing keeps them in the new journal.

use std::fs;

use serde::{Deserialize, Serialize};

use crate::restore_admission::Rejected;
use crate::restore_admission::RestoreAdmissionReason;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::files::read_whole;
use crate::key_custody::files::write_once;
use crate::key_custody::log::log_corrupt;
use crate::key_custody::protocol::hex;

pub const RECIPIENTS: &str = "recipients";
/// The longest label a fact holds: a wrap name is at most 64 bytes.
const LABEL_MAX: usize = 64;

/// One released escrow recipient retired here: public facts only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientRetirement {
    pub label: String,
    /// BLAKE3 of the recipient's public key bytes.
    pub fingerprint: [u8; 32],
    /// The vault's retirement receipt id.
    pub receipt: [u8; 16],
}

impl RecipientRetirement {
    /// `u8 label length ‖ label ‖ fingerprint (32) ‖ receipt (16)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.label.len() + 48);
        // A label is a wrap name, at most LABEL_MAX bytes.
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&self.receipt);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&len, rest) = bytes.split_first()?;
        let len = usize::from(len);
        if len == 0 || len > LABEL_MAX || rest.len() != len + 48 {
            return None;
        }
        let label = std::str::from_utf8(&rest[..len]).ok()?.to_owned();
        Some(Self {
            label,
            fingerprint: rest[len..len + 32].try_into().ok()?,
            receipt: rest[len + 32..].try_into().ok()?,
        })
    }

    pub fn file_name(&self) -> String {
        hex(&self.fingerprint)
    }

    /// The obligation its frame is handed off as.
    pub fn obligation_name(&self) -> String {
        format!("r.rcpt.{}", hex(&self.fingerprint))
    }

    /// A label that fits a wrap name, ahead of any write.
    pub fn checked(&self) -> Result<&Self> {
        if self.label.is_empty() || self.label.len() > LABEL_MAX {
            return Err(log_corrupt());
        }
        Ok(self)
    }
}
