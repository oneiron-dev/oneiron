//! Erased credentials' evidence on the custody head (FIX 10584 item 3): one
//! value-free fact per credential id an authorized erase fenced, carried by
//! every head whatever key eligibility keeps local, so a disaster recovery
//! or a second machine learns each erase even where no retired key of it
//! reaches the head: a fence with no key yet, one whose discovery is owed,
//! a completed erase, and a fence whose discovery found no subject.
//!
//! A fact is journaled (it moves the log on, so every member's head is
//! sealed again), then kept beside the vault in
//! `<compartment>/.erase-evidence/<credential hex>`, one byte, the larger
//! fact winning. An erase hands its fence's fact over once its writer
//! commits (FIX 11211), and the finisher hands every fact over again: a
//! fact kept already, or a smaller one, is never journaled twice. A fence
//! that comes before any key is in custody pins the binding first. A
//! landing writes the head's facts into the custody it lands, where
//! [`crate::store::CredentialFences`] reads them as fences.
//! Only an erase makes a fact: a soft delete, a rotation or a revoke never
//! does, and an image's own fence rows never count.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::files::open_dir;
use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::identity::hex_decode;

pub const EVIDENCE: &str = ".erase-evidence";

/// Where one erased credential's erase stands, value-free; a larger one
/// dominates a smaller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FenceFact {
    /// Fenced, its discovery owed; or an erase intent of one of its keys
    /// committed whose fence did not write.
    Owed,
    /// Its discovery completed and found no subject its id names.
    NoSubject,
    /// Its discovery completed and staged every key its id names.
    Keyed,
    /// Its erase finished here: every key retired and acknowledged.
    Complete,
}

impl FenceFact {
    pub const fn code(self) -> u8 {
        match self {
            Self::Owed => 0,
            Self::NoSubject => 1,
            Self::Keyed => 2,
            Self::Complete => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Owed,
            1 => Self::NoSubject,
            2 => Self::Keyed,
            3 => Self::Complete,
            _ => return None,
        })
    }
}

/// One erased credential's fact: its 16-byte id and where its erase stands.
/// Never a value, a key or a handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialFenceFact {
    pub credential: EntityId,
    pub fact: FenceFact,
}

impl CredentialFenceFact {
    /// `credential id (16) | fact (1)`: a log frame's body after its op.
    pub fn encode(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[..16].copy_from_slice(self.credential.as_bytes());
        out[16] = self.fact.code();
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (id, fact) = bytes.split_first_chunk::<16>()?;
        let [fact] = fact else {
            return None;
        };
        Some(Self {
            credential: EntityId::from_bytes(*id).ok()?,
            fact: FenceFact::from_code(*fact)?,
        })
    }
}

/// Folds `fact` into `facts`, the larger winning.
pub fn fold_fact(facts: &mut BTreeMap<EntityId, FenceFact>, fact: CredentialFenceFact) {
    let slot = facts.entry(fact.credential).or_insert(fact.fact);
    *slot = (*slot).max(fact.fact);
}

pub fn evidence_corrupt() -> Error {
    Error::CorruptedIndex("key custody erase evidence")
}
