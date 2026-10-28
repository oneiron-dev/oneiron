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
//! fact winning. A fence that comes before any key is in custody pins the
//! binding first. A landing writes the head's facts into the custody it
//! lands, where [`crate::store::CredentialFences`] reads them as fences.
//! Only an erase makes a fact: a soft delete, a rotation or a revoke never
//! does, and an image's own fence rows never count.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::files::{LocalCustody, open_dir, read_whole, replace_file};
use super::identity::hex_decode;
use super::log::LogEntry;

const EVIDENCE: &str = ".erase-evidence";

/// Where one erased credential's erase stands, value-free; a larger one
/// dominates a smaller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FenceFact {
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
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Owed => 0,
            Self::NoSubject => 1,
            Self::Keyed => 2,
            Self::Complete => 3,
        }
    }

    pub(super) fn from_code(code: u8) -> Option<Self> {
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
pub(crate) struct CredentialFenceFact {
    pub(crate) credential: EntityId,
    pub(crate) fact: FenceFact,
}

impl CredentialFenceFact {
    /// `credential id (16) | fact (1)`: a log frame's body after its op.
    pub(super) fn encode(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[..16].copy_from_slice(self.credential.as_bytes());
        out[16] = self.fact.code();
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
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
pub(super) fn fold_fact(facts: &mut BTreeMap<EntityId, FenceFact>, fact: CredentialFenceFact) {
    let slot = facts.entry(fact.credential).or_insert(fact.fact);
    *slot = (*slot).max(fact.fact);
}

fn evidence_corrupt() -> Error {
    Error::CorruptedIndex("key custody erase evidence")
}

impl LocalCustody<'_> {
    fn evidence_dir(&self) -> Result<PathBuf> {
        Ok(self.compartment()?.join(EVIDENCE))
    }

    /// Every erased credential's fact this custody keeps. No directory
    /// keeps none; a file custody would not write is damaged.
    pub(crate) fn erase_evidence(&self) -> Result<BTreeMap<EntityId, FenceFact>> {
        let dir = self.evidence_dir()?;
        let names = match fs::read_dir(&dir) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(err) => return Err(err.into()),
        };
        let mut facts = BTreeMap::new();
        for name in names {
            let name = name?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // Temporaries a replace left are not facts.
            if name.starts_with('.') {
                continue;
            }
            let credential = hex_decode(name)
                .and_then(|id| <[u8; 16]>::try_from(id).ok())
                .and_then(|id| EntityId::from_bytes(id).ok())
                .ok_or_else(evidence_corrupt)?;
            let fact = match read_whole(&dir.join(name))?.as_deref() {
                Some([code]) => FenceFact::from_code(*code).ok_or_else(evidence_corrupt)?,
                Some(_) => return Err(evidence_corrupt()),
                None => continue,
            };
            fold_fact(&mut facts, CredentialFenceFact { credential, fact });
        }
        Ok(facts)
    }

    /// Keeps `fact`, synced, unless a larger one is kept already.
    pub(super) fn put_erase_evidence(&self, fact: &CredentialFenceFact) -> Result<()> {
        self.open_compartment()?;
        let dir = self.evidence_dir()?;
        open_dir(&dir, true, None)?;
        let name = fact.credential.to_hex();
        if let Some([held]) = read_whole(&dir.join(&name))?.as_deref()
            && FenceFact::from_code(*held).is_some_and(|held| held >= fact.fact)
        {
            return Ok(());
        }
        replace_file(&dir, &name, &[fact.fact.code()])
    }
}

impl Store {
    /// Records each erased credential's fact where every custody head
    /// carries it (FIX 10584 item 3): journaled, so every member's head is
    /// sealed again, then kept beside the vault. A fact already kept, or a
    /// smaller one, is not journaled again. A fence before any key is in
    /// custody pins the binding first, so the head it rides exists. An
    /// archived vault records none: its custody is its replacement's. A
    /// fault is warned; the next finisher pass retries, and the erase it
    /// records stands meanwhile.
    pub(crate) fn publish_credential_erase_evidence(&self) {
        if let Err(error) = self.record_credential_erase_evidence() {
            tracing::warn!(
                kind = ?error.kind(),
                "credential erase evidence did not reach custody; the next pass retries"
            );
        }
    }

    fn record_credential_erase_evidence(&self) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        let facts = {
            let txn = self.env.read_txn()?;
            if self.archived_in_txn(&txn)? {
                return Ok(());
            }
            self.credential_fence_facts_in_txn(&txn)?
        };
        if facts.is_empty() {
            return Ok(());
        }
        if self.core.key_custody.local().is_none() {
            let mut wtxn = self.env.write_txn()?;
            self.core.key_custody.pin_in_txn(self, &mut wtxn)?;
            wtxn.commit()?;
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let kept = custody.erase_evidence()?;
        for fact in facts {
            if kept
                .get(&fact.credential)
                .is_some_and(|held| *held >= fact.fact)
            {
                continue;
            }
            custody.journal_entry(&LogEntry::EraseEvidence(fact))?;
            custody.put_erase_evidence(&fact)?;
        }
        Ok(())
    }
}
