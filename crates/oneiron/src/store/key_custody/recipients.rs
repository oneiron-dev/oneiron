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

use crate::error::{Error, Result};
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason};
use crate::store::Store;

use super::files::{read_whole, write_once};
use super::log::{Journal, LogEntry, log_corrupt};
use super::protocol::hex;

const RECIPIENTS: &str = "recipients";
/// The longest label a fact holds: a wrap name is at most 64 bytes.
const LABEL_MAX: usize = 64;

/// One released escrow recipient retired here: public facts only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientRetirement {
    pub(crate) label: String,
    /// BLAKE3 of the recipient's public key bytes.
    pub(crate) fingerprint: [u8; 32],
    /// The vault's retirement receipt id.
    pub(crate) receipt: [u8; 16],
}

impl RecipientRetirement {
    /// `u8 label length ‖ label ‖ fingerprint (32) ‖ receipt (16)`.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.label.len() + 48);
        // A label is a wrap name, at most LABEL_MAX bytes.
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&self.receipt);
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
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

    fn file_name(&self) -> String {
        hex(&self.fingerprint)
    }

    /// The obligation its frame is handed off as.
    pub(super) fn obligation_name(&self) -> String {
        format!("r.rcpt.{}", hex(&self.fingerprint))
    }

    /// A label that fits a wrap name, ahead of any write.
    fn checked(&self) -> Result<&Self> {
        if self.label.is_empty() || self.label.len() > LABEL_MAX {
            return Err(log_corrupt());
        }
        Ok(self)
    }
}

impl Journal {
    /// Every recipient retirement this lineage holds here, in fingerprint
    /// order: what the next head it seals carries.
    pub(super) fn recipient_facts(&self) -> Result<Vec<RecipientRetirement>> {
        let dir = self.dir().join(RECIPIENTS);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            if let Some(name) = entry?.file_name().to_str()
                && !name.starts_with('.')
            {
                names.push(name.to_owned());
            }
        }
        names.sort_unstable();
        let mut facts = Vec::with_capacity(names.len());
        for name in names {
            let bytes = read_whole(&dir.join(&name))?.ok_or_else(log_corrupt)?;
            let fact = RecipientRetirement::decode(&bytes).ok_or_else(log_corrupt)?;
            if fact.file_name() != name {
                return Err(log_corrupt());
            }
            facts.push(fact);
        }
        Ok(facts)
    }

    /// Keeps `fact`, synced; a fact already kept for its fingerprint stays.
    pub(super) fn put_recipient_fact(&self, fact: &RecipientRetirement) -> Result<()> {
        let dir = self.sub(RECIPIENTS)?;
        write_once(&dir, &fact.checked()?.file_name(), &fact.encode()).map(drop)
    }
}

impl Store {
    /// Journals each of `facts`, released escrow recipients a cold managed
    /// restore retired, in this vault's custody log at the takeover writer
    /// epoch `epoch`: its fact, then one keyless `RetireRecipient` frame,
    /// then its obligation, each synced before the next. A frame an
    /// interrupted handoff journaled is found by the journal's reconcile
    /// walk and never journaled again. Each frame's sequence, in order.
    /// Refused when the vault binds no custody, or its log stands at
    /// another writer epoch than the takeover's.
    pub(crate) fn journal_recipient_retirements(
        &self,
        facts: &[RecipientRetirement],
        epoch: u64,
    ) -> std::result::Result<Vec<u64>, Rejected> {
        let authority = |reason: &str| {
            Rejected::new(
                RestoreAdmissionReason::RetirementAuthorityInvalid,
                Error::InvalidConfig(reason.to_owned()),
            )
        };
        let Some(custody) = self.core.key_custody.local() else {
            return Err(authority(
                "the restored vault binds no key custody to retire its recipients in",
            ));
        };
        let _custody = self.core.key_custody.write_guard()?;
        let journal = custody.journal()?;
        journal.reconcile()?;
        if journal.position()?.epoch.get() != epoch {
            return Err(authority(
                "the restored vault's custody log is not at its takeover writer epoch",
            ));
        }
        let mut seqs = Vec::with_capacity(facts.len());
        for fact in facts {
            journal.put_recipient_fact(fact)?;
            let name = fact.obligation_name();
            let seq = match journal.obligation_named(&name)? {
                Some(seq) => seq,
                None => {
                    let at = custody.journal_entry(&LogEntry::RetireRecipient(fact.clone()))?;
                    journal.record_obligation_named(&name, &at)?;
                    at.seq
                }
            };
            seqs.push(seq);
        }
        Ok(seqs)
    }
}
