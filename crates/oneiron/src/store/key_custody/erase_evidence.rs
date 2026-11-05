//! Core half of `store::key_custody::erase_evidence`: its store-layer items live in `oneiron_store::key_custody::erase_evidence` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::erase_evidence::*;

use super::files::{LocalCustody, open_dir, read_whole, replace_file};
use super::identity::hex_decode;
use super::log::LogEntry;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

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

    /// The fact this custody keeps of `credential`, if any; a file custody
    /// would not write is damaged.
    fn kept_erase_evidence(&self, credential: &EntityId) -> Result<Option<FenceFact>> {
        match read_whole(&self.evidence_dir()?.join(credential.to_hex()))?.as_deref() {
            Some([code]) => FenceFact::from_code(*code)
                .map(Some)
                .ok_or_else(evidence_corrupt),
            Some(_) => Err(evidence_corrupt()),
            None => Ok(None),
        }
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
        self.journal_credential_fence_facts(&facts)
    }

    /// Journals each of `facts` custody keeps no equal or larger fact of,
    /// then keeps it beside the vault: an erase's own hand-off (FIX 11211)
    /// and the finisher's both come here, so a fact goes into the journal
    /// once, and again only once it grows. A fence before any key is in
    /// custody pins the binding first. Called with no writer open on this
    /// thread; the caller rules out an archived vault.
    ///
    /// # Errors
    /// Storage and custody faults: the next finisher pass retries.
    pub(crate) fn journal_credential_fence_facts(
        &self,
        facts: &[CredentialFenceFact],
    ) -> Result<()> {
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
        for fact in facts {
            if custody
                .kept_erase_evidence(&fact.credential)?
                .is_some_and(|held| held >= fact.fact)
            {
                continue;
            }
            custody.journal_entry(&LogEntry::EraseEvidence(*fact))?;
            custody.put_erase_evidence(fact)?;
        }
        Ok(())
    }
}
