//! A fence's fact reaches key custody at its erase (FIX 11211): each
//! credential an erase fenced on this thread is handed to custody once the
//! erase's writer has committed, read from the rows it committed, so the
//! next custody head carries it whether or not a finisher has run. A writer
//! that rolled back left no fence and no erase intent, so it hands over
//! nothing.
//!
//! The finisher hands every fact over again
//! ([`Store::publish_credential_erase_evidence`]); a fact custody keeps
//! already, or a larger one, is never journaled a second time. A fault here
//! is warned and refuses nothing: the erase stands, and the finisher's
//! hand-off is the retry.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::{Discovery, FENCES, STAGED, credential_intents_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::key_custody::{CredentialFenceFact, FenceFact, RetireCause};

impl Store {
    /// The fact fence `credential`, whose discovery stands at `discovery`
    /// in `txn`, gives the custody head: owed while its discovery is; once
    /// discovered, no-subject or keyed; complete once its erase finished
    /// here. A finish that does not read reads not complete yet.
    pub(super) fn fence_fact(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
        discovery: Discovery,
    ) -> FenceFact {
        match discovery {
            Discovery::Owed => FenceFact::Owed,
            Discovery::Complete { .. }
                if self
                    .credential_erase_finished_in_txn(txn, credential)
                    .unwrap_or(false) =>
            {
                FenceFact::Complete
            }
            Discovery::Complete { keys: false } => FenceFact::NoSubject,
            Discovery::Complete { keys: true } => FenceFact::Keyed,
        }
    }

    /// Hands key custody the fact of each credential an erase on this
    /// thread fenced, once the erase's writer has committed: journaled, so
    /// the next custody head carries it, then kept beside the vault. Each
    /// is handed over once from here; a fact custody keeps already, or a
    /// larger one, is not journaled again. While a vault write's closure is
    /// still open on this thread, its erase may not have committed: its
    /// own door hands the facts over. A fault is warned; the finisher's
    /// hand-off retries it, and the erase stands.
    pub(crate) fn journal_staged_fence_facts(&self) {
        if crate::store::active_write_txn_depth() > 0 {
            return;
        }
        let staged =
            STAGED.with(|staged| std::mem::take(&mut staged.borrow_mut().fences_to_journal));
        if staged.is_empty() {
            return;
        }
        if let Err(error) = self.journal_committed_fence_facts(&staged) {
            tracing::warn!(
                kind = ?error.kind(),
                "an erased credential's fence did not reach key custody at its erase; the \
                 finisher hands it over"
            );
        }
    }

    /// Journals the fact of each of `credentials` the committed rows give.
    /// An archived vault journals none: its custody is its replacement's.
    fn journal_committed_fence_facts(&self, credentials: &BTreeSet<EntityId>) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        let facts = {
            let txn = self.env.read_txn()?;
            if self.archived_in_txn(&txn)? {
                return Ok(());
            }
            self.committed_fence_facts_in_txn(&txn, credentials)?
        };
        self.journal_credential_fence_facts(&facts)
    }

    /// The fact of each of `credentials` in `txn`: its fence's, or owed
    /// when no fence wrote but an erase intent of one of its keys stands.
    /// One with neither was erased by no committed writer and has none. A
    /// fence row that does not read is warned and left to the finisher.
    ///
    /// # Errors
    /// Storage faults reading the erase intents.
    fn committed_fence_facts_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credentials: &BTreeSet<EntityId>,
    ) -> Result<Vec<CredentialFenceFact>> {
        let mut facts = Vec::with_capacity(credentials.len());
        let mut unfenced = Vec::new();
        for credential in credentials {
            match FENCES.get(self, txn, credential) {
                Ok(Some(discovery)) => facts.push(CredentialFenceFact {
                    credential: *credential,
                    fact: self.fence_fact(txn, credential, discovery),
                }),
                Ok(None) => unfenced.push(*credential),
                Err(error) => tracing::warn!(
                    credential = %credential.to_hex(),
                    kind = ?error.kind(),
                    "an erased credential's fence did not read; the finisher hands it over"
                ),
            }
        }
        if unfenced.is_empty() {
            return Ok(facts);
        }
        let erasing: BTreeSet<EntityId> = credential_intents_in_txn(self, txn)?
            .into_iter()
            .filter(|(_, intent)| intent.cause == RetireCause::Erase)
            .map(|(parent, _)| parent)
            .collect();
        facts.extend(
            unfenced
                .into_iter()
                .filter(|credential| erasing.contains(credential))
                .map(|credential| CredentialFenceFact {
                    credential,
                    fact: FenceFact::Owed,
                }),
        );
        Ok(facts)
    }
}
