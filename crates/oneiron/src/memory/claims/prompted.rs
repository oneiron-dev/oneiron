//! FIX 8192: a proposal whose words a model wrote from recalled rows. Its
//! birth names those rows as prompt inputs, so the owner's settings for the
//! worlds they lie in hold for the proposal on every later read and sync,
//! settings he changes later included (`settings::device_only` follows a
//! claim's prompt inputs). The rows are named by ref, never copied as text.

use super::*;
use crate::provenance::birth::RowBirth;
use crate::provenance::birth::prompted::prompt_input_held_in_txn;
use crate::provenance::made_by::MadeByClass;

impl Memory<'_> {
    /// [`Self::claim_propose`] for words a model wrote from a prompt that
    /// carried `producers`, read as `read` through `door`: the proposal's
    /// birth names each producer as a prompt input
    /// ([`Self::prompted_birth`]). With no producer it is
    /// [`Self::claim_propose`].
    pub fn claim_propose_prompted(
        &self,
        input: &ClaimInput,
        door: &str,
        producers: &[EntityId],
        read: &[&[u8]],
    ) -> MemoryResult<CommitReceipt> {
        let birth = self.prompted_birth(input, door, producers, read)?;
        self.commit_one_guarded_with_birth(
            input,
            false,
            Some(ClaimApprovalStatus::Proposed),
            || {},
            &|_: &heed::RoTxn<'_>| Ok(()),
            birth.as_ref(),
        )
    }

    /// The birth of `input`, proposed through `door` by this handle's actor
    /// from a prompt that carried `producers` and read as `read`: each
    /// producer, once, as a prompt input, an erased one included, by ref
    /// (rule 5 of FIX 8192). Only an id this vault never held as a row is
    /// left out, since it names nothing. `None` when no producer is left:
    /// the proposal is born as any proposal is.
    pub(super) fn prompted_birth(
        &self,
        input: &ClaimInput,
        door: &str,
        producers: &[EntityId],
        read: &[&[u8]],
    ) -> MemoryResult<Option<RowBirth>> {
        if producers.is_empty() {
            return Ok(None);
        }
        let held = {
            let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
            let mut held = Vec::with_capacity(producers.len());
            for row in producers {
                if prompt_input_held_in_txn(&self.vault.store, &rtxn, row)? {
                    held.push(*row);
                }
            }
            held
        };
        let class = MadeByClass::of_source(self.claim_source(&input.source)?);
        Ok(RowBirth::prompted(
            WriteActor::new(self.actor, self.actor_class),
            class,
            door,
            &held,
            read,
            self.vault.store.clock.now_recorded_at(),
        ))
    }
}
