//! FIX 8192: a proposal whose words a model wrote from recalled rows. Its
//! birth names those rows as prompt inputs, so the owner's settings for the
//! worlds they lie in hold for the proposal on every later read and sync,
//! settings he changes later included (`settings::device_only` follows a
//! claim's prompt inputs). The rows are named by ref, never copied as text.

use super::*;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;

impl Memory<'_> {
    /// [`Self::claim_propose`] for words a model wrote from a prompt that
    /// carried `producers`, read as `read` through `door`: the proposal's
    /// birth names each producer still live here as a prompt input
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
    /// producer still live here, once, as a prompt input. A producer gone
    /// since the prompt was built names no row a birth may point at, so it
    /// drops out. `None` when no producer is live: the proposal is born as
    /// any proposal is.
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
        let live = {
            let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
            let mut live = Vec::with_capacity(producers.len());
            for row in producers {
                let state = crate::vault::live_entity_row_in_txn(&self.vault.store, &rtxn, row)?;
                if state.is_live() {
                    live.push(*row);
                }
            }
            live
        };
        let class = MadeByClass::of_source(self.claim_source(&input.source)?);
        Ok(RowBirth::prompted(
            WriteActor::new(self.actor, self.actor_class),
            class,
            door,
            &live,
            read,
            self.vault.store.clock.now_recorded_at(),
        ))
    }
}
