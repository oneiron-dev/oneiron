//! Caller-bound invocation outcomes use the actual session's RAM keep.

use super::*;
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::InvocationEntry;

impl SessionWitnessContext<'_> {
    /// Rechecks the original credential, session instance, membership and
    /// captured mode before an asynchronous result is released.
    pub fn revalidate(&self) -> MemoryResult<()> {
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)
    }

    /// Claims a request in this actual session. Successful outcomes remain
    /// only in its RAM keep, and session close wakes waiters without a reply.
    /// The caller identity is native; `body` is the door's canonical call hash.
    pub fn claim_invocation(
        &self,
        invocation: InvocationId,
        body: [u8; 32],
    ) -> MemoryResult<InvocationEntry> {
        let key = self.session.hook_key()?;
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.session-invocation.v1\0");
        hasher.update(self.caller.actor.as_bytes());
        hasher.update(self.caller.actor_class.gate_actor_class().as_bytes());
        hasher.update(&body);
        let entry = self
            .caller
            .vault
            .verb_hook_state
            .session
            .claim_invocation(
                self.caller.vault,
                &key,
                &self.route,
                invocation,
                *hasher.finalize().as_bytes(),
            )?
            .ok_or_else(caller_refused)?;
        self.admit_in_txn(&txn)?;
        Ok(entry)
    }
}
