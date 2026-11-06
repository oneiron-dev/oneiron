//! The actual session keep owns successful invocation outcomes until close.

use super::*;

#[derive(Default)]
pub(in crate::runtime_hooks::verb) struct SessionInvocationClaims {
    held: Claims,
}

impl SessionInvocationClaims {
    pub(in crate::runtime_hooks::verb) fn claim(
        &self,
        vault: &Vault,
        invocation: InvocationId,
        body: [u8; 32],
    ) -> InvocationEntry {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = held.get(&invocation) {
            return if slot.body == body {
                InvocationEntry::Busy(InvocationWait(Arc::clone(slot)))
            } else {
                InvocationEntry::Conflict
            };
        }
        // Keep the original vault-wide in-flight exclusion: hooks distinguish
        // nested work from concurrent requests through this same claim.
        let entry = claim_in(
            &vault.verb_hook_state.claims,
            invocation,
            body,
            Some(Arc::clone(&self.held)),
        );
        if let InvocationEntry::Claimed(claim) = &entry {
            held.insert(invocation, Arc::clone(&claim.slot));
        }
        entry
    }
}

impl Drop for SessionInvocationClaims {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        for (_, slot) in held.drain() {
            // Force-clear completed replies too. Some(None) also fences a
            // late producer that still owns this slot after session close.
            *slot.ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(None);
            slot.woken.notify_all();
        }
    }
}
