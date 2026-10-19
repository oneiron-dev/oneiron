//! The vault's one decision-answer signal (FIX 4706). Every
//! [`DecisionAsks`](super::DecisionAsks) over an open vault, and every door
//! that answers or withdraws an ask, shares the one sender its store holds.
//! A door signals only after the commit that answered or withdrew the ask
//! returned, never from inside a writer and never for a write that rolled
//! back, so a waiter it wakes reads the answer. The value is the last ask
//! number signalled (`send_replace`, never the highest: an older ask can be
//! answered later); a waiter never takes its answer from it, only from the
//! ask's row, and subscribes before that read, so no answer between the two
//! is lost. Nothing survives a restart here, and nothing needs to: a fresh
//! subscription reads the persisted answer at once.

use tokio::sync::watch;

use crate::Vault;

impl Vault {
    /// Wakes every waiter on ask `seq`. Call it only once the commit that
    /// answered or withdrew the ask returned.
    pub(crate) fn signal_decision_answer(&self, seq: u64) {
        self.store.decision_answers.send_replace(seq);
    }

    /// A subscription to the signal, taken before the waiter reads its ask.
    pub(super) fn subscribe_decision_answers(&self) -> watch::Receiver<u64> {
        self.store.decision_answers.subscribe()
    }
}
