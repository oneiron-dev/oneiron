//! A draft as solved-run evidence keeps it (CUA E8a; OF-560 secret
//! custody): no secret's value, and no handle the run held.
//!
//! A run's draft holds each secret slot's run-bound handle in its `args`
//! (E7 mints them from the run's custody), and the run's end erases those
//! handles: a durable copy that kept one would keep a handle of an ended
//! run. The copy drops every secret slot's argument and replay argument,
//! keeps each slot's name and kind ([`SecretParam`]) beside it, and drops
//! any other argument, replay argument or slot candidate whose text is a
//! handle's form. Its proposal then needs those slots bound again before
//! it replays, so it is not replay-ready; what its checks met stays true.

use super::{DraftOutput, SecretParam, handle_form};

/// A draft with no secret slot's value and no handle's text, and the slots
/// it names by name and kind.
pub(crate) struct DurableDraft {
    pub(crate) draft: DraftOutput,
    pub(crate) secret_slots: Vec<SecretParam>,
    /// Whether the draft replays as it is: complete, and every parameter
    /// has its argument.
    pub(crate) replay_ready: bool,
}

/// `draft`, whose proposal names `secret_slots`, as evidence keeps it.
pub(crate) fn durable_draft(
    mut draft: DraftOutput,
    secret_slots: Vec<SecretParam>,
) -> DurableDraft {
    let proposal = &mut draft.proposal;
    for slot in &secret_slots {
        proposal.args.remove(&slot.name);
        proposal.replay_args.remove(&slot.name);
    }
    proposal.args.retain(|_, value| !handle_form(value));
    proposal.replay_args.retain(|_, value| !handle_form(value));
    let bound = proposal
        .params
        .iter()
        .all(|param| proposal.args.contains_key(param));
    draft
        .slot_candidates
        .retain(|candidate| !handle_form(&candidate.literal));
    let replay_ready = draft.complete && bound;
    DurableDraft {
        draft,
        secret_slots,
        replay_ready,
    }
}
