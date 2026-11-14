//! `vault.conversations.turn.rebind` (FIX 6108): a queued turn action whose
//! slip no longer stands is rebound, by the requester who asked it, to the
//! live slip this request was admitted on. The authority holds the proof
//! ([`crate::Vault::rebind_invocation_slip_in_txn`]); this door finds the
//! action, swaps its slip in the same writer, records the slip it stood on
//! before, and answers both. Only an action still waiting for its worker
//! rebinds: one that ran, or runs now, is asked again as before. The action
//! keeps everything else it was asked with, and its standing is judged
//! again on the new slip whenever it is judged.

use super::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionAuthority};
use crate::Error;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::conversation::turn_actions::rebind::{
    TurnActionRebindReceipt, TurnActionRebindRequest,
};

/// A 32-hex attempt id.
fn attempt_id(hex: &str) -> MemoryResult<AttemptId> {
    let refused = || MemoryError::bad_request("attempt_id is not a 32-hex attempt id");
    if hex.len() != 32 {
        return Err(refused());
    }
    let mut bytes = [0_u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| refused())
}

impl Memory<'_> {
    /// `vault.conversations.turn.rebind`: rebinds the queued turn action
    /// `attempt_id`, which this handle's actor asked and whose slip no
    /// longer stands, to the live slip this request was admitted on (FIX
    /// 6108). An action another actor asked reads as not found, so the
    /// refusal tells nothing of it. The action must still wait for its
    /// worker, and the proof must hold
    /// ([`crate::Vault::rebind_invocation_slip_in_txn`]).
    pub fn conversations_turn_rebind(
        &self,
        request: &TurnActionRebindRequest,
    ) -> MemoryResult<TurnActionRebindReceipt> {
        let Some(successor) = self.invocation_slip().cloned() else {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a turn action rebinds to the live slip the rebind's own request was admitted on",
                &["Present a live capability slip with its holder proof."],
            ));
        };
        let id = attempt_id(&request.attempt_id)?;
        let vault = self.vault();
        let requester = (self.actor(), self.actor_class());
        let now = vault.now_recorded_at();
        let (action, rebind) = vault.with_write_txn_grouped(|txn| {
            let queue = AttemptQueue::new(vault);
            let record = queue.get_in_txn(txn, id)?.ok_or(Error::EntityNotFound)?;
            if record.kind != TURN_ACTION_ATTEMPT_KIND {
                return Err(Error::EntityNotFound);
            }
            let mut action = TurnActionAttempt::decode(&record)?;
            if action.requester()? != requester {
                return Err(Error::EntityNotFound);
            }
            let TurnActionAuthority::Slip { binding } = &action.authority else {
                return Err(Error::InvalidConfig(
                    "this turn action stands on no slip; nothing to rebind".to_owned(),
                ));
            };
            let rebind = vault.rebind_invocation_slip_in_txn(
                txn,
                binding,
                &successor,
                requester.0,
                requester.1.gate_actor_class(),
            )?;
            action.rebound_from.push(rebind.predecessor);
            action.authority = TurnActionAuthority::Slip {
                binding: successor.clone(),
            };
            queue.replace_waiting_payload_in_txn(
                txn,
                id,
                TURN_ACTION_ATTEMPT_KIND,
                action.encode()?,
                now,
            )?;
            Ok((action, rebind))
        })?;
        Ok(TurnActionRebindReceipt {
            action: action.action,
            turn_id: action.assistant_turn.to_hex(),
            attempt_id: crate::entity_id::bytes_to_hex_lower(id.as_bytes()),
            predecessor_slip: crate::entity_id::bytes_to_hex_lower(&rebind.predecessor),
            successor_slip: crate::entity_id::bytes_to_hex_lower(&rebind.successor),
            owner_work: rebind.owner_work,
        })
    }
}
