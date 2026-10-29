//! `vault.turn_programs.rebind` (FIX 11429): a turn program's try whose
//! waking turn sealed a slip that no longer stands is rebound, by that
//! waking actor, to the live slip this request was admitted on, as a queued
//! turn action is (FIX 6108). The authority holds the proof
//! ([`crate::Vault::rebind_invocation_slip_in_txn`]); this door finds the
//! try's admission, swaps its sealed slip in the same writer, keeps the slip
//! it stood on before in the sealed authority's lineage, and answers both.
//! Only a try that has not settled rebinds. A try held because its authority
//! lapsed then finds it binding again and resumes as any returned lapse
//! does; its standing is judged again on the new slip whenever it is judged.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

use super::{ADMISSION, ATTEMPT};

/// Names the turn program try to rebind.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnProgramRebindRequest {
    /// 32-hex id of the try, as a program read names it (`job:` prefix
    /// allowed).
    pub attempt: String,
}

/// A rebound turn program try: the try, its admission and both slips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnProgramRebindReceipt {
    /// 32-hex id of the try.
    pub attempt: String,
    /// 64-hex id of the admission the try runs under.
    pub admission: String,
    /// 64-hex id of the slip the program stood on before: its predecessor.
    pub predecessor_slip: String,
    /// 64-hex id of the slip it stands on now: the one this request was
    /// admitted on.
    pub successor_slip: String,
    /// A live owner of this vault woke the program: owner work.
    pub owner_work: bool,
}

/// A 32-hex try id, `job:` prefix allowed.
fn attempt_id(text: &str) -> MemoryResult<AttemptId> {
    let refused = || MemoryError::bad_request("attempt is not a 32-hex attempt id");
    let text = text.trim();
    let id =
        EntityId::from_hex(text.strip_prefix("job:").unwrap_or(text)).map_err(|_| refused())?;
    AttemptId::from_bytes(id.as_bytes()).map_err(|_| refused())
}

/// `vault.turn_programs.rebind`: rebinds the turn program try `attempt`,
/// which this handle's actor's turn woke and whose sealed slip no longer
/// stands, to the live slip this request was admitted on (FIX 11429). A try
/// another actor's turn woke reads as not found, so the refusal tells
/// nothing of it. The try must not have settled, the proof must hold
/// ([`crate::Vault::rebind_invocation_slip_in_txn`]), and the successor must
/// be a slip a turn seals a program's authority from.
///
/// # Errors
///
/// A request admitted on no slip (forbidden); a malformed attempt id; a try
/// no program stamped for this actor (not found); one that stands on no
/// slip, has settled, or whose successor seals none; the rebind proof's
/// typed refusal; storage errors.
pub fn rebind_turn_program(
    memory: &Memory<'_>,
    input: &TurnProgramRebindRequest,
) -> MemoryResult<TurnProgramRebindReceipt> {
    let Some(successor) = memory.invocation_slip().cloned() else {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a turn program rebinds to the live slip the rebind's own request was admitted on",
            &["Present a live capability slip with its holder proof."],
        ));
    };
    let attempt = attempt_id(&input.attempt)?;
    let vault = memory.vault();
    let (actor, class) = (memory.actor(), memory.actor_class());
    let (admission, rebind) = vault.with_write_txn_grouped(|txn| {
        let stamp = ATTEMPT
            .get(vault, &*txn, &attempt)?
            .ok_or(Error::EntityNotFound)?;
        if stamp.attempt_id != *attempt.as_bytes()
            || stamp.actor != actor
            || stamp.actor_class != class as u8
        {
            return Err(Error::EntityNotFound);
        }
        let mut row = ADMISSION
            .get(vault, &*txn, &stamp.admission)?
            .ok_or(Error::EntityNotFound)?;
        if row.refused.is_some() || row.wake.authority.actor() != actor {
            return Err(Error::EntityNotFound);
        }
        let settled = DreamerRunnerStore::new(vault)
            .status_with_park_in_txn(&*txn, attempt)?
            .is_none_or(|(status, _)| status.attempt.state.is_terminal());
        if settled {
            return Err(Error::InvalidConfig(
                "a settled turn program try is never rebound; its next turn seals its own"
                    .to_owned(),
            ));
        }
        let predecessor = row
            .wake
            .authority
            .slip_instrument()
            .cloned()
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "this turn program stands on no slip; nothing to rebind".to_owned(),
                )
            })?;
        let rebind = vault.rebind_invocation_slip_in_txn(
            txn,
            &predecessor,
            &successor,
            actor,
            class.gate_actor_class(),
        )?;
        let proof = vault.invocation_slip_in_txn(txn, &successor)?;
        row.wake.authority = row
            .wake
            .authority
            .rebound_to(&proof, &successor)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "the live slip seals no turn program: it must be the waking actor's own \
                     untransferred, reusable slip that allows writes, with no invitation or \
                     delegation"
                        .to_owned(),
                )
            })?;
        ADMISSION.put(vault, txn, &stamp.admission, &row)?;
        Ok((stamp.admission, rebind))
    })?;
    // A try its lapsed authority held finds it binding again on the next pass.
    vault.store.notify_proactivity_changes();
    Ok(TurnProgramRebindReceipt {
        attempt: bytes_to_hex_lower(attempt.as_bytes()),
        admission: bytes_to_hex_lower(&admission),
        predecessor_slip: bytes_to_hex_lower(&rebind.predecessor),
        successor_slip: bytes_to_hex_lower(&rebind.successor),
        owner_work: rebind.owner_work,
    })
}
