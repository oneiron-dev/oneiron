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
//!
//! A wake its turn owes and no admission has judged yet rebinds the same way
//! (FIX 11833): named by its turn and the armed program's registration, its
//! sealed slip is swapped on the owed row through the same proof, and its
//! admission runs on the new slip in that same writer, so no concurrent
//! admission judges or runs the old slip: a drain that read the wake before
//! finds it admitted and admits nothing. A wake whose admission already
//! refused it on the lapse keeps that refusal: it is the lapsed slip's own
//! status.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::authority::{InstrumentRebind, InvocationSlipBinding};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, Vault};

use super::authority::TurnProgramAuthority;
use super::types::TurnProgramAdmissionOutcome;
use super::{ADMISSION, ATTEMPT, WAKE};

/// Names what to rebind: an admitted try by `attempt`, or a wake its turn
/// owes and no admission has judged yet by `turn_ref` and `registration`
/// (FIX 11833). Exactly one of the two.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnProgramRebindRequest {
    /// 32-hex id of the try, as a program read names it (`job:` prefix
    /// allowed).
    #[serde(default)]
    pub attempt: Option<String>,
    /// 32-hex id of the TURN whose landing owes the wake.
    #[serde(default)]
    pub turn_ref: Option<String>,
    /// 32-hex registration of the armed program the turn woke.
    #[serde(default)]
    pub registration: Option<String>,
}

/// A rebound turn program try or owed wake: the try, its admission and both
/// slips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnProgramRebindReceipt {
    /// 32-hex id of the try: the one rebound, or the root try an owed
    /// wake's admission queued on the new slip. None when that admission
    /// refused the wake.
    pub attempt: Option<String>,
    /// 64-hex id of the admission the try runs under, or the owed wake's.
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

/// What one rebind request names.
enum RebindTarget {
    /// An admitted try.
    Try(AttemptId),
    /// An owed wake, by its row key: the turn, then the registration.
    OwedWake((EntityId, EntityId)),
}

impl RebindTarget {
    fn of(input: &TurnProgramRebindRequest) -> MemoryResult<Self> {
        let id = |text: &str, what: &str| {
            EntityId::from_hex(text.trim())
                .map_err(|_| MemoryError::bad_request(format!("{what} is not a 32-hex id")))
        };
        match (&input.attempt, &input.turn_ref, &input.registration) {
            (Some(attempt), None, None) => Ok(Self::Try(attempt_id(attempt)?)),
            (None, Some(turn), Some(registration)) => Ok(Self::OwedWake((
                id(turn.as_str(), "turn_ref")?,
                id(registration.as_str(), "registration")?,
            ))),
            _ => Err(MemoryError::bad_request(
                "name an admitted try by attempt, or an owed wake by turn_ref and registration",
            )),
        }
    }
}

/// `vault.turn_programs.rebind`: rebinds the turn program try `attempt`,
/// which this handle's actor's turn woke and whose sealed slip no longer
/// stands, to the live slip this request was admitted on (FIX 11429), or the
/// wake that actor's turn `turn_ref` owes the program `registration` and no
/// admission has judged yet (FIX 11833), then admits it. A try or wake
/// another actor's turn woke reads as not found, so the refusal tells
/// nothing of it. A try must not have settled, the proof must hold
/// ([`crate::Vault::rebind_invocation_slip_in_txn`]), and the successor must
/// be a slip a turn seals a program's authority from.
///
/// # Errors
///
/// A request admitted on no slip (forbidden); a malformed or ambiguous
/// target; a try no program stamped for this actor, or a wake its turn does
/// not owe for this actor (not found); one that stands on no slip, a try
/// that has settled, or a successor that seals none; the rebind proof's
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
    match RebindTarget::of(input)? {
        RebindTarget::Try(attempt) => rebind_try(memory, &successor, attempt),
        RebindTarget::OwedWake(key) => rebind_owed_wake(memory, &successor, key),
    }
}

/// An admitted, unsettled try's rebind (FIX 11429).
fn rebind_try(
    memory: &Memory<'_>,
    successor: &InvocationSlipBinding,
    attempt: AttemptId,
) -> MemoryResult<TurnProgramRebindReceipt> {
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
        let (authority, rebind) =
            rebound_in_txn(vault, txn, &row.wake.authority, successor, actor, class)?;
        row.wake.authority = authority;
        ADMISSION.put(vault, txn, &stamp.admission, &row)?;
        Ok((stamp.admission, rebind))
    })?;
    // A try its lapsed authority held finds it binding again on the next pass.
    vault.store.notify_proactivity_changes();
    Ok(receipt(Some(attempt), admission, &rebind))
}

/// An owed wake's rebind (FIX 11833): the wake `key` names, owed to this
/// handle's actor and judged by no admission yet, is sealed on the live
/// slip and admitted on it in ONE writer: the proof, the swap and the
/// admission (the drain's own, `admit_in_txn`) commit together, so no
/// admission ever judges the old slip after the swap. A drain that read the
/// wake before this writer finds it admitted on the new slip and admits
/// nothing; one that admitted it first leaves no owed wake here.
fn rebind_owed_wake(
    memory: &Memory<'_>,
    successor: &InvocationSlipBinding,
    key: (EntityId, EntityId),
) -> MemoryResult<TurnProgramRebindReceipt> {
    let vault = memory.vault();
    let (actor, class) = (memory.actor(), memory.actor_class());
    let now = vault.now_recorded_at();
    let (admitted, rebind) = vault.with_write_txn_grouped(|txn| {
        let mut wake = WAKE.get(vault, &*txn, &key)?.ok_or(Error::EntityNotFound)?;
        if wake.key() != key
            || wake.authority.actor() != actor
            || wake.authority.class_byte() != class as u8
        {
            return Err(Error::EntityNotFound);
        }
        if ADMISSION.contains(vault, &*txn, &wake.admission_id())? {
            return Err(Error::InvalidConfig(
                "this wake was admitted; rebind its try by attempt".to_owned(),
            ));
        }
        let (authority, rebind) =
            rebound_in_txn(vault, txn, &wake.authority, successor, actor, class)?;
        wake.authority = authority;
        // The owed row holds the rebound wake until its admission, in this
        // writer, consumes it.
        WAKE.put(vault, txn, &key, &wake)?;
        Ok((super::admit::admit_in_txn(vault, txn, &wake, now)?, rebind))
    })?;
    let attempt = match admitted.outcome {
        TurnProgramAdmissionOutcome::Queued { attempt, .. } => {
            // As `admit_turn_program` after its writer: the queued program
            // is news to the attempt observers and the deadline lane.
            vault.store.notify_attempt_observers();
            vault.store.notify_proactivity_changes();
            Some(attempt)
        }
        TurnProgramAdmissionOutcome::Refused { .. } => None,
    };
    Ok(receipt(attempt, admitted.admission, &rebind))
}

/// `authority`, a try's or an owed wake's sealed authority, sealed instead
/// on `successor` in `txn`, the writer that swaps it, with the proof
/// ([`Vault::rebind_invocation_slip_in_txn`]) that admits the swap.
///
/// # Errors
///
/// An authority that stands on no slip, a successor that seals no turn
/// program, and the proof's typed refusal.
fn rebound_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: &TurnProgramAuthority,
    successor: &InvocationSlipBinding,
    actor: EntityId,
    class: EdgeActorClass,
) -> Result<(TurnProgramAuthority, InstrumentRebind)> {
    let predecessor = authority.slip_instrument().cloned().ok_or_else(|| {
        Error::InvalidConfig("this turn program stands on no slip; nothing to rebind".to_owned())
    })?;
    let rebind = vault.rebind_invocation_slip_in_txn(
        txn,
        &predecessor,
        successor,
        actor,
        class.gate_actor_class(),
    )?;
    let proof = vault.invocation_slip_in_txn(txn, successor)?;
    let rebound = authority.rebound_to(&proof, successor).ok_or_else(|| {
        Error::InvalidConfig(
            "the live slip seals no turn program: it must be the waking actor's own \
             untransferred, reusable slip that allows writes, with no invitation or \
             delegation"
                .to_owned(),
        )
    })?;
    Ok((rebound, rebind))
}

/// The door's answer for one rebind.
fn receipt(
    attempt: Option<AttemptId>,
    admission: [u8; 32],
    rebind: &InstrumentRebind,
) -> TurnProgramRebindReceipt {
    TurnProgramRebindReceipt {
        attempt: attempt.map(|attempt| bytes_to_hex_lower(attempt.as_bytes())),
        admission: bytes_to_hex_lower(&admission),
        predecessor_slip: bytes_to_hex_lower(&rebind.predecessor),
        successor_slip: bytes_to_hex_lower(&rebind.successor),
        owner_work: rebind.owner_work,
    }
}
