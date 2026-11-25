//! The allocation side of the unit claims (row M2-I2, "the hold is the claim"; design pass 32
//! r2, section 7.2 points 3 to 6; Engine EM-15 and HOLD-IS-CLAIM-FOLD = A).
//!
//! A managed unit's hold on its period's allocation is its claim row and nothing else. The
//! standing of one allocation generation is a fold over that generation's claims and its
//! machines' node answers, read in the vault writer. There is one ledger: a restart has nothing
//! to rebuild, nothing can drift from the claims, and a unit of period n settles on n after n+1
//! is installed.
//!
//! - [`open_claim_in_txn`] is the reserve: the room check and the claim's put, in one write. A
//!   claim draws only on its own line's allocation, funded by its own wallet.
//! - [`claim_hold_in_txn`] is the take-up after a restart: the claim's own hold, no admission.
//! - [`super::settle_unit_in_txn`] is the settle: the claim's terminal, written in the job's
//!   terminal transaction, is the allocation's settle.
//! - [`record_node_answer_in_txn`] (EM-15) records that a machine answered since this start of
//!   the vault, with the occupied seconds of jobs it ran that this vault has no row for (after a
//!   restore). Those seconds shrink the room and charge no family, and a generation admits
//!   nothing until every machine of its line has answered since this start. An answer that lists
//!   a job still running is not yet an answer: the issuer stops a live orphan, and its seconds are
//!   final only at its terminal receipt (pass 33 section 8.5).

use serde::{Deserialize, Serialize};

use super::{CLAIMS, ClaimKey, ClaimState, UnitClaim, UnitEnd, UnitTerminal};
use crate::federation::WalletRef;
use crate::llm::run_admission::{Allocation, AllocationRef, gpu_line_allocation_id};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Vault};

/// (generation, machine, allocation id) -> the machine's answer since this start. The rows of
/// one generation number are one prefix scan; a read keeps the rows of its own allocation id.
const NODES: SideTable<(u64, EntityId, String), AllocationNodeRow, Named> =
    SideTable::new(&side_table::GPU_ALLOCATION_NODE);

/// One machine's newest answer for one allocation generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AllocationNodeRow {
    allocation: AllocationRef,
    machine: EntityId,
    /// The vault writer's acquisition the answer came in: one per start of the vault.
    answered_in: [u8; 16],
    /// The vault's clock.
    answered_at_ms: u64,
    /// Jobs the machine ran against this generation that no row of this vault names.
    unattributed: Vec<UnattributedJob>,
}

/// A job a machine ran for this vault that the vault has no row for, such as one that ran and
/// ended after the backup a restore came from (pass 33 section 8.5). Its seconds are recorded
/// against the generation its submit named. No family pays them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattributedJob {
    /// The machine's key for the job.
    pub node_key: String,
    /// Its occupied device seconds.
    pub secs: u64,
    /// The machine holds the job's terminal receipt, so `secs` is final. While the job runs,
    /// the issuer sends it `Stop` (pass 33 section 8.5), and its machine counts as unanswered:
    /// a live job's seconds still grow (review 10413 round 2).
    pub ended: bool,
}

/// Where one allocation generation stands: the fold over its claims and its machines' answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationStanding {
    pub allocation: AllocationRef,
    /// What the wallet granted this generation, in the line's unit.
    pub granted_units: u64,
    /// Charged by the generation's settled claims.
    pub charged_secs: u64,
    /// Occupied by jobs no claim names (EM-15). No family pays them; the owner sees them here.
    pub unattributed_secs: u64,
    /// Reserved, in full, by the generation's open claims. An unconfirmed job is open.
    pub held_secs: u64,
    pub open_claims: u32,
    /// The machines of the line with no answer since this start, or whose answer lists an
    /// unattributed job that has not ended, in the order the caller named them.
    pub unanswered_machines: Vec<EntityId>,
}

impl AllocationStanding {
    /// What the wallet counts as used: the charged seconds and the unattributed ones.
    #[must_use]
    pub fn used_secs(&self) -> u64 {
        self.charged_secs.saturating_add(self.unattributed_secs)
    }

    /// What a new claim may still reserve.
    #[must_use]
    pub fn room(&self) -> u64 {
        self.granted_units
            .saturating_sub(self.used_secs())
            .saturating_sub(self.held_secs)
    }
}

/// Why the claim writer wrote no claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimAdmissionRefused {
    /// The claim names another allocation generation than the one it is admitted on.
    OtherAllocation { claim: AllocationRef },
    /// The allocation is not the claim's own line's: a line's claims draw only on its own
    /// allocation (review 10413 P1).
    OtherLine { line: EntityId },
    /// The allocation is not funded by the wallet the claim names (review 10413 round 2).
    /// `funded_by` is the allocation's wallet; `None` when the host named none.
    OtherWallet { funded_by: Option<WalletRef> },
    /// A new claim is written `Claimed`.
    NotNew,
    /// A claim already stands under this logical attempt.
    ClaimExists,
    /// These machines of the line have not answered since this start, or a job their answer
    /// lists as unattributed is still running (EM-15).
    NodesUnanswered { machines: Vec<EntityId> },
    /// The reservation does not fit what is left.
    Exhausted { room: u64 },
}

impl std::fmt::Display for ClaimAdmissionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtherAllocation { claim } => write!(
                f,
                "the claim names allocation {} generation {}",
                claim.id, claim.generation
            ),
            Self::OtherLine { line } => write!(
                f,
                "the allocation is not line {}'s allocation",
                line.to_hex()
            ),
            Self::OtherWallet {
                funded_by: Some(wallet),
            } => write!(
                f,
                "the allocation is funded by wallet {}/{}, not the claim's",
                wallet.issuer, wallet.id
            ),
            Self::OtherWallet { funded_by: None } => {
                f.write_str("the allocation names no wallet, so no claim draws on it")
            }
            Self::NotNew => f.write_str("a new unit claim is written as claimed"),
            Self::ClaimExists => f.write_str("a unit claim already stands under this attempt"),
            Self::NodesUnanswered { machines } => write!(
                f,
                "{} machine(s) of the line have not answered since this start, or still run an \
                 unattributed job",
                machines.len()
            ),
            Self::Exhausted { room } => {
                write!(f, "the allocation has {room} second(s) left")
            }
        }
    }
}

impl std::error::Error for ClaimAdmissionRefused {}

/// A claim's hold, as the worker re-attaches it after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimHold {
    pub key: ClaimKey,
    /// The claim's own allocation generation, whatever is installed now.
    pub allocation: AllocationRef,
    pub reserved_secs: u64,
    /// The key of the claim's one bounded chunk: its job's first chunk.
    pub chunk_key: String,
    /// The claim's job row was written.
    pub started: bool,
}

/// Why no hold was re-attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimHoldRefused {
    /// No claim under the key.
    NoClaim,
    /// The claim's job is another job.
    OtherJob { claim_job: EntityId },
    /// The claim ended; it holds nothing.
    Ended { stored: Box<UnitTerminal> },
}

impl std::fmt::Display for ClaimHoldRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoClaim => f.write_str("no unit claim under this key"),
            Self::OtherJob { claim_job } => {
                write!(f, "this unit claim belongs to job {}", claim_job.to_hex())
            }
            Self::Ended { stored } => write!(f, "this unit claim ended as {:?}", stored.end),
        }
    }
}

impl std::error::Error for ClaimHoldRefused {}

/// The standing of `allocation`'s generation: its claims folded (open ones hold their full
/// reservation, settled ones their charge, any other end nothing) and its machines' answers
/// since this start. `machines` are the machines the line names. A machine has answered once
/// its answer since this start lists no unattributed job still running.
///
/// # Errors
///
/// A store failure.
pub fn allocation_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    allocation: &Allocation,
    machines: &[EntityId],
) -> crate::Result<AllocationStanding> {
    let reference = &allocation.reference;
    let mut standing = AllocationStanding {
        allocation: reference.clone(),
        granted_units: allocation.units,
        charged_secs: 0,
        unattributed_secs: 0,
        held_secs: 0,
        open_claims: 0,
        unanswered_machines: Vec::new(),
    };
    for (_, claim) in CLAIMS.scan(&vault.store, txn)? {
        if claim.allocation != *reference {
            continue;
        }
        match &claim.state {
            ClaimState::Claimed | ClaimState::Started => {
                standing.held_secs = standing.held_secs.saturating_add(claim.reserved_secs);
                standing.open_claims = standing.open_claims.saturating_add(1);
            }
            ClaimState::Ended(UnitTerminal {
                end: UnitEnd::Settled,
                charged_secs,
                ..
            }) => standing.charged_secs = standing.charged_secs.saturating_add(*charged_secs),
            ClaimState::Ended(_) => {}
        }
    }
    let serving = serving_start(vault);
    let mut answered = Vec::new();
    for (_, row) in NODES.scan_from(&vault.store, txn, &generation_prefix(reference))? {
        if row.allocation != *reference {
            continue;
        }
        standing.unattributed_secs = row
            .unattributed
            .iter()
            .fold(standing.unattributed_secs, |sum, job| {
                sum.saturating_add(job.secs)
            });
        if serving == Some(row.answered_in) && row.unattributed.iter().all(|job| job.ended) {
            answered.push(row.machine);
        }
    }
    for machine in machines {
        if !answered.contains(machine) && !standing.unanswered_machines.contains(machine) {
            standing.unanswered_machines.push(*machine);
        }
    }
    Ok(standing)
}

/// Writes the new claim `claim` on `allocation`, in the caller's write transaction, if
/// `allocation` is the claim's own line's and funded by the claim's wallet, every machine of the
/// line (`machines`) has answered since this start, and its reservation fits.
/// The claim's row is its hold. Answers the standing with the claim in it, or why nothing was
/// written.
///
/// # Errors
///
/// A store failure.
pub fn open_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    allocation: &Allocation,
    machines: &[EntityId],
    claim: &UnitClaim,
) -> crate::Result<Result<AllocationStanding, ClaimAdmissionRefused>> {
    if claim.allocation != allocation.reference {
        return Ok(Err(ClaimAdmissionRefused::OtherAllocation {
            claim: claim.allocation.clone(),
        }));
    }
    if allocation.reference.id != gpu_line_allocation_id(&claim.line) {
        return Ok(Err(ClaimAdmissionRefused::OtherLine { line: claim.line }));
    }
    if allocation.wallet.as_ref() != Some(&claim.wallet) {
        return Ok(Err(ClaimAdmissionRefused::OtherWallet {
            funded_by: allocation.wallet.clone(),
        }));
    }
    if claim.state != ClaimState::Claimed {
        return Ok(Err(ClaimAdmissionRefused::NotNew));
    }
    let key = claim.key();
    if CLAIMS.get(&vault.store, txn, &key)?.is_some() {
        return Ok(Err(ClaimAdmissionRefused::ClaimExists));
    }
    let mut standing = allocation_standing_in_txn(vault, txn, allocation, machines)?;
    if !standing.unanswered_machines.is_empty() {
        return Ok(Err(ClaimAdmissionRefused::NodesUnanswered {
            machines: standing.unanswered_machines,
        }));
    }
    let room = standing.room();
    if claim.reserved_secs > room {
        return Ok(Err(ClaimAdmissionRefused::Exhausted { room }));
    }
    CLAIMS.put(&vault.store, txn, &key, claim)?;
    standing.held_secs = standing.held_secs.saturating_add(claim.reserved_secs);
    standing.open_claims = standing.open_claims.saturating_add(1);
    Ok(Ok(standing))
}

/// The hold of the open claim under `key`, whose job is `job`, as a restarted worker
/// re-attaches it: on the claim's own allocation generation, with no admission and no read of
/// what the host has installed since.
///
/// # Errors
///
/// A store failure.
pub fn claim_hold_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &ClaimKey,
    job: &EntityId,
) -> crate::Result<Result<ClaimHold, ClaimHoldRefused>> {
    let Some(claim) = CLAIMS.get(&vault.store, txn, key)? else {
        return Ok(Err(ClaimHoldRefused::NoClaim));
    };
    if claim.id != *job {
        return Ok(Err(ClaimHoldRefused::OtherJob {
            claim_job: claim.id,
        }));
    }
    let started = match claim.state {
        ClaimState::Claimed => false,
        ClaimState::Started => true,
        ClaimState::Ended(stored) => {
            return Ok(Err(ClaimHoldRefused::Ended {
                stored: Box::new(stored),
            }));
        }
    };
    Ok(Ok(ClaimHold {
        key: *key,
        allocation: claim.allocation,
        reserved_secs: claim.reserved_secs,
        chunk_key: format!("{}:0", claim.id.to_hex()),
        started,
    }))
}

/// One machine's answer for one allocation generation that lists jobs it ran against that
/// generation which no row of this vault names (EM-15), as [`unattributed_in_txn`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattributedRecord {
    pub allocation: AllocationRef,
    pub machine: EntityId,
    /// The vault's clock at the machine's newest answer.
    pub answered_at_ms: u64,
    pub jobs: Vec<UnattributedJob>,
}

impl UnattributedRecord {
    /// The GPU line and the period this generation is, when the allocation is a line's: its id
    /// is [`gpu_line_allocation_id`] of the line's lane project, and its generation is the
    /// period index plus one (`mint_period`). `None` for any other allocation, and for
    /// generation 0, which no period has.
    #[must_use]
    pub fn line_period(&self) -> Option<(EntityId, u32)> {
        let (_, hex) = self.allocation.id.rsplit_once(':')?;
        let line = EntityId::from_hex(hex).ok()?;
        if gpu_line_allocation_id(&line) != self.allocation.id {
            return None;
        }
        let index = self.allocation.generation.checked_sub(1)?;
        let period = u32::try_from(index).ok()?;
        Some((line, period))
    }
}

/// Every machine's answer, of every allocation generation, that lists an unattributed job, in
/// `txn`: for a read that joins them to other rows of one snapshot (`vault.jobs.history`).
///
/// # Errors
///
/// A store failure.
pub fn unattributed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<Vec<UnattributedRecord>> {
    let records = NODES
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(_, row)| !row.unattributed.is_empty())
        .map(|(_, row)| UnattributedRecord {
            allocation: row.allocation,
            machine: row.machine,
            answered_at_ms: row.answered_at_ms,
            jobs: row.unattributed,
        })
        .collect();
    Ok(records)
}

/// Records that `machine` answered for `allocation`'s generation since this start of the
/// vault, with `unattributed`, the jobs it ran against that generation that no row of this
/// vault names. A node key counts once: a repeat keeps the larger seconds, since a live job's
/// seconds only grow, and a job that ended stays ended. Written by the issuer's reconcile once
/// the machine answered its keys, and again at each receipt of a job it stopped.
///
/// # Errors
///
/// No writer lease of this process on the vault, or a store failure.
pub fn record_node_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    allocation: &AllocationRef,
    machine: EntityId,
    unattributed: &[UnattributedJob],
    now_ms: u64,
) -> crate::Result<()> {
    let Some(serving) = serving_start(vault) else {
        return Err(Error::InvalidConfig(
            "a machine's answer needs this process's vault writer lease".to_owned(),
        ));
    };
    let key = (allocation.generation, machine, allocation.id.clone());
    let mut row = match NODES.get(&vault.store, txn, &key)? {
        Some(row) => row,
        None => AllocationNodeRow {
            allocation: allocation.clone(),
            machine,
            answered_in: serving,
            answered_at_ms: now_ms,
            unattributed: Vec::new(),
        },
    };
    row.answered_in = serving;
    row.answered_at_ms = now_ms;
    for job in unattributed {
        match row
            .unattributed
            .iter_mut()
            .find(|kept| kept.node_key == job.node_key)
        {
            Some(kept) => {
                kept.secs = kept.secs.max(job.secs);
                kept.ended |= job.ended;
            }
            None => row.unattributed.push(job.clone()),
        }
    }
    NODES.put(&vault.store, txn, &key, &row)
}

/// The acquisition of this process's writer lease on the vault: one per start.
fn serving_start(vault: &Vault) -> Option<[u8; 16]> {
    vault
        .writer_lease()
        .filter(|lease| lease.held_by_current_process())
        .map(|lease| lease.acquisition_id())
}

fn generation_prefix(allocation: &AllocationRef) -> Vec<u8> {
    let mut prefix = Vec::new();
    allocation.generation.encode_into(&mut prefix);
    prefix
}
