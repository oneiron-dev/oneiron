//! The allocation side of the unit claims (row M2-I2, "the hold is the claim"; design pass 32
//! r2, section 7.2 points 3 to 6; Engine EM-15 and HOLD-IS-CLAIM-FOLD = A).
//!
//! A managed unit's hold on its period's allocation is its claim row and nothing else. The
//! standing of one allocation generation is a fold over that generation's claims and its
//! machines' node answers, read in the vault writer. There is one ledger: a restart has nothing
//! to rebuild, nothing can drift from the claims, and a unit of period n settles on n after n+1
//! is installed.
//!
//! - [`open_claim_in_txn`] is the reserve: the room check and the claim's put, in one write.
//! - [`claim_hold_in_txn`] is the take-up after a restart: the claim's own hold, no admission.
//! - [`super::settle_unit_in_txn`] is the settle: the claim's terminal, written in the job's
//!   terminal transaction, is the allocation's settle.
//! - [`record_node_answer_in_txn`] (EM-15) records that a machine answered since this start of
//!   the vault, with the occupied seconds of jobs it ran that this vault has no row for (after a
//!   restore). Those seconds shrink the room and charge no family, and a generation admits
//!   nothing until every machine of its line has answered since this start.

use serde::{Deserialize, Serialize};

use super::{CLAIMS, ClaimKey, ClaimState, UnitClaim, UnitEnd, UnitTerminal};
use crate::llm::run_admission::{Allocation, AllocationRef};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Vault};

/// Domain of an allocation id's digest in a node answer's row key.
const ALLOCATION_ID_CONTEXT: &str = "oneiron gpu allocation id v1";

/// (allocation, generation, machine) -> the machine's answer since this start.
const NODES: SideTable<AllocationNodeKey, AllocationNodeRow, Named> =
    SideTable::new(&side_table::GPU_ALLOCATION_NODE);

/// A node answer's row key. The rows of one generation are one prefix scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SideKey)]
struct AllocationNodeKey {
    /// The first 16 bytes of the BLAKE3 digest of the allocation id.
    allocation_id_digest: [u8; 16],
    generation: u64,
    machine: EntityId,
}

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
    /// The machines of the line with no answer since this start, in the order the caller
    /// named them.
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
    /// A new claim is written `Claimed`.
    NotNew,
    /// A claim already stands under this logical attempt.
    ClaimExists,
    /// These machines of the line have not answered since this start (EM-15).
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
            Self::NotNew => f.write_str("a new unit claim is written as claimed"),
            Self::ClaimExists => f.write_str("a unit claim already stands under this attempt"),
            Self::NodesUnanswered { machines } => write!(
                f,
                "{} machine(s) of the line have not answered since this start",
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
/// since this start. `machines` are the machines the line names.
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
        if serving == Some(row.answered_in) {
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

/// Writes the new claim `claim` on `allocation`, in the caller's write transaction, if every
/// machine of the line (`machines`) has answered since this start and its reservation fits.
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

/// Records that `machine` answered for `allocation`'s generation since this start of the
/// vault, with `unattributed`, the jobs it ran against that generation that no row of this
/// vault names. A node key counts once: a repeat keeps the larger seconds, since a live job's
/// seconds only grow. Written by the issuer's reconcile once the machine answered its keys.
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
    let key = AllocationNodeKey {
        allocation_id_digest: allocation_id_digest(&allocation.id),
        generation: allocation.generation,
        machine,
    };
    let mut row = match NODES.get(&vault.store, txn, &key)? {
        Some(row) if row.allocation == *allocation => row,
        Some(_) => {
            return Err(Error::InvalidConfig(
                "two allocation ids share a digest".to_owned(),
            ));
        }
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
            Some(kept) => kept.secs = kept.secs.max(job.secs),
            None => row.unattributed.push(job.clone()),
        }
    }
    NODES.put(&vault.store, txn, &key, &row)
}

/// Marks the open claim under `key` started, as the start gate writes it when it inserts the
/// claim's job row (row M2-C). The test door's seam until that gate lands.
#[cfg(oneiron_test_support)]
pub(crate) fn start_claim_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ClaimKey,
) -> crate::Result<()> {
    let Some(mut claim) = CLAIMS.get(&vault.store, txn, key)? else {
        return Err(Error::InvalidConfig(
            "no unit claim under this key".to_owned(),
        ));
    };
    if claim.state != ClaimState::Claimed {
        return Err(Error::InvalidConfig(
            "only a claimed unit starts".to_owned(),
        ));
    }
    claim.state = ClaimState::Started;
    claim.revision += 1;
    CLAIMS.put(&vault.store, txn, key, &claim)
}

/// The acquisition of this process's writer lease on the vault: one per start.
fn serving_start(vault: &Vault) -> Option<[u8; 16]> {
    vault
        .writer_lease()
        .filter(|lease| lease.held_by_current_process())
        .map(|lease| lease.acquisition_id())
}

fn allocation_id_digest(id: &str) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key(ALLOCATION_ID_CONTEXT);
    hasher.update(id.as_bytes());
    let mut digest = [0_u8; 16];
    digest.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    digest
}

fn generation_prefix(allocation: &AllocationRef) -> Vec<u8> {
    let mut prefix = Vec::new();
    allocation_id_digest(&allocation.id).encode_into(&mut prefix);
    allocation.generation.encode_into(&mut prefix);
    prefix
}
