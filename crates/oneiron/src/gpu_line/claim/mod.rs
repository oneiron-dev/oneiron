//! The unit claim of the lane economy (design pass 32 r2, section 3.4): the line's ledger entry
//! for one logical attempt of one unit, and the durable record of its wallet hold.
//!
//! A claim is keyed by the logical attempt (arm, rung, unit key, attempt), so a lost reply and a
//! retry under a fresh intent key find the same claim and never make a second one. Its id is
//! fixed at the reservation and is also the id of the one GPU job it may start. The fold reads
//! claims alone ([`UnitClaim::spend_row`]): a claim that has not ended holds its full reserved
//! seconds, and only a confirmed end frees room.
//!
//! The terminal is written once, by [`settle_unit_in_txn`], in the same write transaction as
//! the job's terminal row (section 7.2 point 6). It lands the machine, the device, the measured
//! seconds, the end cause and the output digests on the claim, so every arm view keeps them
//! after the machine's own records age out. What each end charges is the table of section 7.3:
//! a run that ended pays `min(billed, reserved)`; a confirmed refusal before anything ran, a
//! lost machine and an owner's write-off pay nothing.
//!
//! The claim is also the hold on its period's allocation (row M2-I2): the allocation's
//! standing is a fold over its claims ([`allocation_standing_in_txn`]), so the claim's terminal
//! is the allocation's settle.

use oneiron_contracts::fingerprint::{Fingerprint, purposes};
use serde::{Deserialize, Serialize};

use crate::experiment_arm::ArmEvidenceDigest;
use crate::federation::WalletRef;
use crate::gpu_job::{GpuJobEnd, GpuJobTerminal};
use crate::gpu_line::{Draw, SpendRow, UnitCharge, defaults, stored_period_in_txn};
use crate::llm::run_admission::AllocationRef;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Vault};

mod allocation;
pub(crate) mod tables;

pub use allocation::{
    AllocationStanding, ClaimAdmissionRefused, ClaimHold, ClaimHoldRefused, UnattributedJob,
    UnattributedRecord, allocation_standing_in_txn, claim_hold_in_txn, open_claim_in_txn,
    record_node_answer_in_txn, unattributed_in_txn,
};

/// The logical attempt -> its claim.
const CLAIMS: SideTable<ClaimKey, UnitClaim, Named> =
    SideTable::new(&side_table::EXPERIMENT_ARM_UNIT);

/// A claim's row key: the logical attempt. Rows of one arm sort together, then by rung, so a
/// rung's claims are one prefix scan.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SideKey, Serialize, Deserialize,
)]
pub struct ClaimKey {
    pub arm: EntityId,
    /// 1 is the first rung.
    pub rung: u8,
    /// The first 16 bytes of the unit key's fingerprint (purpose `gpu_line::UNIT_KEY`).
    pub unit_key_digest: [u8; 16],
    /// 1 is the first attempt.
    pub attempt: u16,
}

impl ClaimKey {
    /// The key of attempt `attempt` of unit `unit_key` at rung `rung` of arm `arm`.
    #[must_use]
    pub fn of(arm: EntityId, rung: u8, unit_key: &str, attempt: u16) -> Self {
        let digest = Fingerprint::of_parts(purposes::gpu_line::UNIT_KEY, &[unit_key.as_bytes()])
            .into_bytes();
        let mut unit_key_digest = [0_u8; 16];
        unit_key_digest.copy_from_slice(&digest[..16]);
        Self {
            arm,
            rung,
            unit_key_digest,
            attempt,
        }
    }

    /// The key's bytes after the table's prefix (what an intent row names as `written`).
    #[must_use]
    pub fn key_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// The key whose bytes are `bytes`; `None` for bytes of another shape.
    #[must_use]
    pub fn from_key_bytes(bytes: &[u8]) -> Option<Self> {
        Self::decode_key(bytes)
    }
}

/// What a unit is for (section 4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnitPurpose {
    /// The arm's own work at its rung, inside the rung cap.
    Work,
    /// The reviewer's check of a promote, outside the rung cap and inside the rung's
    /// review-check seconds.
    ReviewCheck,
}

/// One unit claim (section 3.4). Every field but `state`, `reserved_by` and `revision` is fixed
/// at the reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitClaim {
    /// Also the id of the claim's one GPU job: fixed here, before any quote.
    pub id: EntityId,
    pub arm: EntityId,
    /// 1 is the first rung.
    pub rung: u8,
    pub unit_key: String,
    /// 1 is the first attempt; attempt `n + 1` needs attempt `n` ended.
    pub attempt: u16,
    /// The line: id16 of the lane project.
    pub line: EntityId,
    pub family: EntityId,
    pub period: u32,
    pub purpose: UnitPurpose,
    /// The approved workload's digest (pass 33 `JOB_WORKLOAD`): the job's image.
    pub workload: String,
    /// The machine the reserver pinned; `None` for any machine of the line. The quote fixes
    /// the machine the job runs on (pass 33 requires `inputs.machine`).
    pub machine: Option<EntityId>,
    pub code_sha: String,
    pub contract_sha256: String,
    /// The workload pin's maximum: the job's quote and the machine's own limit.
    pub reserved_secs: u64,
    /// Where the reservation sits, in draw order; the units sum to `reserved_secs`.
    pub draws: Vec<Draw>,
    /// The period's wallet.
    pub wallet: WalletRef,
    /// The period's allocation and its generation: the hold's home until the claim ends, also
    /// after the period rolls over (section 7.2 point 4).
    pub allocation: AllocationRef,
    /// The exact Grant that authorised the reservation; `None` for the owner.
    pub grant: Option<EntityId>,
    /// Who reserved it; `None` after their erase.
    pub reserved_by: Option<EntityId>,
    /// The vault's clock.
    pub reserved_at_ms: u64,
    /// The digest of the reservation's ask: the same logical key with another ask is a
    /// conflict.
    pub ask_digest: String,
    pub state: ClaimState,
    /// Bumped at every write: the compare-and-set of a start and of the custody release.
    pub revision: u64,
}

/// Where a claim stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    /// Reserved; no job row yet.
    Claimed,
    /// The claim's `GPU_JOB` row exists.
    Started,
    /// Ended, with its terminal.
    Ended(UnitTerminal),
}

/// A claim's end, written once (section 3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitTerminal {
    pub end: UnitEnd,
    /// What the pools pay: `min(billed, reserved)` when `Settled`, else 0.
    pub charged_secs: u64,
    /// The machine's occupied device time; 0 when unknown.
    pub measured_secs: u64,
    /// For `BoxLost`: the run time last seen, a lower bound; else 0.
    pub lost_secs: u64,
    pub machine: Option<EntityId>,
    pub device_id: Option<String>,
    /// The machine's end cause (`exited(0)`, `time_limit`, ...); `None` when no machine
    /// answered.
    pub node_end: Option<String>,
    /// The digests of the job's outputs.
    pub outputs: Vec<ArmEvidenceDigest>,
    /// The vault's clock when the terminal was written.
    pub ended_at_ms: u64,
}

impl UnitTerminal {
    /// Whether `other` is the same end: every field but the time it was written. A stored
    /// write-off whose writer was erased since (`by` is `None`) matches a write-off by anyone,
    /// so the same report again is a replay; the erased id is never written back.
    #[must_use]
    pub fn same_end(&self, other: &Self) -> bool {
        let mut other = other.clone();
        other.ended_at_ms = self.ended_at_ms;
        if let (UnitEnd::WrittenOff { by: None }, UnitEnd::WrittenOff { by }) =
            (&self.end, &mut other.end)
        {
            *by = None;
        }
        *self == other
    }
}

/// How a claim ended (section 7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitEnd {
    /// The unit ran and ended: charged `min(billed, reserved)`.
    Settled,
    /// Confirmed never ran: refused before dispatch, withdrawn, launch refused, or the period
    /// ended first. Charged 0; the attempt number is used.
    Released(String),
    /// The machine attests the loss. Charged 0; never a verdict, never a loss.
    BoxLost,
    /// The owner closed an unconfirmed job at zero (pass 33 door 10); `by` is `None` after
    /// their erase.
    WrittenOff { by: Option<EntityId> },
}

/// What ends a unit: the rows of section 7.3 that write a terminal. An unreachable machine, a
/// missing answer or an unclear create is no end: the claim stays open and holds its full
/// reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitEndReport {
    /// The job's machine confirmed the end.
    Machine(GpuJobTerminal),
    /// The start, the gate, the wallet or the period's end refused the unit before dispatch:
    /// nothing ran (section 5.2, refusal kind 3).
    Refused { reason: String },
    /// The owner wrote off an unconfirmed job.
    WrittenOff { by: EntityId },
}

/// Why a settle wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitSettleRefused {
    /// No claim under the key.
    NoClaim,
    /// The claim's job is another job.
    OtherJob { claim_job: EntityId },
    /// A machine's end or a write-off for a claim whose job row was never written.
    NotStarted,
    /// The claim already ended with another terminal; it stands.
    EndedOtherwise { stored: Box<UnitTerminal> },
}

impl std::fmt::Display for UnitSettleRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoClaim => f.write_str("no unit claim under this key"),
            Self::OtherJob { claim_job } => {
                write!(f, "this unit claim belongs to job {}", claim_job.to_hex())
            }
            Self::NotStarted => f.write_str(
                "this unit claim never started a job: only a refusal before dispatch ends it",
            ),
            Self::EndedOtherwise { stored } => {
                write!(f, "this unit claim already ended as {:?}", stored.end)
            }
        }
    }
}

impl std::error::Error for UnitSettleRefused {}

/// Where the allocation's hold stands after a settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationSettle {
    /// The hold settled in the settle's own transaction: the claim is the hold (row M2-I2),
    /// so its terminal is the allocation's settle (section 7.2 point 6). No row carries a
    /// pending settlement.
    Settled,
}

/// What a settle wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSettlement {
    /// The claim as it now stands.
    pub claim: UnitClaim,
    /// The same terminal was already stored: nothing was written.
    pub replayed: bool,
    pub allocation: AllocationSettle,
}

impl UnitClaim {
    /// The claim's row key.
    #[must_use]
    pub fn key(&self) -> ClaimKey {
        ClaimKey::of(self.arm, self.rung, &self.unit_key, self.attempt)
    }

    /// Whether the claim still holds its reservation.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !matches!(self.state, ClaimState::Ended(_))
    }

    /// The claim as the fold reads it: an open claim holds every draw; a settled one is
    /// charged its charged seconds in draw order; any other end is free again.
    #[must_use]
    pub fn spend_row(&self) -> SpendRow {
        let charge = match &self.state {
            ClaimState::Claimed | ClaimState::Started => UnitCharge::Live,
            ClaimState::Ended(UnitTerminal {
                end: UnitEnd::Settled,
                charged_secs,
                ..
            }) => UnitCharge::Settled(*charged_secs),
            ClaimState::Ended(_) => UnitCharge::Void,
        };
        SpendRow::Unit {
            arm: self.arm,
            family: self.family,
            period: self.period,
            draws: self.draws.clone(),
            charge,
        }
    }

    /// The terminal `report` writes on this claim (section 7.3), or why it may not.
    ///
    /// # Errors
    ///
    /// [`UnitSettleRefused::NotStarted`] for a machine's end or a write-off on a claim that
    /// never started a job.
    pub fn terminal_for(
        &self,
        report: &UnitEndReport,
        now_ms: u64,
    ) -> Result<UnitTerminal, UnitSettleRefused> {
        let empty = |end: UnitEnd| UnitTerminal {
            end,
            charged_secs: 0,
            measured_secs: 0,
            lost_secs: 0,
            machine: None,
            device_id: None,
            node_end: None,
            outputs: Vec::new(),
            ended_at_ms: now_ms,
        };
        let started = matches!(self.state, ClaimState::Started);
        match report {
            UnitEndReport::Refused { reason } => Ok(empty(UnitEnd::Released(reason.clone()))),
            UnitEndReport::WrittenOff { by } if started => {
                Ok(empty(UnitEnd::WrittenOff { by: Some(*by) }))
            }
            UnitEndReport::Machine(terminal) if started => {
                Ok(self.machine_terminal(terminal, now_ms))
            }
            UnitEndReport::WrittenOff { .. } | UnitEndReport::Machine(_) => {
                Err(UnitSettleRefused::NotStarted)
            }
        }
    }

    fn machine_terminal(&self, terminal: &GpuJobTerminal, now_ms: u64) -> UnitTerminal {
        let (end, charged_secs, lost_secs) = match &terminal.end {
            GpuJobEnd::Withdrawn => (UnitEnd::Released("withdrawn".to_owned()), 0, 0),
            GpuJobEnd::Refused { reason } | GpuJobEnd::LaunchRefused { reason } => {
                (UnitEnd::Released(reason.clone()), 0, 0)
            }
            GpuJobEnd::Lost { last_seen_secs, .. } => (UnitEnd::BoxLost, 0, *last_seen_secs),
            GpuJobEnd::Exited { .. }
            | GpuJobEnd::Signalled { .. }
            | GpuJobEnd::TimeLimit
            | GpuJobEnd::MemoryLimit
            | GpuJobEnd::DiskLimit
            | GpuJobEnd::Stopped
            | GpuJobEnd::Revoked => (
                UnitEnd::Settled,
                terminal.billed_secs.min(self.reserved_secs),
                0,
            ),
        };
        let measured_secs = match end {
            UnitEnd::Settled => terminal.measured_secs.unwrap_or(0),
            _ => 0,
        };
        UnitTerminal {
            end,
            charged_secs,
            measured_secs,
            lost_secs,
            machine: terminal.machine,
            device_id: terminal.device_id.clone(),
            node_end: Some(terminal.end.label()),
            outputs: terminal
                .outputs
                .iter()
                .map(|output| ArmEvidenceDigest {
                    name: output.name.clone(),
                    sha256: output.sha256.clone(),
                    bytes: output.bytes,
                    rows: None,
                })
                .collect(),
            ended_at_ms: now_ms,
        }
    }

    /// This claim ended by `report`: `Ok(None)` when it already holds that terminal (a
    /// repeat writes nothing), `Ok(Some(claim))` with the ended claim, or why it may not end
    /// so.
    ///
    /// # Errors
    ///
    /// [`UnitSettleRefused::EndedOtherwise`] when another terminal stands;
    /// [`UnitSettleRefused::NotStarted`] as [`Self::terminal_for`] says.
    pub fn ended_by(
        &self,
        report: &UnitEndReport,
        now_ms: u64,
    ) -> Result<Option<Self>, UnitSettleRefused> {
        if let ClaimState::Ended(stored) = &self.state {
            let mut probe = self.clone();
            probe.state = ClaimState::Started;
            return match probe.terminal_for(report, now_ms) {
                Ok(terminal) if stored.same_end(&terminal) => Ok(None),
                _ => Err(UnitSettleRefused::EndedOtherwise {
                    stored: Box::new(stored.clone()),
                }),
            };
        }
        let terminal = self.terminal_for(report, now_ms)?;
        let mut ended = self.clone();
        ended.state = ClaimState::Ended(terminal);
        ended.revision += 1;
        Ok(Some(ended))
    }
}

/// Settles the unit whose claim is `key` and whose job is `job`, in the caller's write
/// transaction: the one the job's terminal row is written in (section 7.2 point 6). It writes
/// the claim's terminal once; the pools' release and the allocation's settle follow from it,
/// since both folds read claims ([`allocation_standing_in_txn`]), so an aborted transaction
/// leaves the claim open and its full reservation held. A repeat with the same end writes
/// nothing and answers `replayed`.
///
/// # Errors
///
/// A store failure; the inner [`UnitSettleRefused`] when the settle wrote nothing.
pub fn settle_unit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ClaimKey,
    job: &EntityId,
    report: &UnitEndReport,
    now_ms: u64,
) -> crate::Result<Result<UnitSettlement, UnitSettleRefused>> {
    let Some(claim) = CLAIMS.get(&vault.store, txn, key)? else {
        return Ok(Err(UnitSettleRefused::NoClaim));
    };
    if claim.id != *job {
        return Ok(Err(UnitSettleRefused::OtherJob {
            claim_job: claim.id,
        }));
    }
    let settlement = match claim.ended_by(report, now_ms) {
        Err(refused) => return Ok(Err(refused)),
        Ok(None) => UnitSettlement {
            claim,
            replayed: true,
            allocation: AllocationSettle::Settled,
        },
        Ok(Some(ended)) => {
            CLAIMS.put(&vault.store, txn, key, &ended)?;
            UnitSettlement {
                claim: ended,
                replayed: false,
                allocation: AllocationSettle::Settled,
            }
        }
    };
    Ok(Ok(settlement))
}

/// The release reason of a claim whose job did not start within its custody: the reserve's
/// next attempt, a late start and the order pass give it alike.
pub(crate) const CUSTODY_LAPSED: &str = "custody_lapsed";

/// Whether `claim`, still `Claimed`, has passed its custody at `now_ms`: its job has not
/// started within the `claim_custody_secs` of the policy its period was minted under, read
/// here only, so the reserve's next attempt and a late start judge it alike (design 5.2).
///
/// # Errors
///
/// A store failure.
pub fn custody_lapsed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &UnitClaim,
    now_ms: u64,
) -> crate::Result<bool> {
    if claim.state != ClaimState::Claimed {
        return Ok(false);
    }
    let custody_secs = stored_period_in_txn(vault, txn, &claim.line, claim.period)?
        .map_or(defaults::CLAIM_CUSTODY_SECS, |period| {
            period.policy.claim_custody_secs
        });
    Ok(now_ms
        >= claim
            .reserved_at_ms
            .saturating_add(custody_secs.saturating_mul(1_000)))
}

/// Ends `claim` `Released(reason)` if it still stands as read: `Claimed`, at the same
/// revision (the compare-and-set of design 5.2's custody). Answers the ended claim, or `None`
/// when it has since started, ended or changed: the other writer won.
///
/// # Errors
///
/// A store failure.
pub(crate) fn release_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &UnitClaim,
    reason: &str,
    now_ms: u64,
) -> crate::Result<Option<UnitClaim>> {
    let key = claim.key();
    let Some(stored) = CLAIMS.get(&vault.store, wtxn, &key)? else {
        return Ok(None);
    };
    if stored.state != ClaimState::Claimed || stored.revision != claim.revision {
        return Ok(None);
    }
    let report = UnitEndReport::Refused {
        reason: reason.to_owned(),
    };
    Ok(
        settle_unit_in_txn(vault, wtxn, &key, &stored.id, &report, now_ms)?
            .ok()
            .map(|settlement| settlement.claim),
    )
}

/// Marks `claim` started if it still stands as read: `Claimed`, at the same revision (the
/// compare-and-set of design 5.2 that the custody release also takes). The start gate writes it
/// in the write that inserts the claim's job row (design 5.3). Answers the started claim, or
/// `None` when it has since started, ended or changed: the other writer won.
///
/// # Errors
///
/// A store failure.
pub(crate) fn start_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &UnitClaim,
) -> crate::Result<Option<UnitClaim>> {
    let key = claim.key();
    let Some(mut stored) = CLAIMS.get(&vault.store, wtxn, &key)? else {
        return Ok(None);
    };
    if stored.state != ClaimState::Claimed || stored.revision != claim.revision {
        return Ok(None);
    }
    stored.state = ClaimState::Started;
    stored.revision += 1;
    CLAIMS.put(&vault.store, wtxn, &key, &stored)?;
    Ok(Some(stored))
}

/// The claim under `key`.
///
/// # Errors
///
/// A store failure.
pub fn claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &ClaimKey,
) -> crate::Result<Option<UnitClaim>> {
    CLAIMS.get(&vault.store, txn, key)
}

/// Every claim of arm `arm` at rung `rung`, over every unit and attempt, in key order.
///
/// # Errors
///
/// A store failure.
pub fn claims_at_rung_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &EntityId,
    rung: u8,
) -> crate::Result<Vec<UnitClaim>> {
    let mut prefix = Vec::new();
    arm.encode_into(&mut prefix);
    rung.encode_into(&mut prefix);
    Ok(CLAIMS
        .scan_from(&vault.store, txn, &prefix)?
        .into_iter()
        .map(|(_, claim)| claim)
        .collect())
}

/// Every claim of the vault, over every arm, rung, unit and attempt, in key order: the rows a
/// read over the whole line's history (`vault.jobs.history`) projects.
///
/// # Errors
///
/// A store failure.
pub fn claims_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<Vec<UnitClaim>> {
    Ok(CLAIMS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, claim)| claim)
        .collect())
}

/// Puts `claim` under its key as given (TEST-ONLY, `test_doors::experiment_arm_rows`): a test
/// stands a claim whose writer, the reserve door, is row M2-C's.
#[cfg(oneiron_test_support)]
pub(crate) fn put_claim_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &UnitClaim,
) -> crate::Result<()> {
    CLAIMS.put(&vault.store, wtxn, &claim.key(), claim)
}

/// Takes the erased actor out of every claim (the side table's actor scrub): as reserver or
/// as the owner who wrote it off, its id is forgotten and the rest of the record stays. The
/// scrub bumps the claim's revision.
pub(crate) fn erase_claim_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (key, mut claim) in CLAIMS.scan(&vault.store, wtxn)? {
        let mut changed = false;
        if claim.reserved_by == Some(*actor) {
            claim.reserved_by = None;
            changed = true;
        }
        if let ClaimState::Ended(UnitTerminal {
            end: UnitEnd::WrittenOff { by },
            ..
        }) = &mut claim.state
            && *by == Some(*actor)
        {
            *by = None;
            changed = true;
        }
        if changed {
            claim.revision += 1;
            CLAIMS.put(&vault.store, wtxn, &key, &claim)?;
        }
    }
    Ok(())
}
