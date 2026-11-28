//! Row M2-I2, "the hold is the claim" (design pass 32 r2, section 7.2 points 3 to 6; Engine
//! EM-15). A managed unit's hold on its period's allocation is its claim row: the allocation's
//! standing for one generation is a fold over that generation's claims and its machines' node
//! answers, read in the vault writer. So:
//!
//! - a restart re-attaches the hold on the claim's own generation, also after the next
//!   generation was installed, and takes no new admission (T49);
//! - the wallet agrees with the claims on both sides of the terminal write, across a reopen
//!   (T50);
//! - a claim past the room is refused and writes nothing, and so is a claim on another line's
//!   allocation or on an allocation its own wallet does not fund;
//! - an orphan's occupied seconds shrink the room and charge no family (EM-15);
//! - a generation admits nothing until every machine of the line has answered since this
//!   start (EM-15), and an orphan still running keeps its machine unanswered until it ends;
//! - only a claim draws on a line's allocation: neither host-account backend installs it, so a
//!   plain unfunded `gpu_seconds` job never draws on it (Engine HOLD-IS-CLAIM-FOLD = A, 00:25).
//!
//! Compiled with `--cfg oneiron_test_support` (the started claim's door).
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::Arc;

use oneiron::federation::WalletRef;
use oneiron::gpu_job::{GpuJobEnd, GpuJobTerminal, MeterVerdict};
use oneiron::gpu_line::{
    AllocationSettle, AllocationStanding, ClaimAdmissionRefused, ClaimHoldRefused, ClaimKey,
    ClaimState, Draw, DrawSource, UnattributedJob, UnitClaim, UnitEnd, UnitEndReport, UnitPurpose,
    UnitSettleRefused, UnitSettlement, allocation_standing_in_txn, claim_hold_in_txn, claim_in_txn,
    open_claim_in_txn, record_node_answer_in_txn, settle_unit_in_txn,
};
use oneiron::llm::run_admission::{
    Allocation, AllocationGrantError, AllocationRef, AllocationStoreError, HostAccount, LeaseUnit,
    VaultAllocationLedger, gpu_line_allocation_id, is_gpu_line_allocation,
};
use oneiron::test_doors::gpu_line_hold_is_the_claim::{read_txn, start_claim};
use oneiron::{EntityId, Vault, VaultConfig};

const RESERVED: u64 = 1_800;
const GRANTED: u64 = 3_000;
const NOW: u64 = 1_764_000_000_000;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x02;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn wallet() -> WalletRef {
    WalletRef {
        issuer: "home".to_owned(),
        id: "gpu".to_owned(),
    }
}

/// The allocation of period `period`: generation `period + 1`, as the installer names it.
fn allocation(period: u32) -> Allocation {
    Allocation {
        reference: AllocationRef {
            id: gpu_line_allocation_id(&id(3)),
            generation: u64::from(period) + 1,
        },
        units: GRANTED,
        unit: LeaseUnit::new("gpu_seconds").expect("unit"),
        wallet: Some(wallet()),
    }
}

/// A new claim, `n` naming its job and unit, on `period`'s allocation.
fn claim(n: u8, period: u32, reserved_secs: u64) -> UnitClaim {
    UnitClaim {
        id: id(100 + n),
        arm: id(2),
        rung: 1,
        unit_key: format!("inkling-check/shard-{n}"),
        attempt: 1,
        line: id(3),
        family: id(4),
        period,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        result: None,
        reserved_secs,
        draws: vec![Draw {
            source: DrawSource::Floor,
            units: reserved_secs,
        }],
        wallet: wallet(),
        allocation: allocation(period).reference,
        grant: Some(id(5)),
        reserved_by: Some(id(6)),
        reserved_at_ms: NOW - 60_000,
        ask_digest: "ad".repeat(32),
        state: ClaimState::Claimed,
        revision: 1,
    }
}

fn ended(billed_secs: u64) -> UnitEndReport {
    UnitEndReport::Machine(GpuJobTerminal {
        end: GpuJobEnd::Exited { code: 0 },
        measured_secs: Some(billed_secs),
        billed_secs,
        meter: MeterVerdict::Agreed,
        machine: Some(id(9)),
        device_id: Some("GPU-1f2e3d4c".to_owned()),
        outputs: Vec::new(),
    })
}

fn open(dir: &Path) -> Vault {
    Vault::open_owned(dir, VaultConfig::default()).expect("owned vault")
}

fn standing(vault: &Vault, allocation: &Allocation, machines: &[EntityId]) -> AllocationStanding {
    let txn = read_txn(vault).expect("read txn");
    allocation_standing_in_txn(vault, &txn, allocation, machines).expect("standing")
}

fn admit(
    vault: &Vault,
    allocation: &Allocation,
    machines: &[EntityId],
    claim: &UnitClaim,
) -> Result<AllocationStanding, ClaimAdmissionRefused> {
    vault
        .with_write_txn(|txn| open_claim_in_txn(vault, txn, allocation, machines, claim))
        .expect("claim writer")
}

fn settle(
    vault: &Vault,
    claim: &UnitClaim,
    report: &UnitEndReport,
) -> Result<UnitSettlement, UnitSettleRefused> {
    vault
        .with_write_txn(|txn| settle_unit_in_txn(vault, txn, &claim.key(), &claim.id, report, NOW))
        .expect("terminal writer")
}

fn stored(vault: &Vault, key: &ClaimKey) -> Option<UnitClaim> {
    let txn = read_txn(vault).expect("read txn");
    claim_in_txn(vault, &txn, key).expect("claim read")
}

fn assert_standing(standing: &AllocationStanding, charged: u64, held: u64, open_claims: u32) {
    assert_eq!(standing.charged_secs, charged, "charged: {standing:?}");
    assert_eq!(standing.held_secs, held, "held: {standing:?}");
    assert_eq!(
        standing.open_claims, open_claims,
        "open claims: {standing:?}"
    );
    assert_eq!(
        standing.room(),
        GRANTED - standing.used_secs() - held,
        "room: {standing:?}"
    );
}

/// T49. A unit of period n survives a restart after period n+1 was installed and a unit
/// reserved there: the hold read back after the reopen names generation n, the standing of n
/// holds it before anything is admitted (there is nothing to rebuild), and its end settles on
/// n alone.
#[test]
fn a_restart_reattaches_the_hold_on_its_own_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (period_n, period_next) = (allocation(6), allocation(7));
    let on_n = claim(1, 6, RESERVED);
    let on_next = claim(2, 7, 1_000);
    {
        let vault = open(dir.path());
        admit(&vault, &period_n, &[], &on_n).expect("claim on n");
        start_claim(&vault, &on_n.key()).expect("start on n");
        admit(&vault, &period_next, &[], &on_next).expect("claim on n+1");
    }

    let vault = open(dir.path());
    assert_standing(&standing(&vault, &period_n, &[]), 0, RESERVED, 1);
    assert_standing(&standing(&vault, &period_next, &[]), 0, 1_000, 1);

    let txn = read_txn(&vault).expect("read txn");
    let hold = claim_hold_in_txn(&vault, &txn, &on_n.key(), &on_n.id)
        .expect("hold read")
        .expect("the open claim's hold");
    drop(txn);
    assert_eq!(hold.allocation, period_n.reference, "its own generation");
    assert_eq!(hold.reserved_secs, RESERVED);
    assert_eq!(hold.chunk_key, format!("{}:0", on_n.id.to_hex()));

    let txn = read_txn(&vault).expect("read txn");
    let other_job = claim_hold_in_txn(&vault, &txn, &on_n.key(), &on_next.id).expect("hold read");
    drop(txn);
    assert_eq!(
        other_job,
        Err(ClaimHoldRefused::OtherJob { claim_job: on_n.id })
    );

    let settled = settle(&vault, &on_n, &ended(1_200)).expect("settle on n");
    assert_eq!(settled.allocation, AllocationSettle::Settled);
    assert_standing(&standing(&vault, &period_n, &[]), 1_200, 0, 0);
    assert_standing(&standing(&vault, &period_next, &[]), 0, 1_000, 1);

    let txn = read_txn(&vault).expect("read txn");
    let after = claim_hold_in_txn(&vault, &txn, &on_n.key(), &on_n.id).expect("hold read");
    drop(txn);
    assert!(
        matches!(after, Err(ClaimHoldRefused::Ended { .. })),
        "an ended claim holds nothing: {after:?}"
    );
}

/// T50. A crash on either side of the job's terminal write: before its commit the claim is
/// open and the wallet holds the full reservation; after it the wallet shows the charge and
/// holds nothing. Each side reads the same across a reopen, and a repeat of the same end
/// changes nothing.
#[test]
fn the_wallet_agrees_with_the_claims_after_a_crash_at_the_job_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let period = allocation(6);
    let unit = claim(1, 6, RESERVED);
    {
        let vault = open(dir.path());
        admit(&vault, &period, &[], &unit).expect("claim");
        start_claim(&vault, &unit.key()).expect("start");
        // The terminal transaction aborts after the settle ran inside it: a crash before the
        // commit.
        let aborted: Result<(), oneiron::Error> = vault.with_write_txn(|txn| {
            settle_unit_in_txn(&vault, txn, &unit.key(), &unit.id, &ended(1_200), NOW)?
                .expect("settle in the aborted transaction");
            Err(oneiron::Error::InvalidConfig(
                "crash before the commit".to_owned(),
            ))
        });
        assert!(aborted.is_err());
        assert_standing(&standing(&vault, &period, &[]), 0, RESERVED, 1);
    }

    {
        let vault = open(dir.path());
        assert_standing(&standing(&vault, &period, &[]), 0, RESERVED, 1);
        assert!(
            stored(&vault, &unit.key()).is_some_and(|claim| claim.is_open()),
            "the claim is still open"
        );
        let settled = settle(&vault, &unit, &ended(1_200)).expect("settle");
        assert!(!settled.replayed);
        assert_eq!(settled.allocation, AllocationSettle::Settled);
        assert_standing(&standing(&vault, &period, &[]), 1_200, 0, 0);
    }

    let vault = open(dir.path());
    assert_standing(&standing(&vault, &period, &[]), 1_200, 0, 0);
    let again = settle(&vault, &unit, &ended(1_200)).expect("the same end again");
    assert!(again.replayed);
    assert_eq!(again.allocation, AllocationSettle::Settled);
    assert_standing(&standing(&vault, &period, &[]), 1_200, 0, 0);
    let ClaimState::Ended(terminal) = stored(&vault, &unit.key()).expect("claim").state else {
        panic!("the claim ended");
    };
    assert_eq!(terminal.end, UnitEnd::Settled);
    assert_eq!(terminal.charged_secs, 1_200);
}

/// The claim writer's room check: the second unit does not fit, is refused with the room
/// left, and writes no claim. A released claim gives its room back once.
#[test]
fn a_claim_past_the_room_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    let period = allocation(6);
    let first = claim(1, 6, RESERVED);
    let second = claim(2, 6, RESERVED);

    let after_first = admit(&vault, &period, &[], &first).expect("first claim");
    assert_standing(&after_first, 0, RESERVED, 1);
    assert_eq!(
        admit(&vault, &period, &[], &second),
        Err(ClaimAdmissionRefused::Exhausted {
            room: GRANTED - RESERVED
        })
    );
    assert!(stored(&vault, &second.key()).is_none(), "no claim written");
    assert_eq!(
        admit(&vault, &period, &[], &first),
        Err(ClaimAdmissionRefused::ClaimExists)
    );
    assert_eq!(
        admit(&vault, &allocation(7), &[], &claim(3, 6, 10)),
        Err(ClaimAdmissionRefused::OtherAllocation {
            claim: period.reference.clone()
        })
    );
    // Review 10413 P1: a claim of another line that names this line's allocation is refused,
    // and this line's room is unchanged.
    let other_line = UnitClaim {
        line: id(8),
        ..claim(4, 6, 10)
    };
    assert_eq!(
        admit(&vault, &period, &[], &other_line),
        Err(ClaimAdmissionRefused::OtherLine { line: id(8) })
    );
    assert!(
        stored(&vault, &other_line.key()).is_none(),
        "no claim written"
    );
    // Review 10413 round 2 P1: a claim of this line that names another wallet is refused, as
    // is any claim on an allocation that names no wallet; this line's room is unchanged.
    let other_wallet = UnitClaim {
        wallet: WalletRef {
            issuer: "home".to_owned(),
            id: "other".to_owned(),
        },
        ..claim(5, 6, 10)
    };
    assert_eq!(
        admit(&vault, &period, &[], &other_wallet),
        Err(ClaimAdmissionRefused::OtherWallet {
            funded_by: Some(wallet())
        })
    );
    assert!(
        stored(&vault, &other_wallet.key()).is_none(),
        "no claim written"
    );
    let walletless = Allocation {
        wallet: None,
        ..period.clone()
    };
    assert_eq!(
        admit(&vault, &walletless, &[], &claim(6, 6, 10)),
        Err(ClaimAdmissionRefused::OtherWallet { funded_by: None })
    );
    assert!(
        stored(&vault, &claim(6, 6, 10).key()).is_none(),
        "no claim written"
    );
    assert_standing(&standing(&vault, &period, &[]), 0, RESERVED, 1);

    let released = UnitEndReport::Refused {
        reason: "none_free".to_owned(),
    };
    settle(&vault, &first, &released).expect("release before dispatch");
    assert_standing(&standing(&vault, &period, &[]), 0, 0, 0);
    admit(&vault, &period, &[], &second).expect("the room came back");
}

/// EM-15. After a restore, a job the node ran and ended since the backup is recorded against
/// the generation its submit named: no claim and no family is charged, the owner sees the
/// seconds, and the room shrinks by them. A repeated answer counts each node key once.
#[test]
fn unattributed_seconds_shrink_the_room_and_charge_no_family() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    let period = allocation(6);
    let machine = id(9);
    let orphan = UnattributedJob {
        node_key: "job-from-before-the-restore:0".to_owned(),
        secs: 500,
        ended: true,
    };
    for _ in 0..2 {
        vault
            .with_write_txn(|txn| {
                record_node_answer_in_txn(
                    &vault,
                    txn,
                    &period.reference,
                    machine,
                    std::slice::from_ref(&orphan),
                    NOW,
                )
            })
            .expect("node answer");
    }
    let seen = standing(&vault, &period, &[machine]);
    assert_eq!(seen.unattributed_secs, 500);
    assert_eq!(seen.charged_secs, 0, "no claim is charged");
    assert_eq!(seen.used_secs(), 500);
    assert_eq!(seen.room(), GRANTED - 500);
    assert!(seen.unanswered_machines.is_empty());

    assert_eq!(
        admit(&vault, &period, &[machine], &claim(1, 6, GRANTED - 499)),
        Err(ClaimAdmissionRefused::Exhausted {
            room: GRANTED - 500
        })
    );
    admit(&vault, &period, &[machine], &claim(2, 6, GRANTED - 500)).expect("what is left");
    let other = standing(&vault, &allocation(7), &[]);
    assert_eq!(other.unattributed_secs, 0, "only its own generation");
}

/// EM-15, review 10413 round 2 P1. An orphan still running when its machine answers has no
/// final seconds: the machine stays unanswered, and the generation admits nothing, until a later
/// answer lists the orphan ended. Its final seconds then shrink the room, and a late repeat of
/// the running answer changes nothing.
#[test]
fn a_live_orphan_keeps_its_machine_unanswered_until_it_ends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    let period = allocation(6);
    let machine = id(9);
    let orphan = |secs: u64, ended: bool| UnattributedJob {
        node_key: "job-from-before-the-restore:0".to_owned(),
        secs,
        ended,
    };
    let answer = |job: UnattributedJob| {
        vault
            .with_write_txn(|txn| {
                record_node_answer_in_txn(
                    &vault,
                    txn,
                    &period.reference,
                    machine,
                    std::slice::from_ref(&job),
                    NOW,
                )
            })
            .expect("node answer");
    };

    answer(orphan(1_000, false));
    let running = standing(&vault, &period, &[machine]);
    assert_eq!(running.unattributed_secs, 1_000);
    assert_eq!(
        running.unanswered_machines,
        vec![machine],
        "a machine with a live orphan has not answered"
    );
    let fits_while_running = claim(1, 6, GRANTED - 1_000);
    assert_eq!(
        admit(&vault, &period, &[machine], &fits_while_running),
        Err(ClaimAdmissionRefused::NodesUnanswered {
            machines: vec![machine]
        })
    );
    assert!(
        stored(&vault, &fits_while_running.key()).is_none(),
        "no claim written"
    );

    answer(orphan(1_500, true));
    let stopped = standing(&vault, &period, &[machine]);
    assert_eq!(stopped.unattributed_secs, 1_500);
    assert!(stopped.unanswered_machines.is_empty());
    assert_eq!(
        admit(&vault, &period, &[machine], &fits_while_running),
        Err(ClaimAdmissionRefused::Exhausted {
            room: GRANTED - 1_500
        })
    );
    admit(&vault, &period, &[machine], &claim(2, 6, GRANTED - 1_500)).expect("what is left");

    answer(orphan(1_000, false));
    let repeated = standing(&vault, &period, &[machine]);
    assert_eq!(repeated.unattributed_secs, 1_500, "the larger seconds stay");
    assert!(
        repeated.unanswered_machines.is_empty(),
        "an ended orphan stays ended"
    );
    assert_eq!(repeated.used_secs() + repeated.held_secs, GRANTED);
}

/// EM-15. A generation admits nothing until every machine of the line has answered since this
/// start of the vault; a reopen asks again.
#[test]
fn a_generation_admits_nothing_until_every_machine_has_answered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let period = allocation(6);
    let machines = [id(9), id(10)];
    let answer = |vault: &Vault, machine: EntityId| {
        vault
            .with_write_txn(|txn| {
                record_node_answer_in_txn(vault, txn, &period.reference, machine, &[], NOW)
            })
            .expect("node answer");
    };
    {
        let vault = open(dir.path());
        assert_eq!(
            admit(&vault, &period, &machines, &claim(1, 6, 10)),
            Err(ClaimAdmissionRefused::NodesUnanswered {
                machines: machines.to_vec()
            })
        );
        answer(&vault, machines[0]);
        assert_eq!(
            admit(&vault, &period, &machines, &claim(1, 6, 10)),
            Err(ClaimAdmissionRefused::NodesUnanswered {
                machines: vec![machines[1]]
            })
        );
        answer(&vault, machines[1]);
        admit(&vault, &period, &machines, &claim(1, 6, 10)).expect("every machine answered");
    }

    let vault = open(dir.path());
    assert_eq!(
        standing(&vault, &period, &machines).unanswered_machines,
        machines.to_vec(),
        "a new start asks every machine again"
    );
    assert_eq!(
        admit(&vault, &period, &machines, &claim(2, 6, 10)),
        Err(ClaimAdmissionRefused::NodesUnanswered {
            machines: machines.to_vec()
        })
    );
    assert_standing(&standing(&vault, &period, &machines), 0, 10, 1);
}

/// Only a claim draws on a line's allocation (Engine HOLD-IS-CLAIM-FOLD = A, 00:25). Neither
/// host-account backend installs it, so no slot can hand it to a plain unfunded `gpu_seconds`
/// job: such a job draws on the host's own allocation, and with none it has none to draw on.
#[test]
fn a_plain_job_never_draws_on_a_lines_allocation() {
    let line = allocation(6);
    assert!(is_gpu_line_allocation(&line.reference));
    let plain = Allocation {
        reference: AllocationRef {
            id: "host-gpu".to_owned(),
            generation: 1,
        },
        units: GRANTED,
        unit: LeaseUnit::new("gpu_seconds").expect("unit"),
        wallet: None,
    };
    assert!(!is_gpu_line_allocation(&plain.reference));

    let account = HostAccount::new();
    assert_eq!(
        account.grant(line.clone()),
        Err(AllocationGrantError::LineManaged)
    );
    assert!(
        account.status().allocations.is_empty(),
        "the line's allocation is never selected"
    );
    account
        .grant(plain.clone())
        .expect("the host's own allocation");
    let selected: Vec<AllocationRef> = account
        .status()
        .allocations
        .into_iter()
        .map(|selected| selected.reference)
        .collect();
    assert_eq!(selected, vec![plain.reference.clone()]);

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(open(dir.path()));
    let ledger = VaultAllocationLedger::new(vault).expect("ledger").value;
    assert!(matches!(
        ledger.grant(line),
        Err(AllocationStoreError::LineManaged)
    ));
    assert!(ledger.status().expect("status").allocations.is_empty());
}
