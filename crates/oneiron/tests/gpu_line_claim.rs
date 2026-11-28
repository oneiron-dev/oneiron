//! The unit claim's key and its end rule (design pass 32 r2, sections 3.4 and 7.3): a claim is
//! keyed by its logical attempt; an open claim holds its full reservation in the fold; a run
//! that ended is charged its billed seconds, never above the reservation; a refusal before
//! anything ran, a lost machine and a write-off charge nothing; a machine's end needs a started
//! claim; and the terminal is written once. The rule is pure, so these run without a vault.
use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_job::{GpuJobEnd, GpuJobOutput, GpuJobTerminal, MeterVerdict};
use oneiron::gpu_line::{
    ClaimKey, ClaimState, Draw, DrawSource, SpendRow, UnitCharge, UnitClaim, UnitEnd,
    UnitEndReport, UnitPurpose, UnitSettleRefused,
};
use oneiron::llm::run_admission::AllocationRef;

const RESERVED: u64 = 1_800;
const NOW: u64 = 1_764_000_000_000;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x02;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn claim(state: ClaimState) -> UnitClaim {
    UnitClaim {
        id: id(1),
        arm: id(2),
        rung: 1,
        unit_key: "inkling-check/shard-0".to_owned(),
        attempt: 1,
        line: id(3),
        family: id(4),
        period: 7,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        result: None,
        reserved_secs: RESERVED,
        draws: vec![
            Draw {
                source: DrawSource::FirstAllowance,
                units: 1_000,
            },
            Draw {
                source: DrawSource::Floor,
                units: 800,
            },
        ],
        wallet: WalletRef {
            issuer: "home".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-7".to_owned(),
            generation: 7,
        },
        grant: Some(id(5)),
        reserved_by: Some(id(6)),
        reserved_at_ms: NOW - 60_000,
        ask_digest: "ad".repeat(32),
        state,
        revision: 1,
    }
}

fn machine_end(end: GpuJobEnd, measured: Option<u64>, billed: u64) -> UnitEndReport {
    UnitEndReport::Machine(GpuJobTerminal {
        end,
        measured_secs: measured,
        billed_secs: billed,
        meter: MeterVerdict::Agreed,
        machine: Some(id(9)),
        device_id: Some("GPU-1f2e3d4c".to_owned()),
        outputs: vec![GpuJobOutput {
            name: "result.json".to_owned(),
            sha256: "0f".repeat(32),
            bytes: 512,
        }],
    })
}

fn charge(claim: &UnitClaim) -> UnitCharge {
    match claim.spend_row() {
        SpendRow::Unit { charge, .. } => charge,
        SpendRow::Hold { .. } => panic!("a claim is a unit row"),
    }
}

fn ended(claim: &UnitClaim, report: &UnitEndReport) -> UnitClaim {
    claim
        .ended_by(report, NOW)
        .expect("the claim may end so")
        .expect("the claim was open")
}

#[test]
fn a_claim_key_names_the_logical_attempt_and_sorts_by_arm_then_rung() {
    let key = ClaimKey::of(id(2), 1, "inkling-check/shard-0", 1);
    assert_eq!(claim(ClaimState::Claimed).key(), key);
    let bytes = key.key_bytes();
    assert_eq!(bytes.len(), 16 + 1 + 16 + 2);
    assert_eq!(ClaimKey::from_key_bytes(&bytes), Some(key));
    assert_eq!(ClaimKey::from_key_bytes(&bytes[..34]), None);

    let retry = ClaimKey::of(id(2), 1, "inkling-check/shard-0", 1);
    assert_eq!(
        retry, key,
        "a retry of the same attempt finds the same claim"
    );
    let next = ClaimKey::of(id(2), 1, "inkling-check/shard-0", 2);
    let other_unit = ClaimKey::of(id(2), 1, "inkling-check/shard-1", 1);
    let rung_two = ClaimKey::of(id(2), 2, "inkling-check/shard-0", 1);
    assert_ne!(next, key);
    assert_ne!(other_unit.unit_key_digest, key.unit_key_digest);
    for same_rung in [&next, &other_unit] {
        assert_eq!(same_rung.key_bytes()[..17], bytes[..17]);
    }
    assert_ne!(rung_two.key_bytes()[..17], bytes[..17]);
    assert!(
        next.key_bytes() > bytes,
        "attempts of one unit sort in order"
    );
}

#[test]
fn an_open_claim_holds_its_full_reservation_in_the_fold() {
    for state in [ClaimState::Claimed, ClaimState::Started] {
        let open = claim(state);
        assert!(open.is_open());
        let SpendRow::Unit {
            arm,
            family,
            period,
            draws,
            charge,
        } = open.spend_row()
        else {
            panic!("a claim is a unit row");
        };
        assert_eq!((arm, family, period), (id(2), id(4), 7));
        assert_eq!(draws, open.draws);
        assert_eq!(charge, UnitCharge::Live);
    }
}

#[test]
fn a_run_that_ended_is_charged_its_billed_seconds_never_above_the_reservation() {
    let started = claim(ClaimState::Started);
    let cases = [
        (GpuJobEnd::Exited { code: 0 }, 1_200, 1_200, "exited(0)"),
        (GpuJobEnd::Signalled { signal: 9 }, 40, 40, "signalled(9)"),
        (GpuJobEnd::TimeLimit, RESERVED + 30, RESERVED, "time_limit"),
        (GpuJobEnd::MemoryLimit, 300, 300, "memory_limit"),
        (GpuJobEnd::DiskLimit, 301, 301, "disk_limit"),
        (GpuJobEnd::Stopped, 302, 302, "stopped"),
        (GpuJobEnd::Revoked, 303, 303, "revoked"),
    ];
    for (end, billed, charged, label) in cases {
        let done = ended(&started, &machine_end(end, Some(billed + 2), billed));
        let ClaimState::Ended(terminal) = &done.state else {
            panic!("the claim ended");
        };
        assert_eq!(terminal.end, UnitEnd::Settled, "{label}");
        assert_eq!(terminal.charged_secs, charged, "{label}");
        assert_eq!(terminal.measured_secs, billed + 2, "{label}");
        assert_eq!(terminal.lost_secs, 0);
        assert_eq!(terminal.node_end.as_deref(), Some(label));
        assert_eq!(terminal.machine, Some(id(9)));
        assert_eq!(terminal.device_id.as_deref(), Some("GPU-1f2e3d4c"));
        assert_eq!(terminal.outputs.len(), 1);
        assert_eq!(terminal.outputs[0].sha256, "0f".repeat(32));
        assert_eq!(terminal.ended_at_ms, NOW);
        assert_eq!(charge(&done), UnitCharge::Settled(charged));
        assert!(!done.is_open());
        assert_eq!(done.revision, started.revision + 1);
    }
}

#[test]
fn a_refusal_before_anything_ran_releases_the_claim_at_zero() {
    let started = claim(ClaimState::Started);
    let cases = [
        (GpuJobEnd::Withdrawn, "withdrawn"),
        (
            GpuJobEnd::Refused {
                reason: "no_free_device".to_owned(),
            },
            "no_free_device",
        ),
        (
            GpuJobEnd::LaunchRefused {
                reason: "contract_changed".to_owned(),
            },
            "contract_changed",
        ),
    ];
    for (end, reason) in cases {
        assert!(end.never_ran());
        let done = ended(&started, &machine_end(end, None, 0));
        let ClaimState::Ended(terminal) = &done.state else {
            panic!("the claim ended");
        };
        assert_eq!(terminal.end, UnitEnd::Released(reason.to_owned()));
        assert_eq!((terminal.charged_secs, terminal.measured_secs), (0, 0));
        assert_eq!(charge(&done), UnitCharge::Void);
    }

    // The gate or the wallet refused before the job row was written: the claim never started.
    let refused = UnitEndReport::Refused {
        reason: "workload_revoked".to_owned(),
    };
    for state in [ClaimState::Claimed, ClaimState::Started] {
        let done = ended(&claim(state), &refused);
        let ClaimState::Ended(terminal) = &done.state else {
            panic!("the claim ended");
        };
        assert_eq!(
            terminal.end,
            UnitEnd::Released("workload_revoked".to_owned())
        );
        assert_eq!(terminal.node_end, None);
        assert_eq!(charge(&done), UnitCharge::Void);
    }
}

#[test]
fn a_lost_machine_charges_nobody_and_keeps_the_last_seen_seconds() {
    let lost = GpuJobEnd::Lost {
        reason: "host_reset".to_owned(),
        last_seen_secs: 640,
    };
    let done = ended(
        &claim(ClaimState::Started),
        &UnitEndReport::Machine(GpuJobTerminal {
            end: lost,
            measured_secs: None,
            billed_secs: 0,
            meter: MeterVerdict::Unknown,
            machine: Some(id(9)),
            device_id: None,
            outputs: Vec::new(),
        }),
    );
    let ClaimState::Ended(terminal) = &done.state else {
        panic!("the claim ended");
    };
    assert_eq!(terminal.end, UnitEnd::BoxLost);
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(terminal.lost_secs, 640);
    assert_eq!(terminal.node_end.as_deref(), Some("lost(host_reset)"));
    assert_eq!(charge(&done), UnitCharge::Void);
}

#[test]
fn a_machine_end_or_a_write_off_needs_a_started_claim() {
    let reserved = claim(ClaimState::Claimed);
    let exited = machine_end(GpuJobEnd::Exited { code: 0 }, Some(10), 10);
    let write_off = UnitEndReport::WrittenOff { by: id(7) };
    assert_eq!(
        reserved.ended_by(&exited, NOW),
        Err(UnitSettleRefused::NotStarted)
    );
    assert_eq!(
        reserved.ended_by(&write_off, NOW),
        Err(UnitSettleRefused::NotStarted)
    );

    let done = ended(&claim(ClaimState::Started), &write_off);
    let ClaimState::Ended(terminal) = &done.state else {
        panic!("the claim ended");
    };
    assert_eq!(terminal.end, UnitEnd::WrittenOff { by: Some(id(7)) });
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(charge(&done), UnitCharge::Void);
}

#[test]
fn the_terminal_is_written_once() {
    let exited = machine_end(GpuJobEnd::Exited { code: 0 }, Some(900), 900);
    let done = ended(&claim(ClaimState::Started), &exited);

    // The same end again, later: nothing to write.
    assert_eq!(done.ended_by(&exited, NOW + 5_000), Ok(None));

    // Any other end: refused, and the stored terminal stands.
    let ClaimState::Ended(stored) = &done.state else {
        panic!("the claim ended");
    };
    let others = [
        machine_end(GpuJobEnd::Exited { code: 0 }, Some(900), 901),
        machine_end(GpuJobEnd::Stopped, Some(900), 900),
        UnitEndReport::Refused {
            reason: "period_ended".to_owned(),
        },
        UnitEndReport::WrittenOff { by: id(7) },
    ];
    for other in &others {
        assert_eq!(
            done.ended_by(other, NOW),
            Err(UnitSettleRefused::EndedOtherwise {
                stored: Box::new(stored.clone()),
            })
        );
    }
}

#[test]
fn a_write_off_repeated_after_its_writer_is_erased_is_still_a_replay() {
    let write_off = UnitEndReport::WrittenOff { by: id(7) };
    let mut done = ended(&claim(ClaimState::Started), &write_off);
    // The erase's actor scrub forgets the writer and keeps the rest of the record.
    let ClaimState::Ended(terminal) = &mut done.state else {
        panic!("the claim ended");
    };
    terminal.end = UnitEnd::WrittenOff { by: None };

    // The same report again writes nothing, so the erased id is never stored back.
    assert_eq!(done.ended_by(&write_off, NOW + 5_000), Ok(None));
    // A different end still meets the stored terminal.
    let ClaimState::Ended(stored) = &done.state else {
        panic!("the claim ended");
    };
    assert_eq!(
        done.ended_by(
            &machine_end(GpuJobEnd::Exited { code: 0 }, Some(10), 10),
            NOW
        ),
        Err(UnitSettleRefused::EndedOtherwise {
            stored: Box::new(stored.clone()),
        })
    );
}
