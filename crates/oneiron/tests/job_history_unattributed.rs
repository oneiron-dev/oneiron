//! `vault.jobs.history`'s unattributed seconds (pass 33 section 8.5 and EM-15; design pass 34
//! sections 5 and 9.3: "unattributed and lost seconds on their own lines"). A machine that ran
//! jobs for this vault that no row of it names has their seconds recorded against the
//! allocation generation their submit named. History shows them on their own sum fields: in
//! the totals, by machine and, for a line's generation, by line and period, never by family,
//! and never inside the occupied, charged or lost seconds. Only the owner sees them, and a
//! family or a work-order filter admits none.
//!
//! The projection is pure; the last test reads a vault's own row. Fleet command:
//! `cargo test --locked -p oneiron --all-features --test job_history_unattributed`.
use std::path::Path;

use oneiron::gpu_line::{UnattributedJob, UnattributedRecord, record_node_answer_in_txn};
use oneiron::job_history::{
    HistoryInputs, HistoryViewer, JobHistory, JobHistoryRequest, JobHistorySum, project,
    read_job_history,
};
use oneiron::llm::run_admission::{AllocationRef, gpu_line_allocation_id};
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 1_764_000_000_000;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x07;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn line_a() -> EntityId {
    id(1)
}

fn line_b() -> EntityId {
    id(2)
}

fn first_machine() -> EntityId {
    id(8)
}

fn second_machine() -> EntityId {
    id(9)
}

fn open(dir: &Path) -> Vault {
    Vault::open_owned(dir, VaultConfig::default()).expect("owned vault")
}

fn job(node_key: &str, secs: u64, ended: bool) -> UnattributedJob {
    UnattributedJob {
        node_key: node_key.to_owned(),
        secs,
        ended,
    }
}

fn record(
    id: String,
    generation: u64,
    machine: EntityId,
    jobs: Vec<UnattributedJob>,
) -> UnattributedRecord {
    UnattributedRecord {
        allocation: AllocationRef { id, generation },
        machine,
        answered_at_ms: NOW,
        jobs,
    }
}

/// Line A's period 2 (generation 3) on the first machine, one job ended and one still running;
/// line A's period 0 on the second; a host allocation that is no line's; an id that ends in
/// line A's hex but is not its allocation; and line B's generation 0, which no period has.
fn records() -> Vec<UnattributedRecord> {
    vec![
        record(
            gpu_line_allocation_id(&line_a()),
            3,
            first_machine(),
            vec![
                job("restored-a:0", 500, true),
                job("restored-b:0", 70, false),
            ],
        ),
        record(
            gpu_line_allocation_id(&line_a()),
            1,
            second_machine(),
            vec![job("restored-c:0", 200, true)],
        ),
        record(
            "host-default".to_owned(),
            1,
            first_machine(),
            vec![job("restored-d:0", 30, true)],
        ),
        record(
            format!("wallet:{}", line_a().to_hex()),
            2,
            first_machine(),
            vec![job("restored-e:0", 5, true)],
        ),
        record(
            gpu_line_allocation_id(&line_b()),
            0,
            second_machine(),
            vec![job("restored-f:0", 40, true)],
        ),
    ]
}

fn history(
    records: &[UnattributedRecord],
    request: &JobHistoryRequest,
    viewer: HistoryViewer,
) -> JobHistory {
    let inputs = HistoryInputs {
        jobs: &[],
        claims: &[],
        periods: &[],
        orders: &[],
        observations: &[],
        unattributed: records,
    };
    let filter = request.filter().expect("a valid request");
    project(&inputs, &filter, viewer)
}

fn owner_history(records: &[UnattributedRecord], request: &JobHistoryRequest) -> JobHistory {
    history(records, request, HistoryViewer::Owner)
}

fn unattributed(secs: u64, running: u32) -> JobHistorySum {
    JobHistorySum {
        unattributed_secs: secs,
        unattributed_running: running,
        ..JobHistorySum::default()
    }
}

#[test]
fn the_owner_sees_unattributed_seconds_by_machine_line_and_period_and_never_by_family() {
    let records = records();
    let answer = owner_history(&records, &JobHistoryRequest::default());

    // Unattributed seconds are no attempt, and no other figure of the sums takes them.
    assert!(answer.attempts.is_empty());
    assert_eq!(answer.next, None);
    let totals = &answer.totals;
    assert_eq!(totals.all, unattributed(845, 1));

    let by_machine: Vec<(Option<String>, JobHistorySum)> = totals
        .by_machine
        .iter()
        .map(|entry| (entry.machine.clone(), entry.sum))
        .collect();
    let expected = vec![
        (Some(first_machine().to_hex()), unattributed(605, 1)),
        (Some(second_machine().to_hex()), unattributed(240, 0)),
    ];
    assert_eq!(by_machine, expected);

    // Only a line's own allocation, at a generation a period has, places them on the line.
    let by_line: Vec<(String, JobHistorySum)> = totals
        .by_line
        .iter()
        .map(|entry| (entry.line.clone(), entry.sum))
        .collect();
    let expected = vec![(line_a().to_hex(), unattributed(770, 1))];
    assert_eq!(by_line, expected);

    // Generation n is period n - 1, and a period with no record shows no window.
    let by_period: Vec<(String, u32, Option<u64>, JobHistorySum)> = totals
        .by_period
        .iter()
        .map(|entry| (entry.line.clone(), entry.period, entry.start_ms, entry.sum))
        .collect();
    let expected = vec![
        (line_a().to_hex(), 0, None, unattributed(200, 0)),
        (line_a().to_hex(), 2, None, unattributed(570, 1)),
    ];
    assert_eq!(by_period, expected);

    // No family pays them.
    assert!(totals.by_family.is_empty());
}

#[test]
fn an_agent_and_a_family_or_order_filter_see_no_unattributed_seconds() {
    let records = records();
    let agent = history(
        &records,
        &JobHistoryRequest::default(),
        HistoryViewer::Requester(id(30)),
    );
    assert_eq!(agent.totals.all, JobHistorySum::default());
    assert!(agent.totals.by_machine.is_empty());
    assert!(agent.totals.by_line.is_empty());
    assert!(agent.totals.by_period.is_empty());

    let family = JobHistoryRequest {
        family: Some(id(40).to_hex()),
        ..JobHistoryRequest::default()
    };
    let order = JobHistoryRequest {
        order: Some(id(41).to_hex()),
        ..JobHistoryRequest::default()
    };
    for request in [family, order] {
        let owner = owner_history(&records, &request);
        assert_eq!(owner.totals.all, JobHistorySum::default(), "{request:?}");
        assert!(owner.totals.by_machine.is_empty(), "{request:?}");
    }
}

#[test]
fn a_machine_line_or_period_filter_keeps_the_records_it_names() {
    let records = records();
    let all_of = |request: &JobHistoryRequest| owner_history(&records, request).totals.all;
    let of_line_a = JobHistoryRequest {
        line: Some(line_a().to_hex()),
        ..JobHistoryRequest::default()
    };
    let of_line_a_period_2 = JobHistoryRequest {
        period: Some(2),
        ..of_line_a.clone()
    };
    let of_period_0 = JobHistoryRequest {
        period: Some(0),
        ..JobHistoryRequest::default()
    };
    let of_line_b = JobHistoryRequest {
        line: Some(line_b().to_hex()),
        ..JobHistoryRequest::default()
    };
    let of_second_machine = JobHistoryRequest {
        machine: Some(second_machine().to_hex()),
        ..JobHistoryRequest::default()
    };

    assert_eq!(all_of(&of_line_a), unattributed(770, 1));
    assert_eq!(all_of(&of_line_a_period_2), unattributed(570, 1));
    // A period filter admits only a line's generation.
    assert_eq!(all_of(&of_period_0), unattributed(200, 0));
    // Generation 0 is no period of the line.
    assert_eq!(all_of(&of_line_b), JobHistorySum::default());
    assert_eq!(all_of(&of_second_machine), unattributed(240, 0));
}

#[test]
fn the_vault_read_holds_the_allocations_record_in_its_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    let period = AllocationRef {
        id: gpu_line_allocation_id(&line_a()),
        generation: 2,
    };
    vault
        .with_write_txn(|txn| {
            record_node_answer_in_txn(
                &vault,
                txn,
                &period,
                first_machine(),
                &[job("job-from-before-the-restore:0", 300, true)],
                NOW,
            )
        })
        .expect("node answer");

    let filter = JobHistoryRequest::default()
        .filter()
        .expect("a valid request");
    let owner = read_job_history(&vault, &filter, HistoryViewer::Owner).expect("history read");
    assert_eq!(owner.totals.all, unattributed(300, 0));
    let by_period: Vec<(String, u32, JobHistorySum)> = owner
        .totals
        .by_period
        .iter()
        .map(|entry| (entry.line.clone(), entry.period, entry.sum))
        .collect();
    let expected = vec![(line_a().to_hex(), 1, unattributed(300, 0))];
    assert_eq!(by_period, expected);

    let agent_viewer = HistoryViewer::Requester(id(30));
    let agent = read_job_history(&vault, &filter, agent_viewer).expect("history read");
    assert_eq!(agent.totals.all, JobHistorySum::default());
}
