//! FIX LANE-ECONOMY-SIBLING-TABLES-ARCHIVE-CLASS (P3; Engine TASK 25 Nov 19:57; OPUS-LE-ARMS PLAN
//! 21:01): the whole-vault archive carries the seven side tables beside the lane economy's
//! (`GPU_ALLOCATION_NODE`, `GPU_JOB`, `GPU_JOB_ALLOWANCE`, `JOB_DISPATCH`, `JOB_OBSERVATION`,
//! `JOB_WORKLOAD`, `WORK_ORDER`) as retained copies, and no import door, the owner's restore
//! included, writes one of their rows live. A restore of a vault whose GPU job runs at its
//! provider, dispatched to a machine with its observation, beside an approved workload, an open
//! order, an agent's allowance and a machine's answer, reopens nothing: the host's step finds no
//! live job, and no dispatch, order or allowance reads back.
//!
//! None of the seven holds a field its read view keeps back until a time or a state, so no row
//! is held home under LE-ARCHIVE-PERIOD-SEED = A; every row travels.
//!
//! A job's quote inputs are its starter's own JSON, stored inside the job's MessagePack row. A
//! job whose inputs name a password stays home: the export reads those inputs' keys as field
//! names, as the document pass reads a JSON row (blind review round 1 of #10515, P1). A map key
//! of a typed row is no caller's field name, so a row whose map key reads as a credential word
//! and holds no secret still travels.
//!
//! Red on #10489's head: the seven tables are unclassified
//! (tests/archive_side_catalogue_unclassified.txt), so the export carries no row of them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test archive_lane_economy_sibling_tables_retained`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;

use oneiron::gpu_job::{GpuJob, GpuJobAllowance};
use oneiron::gpu_line::{UnattributedJob, record_node_answer_in_txn};
use oneiron::job_dispatch::{DispatchPhase, JobDispatch, JobObservation};
use oneiron::job_workload::{
    DeviceClaim, DeviceKind, NetworkMode, ResourceRequest, ScopeKind, Sharing, WorkloadPin,
};
use oneiron::llm::run_admission::{AllocationRef, gpu_line_allocation_id};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::archive_side_catalogue::retained_row_withholds_credential;
use oneiron::test_doors::lane_economy_archive::{
    SIBLING_TABLES, exported_rows, live_rows, put_gpu_job_allowance, put_running_gpu_job,
    put_running_gpu_job_with_inputs,
};
use oneiron::test_doors::work_order::{put_approved_workload, put_order};
use oneiron::work_order::{
    OrderCharge, OrderClass, OrderLimits, OrderState, OrderWishes, OrderedBy, WaitRule, WorkOrder,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_store::ports::manual_clock::ManualClock;

/// The source's manual store clock, in seconds: 21 Sep 2026, earlier than the host's clock the
/// destinations open on.
const T0_SECS: u64 = 1_790_000_000;
const NOW_MS: u64 = T0_SECS * 1_000;

/// A writer-owned vault on a manual store clock (a machine's answer needs this process's writer
/// lease), holding a row of each sibling table: a GPU job its owner started whose one chunk runs
/// at its provider, dispatched to `machine` with the node's running observation, the workload
/// the dispatch names approved on that machine, an open order of it, an agent's allowance, and
/// the machine's answer for a GPU line's allocation that lists the running job.
struct Fixture {
    vault: Vault,
    job: GpuJob,
    grant: EntityId,
    order: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::default();
    config.store_clock = ManualClock::new(T0_SECS).bundle();
    let vault = Vault::open_owned(dir.path(), config).expect("fresh owned vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let machine = EntityId::now();

    let job = put_running_gpu_job(&vault, owner, NOW_MS).expect("the running job's row");
    let key = job.chunks[0].idempotency_key.clone();
    let workload = put_approved_workload(
        &vault,
        pin(),
        owner,
        vec![machine],
        Vec::new(),
        NOW_MS + 86_400_000,
        NOW_MS,
    );
    vault
        .insert_job_dispatch(JobDispatch {
            key: key.clone(),
            job: job.id,
            chunk: 0,
            workload: workload.clone(),
            machine,
            submit: b"fixture signed submit".to_vec(),
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 60_000,
            phase: DispatchPhase::Submitted,
            held: Some(b"fixture held receipt".to_vec()),
            sent_boot: None,
            closed: None,
            history_lost_at_ms: None,
        })
        .expect("the chunk's dispatch");
    vault
        .put_job_observation(&JobObservation {
            key: key.clone(),
            machine,
            device_id: Some("GPU-0".to_owned()),
            receipt: b"fixture running receipt".to_vec(),
            epoch: "epoch-1".to_owned(),
            seq: 3,
            last_measured_secs: Some(30),
            observed_at_ms: NOW_MS,
            end_seen: None,
            meter: None,
            terminal: None,
            started: true,
        })
        .expect("the node's running observation");
    let order = WorkOrder {
        id: EntityId::now(),
        ordered_by: OrderedBy::Owner { owner: Some(owner) },
        workload,
        request: request(),
        charge: OrderCharge::Offer {
            name: "fixture-machines".to_owned(),
        },
        limits: OrderLimits::default(),
        wishes: OrderWishes::default(),
        class: OrderClass::Normal,
        wait: WaitRule::Open,
        retry_on: Vec::new(),
        state: OrderState::Open {
            blocked: Vec::new(),
            looked_at_ms: NOW_MS,
            earliest_ms: None,
        },
        cancel: None,
        retry_not_before_ms: None,
        attempts: Vec::new(),
        result: None,
        intent_key: None,
        after: None,
        group: None,
        ordered_at_ms: NOW_MS,
        updated_at_ms: NOW_MS,
        revision: 0,
    };
    put_order(&vault, &order);
    let grant = EntityId::now();
    put_gpu_job_allowance(
        &vault,
        &GpuJobAllowance {
            grant,
            agent: EntityId::now(),
            maximum_secs: 600,
            set_by: Some(owner),
            set_at_ms: NOW_MS,
        },
    )
    .expect("the agent Grant's allowance");
    let lane = EntityId::now();
    vault
        .with_write_txn(|txn| {
            record_node_answer_in_txn(
                &vault,
                txn,
                &AllocationRef {
                    id: gpu_line_allocation_id(&lane),
                    generation: 1,
                },
                machine,
                &[UnattributedJob {
                    node_key: key.clone(),
                    secs: 30,
                    ended: false,
                }],
                NOW_MS,
            )
        })
        .expect("the machine's answer");
    Fixture {
        vault,
        job,
        grant,
        order: order.id,
        _dir: dir,
    }
}

fn request() -> ResourceRequest {
    ResourceRequest {
        cpu_threads: 0,
        memory_mib: 8_192,
        disk_mib: 1_024,
        devices: vec![DeviceClaim {
            kind: DeviceKind::Gpu,
            count: 1,
            memory_mib: 20_000,
            features: vec!["cuda".to_owned()],
            sharing: Sharing::Exclusive,
        }],
        maximum_secs: 600,
    }
}

fn pin() -> WorkloadPin {
    WorkloadPin {
        template: "open-models".to_owned(),
        template_digest: "1".repeat(64),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/arm.json".to_owned(),
        entry: "tools/units/run_arm.sh".to_owned(),
        args: vec!["arm=d2".to_owned()],
        request: request(),
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: Vec::new(),
    }
}

/// The live rows of `table` in `vault`, sorted.
fn live(vault: &Vault, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows =
        live_rows(vault, table).unwrap_or_else(|error| panic!("{table}'s live rows: {error:?}"));
    rows.sort();
    rows
}

/// The rows of `table` `vault`'s whole-vault export carries, sorted (the export orders them by
/// their retained identity, not by source key).
fn exported(vault: &Vault, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = exported_rows(vault, table)
        .unwrap_or_else(|error| panic!("{table}'s exported rows: {error:?}"));
    rows.sort();
    rows
}

/// A fresh destination on the host's clock, later than the source's manual store clock, so the
/// engine seeds' times differ without a wait, as `campaign_house_voice_guide.rs` opens its
/// restored vault.
fn open_destination() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the destination vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::default()).expect("open the destination vault");
    (dir, vault)
}

#[test]
fn the_export_carries_every_sibling_table_byte_for_byte() {
    let fixture = fixture();
    for table in SIBLING_TABLES {
        let live = live(&fixture.vault, table);
        assert_eq!(live.len(), 1, "{table} holds the fixture's one live row");
        assert_eq!(
            exported(&fixture.vault, table),
            live,
            "the export carries every {table} row byte for byte"
        );
    }
}

/// The password a second job's quote inputs name: a text the release text rules alone do not
/// read as a credential, so only its field name marks it.
const INPUTS_PASSWORD: &str = "quartz-harbor-2026";

#[test]
fn a_job_whose_quote_inputs_name_a_password_stays_home() {
    let fixture = fixture();
    let owner = fixture.job.started_by.expect("the fixture job's starter");
    put_running_gpu_job_with_inputs(
        &fixture.vault,
        owner,
        NOW_MS,
        serde_json::json!({ "dataset": "owen-notes", "password": INPUTS_PASSWORD }),
    )
    .expect("the second job's row");
    let (named, clean): (Vec<_>, Vec<_>) =
        live(&fixture.vault, "GPU_JOB")
            .into_iter()
            .partition(|(_, value)| {
                value
                    .windows(INPUTS_PASSWORD.len())
                    .any(|window| window == INPUTS_PASSWORD.as_bytes())
            });
    assert_eq!(
        named.len(),
        1,
        "the second job's row holds the password as given"
    );
    assert_eq!(clean.len(), 1, "the fixture's job is the other live row");
    for ((key, value), withheld) in [(&named[0], true), (&clean[0], false)] {
        assert_eq!(
            retained_row_withholds_credential("GPU_JOB", key, value).expect("the envelope encodes"),
            withheld,
            "the export withholds the job whose inputs name a password, and only that job"
        );
    }

    let archive = fixture
        .vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let (_dest_dir, dest) = open_destination();
    let dest_owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let dest_proof = dest
        .authenticate_owner(
            dest_owner,
            &dest_owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the destination owner's proof");
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_proof)
        .expect("the owner's restore");
    assert_eq!(
        exported(&dest, "GPU_JOB"),
        clean,
        "the archive carries the clean job byte for byte and leaves the password's job home"
    );
}

#[test]
fn a_typed_rows_credential_worded_map_key_travels() {
    // A team receipt's role counts, keyed by the names its recorder copied: a role named `token`
    // holds a head count, no secret.
    let receipt = rmpv::Value::Map(vec![(
        rmpv::Value::from("roles"),
        rmpv::Value::Map(vec![
            (rmpv::Value::from("lead"), rmpv::Value::from(1)),
            (rmpv::Value::from("token"), rmpv::Value::from(2)),
        ]),
    )]);
    let mut value = Vec::new();
    rmpv::encode::write_value(&mut value, &receipt).expect("encode the receipt");
    assert!(
        !retained_row_withholds_credential("TEAM_RECEIPT", &[], &value)
            .expect("the envelope encodes"),
        "a typed row whose map key reads as a credential word and holds no secret travels"
    );
}

#[test]
fn no_import_door_reopens_a_job_a_dispatch_or_an_order() {
    let fixture = fixture();
    let source: Vec<_> = SIBLING_TABLES
        .iter()
        .map(|table| (*table, exported(&fixture.vault, table)))
        .collect();
    for (table, rows) in &source {
        assert_eq!(rows.len(), 1, "the source archive carries the {table} row");
    }
    let archive = fixture
        .vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();

    let (_owner_dir, owner_dest) = open_destination();
    let owner = owner_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let dest_proof = owner_dest
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the destination owner's proof");
    let receipt = owner_dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_proof)
        .expect("the owner's restore");
    for (table, rows) in &source {
        let count = receipt
            .retained_side_rows
            .tables
            .iter()
            .find(|count| count.source_table == *table)
            .unwrap_or_else(|| panic!("the owner's receipt counts {table}"));
        assert_eq!(
            (count.inserted_rows, count.installed_rows),
            (rows.len(), 0),
            "the owner's restore stores every {table} row inert and installs none"
        );
    }
    let (_actor_dir, actor_dest) = open_destination();
    let actor = actor_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    actor_dest
        .import_whole_vault_archive_from_with_actor(
            Cursor::new(&archive),
            &WriteActor::new(actor, EdgeActorClass::Human),
        )
        .expect("the actor import");
    let (_bare_dir, bare_dest) = open_destination();
    bare_dest
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import");

    let key = &fixture.job.chunks[0].idempotency_key;
    for (door, dest) in [
        ("owner", &owner_dest),
        ("actor", &actor_dest),
        ("actorless", &bare_dest),
    ] {
        for (table, rows) in &source {
            assert!(
                live(dest, table).is_empty(),
                "the {door} import writes no {table} row live"
            );
            assert_eq!(
                &exported(dest, table),
                rows,
                "the {door} destination keeps every {table} row as an inert copy and carries it on"
            );
        }
        assert_eq!(
            dest.live_gpu_jobs().expect("live jobs"),
            Vec::<EntityId>::new(),
            "after the {door} import the host's step takes up no job"
        );
        assert!(
            dest.gpu_job(&fixture.job.id).expect("job read").is_none(),
            "the {door} import reopens no job"
        );
        assert!(
            dest.job_dispatch(key).expect("dispatch read").is_none(),
            "the {door} import leaves no dispatch to send again"
        );
        assert!(
            dest.job_observation(key)
                .expect("observation read")
                .is_none(),
            "the {door} import leaves no observation of the chunk"
        );
        assert!(
            dest.work_order(&fixture.order)
                .expect("order read")
                .is_none(),
            "the {door} import reopens no order"
        );
        assert!(
            dest.gpu_job_allowance(&fixture.grant)
                .expect("allowance read")
                .is_none(),
            "the {door} import gives no agent an allowance"
        );
    }
}
