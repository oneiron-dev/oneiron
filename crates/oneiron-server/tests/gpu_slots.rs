#![cfg(oneiron_test_support)]
//! GPU inventory, live slots and selection (machines map, section 9 row 2):
//! each machine records its GPUs by stable device id, model and memory on
//! its `machine.capacity` record; a machine's slot table reserves one GPU
//! atomically from a fresh driver reading, and rechecks it at launch; the
//! home's selection takes only admitted machines that answer now, and never
//! admits from the hourly record or reroutes an uncertain reservation.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test gpu_slots`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier, Mutex};

use oneiron::authority::MachineRole;
use oneiron::machine_capacity::{
    GpuDevice, MachineCapacity, MachineCapacityWrite, MachineMeasurement, MachinePower,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::gpu_execution_node::{
    GPU_SLOT_HOLD_SECS, GpuAvailability, GpuComputeProcess, GpuDeviceOffer, GpuDeviceProbe,
    GpuDeviceState, GpuNodeCandidate, GpuProbeError, GpuSelectionRefusal, GpuSlotGrant,
    GpuSlotPeer, GpuSlotPeerError, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable, LocalGpuSlotPeer,
    gpu_node_candidates, parse_compute_process_lines, parse_device_lines, recorded_gpu_devices,
    select_gpu_slot,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GIB: u64 = 1 << 30;
const RTX_4090: &str = "NVIDIA GeForce RTX 4090";
const RTX_4090_MIB: u64 = 24_564;
const A4000: &str = "NVIDIA RTX A4000";
const A4000_MIB: u64 = 16_376;
const A6000: &str = "NVIDIA RTX A6000";
const A6000_MIB: u64 = 49_140;
/// A moment in Unix milliseconds the slot tests start from.
const T0: u64 = 1_800_000_000_000;

fn gpu(device_id: &str, model: &str, memory_total_mib: u64) -> GpuDevice {
    GpuDevice {
        device_id: device_id.to_owned(),
        model: model.to_owned(),
        memory_total_mib,
    }
}

fn rtx4090(device_id: &str) -> GpuDevice {
    gpu(device_id, RTX_4090, RTX_4090_MIB)
}

/// A driver whose GPUs, compute processes and failure the test sets.
struct FakeProbe {
    devices: Mutex<Vec<GpuDevice>>,
    processes: Mutex<Vec<GpuComputeProcess>>,
    failure: Mutex<Option<GpuProbeError>>,
}

impl FakeProbe {
    fn with(devices: Vec<GpuDevice>) -> Arc<Self> {
        Arc::new(Self {
            devices: Mutex::new(devices),
            processes: Mutex::default(),
            failure: Mutex::default(),
        })
    }

    fn run_on(&self, device_id: &str, pid: u32) {
        self.processes.lock().unwrap().push(GpuComputeProcess {
            device_id: device_id.to_owned(),
            pid: Some(pid),
        });
    }

    fn end_processes(&self) {
        self.processes.lock().unwrap().clear();
    }

    fn fail(&self, error: GpuProbeError) {
        *self.failure.lock().unwrap() = Some(error);
    }
}

impl GpuDeviceProbe for FakeProbe {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        match self.failure.lock().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(self.devices.lock().unwrap().clone()),
        }
    }

    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
        match self.failure.lock().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(self.processes.lock().unwrap().clone()),
        }
    }
}

fn offering(device_ids: &[&str]) -> GpuDeviceOffer {
    GpuDeviceOffer {
        offered: device_ids.iter().map(|id| (*id).to_owned()).collect(),
        withheld_file: None,
        hold_secs: GPU_SLOT_HOLD_SECS,
    }
}

fn table(probe: &Arc<FakeProbe>, offer: GpuDeviceOffer) -> Arc<GpuSlotTable> {
    Arc::new(GpuSlotTable::new(
        Arc::clone(probe) as Arc<dyn GpuDeviceProbe>,
        offer,
    ))
}

fn request(key: &str) -> GpuSlotRequest {
    GpuSlotRequest {
        key: key.to_owned(),
        device_id: None,
        model: None,
        min_memory_mib: 0,
    }
}

fn pinned(key: &str, device_id: &str) -> GpuSlotRequest {
    GpuSlotRequest {
        device_id: Some(device_id.to_owned()),
        ..request(key)
    }
}

fn state_of(answer: &GpuAvailability, device_id: &str) -> GpuDeviceState {
    answer
        .devices
        .iter()
        .find(|device| device.device.device_id == device_id)
        .map(|device| device.state.clone())
        .unwrap_or_else(|| panic!("the answer lists {device_id}"))
}

fn machine(n: u8) -> EntityId {
    EntityId::from_bytes_unchecked([n; 16])
}

/// Runs `test` on a thread with the engine's stack, as the server's binary
/// runs its work, so an enrolment's authority fold never meets a test
/// thread's default stack.
fn on_engine_stack(test: impl FnOnce() -> TestResult + Send + 'static) -> TestResult {
    let driver = std::thread::Builder::new()
        .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || test().map_err(|error| error.to_string()))?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A vault whose serving install is enrolled: this install has its MACHINE
/// row.
fn enrolled_vault() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let machine = vault
        .local_machine()?
        .ok_or("the enrolled install names no machine")?
        .id;
    Ok((dir, vault, machine))
}

fn measured_with(gpus: Vec<GpuDevice>, measured_at: u64) -> MachineCapacity {
    MachineCapacity::from_measurement(
        MachineMeasurement {
            cores: 16,
            memory_total_bytes: 64 * GIB,
            memory_available_bytes: 48 * GIB,
            gpu_memory_mib: gpus.iter().map(|gpu| gpu.memory_total_mib).collect(),
            gpus,
            disk_total_bytes: 2048 * GIB,
            disk_free_bytes: 900 * GIB,
            power: MachinePower::Mains,
        },
        measured_at,
    )
}

#[test]
fn a_recorded_capacity_carries_each_gpus_device_id_model_and_memory() -> TestResult {
    on_engine_stack(|| {
        let (_dir, vault, machine) = enrolled_vault()?;
        let first = measured_with(vec![rtx4090("GPU-bbbb"), rtx4090("GPU-aaaa")], 1_000);
        assert_eq!(
            first.gpus,
            vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")],
            "the record keeps device id order"
        );
        let MachineCapacityWrite::Recorded(standing) = vault.record_machine_capacity(&first)?
        else {
            panic!("the first record lands");
        };
        let recorded = vault
            .machine_capacity(machine)?
            .ok_or("the MACHINE reads its capacity")?;
        assert_eq!(recorded.gpus, first.gpus);

        // A changed card order alone moves nothing.
        let reordered = measured_with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")], 4_600);
        assert_eq!(
            vault.record_machine_capacity(&reordered)?,
            MachineCapacityWrite::Unchanged(standing)
        );

        // A swapped card records again, though every memory total is the same.
        let swapped = measured_with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-cccc")], 8_200);
        assert_eq!(swapped.gpu_memory_mib, first.gpu_memory_mib);
        let MachineCapacityWrite::Recorded(replaced) = vault.record_machine_capacity(&swapped)?
        else {
            panic!("a changed GPU list records again");
        };
        assert_ne!(replaced, standing);
        assert_eq!(
            vault
                .machine_capacity(machine)?
                .map(|capacity| capacity.gpus),
            Some(swapped.gpus.clone())
        );

        // The admitted machines with a recorded GPU are the candidates; a
        // machine named twice is one candidate, and no admitted machine is
        // no candidate.
        assert_eq!(
            gpu_node_candidates(&vault, &[machine, machine])?,
            vec![GpuNodeCandidate {
                machine,
                inventory: swapped.gpus,
            }]
        );
        assert_eq!(gpu_node_candidates(&vault, &[])?, Vec::new());
        Ok(())
    })
}

#[test]
fn the_probe_records_the_gpus_the_driver_names() -> TestResult {
    on_engine_stack(|| {
        let (_dir, vault, machine) = enrolled_vault()?;
        oneiron_server::machine_capacity::record_measured_capacity(&vault)?;
        let recorded = vault
            .machine_capacity(machine)?
            .ok_or("the probe records the capacity")?;
        let mut driver = recorded_gpu_devices();
        driver.sort();
        assert_eq!(
            recorded.gpus, driver,
            "the record names each GPU the driver names (none on a machine with no NVIDIA driver)"
        );
        Ok(())
    })
}

#[test]
fn a_capacity_record_written_before_gpus_were_named_reads_as_no_gpus() -> TestResult {
    let current = measured_with(vec![rtx4090("GPU-aaaa")], 1_000).to_value();
    let rmpv::Value::Map(entries) = current else {
        panic!("a capacity record is a map");
    };
    let older = rmpv::Value::Map(
        entries
            .into_iter()
            .filter(|(key, _)| key.as_str() != Some("gpus"))
            .collect(),
    );
    let read = MachineCapacity::from_value(&older)?;
    assert_eq!(read.gpus, Vec::new());
    assert_eq!(read.gpu_memory_mib, vec![RTX_4090_MIB]);

    // A later key the reader does not know is passed over.
    let rmpv::Value::Map(mut later) = measured_with(vec![rtx4090("GPU-aaaa")], 1_000).to_value()
    else {
        panic!("a capacity record is a map");
    };
    later.push((rmpv::Value::from("later_field"), rmpv::Value::from(7)));
    let read = MachineCapacity::from_value(&rmpv::Value::Map(later))?;
    assert_eq!(read.gpus, vec![rtx4090("GPU-aaaa")]);
    Ok(())
}

#[test]
fn nvidia_smi_lines_parse_to_devices_and_compute_processes() -> TestResult {
    assert_eq!(
        parse_device_lines(
            "GPU-aaaa, NVIDIA GeForce RTX 4090, 24564\nGPU-bbbb, NVIDIA RTX A4000, 16376\n\n"
        )?,
        vec![rtx4090("GPU-aaaa"), gpu("GPU-bbbb", A4000, A4000_MIB)]
    );
    assert_eq!(
        parse_device_lines("GPU-cccc, Model, With A Comma, 8192")?,
        vec![gpu("GPU-cccc", "Model, With A Comma", 8192)],
        "the model is everything between the UUID and the memory"
    );
    assert_eq!(parse_device_lines("")?, Vec::new());
    for unreadable in [
        "GPU-dddd, NVIDIA GeForce RTX 4090, [N/A]",
        "GPU-dddd, 24564",
        " , NVIDIA GeForce RTX 4090, 24564",
        "GPU-dddd, , 24564",
        "garbage",
    ] {
        assert!(
            matches!(
                parse_device_lines(unreadable),
                Err(GpuProbeError::Unreadable { .. })
            ),
            "{unreadable:?} is no device line"
        );
    }

    assert_eq!(
        parse_compute_process_lines("GPU-aaaa, 4242\nGPU-aaaa, [N/A]\nGPU-bbbb\n")?,
        vec![
            GpuComputeProcess {
                device_id: "GPU-aaaa".to_owned(),
                pid: Some(4242),
            },
            GpuComputeProcess {
                device_id: "GPU-aaaa".to_owned(),
                pid: None,
            },
            GpuComputeProcess {
                device_id: "GPU-bbbb".to_owned(),
                pid: None,
            },
        ],
        "a process whose id the driver hides still runs on its card"
    );
    assert_eq!(parse_compute_process_lines("\n")?, Vec::new());
    assert!(matches!(
        parse_compute_process_lines(" , 12"),
        Err(GpuProbeError::Unreadable { .. })
    ));
    Ok(())
}

#[test]
fn a_free_offered_gpu_is_reserved_once_and_the_same_key_gets_the_same_grant() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );

    let racers = 8;
    let start = Arc::new(Barrier::new(racers));
    let outcomes: Vec<Result<GpuSlotGrant, GpuSlotRefusal>> = (0..racers)
        .map(|n| {
            let slots = Arc::clone(&slots);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                slots.reserve(&request(&format!("chunk-{n}")), T0)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|racer| racer.join().unwrap())
        .collect();
    let granted: Vec<&GpuSlotGrant> = outcomes.iter().filter_map(|o| o.as_ref().ok()).collect();
    assert_eq!(granted.len(), 1, "one GPU holds one reservation");
    assert!(
        outcomes
            .iter()
            .filter_map(|o| o.as_ref().err())
            .all(|refusal| *refusal == GpuSlotRefusal::NoneFree)
    );
    let grant = granted[0].clone();
    assert_eq!(grant.device, rtx4090("GPU-aaaa"));
    assert_eq!(grant.held_at_ms, T0);
    assert_eq!(grant.hold_until_ms, T0 + GPU_SLOT_HOLD_SECS * 1000);

    // The same key again, later, is the same grant.
    assert_eq!(slots.reserve(&request(&grant.key), T0 + 5)?, grant);
    assert_eq!(
        state_of(&slots.availability(T0 + 5)?, "GPU-aaaa"),
        GpuDeviceState::Held {
            key: grant.key.clone()
        }
    );
    assert_eq!(
        slots.reserve(&pinned("another", "GPU-aaaa"), T0 + 5),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        })
    );

    assert!(slots.release(&grant.key));
    assert!(!slots.release(&grant.key), "a released slot is gone");
    assert_eq!(
        state_of(&slots.availability(T0 + 6)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    Ok(())
}

#[test]
fn a_gpu_with_a_compute_process_is_never_reserved() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    probe.run_on("GPU-aaaa", 777);

    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![777] }
    );
    assert_eq!(
        slots.reserve(&pinned("pinned", "GPU-aaaa"), T0),
        Err(GpuSlotRefusal::Busy {
            device_id: "GPU-aaaa".to_owned(),
            pids: vec![777],
        })
    );
    assert_eq!(
        slots.reserve(&request("any"), T0)?.device.device_id,
        "GPU-bbbb",
        "an unpinned reservation passes the busy GPU over"
    );
    assert_eq!(
        slots.reserve(&request("one-more"), T0),
        Err(GpuSlotRefusal::NoneFree)
    );
    Ok(())
}

#[test]
fn a_withheld_or_unoffered_gpu_is_never_reserved_and_a_hold_withheld_later_does_not_launch()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let withheld = dir.path().join("gpu-withheld");
    std::fs::write(&withheld, "# another booker's GPUs\nGPU-bbbb\n")?;
    let probe = FakeProbe::with(vec![
        rtx4090("GPU-aaaa"),
        rtx4090("GPU-bbbb"),
        rtx4090("GPU-cccc"),
    ]);
    let slots = table(
        &probe,
        GpuDeviceOffer {
            withheld_file: Some(withheld.clone()),
            ..offering(&["GPU-aaaa", "GPU-bbbb"])
        },
    );

    let answer = slots.availability(T0)?;
    assert_eq!(state_of(&answer, "GPU-aaaa"), GpuDeviceState::Free);
    assert_eq!(state_of(&answer, "GPU-bbbb"), GpuDeviceState::Withheld);
    assert_eq!(state_of(&answer, "GPU-cccc"), GpuDeviceState::NotOffered);
    assert_eq!(
        slots.reserve(&pinned("b", "GPU-bbbb"), T0),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-bbbb".to_owned()
        })
    );
    assert_eq!(
        slots.reserve(&pinned("c", "GPU-cccc"), T0),
        Err(GpuSlotRefusal::NotOffered {
            device_id: "GPU-cccc".to_owned()
        })
    );
    assert_eq!(
        slots.reserve(&pinned("z", "GPU-zzzz"), T0),
        Err(GpuSlotRefusal::UnknownDevice {
            device_id: "GPU-zzzz".to_owned()
        })
    );
    let grant = slots.reserve(&request("job"), T0)?;
    assert_eq!(grant.device.device_id, "GPU-aaaa");

    // The other booker takes the held GPU before the launch: it does not
    // launch, and the hold stays until it is released or lapses.
    std::fs::write(&withheld, "GPU-aaaa\nGPU-bbbb\n")?;
    assert_eq!(
        slots.confirm_launch("job", T0 + 1_000),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    assert_eq!(
        state_of(&slots.availability(T0 + 1_000)?, "GPU-aaaa"),
        GpuDeviceState::Withheld
    );

    // Given back, the same hold launches.
    std::fs::write(&withheld, "GPU-bbbb\n")?;
    assert_eq!(slots.confirm_launch("job", T0 + 2_000)?, grant);
    assert_eq!(
        state_of(&slots.availability(T0 + 2_000)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );

    // A named withheld file that cannot be read offers nothing.
    std::fs::remove_file(&withheld)?;
    assert!(matches!(
        slots.availability(T0 + 3_000),
        Err(GpuProbeError::WithheldUnreadable { .. })
    ));
    assert!(matches!(
        slots.reserve(&request("next"), T0 + 3_000),
        Err(GpuSlotRefusal::Unmeasured {
            probe: GpuProbeError::WithheldUnreadable { .. }
        })
    ));
    Ok(())
}

#[test]
fn the_launch_recheck_refuses_a_gpu_that_turned_busy() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let grant = slots.reserve(&request("job"), T0)?;

    probe.run_on("GPU-aaaa", 99);
    assert_eq!(
        slots.confirm_launch("job", T0 + 10),
        Err(GpuSlotRefusal::Busy {
            device_id: "GPU-aaaa".to_owned(),
            pids: vec![99],
        })
    );
    probe.end_processes();
    assert_eq!(slots.confirm_launch("job", T0 + 20)?, grant);
    assert_eq!(
        slots.confirm_launch("job", T0 + 30)?,
        grant,
        "asked again once launched, it answers the same grant"
    );

    // The launched job's own process does not make its GPU busy.
    probe.run_on("GPU-aaaa", 4_100);
    assert_eq!(
        state_of(&slots.availability(T0 + 40)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );
    // Released while a process still runs there, the GPU is busy, not free.
    assert!(slots.release("job"));
    assert_eq!(
        state_of(&slots.availability(T0 + 50)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![4_100] }
    );
    assert_eq!(
        slots.confirm_launch("nobody", T0 + 60),
        Err(GpuSlotRefusal::NotHeld)
    );
    Ok(())
}

#[test]
fn a_lapsed_hold_frees_the_gpu() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    let hold = GPU_SLOT_HOLD_SECS * 1000;

    let first = slots.reserve(&pinned("first", "GPU-aaaa"), T0)?;
    assert_eq!(
        slots.reserve(&pinned("second", "GPU-aaaa"), T0 + hold - 1),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    let second = slots.reserve(&pinned("second", "GPU-aaaa"), first.hold_until_ms)?;
    assert_eq!(second.device.device_id, "GPU-aaaa");
    assert_eq!(
        slots.confirm_launch("first", first.hold_until_ms),
        Err(GpuSlotRefusal::NotHeld),
        "the lapsed hold is gone"
    );

    // A hold confirmed too late lapses there and then.
    let late = slots.reserve(&pinned("late", "GPU-bbbb"), T0)?;
    assert_eq!(
        slots.confirm_launch("late", late.hold_until_ms),
        Err(GpuSlotRefusal::Lapsed)
    );
    assert_eq!(
        slots.confirm_launch("late", late.hold_until_ms),
        Err(GpuSlotRefusal::NotHeld)
    );

    // A launched slot never lapses.
    slots.confirm_launch("second", second.hold_until_ms - 1)?;
    assert_eq!(
        state_of(&slots.availability(T0 + 36_000_000)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "second".to_owned()
        }
    );
    Ok(())
}

#[test]
fn a_failed_probe_offers_nothing() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let grant = slots.reserve(&request("job"), T0)?;
    let failure = GpuProbeError::Unavailable {
        reason: "nvidia-smi did not answer within 10 s".to_owned(),
    };
    probe.fail(failure.clone());

    assert_eq!(slots.availability(T0 + 1), Err(failure.clone()));
    assert_eq!(
        slots.reserve(&request("other"), T0 + 1),
        Err(GpuSlotRefusal::Unmeasured {
            probe: failure.clone()
        })
    );
    assert_eq!(
        slots.confirm_launch(&grant.key, T0 + 1),
        Err(GpuSlotRefusal::Unmeasured {
            probe: failure.clone()
        }),
        "an unmeasured GPU does not launch"
    );

    let home = machine(1);
    let local = LocalGpuSlotPeer::new(home, Arc::clone(&slots));
    assert_eq!(
        local.availability(home),
        Err(GpuSlotPeerError::Refused(GpuSlotRefusal::Unmeasured {
            probe: failure
        }))
    );
    assert!(matches!(
        local.availability(machine(2)),
        Err(GpuSlotPeerError::Unreachable { .. })
    ));
    let candidates = [GpuNodeCandidate {
        machine: home,
        inventory: vec![rtx4090("GPU-aaaa")],
    }];
    assert_eq!(
        select_gpu_slot(&candidates, &local, &request("chunk")),
        Err(GpuSelectionRefusal::NoneFree),
        "the machine answered, so it is live, and it offers nothing"
    );
    Ok(())
}

/// The vault's machines as the home reaches them: each a real slot table on
/// a fake driver, some unreachable, some whose reservations are refused or
/// lost. It records every call.
#[derive(Default)]
struct FakePeers {
    tables: BTreeMap<EntityId, Arc<GpuSlotTable>>,
    unreachable: BTreeSet<EntityId>,
    refuse_reserve: BTreeSet<EntityId>,
    lose_reserve_answer: BTreeSet<EntityId>,
    asked: Mutex<Vec<(EntityId, &'static str)>>,
}

impl FakePeers {
    fn machine(mut self, id: EntityId, devices: Vec<GpuDevice>) -> (Self, Arc<FakeProbe>) {
        let ids: Vec<String> = devices.iter().map(|d| d.device_id.clone()).collect();
        let probe = FakeProbe::with(devices);
        let offer = GpuDeviceOffer {
            offered: ids.into_iter().collect(),
            ..GpuDeviceOffer::default()
        };
        self.tables.insert(id, table(&probe, offer));
        (self, probe)
    }

    fn asked(&self, call: &str) -> Vec<EntityId> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, asked)| *asked == call)
            .map(|(machine, _)| *machine)
            .collect()
    }

    fn reach(
        &self,
        machine: EntityId,
        call: &'static str,
    ) -> Result<&GpuSlotTable, GpuSlotPeerError> {
        self.asked.lock().unwrap().push((machine, call));
        if self.unreachable.contains(&machine) {
            return Err(GpuSlotPeerError::Unreachable {
                reason: "no route to the machine".to_owned(),
            });
        }
        self.tables
            .get(&machine)
            .map(|table| &**table)
            .ok_or_else(|| GpuSlotPeerError::Unreachable {
                reason: "an unknown machine".to_owned(),
            })
    }
}

impl GpuSlotPeer for FakePeers {
    fn availability(&self, machine: EntityId) -> Result<GpuAvailability, GpuSlotPeerError> {
        self.reach(machine, "availability")?
            .availability(T0)
            .map_err(|probe| GpuSlotRefusal::Unmeasured { probe }.into())
    }

    fn reserve(
        &self,
        machine: EntityId,
        request: &GpuSlotRequest,
    ) -> Result<GpuSlotGrant, GpuSlotPeerError> {
        let table = self.reach(machine, "reserve")?;
        if self.refuse_reserve.contains(&machine) {
            return Err(GpuSlotRefusal::Taken {
                device_id: request.device_id.clone().unwrap_or_default(),
            }
            .into());
        }
        let grant = table.reserve(request, T0)?;
        if self.lose_reserve_answer.contains(&machine) {
            return Err(GpuSlotPeerError::Uncertain {
                reason: "the answer did not arrive in time".to_owned(),
            });
        }
        Ok(grant)
    }

    fn release(&self, machine: EntityId, key: &str) -> Result<(), GpuSlotPeerError> {
        self.reach(machine, "release")?.release(key);
        Ok(())
    }
}

#[test]
fn selection_takes_the_best_fit_admitted_machine_whose_fresh_answer_shows_a_free_match()
-> TestResult {
    let (busy, small, roomy, large, gone) =
        (machine(1), machine(2), machine(3), machine(4), machine(5));
    let (peers, busy_probe) = FakePeers::default().machine(busy, vec![rtx4090("GPU-busy")]);
    let (peers, _) = peers.machine(small, vec![gpu("GPU-small", A4000, A4000_MIB)]);
    let (peers, _) = peers.machine(roomy, vec![rtx4090("GPU-roomy")]);
    let (mut peers, _) = peers.machine(large, vec![gpu("GPU-large", A6000, A6000_MIB)]);
    peers.unreachable.insert(gone);
    busy_probe.run_on("GPU-busy", 31_337);

    // The records still say what each card is; only the answers say whether
    // it is free. `busy` records a free-looking 4090 that is busy now.
    let candidates = vec![
        GpuNodeCandidate {
            machine: busy,
            inventory: vec![rtx4090("GPU-busy")],
        },
        GpuNodeCandidate {
            machine: small,
            inventory: vec![gpu("GPU-small", A4000, A4000_MIB)],
        },
        GpuNodeCandidate {
            machine: roomy,
            inventory: vec![rtx4090("GPU-roomy")],
        },
        GpuNodeCandidate {
            machine: large,
            inventory: vec![gpu("GPU-large", A6000, A6000_MIB)],
        },
        GpuNodeCandidate {
            machine: gone,
            inventory: vec![rtx4090("GPU-gone")],
        },
    ];
    let twenty_gib = |key: &str| GpuSlotRequest {
        min_memory_mib: 20_000,
        ..request(key)
    };

    let placement = select_gpu_slot(&candidates, &peers, &twenty_gib("chunk-1"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, roomy, "the smallest free card that fits");
    assert_eq!(placement.grant.device.device_id, "GPU-roomy");
    assert_eq!(
        peers.asked("availability"),
        vec![busy, roomy, large, gone],
        "a machine whose record lists no matching GPU is never asked"
    );
    assert_eq!(peers.asked("reserve"), vec![roomy]);

    let next = select_gpu_slot(&candidates, &peers, &twenty_gib("chunk-2"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(next.machine, large, "the held 4090 is no longer free");
    assert_eq!(
        select_gpu_slot(&candidates, &peers, &twenty_gib("chunk-3")),
        Err(GpuSelectionRefusal::NoneFree)
    );

    // Pinned by model: only machines recording that model are asked.
    let a4000 = GpuSlotRequest {
        model: Some(A4000.to_owned()),
        ..request("chunk-4")
    };
    assert_eq!(
        select_gpu_slot(&candidates, &peers, &a4000)
            .map_err(|refusal| refusal.to_string())?
            .machine,
        small
    );

    // No admitted machine records a match; none of the matches answers.
    assert_eq!(
        select_gpu_slot(
            &candidates,
            &peers,
            &GpuSlotRequest {
                min_memory_mib: 80_000,
                ..request("chunk-5")
            }
        ),
        Err(GpuSelectionRefusal::NoCandidate)
    );
    assert_eq!(
        select_gpu_slot(&candidates[4..], &peers, &request("chunk-6")),
        Err(GpuSelectionRefusal::NoneLive)
    );
    assert_eq!(
        select_gpu_slot(&[], &peers, &request("chunk-7")),
        Err(GpuSelectionRefusal::NoCandidate)
    );
    Ok(())
}

#[test]
fn a_refused_reservation_moves_to_the_next_fit_and_an_uncertain_one_is_never_rerouted() -> TestResult
{
    let (first, second) = (machine(1), machine(2));
    let (peers, _) = FakePeers::default().machine(first, vec![gpu("GPU-first", A4000, A4000_MIB)]);
    let (mut peers, _) = peers.machine(second, vec![rtx4090("GPU-second")]);
    let candidates = vec![
        GpuNodeCandidate {
            machine: first,
            inventory: vec![gpu("GPU-first", A4000, A4000_MIB)],
        },
        GpuNodeCandidate {
            machine: second,
            inventory: vec![rtx4090("GPU-second")],
        },
    ];

    // `first` fits best, but its GPU was taken between the answer and the
    // reservation: the next fit is tried.
    peers.refuse_reserve.insert(first);
    let placement = select_gpu_slot(&candidates, &peers, &request("raced"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, second);
    assert_eq!(peers.asked("reserve"), vec![first, second]);
    peers.release(second, "raced")?;

    // `first` took the reservation but its answer was lost: the selection
    // stops there and names it, and `second` is never asked to reserve.
    peers.refuse_reserve.clear();
    peers.lose_reserve_answer.insert(first);
    peers.asked.lock().unwrap().clear();
    let refusal = select_gpu_slot(&candidates, &peers, &request("lost")).unwrap_err();
    assert!(
        matches!(&refusal, GpuSelectionRefusal::Uncertain { machine, .. } if *machine == first),
        "{refusal}"
    );
    assert_eq!(peers.asked("reserve"), vec![first]);

    // Asking that machine again under the same key finds the hold it took.
    peers.lose_reserve_answer.clear();
    let again = peers.reserve(first, &pinned("lost", "GPU-first"))?;
    assert_eq!(again.device.device_id, "GPU-first");
    Ok(())
}

#[test]
fn the_devices_section_offers_listed_gpus_and_none_by_default() -> TestResult {
    use oneiron_server::test_doors::gpu_backend::gpu_jobs_section;

    assert_eq!(gpu_jobs_section("")?.devices, GpuDeviceOffer::default());
    assert!(
        GpuDeviceOffer::default().offered.is_empty(),
        "no GPU is offered by default"
    );
    assert_eq!(GpuDeviceOffer::default().hold_secs, GPU_SLOT_HOLD_SECS);

    let devices = gpu_jobs_section(
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-bbbb\"]\nwithheld_file = \"/var/lib/oneiron/gpu-withheld\"\nhold_secs = 30\n",
    )?
    .devices;
    assert_eq!(
        devices,
        GpuDeviceOffer {
            offered: ["GPU-aaaa", "GPU-bbbb"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            withheld_file: Some("/var/lib/oneiron/gpu-withheld".into()),
            hold_secs: 30,
        }
    );

    for refused in [
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-aaaa\"]\n",
        "[devices]\noffered = [\"GPU aaaa\"]\n",
        "[devices]\noffered = [\"\"]\n",
        "[devices]\nwithheld_file = \"relative/gpu-withheld\"\n",
        "[devices]\nhold_secs = 0\n",
        "[devices]\nofered = [\"GPU-aaaa\"]\n",
    ] {
        assert!(gpu_jobs_section(refused).is_err(), "{refused:?} is refused");
    }
    Ok(())
}
