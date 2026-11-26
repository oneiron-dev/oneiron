#![cfg(oneiron_test_support)]
//! GPU inventory, live slots and selection (machines map, section 9 row 2;
//! Engine 24 Nov 21:24: a device lease beside FloorLease, a disk reserve at
//! booking, a drain guard): each machine records its GPUs by stable device
//! id, model and memory on its `machine.capacity` record; a machine's slot
//! table leases one GPU atomically from a fresh driver reading, refuses a
//! booking whose disk is under its reserve, and rechecks the GPU at launch;
//! a quarantined GPU and a paused machine take no new work; a machine whose
//! jobs fail several times in a row takes no new GPU work until a person
//! clears it; the home's selection reads only admitted machines that answer
//! now, and takes no device. A request claims a device by kind, features and
//! memory (pass 34, 2.1, row G1), and the table's reading feeds the general
//! placement as `HeldDevice`s.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test gpu_slots`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use oneiron::authority::MachineRole;
use oneiron::job_workload::{
    DeviceClaim, DeviceKind, DeviceLease, DeviceMemory, DevicePlacementError, DeviceState,
    ResourceRequest, Sharing,
};
use oneiron::machine_capacity::{
    GpuDevice, MachineCapacity, MachineCapacityWrite, MachineMeasurement, MachinePower,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::gpu_execution_node::{
    GPU_DRAIN_AFTER_FAILURES, GpuAvailability, GpuComputeProcess, GpuDeviceAvailability,
    GpuDeviceLease, GpuDeviceOffer, GpuDeviceProbe, GpuDeviceProcesses, GpuDeviceState,
    GpuDiskReading, GpuJobDisk, GpuLeaseEnd, GpuNodeCandidate, GpuProbeError, GpuSelectionRefusal,
    GpuSlotPeer, GpuSlotPeerError, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable, LocalGpuSlotPeer,
    MachineGpus, gpu_node_candidates, parse_compute_process_lines, parse_device_lines,
    select_gpu_slot,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GIB: u64 = 1 << 30;
const RTX_4090: &str = "NVIDIA GeForce RTX 4090";
const RTX_4090_MIB: u64 = 24_564;
const A4000: &str = "NVIDIA RTX A4000";
const A4000_MIB: u64 = 16_376;
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

/// A disk with `free` bytes and a `reserve`, whose claims count against each
/// other until they drop.
struct FakeDisk {
    free: u64,
    reserve: u64,
    claimed: Arc<Mutex<u64>>,
}

struct FakeClaim {
    bytes: u64,
    claimed: Arc<Mutex<u64>>,
}

impl Drop for FakeClaim {
    fn drop(&mut self) {
        *self.claimed.lock().unwrap() -= self.bytes;
    }
}

impl GpuJobDisk for FakeDisk {
    fn claim(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, GpuSlotRefusal> {
        let mut claimed = self.claimed.lock().unwrap();
        let needed = self.reserve + *claimed + bytes;
        if self.free < needed {
            return Err(GpuSlotRefusal::DiskUnderReserve {
                needed_bytes: needed,
                free_bytes: self.free,
            });
        }
        *claimed += bytes;
        Ok(Box::new(FakeClaim {
            bytes,
            claimed: Arc::clone(&self.claimed),
        }))
    }
    fn restore(&self, bytes: u64) -> Box<dyn Send + Sync> {
        *self.claimed.lock().unwrap() += bytes;
        Box::new(FakeClaim {
            bytes,
            claimed: Arc::clone(&self.claimed),
        })
    }
    fn reading(&self) -> std::io::Result<GpuDiskReading> {
        Ok(GpuDiskReading {
            free_bytes: self.free,
            reserve_bytes: self.reserve,
            claimed_bytes: *self.claimed.lock().unwrap(),
        })
    }
}

fn offering(device_ids: &[&str]) -> GpuDeviceOffer {
    GpuDeviceOffer {
        offered: device_ids.iter().map(|id| (*id).to_owned()).collect(),
        ..GpuDeviceOffer::default()
    }
}

fn table(probe: &Arc<FakeProbe>, offer: GpuDeviceOffer) -> Arc<GpuSlotTable> {
    Arc::new(GpuSlotTable::new(
        Arc::clone(probe) as Arc<dyn GpuDeviceProbe>,
        offer,
    ))
}

/// A claim for one GPU of any memory.
fn gpu_claim() -> DeviceClaim {
    DeviceClaim {
        kind: DeviceKind::Gpu,
        count: 1,
        memory_mib: 0,
        features: Vec::new(),
        sharing: Sharing::Exclusive,
    }
}

fn request(key: &str) -> GpuSlotRequest {
    GpuSlotRequest {
        key: key.to_owned(),
        device_id: None,
        claim: gpu_claim(),
        disk_bytes: 0,
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

        // Nor does a changed order of unequal cards: the memory totals are
        // compared as a set too.
        let mixed = measured_with(
            vec![rtx4090("GPU-aaaa"), gpu("GPU-dddd", A4000, A4000_MIB)],
            5_000,
        );
        let MachineCapacityWrite::Recorded(mixed_id) = vault.record_machine_capacity(&mixed)?
        else {
            panic!("an added card records again");
        };
        let mixed_reordered = measured_with(
            vec![gpu("GPU-dddd", A4000, A4000_MIB), rtx4090("GPU-aaaa")],
            6_000,
        );
        assert_ne!(mixed_reordered.gpu_memory_mib, mixed.gpu_memory_mib);
        assert_eq!(
            vault.record_machine_capacity(&mixed_reordered)?,
            MachineCapacityWrite::Unchanged(mixed_id)
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
fn a_gpu_with_a_compute_process_is_never_taken() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    probe.run_on("GPU-aaaa", 777);

    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![777] }
    );
    assert_eq!(
        slots.lease(&pinned("pinned", "GPU-aaaa"), T0).map(|_| ()),
        Err(GpuSlotRefusal::Busy {
            device_id: "GPU-aaaa".to_owned(),
            pids: vec![777],
        })
    );
    let lease = slots.lease(&request("any"), T0)?;
    assert_eq!(
        lease.grant().device.device_id,
        "GPU-bbbb",
        "an unpinned lease passes the busy GPU over"
    );
    assert_eq!(
        slots.lease(&request("one-more"), T0).map(|_| ()),
        Err(GpuSlotRefusal::NoneFree)
    );
    Ok(())
}

#[test]
fn the_host_leases_a_gpu_through_machine_gpus_as_it_leases_memory() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let gpus: Arc<dyn MachineGpus> = Arc::clone(&slots) as Arc<dyn MachineGpus>;

    let mut lease: Box<dyn GpuDeviceLease> = gpus.try_lease(&request("call"))?;
    assert_eq!(lease.grant().device, rtx4090("GPU-aaaa"));
    assert_eq!(lease.grant().key, "call");
    assert!(matches!(
        gpus.try_lease(&request("other")),
        Err(GpuSlotRefusal::NoneFree)
    ));
    lease.confirm_launch()?;
    assert!(matches!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Launched { .. }
    ));
    lease.finish(GpuLeaseEnd::Succeeded);
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    Ok(())
}

#[test]
fn a_withheld_or_unoffered_gpu_is_never_taken_and_a_lease_withheld_later_does_not_launch()
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
        slots.lease(&pinned("b", "GPU-bbbb"), T0).map(|_| ()),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-bbbb".to_owned()
        })
    );
    assert_eq!(
        slots.lease(&pinned("c", "GPU-cccc"), T0).map(|_| ()),
        Err(GpuSlotRefusal::NotOffered {
            device_id: "GPU-cccc".to_owned()
        })
    );
    assert_eq!(
        slots.lease(&pinned("z", "GPU-zzzz"), T0).map(|_| ()),
        Err(GpuSlotRefusal::UnknownDevice {
            device_id: "GPU-zzzz".to_owned()
        })
    );
    let mut lease = slots.lease(&request("job"), T0)?;
    assert_eq!(lease.grant().device.device_id, "GPU-aaaa");

    // The other booker takes the leased GPU before the launch: it does not
    // launch, and the lease still holds it (its key still shows).
    std::fs::write(&withheld, "GPU-aaaa\nGPU-bbbb\n")?;
    assert_eq!(
        lease.confirm_launch(),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    assert_eq!(
        state_of(&slots.availability(T0 + 1_000)?, "GPU-aaaa"),
        GpuDeviceState::Leased {
            key: "job".to_owned()
        }
    );

    // Given back, the same lease launches.
    std::fs::write(&withheld, "GPU-bbbb\n")?;
    lease.confirm_launch()?;
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
        slots.lease(&request("next"), T0 + 3_000),
        Err(GpuSlotRefusal::Unmeasured { reason }) if reason.contains("gpu_probe.withheld_unreadable")
    ));
    Ok(())
}

#[test]
fn the_launch_recheck_refuses_a_gpu_that_turned_busy() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let mut lease = slots.lease(&request("job"), T0)?;

    probe.run_on("GPU-aaaa", 99);
    assert_eq!(
        lease.confirm_launch(),
        Err(GpuSlotRefusal::Busy {
            device_id: "GPU-aaaa".to_owned(),
            pids: vec![99],
        })
    );
    probe.end_processes();
    lease.confirm_launch()?;
    lease.confirm_launch()?;

    // The launched job's own process does not make its GPU busy.
    probe.run_on("GPU-aaaa", 4_100);
    assert_eq!(
        state_of(&slots.availability(T0 + 40)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );
    // Given back while a process still runs there, the GPU is busy, not free.
    drop(lease);
    assert_eq!(
        state_of(&slots.availability(T0 + 50)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![4_100] }
    );
    Ok(())
}

#[test]
fn a_quarantined_gpu_refuses_a_lease_and_clear_quarantine_frees_it() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let why = "the job's process survived its kill".to_owned();
    slots.quarantine("GPU-aaaa", why.clone());

    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Quarantined {
            why: why.clone(),
            key: None,
        }
    );
    assert_eq!(
        slots.lease(&request("job"), T0).map(|_| ()),
        Err(GpuSlotRefusal::Quarantined {
            device_id: "GPU-aaaa".to_owned(),
            why: why.clone(),
        })
    );
    assert!(slots.clear_quarantine("GPU-aaaa"));
    assert!(!slots.clear_quarantine("GPU-aaaa"));
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    slots.lease(&request("job"), T0)?;
    Ok(())
}

#[test]
fn a_quarantined_gpu_still_reattaches_its_key_and_availability_names_it() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let why = "a torn end record".to_owned();
    slots.quarantine("GPU-aaaa", why.clone());
    probe.run_on("GPU-aaaa", 4_242);

    let reattached = slots.reattach("job", "GPU-aaaa", 0, T0)?;
    assert_eq!(reattached.device, rtx4090("GPU-aaaa"));
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Quarantined {
            why,
            key: Some("job".to_owned()),
        }
    );
    Ok(())
}

#[test]
fn a_paused_machine_refuses_a_lease_and_a_launch_until_it_is_resumed() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    let mut waiting = slots.lease(&pinned("waiting", "GPU-aaaa"), T0)?;
    let reason = "a person paused GPU work".to_owned();
    slots.set_paused(Some(reason.clone()));

    let answer = slots.availability(T0)?;
    assert_eq!(answer.paused.as_deref(), Some(reason.as_str()));
    assert_eq!(answer.free_matching(&request("next")).count(), 0);
    assert_eq!(
        slots.lease(&request("next"), T0).map(|_| ()),
        Err(GpuSlotRefusal::Paused {
            reason: reason.clone()
        })
    );
    assert_eq!(
        waiting.confirm_launch(),
        Err(GpuSlotRefusal::Paused {
            reason: reason.clone()
        })
    );

    slots.set_paused(None);
    assert_eq!(slots.availability(T0)?.paused, None);
    waiting.confirm_launch()?;
    slots.lease(&request("next"), T0)?;
    Ok(())
}

#[test]
fn a_booking_is_refused_while_the_disk_is_under_its_reserve() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let disk = Arc::new(FakeDisk {
        free: 100 * GIB,
        reserve: 10 * GIB,
        claimed: Arc::default(),
    });
    let slots = GpuSlotTable::with_disk(
        Arc::clone(&probe) as Arc<dyn GpuDeviceProbe>,
        offering(&["GPU-aaaa", "GPU-bbbb"]),
        Some(Arc::clone(&disk) as Arc<dyn GpuJobDisk>),
    );
    let sized = |key: &str, disk_bytes: u64| GpuSlotRequest {
        disk_bytes,
        ..request(key)
    };

    assert_eq!(
        slots.lease(&sized("too-big", 91 * GIB), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 101 * GIB,
            free_bytes: 100 * GIB,
        }),
        "the job's bytes past the reserve must fit at booking, not after the start"
    );
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free,
        "a refused booking holds nothing"
    );

    // A lease claims its bytes until it ends.
    let first = slots.lease(&sized("first", 60 * GIB), T0)?;
    assert_eq!(*disk.claimed.lock().unwrap(), 60 * GIB);
    assert_eq!(
        slots.lease(&sized("second", 40 * GIB), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 110 * GIB,
            free_bytes: 100 * GIB,
        })
    );
    drop(first);
    assert_eq!(
        *disk.claimed.lock().unwrap(),
        0,
        "the claim ends with its slot"
    );

    // A lease that takes a kept slot keeps the claim its first lease took.
    let kept = slots.lease(&sized("kept", 60 * GIB), T0)?;
    let kept = kept.keep();
    assert_eq!(*disk.claimed.lock().unwrap(), 60 * GIB);
    let again = slots.lease(&sized("kept", 50 * GIB), T0)?;
    assert_eq!(again.grant(), &kept);
    assert_eq!(
        *disk.claimed.lock().unwrap(),
        60 * GIB,
        "a kept slot keeps its claim"
    );
    drop(again);
    assert_eq!(*disk.claimed.lock().unwrap(), 0);

    // A disk already under its reserve takes no lease, even of 0 bytes.
    let full = GpuSlotTable::with_disk(
        Arc::clone(&probe) as Arc<dyn GpuDeviceProbe>,
        offering(&["GPU-aaaa"]),
        Some(Arc::new(FakeDisk {
            free: 5 * GIB,
            reserve: 10 * GIB,
            claimed: Arc::default(),
        })),
    );
    assert_eq!(
        full.lease(&request("zero"), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 10 * GIB,
            free_bytes: 5 * GIB,
        })
    );
    Ok(())
}

#[test]
fn a_machine_whose_jobs_fail_several_times_in_a_row_takes_no_new_work_until_a_person_clears_it()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let drain_file = dir.path().join("gpu-drained");
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let offer = GpuDeviceOffer {
        drain_file: Some(drain_file.clone()),
        ..offering(&["GPU-aaaa"])
    };
    assert_eq!(offer.drain_after_failures, GPU_DRAIN_AFTER_FAILURES);
    assert_eq!(GPU_DRAIN_AFTER_FAILURES, 3);
    let slots = table(&probe, offer.clone());
    let run = |key: &str, end: GpuLeaseEnd| -> TestResult {
        slots.lease(&request(key), T0)?.finish(end);
        Ok(())
    };
    let failed = |why: &str| GpuLeaseEnd::Failed {
        reason: why.to_owned(),
    };

    // Two failures, a success, two more and a cancel: never three in a row.
    run("1", failed("exit 1"))?;
    run("2", failed("exit 1"))?;
    run("3", GpuLeaseEnd::Succeeded)?;
    run("4", failed("exit 1"))?;
    run("5", failed("exit 1"))?;
    run("6", GpuLeaseEnd::Cancelled)?;
    assert_eq!(slots.drained()?, None);

    run("7", failed("CUDA error: an illegal memory access"))?;

    let drained = slots
        .drained()?
        .ok_or("three failed jobs in a row drain the machine")?;
    assert!(drained.contains("3 failed GPU jobs in a row"), "{drained}");
    assert!(drained.contains("illegal memory access"), "{drained}");
    assert!(std::fs::read_to_string(&drain_file)?.contains("Delete this file"));
    let answer = slots.availability(T0)?;
    assert_eq!(answer.drained.as_deref(), Some(drained.as_str()));
    assert_eq!(answer.free_matching(&request("x")).count(), 0);
    assert!(matches!(
        slots.lease(&request("new"), T0),
        Err(GpuSlotRefusal::Drained { .. })
    ));

    // The drain outlasts a restart: a new table on the same file is drained.
    let restarted = table(&probe, offer.clone());
    assert_eq!(restarted.drained()?, Some(drained));

    // A person clears it by deleting the file; the machine takes work again.
    std::fs::remove_file(&drain_file)?;
    assert_eq!(restarted.drained()?, None);
    restarted.lease(&request("after"), T0)?;

    // Or through the table, which also starts the count over.
    run("8", failed("exit 1"))?;
    run("9", failed("exit 1"))?;
    run("10", failed("exit 1"))?;
    assert!(slots.drained()?.is_some());
    slots.clear_drain()?;
    assert_eq!(slots.drained()?, None);
    assert!(!drain_file.exists());

    // 0 never drains; with no drain file the drain is kept in memory.
    let never = table(
        &probe,
        GpuDeviceOffer {
            drain_after_failures: 0,
            ..offering(&["GPU-aaaa"])
        },
    );
    let in_memory = table(&probe, offering(&["GPU-aaaa"]));
    for n in 0..5 {
        never
            .lease(&request(&format!("n{n}")), T0)?
            .finish(failed("exit 1"));
        if n < 3 {
            in_memory
                .lease(&request(&format!("m{n}")), T0)?
                .finish(failed("exit 1"));
        }
    }
    assert_eq!(never.drained()?, None);
    assert!(in_memory.drained()?.is_some());
    in_memory.clear_drain()?;
    assert_eq!(in_memory.drained()?, None);
    Ok(())
}

#[test]
fn a_leased_job_does_not_launch_once_the_machine_is_drained() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    let mut waiting = slots.lease(&pinned("waiting", "GPU-bbbb"), T0)?;
    for n in 0..GPU_DRAIN_AFTER_FAILURES {
        slots
            .lease(&pinned(&format!("f{n}"), "GPU-aaaa"), T0)?
            .finish(GpuLeaseEnd::Failed {
                reason: "exit 1".to_owned(),
            });
    }
    assert!(matches!(
        waiting.confirm_launch(),
        Err(GpuSlotRefusal::Drained { .. })
    ));
    Ok(())
}

#[test]
fn a_failed_probe_offers_nothing() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let mut lease = slots.lease(&request("job"), T0)?;
    let failure = GpuProbeError::Unavailable {
        reason: "nvidia-smi did not answer within 10 s".to_owned(),
    };
    probe.fail(failure.clone());
    let unmeasured = GpuSlotRefusal::Unmeasured {
        reason: failure.to_string(),
    };

    assert_eq!(slots.availability(T0 + 1), Err(failure.clone()));
    assert_eq!(
        slots.lease(&request("other"), T0 + 1).map(|_| ()),
        Err(unmeasured.clone())
    );
    assert_eq!(
        lease.confirm_launch(),
        Err(unmeasured.clone()),
        "an unmeasured GPU does not launch"
    );

    let home = machine(1);
    let local = LocalGpuSlotPeer::new(home, Arc::clone(&slots));
    assert_eq!(
        local.availability(home),
        Err(GpuSlotPeerError::Refused(unmeasured))
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

/// FIX G1-PLACEMENT-DUPLICATE-DEVICE-ID (first-pass review of #10471): a
/// lease and its launch recheck find their GPU by id in a fresh reading, so
/// a reading that lists one id twice, here under two models, could lease or
/// launch on either line. Such a reading measures nothing.
#[test]
fn a_reading_that_lists_one_gpu_twice_offers_nothing() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let mut lease = slots.lease(&pinned("job", "GPU-aaaa"), T0)?;

    probe
        .devices
        .lock()
        .unwrap()
        .push(gpu("GPU-aaaa", A4000, A4000_MIB));
    let repeated = GpuProbeError::RepeatedDevice {
        device_id: "GPU-aaaa".to_owned(),
    };
    let unmeasured = GpuSlotRefusal::Unmeasured {
        reason: repeated.to_string(),
    };
    assert_eq!(slots.availability(T0 + 1), Err(repeated));
    assert_eq!(slots.held_devices(T0 + 1), Err(unmeasured.clone()));
    assert_eq!(
        slots.lease(&request("other"), T0 + 1).map(|_| ()),
        Err(unmeasured.clone())
    );
    assert_eq!(
        lease.confirm_launch(),
        Err(unmeasured),
        "the launch recheck cannot tell which line is its GPU"
    );
    Ok(())
}

/// The vault's machines as the home reads them: each a real slot table on
/// a fake driver, some unreachable, some whose answer is a refusal. It
/// records every machine it asks.
#[derive(Default)]
struct FakePeers {
    tables: BTreeMap<EntityId, Arc<GpuSlotTable>>,
    unreachable: BTreeSet<EntityId>,
    asked: Mutex<Vec<EntityId>>,
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

    fn asked(&self) -> Vec<EntityId> {
        self.asked.lock().unwrap().clone()
    }

    fn reach(&self, machine: EntityId) -> Result<&GpuSlotTable, GpuSlotPeerError> {
        self.asked.lock().unwrap().push(machine);
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
        self.reach(machine)?.availability(T0).map_err(|probe| {
            GpuSlotRefusal::Unmeasured {
                reason: probe.to_string(),
            }
            .into()
        })
    }
}

#[test]
fn selection_reads_the_best_fit_free_gpu_and_takes_nothing() -> TestResult {
    let (small, roomy) = (machine(1), machine(2));
    let (peers, _) = FakePeers::default().machine(small, vec![gpu("GPU-small", A4000, A4000_MIB)]);
    let (peers, _) = peers.machine(roomy, vec![rtx4090("GPU-roomy")]);
    let candidates = vec![
        GpuNodeCandidate {
            machine: small,
            inventory: vec![gpu("GPU-small", A4000, A4000_MIB)],
        },
        GpuNodeCandidate {
            machine: roomy,
            inventory: vec![rtx4090("GPU-roomy")],
        },
    ];

    let placement = select_gpu_slot(&candidates, &peers, &request("chunk"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, small, "the smallest free card that fits");
    assert_eq!(placement.device, gpu("GPU-small", A4000, A4000_MIB));
    assert_eq!(
        peers.asked(),
        vec![small, roomy],
        "every admitted machine whose record lists a match is asked"
    );
    assert_eq!(
        state_of(&peers.tables[&small].availability(T0)?, "GPU-small"),
        GpuDeviceState::Free,
        "the selection took nothing"
    );

    let again = select_gpu_slot(&candidates, &peers, &request("chunk-2"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(again.machine, small);
    assert_eq!(again.device, gpu("GPU-small", A4000, A4000_MIB));

    assert_eq!(
        select_gpu_slot(
            &candidates,
            &peers,
            &GpuSlotRequest {
                claim: DeviceClaim {
                    memory_mib: 80_000,
                    ..gpu_claim()
                },
                ..request("none")
            }
        ),
        Err(GpuSelectionRefusal::NoCandidate)
    );

    peers.asked.lock().unwrap().clear();
    let roomy_only = GpuSlotRequest {
        claim: DeviceClaim {
            memory_mib: 20_000,
            ..gpu_claim()
        },
        ..request("roomy-only")
    };
    let placement =
        select_gpu_slot(&candidates, &peers, &roomy_only).map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, roomy);
    assert_eq!(
        peers.asked(),
        vec![roomy],
        "a machine whose record lists no matching GPU is never asked"
    );
    Ok(())
}

#[test]
fn selection_chooses_the_machine_whose_answer_names_the_request_key() -> TestResult {
    let (better, keyed, later) = (machine(1), machine(2), machine(3));
    let (peers, _) =
        FakePeers::default().machine(better, vec![gpu("GPU-better", A4000, A4000_MIB)]);
    let (peers, _) = peers.machine(keyed, vec![rtx4090("GPU-keyed")]);
    let (peers, _) = peers.machine(later, vec![gpu("GPU-later", A4000, A4000_MIB)]);
    peers.tables[&keyed].reattach("chunk", "GPU-keyed", 0, T0)?;

    let candidates = vec![
        GpuNodeCandidate {
            machine: better,
            inventory: vec![gpu("GPU-better", A4000, A4000_MIB)],
        },
        GpuNodeCandidate {
            machine: keyed,
            inventory: vec![rtx4090("GPU-keyed")],
        },
        GpuNodeCandidate {
            machine: later,
            inventory: vec![gpu("GPU-later", A4000, A4000_MIB)],
        },
    ];
    let placement = select_gpu_slot(&candidates, &peers, &request("chunk"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, keyed);
    assert_eq!(placement.device, rtx4090("GPU-keyed"));
    assert_eq!(
        peers.asked(),
        vec![better, keyed],
        "no machine is asked after the one whose answer names the key"
    );
    Ok(())
}

#[test]
fn selection_skips_an_unreachable_and_a_refusing_machine() -> TestResult {
    let (gone, refusing, good) = (machine(1), machine(2), machine(3));
    let (mut peers, _) = FakePeers::default().machine(gone, vec![rtx4090("GPU-gone")]);
    peers.unreachable.insert(gone);
    let (peers, refusing_probe) = peers.machine(refusing, vec![rtx4090("GPU-refusing")]);
    let (peers, _) = peers.machine(good, vec![rtx4090("GPU-good")]);
    refusing_probe.fail(GpuProbeError::Unavailable {
        reason: "nvidia-smi did not answer".to_owned(),
    });
    let candidates = vec![
        GpuNodeCandidate {
            machine: gone,
            inventory: vec![rtx4090("GPU-gone")],
        },
        GpuNodeCandidate {
            machine: refusing,
            inventory: vec![rtx4090("GPU-refusing")],
        },
        GpuNodeCandidate {
            machine: good,
            inventory: vec![rtx4090("GPU-good")],
        },
    ];

    let placement = select_gpu_slot(&candidates, &peers, &request("chunk"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, good);
    assert_eq!(placement.device, rtx4090("GPU-good"));
    assert_eq!(peers.asked(), vec![gone, refusing, good]);

    assert_eq!(
        select_gpu_slot(&candidates[..1], &peers, &request("only-gone")),
        Err(GpuSelectionRefusal::NoneLive)
    );
    assert_eq!(
        select_gpu_slot(&candidates[1..2], &peers, &request("only-refusing")),
        Err(GpuSelectionRefusal::NoneFree),
        "a machine that answered is live, and it offers nothing"
    );
    Ok(())
}

/// Machines whose answers come from somewhere other than this build's slot
/// table (which refuses a reading that lists one GPU twice): each machine
/// gives the same fixed answer every time it is asked.
struct FixedAnswers(BTreeMap<EntityId, GpuAvailability>);

impl GpuSlotPeer for FixedAnswers {
    fn availability(&self, machine: EntityId) -> Result<GpuAvailability, GpuSlotPeerError> {
        self.0
            .get(&machine)
            .cloned()
            .ok_or_else(|| GpuSlotPeerError::Unreachable {
                reason: "an unknown machine".to_owned(),
            })
    }
}

/// An answer from an open machine (not paused, not drained, no disk
/// reading) that lists `devices`, one line each, in this order.
fn answer(devices: Vec<(GpuDevice, GpuDeviceState)>) -> GpuAvailability {
    GpuAvailability {
        measured_at_ms: T0,
        paused: None,
        drained: None,
        disk: None,
        devices: devices
            .into_iter()
            .map(|(device, state)| GpuDeviceAvailability { device, state })
            .collect(),
    }
}

#[test]
fn free_matching_skips_a_gpu_the_answer_lists_twice() -> TestResult {
    let twice = answer(vec![
        (gpu("GPU-a", A4000, A4000_MIB), GpuDeviceState::Free),
        (
            gpu("GPU-a", A4000, A4000_MIB),
            GpuDeviceState::Busy { pids: vec![4242] },
        ),
        (rtx4090("GPU-b"), GpuDeviceState::Free),
    ]);
    assert_eq!(
        twice
            .free_matching(&request("chunk"))
            .cloned()
            .collect::<Vec<GpuDevice>>(),
        vec![rtx4090("GPU-b")],
        "only the GPU the answer lists once is offered"
    );

    let both_free = answer(vec![
        (gpu("GPU-a", A4000, A4000_MIB), GpuDeviceState::Free),
        (gpu("GPU-a", A4000, A4000_MIB), GpuDeviceState::Free),
    ]);
    assert_eq!(
        both_free.free_matching(&request("chunk")).count(),
        0,
        "two free lines of one GPU id offer nothing"
    );
    Ok(())
}

#[test]
fn selection_skips_a_gpu_that_one_answer_lists_twice() -> TestResult {
    let (repeating, roomy) = (machine(1), machine(2));
    let small = gpu("GPU-small", A4000, A4000_MIB);
    let peers = FixedAnswers(BTreeMap::from([
        (
            repeating,
            answer(vec![
                (small.clone(), GpuDeviceState::Free),
                (small.clone(), GpuDeviceState::Free),
            ]),
        ),
        (
            roomy,
            answer(vec![(rtx4090("GPU-roomy"), GpuDeviceState::Free)]),
        ),
    ]));
    let candidates = vec![
        GpuNodeCandidate {
            machine: repeating,
            inventory: vec![small],
        },
        GpuNodeCandidate {
            machine: roomy,
            inventory: vec![rtx4090("GPU-roomy")],
        },
    ];

    let placement = select_gpu_slot(&candidates, &peers, &request("chunk"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(
        placement.machine, roomy,
        "the smaller card fits best, but its machine lists it twice"
    );
    assert_eq!(placement.device, rtx4090("GPU-roomy"));

    assert_eq!(
        select_gpu_slot(&candidates[..1], &peers, &request("only-repeating")),
        Err(GpuSelectionRefusal::NoneFree),
        "a machine whose one GPU is listed twice is live and offers nothing"
    );
    Ok(())
}

#[test]
fn the_devices_section_offers_listed_gpus_and_none_by_default() -> TestResult {
    use oneiron_server::test_doors::gpu_backend::gpu_jobs_section;

    assert_eq!(gpu_jobs_section("")?.devices, GpuDeviceOffer::default());
    let default = GpuDeviceOffer::default();
    assert!(default.offered.is_empty(), "no GPU is offered by default");
    assert_eq!(default.drain_after_failures, GPU_DRAIN_AFTER_FAILURES);
    assert_eq!(default.drain_file, None);

    let dir = tempfile::tempdir()?;
    let drain_file = dir.path().join("gpu-drained");
    let owner_lock_dir = dir.path().join("gpu-owners");
    std::fs::create_dir(&owner_lock_dir)?;
    let devices = gpu_jobs_section(&format!(
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-bbbb\"]\nwithheld_file = \"/var/lib/oneiron/gpu-withheld\"\ndrain_after_failures = 5\ndrain_file = {:?}\nowner_lock_dir = {:?}\n",
        drain_file.display().to_string(),
        owner_lock_dir.display().to_string(),
    ))?
    .devices;
    assert_eq!(
        devices,
        GpuDeviceOffer {
            offered: ["GPU-aaaa", "GPU-bbbb"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            withheld_file: Some("/var/lib/oneiron/gpu-withheld".into()),
            drain_after_failures: 5,
            drain_file: Some(drain_file),
            owner_lock_dir: Some(owner_lock_dir),
        }
    );
    // review-10425 round 2, P1 1: no default lock directory, since only the
    // owner knows the host directory every server (and container) shares.
    let unnamed = gpu_jobs_section("[devices]\noffered = [\"GPU-aaaa\"]\n")
        .expect_err("an offering server names its owner lock directory");
    assert!(
        unnamed.to_string().contains("owner_lock_dir must be named"),
        "{unnamed}"
    );
    let missing = gpu_jobs_section(&format!(
        "[devices]\noffered = [\"GPU-aaaa\"]\nowner_lock_dir = {:?}\n",
        dir.path().join("not-made").display().to_string(),
    ))
    .expect_err("the owner lock directory must already exist");
    assert!(
        missing.to_string().contains("existing directory"),
        "{missing}"
    );
    assert_eq!(
        gpu_jobs_section("[devices]\nowner_lock_dir = \"/no/such/gpu-owners\"\n")?
            .devices
            .owner_lock_dir,
        Some("/no/such/gpu-owners".into()),
        "a machine that offers no GPU takes no lock, wherever the directory is"
    );

    for refused in [
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-aaaa\"]\n",
        "[devices]\noffered = [\"GPU aaaa\"]\n",
        "[devices]\noffered = [\"\"]\n",
        "[devices]\nwithheld_file = \"relative/gpu-withheld\"\n",
        "[devices]\ndrain_file = \"relative/gpu-drained\"\n",
        "[devices]\ndrain_file = \"/no/such/directory/gpu-drained\"\n",
        "[devices]\nowner_lock_dir = \"relative/gpu-owners\"\n",
        "[devices]\nofered = [\"GPU-aaaa\"]\n",
    ] {
        assert!(gpu_jobs_section(refused).is_err(), "{refused:?} is refused");
    }
    Ok(())
}

#[test]
fn a_kept_lease_stays_with_its_running_job_until_its_key_ends_it_and_a_restart_reattaches_it()
-> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let offer = offering(&["GPU-aaaa"]);
    let slots = table(&probe, offer.clone());
    let mut lease = slots.lease(&request("job"), T0)?;
    lease.confirm_launch()?;
    probe.run_on("GPU-aaaa", 4_242);
    let kept = lease.keep();
    assert_eq!(kept.key, "job");

    // Past the lease, the job holds its GPU under its key, and never lapses.
    assert_eq!(
        state_of(&slots.availability(T0 + 36_000_000)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );
    assert_eq!(
        slots.lease(&request("other"), T0).map(|_| ()),
        Err(GpuSlotRefusal::NoneFree)
    );
    assert_eq!(
        slots.end_check("job")?,
        GpuDeviceProcesses {
            pids: vec![4_242],
            hidden: 0,
        }
    );
    assert_eq!(slots.end_check("nobody"), Err(GpuSlotRefusal::NotHeld));

    // The job's key can take a lease on it again, one at a time.
    let again = slots.lease(&request("job"), T0)?;
    assert_eq!(again.grant(), &kept);
    assert!(
        !slots.finish("job", &GpuLeaseEnd::Succeeded),
        "a slot under a live lease is that lease's to end"
    );
    drop(again);
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![4_242] },
        "the dropped lease gave the GPU back; the job's process is still seen"
    );

    // After a restart the table is empty: the job reattaches under its key.
    let restarted = table(&probe, offer);
    assert_eq!(
        state_of(&restarted.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Busy { pids: vec![4_242] }
    );
    let reattached = restarted.reattach("job", "GPU-aaaa", 0, T0)?;
    assert_eq!(reattached.device, rtx4090("GPU-aaaa"));
    assert_eq!(
        restarted.reattach("job", "GPU-aaaa", 0, T0 + 1)?,
        reattached
    );
    assert_eq!(
        restarted.reattach("twin", "GPU-aaaa", 0, T0),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    assert_eq!(
        restarted.reattach("lost", "GPU-zzzz", 0, T0),
        Err(GpuSlotRefusal::UnknownDevice {
            device_id: "GPU-zzzz".to_owned()
        })
    );
    assert_eq!(
        state_of(&restarted.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );

    // The job ends: its key finishes the slot and the end is counted.
    probe.end_processes();
    assert!(restarted.end_check("job")?.is_empty());
    assert!(restarted.finish(
        "job",
        &GpuLeaseEnd::Failed {
            reason: "exit 1".to_owned()
        }
    ));
    assert!(!restarted.release("job"), "the slot is already gone");
    assert_eq!(
        state_of(&restarted.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    Ok(())
}

#[test]
fn availability_shows_the_disk_and_the_drain_and_selection_skips_a_full_or_drained_machine()
-> TestResult {
    let (full, drained, roomy) = (machine(1), machine(2), machine(3));
    let mut peers = FakePeers::default();
    let mut add = |id: EntityId, free: u64| {
        let device_id = format!("GPU-{}", id.to_hex());
        let probe = FakeProbe::with(vec![rtx4090(&device_id)]);
        let offer = offering(&[device_id.as_str()]);
        let table = Arc::new(GpuSlotTable::with_disk(
            Arc::clone(&probe) as Arc<dyn GpuDeviceProbe>,
            offer,
            Some(Arc::new(FakeDisk {
                free,
                reserve: 10 * GIB,
                claimed: Arc::default(),
            })),
        ));
        peers.tables.insert(id, Arc::clone(&table));
        table
    };
    let full_table = add(full, 20 * GIB);
    let drained_table = add(drained, 500 * GIB);
    add(roomy, 500 * GIB);
    for n in 0..GPU_DRAIN_AFTER_FAILURES {
        drained_table
            .lease(&request(&format!("f{n}")), T0)?
            .finish(GpuLeaseEnd::Failed {
                reason: "exit 1".to_owned(),
            });
    }

    let answer = full_table.availability(T0)?;
    assert_eq!(
        answer.disk,
        Some(GpuDiskReading {
            free_bytes: 20 * GIB,
            reserve_bytes: 10 * GIB,
            claimed_bytes: 0,
        })
    );
    let fifty_gib = GpuSlotRequest {
        disk_bytes: 50 * GIB,
        ..request("chunk")
    };
    assert_eq!(answer.free_matching(&fifty_gib).count(), 0);
    assert_eq!(answer.free_matching(&request("small")).count(), 1);
    assert!(drained_table.availability(T0)?.drained.is_some());

    let candidates: Vec<GpuNodeCandidate> = [full, drained, roomy]
        .into_iter()
        .map(|id| GpuNodeCandidate {
            machine: id,
            inventory: vec![rtx4090(&format!("GPU-{}", id.to_hex()))],
        })
        .collect();
    let placement =
        select_gpu_slot(&candidates, &peers, &fifty_gib).map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, roomy);
    assert_eq!(
        placement.device.device_id,
        format!("GPU-{}", roomy.to_hex())
    );
    assert_eq!(
        peers.asked(),
        vec![full, drained, roomy],
        "the full and drained machines answer, and offer nothing"
    );
    Ok(())
}

#[test]
fn an_offered_gpu_that_a_model_worker_runs_on_is_refused() -> TestResult {
    use oneiron_server::config::gpu_jobs::refuse_worker_device_overlap;

    let offered: BTreeSet<String> = ["GPU-aaaa".to_owned()].into_iter().collect();
    refuse_worker_device_overlap(&offered, [("chat", Some("GPU-bbbb"))])?;
    refuse_worker_device_overlap(&offered, [("cpu", Some("-1"))])?;
    refuse_worker_device_overlap(&BTreeSet::new(), [("chat", Some("0"))])?;
    refuse_worker_device_overlap(&BTreeSet::new(), [("chat", None)])?;
    let overlap = refuse_worker_device_overlap(&offered, [("chat", Some("GPU-bbbb, GPU-aaaa"))])
        .expect_err("a worker on an offered GPU is refused");
    assert!(overlap.to_string().contains("chat"), "{overlap}");
    let by_index = refuse_worker_device_overlap(&offered, [("voice", Some("0"))])
        .expect_err("an index cannot be told apart from an offered GPU");
    assert!(by_index.to_string().contains("by index"), "{by_index}");
    // review-10425 round 2, P1 2: a worker that names no device sees every
    // GPU (CUDA_VISIBLE_DEVICES unset), the offered one too.
    let unpinned = refuse_worker_device_overlap(&offered, [("exl3", None)])
        .expect_err("a worker with no device is refused while a GPU is offered");
    assert!(
        unpinned.to_string().contains("exl3") && unpinned.to_string().contains("no device"),
        "{unpinned}"
    );
    // CUDA takes a unique UUID prefix, in any case, and the older MIG form
    // holds its GPU's id (review-10425 P1 4).
    for named in ["GPU-aa", "gpu-AAAA", "MIG-GPU-aaaa/1/0"] {
        let refused = refuse_worker_device_overlap(&offered, [("chat", Some(named))])
            .expect_err("a worker naming an offered GPU by another form is refused");
        assert!(
            refused.to_string().contains("GPU-aaaa"),
            "{named}: {refused}"
        );
    }
    Ok(())
}

#[test]
fn a_drain_written_after_a_failed_write_clears_when_its_file_is_deleted() -> TestResult {
    // review-10425 P1 7: a drain kept in memory after a failed write must
    // not outlive a later drain that the file holds.
    let dir = tempfile::tempdir()?;
    let drain_file = dir.path().join("later").join("gpu-drained");
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(
        &probe,
        GpuDeviceOffer {
            drain_file: Some(drain_file.clone()),
            ..offering(&["GPU-aaaa"])
        },
    );
    slots.drain("first".to_owned());
    assert_eq!(
        slots.drained()?,
        Some("first".to_owned()),
        "kept in memory while its file cannot be written"
    );
    std::fs::create_dir(dir.path().join("later"))?;
    slots.drain("second".to_owned());
    assert!(drain_file.is_file(), "the second drain is written");
    assert_eq!(slots.drained()?, Some("second".to_owned()));
    std::fs::remove_file(&drain_file)?;
    assert_eq!(
        slots.drained()?,
        None,
        "deleting the written drain clears it"
    );
    Ok(())
}

#[test]
fn two_servers_on_one_machine_never_offer_the_same_gpu() -> TestResult {
    let dir = tempfile::tempdir()?;
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let offer = GpuDeviceOffer {
        owner_lock_dir: Some(dir.path().to_path_buf()),
        ..offering(&["GPU-aaaa"])
    };
    let first = table(&probe, offer.clone());
    let second = table(&probe, offer);
    assert_eq!(
        state_of(&first.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Withheld,
        "the GPU's owner lock is the first server's"
    );
    assert_eq!(
        second.lease(&request("b"), T0).map(|_| ()),
        Err(GpuSlotRefusal::NoneFree)
    );
    assert_eq!(
        second.lease(&pinned("b", "GPU-aaaa"), T0).map(|_| ()),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    // A restarted server takes back only a GPU it owns (review-10425 P1 3).
    assert_eq!(
        second.reattach("b", "GPU-aaaa", 0, T0).map(|_| ()),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    first.lease(&request("a"), T0)?;

    // The first server stops: the second owns the GPU at its next reading.
    drop(first);
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    second.lease(&request("b"), T0)?;
    Ok(())
}

#[test]
fn a_job_that_outlives_its_server_keeps_its_gpu_until_its_restarted_server_ends_it() -> TestResult {
    // review-10425 round 2, P1 3: the owner lock alone ended with its server,
    // so a second server could confirm another job on a GPU whose job had not
    // opened its CUDA context yet.
    let dir = tempfile::tempdir()?;
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let offer = GpuDeviceOffer {
        owner_lock_dir: Some(dir.path().to_path_buf()),
        ..offering(&["GPU-aaaa"])
    };
    let first = table(&probe, offer.clone());
    let second = table(&probe, offer.clone());
    let mut lease = first.lease(&request("job"), T0)?;
    lease.confirm_launch()?;
    assert_eq!(lease.keep().key, "job");

    // The first server stops while the driver still shows the GPU idle.
    drop(first);
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Withheld,
        "the running job keeps its GPU past its server"
    );
    assert_eq!(
        second.lease(&request("other"), T0).map(|_| ()),
        Err(GpuSlotRefusal::NoneFree)
    );
    assert_eq!(
        second.reattach("other", "GPU-aaaa", 0, T0).map(|_| ()),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    assert!(
        !second.release("other"),
        "releasing another key clears nothing"
    );

    // The first server restarts and takes its job back under its key.
    let restarted = table(&probe, offer.clone());
    assert_eq!(restarted.reattach("job", "GPU-aaaa", 0, T0)?.key, "job");
    assert_eq!(
        state_of(&restarted.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Launched {
            key: "job".to_owned()
        }
    );
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Withheld
    );

    // The job ends: its record goes with its slot, and the GPU is offered.
    assert!(restarted.finish("job", &GpuLeaseEnd::Succeeded));
    assert_eq!(
        state_of(&restarted.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    drop(restarted);
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );

    // A journaled job that did not survive a restart: releasing its key
    // clears its record, and the GPU is offered again.
    let mut lease = second.lease(&request("lost"), T0)?;
    lease.confirm_launch()?;
    assert_eq!(lease.keep().key, "lost");
    drop(second);
    let third = table(&probe, offer);
    assert_eq!(
        state_of(&third.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Withheld
    );
    assert!(!third.release("lost"), "no slot ended");
    assert_eq!(
        state_of(&third.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free,
        "the record of the job that did not survive is cleared"
    );
    Ok(())
}

#[test]
fn a_reattached_job_claims_its_booked_disk_again_before_new_work() -> TestResult {
    // review-10425 round 2, P1 4: a reattached job's booking was lost, so a
    // second job could book room the first still needs.
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let disk = Arc::new(FakeDisk {
        free: 110 * GIB,
        reserve: 10 * GIB,
        claimed: Arc::default(),
    });
    let with_disk = || {
        GpuSlotTable::with_disk(
            Arc::clone(&probe) as Arc<dyn GpuDeviceProbe>,
            offering(&["GPU-aaaa", "GPU-bbbb"]),
            Some(Arc::clone(&disk) as Arc<dyn GpuJobDisk>),
        )
    };
    let sized = |key: &str, disk_bytes: u64| GpuSlotRequest {
        disk_bytes,
        ..request(key)
    };
    let slots = with_disk();
    let mut lease = slots.lease(&sized("job", 80 * GIB), T0)?;
    assert_eq!(lease.grant().device.device_id, "GPU-aaaa");
    lease.confirm_launch()?;
    assert_eq!(lease.keep().key, "job");
    assert_eq!(*disk.claimed.lock().unwrap(), 80 * GIB);
    drop(slots);
    assert_eq!(
        *disk.claimed.lock().unwrap(),
        0,
        "a stopped server's claims end with it"
    );

    // Restarted, the server reattaches the job with its journaled booking.
    let restarted = with_disk();
    restarted.reattach("job", "GPU-aaaa", 80 * GIB, T0)?;
    assert_eq!(*disk.claimed.lock().unwrap(), 80 * GIB);
    assert_eq!(
        restarted.lease(&sized("next", 50 * GIB), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 140 * GIB,
            free_bytes: 110 * GIB,
        }),
        "the live job's 80 GiB and a new 50 GiB do not both fit past the reserve"
    );

    // The job ends: its claim goes with its slot.
    assert!(restarted.finish("job", &GpuLeaseEnd::Succeeded));
    assert_eq!(*disk.claimed.lock().unwrap(), 0);
    restarted.lease(&sized("next", 50 * GIB), T0)?;
    Ok(())
}

#[test]
fn every_launch_attempt_is_checked_afresh() -> TestResult {
    // review-10425 round 2, P1 6: a confirmation after an earlier success
    // answered from that success, so a retry launched on a GPU withheld since.
    let dir = tempfile::tempdir()?;
    let withheld = dir.path().join("gpu-withheld");
    std::fs::write(&withheld, "")?;
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(
        &probe,
        GpuDeviceOffer {
            withheld_file: Some(withheld.clone()),
            ..offering(&["GPU-aaaa"])
        },
    );
    let mut lease = slots.lease(&request("job"), T0)?;
    lease.confirm_launch()?;

    // The first start failed; another booker takes the GPU before the retry.
    std::fs::write(&withheld, "GPU-aaaa\n")?;
    assert_eq!(
        lease.confirm_launch(),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    std::fs::write(&withheld, "")?;
    slots.drain("a person drained the machine".to_owned());
    assert!(matches!(
        lease.confirm_launch(),
        Err(GpuSlotRefusal::Drained { .. })
    ));
    slots.clear_drain()?;

    // A process the first attempt left running refuses a relaunch on top.
    probe.run_on("GPU-aaaa", 7);
    assert_eq!(
        lease.confirm_launch(),
        Err(GpuSlotRefusal::Busy {
            device_id: "GPU-aaaa".to_owned(),
            pids: vec![7],
        })
    );
    probe.end_processes();
    lease.confirm_launch()?;
    Ok(())
}

/// Pass 34, 2.1 (row G1): a GPU lease matches its claim's kind, features and
/// least memory against the driver's facts (a GPU the NVIDIA driver lists
/// offers `cuda`), never a vendor or a model name.
#[test]
fn a_claim_is_met_by_kind_features_and_memory_never_by_a_model_name() -> TestResult {
    let probe = FakeProbe::with(vec![gpu("GPU-aaaa", A4000, A4000_MIB), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    let claiming = |key: &str, claim: DeviceClaim| GpuSlotRequest {
        claim,
        ..request(key)
    };

    let facts = slots.availability(T0)?.devices[0].facts();
    assert_eq!(facts.id, "GPU-aaaa");
    assert_eq!(facts.kind, DeviceKind::Gpu);
    assert_eq!(facts.vendor, "nvidia");
    assert_eq!(facts.model, A4000, "shown to people, never matched");
    assert_eq!(facts.features, vec!["cuda".to_owned()]);
    assert_eq!(facts.memory, DeviceMemory::Dedicated { mib: A4000_MIB });
    assert_eq!(facts.state, DeviceState::Offered);
    assert_eq!(facts.max_claimants, 1);

    for (claim, why) in [
        (
            DeviceClaim {
                features: vec!["rocm".to_owned()],
                ..gpu_claim()
            },
            "a feature no GPU offers",
        ),
        (
            DeviceClaim {
                kind: DeviceKind::Npu,
                ..gpu_claim()
            },
            "another kind of device",
        ),
        (
            DeviceClaim {
                memory_mib: 80_000,
                ..gpu_claim()
            },
            "more memory than any GPU has",
        ),
    ] {
        assert_eq!(
            slots.lease(&claiming("none", claim), T0).map(|_| ()),
            Err(GpuSlotRefusal::NoMatch),
            "{why}"
        );
    }
    let cuda = slots.lease(
        &claiming(
            "cuda",
            DeviceClaim {
                features: vec!["cuda".to_owned()],
                ..gpu_claim()
            },
        ),
        T0,
    )?;
    assert_eq!(
        cuda.grant().device.device_id,
        "GPU-aaaa",
        "the smallest GPU with the feature"
    );
    let roomy = slots.lease(
        &claiming(
            "roomy",
            DeviceClaim {
                memory_mib: 20_000,
                ..gpu_claim()
            },
        ),
        T0,
    )?;
    assert_eq!(
        roomy.grant().device.device_id,
        "GPU-bbbb",
        "only the RTX 4090 has 20 000 MiB"
    );
    Ok(())
}

/// Pass 34, 2.1 (row G1): a key leases one device here, so a claim for 0 or
/// 2 devices is refused, and nothing is taken.
#[test]
fn a_claim_for_other_than_one_device_is_refused_and_takes_nothing() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    for count in [0, 2] {
        let asked = GpuSlotRequest {
            claim: DeviceClaim {
                count,
                ..gpu_claim()
            },
            ..request("many")
        };
        assert_eq!(
            slots.lease(&asked, T0).map(|_| ()),
            Err(GpuSlotRefusal::ClaimCount { count })
        );
    }
    let answer = slots.availability(T0)?;
    assert_eq!(state_of(&answer, "GPU-aaaa"), GpuDeviceState::Free);
    assert_eq!(state_of(&answer, "GPU-bbbb"), GpuDeviceState::Free);
    Ok(())
}

/// Pass 34, 2.1 (row G1): the table's fresh reading, as `HeldDevice`s, feeds
/// `ResourceRequest::place_devices`. A GPU a key leased has that key as its
/// one exclusive holder, a GPU another's compute process runs on is
/// withheld, and placement picks the one free GPU, which the launch commit
/// then leases by its id. A paused machine places nothing.
#[test]
fn held_devices_place_a_request_on_the_gpu_no_key_holds() -> TestResult {
    let probe = FakeProbe::with(vec![
        rtx4090("GPU-aaaa"),
        rtx4090("GPU-bbbb"),
        rtx4090("GPU-cccc"),
    ]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb", "GPU-cccc"]));
    let first = slots.lease(&pinned("first", "GPU-aaaa"), T0)?;
    probe.run_on("GPU-cccc", 4242);

    let held = slots.held_devices(T0)?;
    let by_id = |id: &str| {
        held.iter()
            .find(|device| device.facts.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} is listed"))
    };
    assert_eq!(
        by_id("GPU-aaaa").facts.state,
        DeviceState::Leased {
            keys: vec!["first".to_owned()]
        }
    );
    assert_eq!(by_id("GPU-aaaa").holders, vec![Sharing::Exclusive]);
    assert_eq!(by_id("GPU-bbbb").facts.state, DeviceState::Offered);
    assert!(by_id("GPU-bbbb").holders.is_empty());
    assert_eq!(
        by_id("GPU-cccc").facts.state,
        DeviceState::Withheld,
        "another's compute process runs there"
    );

    let resources = ResourceRequest {
        cpu_threads: 0,
        memory_mib: 1_024,
        disk_mib: 0,
        devices: vec![gpu_claim()],
        maximum_secs: 60,
    };
    let placement = resources
        .place_devices(&held)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        placement.devices,
        vec![DeviceLease {
            claim: 0,
            device_id: "GPU-bbbb".to_owned(),
            sharing: Sharing::Exclusive,
        }]
    );
    assert_eq!(
        placement.host_memory_mib, 1_024,
        "a GPU with its own memory adds none"
    );
    let second = slots.lease(&pinned("second", &placement.devices[0].device_id), T0)?;
    assert_eq!(second.grant().device.device_id, "GPU-bbbb");

    let two = ResourceRequest {
        devices: vec![DeviceClaim {
            count: 2,
            ..gpu_claim()
        }],
        ..resources
    };
    assert_eq!(
        two.place_devices(&slots.held_devices(T0)?),
        Err(DevicePlacementError::DeviceBusy { claim: 0 }),
        "each GPU is held or busy now, so a wait may clear it"
    );

    slots.set_paused(Some("maintenance".to_owned()));
    assert_eq!(
        slots.held_devices(T0),
        Err(GpuSlotRefusal::Paused {
            reason: "maintenance".to_owned()
        })
    );
    drop((first, second));
    Ok(())
}
