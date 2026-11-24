#![cfg(oneiron_test_support)]
//! GPU inventory, live slots and selection (machines map, section 9 row 2;
//! Engine 24 Nov 21:24: a device lease beside FloorLease, a disk reserve at
//! booking, a drain guard): each machine records its GPUs by stable device
//! id, model and memory on its `machine.capacity` record; a machine's slot
//! table holds or leases one GPU atomically from a fresh driver reading,
//! refuses a booking whose disk is under its reserve, and rechecks the GPU
//! at launch; a machine whose jobs fail several times in a row takes no new
//! GPU work until a person clears it; the home's selection takes only
//! admitted machines that answer now, and never admits from the hourly
//! record or reroutes an uncertain hold.
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
    GPU_DRAIN_AFTER_FAILURES, GPU_SLOT_HOLD_SECS, GpuAvailability, GpuComputeProcess,
    GpuDeviceLease, GpuDeviceOffer, GpuDeviceProbe, GpuDeviceProcesses, GpuDeviceState,
    GpuDiskReading, GpuJobDisk, GpuJobEnd, GpuNodeCandidate, GpuProbeError, GpuSelectionRefusal,
    GpuSlotHold, GpuSlotPeer, GpuSlotPeerError, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable,
    LocalGpuSlotPeer, MachineGpus, gpu_node_candidates, parse_compute_process_lines,
    parse_device_lines, select_gpu_slot,
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

fn request(key: &str) -> GpuSlotRequest {
    GpuSlotRequest {
        key: key.to_owned(),
        device_id: None,
        model: None,
        min_memory_mib: 0,
        disk_bytes: 0,
    }
}

fn pinned(key: &str, device_id: &str) -> GpuSlotRequest {
    GpuSlotRequest {
        device_id: Some(device_id.to_owned()),
        ..request(key)
    }
}

/// [`select_gpu_slot`] with an assignment that always lands.
fn select(
    candidates: &[GpuNodeCandidate],
    peer: &dyn GpuSlotPeer,
    request: &GpuSlotRequest,
) -> Result<oneiron_server::gpu_execution_node::GpuSlotPlacement, GpuSelectionRefusal> {
    select_gpu_slot(candidates, peer, request, &mut |_, _| Ok(()))
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
fn a_free_offered_gpu_is_held_once_and_the_same_key_gets_the_same_hold() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    assert_eq!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );

    let racers = 8;
    let start = Arc::new(Barrier::new(racers));
    let outcomes: Vec<Result<GpuSlotHold, GpuSlotRefusal>> = (0..racers)
        .map(|n| {
            let slots = Arc::clone(&slots);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                slots.hold(&request(&format!("chunk-{n}")), T0)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|racer| racer.join().unwrap())
        .collect();
    let held: Vec<&GpuSlotHold> = outcomes.iter().filter_map(|o| o.as_ref().ok()).collect();
    assert_eq!(held.len(), 1, "one GPU takes one hold");
    assert!(
        outcomes
            .iter()
            .filter_map(|o| o.as_ref().err())
            .all(|refusal| *refusal == GpuSlotRefusal::NoneFree)
    );
    let hold = held[0].clone();
    assert_eq!(hold.device, rtx4090("GPU-aaaa"));
    assert_eq!(hold.held_at_ms, T0);
    assert_eq!(hold.hold_until_ms, T0 + GPU_SLOT_HOLD_SECS * 1000);

    // The same key again, later, is the same hold.
    assert_eq!(slots.hold(&request(&hold.key), T0 + 5)?, hold);
    assert_eq!(
        state_of(&slots.availability(T0 + 5)?, "GPU-aaaa"),
        GpuDeviceState::Held {
            key: hold.key.clone()
        }
    );
    assert_eq!(
        slots.hold(&pinned("another", "GPU-aaaa"), T0 + 5),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        })
    );

    assert!(slots.release(&hold.key));
    assert!(!slots.release(&hold.key), "a released hold is gone");
    assert_eq!(
        state_of(&slots.availability(T0 + 6)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
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
    let busy = Err(GpuSlotRefusal::Busy {
        device_id: "GPU-aaaa".to_owned(),
        pids: vec![777],
    });
    assert_eq!(slots.hold(&pinned("pinned", "GPU-aaaa"), T0), busy);
    assert_eq!(
        slots.lease(&pinned("pinned", "GPU-aaaa"), T0).map(|_| ()),
        busy.map(|_| ())
    );
    assert_eq!(
        slots.hold(&request("any"), T0)?.device.device_id,
        "GPU-bbbb",
        "an unpinned hold passes the busy GPU over"
    );
    assert_eq!(
        slots.hold(&request("one-more"), T0),
        Err(GpuSlotRefusal::NoneFree)
    );
    Ok(())
}

#[test]
fn a_lease_takes_its_keys_hold_holds_one_gpu_per_key_and_gives_it_back_when_it_drops() -> TestResult
{
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa"), rtx4090("GPU-bbbb")]);
    let slots = table(&probe, offering(&["GPU-aaaa", "GPU-bbbb"]));
    let hold = slots.hold(&request("chunk"), T0)?;
    assert_eq!(hold.device.device_id, "GPU-aaaa");

    // The call under the held key takes the held GPU, whatever it pins.
    let lease = slots.lease(&pinned("chunk", "GPU-bbbb"), T0 + 10)?;
    assert_eq!(lease.hold(), &hold);
    assert_eq!(
        state_of(&slots.availability(T0 + 10)?, "GPU-aaaa"),
        GpuDeviceState::Leased {
            key: "chunk".to_owned()
        }
    );
    assert_eq!(
        slots.lease(&request("chunk"), T0 + 11).map(|_| ()),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        }),
        "one key leases one GPU at a time"
    );
    assert!(
        !slots.release("chunk"),
        "the home's release does not take a leased GPU from its call"
    );
    // A lease never lapses.
    assert_eq!(
        state_of(&slots.availability(T0 + 36_000_000)?, "GPU-aaaa"),
        GpuDeviceState::Leased {
            key: "chunk".to_owned()
        }
    );

    // With no hold, a lease picks as a hold does.
    let fresh = slots.lease(&request("fresh"), T0 + 20)?;
    assert_eq!(fresh.hold().device.device_id, "GPU-bbbb");

    drop(lease);
    drop(fresh);
    let answer = slots.availability(T0 + 30)?;
    assert_eq!(state_of(&answer, "GPU-aaaa"), GpuDeviceState::Free);
    assert_eq!(state_of(&answer, "GPU-bbbb"), GpuDeviceState::Free);
    Ok(())
}

#[test]
fn the_host_leases_a_gpu_through_machine_gpus_as_it_leases_memory() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let gpus: Arc<dyn MachineGpus> = Arc::clone(&slots) as Arc<dyn MachineGpus>;

    let mut lease: Box<dyn GpuDeviceLease> = gpus.try_lease(&request("call"))?;
    assert_eq!(lease.hold().device, rtx4090("GPU-aaaa"));
    assert_eq!(lease.hold().key, "call");
    assert!(matches!(
        gpus.try_lease(&request("other")),
        Err(GpuSlotRefusal::NoneFree)
    ));
    lease.confirm_launch()?;
    assert!(matches!(
        state_of(&slots.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Launched { .. }
    ));
    lease.finish(GpuJobEnd::Succeeded);
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
        slots.hold(&pinned("b", "GPU-bbbb"), T0),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-bbbb".to_owned()
        })
    );
    assert_eq!(
        slots.hold(&pinned("c", "GPU-cccc"), T0),
        Err(GpuSlotRefusal::NotOffered {
            device_id: "GPU-cccc".to_owned()
        })
    );
    assert_eq!(
        slots.hold(&pinned("z", "GPU-zzzz"), T0),
        Err(GpuSlotRefusal::UnknownDevice {
            device_id: "GPU-zzzz".to_owned()
        })
    );
    let mut lease = slots.lease(&request("job"), T0)?;
    assert_eq!(lease.hold().device.device_id, "GPU-aaaa");

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
        slots.hold(&request("next"), T0 + 3_000),
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
fn a_lapsed_hold_frees_the_gpu() -> TestResult {
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let slots = table(&probe, offering(&["GPU-aaaa"]));
    let hold = GPU_SLOT_HOLD_SECS * 1000;

    let first = slots.hold(&request("first"), T0)?;
    assert_eq!(
        slots.hold(&request("second"), T0 + hold - 1),
        Err(GpuSlotRefusal::NoneFree)
    );
    let second = slots.hold(&request("second"), first.hold_until_ms)?;
    assert_eq!(second.device.device_id, "GPU-aaaa");
    assert!(!slots.release("first"), "the lapsed hold is gone");
    assert_eq!(
        slots
            .lease(&request("first"), first.hold_until_ms)
            .map(|_| ()),
        Err(GpuSlotRefusal::NoneFree),
        "a call whose hold lapsed is admitted afresh, and the GPU is taken"
    );
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
        slots.hold(&sized("too-big", 91 * GIB), T0),
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

    // A hold checks the room and claims nothing, so a hold that lapses
    // holds no disk; the lease that runs the job claims its own bytes.
    let held = slots.hold(&sized("first", 60 * GIB), T0)?;
    assert_eq!(*disk.claimed.lock().unwrap(), 0);
    let first = slots.lease(&sized(&held.key, 60 * GIB), T0)?;
    assert_eq!(first.hold(), &held);
    assert_eq!(*disk.claimed.lock().unwrap(), 60 * GIB);

    // A lease's claim counts against the next booking until it ends.
    assert_eq!(
        slots.lease(&sized("second", 40 * GIB), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 110 * GIB,
            free_bytes: 100 * GIB,
        })
    );
    assert_eq!(
        slots.hold(&sized("third", 40 * GIB), T0),
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

    // A lease that takes a hold claims its own bytes: too many leave the
    // hold as it was.
    let small = slots.hold(&sized("small", 0), T0)?;
    let other = slots.lease(&sized("other", 45 * GIB), T0)?;
    assert_eq!(
        slots.lease(&sized(&small.key, 50 * GIB), T0).map(|_| ()),
        Err(GpuSlotRefusal::DiskUnderReserve {
            needed_bytes: 105 * GIB,
            free_bytes: 100 * GIB,
        })
    );
    assert_eq!(
        state_of(&slots.availability(T0)?, &small.device.device_id),
        GpuDeviceState::Held {
            key: small.key.clone()
        }
    );
    drop(other);
    assert!(slots.release(&small.key));

    // A disk already under its reserve takes no booking, even of 0 bytes.
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
        full.hold(&request("zero"), T0),
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
    let run = |key: &str, end: GpuJobEnd| -> TestResult {
        slots.lease(&request(key), T0)?.finish(end);
        Ok(())
    };
    let failed = |why: &str| GpuJobEnd::Failed {
        reason: why.to_owned(),
    };

    // Two failures, a success, two more and a cancel: never three in a row.
    run("1", failed("exit 1"))?;
    run("2", failed("exit 1"))?;
    run("3", GpuJobEnd::Succeeded)?;
    run("4", failed("exit 1"))?;
    run("5", failed("exit 1"))?;
    run("6", GpuJobEnd::Cancelled)?;
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
    assert_eq!(
        slots.hold(&request("new"), T0),
        Err(GpuSlotRefusal::Drained {
            reason: drained.clone()
        })
    );
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
    restarted.hold(&request("after"), T0)?;

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
            .finish(GpuJobEnd::Failed {
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
        slots.hold(&request("other"), T0 + 1),
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
        select(&candidates, &local, &request("chunk")),
        Err(GpuSelectionRefusal::NoneFree),
        "the machine answered, so it is live, and it offers nothing"
    );
    Ok(())
}

/// The vault's machines as the home reaches them: each a real slot table on
/// a fake driver, some unreachable, some whose holds are refused or lost.
/// It records every call.
#[derive(Default)]
struct FakePeers {
    tables: BTreeMap<EntityId, Arc<GpuSlotTable>>,
    unreachable: BTreeSet<EntityId>,
    refuse_hold: BTreeSet<EntityId>,
    lose_hold_answer: BTreeSet<EntityId>,
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
            .map_err(|probe| {
                GpuSlotRefusal::Unmeasured {
                    reason: probe.to_string(),
                }
                .into()
            })
    }

    fn hold(
        &self,
        machine: EntityId,
        request: &GpuSlotRequest,
    ) -> Result<GpuSlotHold, GpuSlotPeerError> {
        let table = self.reach(machine, "hold")?;
        if self.refuse_hold.contains(&machine) {
            return Err(GpuSlotRefusal::Taken {
                device_id: request.device_id.clone().unwrap_or_default(),
            }
            .into());
        }
        let hold = table.hold(request, T0)?;
        if self.lose_hold_answer.contains(&machine) {
            return Err(GpuSlotPeerError::Uncertain {
                reason: "the answer did not arrive in time".to_owned(),
            });
        }
        Ok(hold)
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

    let placement = select(&candidates, &peers, &twenty_gib("chunk-1"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, roomy, "the smallest free card that fits");
    assert_eq!(placement.hold.device.device_id, "GPU-roomy");
    assert_eq!(
        peers.asked("availability"),
        vec![busy, roomy, large, gone],
        "a machine whose record lists no matching GPU is never asked"
    );
    assert_eq!(peers.asked("hold"), vec![roomy]);

    let next = select(&candidates, &peers, &twenty_gib("chunk-2"))
        .map_err(|refusal| refusal.to_string())?;
    assert_eq!(next.machine, large, "the held 4090 is no longer free");
    assert_eq!(
        select(&candidates, &peers, &twenty_gib("chunk-3")),
        Err(GpuSelectionRefusal::NoneFree)
    );

    // Pinned by model: only machines recording that model are asked.
    let a4000 = GpuSlotRequest {
        model: Some(A4000.to_owned()),
        ..request("chunk-4")
    };
    assert_eq!(
        select(&candidates, &peers, &a4000)
            .map_err(|refusal| refusal.to_string())?
            .machine,
        small
    );

    // No admitted machine records a match; none of the matches answers.
    assert_eq!(
        select(
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
        select(&candidates[4..], &peers, &request("chunk-6")),
        Err(GpuSelectionRefusal::NoneLive)
    );
    assert_eq!(
        select(&[], &peers, &request("chunk-7")),
        Err(GpuSelectionRefusal::NoCandidate)
    );
    Ok(())
}

#[test]
fn a_refused_hold_moves_to_the_next_fit_and_an_uncertain_one_is_never_rerouted() -> TestResult {
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
    // hold: the next fit is tried.
    peers.refuse_hold.insert(first);
    let placement =
        select(&candidates, &peers, &request("raced")).map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, second);
    assert_eq!(peers.asked("hold"), vec![first, second]);
    peers.release(second, "raced")?;

    // `first` took the hold but its answer was lost: the selection stops
    // there and names it, and `second` is never asked to hold.
    peers.refuse_hold.clear();
    peers.lose_hold_answer.insert(first);
    peers.asked.lock().unwrap().clear();
    let refusal = select(&candidates, &peers, &request("lost")).unwrap_err();
    assert!(
        matches!(&refusal, GpuSelectionRefusal::Uncertain { machine, .. } if *machine == first),
        "{refusal}"
    );
    assert_eq!(peers.asked("hold"), vec![first]);

    // A retry under the same key sees the key on `first` and asks only
    // `first` again, even while its answers are still lost, though `second`
    // is free.
    peers.asked.lock().unwrap().clear();
    let refusal = select(&candidates, &peers, &request("lost")).unwrap_err();
    assert!(
        matches!(&refusal, GpuSelectionRefusal::Uncertain { machine, .. } if *machine == first),
        "{refusal}"
    );
    peers.lose_hold_answer.clear();
    let placement =
        select(&candidates, &peers, &request("lost")).map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, first);
    assert_eq!(placement.hold.device.device_id, "GPU-first");
    assert_eq!(peers.asked("hold"), vec![first, first]);

    // A twin call for a key that is already held is answered there too.
    let twin =
        select(&candidates, &peers, &request("lost")).map_err(|refusal| refusal.to_string())?;
    assert_eq!(twin, placement);
    Ok(())
}

#[test]
fn the_devices_section_offers_listed_gpus_and_none_by_default() -> TestResult {
    use oneiron_server::test_doors::gpu_backend::gpu_jobs_section;

    assert_eq!(gpu_jobs_section("")?.devices, GpuDeviceOffer::default());
    let default = GpuDeviceOffer::default();
    assert!(default.offered.is_empty(), "no GPU is offered by default");
    assert_eq!(default.hold_secs, GPU_SLOT_HOLD_SECS);
    assert_eq!(default.drain_after_failures, GPU_DRAIN_AFTER_FAILURES);
    assert_eq!(default.drain_file, None);

    let dir = tempfile::tempdir()?;
    let drain_file = dir.path().join("gpu-drained");
    let owner_lock_dir = dir.path().join("gpu-owners");
    let devices = gpu_jobs_section(&format!(
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-bbbb\"]\nwithheld_file = \"/var/lib/oneiron/gpu-withheld\"\nhold_secs = 30\ndrain_after_failures = 5\ndrain_file = {:?}\nowner_lock_dir = {:?}\n",
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
            hold_secs: 30,
            drain_after_failures: 5,
            drain_file: Some(drain_file),
            owner_lock_dir: Some(owner_lock_dir),
        }
    );
    assert_eq!(
        gpu_jobs_section("[devices]\noffered = [\"GPU-aaaa\"]\n")?
            .devices
            .owner_lock_dir,
        Some(std::env::temp_dir().join("oneiron-gpu-owners")),
        "an offering server takes owner locks by default"
    );

    for refused in [
        "[devices]\noffered = [\"GPU-aaaa\", \"GPU-aaaa\"]\n",
        "[devices]\noffered = [\"GPU aaaa\"]\n",
        "[devices]\noffered = [\"\"]\n",
        "[devices]\nwithheld_file = \"relative/gpu-withheld\"\n",
        "[devices]\ndrain_file = \"relative/gpu-drained\"\n",
        "[devices]\ndrain_file = \"/no/such/directory/gpu-drained\"\n",
        "[devices]\nowner_lock_dir = \"relative/gpu-owners\"\n",
        "[devices]\nhold_secs = 0\n",
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
        slots.hold(&request("other"), T0),
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
    assert_eq!(again.hold(), &kept);
    assert!(
        !slots.finish("job", &GpuJobEnd::Succeeded),
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
    let reattached = restarted.reattach("job", "GPU-aaaa", T0)?;
    assert_eq!(reattached.device, rtx4090("GPU-aaaa"));
    assert_eq!(restarted.reattach("job", "GPU-aaaa", T0 + 1)?, reattached);
    assert_eq!(
        restarted.reattach("twin", "GPU-aaaa", T0),
        Err(GpuSlotRefusal::Taken {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    assert_eq!(
        restarted.reattach("lost", "GPU-zzzz", T0),
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
        &GpuJobEnd::Failed {
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
            .finish(GpuJobEnd::Failed {
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
        select(&candidates, &peers, &fifty_gib).map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, roomy);
    assert_eq!(
        peers.asked("hold"),
        vec![roomy],
        "neither the full nor the drained machine is asked to hold"
    );
    Ok(())
}

#[test]
fn the_assignment_is_written_before_each_hold_and_a_failed_one_stops_the_selection() -> TestResult {
    let (first, second) = (machine(1), machine(2));
    let (peers, _) = FakePeers::default().machine(first, vec![gpu("GPU-first", A4000, A4000_MIB)]);
    let (mut peers, _) = peers.machine(second, vec![rtx4090("GPU-second")]);
    peers.refuse_hold.insert(first);
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

    let mut written: Vec<(EntityId, Option<String>)> = Vec::new();
    let placement = select_gpu_slot(
        &candidates,
        &peers,
        &request("chunk"),
        &mut |machine, sent| {
            written.push((machine, sent.device_id.clone()));
            Ok(())
        },
    )
    .map_err(|refusal| refusal.to_string())?;
    assert_eq!(placement.machine, second);
    assert_eq!(
        written,
        vec![
            (first, Some("GPU-first".to_owned())),
            (second, Some("GPU-second".to_owned())),
        ],
        "each hold is preceded by its assignment, the refused one too"
    );

    peers.asked.lock().unwrap().clear();
    let refusal = select_gpu_slot(&candidates, &peers, &request("other"), &mut |_, _| {
        Err("the vault refused the write".to_owned())
    })
    .unwrap_err();
    assert_eq!(
        refusal,
        GpuSelectionRefusal::AssignmentFailed {
            machine: first,
            reason: "the vault refused the write".to_owned(),
        }
    );
    assert_eq!(
        peers.asked("hold"),
        Vec::new(),
        "no machine is asked without its assignment"
    );
    Ok(())
}

#[test]
fn an_offered_gpu_that_a_model_worker_runs_on_is_refused() -> TestResult {
    use oneiron_server::config::gpu_jobs::refuse_worker_device_overlap;

    let offered: BTreeSet<String> = ["GPU-aaaa".to_owned()].into_iter().collect();
    refuse_worker_device_overlap(&offered, [("chat", "GPU-bbbb")])?;
    refuse_worker_device_overlap(&BTreeSet::new(), [("chat", "0")])?;
    let overlap = refuse_worker_device_overlap(&offered, [("chat", "GPU-bbbb, GPU-aaaa")])
        .expect_err("a worker on an offered GPU is refused");
    assert!(overlap.to_string().contains("chat"), "{overlap}");
    let by_index = refuse_worker_device_overlap(&offered, [("voice", "0")])
        .expect_err("an index cannot be told apart from an offered GPU");
    assert!(by_index.to_string().contains("by index"), "{by_index}");
    Ok(())
}

#[test]
fn two_servers_on_one_machine_never_offer_the_same_gpu() -> TestResult {
    let dir = tempfile::tempdir()?;
    let probe = FakeProbe::with(vec![rtx4090("GPU-aaaa")]);
    let offer = GpuDeviceOffer {
        owner_lock_dir: Some(dir.path().join("owners")),
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
        second.hold(&request("b"), T0),
        Err(GpuSlotRefusal::NoneFree)
    );
    assert_eq!(
        second.hold(&pinned("b", "GPU-aaaa"), T0),
        Err(GpuSlotRefusal::Withheld {
            device_id: "GPU-aaaa".to_owned()
        })
    );
    first.hold(&request("a"), T0)?;

    // The first server stops: the second owns the GPU at its next reading.
    drop(first);
    assert_eq!(
        state_of(&second.availability(T0)?, "GPU-aaaa"),
        GpuDeviceState::Free
    );
    second.hold(&request("b"), T0)?;
    Ok(())
}
