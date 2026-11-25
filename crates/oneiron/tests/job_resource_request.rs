//! The general resource request (pass 34 row G1, `34-compute-general/DESIGN.md`
//! sections 2.1, 2.2 and 10): a run asks for threads, memory, disk and zero or
//! more device claims; a device is matched by kind, features and memory,
//! never by a vendor name; on unified memory the host request and the device
//! claim are one pool, and a pool with no value in MiB is refused; every
//! holder of a device counts; a device id that a report repeats is never
//! leased; and a launch scope reports each bound as kernel, supervised or
//! none.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test
//! job_resource_request`.

use oneiron::job_workload::{
    BoundReport, BoundRequirement, BoundStrength, DeviceClaim, DeviceClosure, DeviceFacts,
    DeviceIdSource, DeviceKind, DeviceMemory, DevicePlacementError, DeviceState, HeldDevice,
    ResourceRequest, ScopeBound, ScopeCapabilities, Sharing,
};

const HOST_MIB: u64 = 8_192;
const DEVICE_MIB: u64 = 16_384;

fn request(devices: Vec<DeviceClaim>) -> ResourceRequest {
    ResourceRequest {
        cpu_threads: 4,
        memory_mib: HOST_MIB,
        disk_mib: 2_048,
        devices,
        maximum_secs: 1_800,
    }
}

fn claim(kind: DeviceKind, memory_mib: u64, features: &[&str], sharing: Sharing) -> DeviceClaim {
    DeviceClaim {
        kind,
        count: 1,
        memory_mib,
        features: features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        sharing,
    }
}

fn gpu_claim(features: &[&str]) -> DeviceClaim {
    claim(DeviceKind::Gpu, DEVICE_MIB, features, Sharing::Exclusive)
}

fn device(id: &str, kind: DeviceKind, memory: DeviceMemory, features: &[&str]) -> DeviceFacts {
    DeviceFacts {
        id: id.to_owned(),
        id_source: DeviceIdSource::VendorUuid,
        kind,
        vendor: "vendor-a".to_owned(),
        model: "model-a".to_owned(),
        memory,
        features: features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        closure: DeviceClosure::Closed,
        state: DeviceState::Offered,
        max_claimants: 1,
    }
}

fn free(facts: DeviceFacts) -> HeldDevice {
    HeldDevice {
        facts,
        holders: Vec::new(),
    }
}

fn held(mut facts: DeviceFacts, holders: Vec<Sharing>) -> HeldDevice {
    facts.state = DeviceState::Leased {
        keys: (0..holders.len()).map(|at| format!("key-{at}")).collect(),
    };
    HeldDevice { facts, holders }
}

fn dedicated_gpu(id: &str, features: &[&str]) -> DeviceFacts {
    device(
        id,
        DeviceKind::Gpu,
        DeviceMemory::Dedicated { mib: 24_576 },
        features,
    )
}

fn report(strength: BoundStrength) -> BoundReport {
    BoundReport {
        strength,
        evidence: "probed".to_owned(),
    }
}

/// A scope that enforces every bound at `strength`.
fn capabilities(strength: BoundStrength) -> ScopeCapabilities {
    ScopeCapabilities {
        tree_kill: report(strength),
        cutoff_without_engine: report(strength),
        emptiness: report(strength),
        memory_cap: report(strength),
        cpu_cap: report(strength),
        file_wall: report(strength),
        network_closed: report(strength),
        device_closure: report(strength),
        processes_hidden: report(strength),
        write_rate_cap: report(strength),
    }
}

fn requirement(text: &str) -> BoundRequirement {
    text.parse().expect("a known bound")
}

#[test]
fn a_request_with_no_device_claim_takes_no_device_lease() {
    let cpu_only = request(Vec::new());
    let busy_gpu = held(dedicated_gpu("gpu-0", &["cuda"]), vec![Sharing::Exclusive]);
    for machine in [Vec::new(), vec![busy_gpu]] {
        let placement = cpu_only
            .place_devices(&machine)
            .expect("a CPU-only run fits a machine whatever its devices do");
        assert!(placement.devices.is_empty(), "no device lease");
        assert_eq!(placement.host_memory_mib, HOST_MIB, "only its own memory");
    }
    // The wire form the code-mode sketch writes (section 14): no device claim.
    let decoded: ResourceRequest = serde_json::from_value(serde_json::json!({
        "cpu_threads": 1, "memory_mib": 512, "disk_mib": 64, "maximum_secs": 300, "devices": [],
    }))
    .expect("a CPU-only request decodes");
    assert!(decoded.devices.is_empty());
    assert!(
        serde_json::from_value::<ResourceRequest>(serde_json::json!({
            "gpus": 1, "vram_mib": 22_528, "memory_mib": 512, "disk_mib": 64, "maximum_secs": 300,
        }))
        .is_err(),
        "the GPU-only shape is gone",
    );
}

#[test]
fn a_device_claim_is_matched_by_kind_features_and_memory() {
    let wanted = gpu_claim(&["cuda"]);
    assert!(wanted.is_met_by(&dedicated_gpu("gpu-0", &["cuda", "vulkan"])));
    assert!(
        !wanted.is_met_by(&device(
            "npu-0",
            DeviceKind::Npu,
            DeviceMemory::Dedicated { mib: 24_576 },
            &["cuda"]
        )),
        "another kind"
    );
    assert!(
        !wanted.is_met_by(&dedicated_gpu("gpu-1", &["metal"])),
        "a missing feature"
    );
    assert!(
        !wanted.is_met_by(&device(
            "gpu-2",
            DeviceKind::Gpu,
            DeviceMemory::Dedicated { mib: 8_192 },
            &["cuda"]
        )),
        "too little memory"
    );
    // Vendor and model are never read: two devices that differ only there
    // match alike.
    let mut other_vendor = dedicated_gpu("gpu-3", &["cuda"]);
    other_vendor.vendor = "vendor-b".to_owned();
    other_vendor.model = "model-b".to_owned();
    assert!(wanted.is_met_by(&other_vendor));
    // A kind of its own name, matched by that name.
    let tpu = claim(
        DeviceKind::Other("tpu".to_owned()),
        0,
        &[],
        Sharing::Exclusive,
    );
    assert!(tpu.is_met_by(&device(
        "tpu-0",
        DeviceKind::Other("tpu".to_owned()),
        DeviceMemory::Dedicated { mib: 1 },
        &[]
    )));
    assert!(!tpu.is_met_by(&device(
        "fpga-0",
        DeviceKind::Fpga,
        DeviceMemory::Dedicated { mib: 1 },
        &[]
    )));

    let placement = request(vec![wanted.clone()])
        .place_devices(&[
            free(dedicated_gpu("gpu-1", &["metal"])),
            free(dedicated_gpu("gpu-0", &["cuda"])),
        ])
        .expect("the cuda device takes the claim");
    assert_eq!(placement.devices.len(), 1);
    assert_eq!(placement.devices[0].device_id, "gpu-0");
    assert_eq!(
        request(vec![wanted]).place_devices(&[free(dedicated_gpu("gpu-1", &["metal"]))]),
        Err(DevicePlacementError::NoDevice {
            claim: 0,
            kind: DeviceKind::Gpu,
            features: vec!["cuda".to_owned()],
        }),
        "no device of the machine can ever serve it",
    );
}

#[test]
fn on_unified_memory_the_host_request_and_the_device_claim_are_leased_as_their_sum() {
    let unified = device(
        "soc-gpu",
        DeviceKind::Gpu,
        DeviceMemory::Unified { mib: 65_536 },
        &["metal"],
    );
    let placement = request(vec![gpu_claim(&["metal"])])
        .place_devices(&[free(unified)])
        .expect("the unified device takes the claim");
    assert_eq!(
        placement.host_memory_mib,
        HOST_MIB + DEVICE_MIB,
        "one pool: both are leased from it"
    );

    let placement = request(vec![gpu_claim(&["cuda"])])
        .place_devices(&[free(dedicated_gpu("gpu-0", &["cuda"]))])
        .expect("the dedicated device takes the claim");
    assert_eq!(
        placement.host_memory_mib, HOST_MIB,
        "the device's own memory is not the host's"
    );
}

/// Review round 1 of #10431: the sum was saturated, so a request for
/// `u64::MAX` MiB with a 1 MiB claim on a unified device was placed with
/// `u64::MAX` MiB, one MiB short of what it asked.
#[test]
fn a_unified_pool_with_no_value_in_mib_is_refused_not_saturated() {
    let unified = device(
        "soc-gpu",
        DeviceKind::Gpu,
        DeviceMemory::Unified { mib: 65_536 },
        &["metal"],
    );
    let mut whole_range = request(vec![claim(
        DeviceKind::Gpu,
        1,
        &["metal"],
        Sharing::Exclusive,
    )]);
    whole_range.memory_mib = u64::MAX;
    assert_eq!(
        whole_range.place_devices(&[free(unified)]),
        Err(DevicePlacementError::HostMemoryOverflow { claim: 0 }),
        "u64::MAX MiB plus 1 MiB is no amount a machine can lease",
    );
}

#[test]
fn an_exclusive_and_a_shared_claim_never_hold_one_device_together() {
    let mut sharing_gpu = dedicated_gpu("gpu-0", &["cuda"]);
    sharing_gpu.closure = DeviceClosure::Admitted;
    sharing_gpu.max_claimants = 3;
    let exclusive = request(vec![gpu_claim(&["cuda"])]);
    let shared = request(vec![claim(
        DeviceKind::Gpu,
        DEVICE_MIB,
        &["cuda"],
        Sharing::Shared,
    )]);
    let busy = Err(DevicePlacementError::DeviceBusy { claim: 0 });

    assert_eq!(
        exclusive.place_devices(&[held(sharing_gpu.clone(), vec![Sharing::Shared])]),
        busy,
        "an exclusive claim takes only a device with no holder"
    );
    assert_eq!(
        shared.place_devices(&[held(sharing_gpu.clone(), vec![Sharing::Exclusive])]),
        busy,
        "a shared claim never joins an exclusive holder"
    );
    assert!(
        shared
            .place_devices(&[held(
                sharing_gpu.clone(),
                vec![Sharing::Shared, Sharing::Shared]
            )])
            .is_ok(),
        "fewer holders than max_claimants"
    );
    assert_eq!(
        shared.place_devices(&[held(sharing_gpu.clone(), vec![Sharing::Shared; 3])]),
        busy,
        "every holder counts"
    );
    assert!(exclusive.place_devices(&[free(sharing_gpu)]).is_ok());
    // A device that does not share (max_claimants 1) takes one claim of
    // either kind.
    assert_eq!(
        shared.place_devices(&[held(
            dedicated_gpu("gpu-1", &["cuda"]),
            vec![Sharing::Shared]
        )]),
        busy
    );
}

#[test]
fn two_claims_are_placed_so_that_each_gets_a_device_that_meets_it() {
    // The first claim could take either device; the second only the first.
    let any_gpu = claim(DeviceKind::Gpu, 0, &[], Sharing::Exclusive);
    let cuda_gpu = gpu_claim(&["cuda"]);
    let machine = [
        free(dedicated_gpu("gpu-cuda", &["cuda"])),
        free(dedicated_gpu("gpu-plain", &[])),
    ];
    let placement = request(vec![any_gpu, cuda_gpu])
        .place_devices(&machine)
        .expect("both claims fit together");
    let by_claim: Vec<(usize, &str)> = placement
        .devices
        .iter()
        .map(|lease| (lease.claim, lease.device_id.as_str()))
        .collect();
    assert_eq!(by_claim, vec![(0, "gpu-plain"), (1, "gpu-cuda")]);
    // Busy is only what waiting clears: a held device that meets the claim.
    let one_cuda = request(vec![gpu_claim(&["cuda"])]);
    assert_eq!(
        one_cuda.place_devices(&[held(
            dedicated_gpu("gpu-cuda", &["cuda"]),
            vec![Sharing::Exclusive]
        )]),
        Err(DevicePlacementError::DeviceBusy { claim: 0 }),
    );
    let mut quarantined = dedicated_gpu("gpu-cuda", &["cuda"]);
    quarantined.state = DeviceState::Quarantined {
        why: "probe failed".to_owned(),
    };
    assert_eq!(
        one_cuda.place_devices(&[free(quarantined)]),
        Err(DevicePlacementError::DeviceBusy { claim: 0 })
    );
}

#[test]
fn a_claim_for_more_devices_than_the_machine_has_is_no_device() {
    let mut many = gpu_claim(&["cuda"]);
    many.count = u32::MAX;
    assert!(matches!(
        request(vec![many]).place_devices(&[free(dedicated_gpu("gpu-0", &["cuda"]))]),
        Err(DevicePlacementError::NoDevice { claim: 0, .. }),
    ));
}

/// FIX G1-PLACEMENT-DUPLICATE-DEVICE-ID (review round 1 of #10431):
/// placement matched report rows, not device ids, so two rows of one id were
/// leased twice in one placement, and the free row of an id was leased while
/// a key held the id on its other row.
#[test]
fn a_device_id_on_two_rows_of_a_report_is_never_leased() {
    let mut two = gpu_claim(&["cuda"]);
    two.count = 2;
    let one_device_twice = [
        free(dedicated_gpu("gpu-0", &["cuda"])),
        free(dedicated_gpu("gpu-0", &["cuda"])),
    ];
    assert!(
        matches!(
            request(vec![two]).place_devices(&one_device_twice),
            Err(DevicePlacementError::NoDevice { claim: 0, .. }),
        ),
        "one device under two rows is not two devices",
    );

    let held_and_free = [
        held(dedicated_gpu("gpu-0", &["cuda"]), vec![Sharing::Exclusive]),
        free(dedicated_gpu("gpu-0", &["cuda"])),
    ];
    assert!(
        matches!(
            request(vec![gpu_claim(&["cuda"])]).place_devices(&held_and_free),
            Err(DevicePlacementError::NoDevice { claim: 0, .. }),
        ),
        "a key holds gpu-0 on one row: its other row is not a free device",
    );
}

#[test]
fn a_repeated_id_is_skipped_and_a_device_whose_id_is_its_own_is_leased() {
    let placement = request(vec![gpu_claim(&["cuda"])])
        .place_devices(&[
            free(dedicated_gpu("gpu-0", &["cuda"])),
            free(dedicated_gpu("gpu-0", &["cuda"])),
            free(dedicated_gpu("gpu-1", &["cuda"])),
        ])
        .expect("gpu-1 takes the claim");
    let leased: Vec<&str> = placement
        .devices
        .iter()
        .map(|lease| lease.device_id.as_str())
        .collect();
    assert_eq!(leased, vec!["gpu-1"]);
}

#[test]
fn a_scope_without_tree_kill_cutoff_or_emptiness_misses_the_minimum_contract() {
    assert!(capabilities(BoundStrength::Kernel).meets_minimum_contract());
    assert!(
        capabilities(BoundStrength::Supervised {
            worst_lateness_ms: 2_000
        })
        .meets_minimum_contract()
    );
    for bound in ScopeBound::MINIMUM_CONTRACT {
        let mut scope = capabilities(BoundStrength::Kernel);
        let lacking = match bound {
            ScopeBound::TreeKill => &mut scope.tree_kill,
            ScopeBound::CutoffWithoutEngine => &mut scope.cutoff_without_engine,
            _ => &mut scope.emptiness,
        };
        lacking.strength = BoundStrength::None;
        assert!(!scope.meets_minimum_contract(), "{bound:?} is not optional");
    }
    // Every other bound may be absent.
    let mut minimal = capabilities(BoundStrength::None);
    minimal.tree_kill = report(BoundStrength::Kernel);
    minimal.cutoff_without_engine = report(BoundStrength::Supervised {
        worst_lateness_ms: 2_000,
    });
    minimal.emptiness = report(BoundStrength::Kernel);
    assert!(minimal.meets_minimum_contract());
}

#[test]
fn a_required_bound_the_scope_lacks_is_missing_and_an_unrequired_one_is_unproven() {
    // A scope that walls files and closes the network in the kernel, caps
    // memory under a supervisor, and cannot cap CPU or close the device.
    let mut scope = capabilities(BoundStrength::Kernel);
    scope.memory_cap = report(BoundStrength::Supervised {
        worst_lateness_ms: 2_000,
    });
    scope.cpu_cap = report(BoundStrength::None);
    scope.device_closure = report(BoundStrength::None);

    let template_default = [requirement("file_wall"), requirement("network_closed")];
    assert!(
        scope.missing(&template_default).is_empty(),
        "the default list fits"
    );
    assert_eq!(
        scope.unproven(&template_default),
        vec![ScopeBound::CpuCap, ScopeBound::DeviceClosure]
    );

    let sealed = [
        requirement("file_wall"),
        requirement("network_closed"),
        requirement("device_closure"),
        requirement("memory_cap:kernel"),
    ];
    assert_eq!(
        scope.missing(&sealed),
        vec![
            requirement("device_closure"),
            requirement("memory_cap:kernel")
        ]
    );
    assert_eq!(
        scope.unproven(&sealed),
        vec![ScopeBound::CpuCap],
        "a required bound is missing, never unproven"
    );
    assert!(
        scope.missing(&[requirement("memory_cap")]).is_empty(),
        "a supervised cap meets a requirement without :kernel"
    );

    // The require list's text form, as a template states it.
    let decoded: Vec<BoundRequirement> =
        serde_json::from_value(serde_json::json!(["file_wall", "memory_cap:kernel"]))
            .expect("names decode");
    assert_eq!(
        decoded,
        vec![
            BoundRequirement {
                bound: ScopeBound::FileWall,
                kernel: false
            },
            BoundRequirement {
                bound: ScopeBound::MemoryCap,
                kernel: true
            }
        ]
    );
    assert_eq!(
        serde_json::to_value(&decoded).expect("encode"),
        serde_json::json!(["file_wall", "memory_cap:kernel"])
    );
    assert!(
        serde_json::from_value::<BoundRequirement>(serde_json::json!("gpu_fence")).is_err(),
        "an unknown bound is refused"
    );
}
