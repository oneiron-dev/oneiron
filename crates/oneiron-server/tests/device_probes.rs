//! Device probes for AMD, Intel and Apple GPUs (pass 34 row S5): each
//! reports its devices as `DeviceFacts` by kind, features and memory, read
//! from fixtures of its tool's or driver's output (no hardware needed), and
//! placement matches the reports by kind, features and memory alone, never
//! by vendor or model.
//!
//! Fixtures: `kfd_properties_*.txt` are KFD topology files read on an AMD
//! Radeon 780M APU (PCI 1002:1900, gfx1103) on Linux; the amdgpu sysfs
//! values beside them are that machine's. `system_profiler_m4_max.json` is
//! `system_profiler -json SPDisplaysDataType SPHardwareDataType` from an
//! M4 Max Mac, with its serial, platform UUID and provisioning id replaced.
//! The `xpu_smi_*.json` fixtures follow xpumanager's own output (cited in
//! each test). Placement tests also use NVIDIA's probe facts.

#![cfg(unix)]

use oneiron::job_workload::{
    DeviceClaim, DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory,
    DevicePlacementError, DeviceState, HeldDevice, ResourceRequest, Sharing,
};
use oneiron_server::gpu_execution_node::device_probes::{
    AmdgpuSysfsProbe, ComputeProcesses, DeviceProbe, SystemProfilerProbe, XpuSmiProbe,
    parse_system_profiler_devices,
};
use oneiron_server::gpu_execution_node::{
    GpuComputeProcess, GpuDevice, GpuProbeError, NvidiaSmiProbe,
};

const APU_PROPERTIES: &str = include_str!("fixtures/device_probes/kfd_properties_gfx1103_apu.txt");
const CPU_PROPERTIES: &str = include_str!("fixtures/device_probes/kfd_properties_cpu.txt");
const M4_MAX: &str = include_str!("fixtures/device_probes/system_profiler_m4_max.json");

/// The APU's PCI address and KFD id on the machine the fixtures come from.
const APU_SLOT: &str = "0000:c4:00.0";
const APU_KFD_ID: u32 = 50809;
/// Its GTT total, the host memory the driver lets it map, in bytes.
const APU_GTT_BYTES: u64 = 16_462_188_544;

const HOST_MIB: u64 = 4_096;

// ---------------------------------------------------------------------------
// A sysfs tree in a temporary directory.

struct SysfsTree {
    dir: tempfile::TempDir,
}

impl SysfsTree {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn probe(&self) -> AmdgpuSysfsProbe {
        AmdgpuSysfsProbe {
            drm_root: self.dir.path().join("class/drm"),
            kfd_root: self.dir.path().join("class/kfd/kfd"),
        }
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.dir.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, text).expect("write");
    }

    /// A DRM card on `slot` with `driver` bound and these attribute files.
    fn card(
        &self,
        card: &str,
        slot: &str,
        vendor: &str,
        driver: &str,
        attributes: &[(&str, &str)],
    ) {
        let device = format!("devices/pci/{slot}");
        self.write(&format!("{device}/vendor"), &format!("{vendor}\n"));
        self.write(
            &format!("{device}/uevent"),
            &format!("DRIVER={driver}\nPCI_CLASS=30000\nPCI_SLOT_NAME={slot}\n"),
        );
        for (name, value) in attributes {
            self.write(&format!("{device}/{name}"), &format!("{value}\n"));
        }
        let drivers = self.dir.path().join("bus/pci/drivers").join(driver);
        std::fs::create_dir_all(&drivers).expect("driver dir");
        std::os::unix::fs::symlink(&drivers, self.dir.path().join(&device).join("driver"))
            .expect("driver link");
        let class = self.dir.path().join("class/drm").join(card);
        std::fs::create_dir_all(&class).expect("card dir");
        std::os::unix::fs::symlink(self.dir.path().join(&device), class.join("device"))
            .expect("device link");
        // A connector of the card, which is not a device.
        std::fs::create_dir_all(
            self.dir
                .path()
                .join("class/drm")
                .join(format!("{card}-DP-1")),
        )
        .expect("connector dir");
    }

    /// The APU of the fixture machine, as amdgpu wrote it there.
    fn fixture_apu(&self) {
        self.card(
            "card0",
            APU_SLOT,
            "0x1002",
            "amdgpu",
            &[
                ("device", "0x1900"),
                ("unique_id", ""),
                ("mem_info_vram_total", "536870912"),
                ("mem_info_gtt_total", &APU_GTT_BYTES.to_string()),
            ],
        );
    }

    fn kfd_node(&self, node: u32, gpu_id: u32, properties: &str) {
        self.write(
            &format!("class/kfd/kfd/topology/nodes/{node}/gpu_id"),
            &format!("{gpu_id}\n"),
        );
        self.write(
            &format!("class/kfd/kfd/topology/nodes/{node}/properties"),
            properties,
        );
    }

    /// The fixture machine's KFD topology: its CPU node and the APU's node.
    fn fixture_kfd(&self) {
        self.kfd_node(0, 0, CPU_PROPERTIES);
        self.kfd_node(1, APU_KFD_ID, APU_PROPERTIES);
        std::fs::create_dir_all(self.dir.path().join("class/kfd/kfd/proc")).expect("proc dir");
    }

    /// A process with a compute context on each of `gpu_ids`.
    fn kfd_process(&self, pid: u32, gpu_ids: &[u32]) {
        self.write(&format!("class/kfd/kfd/proc/{pid}/pasid"), "32770\n");
        for gpu_id in gpu_ids {
            self.write(&format!("class/kfd/kfd/proc/{pid}/vram_{gpu_id}"), "0\n");
            self.write(&format!("class/kfd/kfd/proc/{pid}/sdma_{gpu_id}"), "0\n");
        }
    }
}

/// The APU's properties as a discrete card at `location_id` would write
/// them: its own memory, `local_mem_size` above 0.
fn discrete_properties(location_id: u32, local_mem_size: u64) -> String {
    APU_PROPERTIES
        .lines()
        .map(|line| match line.split_once(' ') {
            Some(("location_id", _)) => format!("location_id {location_id}"),
            Some(("local_mem_size", _)) => format!("local_mem_size {local_mem_size}"),
            _ => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn apu_facts() -> DeviceFacts {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    let mut devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    devices.remove(0)
}

// ---------------------------------------------------------------------------
// AMD through amdgpu sysfs.

#[test]
fn an_amd_apu_with_no_unique_id_is_found_by_its_pci_address_with_unified_memory_and_rocm() {
    assert_eq!(
        apu_facts(),
        DeviceFacts {
            id: format!("pci-{APU_SLOT}"),
            id_source: DeviceIdSource::PlatformRegistry,
            kind: DeviceKind::Gpu,
            vendor: "amd".to_owned(),
            model: "gfx1103".to_owned(),
            memory: DeviceMemory::Unified {
                mib: APU_GTT_BYTES / (1024 * 1024),
            },
            features: vec!["rocm".to_owned()],
            closure: DeviceClosure::Closed,
            state: DeviceState::Offered,
            max_claimants: 1,
        }
    );
}

#[test]
fn a_discrete_amd_card_is_found_by_its_unique_id_with_its_own_memory() {
    let tree = SysfsTree::new();
    tree.fixture_kfd();
    // Bus 0x03, device 0, function 0.
    tree.card(
        "card1",
        "0000:03:00.0",
        "0x1002",
        "amdgpu",
        &[
            ("device", "0x740f"),
            ("unique_id", "52d10e8a52d4b1c3"),
            ("product_name", "AMD Instinct MI210"),
            ("mem_info_vram_total", "68702699520"),
            ("mem_info_gtt_total", "135015096320"),
        ],
    );
    tree.kfd_node(2, 41210, &discrete_properties(0x0300, 68_702_699_520));
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    let card = &devices[0];
    assert_eq!(card.id, "52d10e8a52d4b1c3");
    assert_eq!(card.id_source, DeviceIdSource::VendorUuid);
    assert_eq!(card.model, "AMD Instinct MI210");
    assert_eq!(card.memory, DeviceMemory::Dedicated { mib: 65_520 });
    assert_eq!(card.features, vec!["rocm".to_owned()]);
    assert_eq!(card.closure, DeviceClosure::Closed);
}

#[test]
fn an_amd_card_with_a_serial_and_no_unique_id_is_found_by_its_serial() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:03:00.0",
        "0x1002",
        "amdgpu",
        &[
            ("unique_id", "0000000000000000"),
            ("serial_number", "692214000123"),
            ("mem_info_vram_total", "17163091968"),
        ],
    );
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, "692214000123");
    assert_eq!(devices[0].id_source, DeviceIdSource::Serial);
}

#[test]
fn a_discrete_amd_card_with_no_stable_id_is_not_listed() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:03:00.0",
        "0x1002",
        "amdgpu",
        &[("unique_id", ""), ("mem_info_vram_total", "17163091968")],
    );
    tree.kfd_node(1, 41210, &discrete_properties(0x0300, 17_163_091_968));
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn without_kfd_an_amd_card_has_no_rocm_feature_and_is_admitted() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:03:00.0",
        "0x1002",
        "amdgpu",
        &[
            ("device", "0x73bf"),
            ("unique_id", "a1b2c3d4e5f60718"),
            ("mem_info_vram_total", "17163091968"),
        ],
    );
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].features, Vec::<String>::new());
    assert_eq!(devices[0].closure, DeviceClosure::Admitted);
    assert_eq!(devices[0].model, "device 0x73bf");
    assert_eq!(devices[0].memory, DeviceMemory::Dedicated { mib: 16_368 });
}

#[test]
fn cards_of_other_vendors_or_drivers_are_not_amd_devices() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:01:00.0",
        "0x10de",
        "nvidia",
        &[("mem_info_vram_total", "1")],
    );
    tree.card(
        "card1",
        "0000:02:00.0",
        "0x1002",
        "vfio-pci",
        &[("unique_id", "52d10e8a52d4b1c3")],
    );
    tree.card("card2", "0000:00:02.0", "0x8086", "i915", &[]);
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn a_machine_with_no_drm_or_kfd_tree_lists_no_amd_device() {
    let tree = SysfsTree::new();
    let probe = tree.probe();
    assert_eq!(probe.list().expect("list"), Vec::new());
    assert_eq!(
        probe.processes().expect("processes"),
        ComputeProcesses::Listed(Vec::new())
    );
}

#[test]
fn kfd_lists_every_process_with_a_compute_context_on_the_apu() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    tree.kfd_process(4242, &[APU_KFD_ID]);
    tree.kfd_process(5151, &[APU_KFD_ID, 7777]);
    // A process directory with no compute context on a listed device.
    tree.kfd_process(6000, &[7777]);
    let id = format!("pci-{APU_SLOT}");
    assert_eq!(
        tree.probe().processes().expect("processes"),
        ComputeProcesses::Listed(vec![
            GpuComputeProcess {
                device_id: id.clone(),
                pid: Some(4242),
            },
            GpuComputeProcess {
                device_id: id,
                pid: Some(5151),
            },
        ])
    );
}

#[test]
fn an_idle_apu_lists_no_process() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    assert_eq!(
        tree.probe().processes().expect("processes"),
        ComputeProcesses::Listed(Vec::new())
    );
}

#[test]
fn a_kfd_device_without_the_process_directory_cannot_tell_and_is_never_read_as_idle() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    std::fs::remove_dir(tree.dir.path().join("class/kfd/kfd/proc")).expect("remove proc");
    assert!(matches!(
        tree.probe().processes(),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn unreadable_amd_files_are_refused() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.kfd_node(0, 0, CPU_PROPERTIES);
    tree.kfd_node(1, APU_KFD_ID, "location_id 50176\ndomain zero\n");
    assert!(matches!(
        tree.probe().list(),
        Err(GpuProbeError::Unreadable { .. })
    ));

    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:03:00.0",
        "0x1002",
        "amdgpu",
        &[
            ("unique_id", "52d10e8a52d4b1c3"),
            ("mem_info_vram_total", "16 GiB"),
        ],
    );
    assert!(matches!(
        tree.probe().list(),
        Err(GpuProbeError::Unreadable { .. })
    ));
}

// ---------------------------------------------------------------------------
// Apple through system_profiler.

fn apple_facts() -> DeviceFacts {
    let mut devices = parse_system_profiler_devices(M4_MAX).expect("parse");
    assert_eq!(devices.len(), 1);
    devices.remove(0)
}

#[test]
fn an_apple_gpu_is_found_by_the_platform_uuid_with_unified_memory_and_metal() {
    assert_eq!(
        apple_facts(),
        DeviceFacts {
            id: "00000000-0000-4000-8000-00000000A001-gpu0".to_owned(),
            id_source: DeviceIdSource::PlatformRegistry,
            kind: DeviceKind::Gpu,
            vendor: "apple".to_owned(),
            model: "Apple M4 Max".to_owned(),
            memory: DeviceMemory::Unified { mib: 65_536 },
            features: vec!["metal".to_owned()],
            closure: DeviceClosure::Admitted,
            state: DeviceState::Offered,
            max_claimants: 1,
        }
    );
}

#[test]
fn the_apple_probe_never_lists_processes() {
    assert_eq!(
        SystemProfilerProbe.processes().expect("processes"),
        ComputeProcesses::NeverListed
    );
}

#[test]
fn a_report_with_no_apple_gpu_lists_none() {
    // A Mac with an Intel processor and an AMD GPU.
    let report = r#"{
      "SPDisplaysDataType": [{
        "_name": "AMD Radeon Pro 5500M",
        "sppci_device_type": "spdisplays_gpu",
        "spdisplays_vendor": "sppci_vendor_amd",
        "sppci_model": "AMD Radeon Pro 5500M"
      }],
      "SPHardwareDataType": [{ "physical_memory": "32 GB", "platform_UUID": "X" }]
    }"#;
    assert_eq!(
        parse_system_profiler_devices(report).expect("parse"),
        Vec::new()
    );
}

#[test]
fn a_mac_with_no_platform_uuid_offers_no_apple_gpu() {
    let mut report: serde_json::Value = serde_json::from_str(M4_MAX).expect("json");
    report["SPHardwareDataType"][0]
        .as_object_mut()
        .expect("hardware")
        .remove("platform_UUID");
    assert_eq!(
        parse_system_profiler_devices(&report.to_string()).expect("parse"),
        Vec::new()
    );
}

#[test]
fn an_unreadable_report_is_refused_not_read_as_no_gpu() {
    assert!(matches!(
        parse_system_profiler_devices("System Profiler is busy"),
        Err(GpuProbeError::Unreadable { .. })
    ));
    assert!(matches!(
        parse_system_profiler_devices(r#"{"SPHardwareDataType": []}"#),
        Err(GpuProbeError::Unreadable { .. })
    ));
    let mut report: serde_json::Value = serde_json::from_str(M4_MAX).expect("json");
    report["SPHardwareDataType"][0]["physical_memory"] = "64 XB".into();
    assert!(matches!(
        parse_system_profiler_devices(&report.to_string()),
        Err(GpuProbeError::Unreadable { .. })
    ));
}

// ---------------------------------------------------------------------------
// Placement reads kind, features and memory, never vendor or model.

fn nvidia_facts() -> DeviceFacts {
    oneiron_server::gpu_execution_node::device::gpu_device_facts(
        &GpuDevice {
            device_id: "GPU-6f1e2d3c-0000-4000-8000-000000000001".to_owned(),
            model: "NVIDIA GeForce RTX 4090".to_owned(),
            memory_total_mib: 24_564,
        },
        DeviceState::Offered,
    )
}

fn machine() -> Vec<DeviceFacts> {
    vec![nvidia_facts(), apu_facts(), apple_facts()]
}

fn free(devices: Vec<DeviceFacts>) -> Vec<HeldDevice> {
    devices
        .into_iter()
        .map(|facts| HeldDevice {
            facts,
            holders: Vec::new(),
        })
        .collect()
}

fn gpu_claim(features: &[&str], memory_mib: u64, count: u32) -> DeviceClaim {
    DeviceClaim {
        kind: DeviceKind::Gpu,
        count,
        memory_mib,
        features: features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        sharing: Sharing::Exclusive,
    }
}

fn request(devices: Vec<DeviceClaim>) -> ResourceRequest {
    ResourceRequest {
        cpu_threads: 2,
        memory_mib: HOST_MIB,
        disk_mib: 1_024,
        devices,
        maximum_secs: 600,
    }
}

fn placed_ids(devices: &[HeldDevice], claims: Vec<DeviceClaim>) -> Vec<String> {
    request(claims)
        .place_devices(devices)
        .expect("placed")
        .devices
        .into_iter()
        .map(|lease| lease.device_id)
        .collect()
}

#[test]
fn a_claim_for_a_feature_lands_only_on_the_device_whose_probe_reports_it() {
    let devices = free(machine());
    let [nvidia, amd, apple] = [&devices[0], &devices[1], &devices[2]].map(|d| d.facts.id.clone());
    assert_eq!(
        placed_ids(&devices, vec![gpu_claim(&["cuda"], 0, 1)]),
        vec![nvidia]
    );
    assert_eq!(
        placed_ids(&devices, vec![gpu_claim(&["rocm"], 0, 1)]),
        vec![amd]
    );
    assert_eq!(
        placed_ids(&devices, vec![gpu_claim(&["metal"], 0, 1)]),
        vec![apple]
    );
    assert!(matches!(
        request(vec![gpu_claim(&["oneapi"], 0, 1)]).place_devices(&devices),
        Err(DevicePlacementError::NoDevice { .. })
    ));
}

#[test]
fn a_claim_naming_no_feature_takes_a_gpu_of_any_vendor() {
    let devices = free(machine());
    let mut placed = placed_ids(&devices, vec![gpu_claim(&[], 0, 3)]);
    placed.sort();
    let mut all: Vec<String> = devices.iter().map(|d| d.facts.id.clone()).collect();
    all.sort();
    assert_eq!(placed, all);
}

#[test]
fn a_claim_on_a_unified_memory_gpu_leases_its_memory_from_the_host() {
    let devices = free(machine());
    for feature in ["metal", "rocm"] {
        let placement = request(vec![gpu_claim(&[feature], 8_192, 1)])
            .place_devices(&devices)
            .expect("placed");
        assert_eq!(placement.host_memory_mib, HOST_MIB + 8_192, "{feature}");
    }
    let placement = request(vec![gpu_claim(&["cuda"], 8_192, 1)])
        .place_devices(&devices)
        .expect("placed");
    assert_eq!(placement.host_memory_mib, HOST_MIB);
    assert!(matches!(
        request(vec![gpu_claim(&["metal"], 65_537, 1)]).place_devices(&devices),
        Err(DevicePlacementError::NoDevice { .. })
    ));
}

#[test]
fn vendor_and_model_never_change_a_placement() {
    let devices = free(machine());
    let mut renamed = machine();
    let names: Vec<(String, String)> = renamed
        .iter()
        .map(|facts| (facts.vendor.clone(), facts.model.clone()))
        .collect();
    for (place, facts) in renamed.iter_mut().enumerate() {
        let (vendor, model) = &names[(place + 1) % names.len()];
        facts.vendor.clone_from(vendor);
        facts.model.clone_from(model);
    }
    let renamed = free(renamed);
    let cases: [&[&str]; 4] = [&["cuda"], &["rocm"], &["metal"], &[]];
    for features in cases {
        assert_eq!(
            placed_ids(&devices, vec![gpu_claim(features, 0, 1)]),
            placed_ids(&renamed, vec![gpu_claim(features, 0, 1)]),
            "{features:?}"
        );
    }
}

#[test]
fn every_probe_sits_behind_the_one_trait() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    let probes: Vec<Box<dyn DeviceProbe>> = vec![
        Box::new(NvidiaSmiProbe),
        Box::new(tree.probe()),
        Box::new(XpuSmiProbe),
        Box::new(SystemProfilerProbe),
    ];
    assert_eq!(probes[1].list().expect("list"), vec![apu_facts()]);
}
