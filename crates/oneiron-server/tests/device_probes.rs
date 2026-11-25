//! Device probes for AMD, Intel and Apple GPUs (pass 34 row S5): each
//! reports its devices as `DeviceFacts` by kind, features and memory, read
//! from fixtures of its tool's or driver's output (no hardware needed), and
//! placement matches the reports by kind, features and memory alone, never
//! by vendor or model.
//!
//! Fixtures: `kfd_properties_*.txt` and `kfd_mem_bank_gfx1103_apu.txt` are
//! KFD topology files read on an AMD Radeon 780M APU (PCI 1002:1900,
//! gfx1103) on Linux; the amdgpu sysfs values beside them are that
//! machine's. `system_profiler_m4_max.json` is `system_profiler -json
//! SPDisplaysDataType SPHardwareDataType` from an M4 Max Mac, with its
//! serial, platform UUID and provisioning id replaced. The `xpu_smi_*.json`
//! fixtures are built (no Intel GPU was at hand) on the keys, JSON types and
//! `device_type` values xpumanager 6882e2ca writes in
//! `ial/cmn/cmd_discovery.cpp`: `device_list` entries (lines 456-514, the
//! survivability entry 2581-2589) and one device's detail (lines 710-953).
//! Placement tests also use NVIDIA's probe facts.

#![cfg(unix)]

use oneiron::job_workload::{
    DeviceClaim, DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory,
    DevicePlacementError, DeviceState, HeldDevice, ResourceRequest, Sharing,
};
use oneiron_server::gpu_execution_node::device_probes::{
    AmdgpuSysfsProbe, ComputeProcesses, DeviceProbe, SystemProfilerProbe, XpuSmiProbe,
    parse_system_profiler_devices, parse_xpu_smi_device_detail, parse_xpu_smi_device_list,
};
use oneiron_server::gpu_execution_node::{
    GpuComputeProcess, GpuDevice, GpuProbeError, NvidiaSmiProbe,
};

const APU_PROPERTIES: &str = include_str!("fixtures/device_probes/kfd_properties_gfx1103_apu.txt");
const CPU_PROPERTIES: &str = include_str!("fixtures/device_probes/kfd_properties_cpu.txt");
const APU_BANK: &str = include_str!("fixtures/device_probes/kfd_mem_bank_gfx1103_apu.txt");
const M4_MAX: &str = include_str!("fixtures/device_probes/system_profiler_m4_max.json");
const XPU_LIST: &str = include_str!("fixtures/device_probes/xpu_smi_discovery_list.json");
const XPU_DEVICE: &str = include_str!("fixtures/device_probes/xpu_smi_discovery_device.json");

/// The APU's PCI address, render minor and KFD id on the machine the
/// fixtures come from.
const APU_SLOT: &str = "0000:c4:00.0";
const APU_RENDER_MINOR: u32 = 128;
const APU_KFD_ID: u32 = 50809;
/// Its VRAM carve-out and its GTT total (what KFD's bank gives it), in bytes.
const APU_VRAM_BYTES: u64 = 536_870_912;
const APU_GTT_BYTES: u64 = 16_462_188_544;

/// The PCI address of the Intel GPU the detail fixture describes.
const XPU_BDF: &str = "0000:29:00.0";

/// A discrete card's unique id, as the driver's `unique_id` file writes it.
const CARD_UNIQUE_ID: &str = "52d10e8a52d4b1c3";

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

    fn mkdir(&self, relative: &str) {
        std::fs::create_dir_all(self.dir.path().join(relative)).expect("dir");
    }

    /// A DRM card on `slot` with its render node, `driver` bound and these
    /// attribute files.
    fn card(
        &self,
        card: &str,
        slot: &str,
        render_minor: u32,
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
        self.mkdir(&format!("{device}/drm/{card}"));
        self.mkdir(&format!("{device}/drm/renderD{render_minor}"));
        let drivers = self.dir.path().join("bus/pci/drivers").join(driver);
        std::fs::create_dir_all(&drivers).expect("driver dir");
        std::os::unix::fs::symlink(&drivers, self.dir.path().join(&device).join("driver"))
            .expect("driver link");
        let class = self.dir.path().join("class/drm").join(card);
        std::fs::create_dir_all(&class).expect("card dir");
        std::os::unix::fs::symlink(self.dir.path().join(&device), class.join("device"))
            .expect("device link");
        // A connector of the card, which is not a device.
        self.mkdir(&format!("class/drm/{card}-DP-1"));
    }

    /// The APU of the fixture machine, as amdgpu wrote it there.
    fn fixture_apu(&self) {
        self.card(
            "card0",
            APU_SLOT,
            APU_RENDER_MINOR,
            "0x1002",
            "amdgpu",
            &[
                ("device", "0x1900"),
                ("unique_id", ""),
                ("mem_info_vram_total", &APU_VRAM_BYTES.to_string()),
                ("mem_info_gtt_total", &APU_GTT_BYTES.to_string()),
            ],
        );
    }

    /// A KFD node with `properties` and, for a GPU, one memory bank.
    fn kfd_node(&self, node: u32, gpu_id: u32, properties: &str, bank: Option<&str>) {
        let dir = format!("class/kfd/kfd/topology/nodes/{node}");
        self.write(&format!("{dir}/gpu_id"), &format!("{gpu_id}\n"));
        self.write(&format!("{dir}/properties"), properties);
        if let Some(bank) = bank {
            self.write(&format!("{dir}/mem_banks/0/properties"), bank);
        }
    }

    /// The fixture machine's KFD topology: its CPU node and the APU's node.
    fn fixture_kfd(&self) {
        self.kfd_node(0, 0, CPU_PROPERTIES, None);
        self.kfd_node(1, APU_KFD_ID, APU_PROPERTIES, Some(APU_BANK));
        self.mkdir("class/kfd/kfd/proc");
    }

    /// A process with a compute context on each of `gpu_ids`.
    fn kfd_process(&self, pid: u32, gpu_ids: &[u32]) {
        self.write(&format!("class/kfd/kfd/proc/{pid}/pasid"), "0\n");
        self.mkdir(&format!("class/kfd/kfd/proc/{pid}/queues"));
        for gpu_id in gpu_ids {
            self.write(&format!("class/kfd/kfd/proc/{pid}/vram_{gpu_id}"), "0\n");
            self.write(&format!("class/kfd/kfd/proc/{pid}/sdma_{gpu_id}"), "0\n");
        }
    }
}

/// The APU's node properties as a card at `location_id` with render node
/// `render_minor` and unique id `unique_id` would write them (KFD writes
/// `local_mem_size 0` for every GPU).
fn card_properties(location_id: u32, render_minor: u32, unique_id: u64) -> String {
    APU_PROPERTIES
        .lines()
        .map(|line| match line.split_once(' ') {
            Some(("location_id", _)) => format!("location_id {location_id}"),
            Some(("drm_render_minor", _)) => format!("drm_render_minor {render_minor}"),
            Some(("unique_id", _)) => format!("unique_id {unique_id}"),
            _ => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A frame buffer bank of `bytes`: a discrete card's VRAM.
fn frame_buffer_bank(bytes: u64) -> String {
    format!("heap_type 1\nsize_in_bytes {bytes}\nflags 0\nwidth 4096\nmem_clk_max 1600\n")
}

/// A discrete card at `0000:03:00.0` (render minor 129) with these
/// attributes and, when `kfd_vram` is given, a KFD node with that VRAM.
fn discrete_card(tree: &SysfsTree, attributes: &[(&str, &str)], kfd_vram: Option<u64>) {
    tree.card("card1", "0000:03:00.0", 129, "0x1002", "amdgpu", attributes);
    if let Some(vram) = kfd_vram {
        tree.kfd_node(
            2,
            41210,
            &card_properties(0x0300, 129, 0),
            Some(&frame_buffer_bank(vram)),
        );
    }
}

fn apu_facts() -> DeviceFacts {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    let mut devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    devices.remove(0)
}

fn apu_id() -> String {
    format!("pci-{APU_SLOT}")
}

// ---------------------------------------------------------------------------
// AMD through amdgpu sysfs and KFD.

#[test]
fn an_amd_apu_with_no_unique_id_is_found_by_its_pci_address_with_unified_memory_and_rocm() {
    assert_eq!(
        apu_facts(),
        DeviceFacts {
            id: apu_id(),
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
    discrete_card(
        &tree,
        &[
            ("device", "0x740f"),
            ("unique_id", CARD_UNIQUE_ID),
            ("product_name", "AMD Instinct MI210"),
            ("mem_info_vram_total", "68702699520"),
            ("mem_info_gtt_total", "135015096320"),
        ],
        Some(68_702_699_520),
    );
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    let card = &devices[0];
    assert_eq!(card.id, CARD_UNIQUE_ID);
    assert_eq!(card.id_source, DeviceIdSource::VendorUuid);
    assert_eq!(card.model, "AMD Instinct MI210");
    assert_eq!(card.memory, DeviceMemory::Dedicated { mib: 65_520 });
    assert_eq!(card.features, vec!["rocm".to_owned()]);
    assert_eq!(card.closure, DeviceClosure::Closed);
}

#[test]
fn kfds_unique_id_gives_the_same_id_when_the_driver_file_is_absent() {
    let tree = SysfsTree::new();
    tree.card(
        "card1",
        "0000:03:00.0",
        129,
        "0x1002",
        "amdgpu",
        &[("mem_info_vram_total", "68702699520")],
    );
    let unique_id = u64::from_str_radix(CARD_UNIQUE_ID, 16).expect("hex");
    tree.kfd_node(
        2,
        41210,
        &card_properties(0x0300, 129, unique_id),
        Some(&frame_buffer_bank(68_702_699_520)),
    );
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, CARD_UNIQUE_ID);
    assert_eq!(devices[0].id_source, DeviceIdSource::VendorUuid);
}

#[test]
fn an_amd_card_with_a_serial_and_no_unique_id_is_found_by_its_serial() {
    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[
            ("unique_id", ""),
            ("serial_number", "692214000123"),
            ("mem_info_vram_total", "17163091968"),
        ],
        None,
    );
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, "692214000123");
    assert_eq!(devices[0].id_source, DeviceIdSource::Serial);
}

#[test]
fn a_discrete_amd_card_with_no_stable_id_is_not_listed() {
    // "0" is the FRU reader's fallback serial for a card whose unique id is 0.
    for serial in [None, Some("0"), Some("")] {
        let tree = SysfsTree::new();
        let mut attributes = vec![("unique_id", ""), ("mem_info_vram_total", "17163091968")];
        if let Some(serial) = serial {
            attributes.push(("serial_number", serial));
        }
        discrete_card(&tree, &attributes, Some(17_163_091_968));
        assert_eq!(tree.probe().list().expect("list"), Vec::new(), "{serial:?}");
    }
}

#[test]
fn an_apu_with_no_vram_carve_out_is_unified_with_the_memory_kfd_gives_it() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        APU_SLOT,
        APU_RENDER_MINOR,
        "0x1002",
        "amdgpu",
        &[("mem_info_gtt_total", &APU_GTT_BYTES.to_string())],
    );
    tree.fixture_kfd();
    let devices = tree.probe().list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, apu_id());
    assert_eq!(
        devices[0].memory,
        DeviceMemory::Unified {
            mib: APU_GTT_BYTES / (1024 * 1024)
        }
    );
}

#[test]
fn a_gpu_with_neither_vram_nor_kfd_memory_is_not_listed() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        APU_SLOT,
        APU_RENDER_MINOR,
        "0x1002",
        "amdgpu",
        &[("unique_id", CARD_UNIQUE_ID)],
    );
    tree.kfd_node(1, APU_KFD_ID, APU_PROPERTIES, None);
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn an_apu_whose_kfd_memory_is_its_carve_out_reads_as_dedicated_and_needs_an_id() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.kfd_node(
        1,
        APU_KFD_ID,
        APU_PROPERTIES,
        Some(&frame_buffer_bank(APU_VRAM_BYTES)),
    );
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn a_card_split_into_compute_partitions_is_not_listed() {
    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[
            ("unique_id", CARD_UNIQUE_ID),
            ("mem_info_vram_total", "206141652992"),
        ],
        Some(103_070_826_496),
    );
    // The second partition: its partition in the function bits of its
    // location, and a render node of its own that is no card's.
    tree.kfd_node(
        3,
        41211,
        &card_properties(0x0301, 130, 0),
        Some(&frame_buffer_bank(103_070_826_496)),
    );
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn two_gpu_functions_of_one_pci_device_are_two_devices() {
    let tree = SysfsTree::new();
    for (card, slot, minor, location, id, gpu_id) in [
        (
            "card1",
            "0000:03:00.0",
            129,
            0x0300,
            "1111111111111111",
            41210,
        ),
        (
            "card2",
            "0000:03:00.1",
            130,
            0x0301,
            "2222222222222222",
            41211,
        ),
    ] {
        tree.card(
            card,
            slot,
            minor,
            "0x1002",
            "amdgpu",
            &[("unique_id", id), ("mem_info_vram_total", "17163091968")],
        );
        tree.kfd_node(
            minor,
            gpu_id,
            &card_properties(location, minor, 0),
            Some(&frame_buffer_bank(17_163_091_968)),
        );
    }
    let ids: Vec<String> = tree
        .probe()
        .list()
        .expect("list")
        .into_iter()
        .map(|device| device.id)
        .collect();
    assert_eq!(ids, vec!["1111111111111111", "2222222222222222"]);
}

#[test]
fn devices_that_repeat_one_id_are_not_listed() {
    let tree = SysfsTree::new();
    for (card, slot, minor) in [
        ("card1", "0000:03:00.0", 129),
        ("card2", "0000:83:00.0", 130),
    ] {
        tree.card(
            card,
            slot,
            minor,
            "0x1002",
            "amdgpu",
            &[
                ("serial_number", "692214000123"),
                ("mem_info_vram_total", "17163091968"),
            ],
        );
    }
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn without_kfd_an_amd_card_has_no_rocm_feature_is_admitted_and_never_lists_processes() {
    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[
            ("device", "0x73bf"),
            ("unique_id", "a1b2c3d4e5f60718"),
            ("mem_info_vram_total", "17163091968"),
        ],
        None,
    );
    let probe = tree.probe();
    let devices = probe.list().expect("list");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].features, Vec::<String>::new());
    assert_eq!(devices[0].closure, DeviceClosure::Admitted);
    assert_eq!(devices[0].model, "device 0x73bf");
    assert_eq!(devices[0].memory, DeviceMemory::Dedicated { mib: 16_368 });
    assert_eq!(
        probe.processes_on("a1b2c3d4e5f60718").expect("processes"),
        ComputeProcesses::NeverListed
    );
}

#[test]
fn a_serial_comes_before_kfds_unique_id_so_the_id_does_not_change_with_kfd() {
    let tree = SysfsTree::new();
    tree.card(
        "card1",
        "0000:03:00.0",
        129,
        "0x1002",
        "amdgpu",
        &[
            ("serial_number", "692214000123"),
            ("mem_info_vram_total", "68702699520"),
        ],
    );
    let unique_id = u64::from_str_radix(CARD_UNIQUE_ID, 16).expect("hex");
    tree.kfd_node(
        2,
        41210,
        &card_properties(0x0300, 129, unique_id),
        Some(&frame_buffer_bank(68_702_699_520)),
    );
    let with_kfd = tree.probe().list().expect("list");
    std::fs::remove_dir_all(tree.dir.path().join("class/kfd")).expect("unload KFD");
    let without_kfd = tree.probe().list().expect("list");
    assert_eq!(with_kfd.len(), 1);
    assert_eq!(without_kfd.len(), 1);
    assert_eq!(with_kfd[0].id, "692214000123");
    assert_eq!(without_kfd[0].id, with_kfd[0].id);
}

#[test]
fn a_card_with_no_memory_is_not_listed() {
    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[("unique_id", CARD_UNIQUE_ID), ("mem_info_vram_total", "0")],
        None,
    );
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn a_listed_device_kfd_no_longer_lists_cannot_tell_and_is_never_read_as_unlisted() {
    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[
            ("unique_id", CARD_UNIQUE_ID),
            ("mem_info_vram_total", "68702699520"),
        ],
        Some(68_702_699_520),
    );
    tree.mkdir("class/kfd/kfd/proc");
    let probe = tree.probe();
    assert_eq!(
        probe.list().expect("list")[0].closure,
        DeviceClosure::Closed
    );
    // KFD rebuilds its topology: the card's node is gone for a moment.
    std::fs::remove_dir_all(tree.dir.path().join("class/kfd/kfd/topology/nodes/2"))
        .expect("remove node");
    assert!(matches!(
        probe.processes_on(CARD_UNIQUE_ID),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn cards_of_other_vendors_or_drivers_are_not_amd_devices() {
    let tree = SysfsTree::new();
    tree.card(
        "card0",
        "0000:01:00.0",
        128,
        "0x10de",
        "nvidia",
        &[("mem_info_vram_total", "1")],
    );
    tree.card(
        "card1",
        "0000:02:00.0",
        129,
        "0x1002",
        "vfio-pci",
        &[("unique_id", CARD_UNIQUE_ID)],
    );
    tree.card("card2", "0000:00:02.0", 130, "0x8086", "i915", &[]);
    assert_eq!(tree.probe().list().expect("list"), Vec::new());
}

#[test]
fn a_machine_with_no_drm_or_kfd_tree_lists_no_amd_device() {
    let probe = SysfsTree::new().probe();
    assert_eq!(probe.list().expect("list"), Vec::new());
    assert!(matches!(
        probe.processes_on(&apu_id()),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn kfd_lists_every_process_with_a_compute_context_on_the_apu() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    tree.kfd_process(4242, &[APU_KFD_ID]);
    tree.kfd_process(5151, &[APU_KFD_ID, 7777]);
    // A process with a compute context on another GPU only.
    tree.kfd_process(6000, &[7777]);
    assert_eq!(
        tree.probe().processes_on(&apu_id()).expect("processes"),
        ComputeProcesses::Listed(vec![
            GpuComputeProcess {
                device_id: apu_id(),
                pid: Some(4242),
            },
            GpuComputeProcess {
                device_id: apu_id(),
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
        tree.probe().processes_on(&apu_id()).expect("processes"),
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
        tree.probe().processes_on(&apu_id()),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn a_device_the_read_no_longer_finds_cannot_tell_and_is_never_read_as_idle() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.fixture_kfd();
    let probe = tree.probe();
    assert_eq!(probe.list().expect("list").len(), 1);
    // The card leaves between the listing and the process read.
    std::fs::remove_dir_all(tree.dir.path().join("class/drm/card0")).expect("remove card");
    assert!(matches!(
        probe.processes_on(&apu_id()),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn unreadable_amd_files_are_refused() {
    let tree = SysfsTree::new();
    tree.fixture_apu();
    tree.kfd_node(0, 0, CPU_PROPERTIES, None);
    tree.kfd_node(
        1,
        APU_KFD_ID,
        "location_id 50176\ndomain zero\n",
        Some(APU_BANK),
    );
    assert!(matches!(
        tree.probe().list(),
        Err(GpuProbeError::Unreadable { .. })
    ));

    let tree = SysfsTree::new();
    discrete_card(
        &tree,
        &[
            ("unique_id", CARD_UNIQUE_ID),
            ("mem_info_vram_total", "16 GiB"),
        ],
        None,
    );
    assert!(matches!(
        tree.probe().list(),
        Err(GpuProbeError::Unreadable { .. })
    ));
}

// ---------------------------------------------------------------------------
// Intel through xpu-smi.

fn intel_detail(edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> String {
    let mut detail: serde_json::Value = serde_json::from_str(XPU_DEVICE).expect("json");
    edit(detail.as_object_mut().expect("object"));
    detail.to_string()
}

fn parsed_intel(detail: &str) -> DeviceFacts {
    parse_xpu_smi_device_detail(detail, XPU_BDF)
        .expect("parse")
        .expect("a device")
}

fn intel_facts() -> DeviceFacts {
    parsed_intel(XPU_DEVICE)
}

#[test]
fn an_intel_gpu_is_found_by_its_level_zero_uuid_with_its_own_memory_and_oneapi() {
    assert_eq!(
        intel_facts(),
        DeviceFacts {
            id: "00000000-0000-0029-0000-002f0bda8086".to_owned(),
            id_source: DeviceIdSource::VendorUuid,
            kind: DeviceKind::Gpu,
            vendor: "intel".to_owned(),
            model: "Intel(R) Data Center GPU Max 1100".to_owned(),
            memory: DeviceMemory::Dedicated { mib: 49_152 },
            features: vec!["oneapi".to_owned()],
            closure: DeviceClosure::Admitted,
            state: DeviceState::Offered,
            max_claimants: 1,
        }
    );
}

#[test]
fn an_intel_gpu_with_no_uuid_is_found_by_its_serial_unless_it_has_none() {
    let detail = intel_detail(|detail| {
        detail.insert("uuid".to_owned(), "".into());
    });
    let facts = parsed_intel(&detail);
    assert_eq!(facts.id, "LQAC31600342");
    assert_eq!(facts.id_source, DeviceIdSource::Serial);
    for serial in ["unknown", "N/A (Requires Root)", ""] {
        let detail = intel_detail(|detail| {
            detail.insert("uuid".to_owned(), "".into());
            detail.insert("serial_number".to_owned(), serial.into());
        });
        assert_eq!(
            parse_xpu_smi_device_detail(&detail, XPU_BDF).expect("parse"),
            None,
            "{serial}"
        );
    }
}

#[test]
fn an_integrated_intel_gpu_computes_in_the_machines_memory() {
    let detail = intel_detail(|detail| {
        detail.insert("device_type".to_owned(), "Integrated GPU".into());
        detail.insert(
            "memory_physical_size_byte".to_owned(),
            17_179_869_184_u64.into(),
        );
    });
    assert_eq!(
        parsed_intel(&detail).memory,
        DeviceMemory::Unified { mib: 16_384 }
    );
}

#[test]
fn an_intel_gpu_level_zero_did_not_reach_is_not_listed() {
    // Found through the management interface only: no compute device type.
    let detail = intel_detail(|detail| {
        detail.insert("device_type".to_owned(), "".into());
    });
    assert_eq!(
        parse_xpu_smi_device_detail(&detail, XPU_BDF).expect("parse"),
        None
    );
}

#[test]
fn a_memory_size_the_tool_writes_as_a_string_is_read() {
    let detail = intel_detail(|detail| {
        detail.insert("memory_physical_size_byte".to_owned(), "51539607552".into());
    });
    assert_eq!(
        parsed_intel(&detail).memory,
        DeviceMemory::Dedicated { mib: 49_152 }
    );
}

#[test]
fn the_device_list_gives_each_compute_gpu_and_leaves_out_the_rest() {
    // Device 2 was found through the management interface only, device 3
    // is in survivability mode.
    assert_eq!(
        parse_xpu_smi_device_list(XPU_LIST).expect("parse"),
        vec![(0, XPU_BDF.to_owned()), (1, "0000:3a:00.0".to_owned())]
    );
    assert_eq!(
        parse_xpu_smi_device_list(r#"{"device_list": null}"#).expect("parse"),
        Vec::new()
    );
}

#[test]
fn unreadable_xpu_smi_output_is_refused() {
    // What the tool prints on stdout when Level Zero does not start.
    assert!(matches!(
        parse_xpu_smi_device_list("Sysman driver initialization failed."),
        Err(GpuProbeError::Unreadable { .. })
    ));
    assert!(matches!(
        parse_xpu_smi_device_list(r#"{"device_list": [{"device_name": "x"}]}"#),
        Err(GpuProbeError::Unreadable { .. })
    ));
    let detail = intel_detail(|detail| {
        detail.remove("memory_physical_size_byte");
    });
    assert!(matches!(
        parse_xpu_smi_device_detail(&detail, XPU_BDF),
        Err(GpuProbeError::Unreadable { .. })
    ));
}

#[test]
fn a_detail_of_another_device_than_the_listed_one_cannot_tell() {
    // A device added between the list and the detail moves the numbers.
    assert!(matches!(
        parse_xpu_smi_device_detail(XPU_DEVICE, "0000:3a:00.0"),
        Err(GpuProbeError::Unavailable { .. })
    ));
}

#[test]
fn an_intel_gpu_whose_memory_query_failed_is_not_listed() {
    // The tool writes 0 when its memory module query fails.
    let detail = intel_detail(|detail| {
        detail.insert("memory_physical_size_byte".to_owned(), 0.into());
    });
    assert_eq!(
        parse_xpu_smi_device_detail(&detail, XPU_BDF).expect("parse"),
        None
    );
}

#[test]
fn the_intel_probe_never_lists_processes() {
    assert_eq!(
        XpuSmiProbe
            .processes_on("00000000-0000-0029-0000-002f0bda8086")
            .expect("processes"),
        ComputeProcesses::NeverListed
    );
}

// ---------------------------------------------------------------------------
// Apple through system_profiler.

fn apple_facts() -> DeviceFacts {
    let mut devices = parse_system_profiler_devices(M4_MAX).expect("parse");
    assert_eq!(devices.len(), 1);
    devices.remove(0)
}

fn m4_max_report() -> serde_json::Value {
    serde_json::from_str(M4_MAX).expect("json")
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
        SystemProfilerProbe
            .processes_on("00000000-0000-4000-8000-00000000A001-gpu0")
            .expect("processes"),
        ComputeProcesses::NeverListed
    );
}

#[test]
fn a_report_with_no_apple_gpu_lists_none() {
    // A Mac with an Intel processor and an AMD GPU (keys and values as in a
    // public capture: displayplacer pull request 96).
    let report = r#"{
      "SPDisplaysDataType": [{
        "_name": "AMD Radeon Pro 5500M",
        "sppci_device_type": "spdisplays_gpu",
        "spdisplays_vendor": "sppci_vendor_amd",
        "spdisplays_vram": "4 GB",
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
    let mut report = m4_max_report();
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
    let mut report = m4_max_report();
    report["SPHardwareDataType"][0]["physical_memory"] = "64 XB".into();
    assert!(matches!(
        parse_system_profiler_devices(&report.to_string()),
        Err(GpuProbeError::Unreadable { .. })
    ));
    // Two Apple GPU rows: no id would tell them apart.
    let mut report = m4_max_report();
    let row = report["SPDisplaysDataType"][0].clone();
    report["SPDisplaysDataType"]
        .as_array_mut()
        .expect("rows")
        .push(row);
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
    vec![nvidia_facts(), apu_facts(), intel_facts(), apple_facts()]
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
    let [nvidia, amd, intel, apple] =
        [&devices[0], &devices[1], &devices[2], &devices[3]].map(|d| d.facts.id.clone());
    for (feature, device) in [
        ("cuda", nvidia),
        ("rocm", amd),
        ("oneapi", intel),
        ("metal", apple),
    ] {
        assert_eq!(
            placed_ids(&devices, vec![gpu_claim(&[feature], 0, 1)]),
            vec![device],
            "{feature}"
        );
    }
    assert!(matches!(
        request(vec![gpu_claim(&["vulkan"], 0, 1)]).place_devices(&devices),
        Err(DevicePlacementError::NoDevice { .. })
    ));
}

#[test]
fn a_claim_naming_no_feature_takes_a_gpu_of_any_vendor() {
    let devices = free(machine());
    let mut placed = placed_ids(&devices, vec![gpu_claim(&[], 0, 4)]);
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
    for feature in ["cuda", "oneapi"] {
        let placement = request(vec![gpu_claim(&[feature], 8_192, 1)])
            .place_devices(&devices)
            .expect("placed");
        assert_eq!(placement.host_memory_mib, HOST_MIB, "{feature}");
    }
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
    let cases: [&[&str]; 5] = [&["cuda"], &["rocm"], &["oneapi"], &["metal"], &[]];
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
    assert_eq!(
        probes[3].processes_on("any").expect("processes"),
        ComputeProcesses::NeverListed
    );
}
