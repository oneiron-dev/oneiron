//! AMD GPUs, read from the `amdgpu` driver's sysfs files: no tool needs to
//! be installed (`rocm-smi` is deprecated, and `amd-smi` reads the same
//! driver). A device is each `/sys/class/drm/card<N>` whose PCI vendor is
//! AMD and whose driver is `amdgpu`. The KFD compute driver
//! (`/sys/class/kfd/kfd`), where it is loaded, adds what ROCm sees: the
//! device's KFD node, which gives the `rocm` feature, the memory ROCm
//! allocates on it, and the processes that hold a compute context on it.
//!
//! Memory: the device's own VRAM (`mem_info_vram_total`), unless KFD gives
//! it more memory than that VRAM, or the driver keeps no VRAM for it. That
//! is a GPU built into the processor (an APU), whose compute memory comes
//! from the machine's own: it is [`DeviceMemory::Unified`], with the memory
//! KFD reports.
//!
//! The id is the device's own unique id where the driver gives one, else
//! its serial number. A built-in GPU with neither is found by its PCI
//! address, which the platform fixes for a built-in device. A discrete card
//! with neither is not listed: its PCI address changes when the card moves.
//! Nor is a card split into compute partitions, which KFD lists as several
//! nodes: each partition would be a device of its own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};

use super::super::device::{GpuComputeProcess, GpuProbeError, plain_device_id};
use super::{ComputeProcesses, DeviceProbe, bytes_to_mib};

/// AMD's PCI vendor id, as sysfs writes it.
const AMD_PCI_VENDOR: &str = "0x1002";

/// The driver whose devices this probe reads.
const AMDGPU_DRIVER: &str = "amdgpu";

/// The vendor this probe reports, for people.
const AMD: &str = "amd";

/// The compute feature of a device KFD lists.
const ROCM: &str = "rocm";

/// KFD's heap types of a GPU's own memory: frame buffer, public and
/// private.
const FRAME_BUFFER_HEAPS: [u64; 2] = [1, 2];

/// The probe of this machine's AMD GPUs. The roots are fields so a test can
/// point the probe at a copy of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdgpuSysfsProbe {
    /// The DRM class directory, `/sys/class/drm`.
    pub drm_root: PathBuf,
    /// The KFD directory, `/sys/class/kfd/kfd`.
    pub kfd_root: PathBuf,
}

impl Default for AmdgpuSysfsProbe {
    fn default() -> Self {
        Self {
            drm_root: PathBuf::from("/sys/class/drm"),
            kfd_root: PathBuf::from("/sys/class/kfd/kfd"),
        }
    }
}

/// One GPU node of KFD's topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KfdNode {
    /// KFD's id for the device, which names it in each process's files.
    gpu_id: u32,
    /// The frame buffer memory ROCm allocates on the device, in bytes.
    memory_bytes: u64,
    /// The device's graphics IP version, `110003` for `gfx1103`.
    gfx_target_version: Option<u64>,
}

/// KFD's GPU nodes: by PCI address, and the PCI devices (address without
/// its function) that more than one node names, which are partitioned.
#[derive(Debug, Default)]
struct KfdTopology {
    nodes: BTreeMap<String, KfdNode>,
    partitioned: BTreeSet<String>,
}

/// One AMD GPU as this probe read it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AmdgpuDevice {
    facts: DeviceFacts,
    /// Its KFD id, when KFD lists the device.
    kfd_gpu_id: Option<u32>,
}

impl DeviceProbe for AmdgpuSysfsProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        Ok(self
            .devices()?
            .into_iter()
            .map(|device| device.facts)
            .collect())
    }

    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError> {
        let by_kfd_id: BTreeMap<u32, String> = self
            .devices()?
            .into_iter()
            .filter_map(|device| Some((device.kfd_gpu_id?, device.facts.id)))
            .collect();
        if by_kfd_id.is_empty() {
            return Ok(ComputeProcesses::Listed(Vec::new()));
        }
        // KFD lists a device: a missing process directory cannot tell.
        let proc_dir = self.kfd_root.join("proc");
        if !proc_dir.is_dir() {
            return Err(GpuProbeError::Unavailable {
                reason: format!("{} does not exist", proc_dir.display()),
            });
        }
        let mut processes = Vec::new();
        for (name, path) in sorted_entries(&proc_dir)? {
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            // A process that ends between the two reads has no entries
            // left: it holds nothing.
            let entries = match sorted_entries(&path) {
                Ok(entries) => entries,
                Err(_) if !path.exists() => continue,
                Err(error) => return Err(error),
            };
            for (entry, _) in entries {
                let Some(gpu_id) = entry
                    .strip_prefix("vram_")
                    .and_then(|id| id.parse::<u32>().ok())
                else {
                    continue;
                };
                if let Some(device_id) = by_kfd_id.get(&gpu_id) {
                    processes.push(GpuComputeProcess {
                        device_id: device_id.clone(),
                        pid: Some(pid),
                    });
                }
            }
        }
        Ok(ComputeProcesses::Listed(processes))
    }
}

impl AmdgpuSysfsProbe {
    /// Every AMD GPU the tree lists, in card order.
    fn devices(&self) -> Result<Vec<AmdgpuDevice>, GpuProbeError> {
        let kfd = self.kfd_topology()?;
        let mut devices = Vec::new();
        for (name, card) in sorted_entries(&self.drm_root)? {
            if !is_card_name(&name) {
                continue;
            }
            let device = card.join("device");
            if attribute(&device.join("vendor"))?.as_deref() != Some(AMD_PCI_VENDOR)
                || driver_name(&device)?.as_deref() != Some(AMDGPU_DRIVER)
            {
                continue;
            }
            let uevent = device.join("uevent");
            let slot = attribute(&uevent)?
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.strip_prefix("PCI_SLOT_NAME="))
                        .map(str::to_ascii_lowercase)
                })
                .ok_or_else(|| GpuProbeError::Unreadable {
                    line: format!("{}: no PCI_SLOT_NAME", uevent.display()),
                })?;
            if slot
                .rsplit_once('.')
                .is_some_and(|(pci_device, _)| kfd.partitioned.contains(pci_device))
            {
                continue;
            }
            let node = kfd.nodes.get(&slot).copied();
            let vram_bytes = optional_byte_count(&device.join("mem_info_vram_total"))?;
            let memory = match (node, vram_bytes) {
                (Some(node), vram) if vram.is_none_or(|vram| node.memory_bytes > vram) => {
                    DeviceMemory::Unified {
                        mib: bytes_to_mib(node.memory_bytes),
                    }
                }
                (_, Some(vram)) => DeviceMemory::Dedicated {
                    mib: bytes_to_mib(vram),
                },
                (None, None) => {
                    return Err(GpuProbeError::Unavailable {
                        reason: format!(
                            "{}: no mem_info_vram_total and no KFD node",
                            device.display()
                        ),
                    });
                }
            };
            let unique_id = optional_attribute(&device.join("unique_id"))?
                .filter(|id| id.bytes().any(|byte| byte != b'0'));
            let serial =
                optional_attribute(&device.join("serial_number"))?.filter(|id| !id.is_empty());
            let (id, id_source) = if let Some(id) = unique_id {
                (id, DeviceIdSource::VendorUuid)
            } else if let Some(serial) = serial {
                (serial, DeviceIdSource::Serial)
            } else if memory.is_unified() {
                (format!("pci-{slot}"), DeviceIdSource::PlatformRegistry)
            } else {
                continue;
            };
            let id = plain_device_id(&id).ok_or_else(|| GpuProbeError::Unreadable {
                line: format!("{}: device id {id:?}", device.display()),
            })?;
            let model = match optional_attribute(&device.join("product_name"))?
                .filter(|product| !product.is_empty())
            {
                Some(product) => product,
                None => match node
                    .and_then(|node| node.gfx_target_version)
                    .and_then(gfx_name)
                {
                    Some(gfx) => gfx,
                    None => format!(
                        "device {}",
                        attribute(&device.join("device"))?.unwrap_or_default()
                    ),
                },
            };
            devices.push(AmdgpuDevice {
                facts: DeviceFacts {
                    id,
                    id_source,
                    kind: DeviceKind::Gpu,
                    vendor: AMD.to_owned(),
                    model,
                    memory,
                    features: node.map(|_| ROCM.to_owned()).into_iter().collect(),
                    // KFD lists every user's processes with a compute
                    // context on the device; without KFD nothing can say who
                    // computes on it.
                    closure: if node.is_some() {
                        DeviceClosure::Closed
                    } else {
                        DeviceClosure::Admitted
                    },
                    state: DeviceState::Offered,
                    max_claimants: 1,
                },
                kfd_gpu_id: node.map(|node| node.gpu_id),
            });
        }
        Ok(devices)
    }

    /// KFD's GPU nodes. None where KFD is not loaded.
    fn kfd_topology(&self) -> Result<KfdTopology, GpuProbeError> {
        let mut topology = KfdTopology::default();
        let mut nodes_per_device: BTreeMap<String, usize> = BTreeMap::new();
        for (_, node) in sorted_entries(&self.kfd_root.join("topology").join("nodes"))? {
            let gpu_id_file = node.join("gpu_id");
            let gpu_id = attribute(&gpu_id_file)?
                .map(|text| {
                    text.parse::<u32>().map_err(|_| GpuProbeError::Unreadable {
                        line: format!("{}: {text}", gpu_id_file.display()),
                    })
                })
                .transpose()?
                .unwrap_or(0);
            // A CPU node has no gpu_id.
            if gpu_id == 0 {
                continue;
            }
            let properties = pairs(&node.join("properties"))?;
            let (Some(&domain), Some(&location)) =
                (properties.get("domain"), properties.get("location_id"))
            else {
                return Err(GpuProbeError::Unreadable {
                    line: format!("{}: no domain or location_id", node.display()),
                });
            };
            // `location_id` is the PCI bus and device-function; a node of
            // a partitioned card has its partition in the function bits.
            let pci_device = format!(
                "{domain:04x}:{:02x}:{:02x}",
                (location >> 8) & 0xff,
                (location >> 3) & 0x1f
            );
            *nodes_per_device.entry(pci_device.clone()).or_default() += 1;
            let mut memory_bytes = 0_u64;
            for (_, bank) in sorted_entries(&node.join("mem_banks"))? {
                let bank = pairs(&bank.join("properties"))?;
                if bank
                    .get("heap_type")
                    .is_some_and(|heap| FRAME_BUFFER_HEAPS.contains(heap))
                {
                    memory_bytes = memory_bytes
                        .saturating_add(bank.get("size_in_bytes").copied().unwrap_or(0));
                }
            }
            topology.nodes.insert(
                format!("{pci_device}.{:x}", location & 0x7),
                KfdNode {
                    gpu_id,
                    memory_bytes,
                    gfx_target_version: properties.get("gfx_target_version").copied(),
                },
            );
        }
        topology.partitioned = nodes_per_device
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(pci_device, _)| pci_device)
            .collect();
        Ok(topology)
    }
}

/// A DRM card's name: `card` and its number, not one of its connectors
/// (`card0-DP-1`).
fn is_card_name(name: &str) -> bool {
    name.strip_prefix("card")
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// The entries of `dir` by name, sorted; none when it does not exist.
fn sorted_entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, GpuProbeError> {
    let unavailable = |error: std::io::Error| GpuProbeError::Unavailable {
        reason: format!("{}: {error}", dir.display()),
    };
    let reader = match std::fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(unavailable(error)),
    };
    let mut entries = Vec::new();
    for entry in reader {
        let entry = entry.map_err(unavailable)?;
        if let Some(name) = entry.file_name().to_str() {
            entries.push((name.to_owned(), entry.path()));
        }
    }
    entries.sort();
    Ok(entries)
}

/// A sysfs attribute's text, trimmed; `None` when the file does not exist.
fn attribute(path: &Path) -> Result<Option<String>, GpuProbeError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(GpuProbeError::Unavailable {
            reason: format!("{}: {error}", path.display()),
        }),
    }
}

/// An attribute that only some devices give, or only root may read (the
/// PCI serial number is `0400`): `None` when this server cannot read it.
fn optional_attribute(path: &Path) -> Result<Option<String>, GpuProbeError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(GpuProbeError::Unavailable {
            reason: format!("{}: {error}", path.display()),
        }),
    }
}

/// An attribute that holds a count of bytes; `None` when the file does not
/// exist.
fn optional_byte_count(path: &Path) -> Result<Option<u64>, GpuProbeError> {
    attribute(path)?
        .map(|text| {
            text.parse().map_err(|_| GpuProbeError::Unreadable {
                line: format!("{}: {text}", path.display()),
            })
        })
        .transpose()
}

/// The name of the driver bound to the PCI device at `device`; `None` when
/// no driver is bound.
fn driver_name(device: &Path) -> Result<Option<String>, GpuProbeError> {
    match std::fs::read_link(device.join("driver")) {
        Ok(target) => Ok(target
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(GpuProbeError::Unavailable {
            reason: format!("{}: {error}", device.join("driver").display()),
        }),
    }
}

/// A KFD `properties` file: one `name value` pair per line.
fn pairs(path: &Path) -> Result<BTreeMap<String, u64>, GpuProbeError> {
    let text = attribute(path)?.ok_or_else(|| GpuProbeError::Unavailable {
        reason: format!("{} does not exist", path.display()),
    })?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split_once(' ')
                .and_then(|(name, value)| Some((name.to_owned(), value.trim().parse().ok()?)))
                .ok_or_else(|| GpuProbeError::Unreadable {
                    line: format!("{}: {line}", path.display()),
                })
        })
        .collect()
}

/// The `gfx` name of a KFD graphics IP version: `110003` is `gfx1103`,
/// `90010` is `gfx90a`. `None` for 0, a node with no graphics IP.
fn gfx_name(version: u64) -> Option<String> {
    (version != 0).then(|| {
        format!(
            "gfx{}{:x}{:x}",
            version / 10_000,
            (version / 100) % 100,
            version % 100
        )
    })
}
