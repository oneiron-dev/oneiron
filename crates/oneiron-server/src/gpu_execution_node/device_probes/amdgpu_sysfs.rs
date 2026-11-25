//! AMD GPUs, read from the `amdgpu` driver's sysfs files: no tool needs to
//! be installed. A device is each `/sys/class/drm/card<N>` whose PCI vendor
//! is AMD and whose driver is `amdgpu`. The KFD compute driver
//! (`/sys/class/kfd/kfd`), where it is loaded, adds what ROCm sees: the
//! device's KFD node, which gives the `rocm` feature, and the processes
//! that hold a compute context on it.
//!
//! The id is the device's own unique id where the driver gives one, else
//! its serial number. A GPU built into the processor (an APU) has neither,
//! and is found by its PCI address, which the platform fixes for a built-in
//! device. A discrete card with neither is not listed: its PCI address
//! changes when the card moves.

use std::collections::BTreeMap;
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
    /// The device's own memory as KFD counts it, in bytes; 0 on a GPU that
    /// has none and shares the machine's memory.
    local_mem_size: Option<u64>,
    /// The device's graphics IP version, `110003` for `gfx1103`.
    gfx_target_version: Option<u64>,
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
        let kfd_nodes = self.kfd_nodes()?;
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
                        .map(str::to_owned)
                })
                .ok_or_else(|| GpuProbeError::Unreadable {
                    line: format!("{}: no PCI_SLOT_NAME", uevent.display()),
                })?;
            let kfd = kfd_nodes.get(&slot.to_ascii_lowercase()).copied();
            let built_in = kfd.is_some_and(|node| node.local_mem_size == Some(0));
            let unique_id = attribute(&device.join("unique_id"))?
                .filter(|id| id.bytes().any(|byte| byte != b'0'));
            let serial = attribute(&device.join("serial_number"))?.filter(|id| !id.is_empty());
            let (id, id_source) = if let Some(id) = unique_id {
                (id, DeviceIdSource::VendorUuid)
            } else if let Some(serial) = serial {
                (serial, DeviceIdSource::Serial)
            } else if built_in {
                (format!("pci-{slot}"), DeviceIdSource::PlatformRegistry)
            } else {
                continue;
            };
            let id = plain_device_id(&id).ok_or_else(|| GpuProbeError::Unreadable {
                line: format!("{}: device id {id:?}", device.display()),
            })?;
            let memory = if built_in {
                DeviceMemory::Unified {
                    mib: bytes_to_mib(byte_count(&device.join("mem_info_gtt_total"))?),
                }
            } else {
                DeviceMemory::Dedicated {
                    mib: bytes_to_mib(byte_count(&device.join("mem_info_vram_total"))?),
                }
            };
            let model = match attribute(&device.join("product_name"))?.filter(|n| !n.is_empty()) {
                Some(product) => product,
                None => match kfd
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
                    features: kfd.map(|_| ROCM.to_owned()).into_iter().collect(),
                    // KFD lists every process with a compute context on the
                    // device; without KFD nothing can say who computes on it.
                    closure: if kfd.is_some() {
                        DeviceClosure::Closed
                    } else {
                        DeviceClosure::Admitted
                    },
                    state: DeviceState::Offered,
                    max_claimants: 1,
                },
                kfd_gpu_id: kfd.map(|node| node.gpu_id),
            });
        }
        Ok(devices)
    }

    /// KFD's GPU nodes by their PCI address (`0000:c4:00.0`). None where
    /// KFD is not loaded.
    fn kfd_nodes(&self) -> Result<BTreeMap<String, KfdNode>, GpuProbeError> {
        let mut nodes = BTreeMap::new();
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
            let properties = kfd_properties(&node.join("properties"))?;
            let (Some(&domain), Some(&location)) =
                (properties.get("domain"), properties.get("location_id"))
            else {
                return Err(GpuProbeError::Unreadable {
                    line: format!("{}: no domain or location_id", node.display()),
                });
            };
            let slot = format!(
                "{domain:04x}:{:02x}:{:02x}.{:x}",
                (location >> 8) & 0xff,
                (location >> 3) & 0x1f,
                location & 0x7
            );
            nodes.insert(
                slot,
                KfdNode {
                    gpu_id,
                    local_mem_size: properties.get("local_mem_size").copied(),
                    gfx_target_version: properties.get("gfx_target_version").copied(),
                },
            );
        }
        Ok(nodes)
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

/// A sysfs attribute that holds a count of bytes.
fn byte_count(path: &Path) -> Result<u64, GpuProbeError> {
    let text = attribute(path)?.ok_or_else(|| GpuProbeError::Unavailable {
        reason: format!("{} does not exist", path.display()),
    })?;
    text.parse().map_err(|_| GpuProbeError::Unreadable {
        line: format!("{}: {text}", path.display()),
    })
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

/// A KFD node's `properties` file: one `name value` pair per line.
fn kfd_properties(path: &Path) -> Result<BTreeMap<String, u64>, GpuProbeError> {
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
