//! AMD GPUs, read from the `amdgpu` driver's sysfs files: no tool needs to
//! be installed (`rocm-smi` is deprecated, and `amd-smi` reads the same
//! driver). A device is each `/sys/class/drm/card<N>` whose PCI vendor is
//! AMD and whose driver is `amdgpu`. The KFD compute driver
//! (`/sys/class/kfd/kfd`), where it is loaded, adds what ROCm sees: the
//! device's KFD node (found by its DRM render node), which gives the `rocm`
//! feature, the memory ROCm allocates on it, and the processes that hold a
//! compute context on it.
//!
//! Memory: the device's own VRAM (`mem_info_vram_total`), unless KFD gives
//! it more memory than that VRAM, or the driver keeps no VRAM for it. That
//! is a GPU built into the processor (an APU) whose compute memory is the
//! machine's own (the driver's GTT pool): [`DeviceMemory::Unified`], with
//! the memory KFD reports. An APU whose firmware reserves a carve-out large
//! enough that KFD allocates from it alone reads as dedicated memory of
//! that carve-out, which the machine's own memory does not hold.
//!
//! The id is the device's unique id (the driver's `unique_id`, else KFD's,
//! one value in one form), else its serial number. A built-in GPU with
//! neither is found by its PCI address, which the platform fixes for a
//! built-in device. A discrete card with neither is not listed: its PCI
//! address changes when the card moves. Nor is a device whose serial only
//! root may read (it would change id with the server's account), a device
//! whose id another device repeats, or a card split into compute
//! partitions, which KFD lists as further nodes on the card's PCI device:
//! each partition would be a device of its own.
//!
//! Processes: KFD lists every user's process that holds a compute context
//! on a device, so a device KFD lists is [`DeviceClosure::Closed`], to the
//! same measure as `nvidia-smi`'s compute list: a process that reaches the
//! GPU only through a graphics API (Vulkan on the render node), never
//! opening KFD, is in neither list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};

use super::super::device::{GpuComputeProcess, GpuProbeError, plain_device_id};
use super::{ComputeProcesses, DeviceProbe, bytes_to_mib, not_found};

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
    /// The device's unique id, 0 when it has none.
    unique_id: u64,
}

/// KFD's GPU nodes.
#[derive(Debug, Default)]
struct KfdTopology {
    /// Each node by its DRM render minor (`/dev/dri/renderD<minor>`).
    by_render_minor: BTreeMap<u64, KfdNode>,
    /// Each node's PCI device (domain, bus and device number, without the
    /// function, where KFD writes a partition) and render minor.
    pci_devices: Vec<(String, u64)>,
}

/// An AMD card's PCI device directory and what finds it in KFD.
#[derive(Debug)]
struct AmdgpuCard {
    device: PathBuf,
    /// Its PCI address, `0000:c4:00.0`.
    slot: String,
    /// The minors of its render nodes.
    render_minors: Vec<u64>,
}

/// One AMD GPU as this probe read it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AmdgpuDevice {
    facts: DeviceFacts,
    /// Its KFD id, when KFD lists the device.
    kfd_gpu_id: Option<u32>,
}

/// A sysfs attribute as this server could read it.
enum Attribute {
    Text(String),
    Absent,
    /// Only another account (root) may read it.
    Denied,
}

impl DeviceProbe for AmdgpuSysfsProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        Ok(self
            .devices()?
            .into_iter()
            .map(|device| device.facts)
            .collect())
    }

    fn processes_on(&self, device_id: &str) -> Result<ComputeProcesses, GpuProbeError> {
        let device = self
            .devices()?
            .into_iter()
            .find(|device| device.facts.id == device_id)
            .ok_or_else(|| not_found(device_id))?;
        let Some(gpu_id) = device.kfd_gpu_id else {
            return Ok(ComputeProcesses::NeverListed);
        };
        let context_file = format!("vram_{gpu_id}");
        let mut processes = Vec::new();
        for (name, path) in entries(&self.kfd_root.join("proc"))? {
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            // A process that ended since the directory was read holds
            // nothing.
            match std::fs::symlink_metadata(path.join(&context_file)) {
                Ok(_) => processes.push(GpuComputeProcess {
                    device_id: device_id.to_owned(),
                    pid: Some(pid),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(GpuProbeError::Unavailable {
                        reason: format!("{}: {error}", path.join(&context_file).display()),
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
        let cards = self.cards()?;
        let card_minors: BTreeSet<u64> = cards
            .iter()
            .flat_map(|card| card.render_minors.iter().copied())
            .collect();
        // A KFD node on a card's PCI device whose render node is no card's
        // is a partition of that card.
        let partitioned: BTreeSet<&str> = kfd
            .pci_devices
            .iter()
            .filter(|(_, minor)| !card_minors.contains(minor))
            .map(|(pci_device, _)| pci_device.as_str())
            .collect();
        let mut devices = Vec::new();
        for card in &cards {
            if partitioned.contains(pci_device(&card.slot)) {
                continue;
            }
            if let Some(device) = Self::device(card, &kfd)? {
                devices.push(device);
            }
        }
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for device in &devices {
            *seen.entry(device.facts.id.clone()).or_default() += 1;
        }
        devices.retain(|device| seen.get(&device.facts.id) == Some(&1));
        Ok(devices)
    }

    /// `card` as a device; `None` when it has no id that survives a reboot
    /// or no memory this probe can size.
    fn device(card: &AmdgpuCard, kfd: &KfdTopology) -> Result<Option<AmdgpuDevice>, GpuProbeError> {
        let device = &card.device;
        let node = card
            .render_minors
            .iter()
            .find_map(|minor| kfd.by_render_minor.get(minor))
            .copied();
        let vram_bytes = byte_count(&device.join("mem_info_vram_total"))?;
        let memory = match (node, vram_bytes) {
            (Some(node), vram)
                if node.memory_bytes > 0 && vram.is_none_or(|vram| node.memory_bytes > vram) =>
            {
                DeviceMemory::Unified {
                    mib: bytes_to_mib(node.memory_bytes),
                }
            }
            (_, Some(vram)) => DeviceMemory::Dedicated {
                mib: bytes_to_mib(vram),
            },
            (_, None) => return Ok(None),
        };
        let unique_id = match read_attribute(&device.join("unique_id"))? {
            Attribute::Text(id) if has_value(&id) => Some(id.to_ascii_lowercase()),
            _ => node
                .map(|node| node.unique_id)
                .filter(|id| *id != 0)
                .map(|id| format!("{id:016x}")),
        };
        let (id, id_source) = match (unique_id, read_attribute(&device.join("serial_number"))?) {
            (Some(id), _) => (id, DeviceIdSource::VendorUuid),
            (None, Attribute::Text(serial)) if has_value(&serial) => {
                (serial, DeviceIdSource::Serial)
            }
            (None, Attribute::Denied) => return Ok(None),
            (None, _) if memory.is_unified() => (
                format!("pci-{}", card.slot),
                DeviceIdSource::PlatformRegistry,
            ),
            (None, _) => return Ok(None),
        };
        let id = plain_device_id(&id).ok_or_else(|| GpuProbeError::Unreadable {
            line: format!("{}: device id {id:?}", device.display()),
        })?;
        let model = match read_attribute(&device.join("product_name"))? {
            Attribute::Text(product) if !product.is_empty() => product,
            _ => match node
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
        Ok(Some(AmdgpuDevice {
            facts: DeviceFacts {
                id,
                id_source,
                kind: DeviceKind::Gpu,
                vendor: AMD.to_owned(),
                model,
                memory,
                features: node.map(|_| ROCM.to_owned()).into_iter().collect(),
                closure: if node.is_some() {
                    DeviceClosure::Closed
                } else {
                    DeviceClosure::Admitted
                },
                state: DeviceState::Offered,
                max_claimants: 1,
            },
            kfd_gpu_id: node.map(|node| node.gpu_id),
        }))
    }

    /// The DRM cards bound to `amdgpu` with AMD's vendor id, in card order.
    fn cards(&self) -> Result<Vec<AmdgpuCard>, GpuProbeError> {
        let mut cards = Vec::new();
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
            let render_minors = sorted_entries(&device.join("drm"))?
                .into_iter()
                .filter_map(|(name, _)| name.strip_prefix("renderD")?.parse().ok())
                .collect();
            cards.push(AmdgpuCard {
                device,
                slot,
                render_minors,
            });
        }
        Ok(cards)
    }

    /// KFD's GPU nodes. None where KFD is not loaded.
    fn kfd_topology(&self) -> Result<KfdTopology, GpuProbeError> {
        let mut topology = KfdTopology::default();
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
            let (Some(&domain), Some(&location), Some(&render_minor)) = (
                properties.get("domain"),
                properties.get("location_id"),
                properties.get("drm_render_minor"),
            ) else {
                return Err(GpuProbeError::Unreadable {
                    line: format!(
                        "{}: no domain, location_id or drm_render_minor",
                        node.display()
                    ),
                });
            };
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
            // `location_id` is the PCI bus and device-function.
            topology.pci_devices.push((
                format!(
                    "{domain:04x}:{:02x}:{:02x}",
                    (location >> 8) & 0xff,
                    (location >> 3) & 0x1f
                ),
                render_minor,
            ));
            topology.by_render_minor.insert(
                render_minor,
                KfdNode {
                    gpu_id,
                    memory_bytes,
                    gfx_target_version: properties.get("gfx_target_version").copied(),
                    unique_id: properties.get("unique_id").copied().unwrap_or(0),
                },
            );
        }
        Ok(topology)
    }
}

/// A PCI address without its function: `0000:c4:00` of `0000:c4:00.0`.
fn pci_device(slot: &str) -> &str {
    slot.rsplit_once('.').map_or(slot, |(device, _)| device)
}

/// An id that holds a value: not empty, not only zeros (and the dashes
/// between them).
fn has_value(id: &str) -> bool {
    id.bytes().any(|byte| byte != b'0' && byte != b'-')
}

/// A DRM card's name: `card` and its number, not one of its connectors
/// (`card0-DP-1`).
fn is_card_name(name: &str) -> bool {
    name.strip_prefix("card")
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// The entries of `dir` by name, sorted. A directory that is not there is
/// an error.
fn entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, GpuProbeError> {
    let unavailable = |error: std::io::Error| GpuProbeError::Unavailable {
        reason: format!("{}: {error}", dir.display()),
    };
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(unavailable)? {
        let entry = entry.map_err(unavailable)?;
        if let Some(name) = entry.file_name().to_str() {
            entries.push((name.to_owned(), entry.path()));
        }
    }
    entries.sort();
    Ok(entries)
}

/// The entries of `dir` by name, sorted; none when it does not exist.
fn sorted_entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, GpuProbeError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    entries(dir)
}

/// A sysfs attribute's text, trimmed.
fn read_attribute(path: &Path) -> Result<Attribute, GpuProbeError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Attribute::Text(text.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Attribute::Absent),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(Attribute::Denied),
        Err(error) => Err(GpuProbeError::Unavailable {
            reason: format!("{}: {error}", path.display()),
        }),
    }
}

/// An attribute every reader may read: `None` when the file does not
/// exist.
fn attribute(path: &Path) -> Result<Option<String>, GpuProbeError> {
    match read_attribute(path)? {
        Attribute::Text(text) => Ok(Some(text)),
        Attribute::Absent => Ok(None),
        Attribute::Denied => Err(GpuProbeError::Unavailable {
            reason: format!("{}: permission denied", path.display()),
        }),
    }
}

/// An attribute that holds a count of bytes; `None` when the file does not
/// exist.
fn byte_count(path: &Path) -> Result<Option<u64>, GpuProbeError> {
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
