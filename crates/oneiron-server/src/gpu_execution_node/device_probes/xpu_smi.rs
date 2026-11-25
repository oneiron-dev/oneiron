//! Intel GPUs, read through `xpu-smi`, the command-line tool of Intel's XPU
//! Manager: `xpu-smi discovery -j` lists the devices, `xpu-smi discovery -d
//! <device> -j` describes one, and `xpu-smi ps -j` lists the processes on
//! each. The tool asks the XPU Manager daemon, which runs as root, so its
//! process list holds every user's processes and a device is
//! [`DeviceClosure::Closed`], as under NVIDIA's driver.

use std::collections::BTreeMap;

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};
use serde_json::{Map, Value};

use super::super::device::{GpuComputeProcess, GpuProbeError, plain_device_id, run_device_tool};
use super::{ComputeProcesses, DeviceProbe, bytes_to_mib};

/// XPU Manager's command-line tool.
const XPU_SMI: &str = "xpu-smi";

/// The vendor this probe reports, for people.
const INTEL: &str = "intel";

/// The compute feature every device `xpu-smi` lists offers: oneAPI's Level
/// Zero, which XPU Manager itself reads the device through.
const ONEAPI: &str = "oneapi";

/// The `device_type` of a GPU in the device list.
const GPU_DEVICE_TYPE: &str = "GPU";

/// What a serial number field holds when the device gives none.
const NO_SERIAL: [&str; 3] = ["", "unknown", "N/A"];

/// The probe of this machine's Intel GPUs.
#[derive(Debug, Clone, Copy, Default)]
pub struct XpuSmiProbe;

impl DeviceProbe for XpuSmiProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        Ok(Self::devices()?.into_values().collect())
    }

    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError> {
        let devices = Self::devices()?;
        if devices.is_empty() {
            return Ok(ComputeProcesses::Listed(Vec::new()));
        }
        let ids: BTreeMap<u32, String> = devices
            .into_iter()
            .map(|(index, facts)| (index, facts.id))
            .collect();
        parse_xpu_smi_processes(&run_device_tool(XPU_SMI, &["ps", "-j"])?, &ids)
            .map(ComputeProcesses::Listed)
    }
}

impl XpuSmiProbe {
    /// Each listed GPU with a stable id, by its `xpu-smi` device number.
    fn devices() -> Result<BTreeMap<u32, DeviceFacts>, GpuProbeError> {
        let mut devices = BTreeMap::new();
        for index in parse_xpu_smi_device_list(&run_device_tool(XPU_SMI, &["discovery", "-j"])?)? {
            let detail = run_device_tool(XPU_SMI, &["discovery", "-d", &index.to_string(), "-j"])?;
            if let Some(facts) = parse_xpu_smi_device_detail(&detail)? {
                devices.insert(index, facts);
            }
        }
        Ok(devices)
    }
}

/// Reads `xpu-smi discovery -j`: the device number of each GPU in its
/// `device_list`, in the tool's order.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not that JSON, or an
/// entry with no device number.
pub fn parse_xpu_smi_device_list(text: &str) -> Result<Vec<u32>, GpuProbeError> {
    let report = json(text, "discovery -j")?;
    let entries = report
        .get("device_list")
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable(format!("{XPU_SMI} discovery -j: no device_list")))?;
    entries
        .iter()
        .filter_map(Value::as_object)
        .filter(|entry| {
            entry
                .get("device_type")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == GPU_DEVICE_TYPE)
        })
        .map(|entry| {
            count(entry, "device_id")
                .and_then(|index| u32::try_from(index).ok())
                .ok_or_else(|| unreadable(format!("{XPU_SMI} discovery -j: entry {entry:?}")))
        })
        .collect()
}

/// Reads `xpu-smi discovery -d <device> -j`: the device found by its serial
/// number, else by its UUID, with its physical memory as its own. `None`
/// for a device that gives neither: it has no id that survives a reboot.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not that JSON, or a
/// device with an id but no physical memory size this reader can read.
pub fn parse_xpu_smi_device_detail(text: &str) -> Result<Option<DeviceFacts>, GpuProbeError> {
    let detail = json(text, "discovery -d")?;
    let field = |key: &str| detail.get(key).and_then(Value::as_str).map(str::trim);
    let serial = field("serial_number").filter(|serial| !NO_SERIAL.contains(serial));
    let (id, id_source) = match (serial, field("uuid")) {
        (Some(serial), _) => (serial, DeviceIdSource::Serial),
        (None, Some(uuid)) if !uuid.is_empty() => (uuid, DeviceIdSource::VendorUuid),
        _ => return Ok(None),
    };
    let id = plain_device_id(id)
        .ok_or_else(|| unreadable(format!("{XPU_SMI} discovery -d: device id {id:?}")))?;
    let memory_bytes = count(&detail, "memory_physical_size_byte").ok_or_else(|| {
        unreadable(format!(
            "{XPU_SMI} discovery -d: memory_physical_size_byte {:?}",
            detail.get("memory_physical_size_byte")
        ))
    })?;
    Ok(Some(DeviceFacts {
        id,
        id_source,
        kind: DeviceKind::Gpu,
        vendor: INTEL.to_owned(),
        model: field("device_name")
            .filter(|name| !name.is_empty())
            .unwrap_or("Intel GPU")
            .to_owned(),
        memory: DeviceMemory::Dedicated {
            mib: bytes_to_mib(memory_bytes),
        },
        features: vec![ONEAPI.to_owned()],
        closure: DeviceClosure::Closed,
        state: DeviceState::Offered,
        max_claimants: 1,
    }))
}

/// Reads `xpu-smi ps -j`: each process on a device of `device_ids` (by
/// `xpu-smi` device number). A process on a device not among them is not
/// this probe's to report.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not that JSON, or an
/// entry with no device number or process id.
pub fn parse_xpu_smi_processes(
    text: &str,
    device_ids: &BTreeMap<u32, String>,
) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
    let report = json(text, "ps -j")?;
    let entries = report
        .get("device_util_by_proc_list")
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable(format!("{XPU_SMI} ps -j: no device_util_by_proc_list")))?;
    let mut processes = Vec::new();
    for entry in entries.iter().filter_map(Value::as_object) {
        let (Some(index), Some(pid)) = (count(entry, "device_id"), count(entry, "process_id"))
        else {
            return Err(unreadable(format!("{XPU_SMI} ps -j: entry {entry:?}")));
        };
        let device = u32::try_from(index)
            .ok()
            .and_then(|index| device_ids.get(&index));
        if let Some(device_id) = device {
            processes.push(GpuComputeProcess {
                device_id: device_id.clone(),
                pid: u32::try_from(pid).ok(),
            });
        }
    }
    Ok(processes)
}

/// The tool's answer as a JSON object.
fn json(text: &str, query: &str) -> Result<Map<String, Value>, GpuProbeError> {
    match serde_json::from_str(text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(unreadable(format!("{XPU_SMI} {query}: not a JSON object"))),
        Err(error) => Err(unreadable(format!("{XPU_SMI} {query}: {error}"))),
    }
}

/// A count the tool writes as a JSON number or as a string of digits.
fn count(entry: &Map<String, Value>, key: &str) -> Option<u64> {
    match entry.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn unreadable(line: String) -> GpuProbeError {
    GpuProbeError::Unreadable { line }
}
