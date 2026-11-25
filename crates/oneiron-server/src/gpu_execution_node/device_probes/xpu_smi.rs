//! Intel GPUs, read through `xpu-smi`, the command-line tool of Intel's XPU
//! Manager: `xpu-smi discovery -j` lists the devices and `xpu-smi discovery
//! -d <device> -j` describes one (key names, JSON types and the
//! `device_type` values from xpumanager `ial/cmn/cmd_discovery.cpp`).
//!
//! Only a device the tool reached through Level Zero, the oneAPI compute
//! runtime, is listed: its `device_type` is `Discrete GPU` or `Integrated
//! GPU`. A device the tool found only through its management interface
//! (`device_type` empty, as when Level Zero cannot start on it) cannot take
//! oneAPI work. An integrated GPU computes in the machine's own memory, so
//! it is [`DeviceMemory::Unified`].
//!
//! The process list the tool can give (`xpu-smi ps`) reads `/proc/<pid>/fdinfo`,
//! which shows another user's processes only to a caller with ptrace rights
//! over them: run as an ordinary account it can miss a process. So this
//! probe never lists processes ([`ComputeProcesses::NeverListed`]), and
//! every Intel GPU is [`DeviceClosure::Admitted`].

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};
use serde_json::{Map, Value};

use super::super::device::{GpuProbeError, plain_device_id, run_device_tool};
use super::{ComputeProcesses, DeviceProbe, bytes_to_mib};

/// XPU Manager's command-line tool.
const XPU_SMI: &str = "xpu-smi";

/// The vendor this probe reports, for people.
const INTEL: &str = "intel";

/// The compute feature every device `xpu-smi` lists offers: oneAPI's Level
/// Zero, through which the tool itself reads the device.
const ONEAPI: &str = "oneapi";

/// The `device_state` of a device in survivability mode: it runs only its
/// firmware recovery, no work.
const SURVIVABILITY: &str = "survivability mode";

/// The `device_type` of a discrete GPU Level Zero reached.
const DISCRETE_GPU: &str = "Discrete GPU";

/// The `device_type` of an integrated GPU Level Zero reached.
const INTEGRATED_GPU: &str = "Integrated GPU";

/// The probe of this machine's Intel GPUs.
#[derive(Debug, Clone, Copy, Default)]
pub struct XpuSmiProbe;

impl DeviceProbe for XpuSmiProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        let mut devices = Vec::new();
        for index in parse_xpu_smi_device_list(&run_device_tool(XPU_SMI, &["discovery", "-j"])?)? {
            let detail = run_device_tool(XPU_SMI, &["discovery", "-d", &index.to_string(), "-j"])?;
            devices.extend(parse_xpu_smi_device_detail(&detail)?);
        }
        Ok(devices)
    }

    fn processes_on(&self, _device_id: &str) -> Result<ComputeProcesses, GpuProbeError> {
        Ok(ComputeProcesses::NeverListed)
    }
}

/// Reads `xpu-smi discovery -j`: the device number of each GPU in its
/// `device_list` (`null` when there is none) that Level Zero reached, in
/// the tool's order. A device in survivability mode or found only through
/// the management interface is left out.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not that JSON, or an
/// entry with no device number.
pub fn parse_xpu_smi_device_list(text: &str) -> Result<Vec<u32>, GpuProbeError> {
    let report = json(text, "discovery -j")?;
    let entries: &[Value] = match report.get("device_list") {
        Some(Value::Array(entries)) => entries.as_slice(),
        Some(Value::Null) => &[],
        _ => {
            return Err(unreadable(format!(
                "{XPU_SMI} discovery -j: no device_list"
            )));
        }
    };
    entries
        .iter()
        .map(|entry| {
            let entry = entry
                .as_object()
                .ok_or_else(|| unreadable(format!("{XPU_SMI} discovery -j: entry {entry}")))?;
            let index = count(entry, "device_id")
                .and_then(|index| u32::try_from(index).ok())
                .ok_or_else(|| unreadable(format!("{XPU_SMI} discovery -j: entry {entry:?}")))?;
            let computes = text_field(entry, "device_state") != Some(SURVIVABILITY)
                && matches!(
                    text_field(entry, "device_type"),
                    Some(DISCRETE_GPU | INTEGRATED_GPU)
                );
            Ok(computes.then_some(index))
        })
        .filter_map(Result::transpose)
        .collect()
}

/// Reads `xpu-smi discovery -d <device> -j`: the device found by the UUID
/// Level Zero gives it, else by its serial number, with its physical memory:
/// its own on a discrete GPU, the machine's on an integrated one. `None` for
/// a device that gives neither id, which has none that survives a reboot,
/// or that Level Zero did not reach. A serial of `unknown`, or of `N/A ...`
/// (the tool may need root to read it), is none. The UUID comes first: every
/// account reads the same one, so the id does not change with the server's
/// account.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not that JSON, or a
/// device with an id but no physical memory size this reader can read.
pub fn parse_xpu_smi_device_detail(text: &str) -> Result<Option<DeviceFacts>, GpuProbeError> {
    let detail = json(text, "discovery -d")?;
    let serial = text_field(&detail, "serial_number")
        .map(str::trim)
        .filter(|serial| {
            !serial.is_empty()
                && !serial.eq_ignore_ascii_case("unknown")
                && !serial.starts_with("N/A")
        });
    let uuid = text_field(&detail, "uuid")
        .map(str::trim)
        .filter(|uuid| !uuid.is_empty());
    let (id, id_source) = match (uuid, serial) {
        (Some(uuid), _) => (uuid, DeviceIdSource::VendorUuid),
        (None, Some(serial)) => (serial, DeviceIdSource::Serial),
        (None, None) => return Ok(None),
    };
    let integrated = match text_field(&detail, "device_type") {
        Some(DISCRETE_GPU) => false,
        Some(INTEGRATED_GPU) => true,
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
        model: text_field(&detail, "device_name")
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("Intel GPU")
            .to_owned(),
        memory: if integrated {
            DeviceMemory::Unified {
                mib: bytes_to_mib(memory_bytes),
            }
        } else {
            DeviceMemory::Dedicated {
                mib: bytes_to_mib(memory_bytes),
            }
        },
        features: vec![ONEAPI.to_owned()],
        closure: DeviceClosure::Admitted,
        state: DeviceState::Offered,
        max_claimants: 1,
    }))
}

/// The tool's answer as a JSON object.
fn json(text: &str, query: &str) -> Result<Map<String, Value>, GpuProbeError> {
    match serde_json::from_str(text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(unreadable(format!("{XPU_SMI} {query}: not a JSON object"))),
        Err(error) => Err(unreadable(format!("{XPU_SMI} {query}: {error}"))),
    }
}

/// A field that holds text.
fn text_field<'entry>(entry: &'entry Map<String, Value>, key: &str) -> Option<&'entry str> {
    entry.get(key).and_then(Value::as_str)
}

/// A count the tool writes as a JSON number, or as a string of digits when
/// it does not fit a signed 64-bit integer.
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
