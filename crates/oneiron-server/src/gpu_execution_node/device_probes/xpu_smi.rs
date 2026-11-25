//! Intel GPUs, read through `xpu-smi`, the command-line tool of Intel's XPU
//! Manager: `xpu-smi discovery -j` lists the devices and `xpu-smi discovery
//! -d <device> -j` describes one (key names and types from xpumanager
//! `ial/cmn/cmd_discovery.cpp`).
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

    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError> {
        Ok(ComputeProcesses::NeverListed)
    }
}

/// Reads `xpu-smi discovery -j`: the device number of each device in its
/// `device_list` (`null` when there is none), in the tool's order, leaving
/// out a device in survivability mode.
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
            Ok((text_field(entry, "device_state") != Some(SURVIVABILITY)).then_some(index))
        })
        .filter_map(Result::transpose)
        .collect()
}

/// Reads `xpu-smi discovery -d <device> -j`: the device found by its serial
/// number, else by the UUID oneAPI gives it, with its physical memory as its
/// own. `None` for a device that gives neither: it has no id that survives a
/// reboot. A serial of `unknown`, or of `N/A ...` (the tool may need root to
/// read it), is none.
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
    let (id, id_source) = match (serial, uuid) {
        (Some(serial), _) => (serial, DeviceIdSource::Serial),
        (None, Some(uuid)) => (uuid, DeviceIdSource::VendorUuid),
        (None, None) => return Ok(None),
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
        memory: DeviceMemory::Dedicated {
            mib: bytes_to_mib(memory_bytes),
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
