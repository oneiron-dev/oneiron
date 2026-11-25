//! The GPU built into a Mac with Apple silicon, read through
//! `system_profiler -json SPDisplaysDataType SPHardwareDataType` (macOS only;
//! elsewhere the tool does not start and the probe answers
//! [`GpuProbeError::Unavailable`]).
//!
//! The GPU shares the machine's memory, so it reports
//! [`DeviceMemory::Unified`] with the machine's physical memory. It has no
//! serial or UUID of its own: being built in, it is found by the platform's
//! fixed registry id, the machine's platform UUID. macOS lists no process
//! by the GPU it computes on, so the probe never lists processes
//! ([`ComputeProcesses::NeverListed`]) and every Apple GPU is
//! [`DeviceClosure::Admitted`].

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};
use serde_json::{Map, Value};

use super::super::device::{GpuProbeError, plain_device_id, run_device_tool};
use super::{ComputeProcesses, DeviceProbe};

/// The macOS hardware report tool.
const SYSTEM_PROFILER: &str = "system_profiler";

/// The report's section listing graphics devices.
const DISPLAYS: &str = "SPDisplaysDataType";

/// The report's section describing the machine.
const HARDWARE: &str = "SPHardwareDataType";

/// The `sppci_device_type` of a GPU row.
const GPU_DEVICE_TYPE: &str = "spdisplays_gpu";

/// The `spdisplays_vendor` of a GPU Apple made: the only rows this probe
/// reads. A Mac with an Intel processor reports its other GPUs under other
/// vendors; this probe does not list them.
const APPLE_VENDOR: &str = "sppci_vendor_Apple";

/// The vendor this probe reports, for people.
const APPLE: &str = "apple";

/// The compute feature every Apple GPU offers.
const METAL: &str = "metal";

/// The probe of a Mac's built-in Apple GPU.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProfilerProbe;

impl DeviceProbe for SystemProfilerProbe {
    fn list(&self) -> Result<Vec<DeviceFacts>, GpuProbeError> {
        parse_system_profiler_devices(&run_device_tool(
            SYSTEM_PROFILER,
            &["-json", DISPLAYS, HARDWARE],
        )?)
    }

    fn processes(&self) -> Result<ComputeProcesses, GpuProbeError> {
        Ok(ComputeProcesses::NeverListed)
    }
}

/// Reads `system_profiler -json SPDisplaysDataType SPHardwareDataType`:
/// one device per Apple GPU row, in the report's order, found by the
/// machine's `platform_UUID` and its place among those rows (`<uuid>-gpu0`),
/// with the machine's `physical_memory` as unified memory. A report with no
/// Apple GPU row lists none; a machine with no platform UUID offers none,
/// since its GPU has no id that survives a reboot.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for output that is not the JSON report, a
/// report without the displays section, or, beside an Apple GPU row, no
/// hardware section or a physical memory figure this reader cannot read.
pub fn parse_system_profiler_devices(text: &str) -> Result<Vec<DeviceFacts>, GpuProbeError> {
    let unreadable = |line: String| GpuProbeError::Unreadable { line };
    let report: Value = serde_json::from_str(text)
        .map_err(|error| unreadable(format!("{SYSTEM_PROFILER} -json: {error}")))?;
    let rows = report
        .get(DISPLAYS)
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable(format!("{SYSTEM_PROFILER} -json: no {DISPLAYS} list")))?;
    let apple_gpus: Vec<&Map<String, Value>> = rows
        .iter()
        .filter_map(Value::as_object)
        .filter(|row| {
            text_field(row, "sppci_device_type") == Some(GPU_DEVICE_TYPE)
                && text_field(row, "spdisplays_vendor") == Some(APPLE_VENDOR)
        })
        .collect();
    if apple_gpus.is_empty() {
        return Ok(Vec::new());
    }
    let machine = report
        .get(HARDWARE)
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .ok_or_else(|| unreadable(format!("{SYSTEM_PROFILER} -json: no {HARDWARE} entry")))?;
    let Some(platform_id) = text_field(machine, "platform_UUID").and_then(plain_device_id) else {
        return Ok(Vec::new());
    };
    let memory_text = text_field(machine, "physical_memory").unwrap_or_default();
    let memory_mib = memory_mib(memory_text)
        .ok_or_else(|| unreadable(format!("{HARDWARE}.physical_memory: {memory_text}")))?;
    Ok(apple_gpus
        .into_iter()
        .enumerate()
        .map(|(place, row)| DeviceFacts {
            id: format!("{platform_id}-gpu{place}"),
            id_source: DeviceIdSource::PlatformRegistry,
            kind: DeviceKind::Gpu,
            vendor: APPLE.to_owned(),
            model: text_field(row, "sppci_model")
                .or_else(|| text_field(row, "_name"))
                .unwrap_or("Apple GPU")
                .to_owned(),
            memory: DeviceMemory::Unified { mib: memory_mib },
            features: vec![METAL.to_owned()],
            closure: DeviceClosure::Admitted,
            state: DeviceState::Offered,
            max_claimants: 1,
        })
        .collect())
}

/// A field of a report row that holds text.
fn text_field<'row>(row: &'row Map<String, Value>, key: &str) -> Option<&'row str> {
    row.get(key).and_then(Value::as_str)
}

/// A memory figure as `system_profiler` writes it (`64 GB`, `512 MB`,
/// `1 TB`; binary units) in MiB; `None` for any other form.
fn memory_mib(text: &str) -> Option<u64> {
    let mut parts = text.split_whitespace();
    let (Some(count), Some(unit), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let per_unit: u64 = match unit {
        "MB" => 1,
        "GB" => 1024,
        "TB" => 1024 * 1024,
        _ => return None,
    };
    count.parse::<u64>().ok()?.checked_mul(per_unit)
}
