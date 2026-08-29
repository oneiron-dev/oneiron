//! Which way the far end is leaving the machine.
//!
//! The route is the only thing that tells the recorder whether an acoustic
//! echo path exists at all, so the detection is deliberately conservative: a
//! route is [`OutputRoute::Headphones`] only when the HAL says the output is a
//! headphone data source. Anything the HAL leaves ambiguous — Bluetooth, an
//! external interface, a failed query — is [`OutputRoute::Other`], because
//! claiming an isolated route we could not confirm would put a false
//! `bypassed_headphones` on real audio.

/// Where the machine's output is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputRoute {
    /// Output is on headphones: nothing it plays reaches the microphone.
    Headphones,
    /// Output is on speakers the microphone can hear.
    Speakers,
    /// Anything else, including "the HAL would not say".
    Other,
}

impl OutputRoute {
    /// The route's name, for the window and the segment list.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Headphones => "headphones",
            Self::Speakers => "speakers",
            Self::Other => "other",
        }
    }
}

/// Where a capture gets its route from. A capture asks once per segment
/// boundary; a test hands over a fixed answer.
pub trait RouteSource: Send + Sync {
    /// The route right now.
    fn output_route(&self) -> OutputRoute;
}

/// The live system route.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRoute;

impl RouteSource for SystemRoute {
    fn output_route(&self) -> OutputRoute {
        detect().unwrap_or(OutputRoute::Other)
    }
}

/// A fixed route, for wiring a capture whose route is already known.
#[derive(Debug, Clone, Copy)]
pub struct FixedRoute(pub OutputRoute);

impl RouteSource for FixedRoute {
    fn output_route(&self) -> OutputRoute {
        self.0
    }
}

#[cfg(target_os = "macos")]
fn detect() -> super::Result<OutputRoute> {
    use objc2_core_audio::{
        AudioObjectID, kAudioDevicePropertyDataSource, kAudioDevicePropertyTransportType,
        kAudioDeviceTransportTypeBuiltIn, kAudioHardwarePropertyDefaultOutputDevice,
        kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyScopeOutput, kAudioObjectSystemObject,
    };

    use super::hal::{address, read_property};

    /// `'hdpn'` — the HAL's data-source id for a headphone output. The binding
    /// crate does not export the data-source vocabulary; these are the stable
    /// four-character codes from the Core Audio headers.
    const DATA_SOURCE_HEADPHONES: u32 = u32::from_be_bytes(*b"hdpn");
    /// `'ispk'` — the internal speaker.
    const DATA_SOURCE_INTERNAL_SPEAKER: u32 = u32::from_be_bytes(*b"ispk");

    let system = AudioObjectID::try_from(kAudioObjectSystemObject).unwrap_or_default();
    let device: AudioObjectID = read_property(
        system,
        address(
            kAudioHardwarePropertyDefaultOutputDevice,
            kAudioObjectPropertyScopeGlobal,
        ),
        "kAudioHardwarePropertyDefaultOutputDevice",
    )?;

    // The data source is the specific answer ("this built-in device is
    // currently driving the headphone jack"); not every device has one.
    let data_source: Option<u32> = read_property::<u32>(
        device,
        address(
            kAudioDevicePropertyDataSource,
            kAudioObjectPropertyScopeOutput,
        ),
        "kAudioDevicePropertyDataSource",
    )
    .ok();
    match data_source {
        Some(DATA_SOURCE_HEADPHONES) => return Ok(OutputRoute::Headphones),
        Some(DATA_SOURCE_INTERNAL_SPEAKER) => return Ok(OutputRoute::Speakers),
        _ => {}
    }

    // No data source: a built-in device with none is the internal speaker.
    // Everything else stays `Other` — see the module note on why.
    let transport: u32 = read_property(
        device,
        address(
            kAudioDevicePropertyTransportType,
            kAudioObjectPropertyScopeGlobal,
        ),
        "kAudioDevicePropertyTransportType",
    )?;
    if transport == kAudioDeviceTransportTypeBuiltIn {
        return Ok(OutputRoute::Speakers);
    }
    Ok(OutputRoute::Other)
}

/// Output-route detection is a macOS HAL facility. On any other host the route
/// is simply unknown, and unknown is `Other` — the recorder never guesses its
/// way to a bypass.
#[cfg(not(target_os = "macos"))]
fn detect() -> super::Result<OutputRoute> {
    Ok(OutputRoute::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_route_answers_with_itself() {
        assert_eq!(
            FixedRoute(OutputRoute::Headphones).output_route(),
            OutputRoute::Headphones
        );
    }

    #[test]
    fn every_route_has_a_label() {
        for route in [
            OutputRoute::Headphones,
            OutputRoute::Speakers,
            OutputRoute::Other,
        ] {
            assert!(!route.label().is_empty());
        }
    }
}
