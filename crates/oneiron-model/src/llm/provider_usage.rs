//! Provider-reported token measurements, kept apart from budget charges and
//! the normalized usage counters that use zero when a field was not reported.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::LlmUsage;

const MEASUREMENT_KEY: &str = "provider_token_measurement";

/// Counts the native adapter actually read from a provider report. Missing is
/// unknown; `Some(0)` is a reported zero. This does not prove that every physical
/// request in a run or spend scope has been measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTokenMeasurement {
    pub input: Option<u64>,
    pub output: Option<u64>,
}

impl ProviderTokenMeasurement {
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.input.is_none() && self.output.is_none()
    }
}

impl LlmUsage {
    /// Stamps parse-time evidence in the existing provider-usage carrier. The
    /// reserved key is replaced even when no counts were measured, so an
    /// external provider's same-named field cannot supply this observation.
    /// A non-object carrier has no place to store evidence and remains unknown.
    pub fn set_provider_token_measurement(&mut self, measurement: ProviderTokenMeasurement) {
        let Some(raw) = self.raw_provider.as_object_mut() else {
            return;
        };
        // An explicit unknown also shadows any provider-supplied imitation
        // of the ladder's nested usage wrapper.
        if measurement.is_empty() {
            raw.insert(MEASUREMENT_KEY.to_owned(), Value::Null);
            return;
        }
        let mut counts = Map::new();
        counts.insert(
            "input".to_owned(),
            measurement.input.map_or(Value::Null, Value::from),
        );
        counts.insert(
            "output".to_owned(),
            measurement.output.map_or(Value::Null, Value::from),
        );
        raw.insert(MEASUREMENT_KEY.to_owned(), Value::Object(counts));
    }

    /// Reads only the typed evidence a producer stamped, directly or inside
    /// the native ladder's served-usage wrapper. Ordinary provider JSON and
    /// normalized usage totals are not measurement-presence evidence.
    #[must_use]
    pub fn provider_token_measurement(&self) -> Option<ProviderTokenMeasurement> {
        let raw = self.raw_provider.get(MEASUREMENT_KEY).or_else(|| {
            self.raw_provider.get("rung").filter(|rung| rung.is_u64())?;
            self.raw_provider.get("usage")?.get(MEASUREMENT_KEY)
        })?;
        serde_json::from_value::<ProviderTokenMeasurement>(raw.clone())
            .ok()
            .filter(|measurement| !measurement.is_empty())
    }
}
