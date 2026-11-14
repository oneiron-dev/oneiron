//! Moved from `crates/oneiron/src/gate/voice_serving.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;

pub const FIELDS: [&str; 7] = [
    "max_text_bytes",
    "max_ref_bytes",
    "max_queued_renders",
    "max_inflight_uploads",
    "upload_read_deadline_ms",
    "http_deadline_ms",
    "max_header_bytes",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceServingLimits {
    pub max_text_bytes: u64,
    pub max_ref_bytes: u64,
    pub max_queued_renders: u64,
    pub max_inflight_uploads: u64,
    pub upload_read_deadline_ms: u64,
    pub http_deadline_ms: u64,
    pub max_header_bytes: u64,
}

impl VoiceServingLimits {
    pub const DEFAULT: Self = Self {
        max_text_bytes: 8 * 1024,
        max_ref_bytes: 16 * 1024 * 1024,
        max_queued_renders: 16,
        max_inflight_uploads: 2,
        upload_read_deadline_ms: 5_000,
        http_deadline_ms: 45_000,
        max_header_bytes: 32_768,
    };

    fn values(self) -> [u64; 7] {
        [
            self.max_text_bytes,
            self.max_ref_bytes,
            self.max_queued_renders,
            self.max_inflight_uploads,
            self.upload_read_deadline_ms,
            self.http_deadline_ms,
            self.max_header_bytes,
        ]
    }

    fn from_values(v: [u64; 7]) -> Self {
        Self {
            max_text_bytes: v[0],
            max_ref_bytes: v[1],
            max_queued_renders: v[2],
            max_inflight_uploads: v[3],
            upload_read_deadline_ms: v[4],
            http_deadline_ms: v[5],
            max_header_bytes: v[6],
        }
    }

    /// Structural/wire checks only. Operational limits and deadlines are
    /// authored by the trusted manifest, with shipped defaults and narrowing.
    pub fn valid(self) -> bool {
        self.values().iter().all(|n| *n > 0)
            && self.max_ref_bytes >= 12
            && self.max_header_bytes <= u64::from(u32::MAX) // 4-byte wire header
            && self.max_text_bytes <= usize::MAX as u64
            && self.max_ref_bytes <= usize::MAX as u64
            && self.max_queued_renders <= usize::MAX as u64
            && self.max_inflight_uploads <= usize::MAX as u64
            && self.max_ref_bytes.checked_add(self.max_header_bytes)
                .and_then(|n| n.checked_add(4))
                .is_some_and(|n| n <= usize::MAX as u64)
            && self.upload_read_deadline_ms <= self.http_deadline_ms
    }

    pub fn narrow(self, other: Self) -> Self {
        let a = self.values();
        let b = other.values();
        Self::from_values(std::array::from_fn(|i| a[i].min(b[i])))
    }

    pub fn within(self, ceiling: Self) -> bool {
        self.values()
            .into_iter()
            .zip(ceiling.values())
            .all(|(a, b)| a <= b)
    }

    pub fn encode(self) -> Value {
        Value::Map(
            FIELDS
                .into_iter()
                .zip(self.values())
                .map(|(k, v)| (Value::from(k), Value::from(v)))
                .collect(),
        )
    }

    fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != FIELDS.len() {
            return None;
        }
        let mut values = [0; 7];
        for (key, value) in entries {
            let idx = FIELDS
                .iter()
                .position(|field| Some(*field) == key.as_str())?;
            if values[idx] != 0 {
                return None;
            }
            values[idx] = value.as_u64().filter(|n| *n > 0)?;
        }
        let limits = Self::from_values(values);
        limits.valid().then_some(limits)
    }
}
