//! Resolved, narrow-only limits for the generic voice serving seam.
//! The seeded manifest ships values. No budget is inferred from a model name.
use crate::{
    EntityId,
    error::{Error, Result},
};
use rmpv::Value;

pub(crate) const KEY: &str = "voice_serving";
const PRECEDENCE: &str = "nested_narrowing";
const FIELDS: [&str; 8] = [
    "max_text_bytes",
    "max_pcm_bytes",
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
    pub max_pcm_bytes: u64,
    pub max_ref_bytes: u64,
    pub max_queued_renders: u64,
    pub max_inflight_uploads: u64,
    pub upload_read_deadline_ms: u64,
    pub http_deadline_ms: u64,
    pub max_header_bytes: u64,
}
impl VoiceServingLimits {
    const DEFAULT: Self = Self {
        max_text_bytes: 8 * 1024,
        max_pcm_bytes: 2 * 1024 * 1024,
        max_ref_bytes: 16 * 1024 * 1024,
        max_queued_renders: 16,
        max_inflight_uploads: 2,
        upload_read_deadline_ms: 5_000,
        http_deadline_ms: 45_000,
        max_header_bytes: 32_768,
    };
    fn values(self) -> [u64; 8] {
        [
            self.max_text_bytes,
            self.max_pcm_bytes,
            self.max_ref_bytes,
            self.max_queued_renders,
            self.max_inflight_uploads,
            self.upload_read_deadline_ms,
            self.http_deadline_ms,
            self.max_header_bytes,
        ]
    }
    fn from_values(v: [u64; 8]) -> Self {
        Self {
            max_text_bytes: v[0],
            max_pcm_bytes: v[1],
            max_ref_bytes: v[2],
            max_queued_renders: v[3],
            max_inflight_uploads: v[4],
            upload_read_deadline_ms: v[5],
            http_deadline_ms: v[6],
            max_header_bytes: v[7],
        }
    }
    /// Structural/wire checks only. Operational limits and deadlines are
    /// authored by the trusted manifest, with shipped defaults and narrowing.
    pub(crate) fn valid(self) -> bool {
        self.values().iter().all(|n| *n > 0)
            && self.max_ref_bytes >= 12
            && self.max_pcm_bytes.is_multiple_of(2)
            && self.max_header_bytes <= u64::from(u32::MAX) // 4-byte wire header
            && self.max_text_bytes <= usize::MAX as u64
            && self.max_pcm_bytes <= usize::MAX as u64
            && self.max_ref_bytes <= usize::MAX as u64
            && self.max_queued_renders <= usize::MAX as u64
            && self.max_inflight_uploads <= usize::MAX as u64
            && self.max_ref_bytes.checked_add(self.max_header_bytes)
                .and_then(|n| n.checked_add(4))
                .is_some_and(|n| n <= usize::MAX as u64)
            && self.max_pcm_bytes.checked_add(self.max_header_bytes)
                .and_then(|n| n.checked_add(4))
                .is_some_and(|n| n <= usize::MAX as u64)
            && self.upload_read_deadline_ms <= self.http_deadline_ms
    }
    pub(crate) fn narrow(self, other: Self) -> Self {
        let a = self.values();
        let b = other.values();
        Self::from_values(std::array::from_fn(|i| a[i].min(b[i])))
    }
    pub(crate) fn within(self, ceiling: Self) -> bool {
        self.values()
            .into_iter()
            .zip(ceiling.values())
            .all(|(a, b)| a <= b)
    }
    pub(crate) fn encode(self) -> Value {
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
        let mut values = [0; 8];
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VoiceServingRows {
    pub(crate) vault: VoiceServingLimits,
    pub(crate) holders: Vec<(EntityId, VoiceServingLimits)>,
}
impl VoiceServingRows {
    pub(crate) fn seeded() -> Value {
        Value::Map(vec![
            (Value::from("precedence"), Value::from(PRECEDENCE)),
            (Value::from("vault"), VoiceServingLimits::DEFAULT.encode()),
            (Value::from("holders"), Value::Array(vec![])),
        ])
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 3 {
            return None;
        }
        let mut precedence = None;
        let mut vault = None;
        let mut holders = None;
        for (key, value) in entries {
            match key.as_str()? {
                "precedence" if precedence.is_none() => {
                    precedence = Some(value.as_str()? == PRECEDENCE);
                }
                "vault" if vault.is_none() => vault = Some(VoiceServingLimits::decode(value)?),
                "holders" if holders.is_none() => {
                    let Value::Array(rows) = value else {
                        return None;
                    };
                    if rows.len() > 256 {
                        return None;
                    }
                    let mut parsed = Vec::with_capacity(rows.len());
                    for row in rows {
                        let Value::Map(fields) = row else {
                            return None;
                        };
                        if fields.len() != 2 {
                            return None;
                        }
                        let mut holder = None;
                        let mut limits = None;
                        for (k, v) in fields {
                            match k.as_str()? {
                                "holder" if holder.is_none() => {
                                    let id = v.as_str()?;
                                    if id.len() != 32
                                        || !id.bytes().all(|b| {
                                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                                        })
                                    {
                                        return None;
                                    }
                                    holder = Some(EntityId::from_hex(id).ok()?);
                                }
                                "limits" if limits.is_none() => {
                                    limits = Some(VoiceServingLimits::decode(v)?);
                                }
                                _ => return None,
                            }
                        }
                        let holder = holder?;
                        if parsed.iter().any(|(id, _)| *id == holder) {
                            return None;
                        }
                        parsed.push((holder, limits?));
                    }
                    holders = Some(parsed);
                }
                _ => return None,
            }
        }
        if precedence != Some(true) {
            return None;
        }
        Some(Self {
            vault: vault?,
            holders: holders?,
        })
    }
}

pub(crate) fn resolve(
    rows: &[VoiceServingRows],
    holder: Option<EntityId>,
) -> Result<VoiceServingLimits> {
    let first = rows
        .first()
        .ok_or_else(|| Error::InvalidConfig("voice serving manifest row missing".into()))?;
    let vault = rows
        .iter()
        .skip(1)
        .fold(first.vault, |acc, row| acc.narrow(row.vault));
    if !vault.valid() {
        return Err(Error::InvalidConfig(
            "voice serving vault limits invalid".into(),
        ));
    }
    let mut effective = vault;
    for row in rows {
        for (id, limits) in &row.holders {
            if !limits.within(vault) {
                return Err(Error::InvalidConfig(
                    "voice serving holder override widens vault".into(),
                ));
            }
            if Some(*id) == holder {
                effective = effective.narrow(*limits);
            }
        }
    }
    if !effective.valid() {
        return Err(Error::InvalidConfig(
            "voice serving effective limits invalid".into(),
        ));
    }
    Ok(effective)
}
