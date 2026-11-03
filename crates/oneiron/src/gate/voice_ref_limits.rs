//! Resolved policy-manifest limits for the private render-reference bank.
//! Structural key validity remains in the bank; adjustable payload limits live here.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::EntityId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceRefLimits {
    pub(crate) max_clips_per_pack: u64,
    pub(crate) max_audio_bytes_per_pack: u64,
    pub(crate) max_register_bytes: u64,
    pub(crate) max_transcript_bytes: u64,
    pub(crate) max_design_vendor_bytes: u64,
    pub(crate) max_vendor_voice_id_bytes: u64,
}

impl VoiceRefLimits {
    // Absence of a row is represented by a sentinel, not a shipped ceiling.
    // The actual defaults are rows in gate::default_policy_manifest().
    const UNBOUNDED: Self = Self {
        max_clips_per_pack: u64::MAX,
        max_audio_bytes_per_pack: u64::MAX,
        max_register_bytes: u64::MAX,
        max_transcript_bytes: u64::MAX,
        max_design_vendor_bytes: u64::MAX,
        max_vendor_voice_id_bytes: u64::MAX,
    };

    pub(crate) fn narrow(&mut self, other: Self) {
        self.max_clips_per_pack = self.max_clips_per_pack.min(other.max_clips_per_pack);
        self.max_audio_bytes_per_pack = self
            .max_audio_bytes_per_pack
            .min(other.max_audio_bytes_per_pack);
        self.max_register_bytes = self.max_register_bytes.min(other.max_register_bytes);
        self.max_transcript_bytes = self.max_transcript_bytes.min(other.max_transcript_bytes);
        self.max_design_vendor_bytes = self
            .max_design_vendor_bytes
            .min(other.max_design_vendor_bytes);
        self.max_vendor_voice_id_bytes = self
            .max_vendor_voice_id_bytes
            .min(other.max_vendor_voice_id_bytes);
    }

    /// Owner-authored fields replace the shipped row; fields not named by
    /// the owner retain their values from that row.
    fn replace_defined(&mut self, other: Self) {
        if other.max_clips_per_pack != u64::MAX {
            self.max_clips_per_pack = other.max_clips_per_pack;
        }
        if other.max_audio_bytes_per_pack != u64::MAX {
            self.max_audio_bytes_per_pack = other.max_audio_bytes_per_pack;
        }
        if other.max_register_bytes != u64::MAX {
            self.max_register_bytes = other.max_register_bytes;
        }
        if other.max_transcript_bytes != u64::MAX {
            self.max_transcript_bytes = other.max_transcript_bytes;
        }
        if other.max_design_vendor_bytes != u64::MAX {
            self.max_design_vendor_bytes = other.max_design_vendor_bytes;
        }
        if other.max_vendor_voice_id_bytes != u64::MAX {
            self.max_vendor_voice_id_bytes = other.max_vendor_voice_id_bytes;
        }
    }

    fn decode(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        let mut limits = Self::UNBOUNDED;
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in fields {
            let key = key.as_str()?;
            if !seen.insert(key) {
                return None;
            }
            let limit = value.as_u64().filter(|number| *number > 0)?;
            match key {
                "max_clips_per_pack" => limits.max_clips_per_pack = limit,
                "max_audio_bytes_per_pack" => limits.max_audio_bytes_per_pack = limit,
                "max_register_bytes" => limits.max_register_bytes = limit,
                "max_transcript_bytes" => limits.max_transcript_bytes = limit,
                "max_design_vendor_bytes" => limits.max_design_vendor_bytes = limit,
                "max_vendor_voice_id_bytes" => limits.max_vendor_voice_id_bytes = limit,
                _ => return None,
            }
        }
        Some(limits)
    }

    pub(crate) fn fields(self) -> [u64; 6] {
        [
            self.max_clips_per_pack,
            self.max_audio_bytes_per_pack,
            self.max_register_bytes,
            self.max_transcript_bytes,
            self.max_design_vendor_bytes,
            self.max_vendor_voice_id_bytes,
        ]
    }
}

/// Precedence is a policy row, not a branch selected by an engine constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VoiceRefPrecedence {
    /// Trusted owner vault rows replace shipped defaults, then trusted owner
    /// contributions narrow each other. Holder rows narrow the vault result.
    NestedNarrowing,
    /// Explicitly ignore holder-specific rows. The resolved vault row alone
    /// controls admission; the owner can select this mode in policy data.
    VaultOnly,
}

impl VoiceRefPrecedence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "vault_only" => Some(Self::VaultOnly),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::VaultOnly => "vault_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VoiceRefLimitPolicy {
    pub(crate) vault: VoiceRefLimits,
    pub(crate) holders: BTreeMap<EntityId, VoiceRefLimits>,
    pub(crate) precedence: Option<VoiceRefPrecedence>,
}

impl Default for VoiceRefLimitPolicy {
    fn default() -> Self {
        Self {
            vault: VoiceRefLimits::UNBOUNDED,
            holders: BTreeMap::new(),
            precedence: None,
        }
    }
}

impl VoiceRefLimitPolicy {
    /// `voice_ref_limits`: `{ vault: { limit: n }, holders: [{ holder_ref, limits }],
    /// precedence: "nested_narrowing" | "vault_only" }`.
    /// Trusted owner packs replace named shipped defaults; among owner packs,
    /// contributions narrow one another unless their precedence rows conflict.
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let mut policy = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in entries {
            let key = key.as_str()?;
            if !seen.insert(key) {
                return None;
            }
            match key {
                "vault" => policy.vault = VoiceRefLimits::decode(value)?,
                "precedence" => {
                    policy.precedence = Some(VoiceRefPrecedence::parse(value.as_str()?)?);
                }
                "holders" => {
                    let Value::Array(rows) = value else {
                        return None;
                    };
                    for row in rows {
                        let Value::Map(fields) = row else { return None };
                        if fields.len() != 2 {
                            return None;
                        }
                        let mut id = None;
                        let mut limits = None;
                        for (field, value) in fields {
                            match field.as_str()? {
                                "holder_ref" if id.is_none() => {
                                    id = Some(EntityId::from_hex(value.as_str()?).ok()?);
                                }
                                "limits" if limits.is_none() => {
                                    limits = Some(VoiceRefLimits::decode(value)?);
                                }
                                _ => return None,
                            }
                        }
                        if policy.holders.insert(id?, limits?).is_some() {
                            return None;
                        }
                    }
                }
                _ => return None,
            }
        }
        Some(policy)
    }

    pub(crate) fn narrow(&mut self, other: Self) {
        self.vault.narrow(other.vault);
        for (id, limits) in other.holders {
            self.holders
                .entry(id)
                .and_modify(|existing| existing.narrow(limits))
                .or_insert(limits);
        }
    }

    /// Returns None when the shipped manifest has no precedence row.
    pub(crate) fn effective(&self, defaults: &Self, owner: &EntityId) -> Option<VoiceRefLimits> {
        let precedence = self.precedence.or(defaults.precedence)?;
        let mut limits = defaults.vault;
        limits.replace_defined(self.vault);
        if precedence == VoiceRefPrecedence::NestedNarrowing {
            if let Some(holder) = defaults.holders.get(owner) {
                limits.narrow(*holder);
            }
            if let Some(holder) = self.holders.get(owner) {
                limits.narrow(*holder);
            }
        }
        Some(limits)
    }
}
