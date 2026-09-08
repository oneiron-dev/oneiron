//! Scalar newtypes LensText/FiniteF64 with TryFrom/serde impls, and kit-version/kind-list consts.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

pub const LENS_ATOM_KIT_VERSION: u16 = 3;

pub const GENERATED_LENS_ATOM_KINDS: &[&str] = &[
    "text_block",
    "ledger_row",
    "claim_line",
    "status_dot",
    "seal",
    "meta_line",
    "dossier_section",
    "thread_entry",
    "sheet",
    "slip",
    "receipt",
    "charter",
    "postmark",
    "pack_line",
    "answer_sheet",
    "two_clocks",
    "neighborhood_graph",
    "asof_scrubber",
    "throbber",
    "voice_line",
    "quick_filter",
    "inspector_sheet",
    "inspector_rail",
    "inspector_trail",
    "self_ui",
    "media",
    "result_set",
];

/// Wire name of the selectable result-set atom minted at catalog version 3.
pub const RESULT_SET_ATOM_KIND: &str = "result_set";

/// The single rejection a surface below catalog 3 — or one whose primitive list omits
/// [`GeneratedUiPrimitive::ResultSet`] — gets. A result set never lowers to fallback
/// text: a degraded selection surface would offer rows the host cannot resolve.
pub const LENS_RESULT_SET_UNSUPPORTED: &str = "result_set requires lens atom catalog version 3";

pub(crate) const MAX_LENS_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensText(String);

impl LensText {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() > MAX_LENS_TEXT_BYTES {
            return Err(Error::InvalidConfig(format!(
                "lens text must be at most {MAX_LENS_TEXT_BYTES} bytes"
            )));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LensText {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<&str> for LensText {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl From<LensText> for String {
    fn from(value: LensText) -> Self {
        value.0
    }
}

impl Serialize for LensText {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LensText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FiniteF64(f64);

impl FiniteF64 {
    pub fn new(value: f64) -> Result<Self> {
        if !value.is_finite() {
            return Err(Error::InvalidConfig(
                "lens numeric value must be finite".to_string(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for FiniteF64 {
    type Error = Error;

    fn try_from(value: f64) -> Result<Self> {
        Self::new(value)
    }
}

impl From<FiniteF64> for f64 {
    fn from(value: FiniteF64) -> Self {
        value.0
    }
}

impl Serialize for FiniteF64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for FiniteF64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}
