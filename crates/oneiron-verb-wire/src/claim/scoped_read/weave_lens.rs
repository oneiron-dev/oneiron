//! Moved from `crates/oneiron/src/claim/scoped_read/weave_lens.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_lens_wire::lens::atom::LensText;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("weave lens: {reason}"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensPlanSection {
    pub heading: String,
    #[serde(default)]
    pub summary: Vec<String>,
    pub items: Vec<WeaveLensPlanLine>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveLensPlanLine {
    pub key: String,
    pub line: String,
}

pub fn item_key(section: usize, item: usize) -> String {
    format!("{section}.{item}")
}

pub fn required_text(value: &str, what: &str) -> Result<LensText> {
    if value.trim().is_empty() {
        return Err(invalid(&format!("the plan's {what} is empty")));
    }
    LensText::new(value.to_owned())
}
