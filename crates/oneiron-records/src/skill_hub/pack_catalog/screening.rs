//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/screening.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use icu_normalizer::ComposingNormalizer;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use unicode_script::Script;
use unicode_script::UnicodeScript;

/// Owner-managed install prohibitions. A scan verdict is a signal, not a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstallRules {
    pub removed_hashes: Vec<String>,
    pub known_bad_patterns: Vec<String>,
}
