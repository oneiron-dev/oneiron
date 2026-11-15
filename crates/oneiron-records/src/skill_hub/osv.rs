//! Moved from `crates/oneiron/src/skill_hub/osv.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl DependencyCoordinate {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.ecosystem.as_str(),
            "npm" | "PyPI" | "crates.io" | "Go" | "Maven" | "NuGet" | "RubyGems" | "Packagist"
        ) || !token(&self.name, true)
            || !token(&self.version, false)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub fn token(s: &str, package: bool) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"._+-".contains(&b) || (package && b"/@:".contains(&b))
        })
        && !s.contains("://")
        && !s.contains("..")
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid OSV dependency query or response".into())
}
