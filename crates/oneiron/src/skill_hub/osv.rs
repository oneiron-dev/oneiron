//! Dependency-only OSV queries on dynamic installs, using the existing scan ledger.
use super::{
    HubPackage, HubRef, ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance,
    SkillScanReceipt,
};
use crate::{EntityId, Error, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

pub const OSV_SCAN_PROVIDER: &str = "oneiron.osv.v1";
const MAX_COORDINATES: usize = 256;
const MAX_RESPONSE_BYTES: u64 = 1_048_576;
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
fn token(s: &str, package: bool) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"._+-".contains(&b) || (package && b"/@:".contains(&b))
        })
        && !s.contains("://")
        && !s.contains("..")
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid OSV dependency query or response".into())
}
/// Ordered OSV result, one advisory-id list for each input coordinate.
pub trait OsvQuery {
    fn query(&self, coordinates: &[DependencyCoordinate]) -> Result<Vec<Vec<String>>>;
}
/// The production transport has one fixed HTTPS destination and no vault input.
pub struct OsvDevClient;
impl OsvQuery for OsvDevClient {
    fn query(&self, coordinates: &[DependencyCoordinate]) -> Result<Vec<Vec<String>>> {
        validate_coordinates(coordinates)?;
        if coordinates.is_empty() {
            return Ok(Vec::new());
        }
        let queries:Vec<_>=coordinates.iter().map(|d|serde_json::json!({"package":{"ecosystem":d.ecosystem,"name":d.name},"version":d.version})).collect();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|_| invalid())?;
        let response = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&serde_json::json!({"queries":queries}))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| invalid())?;
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(invalid());
        }
        decode_results(&bytes, coordinates.len())
    }
}
fn validate_coordinates(coordinates: &[DependencyCoordinate]) -> Result<()> {
    if coordinates.len() > MAX_COORDINATES {
        return Err(invalid());
    }
    for coordinate in coordinates {
        coordinate.validate()?;
    }
    Ok(())
}
fn decode_results(bytes: &[u8], count: usize) -> Result<Vec<Vec<String>>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let results = value
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(invalid)?;
    if results.len() != count {
        return Err(invalid());
    }
    results
        .iter()
        .map(|result| {
            if !result.is_object() || result.get("error").is_some() {
                return Err(invalid());
            }
            let Some(vulns) = result.get("vulns") else {
                return Ok(Vec::new());
            };
            vulns
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|v| {
                    let id = v.get("id").and_then(|v| v.as_str()).ok_or_else(invalid)?;
                    if !token(id, false) {
                        return Err(invalid());
                    }
                    Ok(id.to_owned())
                })
                .collect()
        })
        .collect()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyScanStatus {
    NoCoordinates,
    Complete,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInstallAdvisories {
    pub entity: EntityId,
    pub advisory_ids: Vec<String>,
    pub status: DependencyScanStatus,
}
impl Vault {
    /// Dynamic dependency install door. Coordinates are host-resolved package
    /// identities, never SKILL instructions, files, credentials or vault data.
    pub fn install_skill_with_advisories(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        coordinates: &[DependencyCoordinate],
        query: &dyn OsvQuery,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SkillInstallAdvisories> {
        self.import_with_advisories(
            hub_ref,
            package,
            EntityId::now(),
            coordinates,
            query,
            occurred,
            learned_at,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "the install binds package identity, dependency inventory and import timing"
    )]
    pub(super) fn import_with_advisories(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        id: EntityId,
        coordinates: &[DependencyCoordinate],
        query: &dyn OsvQuery,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SkillInstallAdvisories> {
        validate_coordinates(coordinates)?;
        let hash = package.content_hash()?;
        // No network call holds a storage transaction. The scan evidence and
        // imported skill co-commit, so activation cannot race the advisory.
        let response = if coordinates.is_empty() {
            None
        } else {
            Some(query.query(coordinates))
        };
        let (status, advisory_ids) = match response {
            None => (DependencyScanStatus::NoCoordinates, Vec::new()),
            Some(Ok(lists))
                if lists.len() == coordinates.len()
                    && lists.iter().flatten().all(|id| token(id, false)) =>
            {
                (
                    DependencyScanStatus::Complete,
                    lists
                        .into_iter()
                        .flatten()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>(),
                )
            }
            _ => (DependencyScanStatus::Unavailable, Vec::new()),
        };
        let mut scans = Vec::new();
        if status == DependencyScanStatus::Complete {
            let prior = self
                .skill_scan_verdicts_for_content_hash(hash)?
                .iter()
                .any(|body| {
                    super::support::map_text(&body.value, "provider") == Some(OSV_SCAN_PROVIDER)
                });
            if !advisory_ids.is_empty() || prior {
                scans.push(SkillScanReceipt::new(
                    OSV_SCAN_PROVIDER,
                    learned_at,
                    if advisory_ids.is_empty() {
                        ScanVerdict::Clean
                    } else {
                        ScanVerdict::Suspicious
                    },
                    if advisory_ids.is_empty() {
                        ScanRiskLevel::None
                    } else {
                        ScanRiskLevel::High
                    },
                    ScanCompleteness::Complete,
                    SkillGovernance::Recommended,
                )?);
            }
        }
        let entity = self
            .import_skill_from_hub_with_scans(hub_ref, package, id, &scans, occurred, learned_at)?;
        Ok(SkillInstallAdvisories {
            entity,
            advisory_ids,
            status,
        })
    }
}
/// Resolves exact npm lockfile and pinned PyPI requirements. Other package
/// managers use the typed inventory door, rather than guessing package names
/// from SKILL dependencies (which name other skills, not registry packages).
pub fn dependency_inventory(package: &HubPackage) -> Result<Vec<DependencyCoordinate>> {
    package.content_hash()?;
    let mut coordinates = BTreeSet::new();
    for file in &package.files {
        if file.path.rsplit('/').next() == Some("package-lock.json") {
            let value: serde_json::Value =
                serde_json::from_slice(&file.content).map_err(|_| invalid())?;
            if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
                for (path, row) in packages {
                    let Some((_, name)) = path.rsplit_once("node_modules/") else {
                        continue;
                    };
                    if row.get("link").and_then(serde_json::Value::as_bool) == Some(true) {
                        continue;
                    }
                    let version = row
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(invalid)?;
                    coordinates.insert(DependencyCoordinate {
                        ecosystem: "npm".into(),
                        name: row
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(name)
                            .into(),
                        version: version.into(),
                    });
                }
            }
        } else if file.path.rsplit('/').next() == Some("requirements.txt") {
            let text = std::str::from_utf8(&file.content).map_err(|_| invalid())?;
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or_default().trim();
                let Some((name, version)) = line.split_once("==") else {
                    continue;
                };
                if name.starts_with('-') || version.contains(';') {
                    continue;
                }
                let version = version.split_whitespace().next().ok_or_else(invalid)?;
                coordinates.insert(DependencyCoordinate {
                    ecosystem: "PyPI".into(),
                    name: name.trim().into(),
                    version: version.into(),
                });
            }
        }
        if coordinates.len() > MAX_COORDINATES {
            return Err(invalid());
        }
    }
    let coordinates: Vec<_> = coordinates.into_iter().collect();
    validate_coordinates(&coordinates)?;
    Ok(coordinates)
}
#[cfg(test)]
mod tests;
