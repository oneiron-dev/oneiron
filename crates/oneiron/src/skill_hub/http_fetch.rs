//! Generic bounded static HTTP index. No marketplace-specific URL rules.
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::package_codec::invalid;
use super::{HubFile, HubIndexEntry, HubPackage, HubPin, HubRef, SkillHubAdapter, SkillHubKind};
use crate::{entity_id::EntityId, error::Result};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

const INDEX_LIMIT: usize = 2 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: u32,
    packages: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    description: String,
    version: String,
    content_hash: String,
    ref_string: String,
    files: Vec<File>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
    url: String,
}

/// Generic index schema: `{schema:1,packages:[{name,description,version,content_hash,ref_string,files:[{path,url}]}]}`.
/// File URLs are relative to the index, same-origin, and fetched without redirects or credentials.
pub struct HttpEndpointSkillHubAdapter {
    hub_id: EntityId,
    endpoint: reqwest::Url,
    client: reqwest::blocking::Client,
}
impl HttpEndpointSkillHubAdapter {
    /// Builds an unauthenticated bounded HTTP(S) transport for a configured hub endpoint.
    pub fn new(hub_id: EntityId, endpoint: &str) -> Result<Self> {
        let endpoint = checked_url(endpoint)?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| invalid("HTTP hub client unavailable"))?;
        Ok(Self {
            hub_id,
            endpoint,
            client,
        })
    }
    fn fetch(&self, url: &reqwest::Url, limit: usize) -> Result<Vec<u8>> {
        let mut response = self
            .client
            .get(url.clone())
            .send()
            .map_err(|_| invalid("HTTP hub fetch failed"))?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > limit as u64)
        {
            return Err(invalid("HTTP hub status or length refused"));
        }
        let mut out = Vec::new();
        response
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| invalid("HTTP hub body read failed"))?;
        if out.len() > limit {
            return Err(invalid("HTTP hub body exceeds bound"));
        }
        Ok(out)
    }
    fn index(&self) -> Result<Index> {
        let index: Index = serde_json::from_slice(&self.fetch(&self.endpoint, INDEX_LIMIT)?)
            .map_err(|_| invalid("invalid hub index"))?;
        if index.schema != 1 || index.packages.len() > 4096 {
            return Err(invalid("unsupported or oversized hub index"));
        }
        let mut aliases = std::collections::BTreeSet::new();
        for entry in &index.packages {
            if !aliases.insert(entry.ref_string.as_str())
                || entry.ref_string.len() > 4096
                || entry.ref_string.is_empty()
                || entry.name.is_empty()
                || entry.name.len() > 256
                || entry.description.len() > 4096
                || entry.version.len() > 128
                || entry.files.is_empty()
                || entry.files.len() > MAX_HUB_PACKAGE_FILES
            {
                return Err(invalid("invalid or duplicate hub index entry"));
            }
            crate::skill::SkillContentHash::parse_hex(&entry.content_hash)?;
            // Validate every path and duplicate before performing a package fetch.
            crate::skill::canonical_skill_tree_hash(
                entry.files.iter().map(|f| (f.path.as_str(), &[][..])),
            )?;
        }
        Ok(index)
    }
}
pub(super) fn checked_url(endpoint: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| invalid("invalid HTTP hub URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(invalid("hub URL credentials, queries or scheme refused"));
    }
    Ok(url)
}
impl SkillHubAdapter for HttpEndpointSkillHubAdapter {
    fn endpoint(&self) -> Option<&str> {
        Some(self.endpoint.as_str())
    }
    fn hub_id(&self) -> EntityId {
        self.hub_id
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::HttpIndex
    }
    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        self.index()?
            .packages
            .into_iter()
            .map(|e| {
                Ok(HubIndexEntry {
                    name: e.name,
                    description: e.description,
                    version: e.version,
                    content_hash: crate::skill::SkillContentHash::parse_hex(&e.content_hash)?,
                    ref_string: e.ref_string,
                })
            })
            .collect()
    }
    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        let (entry, files) = self.fetch_tree(hub_ref)?;
        let package = super::folder::package_from_files(files)?;
        if package.record.skill_id != entry.name
            || package.record.version != entry.version
            || package.record.desc != entry.description
        {
            return Err(invalid("package identity or index metadata drift"));
        }
        Ok(package)
    }
}
impl super::pack_catalog::PackSourceAdapter for HttpEndpointSkillHubAdapter {
    fn fetch_pack_source(&self, reference: &HubRef) -> Result<super::pack_catalog::PackSource> {
        let (entry, files) = self.fetch_tree(reference)?;
        let source = super::pack_catalog::PackSource::from_files(files)?;
        let manifest = source.manifest();
        if manifest.name != entry.name
            || manifest.version != entry.version
            || manifest.description != entry.description
        {
            return Err(invalid("pack identity or index metadata drift"));
        }
        Ok(source)
    }
}
impl HttpEndpointSkillHubAdapter {
    fn fetch_tree(&self, hub_ref: &HubRef) -> Result<(Entry, Vec<HubFile>)> {
        if hub_ref.hub_id != self.hub_id {
            return Err(invalid("cross-hub fetch refused"));
        }
        // A static index supports byte pins, not Git revision semantics.
        let HubPin::ContentHash(pinned) = &hub_ref.pin else {
            return Err(invalid("HTTP index requires a content hash pin"));
        };
        let expected = crate::skill::SkillContentHash::parse_hex(pinned)?;
        let entry = self
            .index()?
            .packages
            .into_iter()
            .find(|e| e.ref_string == hub_ref.ref_string)
            .ok_or_else(|| invalid("package not in index"))?;
        if crate::skill::SkillContentHash::parse_hex(&entry.content_hash)? != expected {
            return Err(invalid("index pin drift"));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut files = Vec::new();
        let mut remaining = MAX_HUB_PACKAGE_TOTAL_BYTES;
        for file in &entry.files {
            if std::time::Instant::now() > deadline {
                return Err(invalid("package fetch deadline exceeded"));
            }
            let url = self
                .endpoint
                .join(&file.url)
                .map_err(|_| invalid("invalid package URL"))?;
            checked_url(url.as_str())?;
            if url.origin() != self.endpoint.origin() {
                return Err(invalid("cross-origin package URL refused"));
            }
            let bytes = self.fetch(&url, MAX_HUB_FILE_BYTES.min(remaining))?;
            remaining -= bytes.len();
            files.push(HubFile::new(file.path.clone(), bytes));
        }
        let actual = crate::skill::canonical_skill_tree_hash(
            files
                .iter()
                .map(|f| (f.path.as_str(), f.content.as_slice())),
        )?;
        if actual != expected {
            return Err(invalid("package content hash drift"));
        }
        Ok((entry, files))
    }
}
