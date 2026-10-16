//! Pack organs (OF-575, ARCH-0075 §9): a PACK.md `organs:` key names folders
//! under `organs/`, each with an `ORGAN.json` facet. The facet names what the
//! install grant names (verbs, the kinds it reads, media types, its resource
//! ask) and pins one build per platform triple by BLAKE3. A build is not pack
//! source: it travels as a blob asset held by the source, so the source hash
//! pins the binary through its facet. The install door hands back a build only
//! for an Active installation, verified against that pin.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{PackInstallStatus, PackManifest, PackSource, invalid};
use crate::consent::AuthenticatedOwner;
use crate::skill::{SkillContentHash, canonical_skill_tree_hash};
use crate::skill_hub::HubFile;
use crate::{EntityId, TimeRange, Vault, error::Result};
use serde::{Deserialize, Serialize};

const ORGAN_DIR: &str = "organs/";
const ORGAN_MANIFEST: &str = "ORGAN.json";
/// The largest organ build a pack may pin.
pub const MAX_ORGAN_BUILD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ORGANS: usize = 32;
const MAX_ORGAN_BUILDS: usize = 16;
const MAX_ORGAN_LIST: usize = 64;
const MAX_ORGAN_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// One organ a pack carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackOrgan {
    /// Its folder under `organs/`.
    pub name: String,
    /// The version the organ reports in its handshake; the host pins it.
    pub version: Option<String>,
    /// The verbs the install grant names.
    pub verbs: Vec<String>,
    /// The kinds it reads.
    pub kinds: Vec<String>,
    /// The input media types it accepts.
    pub media_types: Vec<String>,
    /// Its resource ask: calls at once, and its memory.
    pub threads: Option<u16>,
    pub memory_bytes: Option<u64>,
    /// One pinned build per platform triple.
    pub builds: Vec<PackOrganBuild>,
}

/// One platform's build of an organ, pinned by content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackOrganBuild {
    /// A target triple, e.g. `aarch64-apple-darwin`.
    pub platform: String,
    /// The binary's BLAKE3, 64 lowercase hex.
    pub blake3: String,
    /// The binary's length.
    pub bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganFacet {
    #[serde(default)]
    version: Option<String>,
    verbs: Vec<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    media_types: Vec<String>,
    #[serde(default)]
    threads: Option<u16>,
    #[serde(default)]
    memory_bytes: Option<u64>,
    builds: Vec<PackOrganBuild>,
}

impl PackOrgan {
    fn from_facet(name: &str, bytes: &[u8]) -> Result<Self> {
        let facet: OrganFacet = serde_json::from_slice(bytes)
            .map_err(|_| invalid("ORGAN.json must be a typed JSON object"))?;
        if let Some(version) = &facet.version
            && (version.trim().is_empty()
                || version.len() > 128
                || version.chars().any(char::is_control))
        {
            return Err(invalid("organ version is blank or exceeds its bound"));
        }
        if facet.verbs.is_empty() {
            return Err(invalid("an organ names at least one verb"));
        }
        unique_list(&facet.verbs, 128, is_name)?;
        unique_list(&facet.kinds, 256, is_name)?;
        unique_list(&facet.media_types, 255, is_media_type)?;
        if facet
            .threads
            .is_some_and(|threads| threads == 0 || threads > 256)
            || facet
                .memory_bytes
                .is_some_and(|bytes| bytes == 0 || bytes > MAX_ORGAN_MEMORY_BYTES)
        {
            return Err(invalid("organ resource ask is out of bounds"));
        }
        if facet.builds.is_empty() || facet.builds.len() > MAX_ORGAN_BUILDS {
            return Err(invalid("an organ pins one to sixteen builds"));
        }
        let mut platforms = BTreeSet::new();
        for build in &facet.builds {
            if !is_platform(&build.platform) || !platforms.insert(build.platform.as_str()) {
                return Err(invalid("organ build platform is invalid or repeated"));
            }
            build.hash()?;
            if build.bytes == 0 || build.bytes > MAX_ORGAN_BUILD_BYTES {
                return Err(invalid("organ build length is out of bounds"));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            version: facet.version,
            verbs: facet.verbs,
            kinds: facet.kinds,
            media_types: facet.media_types,
            threads: facet.threads,
            memory_bytes: facet.memory_bytes,
            builds: facet.builds,
        })
    }

    #[must_use]
    pub fn build(&self, platform: &str) -> Option<&PackOrganBuild> {
        self.builds.iter().find(|build| build.platform == platform)
    }

    /// The organ's permission-card tokens: its ask and its pinned builds.
    pub(super) fn capability_tokens(&self) -> Vec<String> {
        let name = &self.name;
        let mut tokens = Vec::new();
        tokens.extend(
            self.verbs
                .iter()
                .map(|verb| format!("organ:{name}:verb:{verb}")),
        );
        tokens.extend(
            self.kinds
                .iter()
                .map(|kind| format!("organ:{name}:kind:{kind}")),
        );
        tokens.extend(
            self.media_types
                .iter()
                .map(|media| format!("organ:{name}:media:{media}")),
        );
        if let Some(threads) = self.threads {
            tokens.push(format!("organ:{name}:threads:{threads}"));
        }
        if let Some(bytes) = self.memory_bytes {
            tokens.push(format!("organ:{name}:memory:{bytes}"));
        }
        tokens.extend(
            self.builds
                .iter()
                .map(|build| format!("organ:{name}:build:{}:{}", build.platform, build.blake3)),
        );
        tokens
    }
}

impl PackOrganBuild {
    /// The pinned BLAKE3.
    pub fn hash(&self) -> Result<[u8; 32]> {
        if self.blake3.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(invalid("organ build hash must be 64 lowercase hex"));
        }
        blake3::Hash::from_hex(&self.blake3)
            .map(|hash| *hash.as_bytes())
            .map_err(|_| invalid("organ build hash must be 64 lowercase hex"))
    }

    fn verify(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        let hash = self.hash()?;
        if bytes.len() as u64 != self.bytes || *blake3::hash(bytes).as_bytes() != hash {
            return Err(invalid("organ build bytes disagree with their pin"));
        }
        Ok(hash)
    }
}

pub(super) fn validate_organ_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
    {
        return Err(invalid("organ names are short lowercase folder names"));
    }
    Ok(())
}

fn is_name(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn is_media_type(value: &str) -> bool {
    value.split_once('/').is_some_and(|(kind, sub)| {
        !kind.is_empty()
            && !sub.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
    })
}

fn is_platform(value: &str) -> bool {
    value.len() <= 64
        && (2..=4).contains(&value.split('-').count())
        && value.split('-').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.')
                })
        })
}

fn unique_list(values: &[String], max_bytes: usize, valid: fn(&str) -> bool) -> Result<()> {
    if values.len() > MAX_ORGAN_LIST {
        return Err(invalid("organ list too long"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() || value.len() > max_bytes || !valid(value) || !seen.insert(value) {
            return Err(invalid("invalid or repeated organ list entry"));
        }
    }
    Ok(())
}

/// This host's platform triple, as an organ build names it.
#[must_use]
pub fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "ios" => "apple-ios",
        "linux" if cfg!(target_env = "musl") => "unknown-linux-musl",
        "linux" => "unknown-linux-gnu",
        "windows" => "pc-windows-msvc",
        "android" => "linux-android",
        other => other,
    };
    format!("{}-{os}", std::env::consts::ARCH)
}

/// A path under `organs/<name>/` other than the facet: a build, not source.
fn organ_build_path(path: &str) -> Option<(&str, &str)> {
    path.strip_prefix(ORGAN_DIR)?
        .split_once('/')
        .filter(|(_, file)| *file != ORGAN_MANIFEST)
}

/// The organs a source's `organs:` key names, each read from its facet. A
/// folder the key does not name, or a build inside the source, is refused.
pub(super) fn parse_source_organs(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Vec<PackOrgan>> {
    let mut facets = BTreeMap::<&str, &[u8]>::new();
    for file in files {
        let Some(relative) = file.path.strip_prefix(ORGAN_DIR) else {
            continue;
        };
        let (folder, name) = relative
            .split_once('/')
            .ok_or_else(|| invalid("an organ must have a folder"))?;
        if name != ORGAN_MANIFEST {
            return Err(invalid(
                "organ builds travel as blob assets, not pack source",
            ));
        }
        if !manifest.organs.contains(folder) {
            return Err(invalid("organ folder is not named under organs:"));
        }
        facets.insert(folder, file.content.as_slice());
    }
    manifest
        .organs
        .iter()
        .map(|name| {
            let facet = facets
                .get(name.as_str())
                .ok_or_else(|| invalid("declared organ folder is absent"))?;
            PackOrgan::from_facet(name, facet)
        })
        .collect()
}

/// A fetched or put pack tree: its text source and the organ builds it
/// carried, each checked against its pin.
pub struct PackTree {
    pub source: PackSource,
    /// The canonical hash of every file, builds included: what a hub
    /// content pin names.
    pub tree_hash: SkillContentHash,
    pub(super) builds: Vec<Vec<u8>>,
}

impl From<PackSource> for PackTree {
    fn from(source: PackSource) -> Self {
        Self {
            tree_hash: source.content_hash(),
            source,
            builds: Vec::new(),
        }
    }
}

impl PackSource {
    /// A tree that may carry organ builds at `organs/<name>/<platform>`. The
    /// builds leave the source, and each must match its facet's pin.
    pub fn from_tree(files: Vec<HubFile>) -> Result<PackTree> {
        let tree_hash = canonical_skill_tree_hash(
            files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )?;
        let (carried, text): (Vec<_>, Vec<_>) = files
            .into_iter()
            .partition(|file| organ_build_path(&file.path).is_some());
        let source = Self::from_files(text)?;
        let mut builds = Vec::new();
        for file in carried {
            let (organ, platform) = organ_build_path(&file.path).expect("partitioned");
            source
                .organs()
                .iter()
                .find(|declared| declared.name == organ)
                .and_then(|declared| declared.build(platform))
                .ok_or_else(|| invalid("organ binary is not a pinned build"))?
                .verify(&file.content)?;
            builds.push(file.content);
        }
        Ok(PackTree {
            source,
            tree_hash,
            builds,
        })
    }
}

/// One organ of an Active installation, and the platforms this vault holds
/// a build for.
#[derive(Debug, Clone, Serialize)]
pub struct PackOrganEntry {
    pub pack_name: String,
    pub source_id: String,
    pub organ: PackOrgan,
    pub held_platforms: Vec<String>,
}

/// An Active pack's organ build, its bytes verified against the pin.
#[derive(Debug, Clone)]
pub struct PackOrganBinary {
    pub pack_name: String,
    pub source_id: EntityId,
    pub organ: PackOrgan,
    pub build: PackOrganBuild,
    pub bytes: Vec<u8>,
}

impl PackOrganBinary {
    /// The build as an executable file at `dir/<blake3>`, written once. A file
    /// already there is hashed again and replaced if it drifted.
    pub fn materialize(&self, dir: &Path) -> Result<PathBuf> {
        let path = dir.join(&self.build.blake3);
        let held = std::fs::read(&path)
            .ok()
            .is_some_and(|bytes| self.build.verify(&bytes).is_ok());
        if !held {
            std::fs::create_dir_all(dir)?;
            let temp = dir.join(format!(
                ".{}.{}.part",
                self.build.blake3,
                std::process::id()
            ));
            std::fs::write(&temp, &self.bytes)?;
            std::fs::File::open(&temp)?.sync_all()?;
            std::fs::rename(&temp, &path)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(path)
    }
}

impl Vault {
    /// Holds a tree's organ builds as blob assets of its staged source.
    pub(super) fn hold_organ_builds_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source_id: &EntityId,
        tree: &PackTree,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        for bytes in &tree.builds {
            crate::ports::BlobStore::port_blob_put(
                self, txn, source_id, bytes, occurred, learned_at,
            )?;
        }
        Ok(())
    }

    /// Owner door: hold one organ build for a staged pack source, checked
    /// against the source's pin. Holding grants nothing; only an Active
    /// installation hands a build out.
    pub fn put_pack_organ_build(
        &self,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        organ: &str,
        platform: &str,
        bytes: &[u8],
    ) -> Result<PackOrganBuild> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let source = self
                .pack_source_in_txn(txn, &source_id)?
                .ok_or_else(|| invalid("pack source missing"))?;
            let build = source
                .organs()
                .iter()
                .find(|declared| declared.name == organ)
                .and_then(|declared| declared.build(platform))
                .ok_or_else(|| invalid("the source pins no such organ build"))?
                .clone();
            build.verify(bytes)?;
            let at = crate::unix_seconds_now();
            crate::ports::BlobStore::port_blob_put(
                self,
                txn,
                &source_id,
                bytes,
                TimeRange { start: at, end: at },
                at,
            )?;
            Ok(build)
        })
    }

    /// Every organ of every Active installation, with the platforms this
    /// vault holds a build for: the inventory a host installs from, or
    /// picks a node of the owner's by.
    pub fn pack_organs(&self) -> Result<Vec<PackOrganEntry>> {
        let installed = self.installed_packs()?;
        let txn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        for receipt in installed {
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let Some(source) = self.pack_source_in_txn(&txn, &source_id)? else {
                continue;
            };
            for organ in source.organs() {
                let mut held_platforms = Vec::new();
                for build in &organ.builds {
                    if crate::ports::BlobStore::port_blob_get(self, &txn, &build.hash()?)?.is_some()
                    {
                        held_platforms.push(build.platform.clone());
                    }
                }
                entries.push(PackOrganEntry {
                    pack_name: receipt.pack_name.clone(),
                    source_id: receipt.source_id.clone(),
                    organ: organ.clone(),
                    held_platforms,
                });
            }
        }
        Ok(entries)
    }

    /// The organ install door (OF-575): an Active pack's organ build for
    /// `platform`, verified against its pin. A Candidate has no execution
    /// right, so it has no build to hand out.
    pub fn pack_organ_build(
        &self,
        pack_name: &str,
        organ: &str,
        platform: &str,
    ) -> Result<PackOrganBinary> {
        let txn = self.store.env.read_txn()?;
        let receipt = self
            .mounted_pack_in_txn(&txn, pack_name)?
            .filter(|receipt| receipt.status == PackInstallStatus::Active)
            .ok_or_else(|| invalid("no Active pack is installed under that name"))?;
        let source_id = EntityId::from_hex(&receipt.source_id)?;
        let source = self
            .pack_source_in_txn(&txn, &source_id)?
            .ok_or_else(|| invalid("installed pack source missing"))?;
        let declared = source
            .organs()
            .iter()
            .find(|declared| declared.name == organ)
            .ok_or_else(|| invalid("the pack carries no such organ"))?;
        let build = declared
            .build(platform)
            .ok_or_else(|| invalid("the organ has no build for this platform"))?;
        let bytes = crate::ports::BlobStore::port_blob_get(self, &txn, &build.hash()?)?
            .ok_or_else(|| invalid("this vault holds no copy of the organ build"))?;
        build.verify(&bytes)?;
        Ok(PackOrganBinary {
            pack_name: receipt.pack_name,
            source_id,
            organ: declared.clone(),
            build: build.clone(),
            bytes,
        })
    }
}
