//! Skill-hub records, provenance aliases, adapter contracts, and update gates.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::registry::{ENTITY_TYPE_SKILL, ENTITY_TYPE_SKILL_CONTENT_ANCHOR};
use crate::skill::{
    SkillContentHash, SkillLifecycle, SkillRecord, canonical_skill_tree_hash,
    cross_check_declared_content_hash, decode_skill_record, encode_skill_record,
};
use crate::temporal::TimeRange;

/// Pinned MessagePack key set for a SKILL_HUB body.
pub const SKILL_HUB_BODY_KEYS: [&str; 4] = ["kind", "endpoint", "trust_tier", "sync_policy"];

/// Pinned MessagePack key set for the structured hub provenance pointer.
pub const HUB_REF_KEYS: [&str; 3] = ["hubId", "refString", "pin"];

/// Pinned MessagePack key set for a hub-ref pin.
pub const HUB_PIN_KEYS: [&str; 2] = ["type", "value"];

/// Claim predicate for mutable hub aliases attached to canonical skill identity.
pub const PREDICATE_SKILL_HUB_PROVENANCE: &str = "skill.hub_provenance";

/// Claim predicate for scanner receipts attached to a canonical content hash.
pub const PREDICATE_SKILL_SCAN_VERDICT: &str = "skill.scan_verdict";

/// Claim predicate for capability-widening update proposals.
pub const PREDICATE_SKILL_HUB_UPDATE_PROPOSAL: &str = "skill.hub_update_proposal";

const CAPABILITY_STATE_PREFIX: &[u8] = b"skill_hub/capability/v1\0";
const CONTENT_HASH_INDEX_PREFIX: &[u8] = b"skill_hub/content_hash_index/v1\0";
const CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY: &[u8] = b"skill_hub/content_hash_index_schema_version";
const CONTENT_HASH_INDEX_SCHEMA_VERSION: u8 = 1;
/// Domain separator for the deterministic content-anchor entity-id
/// derivation (ONE-1741). Bumping this string re-keys every anchor, so it is
/// pinned like a wire constant.
const SKILL_CONTENT_ANCHOR_ID_DOMAIN: &[u8] = b"oneiron:skill-scan-content-anchor:v1";
const MAX_HUB_TEXT_BYTES: usize = 4096;
const MAX_CAPABILITY_ENTRIES: usize = 256;
const MAX_CAPABILITY_TEXT_BYTES: usize = 512;
pub(crate) const MAX_HUB_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HUB_PACKAGE_FILES: usize = 4096;
pub(crate) const MAX_HUB_PACKAGE_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_HUB_SKILL_SCAN_ENTRIES: usize = 100_000;
/// How far a scanner's clock may run ahead of this node's ingest clock before
/// its declared `scannedAt` is treated as skew and clamped (ONE-1892).
///
/// Without the clamp, one receipt stamped a century out would pin the active
/// slot for its `(content_hash, provider)` key against every later legitimate
/// scan — newest-wins turned into a denial-of-update primitive. Five minutes is
/// generous for ordinary clock drift and useless as a pin.
const SCAN_TIMESTAMP_FUTURE_SKEW_SECS: u64 = 300;

/// Generic adapter kind stored on a SKILL_HUB record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillHubKind {
    Git,
    HttpIndex,
    LocalDir,
}

impl SkillHubKind {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::HttpIndex => "http-index",
            Self::LocalDir => "local-dir",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "git" => Some(Self::Git),
            "http-index" => Some(Self::HttpIndex),
            "local-dir" => Some(Self::LocalDir),
            _ => None,
        }
    }
}

/// Friction tier for one configurable hub endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillHubTrustTier {
    Untrusted,
    Community,
    Verified,
}

impl SkillHubTrustTier {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Community => "community",
            Self::Verified => "verified",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "untrusted" => Some(Self::Untrusted),
            "community" => Some(Self::Community),
            "verified" => Some(Self::Verified),
            _ => None,
        }
    }
}

/// Default hub policy, overridden by the policy stored with each tracked ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HubSyncPolicy {
    PinnedRef,
    PinnedCommit,
    ContentHashFrozen,
    MirrorOfHub,
}

impl HubSyncPolicy {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PinnedRef => "pinned-ref",
            Self::PinnedCommit => "pinned-commit",
            Self::ContentHashFrozen => "content-hash-frozen",
            Self::MirrorOfHub => "mirror-of-hub",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pinned-ref" => Some(Self::PinnedRef),
            "pinned-commit" => Some(Self::PinnedCommit),
            "content-hash-frozen" => Some(Self::ContentHashFrozen),
            "mirror-of-hub" => Some(Self::MirrorOfHub),
            _ => None,
        }
    }

    const fn allows_automatic_update(self) -> bool {
        matches!(self, Self::PinnedRef | Self::MirrorOfHub)
    }
}

/// Engine-authored maintenance record describing one configurable skill hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillHubRecord {
    pub kind: SkillHubKind,
    pub endpoint: String,
    pub trust_tier: SkillHubTrustTier,
    pub sync_policy: HubSyncPolicy,
}

impl SkillHubRecord {
    /// Constructs and validates a hub record. The endpoint is always caller data.
    pub fn new(
        kind: SkillHubKind,
        endpoint: impl Into<String>,
        trust_tier: SkillHubTrustTier,
        sync_policy: HubSyncPolicy,
    ) -> Result<Self> {
        let record = Self {
            kind,
            endpoint: endpoint.into(),
            trust_tier,
            sync_policy,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        validate_text(
            &self.endpoint,
            MAX_HUB_TEXT_BYTES,
            "skill hub endpoint must be non-empty configurable data",
        )
    }
}

/// Encodes a SKILL_HUB body in canonical key order.
pub fn encode_skill_hub_record(record: &SkillHubRecord) -> Result<Vec<u8>> {
    record.validate()?;
    encode_value(
        &Value::Map(vec![
            (
                Value::from(SKILL_HUB_BODY_KEYS[0]),
                Value::from(record.kind.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[1]),
                Value::from(record.endpoint.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[2]),
                Value::from(record.trust_tier.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[3]),
                Value::from(record.sync_policy.as_str()),
            ),
        ]),
        "SKILL_HUB record MessagePack encode failed",
    )
}

/// Decodes a SKILL_HUB body, rejecting unknown, missing, or duplicate keys.
pub fn decode_skill_hub_record(bytes: &[u8]) -> Result<SkillHubRecord> {
    let value = decode_value(bytes, "SKILL_HUB body is not valid MessagePack")?;
    let entries = exact_map(&value, &SKILL_HUB_BODY_KEYS, "invalid SKILL_HUB body")?;
    SkillHubRecord::new(
        required_value(entries, SKILL_HUB_BODY_KEYS[0], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(SkillHubKind::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB kind"))?,
        required_text(
            entries,
            SKILL_HUB_BODY_KEYS[1],
            MAX_HUB_TEXT_BYTES,
            "invalid SKILL_HUB endpoint",
        )?,
        required_value(entries, SKILL_HUB_BODY_KEYS[2], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(SkillHubTrustTier::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB trust tier"))?,
        required_value(entries, SKILL_HUB_BODY_KEYS[3], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(HubSyncPolicy::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB sync policy"))?,
    )
}

/// Five-way provenance pin carried by a structured hub ref.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HubPin {
    Semver(String),
    Tag(String),
    Commit(String),
    ContentHash(String),
    None,
}

impl HubPin {
    /// Pinned wire discriminator.
    #[must_use]
    pub const fn pin_type(&self) -> &'static str {
        match self {
            Self::Semver(_) => "semver",
            Self::Tag(_) => "tag",
            Self::Commit(_) => "commit",
            Self::ContentHash(_) => "content_hash",
            Self::None => "none",
        }
    }

    fn value(&self) -> Option<&str> {
        match self {
            Self::Semver(value)
            | Self::Tag(value)
            | Self::Commit(value)
            | Self::ContentHash(value) => Some(value),
            Self::None => None,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::ContentHash(value) => {
                SkillContentHash::parse_hex(value)?;
            }
            Self::Semver(value) | Self::Tag(value) | Self::Commit(value) => {
                validate_text(value, MAX_HUB_TEXT_BYTES, "hub pin value must be non-empty")?;
            }
            Self::None => {}
        }
        Ok(())
    }
}

/// Mutable provenance pointer from one hub alias to canonical skill content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HubRef {
    pub hub_id: EntityId,
    pub ref_string: String,
    pub pin: HubPin,
}

impl HubRef {
    /// Constructs a validated structured hub ref.
    pub fn new(hub_id: EntityId, ref_string: impl Into<String>, pin: HubPin) -> Result<Self> {
        let hub_ref = Self {
            hub_id,
            ref_string: ref_string.into(),
            pin,
        };
        hub_ref.validate()?;
        Ok(hub_ref)
    }

    fn validate(&self) -> Result<()> {
        validate_text(
            &self.ref_string,
            MAX_HUB_TEXT_BYTES,
            "hub ref string must be non-empty",
        )?;
        self.pin.validate()
    }

    /// Encodes the exact `{hubId, refString, pin}` wire shape.
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(Value::Map(vec![
            (
                Value::from(HUB_REF_KEYS[0]),
                Value::from(self.hub_id.to_hex()),
            ),
            (
                Value::from(HUB_REF_KEYS[1]),
                Value::from(self.ref_string.as_str()),
            ),
            (
                Value::from(HUB_REF_KEYS[2]),
                Value::Map(vec![
                    (
                        Value::from(HUB_PIN_KEYS[0]),
                        Value::from(self.pin.pin_type()),
                    ),
                    (
                        Value::from(HUB_PIN_KEYS[1]),
                        self.pin.value().map_or(Value::Nil, Value::from),
                    ),
                ]),
            ),
        ]))
    }

    /// Decodes the exact structured wire shape.
    pub fn from_value(value: &Value) -> Result<Self> {
        let entries = exact_map(value, &HUB_REF_KEYS, "invalid hub ref")?;
        let hub_id = required_value(entries, HUB_REF_KEYS[0], "invalid hub ref")?
            .as_str()
            .ok_or(Error::InvalidSkillBody("hubId must be an entity id"))?;
        let hub_id = EntityId::from_hex(hub_id)
            .map_err(|_| Error::InvalidSkillBody("hubId must be an entity id"))?;
        let ref_string = required_text(
            entries,
            HUB_REF_KEYS[1],
            MAX_HUB_TEXT_BYTES,
            "refString must be non-empty",
        )?;
        let pin_entries = exact_map(
            required_value(entries, HUB_REF_KEYS[2], "invalid hub ref")?,
            &HUB_PIN_KEYS,
            "invalid hub pin",
        )?;
        let pin_type = required_value(pin_entries, HUB_PIN_KEYS[0], "invalid hub pin")?
            .as_str()
            .ok_or(Error::InvalidSkillBody("invalid hub pin type"))?;
        let pin_value = required_value(pin_entries, HUB_PIN_KEYS[1], "invalid hub pin")?;
        let text_pin = |constructor: fn(String) -> HubPin| -> Result<HubPin> {
            let value = pin_value
                .as_str()
                .ok_or(Error::InvalidSkillBody("hub pin value must be text"))?;
            validate_text(value, MAX_HUB_TEXT_BYTES, "hub pin value must be non-empty")?;
            Ok(constructor(value.to_owned()))
        };
        let pin = match pin_type {
            "semver" => text_pin(HubPin::Semver)?,
            "tag" => text_pin(HubPin::Tag)?,
            "commit" => text_pin(HubPin::Commit)?,
            "content_hash" => text_pin(HubPin::ContentHash)?,
            "none" if matches!(pin_value, Value::Nil) => HubPin::None,
            "none" => return Err(Error::InvalidSkillBody("none hub pin value must be nil")),
            _ => return Err(Error::InvalidSkillBody("invalid hub pin type")),
        };
        Self::new(hub_id, ref_string, pin)
    }
}

/// Per-ref sync state. Seen and trusted observations never overwrite one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHubRef {
    pub hub_ref: HubRef,
    pub sync_policy: HubSyncPolicy,
    pub latest_seen: Option<String>,
    pub latest_trusted: Option<String>,
}

impl TrackedHubRef {
    /// Starts tracking one ref under its per-ref policy.
    #[must_use]
    pub fn new(hub_ref: HubRef, sync_policy: HubSyncPolicy) -> Self {
        Self {
            hub_ref,
            sync_policy,
            latest_seen: None,
            latest_trusted: None,
        }
    }

    /// Records the newest observed upstream revision without trusting it.
    pub fn observe(&mut self, revision: impl Into<String>) -> Result<()> {
        let revision = revision.into();
        validate_text(
            &revision,
            MAX_HUB_TEXT_BYTES,
            "latest seen revision must be non-empty",
        )?;
        self.latest_seen = Some(revision);
        Ok(())
    }

    /// Records the newest independently trusted revision.
    pub fn trust(&mut self, revision: impl Into<String>) -> Result<()> {
        let revision = revision.into();
        validate_text(
            &revision,
            MAX_HUB_TEXT_BYTES,
            "latest trusted revision must be non-empty",
        )?;
        self.latest_trusted = Some(revision);
        Ok(())
    }
}

/// One file in a fetched, exportable skill package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubFile {
    pub path: String,
    pub content: Vec<u8>,
}

impl HubFile {
    /// Constructs an owned package file.
    #[must_use]
    pub fn new(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
        }
    }
}

/// Capability surface used by the rug-pull widening diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillCapabilitySurface {
    pub bins: BTreeSet<String>,
    pub env: BTreeSet<String>,
    pub mcp: BTreeSet<String>,
    pub allowed_tools: BTreeSet<String>,
}

impl SkillCapabilitySurface {
    /// Adds a required binary.
    #[must_use]
    pub fn with_bin(mut self, value: impl Into<String>) -> Self {
        self.bins.insert(value.into());
        self
    }

    /// Adds a required environment key.
    #[must_use]
    pub fn with_env(mut self, value: impl Into<String>) -> Self {
        self.env.insert(value.into());
        self
    }

    /// Adds a required MCP capability.
    #[must_use]
    pub fn with_mcp(mut self, value: impl Into<String>) -> Self {
        self.mcp.insert(value.into());
        self
    }

    /// Adds an allowed tool.
    #[must_use]
    pub fn with_allowed_tool(mut self, value: impl Into<String>) -> Self {
        self.allowed_tools.insert(value.into());
        self
    }

    fn validate(&self) -> Result<()> {
        for entries in [&self.bins, &self.env, &self.mcp, &self.allowed_tools] {
            if entries.len() > MAX_CAPABILITY_ENTRIES {
                return Err(Error::InvalidSkillBody(
                    "capability surface has too many entries",
                ));
            }
            for entry in entries {
                validate_text(
                    entry,
                    MAX_CAPABILITY_TEXT_BYTES,
                    "capability entries must be non-empty",
                )?;
            }
        }
        Ok(())
    }

    fn is_same_or_narrower_than(&self, prior: &Self) -> bool {
        self.bins.is_subset(&prior.bins)
            && self.env.is_subset(&prior.env)
            && self.mcp.is_subset(&prior.mcp)
            && self.allowed_tools.is_subset(&prior.allowed_tools)
    }
}

/// Offline package fetched by an adapter or supplied directly to a vault door.
#[derive(Debug, Clone, PartialEq)]
pub struct HubPackage {
    pub record: SkillRecord,
    pub files: Vec<HubFile>,
    pub capabilities: SkillCapabilitySurface,
}

impl HubPackage {
    /// Constructs a package. Tree validation runs when its canonical hash is read.
    #[must_use]
    pub fn new(
        record: SkillRecord,
        files: Vec<HubFile>,
        capabilities: SkillCapabilitySurface,
    ) -> Self {
        Self {
            record,
            files,
            capabilities,
        }
    }

    /// Recomputes canonical identity from the package tree.
    pub fn content_hash(&self) -> Result<SkillContentHash> {
        self.capabilities.validate()?;
        if self.files.len() > MAX_HUB_PACKAGE_FILES {
            return Err(Error::InvalidSkillBody("hub package has too many files"));
        }
        let mut total_bytes = 0_usize;
        for file in &self.files {
            if file.content.len() > MAX_HUB_FILE_BYTES {
                return Err(Error::InvalidSkillBody(
                    "hub package file exceeds the maximum size",
                ));
            }
            total_bytes =
                total_bytes
                    .checked_add(file.content.len())
                    .ok_or(Error::InvalidSkillBody(
                        "hub package total size exceeds the maximum",
                    ))?;
            if total_bytes > MAX_HUB_PACKAGE_TOTAL_BYTES {
                return Err(Error::InvalidSkillBody(
                    "hub package total size exceeds the maximum",
                ));
            }
        }
        canonical_skill_tree_hash(
            self.files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )
    }

    /// Returns a clean, path-sorted folder independent of package origin.
    pub fn export_files(&self) -> Result<Vec<HubFile>> {
        self.content_hash()?;
        let mut files = self.files.clone();
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        Ok(files)
    }
}

/// One http-index discovery row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubIndexEntry {
    pub name: String,
    pub description: String,
    pub version: String,
    pub content_hash: SkillContentHash,
    pub ref_string: String,
}

/// Pluggable package-fetch boundary behind the hub doors.
pub trait SkillHubAdapter {
    /// Hub entity whose refs this adapter resolves.
    fn hub_id(&self) -> EntityId;

    /// Adapter kind compatible with the hub record.
    fn kind(&self) -> SkillHubKind;

    /// Fetches a package for a structured ref.
    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage>;

    /// Returns discovery rows when the adapter exposes an index.
    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Default)]
struct AdapterPackageStore {
    packages: BTreeMap<(String, HubPin), HubPackage>,
}

impl AdapterPackageStore {
    fn insert(&mut self, ref_string: impl Into<String>, pin: HubPin, package: HubPackage) {
        self.packages.insert((ref_string.into(), pin), package);
    }

    fn fetch(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        self.packages
            .get(&(hub_ref.ref_string.clone(), hub_ref.pin.clone()))
            .cloned()
            .ok_or(Error::InvalidSkillBody("hub ref package was not found"))
    }
}

macro_rules! package_adapter {
    ($name:ident, $kind:expr) => {
        #[doc = "In-process package source for the generic adapter boundary."]
        #[derive(Debug, Clone)]
        pub struct $name {
            hub_id: EntityId,
            store: AdapterPackageStore,
        }

        impl $name {
            /// Constructs an empty adapter bound to one hub entity.
            #[must_use]
            pub fn new(hub_id: EntityId) -> Self {
                Self {
                    hub_id,
                    store: AdapterPackageStore::default(),
                }
            }

            /// Adds a fetchable offline package.
            pub fn insert_package(
                &mut self,
                ref_string: impl Into<String>,
                pin: HubPin,
                package: HubPackage,
            ) {
                self.store.insert(ref_string, pin, package);
            }
        }

        impl SkillHubAdapter for $name {
            fn hub_id(&self) -> EntityId {
                self.hub_id
            }

            fn kind(&self) -> SkillHubKind {
                $kind
            }

            fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
                if hub_ref.hub_id != self.hub_id {
                    return Err(Error::InvalidSkillBody(
                        "adapter cannot fetch a ref from another hub",
                    ));
                }
                self.store.fetch(hub_ref)
            }
        }
    };
}

package_adapter!(GitSkillHubAdapter, SkillHubKind::Git);
package_adapter!(LocalDirSkillHubAdapter, SkillHubKind::LocalDir);

/// Generic discovery-index adapter with injected index and package data.
#[derive(Debug, Clone)]
pub struct HttpIndexSkillHubAdapter {
    hub_id: EntityId,
    index: Vec<HubIndexEntry>,
    store: AdapterPackageStore,
}

impl HttpIndexSkillHubAdapter {
    /// Constructs an adapter bound to one hub entity.
    #[must_use]
    pub fn new(hub_id: EntityId, index: Vec<HubIndexEntry>) -> Self {
        Self {
            hub_id,
            index,
            store: AdapterPackageStore::default(),
        }
    }

    /// Adds a package fetchable from an index row's ref string.
    pub fn insert_package(
        &mut self,
        ref_string: impl Into<String>,
        pin: HubPin,
        package: HubPackage,
    ) {
        self.store.insert(ref_string, pin, package);
    }
}

impl SkillHubAdapter for HttpIndexSkillHubAdapter {
    fn hub_id(&self) -> EntityId {
        self.hub_id
    }

    fn kind(&self) -> SkillHubKind {
        SkillHubKind::HttpIndex
    }

    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        if hub_ref.hub_id != self.hub_id {
            return Err(Error::InvalidSkillBody(
                "adapter cannot fetch a ref from another hub",
            ));
        }
        self.store.fetch(hub_ref)
    }

    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        Ok(self.index.clone())
    }
}

/// Result of a policy-checked hub sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubSyncDisposition {
    Applied,
    Proposed {
        proposal_id: EntityId,
        approval: ClaimApprovalStatus,
    },
    RefusedByPolicy,
}

impl HubSyncDisposition {
    /// Approval carried by a proposal disposition.
    #[must_use]
    pub const fn approval_status(&self) -> Option<ClaimApprovalStatus> {
        match self {
            Self::Proposed { approval, .. } => Some(*approval),
            Self::Applied | Self::RefusedByPolicy => None,
        }
    }

    /// Whether the incoming package landed as canon.
    #[must_use]
    pub const fn applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Independent scanner verdict axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl ScanVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        }
    }
}

/// Scanner-reported risk level.
///
/// Ordered least-to-most severe, and the derived `Ord` IS that severity order:
/// the activation dial (`skill_scan`) compares stored risks against a threshold
/// with `>=`, so the variant sequence here is a wire-facing decision, not a
/// cosmetic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ScanRiskLevel {
    /// The pinned on-disk string for this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Scanner coverage completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCompleteness {
    Partial,
    Complete,
}

impl ScanCompleteness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Complete => "complete",
        }
    }
}

/// Governance axis stored separately from scanner signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillGovernance {
    Recommended,
    Discouraged,
    Prohibited,
}

impl SkillGovernance {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Recommended => "recommended",
            Self::Discouraged => "discouraged",
            Self::Prohibited => "prohibited",
        }
    }
}

/// One provider receipt attached to a canonical content hash and scan time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillScanReceipt {
    pub provider: String,
    pub scanned_at: u64,
    pub verdict: ScanVerdict,
    pub risk_level: ScanRiskLevel,
    pub completeness: ScanCompleteness,
    pub governance: SkillGovernance,
}

impl SkillScanReceipt {
    /// Constructs a scanner receipt with an orthogonal governance value.
    pub fn new(
        provider: impl Into<String>,
        scanned_at: u64,
        verdict: ScanVerdict,
        risk_level: ScanRiskLevel,
        completeness: ScanCompleteness,
        governance: SkillGovernance,
    ) -> Result<Self> {
        let receipt = Self {
            provider: provider.into(),
            scanned_at,
            verdict,
            risk_level,
            completeness,
            governance,
        };
        validate_text(
            &receipt.provider,
            MAX_HUB_TEXT_BYTES,
            "scan provider must be non-empty",
        )?;
        Ok(receipt)
    }
}

/// Refusal-first dependency resolution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubDependencyResolution {
    Materialized(EntityId),
    RefusedCrossHub,
    RefusedMissingPackage,
}

impl Vault {
    /// Imports a package directly through the offline hub door.
    pub fn import_skill_from_hub(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_skill_from_hub_with_id(hub_ref, package, EntityId::now(), occurred, learned_at)
    }

    /// Fetches through an adapter and enters the same import door.
    pub fn import_skill_from_adapter<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let package = adapter.fetch_package(hub_ref)?;
        self.import_skill_from_hub(hub_ref, &package, occurred, learned_at)
    }

    /// Fetches an indexed adapter package and cross-checks its declared hash
    /// against the engine's canonical recomputation before any write begins.
    pub fn ingest_skill_from_adapter_checked<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        entry: &HubIndexEntry,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let declared_hex = entry.content_hash.to_hex();
        let hub_ref = HubRef::new(
            adapter.hub_id(),
            entry.ref_string.clone(),
            HubPin::ContentHash(declared_hex.clone()),
        )?;
        let package = adapter.fetch_package(&hub_ref)?;
        let canonical_hash = package.content_hash()?;
        let mut canonical_record = package.record.clone();
        canonical_record.content_hash = Some(canonical_hash);
        cross_check_declared_content_hash(&canonical_record, &declared_hex)?;
        self.import_skill_from_hub_with_id(&hub_ref, &package, preferred_id, occurred, learned_at)
    }

    fn import_skill_from_hub_with_id(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        if package
            .record
            .content_hash
            .is_some_and(|declared| declared != content_hash)
        {
            return Err(Error::InvalidSkillBody(
                "package content hash does not match its canonical file tree",
            ));
        }
        if let HubPin::ContentHash(pinned_hash) = &hub_ref.pin
            && SkillContentHash::parse_hex(pinned_hash)? != content_hash
        {
            return Err(Error::InvalidSkillBody("content-hash-pinned ref drifted"));
        }
        if package.record.source != ClaimSource::Imported {
            return Err(Error::InvalidSkillBody(
                "hub import package must carry imported source",
            ));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let entity =
            match self.imported_skill_entity_for_content_hash_in_txn(&wtxn, content_hash)? {
                Some(existing) => {
                    let existing_record = self.read_skill_record_in_txn(&wtxn, &existing)?;
                    if existing_record.skill_id != package.record.skill_id {
                        return Err(Error::InvalidSkillBody(
                            "hub import content hash collides with a different skill id",
                        ));
                    }
                    existing
                }
                None => {
                    let mut candidate = package.record.clone();
                    candidate.lifecycle_status = SkillLifecycle::Candidate;
                    // ONE-1892: consent is a LOCAL act, so the import door
                    // stamps it rather than copying it. A hub package is
                    // untrusted input all the way down — it declares its own
                    // `approvalStatus`, and an `approved` stamp arriving that
                    // way would be a remote party answering the owner's
                    // question for him: the activation consult only escalates
                    // `auto`, so a self-declared approval would walk a
                    // credential-bearing skill into `active` with no tap. The
                    // sync door already holds this law one line at a time
                    // ("canonical approval/lifecycle state stays local"); the
                    // import door is where the FIRST stamp is minted, and
                    // `auto` — the same default a locally born candidate gets
                    // — is the only honest one.
                    candidate.approval_status = ClaimApprovalStatus::Auto;
                    candidate.content_hash = Some(content_hash);
                    self.apply_hub_import_skill_record(
                        &mut wtxn,
                        &preferred_id,
                        &candidate,
                        occurred,
                        learned_at,
                    )?;
                    self.write_admitted_capability_surface_in_txn(
                        &mut wtxn,
                        &preferred_id,
                        &package.capabilities,
                    )?;
                    preferred_id
                }
            };

        match self.read_admitted_capability_surface_in_txn(&wtxn, &entity)? {
            Some(admitted) if admitted != package.capabilities => {
                return Err(Error::InvalidSkillBody(
                    "matching content hash carries conflicting capabilities",
                ));
            }
            Some(_) => {}
            None => self.write_admitted_capability_surface_in_txn(
                &mut wtxn,
                &entity,
                &package.capabilities,
            )?,
        }
        self.append_hub_provenance_in_txn(
            &mut wtxn,
            &entity,
            content_hash,
            hub_ref,
            occurred,
            learned_at,
        )?;
        // ONE-1892: the ONE producer hook for the import family — the two
        // public import doors and the dependency-materialization door all
        // delegate here, so imported bytes carry a scanner receipt without any
        // caller remembering to ask for one.
        self.scan_and_ingest_on_import_in_txn(
            &mut wtxn,
            &entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(entity)
    }

    /// Counts active mutable provenance aliases for one skill entity.
    pub fn skill_hub_provenance_count(&self, entity: &EntityId) -> Result<usize> {
        Ok(self
            .active_claims_for_predicate(entity, PREDICATE_SKILL_HUB_PROVENANCE)?
            .len())
    }

    /// Applies same/narrower updates and proposes capability widening.
    pub fn sync_skill_from_hub(
        &self,
        entity: &EntityId,
        hub_ref: &HubRef,
        package: &HubPackage,
        sync_policy: HubSyncPolicy,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubSyncDisposition> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.read_skill_record_in_txn(&wtxn, entity)?;
        if current.source != ClaimSource::Imported
            || package.record.source != ClaimSource::Imported
            || current.skill_id != package.record.skill_id
        {
            return Err(Error::InvalidSkillBody(
                "hub sync package must match an imported skill",
            ));
        }
        if package
            .record
            .content_hash
            .is_some_and(|declared| declared != content_hash)
        {
            return Err(Error::InvalidSkillBody(
                "package content hash does not match its canonical file tree",
            ));
        }
        // A content-hash pin binds the ref's identity on every sync path, not only under the
        // frozen policy (mirrors the import door at import_skill_from_hub_with_id).
        if let HubPin::ContentHash(pinned) = &hub_ref.pin
            && SkillContentHash::parse_hex(pinned)? != content_hash
        {
            return Err(Error::InvalidSkillBody("content-hash-pinned ref drifted"));
        }
        if sync_policy == HubSyncPolicy::ContentHashFrozen
            && !matches!(&hub_ref.pin, HubPin::ContentHash(_))
        {
            return Err(Error::InvalidSkillBody(
                "content-hash-frozen policy requires a content_hash pin",
            ));
        }
        if !sync_policy.allows_automatic_update() {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }

        let provenance_rows =
            self.active_claims_for_predicate_in_txn(&wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        // Legacy direct imports remain permissive until vault-bound authority lands in ONE-1751.
        if !provenance_rows.is_empty() {
            let mut matches_provenance_alias = false;
            for (_, body, _) in &provenance_rows {
                let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                    Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
                )?)?;
                if same_hub_alias(&stored_ref, hub_ref) {
                    matches_provenance_alias = true;
                    break;
                }
            }
            if !matches_provenance_alias {
                return Ok(HubSyncDisposition::RefusedByPolicy);
            }
        }

        let admitted = self
            .read_admitted_capability_surface_in_txn(&wtxn, entity)?
            .unwrap_or_default();
        if !package.capabilities.is_same_or_narrower_than(&admitted) {
            let hub_value = hub_ref.to_value()?;
            let hash_hex = content_hash.to_hex();
            let encoded_caps = encode_capability_surface_value(&package.capabilities);
            for (proposal_id, body, _) in self.active_claims_for_predicate_in_txn(
                &wtxn,
                entity,
                PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
            )? {
                if map_value(&body.value, "hubRef") == Some(&hub_value)
                    && map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
                    && map_text(&body.value, "version") == Some(package.record.version.as_str())
                    && map_value(&body.value, "capabilities") == Some(&encoded_caps)
                {
                    return Ok(HubSyncDisposition::Proposed {
                        proposal_id,
                        approval: ClaimApprovalStatus::Proposed,
                    });
                }
            }

            let proposal_id = EntityId::now();
            let mut proposal = ClaimBody::new(
                PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
                ClaimSubject::Entity(*entity),
                Value::Map(vec![
                    (Value::from("hubRef"), hub_value),
                    (
                        Value::from("version"),
                        Value::from(package.record.version.as_str()),
                    ),
                    (Value::from("contentHash"), Value::from(hash_hex)),
                    (Value::from("capabilities"), encoded_caps),
                ]),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            );
            proposal.source = Some(ClaimSource::Imported);
            self.put_reserved_claim_in_txn(
                &mut wtxn,
                &proposal_id,
                &proposal,
                occurred,
                learned_at,
            )?;
            wtxn.commit()?;
            return Ok(HubSyncDisposition::Proposed {
                proposal_id,
                approval: ClaimApprovalStatus::Proposed,
            });
        }

        let content_hash_changed = current.content_hash != Some(content_hash);
        if content_hash_changed
            && self
                .skill_entity_for_content_hash_in_txn(&wtxn, content_hash)?
                .is_some_and(|owner| owner != *entity)
        {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }

        let mut updated = package.record.clone();
        // Hub sync mutates content fields; canonical approval/lifecycle state stays local.
        updated.approval_status = current.approval_status;
        updated.lifecycle_status = current.lifecycle_status;
        updated.content_hash = Some(content_hash);
        self.apply_hub_sync_skill_record(&mut wtxn, entity, &updated, occurred, learned_at)?;
        self.write_admitted_capability_surface_in_txn(&mut wtxn, entity, &package.capabilities)?;
        if content_hash_changed {
            self.replace_hub_provenance_in_txn(
                &mut wtxn,
                entity,
                content_hash,
                hub_ref,
                occurred,
                learned_at,
            )?;
        }
        // ONE-1892: the update door's half of the producer. Unconditional
        // rather than gated on `content_hash_changed` because the guard that
        // matters is content-keyed — an unchanged hash that already carries a
        // static receipt is a no-op here, while a hash that never got one
        // (bytes born through a non-hub path) is scanned on this pass.
        self.scan_and_ingest_on_import_in_txn(
            &mut wtxn,
            entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(HubSyncDisposition::Applied)
    }

    /// Ingests a scanner receipt, superseding every prior active row for the
    /// same content-global `(content_hash, provider)` without gating admission.
    pub fn ingest_skill_scan_verdict(
        &self,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipt: &SkillScanReceipt,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        validate_skill_scan_receipt(receipt)?;
        let mut wtxn = self.store.env.write_txn()?;
        let claim_id = self.ingest_skill_scan_verdict_in_txn(
            &mut wtxn,
            entity,
            content_hash,
            receipt,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(claim_id)
    }

    fn ingest_skill_scan_verdict_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipt: &SkillScanReceipt,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let skill = self.read_skill_record_in_txn(&*wtxn, entity)?;
        if skill.content_hash != Some(content_hash) {
            return Err(Error::InvalidSkillBody(
                "scan receipt content hash does not match the skill",
            ));
        }
        let hash_hex = content_hash.to_hex();
        // ONE-1741: verdicts hang off the deterministic content anchor, not the
        // submitting holder, so ensure it exists before the reserved put (the
        // claim door requires the subject entity) and dedup against the single
        // anchor rather than looping over every current holder.
        let anchor = self.ensure_skill_content_anchor_in_txn(wtxn, content_hash, learned_at)?;
        let scanned_at = clamp_scan_timestamp(receipt.scanned_at, learned_at);
        let mut prior_rows = Vec::new();
        for (id, body, occurred_start) in
            self.active_claims_for_predicate_in_txn(&*wtxn, &anchor, PREDICATE_SKILL_SCAN_VERDICT)?
        {
            if map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
                && map_text(&body.value, "provider") == Some(receipt.provider.as_str())
            {
                prior_rows.push((id, occurred_start, scan_verdict_row_scanned_at(&body)?));
            }
        }

        let claim_id = EntityId::now();
        let mut value = vec![
            (Value::from("contentHash"), Value::from(hash_hex)),
            (
                Value::from("provider"),
                Value::from(receipt.provider.as_str()),
            ),
            (Value::from("scannedAt"), Value::from(scanned_at)),
            (
                Value::from("verdict"),
                Value::from(receipt.verdict.as_str()),
            ),
            (
                Value::from("riskLevel"),
                Value::from(receipt.risk_level.as_str()),
            ),
            (
                Value::from("completeness"),
                Value::from(receipt.completeness.as_str()),
            ),
            (
                Value::from("governance"),
                Value::from(receipt.governance.as_str()),
            ),
        ];
        if scanned_at != receipt.scanned_at {
            // The clamp is RECEIPTED, not silent: the row reports the time the
            // comparison used plus what the provider actually declared, so a
            // skewed scanner is diagnosable from the ledger alone.
            value.push((
                Value::from("scannedAtDeclared"),
                Value::from(receipt.scanned_at),
            ));
        }
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_SCAN_VERDICT,
            ClaimSubject::Entity(anchor),
            Value::Map(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        self.put_reserved_claim_in_txn(wtxn, &claim_id, &body, occurred, learned_at)?;

        // F5 newest-wins (ONE-1892): the ACTIVE verdict for a
        // `(content_hash, provider)` key is the one with the latest SCAN time,
        // not the one ingested last. A late-arriving older scan is real
        // evidence and is kept — it lands as a row and is closed under the
        // newer one in the same transaction, so it stays auditable without ever
        // holding the active slot. Ties go to the later call: two scans of the
        // same bytes at the same second are the same finding, and the fresher
        // ingest is the one whose provenance the caller just asserted.
        let newest_prior = prior_rows
            .iter()
            .max_by_key(|(_, _, prior_scanned_at)| *prior_scanned_at)
            .copied();
        if let Some((newest_id, newest_start, newest_scanned_at)) = newest_prior
            && scanned_at < newest_scanned_at
        {
            let superseded_at = learned_at.max(occurred.start).max(newest_start);
            self.supersede_reserved_claim_in_txn(wtxn, &newest_id, &claim_id, superseded_at)?;
            return Ok(claim_id);
        }
        for (prior_id, prior_start, _) in prior_rows {
            let superseded_at = learned_at.max(prior_start);
            self.supersede_reserved_claim_in_txn(wtxn, &claim_id, &prior_id, superseded_at)?;
        }
        Ok(claim_id)
    }

    /// Runs the engine's own static scan over an incoming package and ingests
    /// its receipt (ONE-1892) — the production PRODUCER behind
    /// [`Vault::ingest_skill_scan_verdict`].
    ///
    /// Idempotent on the CONTENT, not on the caller: the static pass is a pure
    /// function of the package bytes, so bytes that already carry an active
    /// receipt from this provider are left alone. Re-running would mint a row
    /// identical but for its timestamp and supersede the row it duplicates —
    /// churn with no new evidence in it. That also means a second hub alias
    /// over known bytes adds no verdict, while bytes first seen through a
    /// non-hub birth path get scanned the moment they arrive at this door.
    pub(crate) fn scan_and_ingest_on_import_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        package: &HubPackage,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let already_scanned = self
            .skill_scan_verdicts_for_content_hash_in_txn(&*wtxn, content_hash)?
            .iter()
            .any(|body| {
                map_text(&body.value, "provider")
                    == Some(crate::skill_scan::SCAN_PROVIDER_STATIC_V1)
            });
        if already_scanned {
            return Ok(());
        }
        let receipt = crate::skill_scan::run_static_skill_scan(package, learned_at)?;
        self.ingest_skill_scan_verdict_in_txn(
            wtxn,
            entity,
            content_hash,
            &receipt,
            occurred,
            learned_at,
        )?;
        Ok(())
    }

    /// Ingests independent provider receipts as content-keyed audit signals.
    pub fn ingest_skill_audit_verdicts(
        &self,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipts: &[SkillScanReceipt],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<usize> {
        // Validate the full caller-owned array before opening the transaction,
        // so a malformed middle receipt cannot follow any staged write.
        for receipt in receipts {
            validate_skill_scan_receipt(receipt)?;
        }

        let mut wtxn = self.store.env.write_txn()?;
        for receipt in receipts {
            self.ingest_skill_scan_verdict_in_txn(
                &mut wtxn,
                entity,
                content_hash,
                receipt,
                occurred,
                learned_at,
            )?;
        }
        wtxn.commit()?;
        Ok(receipts.len())
    }

    /// Reads active scanner receipts for canonical bytes off the deterministic
    /// content anchor. The anchor is derived from the content hash and never
    /// departs, so discovery is independent of which SKILL holders currently
    /// carry the bytes (ONE-1741).
    pub fn skill_scan_verdicts_for_content_hash(
        &self,
        content_hash: SkillContentHash,
    ) -> Result<Vec<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.skill_scan_verdicts_for_content_hash_in_txn(&rtxn, content_hash)
    }

    /// [`Vault::skill_scan_verdicts_for_content_hash`] inside the caller's
    /// transaction — the activation consult reads from inside the write
    /// transaction that performs the activation, so no verdict can land in
    /// between the consult and the write it governs.
    pub(crate) fn skill_scan_verdicts_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Vec<ClaimBody>> {
        skill_scan_verdicts_for_content_hash_in_store(&self.store, rtxn, content_hash)
    }

    /// Refuses cross-hub dependencies before any package can materialize.
    pub fn resolve_hub_dependency(
        &self,
        importing_ref: &HubRef,
        dependency_ref: &HubRef,
        dependency_entity: &EntityId,
        package: Option<&HubPackage>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubDependencyResolution> {
        importing_ref.validate()?;
        dependency_ref.validate()?;
        if importing_ref.hub_id != dependency_ref.hub_id {
            return Ok(HubDependencyResolution::RefusedCrossHub);
        }
        let Some(package) = package else {
            return Ok(HubDependencyResolution::RefusedMissingPackage);
        };
        self.import_skill_from_hub_with_id(
            dependency_ref,
            package,
            *dependency_entity,
            occurred,
            learned_at,
        )
        .map(HubDependencyResolution::Materialized)
    }

    /// The holder of these exact canonical bytes, whichever birth path put it
    /// there — the shared-namespace dedup probe (ONE-1446 reads it too).
    pub(crate) fn skill_entity_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Option<EntityId>> {
        Ok(self
            .structured_skills_for_content_hash_in_txn(rtxn, content_hash)?
            .into_iter()
            .next()
            .map(|(entity, _)| entity))
    }

    fn imported_skill_entity_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Option<EntityId>> {
        for (entity, record) in
            self.structured_skills_for_content_hash_in_txn(rtxn, content_hash)?
        {
            if record.source == ClaimSource::Imported {
                return Ok(Some(entity));
            }
        }
        Ok(None)
    }

    fn structured_skills_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Vec<(EntityId, SkillRecord)>> {
        let prefix = content_hash_index_prefix(content_hash);
        let mut skills = Vec::new();
        for (scanned, entry) in self
            .store
            .vault_meta
            .prefix_iter(rtxn, &prefix)?
            .enumerate()
        {
            if scanned >= MAX_HUB_SKILL_SCAN_ENTRIES {
                return Err(Error::IndexOverflow("skill_entity_for_content_hash"));
            }
            let (key, _) = entry?;
            let entity =
                crate::entity_id::parse_entity_id(&key[prefix.len()..], "skill content hash index")
                    .map_err(|_| Error::CorruptedIndex("skill content hash index"))?;
            let Some(raw) = self.store.entities.get(rtxn, entity.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL {
                continue;
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let record = match decode_skill_record(body) {
                Ok(record) => record,
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(body) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if record.content_hash == Some(content_hash) {
                skills.push((entity, record));
            }
        }
        Ok(skills)
    }

    fn find_structured_skill_entity_in_txn<T>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        mut find: impl FnMut(EntityId, &SkillRecord) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        for (scanned, entry) in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_SKILL])?
            .enumerate()
        {
            if scanned >= MAX_HUB_SKILL_SCAN_ENTRIES {
                return Err(Error::IndexOverflow("skill_entity_for_content_hash"));
            }
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("skill type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL {
                return Err(Error::CorruptedIndex("skill type index"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let record = match decode_skill_record(body) {
                Ok(record) => record,
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(body) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(found) = find(id, &record)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn active_hub_aliases_on_other_skill_entities_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
        hub_ref: &HubRef,
    ) -> Result<Vec<(EntityId, u64)>> {
        let mut prior_rows = Vec::new();
        self.find_structured_skill_entity_in_txn(rtxn, |candidate, _| {
            if candidate == *entity {
                return Ok(None::<()>);
            }
            for (claim_id, body, occurred_start) in self.active_claims_for_predicate_in_txn(
                rtxn,
                &candidate,
                PREDICATE_SKILL_HUB_PROVENANCE,
            )? {
                let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                    Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
                )?)?;
                if same_hub_alias(&stored_ref, hub_ref) {
                    prior_rows.push((claim_id, occurred_start));
                }
            }
            Ok(None)
        })?;
        Ok(prior_rows)
    }

    fn append_hub_provenance_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let hub_value = hub_ref.to_value()?;
        let prior_rows =
            self.active_hub_aliases_on_other_skill_entities_in_txn(&*wtxn, entity, hub_ref)?;
        let mut replacement_id = None;
        for (claim_id, body, _) in
            self.active_claims_for_predicate_in_txn(&*wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
            )?)?;
            if same_hub_alias(&stored_ref, hub_ref) {
                replacement_id = Some(claim_id);
                break;
            }
        }
        let replacement_id = if let Some(replacement_id) = replacement_id {
            replacement_id
        } else {
            let replacement_id = EntityId::now();
            let mut body = ClaimBody::new(
                PREDICATE_SKILL_HUB_PROVENANCE,
                ClaimSubject::Entity(*entity),
                Value::Map(vec![
                    (
                        Value::from("contentHash"),
                        Value::from(content_hash.to_hex()),
                    ),
                    (Value::from("hubRef"), hub_value),
                ]),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::Observed);
            self.put_reserved_claim_in_txn(wtxn, &replacement_id, &body, occurred, learned_at)?;
            replacement_id
        };
        for (prior_id, prior_start) in prior_rows {
            self.supersede_reserved_claim_in_txn(
                wtxn,
                &replacement_id,
                &prior_id,
                learned_at.max(prior_start),
            )?;
        }
        Ok(())
    }

    fn replace_hub_provenance_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let hub_value = hub_ref.to_value()?;
        let mut prior_rows = Vec::new();
        for (id, body, occurred_start) in
            self.active_claims_for_predicate_in_txn(&*wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
            )?)?;
            prior_rows.push((id, occurred_start));
        }

        let replacement_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_HUB_PROVENANCE,
            ClaimSubject::Entity(*entity),
            Value::Map(vec![
                (
                    Value::from("contentHash"),
                    Value::from(content_hash.to_hex()),
                ),
                (Value::from("hubRef"), hub_value),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        self.put_reserved_claim_in_txn(wtxn, &replacement_id, &body, occurred, learned_at)?;
        for (prior_id, prior_start) in prior_rows {
            self.supersede_reserved_claim_in_txn(
                wtxn,
                &replacement_id,
                &prior_id,
                learned_at.max(prior_start),
            )?;
        }
        Ok(replacement_id)
    }

    /// Ensures the deterministic content-anchor entity for `content_hash`
    /// exists, minting it via the engine-authored maintenance door on first
    /// use, and returns its id. Verdict claims are subjected to this anchor, so
    /// it must exist before the reserved put runs (the claim door requires the
    /// subject entity). The anchor body carries the 32-byte content hash so the
    /// record is self-describing.
    ///
    /// An entity already sitting at the derived id must BE an anchor (ONE-1892).
    /// The pre-existence check is what makes the mint idempotent, so without a
    /// type assert any entity that landed on the derived id first would be
    /// silently adopted as the subject of every verdict for those bytes — a
    /// squat the verdict reader could never see. The id is a domain-separated
    /// digest, so this is a corruption guard, not a policy gate; it fails
    /// closed and writes nothing.
    fn ensure_skill_content_anchor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        content_hash: SkillContentHash,
        learned_at: u64,
    ) -> Result<EntityId> {
        let anchor = skill_content_anchor_entity_id(content_hash)?;
        if let Some(raw) = self.store.entities.get(&*wtxn, anchor.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL_CONTENT_ANCHOR {
                return Err(Error::SkillContentAnchorTypeMismatch {
                    existing: header.entity_type,
                });
            }
            return Ok(anchor);
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: anchor,
                entity_type: ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data: content_hash.as_bytes().to_vec(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(anchor)
    }

    /// Drops the content-hash index row for a SKILL as it leaves the active
    /// store, so import/sync dedup never resolves a deleted holder. The
    /// soft-erase path relies on this because it truncates the entity body in
    /// place rather than routing through `deindex_entity` (which maintains the
    /// index for hard purges and batch deletes). Verdict discovery no longer
    /// depends on this index (verdicts anchor to the content bytes), so a
    /// departing holder never disturbs a verdict.
    pub(crate) fn maintain_skill_content_hash_index_on_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
    ) -> Result<()> {
        let Some(raw) = self.store.entities.get(&*wtxn, entity.as_bytes())? else {
            return Ok(());
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Ok(());
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let content_hash = match decode_skill_record(body) {
            Ok(record) => record.content_hash,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let Some(content_hash) = content_hash else {
            return Ok(());
        };
        maintain_skill_content_hash_index_for_delete(&self.store, wtxn, entity, content_hash)
    }

    fn active_claims_for_predicate(
        &self,
        entity: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_claims_for_predicate_in_txn(&rtxn, entity, predicate)
            .map(|rows| rows.into_iter().map(|(id, body, _)| (id, body)).collect())
    }

    fn active_claims_for_predicate_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
        let mut rows = Vec::new();
        for id in self.claims_for_subject_in_txn(rtxn, entity)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &id)? else {
                continue;
            };
            if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
                let raw = self
                    .store
                    .entities
                    .get(rtxn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("claim_of edge"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                rows.push((id, body, header.occurred_start));
            }
        }
        Ok(rows)
    }

    fn read_admitted_capability_surface_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<SkillCapabilitySurface>> {
        let key = capability_state_key(entity);
        self.store
            .vault_meta
            .get(rtxn, &key)?
            .map(|bytes| decode_capability_surface(&bytes))
            .transpose()
    }

    fn write_admitted_capability_surface_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        surface: &SkillCapabilitySurface,
    ) -> Result<()> {
        surface.validate()?;
        let value = encode_value(
            &encode_capability_surface_value(surface),
            "capability surface MessagePack encode failed",
        )?;
        let key = capability_state_key(entity);
        self.store.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }
}

fn capability_state_key(entity: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CAPABILITY_STATE_PREFIX.len() + 16);
    key.extend_from_slice(CAPABILITY_STATE_PREFIX);
    key.extend_from_slice(entity.as_bytes());
    key
}

/// Derives the deterministic CONTENT-ANCHOR `EntityId` for `content_hash`
/// (ONE-1741): `id16 = first16(SHA-256(domain ‖ content_hash))`. Two nodes
/// ingesting the same bytes MUST converge on the same anchor, so this is a
/// pure function of the content hash — never `EntityId::now()`. On the
/// astronomically rare chance the first 16 digest bytes hit a reserved-id
/// sentinel (`is_reserved_entity_id_bytes`: all-`0x00` / all-`0xFF` /
/// `[type, 0xFF×15]`), the input is perturbed with a rising counter and
/// re-hashed until the derivation lands on a valid id. The base case (counter
/// 0) appends nothing, so the common path is exactly the domain-separated
/// digest; the terminal `Err` is unreachable and kept only for exhaustiveness.
pub(crate) fn skill_content_anchor_entity_id(content_hash: SkillContentHash) -> Result<EntityId> {
    for perturbation in 0..=u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(SKILL_CONTENT_ANCHOR_ID_DOMAIN);
        hasher.update(content_hash.as_bytes());
        if perturbation > 0 {
            hasher.update(perturbation.to_be_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "content anchor id derivation exhausted every perturbation",
    ))
}

fn content_hash_index_prefix(content_hash: SkillContentHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONTENT_HASH_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(CONTENT_HASH_INDEX_PREFIX);
    key.extend_from_slice(content_hash.as_bytes());
    key
}

fn content_hash_index_key(content_hash: SkillContentHash, entity: &EntityId) -> Vec<u8> {
    let mut key = content_hash_index_prefix(content_hash);
    key.extend_from_slice(entity.as_bytes());
    key
}

pub(crate) fn maintain_skill_content_hash_index_for_put(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    previous_hash: Option<SkillContentHash>,
    content_hash: Option<SkillContentHash>,
) -> Result<()> {
    if previous_hash != content_hash
        && let Some(previous_hash) = previous_hash
    {
        store
            .vault_meta
            .delete(wtxn, &content_hash_index_key(previous_hash, entity))?;
    }
    if let Some(content_hash) = content_hash {
        store
            .vault_meta
            .put(wtxn, &content_hash_index_key(content_hash, entity), &[])?;
    }
    Ok(())
}

pub(crate) fn maintain_skill_content_hash_index_for_delete(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    content_hash: SkillContentHash,
) -> Result<()> {
    store
        .vault_meta
        .delete(wtxn, &content_hash_index_key(content_hash, entity))?;
    Ok(())
}

/// Rebuilds the content-hash → holder index at open time when it is missing or
/// stale (schema-version gated), so import/sync dedup can resolve holders that
/// pre-date the index. ONE-1741: scan verdicts no longer ride this table (they
/// anchor to the content bytes), so this reconstructs ONLY the holder index —
/// the old verdict-dedup migration is gone.
pub(crate) fn backfill_content_hash_index_if_needed(vault: &Vault) -> Result<()> {
    let store = &vault.store;
    let rtxn = store.env.read_txn()?;
    let stored_version = match store
        .vault_meta
        .get(&rtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?
    {
        Some(raw) if raw.len() == 1 => raw[0],
        Some(_) => return Err(Error::InvalidKey),
        None => 0,
    };
    drop(rtxn);

    if stored_version > CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Err(Error::InvalidKey);
    }
    if stored_version == CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Ok(());
    }

    // Collect holders first, then write: the type-index cursor is dropped
    // before any vault_meta write, matching the proven pre-ONE-1741 pattern.
    let mut wtxn = store.env.write_txn()?;
    let mut holders = Vec::<(SkillContentHash, EntityId)>::new();
    for entry in store.type_index.prefix_iter(&wtxn, &[ENTITY_TYPE_SKILL])? {
        let (key, _) = entry?;
        let entity = crate::vault::entity_id_from_type_index_key(&key)?;
        let raw = store
            .entities
            .get(&wtxn, entity.as_bytes())?
            .ok_or(Error::CorruptedIndex("skill type index"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill type index"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let record = match decode_skill_record(body) {
            Ok(record) => record,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(content_hash) = record.content_hash {
            holders.push((content_hash, entity));
        }
    }

    for (content_hash, entity) in &holders {
        store.vault_meta.put(
            &mut wtxn,
            &content_hash_index_key(*content_hash, entity),
            &[],
        )?;
    }

    store.vault_meta.put(
        &mut wtxn,
        CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY,
        &[CONTENT_HASH_INDEX_SCHEMA_VERSION],
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Clamps a provider-declared scan time to this node's ingest clock when it
/// runs further ahead than [`SCAN_TIMESTAMP_FUTURE_SKEW_SECS`].
fn clamp_scan_timestamp(scanned_at: u64, learned_at: u64) -> u64 {
    if scanned_at > learned_at.saturating_add(SCAN_TIMESTAMP_FUTURE_SKEW_SECS) {
        learned_at
    } else {
        scanned_at
    }
}

/// The (already clamped) scan time a stored verdict row reports.
///
/// A row missing the field is corruption rather than an implicit zero: the
/// ingest door writes it on every path, and reading damage as "oldest possible"
/// would let a corrupt row lose the newest-wins comparison silently.
fn scan_verdict_row_scanned_at(body: &ClaimBody) -> Result<u64> {
    map_value(&body.value, "scannedAt")
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex("skill scan verdict scannedAt"))
}

/// The risk level a stored verdict row reports.
///
/// Same fail-closed reading as [`scan_verdict_row_scanned_at`]: a damaged row
/// must not read as harmless to the activation dial.
pub(crate) fn scan_verdict_row_risk(body: &ClaimBody) -> Result<ScanRiskLevel> {
    map_text(&body.value, "riskLevel")
        .and_then(ScanRiskLevel::parse)
        .ok_or(Error::CorruptedIndex("skill scan verdict riskLevel"))
}

/// Active scanner receipts for canonical bytes, read off the deterministic
/// content anchor with only the storage handle in hand.
///
/// The one implementation behind
/// [`Vault::skill_scan_verdicts_for_content_hash_in_txn`]. It takes `&Store`
/// rather than `&Vault` because the activation consult's real chokepoint is
/// the batch entity-materialization arm, which never holds a `Vault` — and a
/// gate that reads different rows depending on which door called it is not a
/// gate. Walks the anchor's inbound `claim_of` edges directly, the same rows
/// `Vault::claims_for_subject_in_txn` resolves: a peer that is missing, not a
/// CLAIM, or of another predicate is skipped, exactly as the edge-peer filter
/// skips it.
pub(crate) fn skill_scan_verdicts_for_content_hash_in_store(
    store: &crate::store::Store,
    rtxn: &heed::RoTxn<'_>,
    content_hash: SkillContentHash,
) -> Result<Vec<ClaimBody>> {
    let hash_hex = content_hash.to_hex();
    let anchor = skill_content_anchor_entity_id(content_hash)?;
    let prefix = crate::vault::edge_kind_prefix(&anchor, crate::edge::EdgeKind::ClaimOf);
    let mut rows = Vec::new();
    for (scanned, entry) in store.edges_in.prefix_iter(rtxn, &prefix)?.enumerate() {
        if scanned >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("skill scan verdicts for content hash"));
        }
        let (key, value) = entry?;
        let claim_id = crate::vault::parse_edge_record(&key, &value)?.target;
        let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        // Defense in depth: every row on this anchor is for `content_hash`
        // by construction, but the exact-hash filter keeps discovery precise
        // even against a truncation collision on the derived anchor id.
        if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
            && body.lifecycle == ClaimLifecycleStatus::Active
            && map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
        {
            rows.push(body);
        }
    }
    Ok(rows)
}

fn validate_skill_scan_receipt(receipt: &SkillScanReceipt) -> Result<()> {
    validate_text(
        &receipt.provider,
        MAX_HUB_TEXT_BYTES,
        "scan provider must be non-empty",
    )
}

fn encode_capability_surface_value(surface: &SkillCapabilitySurface) -> Value {
    Value::Map(vec![
        (Value::from("bins"), string_set_value(&surface.bins)),
        (Value::from("env"), string_set_value(&surface.env)),
        (Value::from("mcp"), string_set_value(&surface.mcp)),
        (
            Value::from("allowedTools"),
            string_set_value(&surface.allowed_tools),
        ),
    ])
}

fn decode_capability_surface(bytes: &[u8]) -> Result<SkillCapabilitySurface> {
    const KEYS: [&str; 4] = ["bins", "env", "mcp", "allowedTools"];
    let value = decode_value(bytes, "invalid admitted capability surface")?;
    let entries = exact_map(&value, &KEYS, "invalid admitted capability surface")?;
    let surface = SkillCapabilitySurface {
        bins: decode_string_set(required_value(
            entries,
            KEYS[0],
            "invalid admitted capability surface",
        )?)?,
        env: decode_string_set(required_value(
            entries,
            KEYS[1],
            "invalid admitted capability surface",
        )?)?,
        mcp: decode_string_set(required_value(
            entries,
            KEYS[2],
            "invalid admitted capability surface",
        )?)?,
        allowed_tools: decode_string_set(required_value(
            entries,
            KEYS[3],
            "invalid admitted capability surface",
        )?)?,
    };
    surface.validate()?;
    Ok(surface)
}

fn string_set_value(values: &BTreeSet<String>) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

fn decode_string_set(value: &Value) -> Result<BTreeSet<String>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidSkillBody(
            "capability entries must be an array",
        ));
    };
    let mut decoded = BTreeSet::new();
    for value in values {
        let text = value
            .as_str()
            .ok_or(Error::InvalidSkillBody("capability entry must be text"))?;
        validate_text(
            text,
            MAX_CAPABILITY_TEXT_BYTES,
            "capability entries must be non-empty",
        )?;
        if !decoded.insert(text.to_owned()) {
            return Err(Error::InvalidSkillBody("duplicate capability entry"));
        }
    }
    Ok(decoded)
}

fn exact_map<'a>(
    value: &'a Value,
    keys: &[&str],
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody(context));
    };
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or(Error::InvalidSkillBody(context))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(Error::InvalidSkillBody(context));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody(context));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(entries)
    } else {
        Err(Error::InvalidSkillBody(context))
    }
}

fn required_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(Error::InvalidSkillBody(context))
}

fn required_text(
    entries: &[(Value, Value)],
    key: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<String> {
    let text = required_value(entries, key, context)?
        .as_str()
        .ok_or(Error::InvalidSkillBody(context))?;
    validate_text(text, max_bytes, context)?;
    Ok(text.to_owned())
}

fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(bytes)
}

fn decode_value(bytes: &[u8], context: &'static str) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| Error::InvalidSkillBody(context))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(value)
}

fn map_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn map_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_value(value, key)?.as_str()
}

fn same_hub_alias(left: &HubRef, right: &HubRef) -> bool {
    left.hub_id == right.hub_id && left.ref_string == right.ref_string && left.pin == right.pin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn fixture_hash() -> SkillContentHash {
        canonical_skill_tree_hash([("SKILL.md", b"# fixture\n".as_slice())]).expect("fixture hash")
    }

    fn candidate(skill_id: &str) -> SkillRecord {
        SkillRecord::new(
            skill_id,
            "fixture description",
            "1.0.0",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::Imported,
            1.0,
            false,
            true,
            Vec::new(),
            Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
        )
        .with_content_hash(fixture_hash())
    }

    fn package(record: SkillRecord, capabilities: SkillCapabilitySurface) -> HubPackage {
        HubPackage::new(
            record,
            vec![HubFile::new("SKILL.md", b"# fixture\n".to_vec())],
            capabilities,
        )
    }

    fn package_with_content(
        mut record: SkillRecord,
        content: &[u8],
        capabilities: SkillCapabilitySurface,
    ) -> HubPackage {
        record.content_hash =
            Some(canonical_skill_tree_hash([("SKILL.md", content)]).expect("package content hash"));
        HubPackage::new(
            record,
            vec![HubFile::new("SKILL.md", content.to_vec())],
            capabilities,
        )
    }

    fn hub_ref(pin: HubPin) -> HubRef {
        HubRef::new(EntityId::now(), "skills/example", pin).expect("hub ref")
    }

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let temp = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(temp.path(), crate::VaultConfig::default()).expect("open vault");
        (temp, vault)
    }

    fn materialize_shared_hash_skills(vault: &Vault) -> Result<(EntityId, EntityId)> {
        let local_entity = EntityId::now();
        let mut local = candidate("fixture.local-shared-hash");
        local.source = ClaimSource::UserStated;
        vault.put_skill_record(&local_entity, &local, t(1), 2)?;

        let imported_entity = EntityId::now();
        let imported = package(
            candidate("fixture.imported-shared-hash"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(
            &hub_ref(HubPin::None),
            &imported,
            imported_entity,
            t(3),
            4,
        )?;
        Ok((local_entity, imported_entity))
    }

    /// Active verdict rows for `content_hash`, minus the engine's OWN static
    /// receipt.
    ///
    /// ONE-1892 wired a producer into the import/sync doors, so every hub
    /// import now mints an `oneiron.static.v1` row for the bytes it lands.
    /// These assertions are about the third-party providers the test ingests,
    /// and counting the engine's own row alongside them would measure the
    /// producer instead of the contract under test (the producer has its own
    /// coverage in `skill_scan::tests`).
    fn third_party_verdicts(
        vault: &Vault,
        content_hash: SkillContentHash,
    ) -> Result<Vec<ClaimBody>> {
        Ok(vault
            .skill_scan_verdicts_for_content_hash(content_hash)?
            .into_iter()
            .filter(|body| {
                map_text(&body.value, "provider")
                    != Some(crate::skill_scan::SCAN_PROVIDER_STATIC_V1)
            })
            .collect())
    }

    fn scan_verdict_body(subject: EntityId, provider: &str, scanned_at: u64) -> ClaimBody {
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_SCAN_VERDICT,
            ClaimSubject::Entity(subject),
            Value::Map(vec![
                (
                    Value::from("contentHash"),
                    Value::from(fixture_hash().to_hex()),
                ),
                (Value::from("provider"), Value::from(provider)),
                (Value::from("scannedAt"), Value::from(scanned_at)),
                (Value::from("verdict"), Value::from("clean")),
                (Value::from("riskLevel"), Value::from("low")),
                (Value::from("completeness"), Value::from("complete")),
                (Value::from("governance"), Value::from("recommended")),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        body
    }

    #[test]
    fn hub_package_rejects_file_count_above_limit() {
        let files = (0..=MAX_HUB_PACKAGE_FILES)
            .map(|index| HubFile::new(format!("file-{index}"), Vec::new()))
            .collect();
        let package = HubPackage::new(
            candidate("fixture.file-count-limit"),
            files,
            SkillCapabilitySurface::default(),
        );

        assert_eq!(package.files.len(), MAX_HUB_PACKAGE_FILES + 1);
        assert_eq!(
            package
                .content_hash()
                .expect_err("file count must be capped")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert_eq!(
            package
                .export_files()
                .expect_err("export file count must be capped")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }

    #[test]
    fn hub_package_rejects_total_bytes_above_limit() {
        let bytes_per_file = MAX_HUB_PACKAGE_TOTAL_BYTES / 3 + 1;
        assert!(bytes_per_file < MAX_HUB_FILE_BYTES);
        let files = (0..3)
            .map(|index| HubFile::new(format!("file-{index}"), vec![0; bytes_per_file]))
            .collect();
        let package = HubPackage::new(
            candidate("fixture.total-bytes-limit"),
            files,
            SkillCapabilitySurface::default(),
        );

        assert!(
            package
                .files
                .iter()
                .map(|file| file.content.len())
                .sum::<usize>()
                > MAX_HUB_PACKAGE_TOTAL_BYTES
        );
        assert_eq!(
            package
                .content_hash()
                .expect_err("total bytes must be capped")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert_eq!(
            package
                .export_files()
                .expect_err("export bytes must be capped")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }

    #[test]
    fn hub_package_accepts_normal_small_package() -> Result<()> {
        let package = package(
            candidate("fixture.normal-package"),
            SkillCapabilitySurface::default(),
        );

        assert_eq!(package.content_hash()?, fixture_hash());
        assert_eq!(package.export_files()?, package.files);
        Ok(())
    }

    #[test]
    fn checked_adapter_ingest_refuses_declared_hash_mismatch_before_writes() -> Result<()> {
        let (_temp, vault) = open_vault();
        let hub_id = EntityId::now();
        let target = EntityId::now();
        let package = package(
            candidate("fixture.checked-adapter"),
            SkillCapabilitySurface::default(),
        );
        let alternate_hash =
            canonical_skill_tree_hash([("SKILL.md", b"# alternate adapter bytes\n".as_slice())])?;
        let mut adapter = LocalDirSkillHubAdapter::new(hub_id);
        adapter.insert_package(
            "skills/checked-adapter",
            HubPin::ContentHash(alternate_hash.to_hex()),
            package.clone(),
        );
        let mismatched_entry = HubIndexEntry {
            name: "checked-adapter".to_owned(),
            description: "fixture".to_owned(),
            version: "1.0.0".to_owned(),
            content_hash: alternate_hash,
            ref_string: "skills/checked-adapter".to_owned(),
        };

        vault
            .ingest_skill_from_adapter_checked(&adapter, &mismatched_entry, target, t(1), 2)
            .expect_err("declared hash mismatch must refuse before import");
        assert_eq!(vault.get_skill_record(&target)?, None);
        assert!(vault.claims_for_subject(&target)?.is_empty());

        adapter.insert_package(
            "skills/checked-adapter",
            HubPin::ContentHash(fixture_hash().to_hex()),
            package,
        );
        let matching_entry = HubIndexEntry {
            content_hash: fixture_hash(),
            ..mismatched_entry
        };
        assert_eq!(
            vault.ingest_skill_from_adapter_checked(&adapter, &matching_entry, target, t(3), 4,)?,
            target
        );
        let stored = vault
            .get_skill_record(&target)?
            .expect("matching package materialized");
        assert_eq!(stored.content_hash, Some(fixture_hash()));
        assert_eq!(stored.lifecycle_status, SkillLifecycle::Candidate);
        Ok(())
    }

    #[test]
    fn audit_ingest_preserves_independent_provider_rows_and_lifecycle() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let imported = package(
            candidate("fixture.audit-batch"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &imported, entity, t(1), 2)?;
        let before = vault
            .get_skill_record(&entity)?
            .expect("imported candidate");
        let receipts = [
            SkillScanReceipt::new(
                "alpha",
                3,
                ScanVerdict::Clean,
                ScanRiskLevel::Low,
                ScanCompleteness::Complete,
                SkillGovernance::Recommended,
            )?,
            SkillScanReceipt::new(
                "beta",
                3,
                ScanVerdict::Malicious,
                ScanRiskLevel::Critical,
                ScanCompleteness::Complete,
                SkillGovernance::Prohibited,
            )?,
            SkillScanReceipt::new(
                "gamma",
                3,
                ScanVerdict::Clean,
                ScanRiskLevel::Low,
                ScanCompleteness::Partial,
                SkillGovernance::Recommended,
            )?,
        ];

        assert_eq!(
            vault.ingest_skill_audit_verdicts(&entity, fixture_hash(), &receipts, t(3), 4)?,
            3
        );
        // ONE-1741: audit verdicts anchor to the content bytes, discovered by
        // content hash rather than the submitting holder's subject edges.
        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(rows.len(), 3);
        let providers = rows
            .iter()
            .filter_map(|body| map_text(&body.value, "provider"))
            .collect::<BTreeSet<_>>();
        assert_eq!(providers, BTreeSet::from(["alpha", "beta", "gamma"]));
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("skill remains materialized")
                .lifecycle_status,
            before.lifecycle_status
        );
        Ok(())
    }

    #[test]
    fn audit_ingest_rejects_bad_middle_receipt_atomically() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let imported = package(
            candidate("fixture.audit-atomic"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &imported, entity, t(1), 2)?;
        let first = SkillScanReceipt::new(
            "first",
            3,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        let mut bad = first.clone();
        bad.provider.clear();
        let last = SkillScanReceipt::new(
            "last",
            3,
            ScanVerdict::Suspicious,
            ScanRiskLevel::High,
            ScanCompleteness::Partial,
            SkillGovernance::Discouraged,
        )?;

        let error = vault
            .ingest_skill_audit_verdicts(&entity, fixture_hash(), &[first, bad, last], t(3), 4)
            .expect_err("a malformed middle receipt must reject the whole batch");
        assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
        assert!(
            vault
                .active_claims_for_predicate(&entity, PREDICATE_SKILL_SCAN_VERDICT)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn content_hash_index_returns_every_entity_for_shared_bytes() -> Result<()> {
        let (_temp, vault) = open_vault();
        let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        let indexed = vault
            .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
            .into_iter()
            .map(|(entity, _)| entity)
            .collect::<BTreeSet<_>>();

        assert_eq!(indexed, BTreeSet::from([local_entity, imported_entity]));
        Ok(())
    }

    #[test]
    fn deleting_skill_cleans_index_and_stale_rows_do_not_block_import_dedup() -> Result<()> {
        let (_temp, vault) = open_vault();
        let imported = package(
            candidate("fixture.delete-index"),
            SkillCapabilitySurface::default(),
        );
        let entity = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(1), 2)?;
        let key = content_hash_index_key(fixture_hash(), &entity);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_some());
        drop(rtxn);

        // Deleting the holder drops its content-hash index row, so import dedup
        // stops resolving the departed entity. (Scan verdicts are unaffected:
        // they anchor to the content bytes, not to this holder — see the
        // anchor-invariant tests.)
        assert!(vault.delete_entity(&entity)?);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_none());
        assert!(
            vault
                .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
                .is_empty()
        );
        drop(rtxn);

        // A lagging index row whose entity no longer exists must be skipped by
        // the rebuildable-index reader, never resurrecting a departed holder.
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, &key, &[])?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
                .is_empty()
        );
        drop(rtxn);

        // Re-importing the same bytes mints a fresh entity (the stale row does
        // not block it), and a second import dedups to that entity.
        let reimported = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;
        assert_ne!(reimported, entity);
        assert_eq!(
            vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(5), 6,)?,
            reimported
        );
        Ok(())
    }

    #[test]
    fn soft_erasing_skill_cleans_content_hash_index_before_body_truncation() -> Result<()> {
        let (_temp, vault) = open_vault();
        let imported = package(
            candidate("fixture.soft-delete-index"),
            SkillCapabilitySurface::default(),
        );
        let entity = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(1), 2)?;
        let key = content_hash_index_key(fixture_hash(), &entity);

        vault.delete_entity_with_reason(&entity, crate::DeleteReason::UserDelete)?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_none());
        drop(rtxn);
        assert!(third_party_verdicts(&vault, fixture_hash())?.is_empty());
        Ok(())
    }

    #[test]
    fn open_backfills_pre_index_structured_skills() -> Result<()> {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().to_path_buf();
        let vault = Vault::open(&path, crate::VaultConfig::default())?;
        let entity = EntityId::now();
        let imported = package(
            candidate("fixture.pre-index"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &imported, entity, t(1), 2)?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, &content_hash_index_key(fixture_hash(), &entity))?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?;
        wtxn.commit()?;
        drop(vault);

        let vault = Vault::open(&path, crate::VaultConfig::default())?;
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
                .into_iter()
                .map(|(entity, _)| entity)
                .collect::<Vec<_>>(),
            vec![entity]
        );
        drop(rtxn);
        assert_eq!(
            vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4,)?,
            entity
        );
        let receipt = SkillScanReceipt::new(
            "backfilled",
            5,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(5), 6)?;
        assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
        Ok(())
    }

    #[test]
    fn open_backfill_is_not_capped_by_on_demand_reader_limit() -> Result<()> {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().to_path_buf();
        let vault = Vault::open(&path, crate::VaultConfig::default())?;
        let template_entity = EntityId::now();
        let imported = package(
            candidate("fixture.uncapped-backfill"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(
            &hub_ref(HubPin::None),
            &imported,
            template_entity,
            t(1),
            2,
        )?;

        let mut wtxn = vault.store.env.write_txn()?;
        let template_raw = vault
            .store
            .entities
            .get(&wtxn, template_entity.as_bytes())?
            .expect("template skill")
            .to_vec();
        vault.store.vault_meta.delete(
            &mut wtxn,
            &content_hash_index_key(fixture_hash(), &template_entity),
        )?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?;

        let mut last_entity = template_entity;
        for index in 0..MAX_HUB_SKILL_SCAN_ENTRIES {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&0x0170_0000_0000_0000_u64.to_be_bytes());
            bytes[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            let entity = EntityId::from_bytes(bytes)?;
            vault
                .store
                .entities
                .put(&mut wtxn, entity.as_bytes(), &template_raw)?;
            vault.store.type_index.put(
                &mut wtxn,
                &crate::store::Store::encode_type_key(ENTITY_TYPE_SKILL, &entity),
                &[],
            )?;
            last_entity = entity;
        }
        wtxn.commit()?;
        drop(vault);

        let vault = Vault::open(&path, crate::VaultConfig::default())?;
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .vault_meta
                .get(&rtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?
                .as_deref(),
            Some(&[CONTENT_HASH_INDEX_SCHEMA_VERSION][..])
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &content_hash_index_key(fixture_hash(), &last_entity))?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn reserved_scan_door_preserves_content_global_supersession() -> Result<()> {
        let (_temp, vault) = open_vault();
        let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
        let receipt = SkillScanReceipt::new(
            "reserved-door",
            5,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        let prior =
            vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &receipt, t(5), 6)?;
        vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &receipt, t(7), 8)?;

        assert_eq!(
            vault.get_claim(&prior)?.expect("prior receipt").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
        Ok(())
    }

    #[test]
    fn scan_verdict_supersession_is_content_global_across_entities() -> Result<()> {
        let (_temp, vault) = open_vault();
        let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
        let alpha = SkillScanReceipt::new(
            "alpha",
            5,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        let anchor = skill_content_anchor_entity_id(fixture_hash())?;
        // Same (content_hash, provider) ingested via two different holders
        // dedups to ONE active verdict on the shared content anchor.
        vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &alpha, t(5), 6)?;
        vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &alpha, t(7), 8)?;

        // Verdicts never attach to the submitting holders themselves.
        assert!(
            vault
                .active_claims_for_predicate(&imported_entity, PREDICATE_SKILL_SCAN_VERDICT)?
                .is_empty()
        );
        assert!(
            vault
                .active_claims_for_predicate(&local_entity, PREDICATE_SKILL_SCAN_VERDICT)?
                .is_empty()
        );

        // Exactly one active alpha row plus one superseded, both on the anchor.
        assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
        let mut anchor_superseded = 0;
        for claim_id in vault.claims_for_subject(&anchor)? {
            let Some(body) = vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
                && body.lifecycle == ClaimLifecycleStatus::Superseded
            {
                anchor_superseded += 1;
            }
        }
        assert_eq!(anchor_superseded, 1);
        let hash_rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(hash_rows.len(), 1);
        assert_eq!(map_text(&hash_rows[0].value, "provider"), Some("alpha"));

        let beta = SkillScanReceipt::new(
            "beta",
            9,
            ScanVerdict::Suspicious,
            ScanRiskLevel::High,
            ScanCompleteness::Partial,
            SkillGovernance::Discouraged,
        )?;
        vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &beta, t(9), 10)?;
        let hash_rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(hash_rows.len(), 2);
        let providers = hash_rows
            .iter()
            .filter_map(|body| map_text(&body.value, "provider"))
            .collect::<BTreeSet<_>>();
        assert_eq!(providers, BTreeSet::from(["alpha", "beta"]));
        Ok(())
    }

    #[test]
    fn adapter_package_store_resolves_full_structured_pin() -> Result<()> {
        let hub_id = EntityId::now();
        let first = package(
            candidate("fixture.pin-first"),
            SkillCapabilitySurface::default(),
        );
        let second = package_with_content(
            candidate("fixture.pin-second"),
            b"# second pinned package\n",
            SkillCapabilitySurface::default(),
        );
        let mut adapter = GitSkillHubAdapter::new(hub_id);
        adapter.insert_package(
            "skills/shared-ref",
            HubPin::Tag("first".to_owned()),
            first.clone(),
        );
        adapter.insert_package(
            "skills/shared-ref",
            HubPin::Commit("0123456789abcdef".to_owned()),
            second.clone(),
        );

        let first_ref = HubRef::new(hub_id, "skills/shared-ref", HubPin::Tag("first".to_owned()))?;
        let second_ref = HubRef::new(
            hub_id,
            "skills/shared-ref",
            HubPin::Commit("0123456789abcdef".to_owned()),
        )?;
        assert_eq!(adapter.fetch_package(&first_ref)?, first);
        assert_eq!(adapter.fetch_package(&second_ref)?, second);

        let missing_ref = HubRef::new(
            hub_id,
            "skills/shared-ref",
            HubPin::Semver("^1.0".to_owned()),
        )?;
        adapter
            .fetch_package(&missing_ref)
            .expect_err("an uninserted pin must not resolve another package");
        Ok(())
    }

    #[test]
    fn hub_import_skips_legacy_opaque_skill_during_dedup_scan() -> Result<()> {
        let (_temp, vault) = open_vault();
        let legacy_entity = EntityId::now();
        let structured = encode_skill_record(&candidate("fixture.legacy-opaque"))?;
        vault.put_entity(&legacy_entity, ENTITY_TYPE_SKILL, t(1), 2, &structured)?;

        let legacy_body = b"legacy opaque skill body";
        assert!(crate::skill::is_legacy_opaque_skill_body(legacy_body));
        let rtxn = vault.store.env.read_txn()?;
        let mut raw = vault
            .store
            .entities
            .get(&rtxn, legacy_entity.as_bytes())?
            .expect("legacy fixture entity")
            .to_vec();
        drop(rtxn);
        raw.truncate(ENTITY_METADATA_HEADER_LEN);
        raw.extend_from_slice(legacy_body);
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, legacy_entity.as_bytes(), &raw)?;
        wtxn.commit()?;

        let imported = package(
            candidate("fixture.import-after-legacy"),
            SkillCapabilitySurface::default(),
        );
        let imported_entity =
            vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;

        assert_ne!(imported_entity, legacy_entity);
        assert_eq!(
            vault
                .get_skill_record(&imported_entity)?
                .expect("imported skill")
                .skill_id,
            "fixture.import-after-legacy"
        );
        Ok(())
    }

    #[test]
    fn hub_import_content_hash_pin_must_match_computed_tree_hash() -> Result<()> {
        let (_temp, vault) = open_vault();
        let imported = package(
            candidate("fixture.content-hash-pinned-import"),
            SkillCapabilitySurface::default(),
        );
        let computed_hash = imported.content_hash()?;
        let different_hash =
            canonical_skill_tree_hash([("SKILL.md", b"# different pinned content\n".as_slice())])?;
        assert_ne!(computed_hash, different_hash);

        let mismatched_ref = hub_ref(HubPin::ContentHash(different_hash.to_hex()));
        assert_eq!(
            vault
                .import_skill_from_hub(&mismatched_ref, &imported, t(1), 2)
                .expect_err("content-hash pin must match the computed package tree")
                .kind(),
            ErrorKind::InvalidSkillBody
        );

        let matching_ref = hub_ref(HubPin::ContentHash(computed_hash.to_hex()));
        let imported_entity = vault.import_skill_from_hub(&matching_ref, &imported, t(3), 4)?;
        assert_eq!(
            vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(5), 6)?,
            imported_entity
        );
        Ok(())
    }

    #[test]
    fn hub_import_dedup_ignores_local_skill_with_matching_content_hash() -> Result<()> {
        let (_temp, vault) = open_vault();
        let local_entity = EntityId::now();
        let mut local = candidate("fixture.local-hash-owner");
        local.source = ClaimSource::UserStated;
        vault.put_skill_record(&local_entity, &local, t(1), 2)?;

        let imported = package(
            candidate("fixture.imported-hash-owner"),
            SkillCapabilitySurface::default(),
        );
        assert_eq!(local.content_hash, Some(imported.content_hash()?));
        let imported_entity =
            vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;

        assert_ne!(imported_entity, local_entity);
        assert_eq!(
            vault
                .get_skill_record(&local_entity)?
                .expect("local skill remains materialized")
                .source,
            ClaimSource::UserStated
        );
        assert_eq!(vault.skill_hub_provenance_count(&local_entity)?, 0);
        assert_eq!(
            vault
                .get_skill_record(&imported_entity)?
                .expect("hub import creates a distinct skill")
                .source,
            ClaimSource::Imported
        );
        assert_eq!(vault.skill_hub_provenance_count(&imported_entity)?, 1);
        Ok(())
    }

    #[test]
    fn import_refuses_hash_collision_across_skill_ids() -> Result<()> {
        let (_temp, vault) = open_vault();
        let first_ref = HubRef::new(EntityId::now(), "skills/foo", HubPin::None)?;
        let second_ref = HubRef::new(EntityId::now(), "skills/bar", HubPin::None)?;
        let first = package(candidate("foo"), SkillCapabilitySurface::default());
        let second = package(candidate("bar"), SkillCapabilitySurface::default());

        let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
        let error = vault
            .import_skill_from_hub(&second_ref, &second, t(3), 4)
            .expect_err("matching content must not dedup across skill ids");

        assert!(matches!(
            error,
            Error::InvalidSkillBody("hub import content hash collides with a different skill id")
        ));
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("original imported skill")
                .skill_id,
            "foo"
        );
        Ok(())
    }

    #[test]
    fn import_dedups_matching_skill_id_across_hubs() -> Result<()> {
        let (_temp, vault) = open_vault();
        let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
        let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
        let imported = package(candidate("foo"), SkillCapabilitySurface::default());

        let entity = vault.import_skill_from_hub(&first_ref, &imported, t(1), 2)?;
        assert_eq!(
            vault.import_skill_from_hub(&second_ref, &imported, t(3), 4)?,
            entity
        );
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);
        Ok(())
    }

    #[test]
    fn import_refuses_conflicting_capabilities_on_dedup() -> Result<()> {
        let (_temp, vault) = open_vault();
        let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
        let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
        let first = package(
            candidate("foo"),
            SkillCapabilitySurface::default().with_bin("foo"),
        );
        let second = package(
            candidate("foo"),
            SkillCapabilitySurface::default().with_bin("bar"),
        );

        let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
        let error = vault
            .import_skill_from_hub(&second_ref, &second, t(3), 4)
            .expect_err("matching content must not dedup conflicting capabilities");

        assert!(matches!(
            error,
            Error::InvalidSkillBody("matching content hash carries conflicting capabilities")
        ));
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
        Ok(())
    }

    #[test]
    fn import_dedups_equal_capabilities() -> Result<()> {
        let (_temp, vault) = open_vault();
        let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
        let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
        let first = package(
            candidate("foo"),
            SkillCapabilitySurface::default().with_bin("foo"),
        );
        let second = package(
            candidate("foo"),
            SkillCapabilitySurface::default().with_bin("foo"),
        );

        let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
        assert_eq!(
            vault.import_skill_from_hub(&second_ref, &second, t(3), 4)?,
            entity
        );
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);
        Ok(())
    }

    #[test]
    fn hub_reimport_moves_provenance_alias_to_new_content_entity() -> Result<()> {
        let (_temp, vault) = open_vault();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.mutable-hub-alias"),
            SkillCapabilitySurface::default(),
        );
        let first_entity =
            vault.import_skill_from_hub_with_id(&reference, &initial, EntityId::now(), t(1), 2)?;

        let moved = package_with_content(
            candidate("fixture.mutable-hub-alias"),
            b"# moved upstream ref\n",
            SkillCapabilitySurface::default(),
        );
        let moved_hash = moved.content_hash()?;
        let second_entity =
            vault.import_skill_from_hub_with_id(&reference, &moved, EntityId::now(), t(3), 4)?;
        assert_ne!(first_entity, second_entity);

        let mut first_alias_superseded = 0;
        for claim_id in vault.claims_for_subject(&first_entity)? {
            let Some(body) = vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_SKILL_HUB_PROVENANCE {
                continue;
            }
            let stored_ref =
                HubRef::from_value(map_value(&body.value, "hubRef").expect("provenance hub ref"))?;
            if same_hub_alias(&stored_ref, &reference)
                && body.lifecycle == ClaimLifecycleStatus::Superseded
            {
                first_alias_superseded += 1;
            }
        }
        assert_eq!(first_alias_superseded, 1);

        let first_active =
            vault.active_claims_for_predicate(&first_entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        let second_active =
            vault.active_claims_for_predicate(&second_entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        assert_eq!(first_active.len(), 0);
        assert_eq!(second_active.len(), 1);
        assert_eq!(first_active.len() + second_active.len(), 1);
        assert_eq!(
            map_text(&second_active[0].1.value, "contentHash"),
            Some(moved_hash.to_hex().as_str())
        );
        assert_eq!(
            HubRef::from_value(
                map_value(&second_active[0].1.value, "hubRef").expect("provenance hub ref")
            )?,
            reference
        );
        Ok(())
    }

    #[test]
    fn hub_ref_round_trips_all_five_pin_types() {
        let pins = [
            HubPin::Semver("^1.0".to_owned()),
            HubPin::Tag("stable".to_owned()),
            HubPin::Commit("0123456789abcdef".to_owned()),
            HubPin::ContentHash(fixture_hash().to_hex()),
            HubPin::None,
        ];
        let mut round_tripped = Vec::new();
        for pin in pins {
            let original = hub_ref(pin);
            let encoded = original.to_value().expect("encode hub ref");
            round_tripped.push(HubRef::from_value(&encoded).expect("decode hub ref"));
            assert_eq!(round_tripped.last(), Some(&original));
        }
        assert_eq!(round_tripped.len(), 5);

        let invalid = HubRef {
            hub_id: EntityId::now(),
            ref_string: String::new(),
            pin: HubPin::None,
        };
        assert!(invalid.to_value().is_err());
    }

    #[test]
    fn skill_hub_record_round_trips_exact_body() {
        let record = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "configured-endpoint",
            SkillHubTrustTier::Community,
            HubSyncPolicy::MirrorOfHub,
        )
        .expect("hub record");
        let bytes = encode_skill_hub_record(&record).expect("encode");
        assert_eq!(decode_skill_hub_record(&bytes).expect("decode"), record);
    }

    #[test]
    fn hub_sync_applies_narrowing_and_proposes_widening() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let initial_surface = SkillCapabilitySurface::default().with_bin("existing-bin");
        let initial = package(candidate("fixture.sync"), initial_surface);
        let reference = hub_ref(HubPin::None);
        assert_eq!(
            vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?,
            entity
        );
        let mut invalid_record = candidate("fixture.sync");
        invalid_record.version.clear();
        let invalid = package(invalid_record, SkillCapabilitySurface::default());
        vault
            .import_skill_from_hub(&hub_ref(HubPin::None), &invalid, t(2), 3)
            .expect_err("invalid dedup package must be rejected");
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
        let mut active = vault.get_skill_record(&entity)?.expect("candidate");
        active.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&entity, &active, t(3), 4)?;

        let mut narrower_record = candidate("fixture.sync");
        narrower_record.version = "1.1.0".to_owned();
        narrower_record.confidence = 0.75;
        let narrower = package(narrower_record, SkillCapabilitySurface::default());
        let narrowed = vault.sync_skill_from_hub(
            &entity,
            &reference,
            &narrower,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?;
        assert_eq!(narrowed, HubSyncDisposition::Applied);
        let narrowed_record = vault.get_skill_record(&entity)?.expect("narrowed record");
        assert_eq!(narrowed_record.confidence, 0.75);

        let mut frozen_record = candidate("fixture.sync");
        frozen_record.version = "1.1.1".to_owned();
        let frozen = package(frozen_record, SkillCapabilitySurface::default());
        let frozen_ref = hub_ref(HubPin::ContentHash(fixture_hash().to_hex()));
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &frozen_ref,
                &frozen,
                HubSyncPolicy::ContentHashFrozen,
                t(7),
                8,
            )?,
            HubSyncDisposition::RefusedByPolicy
        );
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("still narrowed")
                .version,
            "1.1.0"
        );

        let mut wider_record = candidate("fixture.sync");
        wider_record.version = "1.2.0".to_owned();
        let wider = package(
            wider_record,
            SkillCapabilitySurface::default().with_bin("new-bin"),
        );
        let widened = vault.sync_skill_from_hub(
            &entity,
            &reference,
            &wider,
            HubSyncPolicy::MirrorOfHub,
            t(9),
            10,
        )?;
        assert_eq!(
            widened.approval_status(),
            Some(ClaimApprovalStatus::Proposed)
        );
        assert_eq!(
            vault.get_skill_record(&entity)?.expect("stored").version,
            "1.1.0"
        );
        Ok(())
    }

    #[test]
    fn sync_enforces_content_hash_pin_under_any_policy() -> Result<()> {
        let (_temp, vault) = open_vault();
        let initial = package(
            candidate("fixture.content-hash-pin-sync"),
            SkillCapabilitySurface::default(),
        );
        let initial_hash = initial.content_hash()?;
        let reference = hub_ref(HubPin::ContentHash(initial_hash.to_hex()));
        let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

        let mut update_record = candidate("fixture.content-hash-pin-sync");
        update_record.version = "1.1.0".to_owned();
        let update = package_with_content(
            update_record,
            b"# drifted content-hash-pinned tree\n",
            SkillCapabilitySurface::default(),
        );
        let updated_hash = update.content_hash()?;
        assert_ne!(updated_hash, initial_hash);

        let error = vault
            .sync_skill_from_hub(
                &entity,
                &reference,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(3),
                4,
            )
            .expect_err("content-hash pin must bind every sync policy");
        assert!(matches!(
            error,
            Error::InvalidSkillBody("content-hash-pinned ref drifted")
        ));
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("original pinned skill")
                .content_hash,
            Some(initial_hash)
        );

        let provenance =
            vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        assert_eq!(provenance.len(), 1);
        assert_eq!(
            map_text(&provenance[0].1.value, "contentHash"),
            Some(initial_hash.to_hex().as_str())
        );
        assert_eq!(
            HubRef::from_value(
                map_value(&provenance[0].1.value, "hubRef").expect("pinned provenance hub ref")
            )?,
            reference
        );
        Ok(())
    }

    #[test]
    fn sync_none_pin_still_moves_hash() -> Result<()> {
        let (_temp, vault) = open_vault();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.none-pin-sync"),
            SkillCapabilitySurface::default(),
        );
        let initial_hash = initial.content_hash()?;
        let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

        let mut update_record = candidate("fixture.none-pin-sync");
        update_record.version = "1.1.0".to_owned();
        let update = package_with_content(
            update_record,
            b"# movable none-pin tree\n",
            SkillCapabilitySurface::default(),
        );
        let updated_hash = update.content_hash()?;
        assert_ne!(updated_hash, initial_hash);
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &reference,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(3),
                4,
            )?,
            HubSyncDisposition::Applied
        );
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("updated none-pin skill")
                .content_hash,
            Some(updated_hash)
        );
        Ok(())
    }

    #[test]
    fn content_hash_frozen_requires_pin() -> Result<()> {
        let (_temp, vault) = open_vault();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.frozen-policy-pin-required"),
            SkillCapabilitySurface::default(),
        );
        let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

        let mut update_record = candidate("fixture.frozen-policy-pin-required");
        update_record.version = "1.1.0".to_owned();
        let update = package(update_record, SkillCapabilitySurface::default());
        let error = vault
            .sync_skill_from_hub(
                &entity,
                &reference,
                &update,
                HubSyncPolicy::ContentHashFrozen,
                t(3),
                4,
            )
            .expect_err("content-hash-frozen policy requires a content_hash pin");
        assert!(matches!(
            error,
            Error::InvalidSkillBody("content-hash-frozen policy requires a content_hash pin")
        ));
        Ok(())
    }

    #[test]
    fn hub_sync_requires_existing_provenance_alias_but_allows_untracked_skills() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.sync-authority"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

        let mut update_record = candidate("fixture.sync-authority");
        update_record.version = "1.1.0".to_owned();
        let update = package(update_record, SkillCapabilitySurface::default());
        let unrelated_ref =
            HubRef::new(EntityId::now(), reference.ref_string.clone(), HubPin::None)?;
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &unrelated_ref,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(3),
                4,
            )?,
            HubSyncDisposition::RefusedByPolicy
        );
        assert_eq!(
            vault
                .get_skill_record(&entity)?
                .expect("original skill")
                .version,
            "1.0.0"
        );
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &reference,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(5),
                6,
            )?,
            HubSyncDisposition::Applied
        );

        let direct_entity = EntityId::now();
        let direct = package_with_content(
            candidate("fixture.sync-without-provenance"),
            b"# direct import\n",
            SkillCapabilitySurface::default(),
        );
        vault.put_skill_record(&direct_entity, &direct.record, t(7), 8)?;
        assert_eq!(vault.skill_hub_provenance_count(&direct_entity)?, 0);
        let mut direct_update_record = direct.record;
        direct_update_record.version = "1.1.0".to_owned();
        let direct_update = package_with_content(
            direct_update_record,
            b"# direct import\n",
            SkillCapabilitySurface::default(),
        );
        assert_eq!(
            vault.sync_skill_from_hub(
                &direct_entity,
                &hub_ref(HubPin::None),
                &direct_update,
                HubSyncPolicy::MirrorOfHub,
                t(9),
                10,
            )?,
            HubSyncDisposition::Applied
        );
        assert_eq!(
            vault
                .get_skill_record(&direct_entity)?
                .expect("direct imported skill")
                .version,
            "1.1.0"
        );
        Ok(())
    }

    #[test]
    fn hub_sync_requires_exact_provenance_pin() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let hub_id = EntityId::now();
        let stable_ref = HubRef::new(
            hub_id,
            "skills/pinned-authority",
            HubPin::Tag("stable".to_owned()),
        )?;
        let beta_ref = HubRef::new(
            hub_id,
            "skills/pinned-authority",
            HubPin::Tag("beta".to_owned()),
        )?;
        let initial = package(
            candidate("fixture.pinned-sync-authority"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&stable_ref, &initial, entity, t(1), 2)?;

        let mut update_record = candidate("fixture.pinned-sync-authority");
        update_record.version = "1.1.0".to_owned();
        let update = package(update_record, SkillCapabilitySurface::default());
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &beta_ref,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(3),
                4,
            )?,
            HubSyncDisposition::RefusedByPolicy
        );
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &stable_ref,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(5),
                6,
            )?,
            HubSyncDisposition::Applied
        );
        Ok(())
    }

    #[test]
    fn hub_sync_refuses_content_hash_owned_by_different_entity() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.hash-collision-source"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

        let owner = EntityId::now();
        let owner_package = package_with_content(
            candidate("fixture.hash-collision-owner"),
            b"# already owned\n",
            SkillCapabilitySurface::default(),
        );
        let owner_hash = owner_package.content_hash()?;
        vault.import_skill_from_hub_with_id(
            &hub_ref(HubPin::None),
            &owner_package,
            owner,
            t(3),
            4,
        )?;

        let mut colliding_record = candidate("fixture.hash-collision-source");
        colliding_record.version = "2.0.0".to_owned();
        let colliding = package_with_content(
            colliding_record,
            b"# already owned\n",
            SkillCapabilitySurface::default(),
        );
        assert_eq!(colliding.content_hash()?, owner_hash);
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &reference,
                &colliding,
                HubSyncPolicy::MirrorOfHub,
                t(5),
                6,
            )?,
            HubSyncDisposition::RefusedByPolicy
        );

        let unchanged = vault.get_skill_record(&entity)?.expect("source skill");
        let existing_owner = vault.get_skill_record(&owner)?.expect("hash owner");
        assert_ne!(entity, owner);
        assert_eq!(unchanged.content_hash, Some(fixture_hash()));
        assert_eq!(unchanged.version, "1.0.0");
        assert_eq!(existing_owner.content_hash, Some(owner_hash));
        Ok(())
    }

    #[test]
    fn hub_sync_refreshes_provenance_after_content_hash_change() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.provenance-refresh"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

        let mut update_record = candidate("fixture.provenance-refresh");
        update_record.version = "1.1.0".to_owned();
        let update = package_with_content(
            update_record,
            b"# changed upstream tree\n",
            SkillCapabilitySurface::default(),
        );
        let updated_hash = update.content_hash()?;
        assert_ne!(updated_hash, fixture_hash());
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &reference,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(3),
                4,
            )?,
            HubSyncDisposition::Applied
        );

        let rows = vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            map_text(&rows[0].1.value, "contentHash"),
            Some(updated_hash.to_hex().as_str())
        );
        assert_eq!(
            HubRef::from_value(map_value(&rows[0].1.value, "hubRef").expect("provenance hub ref"))?,
            reference
        );
        Ok(())
    }

    #[test]
    fn hub_sync_content_change_supersedes_other_hub_provenance_aliases() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let syncing_ref = hub_ref(HubPin::None);
        let other_ref = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.multi-hub-provenance-refresh"),
            SkillCapabilitySurface::default(),
        );
        assert_eq!(
            vault.import_skill_from_hub_with_id(&syncing_ref, &initial, entity, t(1), 2)?,
            entity
        );
        assert_eq!(
            vault.import_skill_from_hub_with_id(&other_ref, &initial, EntityId::now(), t(3), 4,)?,
            entity
        );
        assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);

        let mut update_record = candidate("fixture.multi-hub-provenance-refresh");
        update_record.version = "1.1.0".to_owned();
        let update = package_with_content(
            update_record,
            b"# changed through the syncing hub\n",
            SkillCapabilitySurface::default(),
        );
        let updated_hash = update.content_hash()?;
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &syncing_ref,
                &update,
                HubSyncPolicy::MirrorOfHub,
                t(5),
                6,
            )?,
            HubSyncDisposition::Applied
        );

        let active = vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        assert_eq!(active.len(), 1);
        assert_eq!(
            map_text(&active[0].1.value, "contentHash"),
            Some(updated_hash.to_hex().as_str())
        );
        assert_eq!(
            HubRef::from_value(
                map_value(&active[0].1.value, "hubRef").expect("active provenance hub ref")
            )?,
            syncing_ref
        );

        let mut other_alias_superseded = 0;
        for claim_id in vault.claims_for_subject(&entity)? {
            let Some(body) = vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_SKILL_HUB_PROVENANCE {
                continue;
            }
            let stored_ref =
                HubRef::from_value(map_value(&body.value, "hubRef").expect("provenance hub ref"))?;
            if same_hub_alias(&stored_ref, &other_ref)
                && body.lifecycle == ClaimLifecycleStatus::Superseded
            {
                other_alias_superseded += 1;
            }
        }
        assert_eq!(other_alias_superseded, 1);
        Ok(())
    }

    #[test]
    fn hub_sync_deduplicates_identical_widening_proposals() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.proposal-dedup"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

        let mut wider_record = candidate("fixture.proposal-dedup");
        wider_record.version = "2.0.0".to_owned();
        let wider = package(
            wider_record,
            SkillCapabilitySurface::default().with_bin("new-bin"),
        );
        let first = vault.sync_skill_from_hub(
            &entity,
            &reference,
            &wider,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )?;
        let first_id = match first {
            HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
            other => panic!("expected proposal, got {other:?}"),
        };
        assert_eq!(
            vault.sync_skill_from_hub(
                &entity,
                &reference,
                &wider,
                HubSyncPolicy::MirrorOfHub,
                t(5),
                6,
            )?,
            HubSyncDisposition::Proposed {
                proposal_id: first_id,
                approval: ClaimApprovalStatus::Proposed,
            }
        );

        let proposals =
            vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL)?;
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].0, first_id);
        Ok(())
    }

    #[test]
    fn sync_widening_proposal_refreshes_on_changed_capabilities() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let initial = package(
            candidate("fixture.proposal-capability-refresh"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

        let wider_record = candidate("fixture.proposal-capability-refresh");
        let first_wider = package(
            wider_record.clone(),
            SkillCapabilitySurface::default().with_bin("bin-a"),
        );
        let second_wider = package(
            wider_record,
            SkillCapabilitySurface::default()
                .with_bin("bin-a")
                .with_bin("bin-b"),
        );
        let first_id = match vault.sync_skill_from_hub(
            &entity,
            &reference,
            &first_wider,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )? {
            HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
            other => panic!("expected proposal, got {other:?}"),
        };
        let second_id = match vault.sync_skill_from_hub(
            &entity,
            &reference,
            &second_wider,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )? {
            HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
            other => panic!("expected refreshed proposal, got {other:?}"),
        };

        assert_ne!(second_id, first_id);
        assert_eq!(
            vault
                .active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL)?
                .len(),
            2
        );
        Ok(())
    }

    #[test]
    fn scan_verdict_supersedes_same_hash_and_provider() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        let reference = hub_ref(HubPin::None);
        let imported = package(candidate("fixture.scan"), SkillCapabilitySurface::default());
        vault.import_skill_from_hub_with_id(&reference, &imported, entity, t(1), 2)?;
        let receipt = SkillScanReceipt::new(
            "provider-a",
            3,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        let anchor = skill_content_anchor_entity_id(fixture_hash())?;
        vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(3), 4)?;
        vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(2), 2)?;
        // Same (content_hash, provider) supersedes on the anchor: one active row.
        // Equal `scannedAt` is the TIE case newest-wins leaves to the later
        // call (ONE-1892) — both ingests carry `scanned_at = 3`.
        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(rows.len(), 1);
        let mut superseded = 0;
        for id in vault.claims_for_subject(&anchor)? {
            let Some(body) = vault.get_claim(&id)? else {
                continue;
            };
            if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
                && body.lifecycle == ClaimLifecycleStatus::Superseded
            {
                superseded += 1;
            }
        }
        assert_eq!(superseded, 1);
        Ok(())
    }

    // ═══ ONE-1892 — newest-wins ingest + anchor type guard ══════════════════

    fn scan_receipt_at(provider: &str, scanned_at: u64) -> Result<SkillScanReceipt> {
        SkillScanReceipt::new(
            provider,
            scanned_at,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )
    }

    #[test]
    fn older_scan_ingested_after_a_newer_one_never_takes_the_active_slot() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        vault.put_skill_record(&entity, &candidate("fixture.newest-wins"), t(1), 2)?;

        let newer = vault.ingest_skill_scan_verdict(
            &entity,
            fixture_hash(),
            &scan_receipt_at("provider-a", 500)?,
            t(500),
            501,
        )?;
        let older = vault.ingest_skill_scan_verdict(
            &entity,
            fixture_hash(),
            &scan_receipt_at("provider-a", 100)?,
            t(600),
            601,
        )?;

        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(rows.len(), 1, "one active row per (hash, provider)");
        assert_eq!(
            map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
            Some(500),
            "the LATEST-SCANNED verdict holds the active slot, not the last ingested"
        );
        assert_eq!(
            vault.get_claim(&newer)?.expect("newer row").lifecycle,
            ClaimLifecycleStatus::Active
        );
        assert_eq!(
            vault.get_claim(&older)?.expect("older row").lifecycle,
            ClaimLifecycleStatus::Superseded,
            "the late-arriving older scan is kept as history, never dropped"
        );
        Ok(())
    }

    #[test]
    fn a_far_future_scan_cannot_pin_the_active_slot() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        vault.put_skill_record(&entity, &candidate("fixture.future-clamp"), t(1), 2)?;

        vault.ingest_skill_scan_verdict(
            &entity,
            fixture_hash(),
            &scan_receipt_at("provider-a", u64::MAX)?,
            t(500),
            501,
        )?;
        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(
            map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
            Some(501),
            "a scan time beyond now+skew is clamped to ingest time"
        );
        assert_eq!(
            map_value(&rows[0].value, "scannedAtDeclared").and_then(Value::as_u64),
            Some(u64::MAX),
            "the clamp is receipted on the row, not silent"
        );

        // A later, ordinary scan now wins on merit instead of losing to a
        // timestamp no clock will ever reach.
        let normal = vault.ingest_skill_scan_verdict(
            &entity,
            fixture_hash(),
            &scan_receipt_at("provider-a", 600)?,
            t(600),
            601,
        )?;
        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
            Some(600)
        );
        assert_eq!(
            vault.get_claim(&normal)?.expect("normal row").lifecycle,
            ClaimLifecycleStatus::Active
        );
        Ok(())
    }

    #[test]
    fn a_non_anchor_entity_squatting_the_anchor_id_is_refused() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        vault.put_skill_record(&entity, &candidate("fixture.anchor-squat"), t(1), 2)?;

        // Pre-seed a foreign entity at the derived anchor id.
        let anchor_id = skill_content_anchor_entity_id(fixture_hash())?;
        vault.put_entity(
            &anchor_id,
            crate::registry::ENTITY_TYPE_PERSON,
            t(1),
            2,
            b"squatter",
        )?;

        let error = vault
            .ingest_skill_scan_verdict(
                &entity,
                fixture_hash(),
                &scan_receipt_at("provider-a", 5)?,
                t(5),
                6,
            )
            .expect_err("a squatted anchor id must not be silently adopted");
        assert!(
            matches!(
                error,
                Error::SkillContentAnchorTypeMismatch {
                    existing: crate::registry::ENTITY_TYPE_PERSON
                }
            ),
            "expected a typed anchor mismatch, got {error:?}"
        );
        assert!(
            vault
                .skill_scan_verdicts_for_content_hash(fixture_hash())?
                .is_empty(),
            "the refused ingest wrote nothing"
        );
        Ok(())
    }

    // ═══ ONE-1741 — content-anchor invariants ═══════════════════════════════

    #[test]
    fn content_anchor_id_is_deterministic_and_non_reserved() -> Result<()> {
        let same_a = skill_content_anchor_entity_id(fixture_hash())?;
        let same_b = skill_content_anchor_entity_id(fixture_hash())?;
        assert_eq!(same_a, same_b, "same content hash derives the same anchor");

        let other_hash =
            canonical_skill_tree_hash([("SKILL.md", b"# different bytes\n".as_slice())])?;
        assert_ne!(
            skill_content_anchor_entity_id(other_hash)?,
            same_a,
            "distinct content hashes derive distinct anchors"
        );
        // The derived id round-trips the reserved-sentinel gate.
        assert_eq!(EntityId::from_bytes(*same_a.as_bytes())?, same_a);
        Ok(())
    }

    #[test]
    fn ingest_creates_content_anchor_entity_carrying_the_hash() -> Result<()> {
        let (_temp, vault) = open_vault();
        let entity = EntityId::now();
        // Born through the local put door, NOT the hub import door: the import
        // door now ingests its own scan (ONE-1892), which would mint the anchor
        // before this test could observe it missing. The contract under test is
        // that INGEST mints it, so the fixture reaches ingest with no anchor.
        vault.put_skill_record(&entity, &candidate("fixture.anchor-create"), t(1), 2)?;
        let anchor = skill_content_anchor_entity_id(fixture_hash())?;
        assert_eq!(
            vault.get(&anchor)?,
            None,
            "anchor is minted lazily at ingest"
        );

        let receipt = SkillScanReceipt::new(
            "anchor-provider",
            3,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?;
        vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(3), 4)?;

        let raw = vault
            .get(&anchor)?
            .expect("ingest minted the anchor entity");
        assert_eq!(
            raw.as_slice(),
            fixture_hash().as_bytes(),
            "anchor body carries the 32-byte content hash"
        );
        let header = vault
            .read_entity_header(&anchor)?
            .expect("anchor header present");
        assert_eq!(header.entity_type, ENTITY_TYPE_SKILL_CONTENT_ANCHOR);
        Ok(())
    }

    #[test]
    fn verdict_anchored_to_content_hash_survives_every_holder_departure() -> Result<()> {
        let (_temp, vault) = open_vault();
        let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
        let receipt = SkillScanReceipt::new(
            "immortal",
            5,
            ScanVerdict::Malicious,
            ScanRiskLevel::Critical,
            ScanCompleteness::Complete,
            SkillGovernance::Prohibited,
        )?;
        // Ingested via one holder while two hold the shared bytes.
        vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &receipt, t(5), 6)?;
        let discoverable = |vault: &Vault| -> Result<usize> {
            Ok(third_party_verdicts(vault, fixture_hash())?.len())
        };
        assert_eq!(discoverable(&vault)?, 1);

        // Hard-delete one holder → still discoverable on the anchor.
        assert!(vault.delete_entity(&imported_entity)?);
        assert_eq!(discoverable(&vault)?, 1);

        // Soft-erase the last remaining holder → still discoverable.
        vault.delete_entity_with_reason(&local_entity, crate::DeleteReason::UserDelete)?;
        assert_eq!(
            discoverable(&vault)?,
            1,
            "verdict is anchored to the immortal bytes, not any holder"
        );

        // Re-import the same bytes and hard-delete via a batch → survives.
        let reholder = EntityId::now();
        let reimported = package(
            candidate("fixture.local-shared-hash"),
            SkillCapabilitySurface::default(),
        );
        vault.import_skill_from_hub_with_id(
            &hub_ref(HubPin::None),
            &reimported,
            reholder,
            t(9),
            10,
        )?;
        vault.batch().delete(&reholder).commit()?;
        assert_eq!(
            discoverable(&vault)?,
            1,
            "verdict outlives batch deletion of a fresh holder too"
        );

        // The surviving row still carries its original provider and hash.
        let rows = third_party_verdicts(&vault, fixture_hash())?;
        assert_eq!(map_text(&rows[0].value, "provider"), Some("immortal"));
        assert_eq!(
            map_text(&rows[0].value, "contentHash"),
            Some(fixture_hash().to_hex().as_str())
        );
        Ok(())
    }

    // AUD-1741: the anchor's immortality must be ENFORCED, not just assumed —
    // deleting the anchor would strand every verdict for its bytes. It must be
    // refused on every delete door (targeted AND batch/bulk share one guard).
    #[test]
    fn content_anchor_is_delete_protected_on_every_door() -> Result<()> {
        let (_temp, vault) = open_vault();
        let (_local, imported) = materialize_shared_hash_skills(&vault)?;
        let receipt = SkillScanReceipt::new(
            "anchor-protect",
            5,
            ScanVerdict::Malicious,
            ScanRiskLevel::Critical,
            ScanCompleteness::Complete,
            SkillGovernance::Prohibited,
        )?;
        vault.ingest_skill_scan_verdict(&imported, fixture_hash(), &receipt, t(5), 6)?;
        let anchor_id = skill_content_anchor_entity_id(fixture_hash())?;
        assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);

        // Targeted delete door refuses the anchor; the verdict survives.
        assert!(
            matches!(
                vault.delete_entity(&anchor_id),
                Err(Error::MaintenanceKindNotWritable(_))
            ),
            "targeted delete of the content anchor must be refused"
        );
        assert_eq!(
            third_party_verdicts(&vault, fixture_hash())?.len(),
            1,
            "verdict survives a targeted anchor-delete attempt"
        );

        // Batch/bulk delete door refuses it too (same guard, single source).
        assert!(
            matches!(
                vault.batch().delete(&anchor_id).commit(),
                Err(Error::MaintenanceKindNotWritable(_))
            ),
            "batch delete of the content anchor must be refused"
        );
        assert_eq!(
            third_party_verdicts(&vault, fixture_hash())?.len(),
            1,
            "verdict survives a batch anchor-delete attempt"
        );
        Ok(())
    }

    #[test]
    fn anchor_subjected_verdict_stays_unforgeable_via_public_door() -> Result<()> {
        let (_temp, vault) = open_vault();
        // A well-formed anchor subject cannot smuggle a reserved skill.* claim
        // through the public door — the forgery guard is predicate-keyed and
        // independent of the (now anchor) subject.
        let anchor = skill_content_anchor_entity_id(fixture_hash())?;
        let body = scan_verdict_body(anchor, "forged", 1);
        assert!(matches!(
            vault.put_claim(&EntityId::now(), &body, t(1), 2),
            Err(Error::ReservedPredicate { .. })
        ));
        Ok(())
    }
}
