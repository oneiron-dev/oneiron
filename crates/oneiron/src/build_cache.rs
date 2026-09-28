//! Explicit account-scoped immutable build results. Bytes stay in BLOB_ARTIFACT; this
//! index stores exact version refs and admits only artifact-level `Clean`.
//! No eviction or repair exists: tainted and dangling rows remain tombstones.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::{CodebaseForkHash, RepoRef};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::secret_rotation::ArtifactTaintState;
use crate::side_table::{self, Raw, RawValue, SideTable};

pub const BUILD_CACHE_SCHEMA_VERSION_V1: u8 = 2;
pub const BUILD_CACHE_ACTION_SCHEMA_VERSION_V1: u8 = 1;
pub const BUILD_CACHE_ACTION_DOMAIN_V1: &[u8] = b"oneiron:build-cache:action:v1";
pub const BUILD_CACHE_KEY_PREFIX_V1: &[u8] = b"build_cache:reapi:v2:";
pub const BUILD_CACHE_ACTION_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKey([u8; BUILD_CACHE_ACTION_KEY_LEN]);

impl ActionKey {
    pub fn derive(action: &BuildAction) -> BuildCacheResult<Self> {
        Ok(Self(action.reapi_digest()?.hash))
    }

    pub const fn as_bytes(&self) -> &[u8; BUILD_CACHE_ACTION_KEY_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }
}

/// Validated command inputs. Private fields prevent mutation after freezing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenBuildCommand {
    argv: Vec<String>,
    env_allowlist: BTreeMap<String, String>,
}

impl FrozenBuildCommand {
    pub fn new<I, K, V>(argv: Vec<String>, env_allowlist: I) -> BuildCacheResult<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        if argv.is_empty() {
            return Err(BuildCacheError::InvalidAction("empty argv"));
        }
        Ok(Self {
            argv,
            env_allowlist: canonical_map(env_allowlist, "duplicate env key")?,
        })
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn env_allowlist(&self) -> &BTreeMap<String, String> {
        &self.env_allowlist
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtraInputDigest([u8; 32]);

impl ExtraInputDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Existing repo/snapshot identity plus explicitly ordered extra inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInputRoot {
    pub repo_ref: RepoRef,
    pub fork_hash: CodebaseForkHash,
    pub extra_inputs: Vec<ExtraInputDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlatform {
    properties: BTreeMap<String, String>,
}

impl BuildPlatform {
    pub fn new<I, K, V>(properties: I) -> BuildCacheResult<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Ok(Self {
            properties: canonical_map(properties, "duplicate platform key")?,
        })
    }

    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.properties
    }
}

fn canonical_map<I, K, V>(
    pairs: I,
    duplicate: &'static str,
) -> BuildCacheResult<BTreeMap<String, String>>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let mut map = BTreeMap::new();
    for (key, value) in pairs {
        if map.insert(key.into(), value.into()).is_some() {
            return Err(BuildCacheError::InvalidAction(duplicate));
        }
    }
    Ok(map)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclaredOutputPath(String);

impl DeclaredOutputPath {
    /// Validates `/`-separated strings without normalization or `std::path`.
    pub fn parse(value: impl Into<String>) -> BuildCacheResult<Self> {
        let value = value.into();
        if value.contains(['\0', '\\'])
            || value.split('/').next().is_some_and(|s| s.contains(':'))
            || value.split('/').any(|s| matches!(s, "" | "." | ".."))
        {
            return Err(BuildCacheError::InvalidOutputPath(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildAction {
    pub command: FrozenBuildCommand,
    pub input_root: BuildInputRoot,
    pub platform: BuildPlatform,
    declared_outputs: Vec<DeclaredOutputPath>,
    reapi_input_root: Option<ReapiDigest>,
}

impl BuildAction {
    pub fn new(
        command: FrozenBuildCommand,
        input_root: BuildInputRoot,
        platform: BuildPlatform,
        mut declared_outputs: Vec<DeclaredOutputPath>,
    ) -> BuildCacheResult<Self> {
        validate_repo_ref(&input_root.repo_ref)?;
        declared_outputs.sort();
        if declared_outputs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BuildCacheError::InvalidAction("duplicate declared output"));
        }
        Ok(Self {
            command,
            input_root,
            platform,
            declared_outputs,
            reapi_input_root: None,
        })
    }

    pub fn declared_outputs(&self) -> &[DeclaredOutputPath] {
        &self.declared_outputs
    }

    pub fn action_key(&self) -> BuildCacheResult<ActionKey> {
        ActionKey::derive(self)
    }
}

fn validate_repo_ref(repo_ref: &RepoRef) -> BuildCacheResult<()> {
    match RepoRef::parse(&repo_ref.canonical()) {
        Ok(parsed) if &parsed == repo_ref => Ok(()),
        _ => Err(BuildCacheError::InvalidAction("noncanonical repo_ref")),
    }
}

/// A canonical `<artifact-id>@<nonzero-version>` value, not an artifact store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactVersionRef {
    artifact_id: EntityId,
    version: u64,
}

impl ArtifactVersionRef {
    pub fn new(artifact_id: EntityId, version: u64) -> BuildCacheResult<Self> {
        if version == 0 {
            return Err(BuildCacheError::InvalidArtifactRef(format!(
                "{}@{version}",
                artifact_id.to_hex()
            )));
        }
        Ok(Self {
            artifact_id,
            version,
        })
    }

    pub fn parse(value: &str) -> BuildCacheResult<Self> {
        let invalid = || BuildCacheError::InvalidArtifactRef(value.to_owned());
        let (id, version) = value.split_once('@').ok_or_else(invalid)?;
        if id.len() != 32
            || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || version.is_empty()
            || version.starts_with('0')
            || !version.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let artifact_id = EntityId::from_hex(id).map_err(|_| invalid())?;
        let version = version.parse::<u64>().map_err(|_| invalid())?;
        Self::new(artifact_id, version)
    }

    pub fn artifact_id(&self) -> &EntityId {
        &self.artifact_id
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub fn to_result_ref(&self) -> String {
        format!("{}@{}", self.artifact_id.to_hex(), self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionResult {
    pub exit_code: i32,
    pub outputs: BTreeMap<DeclaredOutputPath, ArtifactVersionRef>,
    pub stdout_ref: Option<ArtifactVersionRef>,
    pub stderr_ref: Option<ArtifactVersionRef>,
    pub produced_at: u64,
    pub producer_ref: String,
}

impl ActionResult {
    pub fn validate(&self) -> BuildCacheResult<()> {
        if self.producer_ref.is_empty() {
            return Err(BuildCacheError::CorruptRecord("empty producer_ref"));
        }
        for path in self.outputs.keys() {
            DeclaredOutputPath::parse(path.as_str())?;
        }
        for reference in self.artifact_refs() {
            ArtifactVersionRef::parse(&reference.to_result_ref())?;
        }
        Ok(())
    }

    pub fn artifact_refs(&self) -> BTreeSet<ArtifactVersionRef> {
        self.outputs
            .values()
            .chain(self.stdout_ref.iter())
            .chain(self.stderr_ref.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedActionResult {
    pub action_key: ActionKey,
    pub result: ActionResult,
    pub referenced_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildCachePutOutcome {
    Stored(CachedActionResult),
    Existing(CachedActionResult),
}

pub type BuildCacheResult<T> = Result<T, BuildCacheError>;

#[derive(Debug, thiserror::Error)]
pub enum BuildCacheError {
    #[error("account cache tenant mismatch")]
    AccountMismatch,
    #[error("action is already running or requires recovery: {action_key}")]
    ActionInFlight { action_key: String },
    #[error("invalid build action: {0}")]
    InvalidAction(&'static str),
    #[error("invalid declared output path: {0}")]
    InvalidOutputPath(String),
    #[error("result contains undeclared output path: {path}")]
    UndeclaredOutput { path: String },
    #[error("invalid artifact version reference: {0}")]
    InvalidArtifactRef(String),
    #[error("artifact version is unavailable: {artifact_ref}")]
    ArtifactUnavailable { artifact_ref: String },
    #[error("artifact taint refuses cached result: {artifact_ref}")]
    TaintedResult { artifact_ref: String },
    #[error("unknown build-cache schema version: {found}")]
    UnknownSchemaVersion { found: u8 },
    #[error("corrupt build-cache record: {0}")]
    CorruptRecord(&'static str),
    #[error("referenced byte accounting overflow")]
    ReferencedBytesOverflow,
    #[error(transparent)]
    Store(#[from] Error),
}

pub struct BuildCache<'a> {
    vault: &'a Vault,
}

impl<'a> BuildCache<'a> {
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    /// Only an absent row is a miss. Admission errors never remove a row.
    pub fn get(&self, key: &ActionKey) -> BuildCacheResult<Option<CachedActionResult>> {
        self.read_row(key)?
            .map(|record| self.admit_row(key, record))
            .transpose()
    }

    /// Immutable first-writer-wins. An admitted existing row short-circuits
    /// proposal validation. `Stored` certifies admission at inspection time:
    /// concurrent taint/deletion can make the very next lookup refuse it.
    pub fn put(
        &self,
        action: &BuildAction,
        result: ActionResult,
    ) -> BuildCacheResult<BuildCachePutOutcome> {
        let key = action.action_key()?;
        if let Some(existing) = self.get(&key)? {
            return Ok(BuildCachePutOutcome::Existing(existing));
        }
        result.validate()?;
        for path in result.outputs.keys() {
            if action.declared_outputs().binary_search(path).is_err() {
                return Err(BuildCacheError::UndeclaredOutput {
                    path: path.as_str().to_owned(),
                });
            }
        }
        let referenced_bytes = inspect_result_for_store(self.vault, &result)?;
        let candidate = CachedActionResult {
            action_key: key,
            result,
            referenced_bytes,
        };
        BUILD_CACHE_REAPI_ROW.encode_value(&candidate)?;
        let store = &self.vault.store;
        // This scope does index work ONLY. Copy a winner before aborting the
        // write transaction, then decode/admit it outside the transaction.
        let winner = {
            let mut wtxn = store.env.write_txn().map_err(Error::from)?;
            let winner = BUILD_CACHE_REAPI_ROW.get(store, &wtxn, key.as_bytes())?;
            if winner.is_none() {
                BUILD_CACHE_REAPI_ROW.put(store, &mut wtxn, key.as_bytes(), &candidate)?;
                wtxn.commit().map_err(Error::from)?;
            }
            winner
        };
        match winner {
            Some(record) => Ok(BuildCachePutOutcome::Existing(
                self.admit_row(&key, record)?,
            )),
            None => Ok(BuildCachePutOutcome::Stored(candidate)),
        }
    }

    fn read_row(&self, key: &ActionKey) -> BuildCacheResult<Option<CachedActionResult>> {
        let store = &self.vault.store;
        let rtxn = store.env.read_txn().map_err(Error::from)?;
        Ok(BUILD_CACHE_REAPI_ROW.get(store, &rtxn, key.as_bytes())?)
    }

    fn admit_row(
        &self,
        key: &ActionKey,
        record: CachedActionResult,
    ) -> BuildCacheResult<CachedActionResult> {
        verify_action_key(key, &record)?;
        admit_result_for_hit(self.vault, &record.result)?;
        Ok(record)
    }
}

/// A cached build/verify action result, addressed by its content-derived action key. Key: bytes32
/// (REAPI action key).
const BUILD_CACHE_REAPI_ROW: SideTable<[u8; BUILD_CACHE_ACTION_KEY_LEN], CachedActionResult, Raw> =
    SideTable::new(&side_table::BUILD_CACHE_REAPI_ROW);

impl RawValue for CachedActionResult {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        encode_build_cache_row(self)
            .map_err(|_| Error::InvariantViolation("build cache row").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        decode_build_cache_row(bytes).map_err(|_| Error::CorruptedIndex("build cache row").into())
    }
}

/// The row's own `action_key` field must match the key it was fetched under: a defense-in-depth
/// check the pure decode above cannot make (it never sees the lookup key).
fn verify_action_key(key: &ActionKey, record: &CachedActionResult) -> BuildCacheResult<()> {
    if record.action_key == *key {
        Ok(())
    } else {
        Err(BuildCacheError::CorruptRecord("action key mismatch"))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildCacheRowV1 {
    action_key: [u8; 32],
    exit_code: i32,
    outputs: Vec<(String, String)>,
    stdout_ref: Option<String>,
    stderr_ref: Option<String>,
    produced_at: u64,
    producer_ref: String,
    referenced_bytes: u64,
}

fn encode_build_cache_row(record: &CachedActionResult) -> BuildCacheResult<Vec<u8>> {
    record.result.validate()?;
    let result = &record.result;
    let row = BuildCacheRowV1 {
        action_key: *record.action_key.as_bytes(),
        exit_code: result.exit_code,
        outputs: result
            .outputs
            .iter()
            .map(|(path, reference)| (path.as_str().to_owned(), reference.to_result_ref()))
            .collect(),
        stdout_ref: result
            .stdout_ref
            .as_ref()
            .map(ArtifactVersionRef::to_result_ref),
        stderr_ref: result
            .stderr_ref
            .as_ref()
            .map(ArtifactVersionRef::to_result_ref),
        produced_at: result.produced_at,
        producer_ref: result.producer_ref.clone(),
        referenced_bytes: record.referenced_bytes,
    };
    let mut bytes = vec![BUILD_CACHE_SCHEMA_VERSION_V1];
    rmp_serde::encode::write(&mut bytes, &row)
        .map_err(|_| BuildCacheError::CorruptRecord("row encode failed"))?;
    Ok(bytes)
}

fn decode_build_cache_row(bytes: &[u8]) -> BuildCacheResult<CachedActionResult> {
    let (&version, body) = bytes
        .split_first()
        .ok_or(BuildCacheError::CorruptRecord("empty row"))?;
    if version != BUILD_CACHE_SCHEMA_VERSION_V1 {
        return Err(BuildCacheError::UnknownSchemaVersion { found: version });
    }
    // The v1 body is the fixed eight-field MessagePack sequence emitted by
    // rmp-serde, not a map with optional/missing fields or an extensible tail.
    if body.first() != Some(&0x98) {
        return Err(BuildCacheError::CorruptRecord("invalid row field set"));
    }
    let mut cursor = Cursor::new(body);
    let row: BuildCacheRowV1 = rmp_serde::from_read(&mut cursor)
        .map_err(|_| BuildCacheError::CorruptRecord("malformed row body"))?;
    if cursor.position()
        != u64::try_from(body.len())
            .map_err(|_| BuildCacheError::CorruptRecord("row length overflow"))?
    {
        return Err(BuildCacheError::CorruptRecord("trailing row bytes"));
    }
    if row.outputs.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(BuildCacheError::CorruptRecord(
            "noncanonical output ordering",
        ));
    }
    let mut outputs = BTreeMap::new();
    for (path, reference) in row.outputs {
        let path = DeclaredOutputPath::parse(path)
            .map_err(|_| BuildCacheError::CorruptRecord("invalid output path"))?;
        outputs.insert(path, decode_artifact_ref(&reference)?);
    }
    let result = ActionResult {
        exit_code: row.exit_code,
        outputs,
        stdout_ref: row
            .stdout_ref
            .as_deref()
            .map(decode_artifact_ref)
            .transpose()?,
        stderr_ref: row
            .stderr_ref
            .as_deref()
            .map(decode_artifact_ref)
            .transpose()?,
        produced_at: row.produced_at,
        producer_ref: row.producer_ref,
    };
    result.validate()?;
    Ok(CachedActionResult {
        action_key: ActionKey(row.action_key),
        result,
        referenced_bytes: row.referenced_bytes,
    })
}

fn decode_artifact_ref(value: &str) -> BuildCacheResult<ArtifactVersionRef> {
    ArtifactVersionRef::parse(value)
        .map_err(|_| BuildCacheError::CorruptRecord("invalid artifact reference"))
}

fn require_clean(vault: &Vault, reference: &ArtifactVersionRef) -> BuildCacheResult<()> {
    match vault.artifact_taint_state(reference.artifact_id())? {
        ArtifactTaintState::Clean => Ok(()),
        ArtifactTaintState::TaintedLive | ArtifactTaintState::TaintedStale => {
            Err(BuildCacheError::TaintedResult {
                artifact_ref: reference.to_result_ref(),
            })
        }
    }
}

fn inspect_result_for_store(vault: &Vault, result: &ActionResult) -> BuildCacheResult<u64> {
    let mut referenced_bytes = 0;
    for reference in result.artifact_refs() {
        let bytes = vault
            .read_blob_artifact_version(reference.artifact_id(), reference.version())?
            .ok_or_else(|| BuildCacheError::ArtifactUnavailable {
                artifact_ref: reference.to_result_ref(),
            })?;
        require_clean(vault, &reference)?;
        let size =
            u64::try_from(bytes.len()).map_err(|_| BuildCacheError::ReferencedBytesOverflow)?;
        referenced_bytes = sum_referenced_bytes([referenced_bytes, size])?;
    }
    Ok(referenced_bytes)
}

fn sum_referenced_bytes<I: IntoIterator<Item = u64>>(sizes: I) -> BuildCacheResult<u64> {
    sizes.into_iter().try_fold(0_u64, |sum, size| {
        sum.checked_add(size)
            .ok_or(BuildCacheError::ReferencedBytesOverflow)
    })
}

fn admit_result_for_hit(vault: &Vault, result: &ActionResult) -> BuildCacheResult<()> {
    for reference in result.artifact_refs() {
        // One exact metadata lookup per ref: neither version-chain scans nor
        // potentially large content bodies belong on the hit path.
        if vault
            .blob_artifact_version_metadata(reference.artifact_id(), reference.version())?
            .is_none()
        {
            return Err(BuildCacheError::ArtifactUnavailable {
                artifact_ref: reference.to_result_ref(),
            });
        }
        require_clean(vault, &reference)?;
    }
    Ok(())
}

mod account;
mod leg;
mod reapi;
pub use leg::{BuildLegReceipt, CachedBuildLeg};
pub use reapi::ReapiDigest;

#[cfg(test)]
mod tests;

impl From<std::io::Error> for BuildCacheError {
    fn from(error: std::io::Error) -> Self {
        Self::Store(Error::from(error))
    }
}
