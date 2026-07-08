//! Sandbox boundary contract for code-mode execution.
//!
//! This module does not start a sandbox or link a production adapter. It pins
//! the host/guest ABI that future runners must obey: plain JavaScript runs
//! inside a QuickJS-class interpreter embedded as a WASM component in the
//! existing Wasmtime/WIT boundary, guests target stable `/mnt` virtual paths,
//! clock/random are deterministic host imports, credential use is handle-only,
//! first-party writes are linked as typed traps, and foreign writes leave the
//! sandbox as reviewable proposal deltas rather than commit authority.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use rmpv::Value;

use crate::{ClaimApprovalStatus, ClaimCandidate, EntityId, Error, Result, code_run::SelfEffect};

pub const SANDBOX_MNT_ROOT: &str = "/mnt";
pub const SANDBOX_WORKSPACE_ROOT: &str = "/mnt/workspace";
pub const SANDBOX_UPLOADS_ROOT: &str = "/mnt/uploads";
pub const SANDBOX_OUTPUTS_ROOT: &str = "/mnt/outputs";
pub const SANDBOX_SKILLS_ROOT: &str = "/mnt/skills";
pub const SANDBOX_WIT_WORLD_NAME: &str = "oneiron:code-run/guest@1.0.0";
pub const SANDBOX_JS_COMPONENT_NAME: &str = "oneiron.plain-js.quickjs-component";
pub const PLAIN_JS_HOST_VERB_DTS: &str = r#"declare namespace self {
  namespace memory {
    function search(input: { query: string; limit?: number }): Promise<{ results: unknown[] }>;
    function put_claim(input: {
      id: string;
      predicate: string;
      subject: unknown;
      value: unknown;
      confidence?: number;
      occurred?: { start: number; end: number };
      learnedAt?: number;
    }): Promise<{ id: string }>;
    function supersede_claim(input: { newId: string; oldId: string; now: number }): Promise<{ id: string }>;
    function put_edge(input: { src: string; kind: string; tgt: string; weight?: number }): Promise<{ src: string; kind: string; tgt: string }>;
  }

  function askHuman(input: { prompt: string }): Promise<{ waitId: string }>;
  function ask_human(input: { prompt: string }): Promise<{ waitId: string }>;
}

declare namespace oneiron {
  namespace clock {
    function now_unix_ms(): number;
  }

  namespace random {
    function bytes(length: number): Uint8Array;
  }
}
"#;

const ABI_KEY_OPERATION: &str = "operation";
const ABI_KEY_CREDENTIAL_HANDLE: &str = "credentialHandle";
const ABI_KEY_ARGS: &str = "args";

/// Trust tier selected by the host before linking a guest program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestTier {
    /// First-party Dreamer code. Public writes link as per-op typed traps.
    FirstPartyDreamer,
    /// Imported or externally-authored code.
    Foreign,
    /// Explicitly untrusted code.
    Untrusted,
}

impl SandboxGuestTier {
    /// Stable tier label for diagnostics and proposal metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstPartyDreamer => "first_party_dreamer",
            Self::Foreign => "foreign",
            Self::Untrusted => "untrusted",
        }
    }

    /// Foreign and untrusted guests cannot link host write imports.
    #[must_use]
    pub const fn requires_zero_write_imports(self) -> bool {
        matches!(self, Self::Foreign | Self::Untrusted)
    }
}

/// Guest language accepted by the code-mode authoring surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestLanguage {
    /// Full plain JavaScript interpreted inside the sandbox component.
    PlainJavaScript,
}

impl SandboxGuestLanguage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainJavaScript => "plain_javascript",
        }
    }
}

/// Stable execution boundary used to host the guest runtime component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxComponentBoundary {
    /// Wasmtime Component Model + WIT-linked host imports.
    WasmtimeWit,
}

impl SandboxComponentBoundary {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmtimeWit => "wasmtime_wit",
        }
    }
}

/// Runtime component selected for code-mode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestRuntime {
    /// QuickJS-class plain-JS interpreter embedded as a WASM component.
    PlainJsQuickJsComponent,
}

impl SandboxGuestRuntime {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => SANDBOX_JS_COMPONENT_NAME,
        }
    }

    #[must_use]
    pub const fn language(self) -> SandboxGuestLanguage {
        match self {
            Self::PlainJsQuickJsComponent => SandboxGuestLanguage::PlainJavaScript,
        }
    }

    #[must_use]
    pub const fn boundary(self) -> SandboxComponentBoundary {
        match self {
            Self::PlainJsQuickJsComponent => SandboxComponentBoundary::WasmtimeWit,
        }
    }

    #[must_use]
    pub const fn wit_world(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => SANDBOX_WIT_WORLD_NAME,
        }
    }

    #[must_use]
    pub const fn prompt_side_dts(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => PLAIN_JS_HOST_VERB_DTS,
        }
    }
}

/// Class of a host import linked into a guest program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxImportClass {
    ReadOnly,
    CredentialHandle,
    Determinism,
    DurableWait,
    WriteTrap,
}

impl SandboxImportClass {
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::WriteTrap)
    }
}

/// One host import exposed at link time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SandboxLinkedImport {
    name: &'static str,
    class: SandboxImportClass,
}

impl SandboxLinkedImport {
    #[must_use]
    pub const fn new(name: &'static str, class: SandboxImportClass) -> Self {
        Self { name, class }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn class(self) -> SandboxImportClass {
        self.class
    }

    #[must_use]
    pub fn write_trap_effect(self) -> Option<SelfEffect> {
        match (self.class, self.name) {
            (SandboxImportClass::WriteTrap, "self.memory.put_claim") => {
                Some(SelfEffect::MemoryPutClaim)
            }
            (SandboxImportClass::WriteTrap, "self.memory.supersede_claim") => {
                Some(SelfEffect::MemorySupersedeClaim)
            }
            (SandboxImportClass::WriteTrap, "self.memory.put_edge") => {
                Some(SelfEffect::MemoryPutEdge)
            }
            _ => None,
        }
    }
}

const READ_FILE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("sandbox.fs.read_file", SandboxImportClass::ReadOnly);
const CREDENTIAL_CALL_IMPORT: SandboxLinkedImport = SandboxLinkedImport::new(
    "sandbox.credential.call",
    SandboxImportClass::CredentialHandle,
);
const CLOCK_NOW_UNIX_MS_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.clock.now_unix_ms", SandboxImportClass::Determinism);
const RANDOM_BYTES_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.random.bytes", SandboxImportClass::Determinism);
const SELF_MEMORY_SEARCH_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.search", SandboxImportClass::ReadOnly);
const SELF_MEMORY_PUT_CLAIM_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.put_claim", SandboxImportClass::WriteTrap);
const SELF_MEMORY_SUPERSEDE_CLAIM_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.supersede_claim", SandboxImportClass::WriteTrap);
const SELF_MEMORY_PUT_EDGE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.put_edge", SandboxImportClass::WriteTrap);
const SELF_ASK_HUMAN_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.ask_human", SandboxImportClass::DurableWait);
const SELF_ASK_HUMAN_CAMEL_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.askHuman", SandboxImportClass::DurableWait);
const NON_WRITE_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
];
const FIRST_PARTY_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
    SELF_MEMORY_SEARCH_IMPORT,
    SELF_MEMORY_PUT_CLAIM_IMPORT,
    SELF_MEMORY_SUPERSEDE_CLAIM_IMPORT,
    SELF_MEMORY_PUT_EDGE_IMPORT,
    SELF_ASK_HUMAN_IMPORT,
    SELF_ASK_HUMAN_CAMEL_IMPORT,
];

/// Link-time contract for one guest tier.
///
/// First-party write traps are immediate typed host calls; foreign and
/// untrusted guests link no write imports and use proposal deltas only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxBoundaryContract {
    tier: SandboxGuestTier,
    runtime: SandboxGuestRuntime,
    linked_imports: &'static [SandboxLinkedImport],
    proposal_delta_channel: bool,
    credential_call_effect: SandboxCredentialEffect,
}

impl SandboxBoundaryContract {
    /// Returns the currently implemented contract for `tier`.
    #[must_use]
    pub const fn for_tier(tier: SandboxGuestTier) -> Self {
        match tier {
            SandboxGuestTier::FirstPartyDreamer => Self {
                tier,
                runtime: SandboxGuestRuntime::PlainJsQuickJsComponent,
                linked_imports: FIRST_PARTY_IMPORTS,
                proposal_delta_channel: false,
                credential_call_effect: SandboxCredentialEffect::ReadOnly,
            },
            SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => Self {
                tier,
                runtime: SandboxGuestRuntime::PlainJsQuickJsComponent,
                linked_imports: NON_WRITE_IMPORTS,
                proposal_delta_channel: true,
                credential_call_effect: SandboxCredentialEffect::ReadOnly,
            },
        }
    }

    #[must_use]
    pub const fn tier(self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub const fn runtime(self) -> SandboxGuestRuntime {
        self.runtime
    }

    #[must_use]
    pub const fn guest_language(self) -> SandboxGuestLanguage {
        self.runtime.language()
    }

    #[must_use]
    pub const fn component_boundary(self) -> SandboxComponentBoundary {
        self.runtime.boundary()
    }

    #[must_use]
    pub const fn wit_world(self) -> &'static str {
        self.runtime.wit_world()
    }

    #[must_use]
    pub const fn prompt_side_dts(self) -> &'static str {
        self.runtime.prompt_side_dts()
    }

    #[must_use]
    pub const fn linked_imports(self) -> &'static [SandboxLinkedImport] {
        self.linked_imports
    }

    /// Whether this tier emits write intents through the proposal-delta channel.
    #[must_use]
    pub const fn has_proposal_delta_channel(self) -> bool {
        self.proposal_delta_channel
    }

    /// Credential-backed imports are handle-only and read-only at this boundary.
    #[must_use]
    pub const fn credential_call_effect(self) -> SandboxCredentialEffect {
        self.credential_call_effect
    }

    /// True if any linked import can commit or trap a host write.
    #[must_use]
    pub fn links_write_imports(self) -> bool {
        self.linked_imports
            .iter()
            .any(|import| import.class().is_write())
    }
}

/// Stable `/mnt` mount classes visible to guest code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SandboxMount {
    Workspace,
    Uploads,
    Outputs,
    Skills,
}

impl SandboxMount {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Uploads => "uploads",
            Self::Outputs => "outputs",
            Self::Skills => "skills",
        }
    }

    #[must_use]
    pub const fn root(self) -> &'static str {
        match self {
            Self::Workspace => SANDBOX_WORKSPACE_ROOT,
            Self::Uploads => SANDBOX_UPLOADS_ROOT,
            Self::Outputs => SANDBOX_OUTPUTS_ROOT,
            Self::Skills => SANDBOX_SKILLS_ROOT,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "workspace" => Some(Self::Workspace),
            "uploads" => Some(Self::Uploads),
            "outputs" => Some(Self::Outputs),
            "skills" => Some(Self::Skills),
            _ => None,
        }
    }
}

/// Canonical virtual path in the guest-visible `/mnt` ABI.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxVirtualPath {
    path: String,
    mount: SandboxMount,
    relative: String,
}

impl SandboxVirtualPath {
    /// Creates a canonical virtual path under `/mnt/{workspace,uploads,outputs,skills}`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the path is not absolute under
    /// `/mnt`, targets an unknown mount, or contains empty / `.` / `..`
    /// components.
    pub fn try_new(path: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref();
        if !path.starts_with('/') {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must be absolute",
            ));
        }

        let without_root = path
            .strip_prefix('/')
            .ok_or(Error::InvalidClaimBody("sandbox virtual path missing root"))?;
        let components = without_root.split('/').collect::<Vec<_>>();
        if components.len() < 2 || components[0] != "mnt" {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must start with /mnt",
            ));
        }

        if components
            .iter()
            .any(|component| component.is_empty() || *component == "." || *component == "..")
        {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path must be canonical",
            ));
        }

        if components
            .iter()
            .any(|component| component.as_bytes().contains(&0))
        {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path contains nul byte",
            ));
        }
        if components.iter().any(|component| component.contains('\\')) {
            return Err(Error::InvalidClaimBody(
                "sandbox virtual path contains host path separator",
            ));
        }

        let mount = SandboxMount::parse(components[1]).ok_or(Error::InvalidClaimBody(
            "sandbox virtual path targets unknown /mnt mount",
        ))?;
        let relative = components[2..].join("/");
        Ok(Self {
            path: format!("/{}", components.join("/")),
            mount,
            relative,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn mount(&self) -> SandboxMount {
        self.mount
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative
    }
}

impl fmt::Debug for SandboxVirtualPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SandboxVirtualPath")
            .field(&self.path)
            .finish()
    }
}

/// Host-owned mapping from virtual `/mnt` roots to real filesystem roots.
pub struct SandboxMountTable {
    workspace: PathBuf,
    uploads: PathBuf,
    outputs: PathBuf,
    skills: PathBuf,
}

impl SandboxMountTable {
    /// Creates a host mount table. The paths are host-only and are never
    /// returned by guest-facing adapter calls.
    #[must_use]
    pub fn new(
        workspace: impl Into<PathBuf>,
        uploads: impl Into<PathBuf>,
        outputs: impl Into<PathBuf>,
        skills: impl Into<PathBuf>,
    ) -> Self {
        Self {
            workspace: workspace.into(),
            uploads: uploads.into(),
            outputs: outputs.into(),
            skills: skills.into(),
        }
    }

    #[must_use]
    pub const fn guest_mount_roots(&self) -> [&'static str; 4] {
        [
            SANDBOX_WORKSPACE_ROOT,
            SANDBOX_UPLOADS_ROOT,
            SANDBOX_OUTPUTS_ROOT,
            SANDBOX_SKILLS_ROOT,
        ]
    }

    /// Resolves a validated virtual path to its host path for host-side IO.
    #[must_use]
    pub fn resolve_host_path(&self, path: &SandboxVirtualPath) -> PathBuf {
        let root = match path.mount() {
            SandboxMount::Workspace => &self.workspace,
            SandboxMount::Uploads => &self.uploads,
            SandboxMount::Outputs => &self.outputs,
            SandboxMount::Skills => &self.skills,
        };
        if path.relative_path().is_empty() {
            return root.clone();
        }
        root.join(Path::new(path.relative_path()))
    }
}

impl fmt::Debug for SandboxMountTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxMountTable")
            .field("guest_mount_roots", &self.guest_mount_roots())
            .field("host_roots", &"<host-only>")
            .finish()
    }
}

/// Opaque credential reference passed through guest ABI instead of secret bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxCredentialHandle(String);

impl SandboxCredentialHandle {
    /// Creates an opaque credential handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the handle is blank or contains
    /// control characters.
    pub fn new(handle: impl Into<String>) -> Result<Self> {
        let handle = handle.into();
        let trimmed = handle.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidClaimBody(
                "sandbox credential handle must not be blank",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(Error::InvalidClaimBody(
                "sandbox credential handle contains control character",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SandboxCredentialHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SandboxCredentialHandle")
            .field(&self.0)
            .finish()
    }
}

/// Effect class for credential-backed host operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxCredentialEffect {
    ReadOnly,
}

impl SandboxCredentialEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
        }
    }
}

/// Typed operation name for a credential-backed, read-only host call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCredentialOperation {
    name: String,
    effect: SandboxCredentialEffect,
}

impl SandboxCredentialOperation {
    /// Creates a read-only credential-backed operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the operation name is blank or
    /// contains control characters.
    pub fn read_only(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidClaimBody(
                "sandbox credential operation must not be blank",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(Error::InvalidClaimBody(
                "sandbox credential operation contains control character",
            ));
        }
        Ok(Self {
            name: trimmed.to_owned(),
            effect: SandboxCredentialEffect::ReadOnly,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn effect(&self) -> SandboxCredentialEffect {
        self.effect
    }
}

/// Read-only file request from guest code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxReadFile {
    pub path: SandboxVirtualPath,
}

impl SandboxReadFile {
    #[must_use]
    pub const fn new(path: SandboxVirtualPath) -> Self {
        Self { path }
    }
}

/// Guest-visible file read result. The host path is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileRead {
    pub path: SandboxVirtualPath,
    pub bytes: Vec<u8>,
}

/// Credential-backed host call from guest code.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxCredentialCall {
    operation: SandboxCredentialOperation,
    credential: SandboxCredentialHandle,
    args: Value,
}

impl SandboxCredentialCall {
    /// Creates a handle-only credential call for a read-only host operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the operation name is invalid.
    pub fn read_only(
        operation: impl Into<String>,
        credential: SandboxCredentialHandle,
        args: Value,
    ) -> Result<Self> {
        Ok(Self {
            operation: SandboxCredentialOperation::read_only(operation)?,
            credential,
            args,
        })
    }

    #[must_use]
    pub fn operation(&self) -> &SandboxCredentialOperation {
        &self.operation
    }

    #[must_use]
    pub fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }

    #[must_use]
    pub fn args(&self) -> &Value {
        &self.args
    }

    /// Guest ABI serialization for the call. It carries a credential handle,
    /// never credential material.
    #[must_use]
    pub fn guest_abi_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::from(ABI_KEY_OPERATION),
                Value::from(self.operation.as_str().to_owned()),
            ),
            (
                Value::from(ABI_KEY_CREDENTIAL_HANDLE),
                Value::from(self.credential.as_str().to_owned()),
            ),
            (Value::from(ABI_KEY_ARGS), self.args.clone()),
        ])
    }
}

/// Host receipt for a credential-backed call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCredentialOutcome {
    operation: SandboxCredentialOperation,
    credential: SandboxCredentialHandle,
}

impl SandboxCredentialOutcome {
    #[must_use]
    pub fn operation(&self) -> &SandboxCredentialOperation {
        &self.operation
    }

    #[must_use]
    pub fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }
}

/// Single write intent emitted by a propose-only guest.
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxProposalWrite {
    FileWrite(SandboxFileWriteProposal),
    ClaimCandidate(SandboxClaimProposal),
}

impl SandboxProposalWrite {
    #[must_use]
    pub const fn kind(&self) -> SandboxProposalKind {
        match self {
            Self::FileWrite(_) => SandboxProposalKind::FileWrite,
            Self::ClaimCandidate(_) => SandboxProposalKind::ClaimCandidate,
        }
    }
}

/// Coarse proposal kind used for review routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxProposalKind {
    FileWrite,
    ClaimCandidate,
}

impl SandboxProposalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileWrite => "file_write",
            Self::ClaimCandidate => "claim_candidate",
        }
    }
}

/// One proposed file write under the virtual `/mnt` ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileWriteProposal {
    pub path: SandboxVirtualPath,
    pub bytes: Vec<u8>,
}

impl SandboxFileWriteProposal {
    #[must_use]
    pub const fn new(path: SandboxVirtualPath, bytes: Vec<u8>) -> Self {
        Self { path, bytes }
    }
}

/// One proposed memory claim from a propose-only guest.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxClaimProposal {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
}

impl SandboxClaimProposal {
    #[must_use]
    pub fn new(id: EntityId, candidate: ClaimCandidate) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
        }
    }
}

/// Reviewable delta emitted for one foreign/untrusted write intent.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxProposalDelta {
    id: EntityId,
    tier: SandboxGuestTier,
    approval: ClaimApprovalStatus,
    write: SandboxProposalWrite,
}

impl SandboxProposalDelta {
    fn new(tier: SandboxGuestTier, write: SandboxProposalWrite) -> Result<Self> {
        if !matches!(
            tier,
            SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted
        ) {
            return Err(Error::InvalidClaimBody(
                "sandbox proposal deltas are only for propose-only tiers",
            ));
        }

        Ok(Self {
            id: EntityId::now(),
            tier,
            approval: ClaimApprovalStatus::Proposed,
            write,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SandboxProposalKind {
        self.write.kind()
    }

    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.id
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub const fn approval(&self) -> ClaimApprovalStatus {
        self.approval
    }

    #[must_use]
    pub const fn write(&self) -> &SandboxProposalWrite {
        &self.write
    }
}

/// Boundary adapter used by a sandbox runtime.
pub trait SandboxBoundaryAdapter {
    /// Reads one file through the virtual `/mnt` ABI.
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead>;

    /// Calls one credential-backed operation by opaque handle.
    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome>;

    /// Emits one proposal delta for a foreign/untrusted write intent.
    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta>;
}

/// In-memory adapter used to pin the boundary contract before production runtime work.
pub struct FakeSandboxAdapter {
    tier: SandboxGuestTier,
    mounts: SandboxMountTable,
    files: BTreeMap<SandboxVirtualPath, Vec<u8>>,
    credential_calls: Vec<SandboxCredentialCall>,
    proposal_deltas: Vec<SandboxProposalDelta>,
}

impl FakeSandboxAdapter {
    #[must_use]
    pub fn new(tier: SandboxGuestTier, mounts: SandboxMountTable) -> Self {
        Self {
            tier,
            mounts,
            files: BTreeMap::new(),
            credential_calls: Vec::new(),
            proposal_deltas: Vec::new(),
        }
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub fn guest_mount_roots(&self) -> [&'static str; 4] {
        self.mounts.guest_mount_roots()
    }

    pub fn stage_file(&mut self, path: SandboxVirtualPath, bytes: impl Into<Vec<u8>>) {
        self.files.insert(path, bytes.into());
    }

    #[must_use]
    pub fn credential_calls(&self) -> &[SandboxCredentialCall] {
        &self.credential_calls
    }

    #[must_use]
    pub fn proposal_deltas(&self) -> &[SandboxProposalDelta] {
        &self.proposal_deltas
    }
}

impl SandboxBoundaryAdapter for FakeSandboxAdapter {
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead> {
        let _host_path = self.mounts.resolve_host_path(&call.path);
        let bytes = self
            .files
            .get(&call.path)
            .ok_or(Error::EntityNotFound)?
            .clone();
        Ok(SandboxFileRead {
            path: call.path,
            bytes,
        })
    }

    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome> {
        self.credential_calls.push(call.clone());
        Ok(SandboxCredentialOutcome {
            operation: call.operation,
            credential: call.credential,
        })
    }

    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta> {
        let contract = SandboxBoundaryContract::for_tier(self.tier);
        if !contract.has_proposal_delta_channel() {
            return Err(Error::InvalidClaimBody(
                "sandbox tier does not expose proposal deltas",
            ));
        }

        let delta = SandboxProposalDelta::new(self.tier, write)?;
        self.proposal_deltas.push(delta.clone());
        Ok(delta)
    }
}

impl fmt::Debug for FakeSandboxAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSandboxAdapter")
            .field("tier", &self.tier)
            .field("mounts", &self.mounts)
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .field("credential_calls", &self.credential_calls)
            .field("proposal_deltas", &self.proposal_deltas)
            .finish()
    }
}

#[cfg(test)]
mod tests;
