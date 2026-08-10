//! MicroVM execution lane for foreign and ingested guest code.
//!
//! The parent module pins the boundary *contract*; this module lands the first
//! *executing* backend seam behind the same [`SandboxBoundaryAdapter`] trait.
//! Two guarantees move from in-process convention to backend enforcement:
//!
//! * **Overlay writes are proposals.** The guest's writable mount is an overlay
//!   upper directory; the base mount is read-only from the host side and the
//!   adapter exposes no commit verb. The only way a guest write leaves the
//!   sandbox is as a [`SandboxProposalDelta`].
//! * **Credentials are resolved at the network boundary.** The guest addresses
//!   an egress request by [`SandboxCredentialHandle`]. The host-side proxy
//!   checks the handle's destination allowlist *before* resolving, measures and
//!   scrubs the material, and returns a receipt that carries no secret bytes.
//!   Outbound transport lands with SECRET-02; the guest-visible outcome stays
//!   handle-only.
//!
//! Backend routing lives in [`select_backend_for_tier`] and nowhere else;
//! [`SandboxBoundaryContract::for_tier`] stays a pure value constructor.

use std::{
    collections::BTreeMap,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use rmpv::Value;

use super::{
    SANDBOX_WORKSPACE_ROOT, SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxCredentialCall,
    SandboxCredentialHandle, SandboxCredentialOutcome, SandboxFileRead, SandboxFileWriteProposal,
    SandboxGuestTier, SandboxMount, SandboxMountTable, SandboxProposalDelta, SandboxProposalWrite,
    SandboxReadFile, SandboxVirtualPath,
};
use crate::{EntityId, Error, Result};

/// Guest ABI key naming the scheme of an egress destination.
pub const SANDBOX_EGRESS_ABI_KEY_SCHEME: &str = "scheme";
/// Guest ABI key naming the host of an egress destination.
pub const SANDBOX_EGRESS_ABI_KEY_HOST: &str = "host";

/// Stable name of the host-side credential proxy in diagnostics.
pub const EGRESS_PROXY_NAME: &str = "credential-egress-proxy";

/// Prebuilt guest image: kernel, root filesystem and the guest component.
///
/// The paths are host-owned build artifacts; nothing here is guest-visible.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestImage {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub component: PathBuf,
}

impl GuestImage {
    #[must_use]
    pub fn new(
        kernel: impl Into<PathBuf>,
        rootfs: impl Into<PathBuf>,
        component: impl Into<PathBuf>,
    ) -> Self {
        Self {
            kernel: kernel.into(),
            rootfs: rootfs.into(),
            component: component.into(),
        }
    }

    /// Checks that every image artifact is present before a guest is booted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when an artifact is missing. The
    /// message names the artifact class, never the host path.
    pub fn ensure_present(&self, backend: &'static str) -> Result<()> {
        for (class, path) in [
            ("kernel", &self.kernel),
            ("rootfs", &self.rootfs),
            ("component", &self.component),
        ] {
            if !path.exists() {
                return Err(backend_error(
                    backend,
                    format!("guest image artifact `{class}` is missing"),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for GuestImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestImage")
            .field("artifacts", &["kernel", "rootfs", "component"])
            .field("host_paths", &"<host-only>")
            .finish()
    }
}

/// Live handle for one prepared microVM.
///
/// Host paths (overlay dirs, egress socket) stay host-side: the [`fmt::Debug`]
/// rendering redacts them so they cannot leak into guest-visible diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct MicroVmHandle {
    id: String,
    tier: SandboxGuestTier,
    base_root: PathBuf,
    overlay_upper: PathBuf,
    egress_socket: PathBuf,
}

impl MicroVmHandle {
    /// Creates a handle for a VM a backend has prepared.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when the VM id is blank or
    /// contains control characters.
    pub fn new(
        id: impl Into<String>,
        tier: SandboxGuestTier,
        base_root: impl Into<PathBuf>,
        overlay_upper: impl Into<PathBuf>,
        egress_socket: impl Into<PathBuf>,
    ) -> Result<Self> {
        let id = id.into();
        let trimmed = id.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            return Err(backend_error("microvm", "vm id must be a non-blank label"));
        }
        Ok(Self {
            id: trimmed.to_owned(),
            tier,
            base_root: base_root.into(),
            overlay_upper: overlay_upper.into(),
            egress_socket: egress_socket.into(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    /// Host root of the read-only base mount. Never written through this handle.
    #[must_use]
    pub fn base_root(&self) -> &Path {
        &self.base_root
    }

    /// Host root of the overlay upper directory the guest writes into.
    #[must_use]
    pub fn overlay_upper(&self) -> &Path {
        &self.overlay_upper
    }

    /// Host endpoint of the VM-internal egress channel owned by the adapter.
    #[must_use]
    pub fn egress_socket(&self) -> &Path {
        &self.egress_socket
    }
}

impl fmt::Debug for MicroVmHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicroVmHandle")
            .field("id", &self.id)
            .field("tier", &self.tier)
            .field("host_paths", &"<host-only>")
            .finish()
    }
}

/// Result of one guest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicroVmExit {
    pub status: i32,
    pub overlay_dirty: bool,
}

/// Resource ceiling applied to one guest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub wall_clock_secs: u64,
    pub mem_mib: u32,
    pub pids: u32,
}

impl ExecutionBudget {
    #[must_use]
    pub const fn new(wall_clock_secs: u64, mem_mib: u32, pids: u32) -> Self {
        Self {
            wall_clock_secs,
            mem_mib,
            pids,
        }
    }

    /// True when every axis of the budget is actually bounded. A zero on any
    /// axis is treated as "unbounded" and refused by backends.
    #[must_use]
    pub const fn is_bounded(self) -> bool {
        self.wall_clock_secs > 0 && self.mem_mib > 0 && self.pids > 0
    }
}

/// One destination in a credential handle's allowlist, and also the shape a
/// guest egress request is parsed into.
///
/// As an allowlist entry `host_suffix` is a domain suffix; as a request it is
/// the concrete host. Matching is label-boundary aware, so `example.com` never
/// admits `notexample.com`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialDestination {
    scheme: String,
    host_suffix: String,
}

impl CredentialDestination {
    /// Creates a normalized destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the scheme or host is blank,
    /// carries control characters, or embeds path/port separators.
    pub fn new(scheme: impl Into<String>, host_suffix: impl Into<String>) -> Result<Self> {
        let scheme = scheme.into().trim().to_lowercase();
        let host_suffix = host_suffix.into().trim().trim_matches('.').to_lowercase();

        if scheme.is_empty() || host_suffix.is_empty() {
            return Err(Error::InvalidClaimBody(
                "credential destination requires a scheme and a host",
            ));
        }
        if !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return Err(Error::InvalidClaimBody(
                "credential destination scheme is not a valid URI scheme",
            ));
        }
        if host_suffix
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | ':' | '@' | '?' | '#' | ' ' | '\\'))
        {
            return Err(Error::InvalidClaimBody(
                "credential destination host must be a bare host",
            ));
        }

        Ok(Self {
            scheme,
            host_suffix,
        })
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host_suffix(&self) -> &str {
        &self.host_suffix
    }

    /// True when `self` (an allowlist entry) admits `requested`.
    #[must_use]
    pub fn matches(&self, requested: &Self) -> bool {
        self.scheme == requested.scheme
            && (requested.host_suffix == self.host_suffix
                || requested
                    .host_suffix
                    .strip_suffix(&self.host_suffix)
                    .is_some_and(|head| head.ends_with('.')))
    }
}

impl fmt::Debug for CredentialDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_suffix)
    }
}

impl fmt::Display for CredentialDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_suffix)
    }
}

/// Per-handle destination allowlist — the confused-deputy guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialAllowlist {
    entries: BTreeMap<String, Vec<CredentialDestination>>,
}

impl CredentialAllowlist {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds one destination to a credential handle.
    pub fn allow(&mut self, handle: &SandboxCredentialHandle, destination: CredentialDestination) {
        let bound = self.entries.entry(handle.as_str().to_owned()).or_default();
        if !bound.contains(&destination) {
            bound.push(destination);
        }
    }

    /// True when `handle` is bound to a destination admitting `requested`.
    /// An unknown handle is refused: the default is deny.
    #[must_use]
    pub fn permits(
        &self,
        handle: &SandboxCredentialHandle,
        requested: &CredentialDestination,
    ) -> bool {
        self.entries
            .get(handle.as_str())
            .is_some_and(|bound| bound.iter().any(|entry| entry.matches(requested)))
    }
}

/// Resolves credential handles into injectable bytes at the egress boundary.
///
/// Implementations enforce the handle's own binding as well; the proxy's
/// allowlist check is the outer of two gates, never the only one.
pub trait CredentialResolver: Send + Sync {
    /// Resolves `handle` for injection into a request addressed to `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle is unknown, revoked, or not bound to
    /// `dest`. Callers treat any error as a refusal — no injection happens.
    fn resolve_for(
        &self,
        handle: &SandboxCredentialHandle,
        dest: &CredentialDestination,
    ) -> Result<Vec<u8>>;
}

/// Host receipt for one boundary injection. Carries no secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialInjection {
    vm_id: String,
    credential: SandboxCredentialHandle,
    destination: CredentialDestination,
    injected_bytes: usize,
}

impl CredentialInjection {
    #[must_use]
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }

    #[must_use]
    pub const fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }

    #[must_use]
    pub const fn destination(&self) -> &CredentialDestination {
        &self.destination
    }

    /// Length of the injected material. The material itself is dropped at the
    /// boundary and is never stored on the receipt.
    #[must_use]
    pub const fn injected_bytes(&self) -> usize {
        self.injected_bytes
    }
}

impl fmt::Debug for CredentialInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjection")
            .field("vm_id", &self.vm_id)
            .field("credential", &self.credential)
            .field("destination", &self.destination)
            .field("injected_bytes", &self.injected_bytes)
            .field("material", &"<never-retained>")
            .finish()
    }
}

/// Host-owned egress proxy: allowlist enforcement plus resolve-and-inject.
///
/// The proxy is armed by the backend before any injection is possible, so a
/// VM whose transport failed to come up refuses credentials instead of
/// silently running without one.
pub struct CredentialEgressProxy {
    allowlist: CredentialAllowlist,
    resolver: Arc<dyn CredentialResolver>,
    armed: bool,
}

impl CredentialEgressProxy {
    #[must_use]
    pub fn new(allowlist: CredentialAllowlist, resolver: Arc<dyn CredentialResolver>) -> Self {
        Self {
            allowlist,
            resolver,
            armed: false,
        }
    }

    #[must_use]
    pub fn resolver(&self) -> &dyn CredentialResolver {
        self.resolver.as_ref()
    }

    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Marks the VM-internal transport as bound and ready.
    pub const fn arm(&mut self) {
        self.armed = true;
    }

    /// Resolves, measures and scrubs `credential` at the outbound boundary.
    ///
    /// The transport that will consume resolved material lands with SECRET-02;
    /// this method retains only a secret-free receipt.
    ///
    /// The allowlist is checked BEFORE the resolver is consulted, so an
    /// off-list destination never reaches secret material. The resolved bytes
    /// are scrubbed and dropped here; only a receipt travels onward.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when the proxy is not armed,
    /// [`Error::MicroVmCredentialDestinationDenied`] when the handle is not
    /// bound to the destination, or the resolver's own refusal.
    pub fn inject(
        &self,
        vm: &MicroVmHandle,
        credential: &SandboxCredentialHandle,
        destination: &CredentialDestination,
    ) -> Result<CredentialInjection> {
        if !self.armed {
            return Err(backend_error(
                EGRESS_PROXY_NAME,
                "credential proxy is not armed for this vm",
            ));
        }
        if !self.allowlist.permits(credential, destination) {
            return Err(Error::MicroVmCredentialDestinationDenied {
                credential: credential.as_str().to_owned(),
                scheme: destination.scheme().to_owned(),
                host: destination.host_suffix().to_owned(),
            });
        }

        let mut material = self.resolver.resolve_for(credential, destination)?;
        if material.is_empty() {
            return Err(backend_error(
                EGRESS_PROXY_NAME,
                "credential resolver returned empty material",
            ));
        }
        let injected_bytes = material.len();
        // Material is resolved, measured and scrubbed at this boundary. The
        // outbound transport lands with SECRET-02; bytes never travel guest-ward.
        for byte in &mut material {
            // SAFETY: `byte` is a valid, uniquely borrowed element of `material`.
            // Volatile writes prevent the scrub from being elided as a dead store.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        drop(material);

        Ok(CredentialInjection {
            vm_id: vm.id().to_owned(),
            credential: credential.clone(),
            destination: destination.clone(),
            injected_bytes,
        })
    }
}

impl fmt::Debug for CredentialEgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialEgressProxy")
            .field("allowlist", &self.allowlist)
            .field("armed", &self.armed)
            .field("resolver", &"<host-only>")
            .finish()
    }
}

/// Virtualization backend able to run one propose-only guest.
pub trait MicroVmBackend: Send + Sync {
    /// Stable backend label for diagnostics.
    fn name(&self) -> &'static str;

    /// Provisions overlay dirs and the egress channel for one guest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when provisioning fails or the
    /// contract is not a propose-only one.
    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle>;

    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when the VM is unknown, the
    /// budget is unbounded, the image is incomplete, or the guest cannot boot.
    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit>;

    /// Diffs the overlay upper against the base into write proposals.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmOverlayError`] when the overlay cannot be read
    /// or contains an entry that is not a plain file.
    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>>;

    /// Binds `resolver` into the VM's egress transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when the VM has no egress
    /// channel this backend can bind.
    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        resolver: &dyn CredentialResolver,
    ) -> Result<()>;
}

impl MicroVmBackend for Box<dyn MicroVmBackend> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        (**self).prepare(contract, mounts)
    }

    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        (**self).run(vm, image, budget)
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        (**self).collect_overlay_delta(vm)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        (**self).proxy_credentials(vm, resolver)
    }
}

/// [`SandboxBoundaryAdapter`] whose guarantees are backed by a microVM.
///
/// There is deliberately no commit verb here: overlay writes become
/// [`SandboxProposalDelta`] values and stop.
pub struct MicroVmSandboxAdapter {
    contract: SandboxBoundaryContract,
    mounts: SandboxMountTable,
    backend: Box<dyn MicroVmBackend>,
    vm: MicroVmHandle,
    proxy: CredentialEgressProxy,
    proposal_deltas: Vec<SandboxProposalDelta>,
    credential_injections: Vec<CredentialInjection>,
    overlay_collected: bool,
}

impl MicroVmSandboxAdapter {
    /// Prepares a VM for `tier` and arms its credential proxy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when `tier` is not a propose-only
    /// tier, or when the backend fails to prepare the VM or bind the egress
    /// transport.
    pub fn new(
        tier: SandboxGuestTier,
        mounts: SandboxMountTable,
        backend: Box<dyn MicroVmBackend>,
        resolver: Arc<dyn CredentialResolver>,
        allowlist: CredentialAllowlist,
    ) -> Result<Self> {
        let contract = SandboxBoundaryContract::for_tier(tier);
        if !contract.has_proposal_delta_channel() || contract.links_write_imports() {
            return Err(backend_error(
                backend.name(),
                "microVM lane accepts propose-only guest tiers only",
            ));
        }

        let vm = backend.prepare(&contract, &mounts)?;
        let mut proxy = CredentialEgressProxy::new(allowlist, resolver);
        backend.proxy_credentials(&vm, proxy.resolver())?;
        proxy.arm();

        Ok(Self {
            contract,
            mounts,
            backend,
            vm,
            proxy,
            proposal_deltas: Vec::new(),
            credential_injections: Vec::new(),
            overlay_collected: false,
        })
    }

    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    #[must_use]
    pub const fn contract(&self) -> SandboxBoundaryContract {
        self.contract
    }

    #[must_use]
    pub const fn vm(&self) -> &MicroVmHandle {
        &self.vm
    }

    #[must_use]
    pub fn proposal_deltas(&self) -> &[SandboxProposalDelta] {
        &self.proposal_deltas
    }

    #[must_use]
    pub fn credential_injections(&self) -> &[CredentialInjection] {
        &self.credential_injections
    }

    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmOverlayError`] after overlay export is sealed;
    /// otherwise propagates the backend's run failure.
    pub fn run(&mut self, image: &GuestImage, budget: ExecutionBudget) -> Result<MicroVmExit> {
        if self.overlay_collected {
            return Err(overlay_error(
                "guest execution is forbidden after overlay export is sealed",
            ));
        }
        self.backend.run(&self.vm, image, budget)
    }

    /// Drains the overlay into proposal deltas.
    ///
    /// This is the only path from a guest write to the host: every collected
    /// overlay entry goes through [`SandboxBoundaryAdapter::propose_write`].
    ///
    /// # Errors
    ///
    /// Propagates [`Error::MicroVmOverlayError`] from the overlay diff, or the
    /// proposal-channel refusal for a tier without one.
    pub fn collect_overlay_proposals(&mut self) -> Result<Vec<SandboxProposalDelta>> {
        if self.overlay_collected {
            return Err(overlay_error("overlay proposals were already collected"));
        }

        let writes = self.backend.collect_overlay_delta(&self.vm)?;
        let mut deltas = Vec::with_capacity(writes.len());
        for write in writes {
            deltas.push(self.propose_write(write)?);
        }
        self.overlay_collected = true;
        Ok(deltas)
    }
}

impl SandboxBoundaryAdapter for MicroVmSandboxAdapter {
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead> {
        let host_path = self.mounts.resolve_host_path(&call.path);
        // Confinement walk: the OS path resolver follows intermediate symlinks,
        // so a symlinked directory under the mount root would smuggle host
        // bytes from outside it — the overlay walker refuses symlinks per
        // entry for exactly this reason. Descend each intermediate component
        // of the relative path with `symlink_metadata` and refuse before any
        // byte is read; the mount root itself is the trusted anchor.
        let relative = Path::new(call.path.relative_path());
        let mut walked = host_path.clone();
        for _ in relative.components() {
            walked.pop();
        }
        let component_total = relative.components().count();
        for (index, component) in relative.components().enumerate() {
            walked.push(component.as_os_str());
            if index + 1 == component_total {
                break; // the final component keeps the refusal below
            }
            let metadata = fs::symlink_metadata(&walked).map_err(|_| Error::EntityNotFound)?;
            if metadata.is_symlink() {
                return Err(Error::MicroVmOverlayError {
                    detail: format!(
                        "base mount entry {} crosses a symlinked directory",
                        call.path.as_str()
                    ),
                });
            }
        }
        let metadata = fs::symlink_metadata(&host_path).map_err(|_| Error::EntityNotFound)?;
        if metadata.is_symlink() {
            return Err(Error::MicroVmOverlayError {
                detail: format!("base mount entry {} is a symlink", call.path.as_str()),
            });
        }
        let file_bytes = metadata.len();
        if file_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {} ({file_bytes} bytes)",
                call.path.as_str()
            )));
        }

        let file = fs::File::open(&host_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => Error::EntityNotFound,
            _ => Error::MicroVmOverlayError {
                detail: format!("base mount read failed for {}", call.path.as_str()),
            },
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_OVERLAY_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::MicroVmOverlayError {
                detail: format!(
                    "base mount read failed for {}: {}",
                    call.path.as_str(),
                    error.kind()
                ),
            })?;
        let actual_bytes = u64::try_from(bytes.len()).map_err(|_| {
            overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {}",
                call.path.as_str()
            ))
        })?;
        if actual_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {} ({actual_bytes} bytes)",
                call.path.as_str()
            )));
        }
        Ok(SandboxFileRead {
            path: call.path,
            bytes,
        })
    }

    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome> {
        let destination = egress_destination_from_args(call.args())?;
        let injection = self
            .proxy
            .inject(&self.vm, call.credential(), &destination)?;
        self.credential_injections.push(injection);
        Ok(SandboxCredentialOutcome {
            operation: call.operation,
            credential: call.credential,
        })
    }

    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta> {
        if !self.contract.has_proposal_delta_channel() {
            return Err(Error::InvalidClaimBody(
                "sandbox tier does not expose proposal deltas",
            ));
        }
        let delta = SandboxProposalDelta::new(self.contract.tier(), write)?;
        self.proposal_deltas.push(delta.clone());
        Ok(delta)
    }
}

impl fmt::Debug for MicroVmSandboxAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicroVmSandboxAdapter")
            .field("backend", &self.backend.name())
            .field("tier", &self.contract.tier())
            .field("mounts", &self.mounts)
            .field("vm", &self.vm)
            .field("proxy", &self.proxy)
            .field("proposal_deltas", &self.proposal_deltas.len())
            .field("credential_injections", &self.credential_injections)
            .field("overlay_collected", &self.overlay_collected)
            .finish()
    }
}

/// Routes one guest tier to its execution backend.
///
/// `Ok(None)` means "no microVM": first-party code runs in-process. Foreign and
/// untrusted code either gets an isolating backend or fails closed — there is
/// no silent no-sandbox path, and the dev reference backend is only ever
/// reachable under `cfg(test)` / `debug_assertions` / feature `microvm-dev`.
///
/// # Errors
///
/// Returns [`Error::MicroVmBackendUnavailable`] when the tier needs isolation
/// and no backend is compiled in or detected.
pub fn select_backend_for_tier(tier: SandboxGuestTier) -> Result<Option<Box<dyn MicroVmBackend>>> {
    match tier {
        SandboxGuestTier::FirstPartyDreamer => Ok(None),
        SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => {
            select_isolating_backend(tier).map(Some)
        }
    }
}

fn select_isolating_backend(tier: SandboxGuestTier) -> Result<Box<dyn MicroVmBackend>> {
    if let Some(backend) = firecracker_backend() {
        return Ok(backend);
    }
    if let Some(backend) = dev_backend() {
        return Ok(backend);
    }
    Err(backend_unavailable(tier))
}

fn backend_unavailable(tier: SandboxGuestTier) -> Error {
    Error::MicroVmBackendUnavailable {
        tier: tier.as_str(),
    }
}

#[cfg(feature = "microvm-firecracker")]
fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::firecracker::FirecrackerBackend::detect()
        .map(|backend| Box::new(backend) as Box<dyn MicroVmBackend>)
}

#[cfg(not(feature = "microvm-firecracker"))]
const fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
fn dev_backend() -> Option<Box<dyn MicroVmBackend>> {
    Some(Box::new(DevProcessBackend::in_temp_root()))
}

#[cfg(not(any(test, debug_assertions, feature = "microvm-dev")))]
const fn dev_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

/// True when the dev reference backend is compiled into this build.
#[must_use]
pub const fn dev_backend_compiled() -> bool {
    cfg!(any(test, debug_assertions, feature = "microvm-dev"))
}

/// True when the Firecracker backend is compiled into this build.
#[must_use]
pub const fn firecracker_backend_compiled() -> bool {
    cfg!(feature = "microvm-firecracker")
}

/// Name of the dev reference backend.
pub const DEV_BACKEND_NAME: &str = "dev-process-isolation";

/// Development-only reference backend.
///
/// It reproduces the boundary *discipline* — writes land in an overlay upper
/// and only reach the host as proposals, credentials resolve behind the
/// allowlist — but it is **not** a security boundary: no VMM, no kernel
/// isolation. It is compiled only under `cfg(test)`, `debug_assertions` or the
/// explicit `microvm-dev` feature, and [`select_backend_for_tier`] never hands
/// it to a release build without that feature.
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
pub struct DevProcessBackend {
    root: PathBuf,
    prepared: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl DevProcessBackend {
    /// Creates a backend rooted at a host-owned scratch directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            prepared: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Creates a backend under the platform temp dir.
    #[must_use]
    pub fn in_temp_root() -> Self {
        Self::new(std::env::temp_dir().join("oneiron-microvm-dev"))
    }

    fn ensure_prepared(&self, vm: &MicroVmHandle) -> Result<()> {
        let prepared = self
            .prepared
            .lock()
            .map_err(|_| backend_error(DEV_BACKEND_NAME, "backend state is poisoned"))?;
        if prepared.contains(vm.id()) {
            return Ok(());
        }
        Err(backend_error(
            DEV_BACKEND_NAME,
            "vm was not prepared by this backend",
        ))
    }
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl MicroVmBackend for DevProcessBackend {
    fn name(&self) -> &'static str {
        DEV_BACKEND_NAME
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        let handle = prepare_overlay_handle(&self.root, DEV_BACKEND_NAME, contract, mounts)?;
        self.prepared
            .lock()
            .map_err(|_| backend_error(DEV_BACKEND_NAME, "backend state is poisoned"))?
            .insert(handle.id().to_owned());
        Ok(handle)
    }

    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        self.ensure_prepared(vm)?;
        if !budget.is_bounded() {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "execution budget must bound wall clock, memory and pids",
            ));
        }
        image.ensure_present(DEV_BACKEND_NAME)?;

        // The dev backend boots no guest: with no VMM and no interpreter linked
        // it exercises the host half of the boundary only. Anything a guest
        // "wrote" is whatever the caller staged in the overlay upper, which is
        // exactly what an isolating backend would hand back.
        let overlay_dirty = fs::read_dir(vm.overlay_upper())
            .map_err(|error| overlay_error(overlay_io_detail("upper", &error)))?
            .next()
            .is_some();
        Ok(MicroVmExit {
            status: 0,
            overlay_dirty,
        })
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        self.ensure_prepared(vm)?;
        collect_overlay_writes(vm.overlay_upper(), SandboxMount::Workspace)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        _resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        // The dev backend has no in-guest transport to bind the resolver into;
        // arming is the parent-directory check that the egress endpoint could
        // exist. Resolution and allowlist enforcement stay host-side in
        // `CredentialEgressProxy`, which is backend-independent by design.
        self.ensure_prepared(vm)?;
        let Some(parent) = vm.egress_socket().parent() else {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "egress endpoint has no host directory",
            ));
        };
        if !parent.is_dir() {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "egress endpoint directory is missing",
            ));
        }
        Ok(())
    }
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl fmt::Debug for DevProcessBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevProcessBackend")
            .field("name", &DEV_BACKEND_NAME)
            .field("root", &"<host-only>")
            .finish()
    }
}

/// Provisions the overlay + egress layout every backend shares.
///
/// The base mount is recorded read-only on the handle and is not created or
/// touched here; only the upper directory the guest writes into is made.
///
/// # Errors
///
/// Returns [`Error::MicroVmBackendError`] when the contract is not
/// propose-only or the overlay directory cannot be created.
pub fn prepare_overlay_handle(
    root: &Path,
    backend: &'static str,
    contract: &SandboxBoundaryContract,
    mounts: &SandboxMountTable,
) -> Result<MicroVmHandle> {
    if contract.links_write_imports() || !contract.has_proposal_delta_channel() {
        return Err(backend_error(backend, "guest contract is not propose-only"));
    }

    ensure_private_scratch_root(root, backend)?;

    let base_root = mounts.resolve_host_path(&SandboxVirtualPath::try_new(SANDBOX_WORKSPACE_ROOT)?);
    let vm_id = EntityId::now().to_hex();
    let vm_root = root.join(&vm_id);
    let overlay_upper = vm_root.join("upper");
    fs::create_dir_all(&overlay_upper)
        .map_err(|error| backend_error(backend, overlay_io_detail("upper", &error)))?;

    MicroVmHandle::new(
        vm_id,
        contract.tier(),
        base_root,
        overlay_upper,
        vm_root.join("egress.sock"),
    )
}

fn ensure_private_scratch_root(root: &Path, backend: &'static str) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_scratch_root(root, backend, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|error| {
                backend_error(backend, scratch_root_io_detail(root, "create", &error))
            })?;
            let metadata = fs::symlink_metadata(root).map_err(|error| {
                backend_error(backend, scratch_root_io_detail(root, "inspect", &error))
            })?;
            validate_scratch_root(root, backend, &metadata)?;
        }
        Err(error) => {
            return Err(backend_error(
                backend,
                scratch_root_io_detail(root, "inspect", &error),
            ));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|error| {
            backend_error(backend, scratch_root_io_detail(root, "chmod 0700", &error))
        })?;
    }

    Ok(())
}

fn validate_scratch_root(
    root: &Path,
    backend: &'static str,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(backend_error(
            backend,
            format!("scratch root `{}` is a symlink", root.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(backend_error(
            backend,
            format!("scratch root `{}` is not a directory", root.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let actual_uid = metadata.uid();
        // SAFETY: `geteuid` has no preconditions and only reads the process's
        // effective user identity; it dereferences no caller-provided pointer.
        let expected_uid = unsafe { libc::geteuid() };
        if actual_uid != expected_uid {
            return Err(backend_error(
                backend,
                format!(
                    "scratch root `{}` has unexpected ownership: expected owner uid {expected_uid}, actual owner uid {actual_uid}",
                    root.display()
                ),
            ));
        }
    }
    Ok(())
}

fn scratch_root_io_detail(root: &Path, operation: &str, error: &std::io::Error) -> String {
    format!(
        "scratch root `{}` {operation} failed: {}",
        root.display(),
        error.kind()
    )
}

/// Maximum bytes accepted from one overlay file during proposal export.
const MAX_OVERLAY_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum aggregate bytes accepted from one overlay during proposal export.
const MAX_OVERLAY_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum regular-file count accepted from one overlay during proposal export.
const MAX_OVERLAY_FILES: usize = 8_192;
/// Maximum directory count accepted below one overlay upper root.
const MAX_OVERLAY_DIRECTORIES: usize = 8_192;
/// Maximum directory depth below the overlay upper root.
const MAX_OVERLAY_DEPTH: usize = 64;

#[derive(Default)]
struct OverlayWalkBounds {
    total_bytes: u64,
    file_count: usize,
    directory_count: usize,
}

/// Diffs an overlay upper directory into write proposals.
///
/// Backends share this so the "writes are proposals" shape is identical across
/// the dev and isolating lanes. The base mount is never opened here.
///
/// # Errors
///
/// Returns [`Error::MicroVmOverlayError`] when the overlay root is missing or
/// invalid, an entry vanishes during traversal, a resource bound is exceeded,
/// or an entry has a non-UTF-8 name, is a symlink, or is not a plain file.
pub fn collect_overlay_writes(
    upper_root: &Path,
    mount: SandboxMount,
) -> Result<Vec<SandboxProposalWrite>> {
    let root_metadata = fs::symlink_metadata(upper_root).map_err(|error| {
        overlay_error(format!(
            "overlay root `{}` is unavailable: {}",
            upper_root.display(),
            error.kind()
        ))
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(overlay_error(format!(
            "overlay root `{}` is a symlink",
            upper_root.display()
        )));
    }
    if !root_metadata.is_dir() {
        return Err(overlay_error(format!(
            "overlay root `{}` is not a directory",
            upper_root.display()
        )));
    }

    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut bounds = OverlayWalkBounds::default();
    let mut stack = vec![(upper_root.to_path_buf(), String::new(), 0_usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        walk_overlay_dir(
            &dir,
            &prefix,
            depth,
            mount,
            &mut files,
            &mut stack,
            &mut bounds,
        )?;
    }

    let mut writes = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        let virtual_path = SandboxVirtualPath::try_new(&path)?;
        writes.push(SandboxProposalWrite::FileWrite(
            SandboxFileWriteProposal::new(virtual_path, bytes),
        ));
    }
    Ok(writes)
}

fn walk_overlay_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    mount: SandboxMount,
    files: &mut BTreeMap<String, Vec<u8>>,
    stack: &mut Vec<(PathBuf, String, usize)>,
    bounds: &mut OverlayWalkBounds,
) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|error| {
        overlay_error(format!(
            "overlay directory `{}` disappeared or cannot be read: {}",
            dir.display(),
            error.kind()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let entry_path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| overlay_error("overlay entry name is not utf-8"))?;
        let metadata = fs::symlink_metadata(&entry_path)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        if metadata.is_symlink() {
            return Err(overlay_error(format!(
                "overlay entry `{name}` is a symlink"
            )));
        }

        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            let child_depth = depth + 1;
            if child_depth > MAX_OVERLAY_DEPTH {
                return Err(overlay_error(format!(
                    "overlay depth bound {MAX_OVERLAY_DEPTH} exceeded at `{relative}`"
                )));
            }
            let next_directory_count = bounds.directory_count.checked_add(1).ok_or_else(|| {
                overlay_error(format!(
                    "overlay directory count bound {MAX_OVERLAY_DIRECTORIES} exceeded at `{relative}`"
                ))
            })?;
            if next_directory_count > MAX_OVERLAY_DIRECTORIES {
                return Err(overlay_error(format!(
                    "overlay directory count bound {MAX_OVERLAY_DIRECTORIES} exceeded at `{relative}`"
                )));
            }
            bounds.directory_count = next_directory_count;
            stack.push((entry_path, relative, child_depth));
            continue;
        }
        if !metadata.is_file() {
            return Err(overlay_error(format!(
                "overlay entry `{relative}` is not a plain file"
            )));
        }

        let file_bytes = metadata.len();
        if file_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}` ({file_bytes} bytes)"
            )));
        }
        if bounds.file_count >= MAX_OVERLAY_FILES {
            return Err(overlay_error(format!(
                "overlay file count bound {MAX_OVERLAY_FILES} exceeded at `{relative}`"
            )));
        }
        let next_total = bounds.total_bytes.checked_add(file_bytes).ok_or_else(|| {
            overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}`"
            ))
        })?;
        if next_total > MAX_OVERLAY_TOTAL_BYTES {
            return Err(overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}` ({next_total} bytes)"
            )));
        }

        let remaining_total = MAX_OVERLAY_TOTAL_BYTES - bounds.total_bytes;
        let read_limit = MAX_OVERLAY_FILE_BYTES.min(remaining_total);
        let file = fs::File::open(&entry_path)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file.take(read_limit + 1), &mut bytes)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let actual_bytes = u64::try_from(bytes.len()).map_err(|_| {
            overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}`"
            ))
        })?;
        if actual_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}`"
            )));
        }
        let actual_total = bounds.total_bytes + actual_bytes;
        if actual_total > MAX_OVERLAY_TOTAL_BYTES {
            return Err(overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}` ({actual_total} bytes)"
            )));
        }

        bounds.file_count += 1;
        bounds.total_bytes = actual_total;
        files.insert(format!("{}/{relative}", mount.root()), bytes);
    }
    Ok(())
}

/// Parses the egress destination a guest paired with its credential handle.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimBody`] when the call carries no usable
/// destination — an unaddressed credential call is refused, never resolved.
pub fn egress_destination_from_args(args: &Value) -> Result<CredentialDestination> {
    let Value::Map(entries) = args else {
        return Err(Error::InvalidClaimBody(
            "sandbox credential call args must be a map",
        ));
    };
    let scheme = abi_str(entries, SANDBOX_EGRESS_ABI_KEY_SCHEME).ok_or(Error::InvalidClaimBody(
        "sandbox credential call must name a destination scheme",
    ))?;
    let host = abi_str(entries, SANDBOX_EGRESS_ABI_KEY_HOST).ok_or(Error::InvalidClaimBody(
        "sandbox credential call must name a destination host",
    ))?;
    CredentialDestination::new(scheme, host)
}

fn abi_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}

fn overlay_io_detail(class: &str, error: &std::io::Error) -> String {
    format!("overlay {class} io failed: {}", error.kind())
}

fn overlay_error(detail: impl Into<String>) -> Error {
    Error::MicroVmOverlayError {
        detail: detail.into(),
    }
}

fn backend_error(backend: &'static str, detail: impl Into<String>) -> Error {
    Error::MicroVmBackendError {
        backend,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    fn destination(scheme: &str, host: &str) -> CredentialDestination {
        CredentialDestination::new(scheme, host).expect("destination")
    }

    fn test_mounts(root: &Path) -> SandboxMountTable {
        SandboxMountTable::new(
            root.join("base/workspace"),
            root.join("base/uploads"),
            root.join("base/outputs"),
            root.join("base/skills"),
        )
    }

    #[test]
    fn code_sandbox_microvm_overlay_rejects_directory_count_breach() {
        const EXPECTED_DIRECTORY_BOUND: usize = 8_192;

        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..=EXPECTED_DIRECTORY_BOUND {
            fs::create_dir(dir.path().join(format!("d{index}"))).expect("overlay directory");
        }

        let result = collect_overlay_writes(dir.path(), SandboxMount::Workspace);
        assert!(
            result.is_err(),
            "a broad tree of empty directories must be bounded"
        );
        let error = result.err().expect("directory count refusal");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(
            error
                .to_string()
                .contains(&format!("directory count bound {EXPECTED_DIRECTORY_BOUND}")),
            "the refusal must name the directory bound: {error}"
        );
    }

    #[test]
    fn code_sandbox_microvm_read_file_bounds_base_mount_bytes() {
        struct UnusedResolver;

        impl CredentialResolver for UnusedResolver {
            fn resolve_for(
                &self,
                _handle: &SandboxCredentialHandle,
                _dest: &CredentialDestination,
            ) -> Result<Vec<u8>> {
                Err(backend_error("test-resolver", "unused resolver"))
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("base/workspace");
        fs::create_dir_all(&workspace).expect("base workspace");
        fs::write(workspace.join("small.bin"), b"small base file").expect("small base file");
        let oversized = workspace.join("oversized.bin");
        let file = fs::File::create(&oversized).expect("create sparse base file");
        file.set_len(64 * 1024 * 1024 + 1)
            .expect("size sparse base file");

        let backend: Box<dyn MicroVmBackend> =
            Box::new(DevProcessBackend::new(dir.path().join("vm")));
        let adapter = MicroVmSandboxAdapter::new(
            SandboxGuestTier::Foreign,
            test_mounts(dir.path()),
            backend,
            Arc::new(UnusedResolver),
            CredentialAllowlist::new(),
        )
        .expect("adapter");

        let small_path = SandboxVirtualPath::try_new("/mnt/workspace/small.bin").expect("path");
        let small = adapter
            .read_file(SandboxReadFile::new(small_path))
            .expect("file under the bound");
        assert_eq!(small.bytes, b"small base file");

        let oversized_path =
            SandboxVirtualPath::try_new("/mnt/workspace/oversized.bin").expect("path");
        let result = adapter.read_file(SandboxReadFile::new(oversized_path));
        assert!(
            result.is_err(),
            "a base-mount file above the byte bound must be refused"
        );
        let error = result.err().expect("oversized base-mount refusal");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("file byte bound"));
        assert!(error.to_string().contains("oversized.bin"));
    }

    #[cfg(unix)]
    #[test]
    fn code_sandbox_microvm_prepare_accepts_self_owned_existing_scratch_root() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("scratch");
        fs::create_dir(&root).expect("pre-existing scratch root");
        let expected_uid = fs::symlink_metadata(dir.path())
            .expect("tempdir metadata")
            .uid();
        assert_eq!(
            fs::symlink_metadata(&root).expect("scratch metadata").uid(),
            expected_uid
        );

        let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
        let handle =
            prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
                .expect("self-owned pre-existing scratch root");
        assert!(handle.overlay_upper().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn code_sandbox_microvm_validate_refuses_non_self_owned_scratch_root() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let expected_uid = fs::symlink_metadata(dir.path())
            .expect("tempdir metadata")
            .uid();
        let (foreign_root, foreign_metadata) = dir
            .path()
            .ancestors()
            .skip(1)
            .find_map(|path| {
                let metadata = fs::symlink_metadata(path).ok()?;
                (metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() != expected_uid)
                    .then(|| (path.to_path_buf(), metadata))
            })
            .expect("a non-self-owned ancestor for the ownership refusal test");
        let actual_uid = foreign_metadata.uid();

        let error = validate_scratch_root(&foreign_root, DEV_BACKEND_NAME, &foreign_metadata)
            .expect_err("a non-self-owned scratch root must be refused");
        assert_eq!(error.kind(), ErrorKind::MicroVmBackendError);
        assert!(
            error
                .to_string()
                .contains(&format!("expected owner uid {expected_uid}"))
        );
        assert!(
            error
                .to_string()
                .contains(&format!("actual owner uid {actual_uid}"))
        );
        assert!(
            error
                .to_string()
                .contains(&foreign_root.display().to_string())
        );
    }

    #[test]
    fn code_sandbox_microvm_overlay_rejects_oversized_single_file_before_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let oversized = dir.path().join("oversized.bin");
        let file = fs::File::create(&oversized).expect("create sparse file");
        file.set_len(MAX_OVERLAY_FILE_BYTES + 1)
            .expect("size sparse file");

        let error = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
            .expect_err("oversized overlay file must be rejected");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("file byte bound"));
        assert!(error.to_string().contains("oversized.bin"));
    }

    #[test]
    fn code_sandbox_microvm_overlay_rejects_aggregate_byte_breach() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("next.bin"), b"x").expect("overlay file");
        let mut files = BTreeMap::new();
        let mut stack = Vec::new();
        let mut bounds = OverlayWalkBounds {
            total_bytes: MAX_OVERLAY_TOTAL_BYTES,
            file_count: 1,
            directory_count: 0,
        };

        let error = walk_overlay_dir(
            dir.path(),
            "",
            0,
            SandboxMount::Workspace,
            &mut files,
            &mut stack,
            &mut bounds,
        )
        .expect_err("aggregate byte bound must be enforced before reading");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("aggregate byte bound"));
        assert!(error.to_string().contains("next.bin"));
    }

    #[test]
    fn code_sandbox_microvm_overlay_rejects_file_count_breach() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("next.bin"), b"x").expect("overlay file");
        let mut files = BTreeMap::new();
        let mut stack = Vec::new();
        let mut bounds = OverlayWalkBounds {
            total_bytes: 0,
            file_count: MAX_OVERLAY_FILES,
            directory_count: 0,
        };

        let error = walk_overlay_dir(
            dir.path(),
            "",
            0,
            SandboxMount::Workspace,
            &mut files,
            &mut stack,
            &mut bounds,
        )
        .expect_err("file count bound must be enforced before reading");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("file count bound"));
        assert!(error.to_string().contains("next.bin"));
    }

    #[test]
    fn code_sandbox_microvm_overlay_rejects_over_depth_descent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nested = dir.path().to_path_buf();
        for index in 0..=MAX_OVERLAY_DEPTH {
            nested.push(format!("d{index}"));
        }
        fs::create_dir_all(&nested).expect("deep overlay tree");

        let error = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
            .expect_err("over-depth overlay tree must be rejected");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("depth bound"));
    }

    #[test]
    fn code_sandbox_microvm_overlay_small_multifile_parity() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("notes")).expect("nested dir");
        fs::write(dir.path().join("result.txt"), b"guest output").expect("overlay file");
        fs::write(dir.path().join("notes/deep.txt"), b"nested output").expect("overlay file");

        let writes = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
            .expect("small overlay collection");
        let collected = writes
            .into_iter()
            .map(|write| match write {
                SandboxProposalWrite::FileWrite(write) => {
                    (write.path.as_str().to_owned(), write.bytes)
                }
                SandboxProposalWrite::ClaimCandidate(_) => unreachable!("file writes only"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            collected,
            vec![
                (
                    "/mnt/workspace/notes/deep.txt".to_owned(),
                    b"nested output".to_vec(),
                ),
                (
                    "/mnt/workspace/result.txt".to_owned(),
                    b"guest output".to_vec(),
                ),
            ]
        );
    }

    #[test]
    fn code_sandbox_microvm_overlay_nested_directory_disappearance_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("nested dir");
        let mut files = BTreeMap::new();
        let mut stack = Vec::new();
        let mut bounds = OverlayWalkBounds::default();
        walk_overlay_dir(
            dir.path(),
            "",
            0,
            SandboxMount::Workspace,
            &mut files,
            &mut stack,
            &mut bounds,
        )
        .expect("discover nested dir");
        fs::remove_dir(&nested).expect("remove nested dir between walk steps");
        let (nested_path, prefix, depth) = stack.pop().expect("queued nested dir");

        let error = walk_overlay_dir(
            &nested_path,
            &prefix,
            depth,
            SandboxMount::Workspace,
            &mut files,
            &mut stack,
            &mut bounds,
        )
        .expect_err("vanished nested dir must fail closed");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(error.to_string().contains("disappeared or cannot be read"));
    }

    #[test]
    fn code_sandbox_microvm_prepare_creates_private_scratch_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("scratch");
        let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
        let handle =
            prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
                .expect("prepare overlay");
        assert!(handle.overlay_upper().is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::symlink_metadata(&root)
                .expect("scratch metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn code_sandbox_microvm_prepare_refuses_symlinked_scratch_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        let root = dir.path().join("scratch");
        fs::create_dir(&target).expect("target dir");
        std::os::unix::fs::symlink(&target, &root).expect("scratch symlink");
        let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);

        let error =
            prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
                .expect_err("symlinked scratch root must be rejected");
        assert_eq!(error.kind(), ErrorKind::MicroVmBackendError);
        assert!(error.to_string().contains("symlink"));
    }

    #[test]
    fn code_sandbox_microvm_destination_matching_respects_label_boundaries() {
        let allowed = destination("https", "example.com");
        assert!(allowed.matches(&destination("https", "example.com")));
        assert!(allowed.matches(&destination("https", "api.example.com")));
        assert!(allowed.matches(&destination("HTTPS", "API.Example.com.")));
        assert!(!allowed.matches(&destination("https", "notexample.com")));
        assert!(!allowed.matches(&destination("http", "example.com")));
        assert!(!allowed.matches(&destination("https", "example.com.evil.test")));

        assert!(CredentialDestination::new("", "example.com").is_err());
        assert!(CredentialDestination::new("https", "").is_err());
        assert!(CredentialDestination::new("https", "example.com/path").is_err());
        assert!(CredentialDestination::new("ht tps", "example.com").is_err());
    }

    #[test]
    fn code_sandbox_microvm_allowlist_defaults_to_deny() {
        let bound = SandboxCredentialHandle::new("cred.bound").expect("handle");
        let unbound = SandboxCredentialHandle::new("cred.unbound").expect("handle");
        let mut allowlist = CredentialAllowlist::new();
        allowlist.allow(&bound, destination("https", "example.com"));

        assert!(allowlist.permits(&bound, &destination("https", "api.example.com")));
        assert!(!allowlist.permits(&bound, &destination("https", "evil.test")));
        assert!(!allowlist.permits(&unbound, &destination("https", "example.com")));
    }

    #[test]
    fn code_sandbox_microvm_first_party_tier_takes_no_backend() {
        let selected =
            select_backend_for_tier(SandboxGuestTier::FirstPartyDreamer).expect("selection");
        assert!(selected.is_none(), "first-party code stays in-process");
    }

    #[test]
    fn code_sandbox_microvm_isolating_tiers_never_fall_through_silently() {
        for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
            match select_backend_for_tier(tier) {
                Ok(selected) => {
                    let backend = selected.expect("isolating tier requires a backend");
                    assert!(
                        dev_backend_compiled() || firecracker_backend_compiled(),
                        "a backend was returned without one being compiled in"
                    );
                    assert!(!backend.name().is_empty());
                }
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::MicroVmBackendUnavailable);
                }
            }
        }

        // The release fail-closed shape, asserted independently of this build's
        // cfg: the refusal is typed and names the tier that needed isolation.
        let refusal = backend_unavailable(SandboxGuestTier::Foreign);
        assert_eq!(refusal.kind(), ErrorKind::MicroVmBackendUnavailable);
        assert!(refusal.to_string().contains("foreign"));
    }

    #[test]
    fn code_sandbox_microvm_budget_must_bound_every_axis() {
        assert!(ExecutionBudget::new(5, 128, 32).is_bounded());
        assert!(!ExecutionBudget::new(0, 128, 32).is_bounded());
        assert!(!ExecutionBudget::new(5, 0, 32).is_bounded());
        assert!(!ExecutionBudget::new(5, 128, 0).is_bounded());
    }
}
