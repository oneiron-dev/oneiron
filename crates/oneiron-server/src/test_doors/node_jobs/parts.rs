//! The scripted admission, memory floor, signer, authority and stager.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{BoundRequirement, DevicePlacement, ScopeBound};
use oneiron::machine_signature::{MachineSignatureError, MachineSignatures};
use oneiron_contracts::fingerprint::ContentHasher;
use oneiron_organ_host::{FloorLease, FloorRefusal, MachineFloor};

use super::{ScriptedDevices, locked};
use crate::gpu_execution_node::jobs::quiet_lease::QuietLease;
use crate::gpu_execution_node::jobs::{
    AuthorityPosition, IssuerNotLive, NodeAdmission, NodeControls, NodeJobSettings, StageFailure,
    StageOrder, Stager,
};
use crate::gpu_execution_node::node_settings::DrainClearBy;
use crate::gpu_execution_node::wire::{JobRefusal, WorkloadPin};

#[derive(Debug, Clone)]
struct AdmissionState {
    controls: NodeControls,
    templates: BTreeMap<String, String>,
    require: Vec<BoundRequirement>,
    /// The template's memory ceiling, in MiB; `None`: no ceiling.
    memory_ceiling_mib: Option<u64>,
    pin_refusal: Option<String>,
    disk_free_mib: u64,
    disk_reserve_mib: u64,
    issuer_refusal: Option<String>,
    staging_limit_secs: u64,
    /// Each template's checkpoint signal, when it names one.
    signals: BTreeMap<String, String>,
    /// Session templates, by name, with their longest run in seconds.
    sessions: BTreeMap<String, u64>,
    receipt_keep_days: u64,
    readiness_every_secs: u64,
    drain_clear_by: DrainClearBy,
    /// Each template's mirror, by template name.
    mirrors: BTreeMap<String, PathBuf>,
    /// The quiet lease (row GPU-QUIET-LEASE): its marker and quiet templates.
    quiet_lease: QuietLease,
}

/// The node's configuration and fold, scripted: enabled, one template, room
/// on the disk, the issuer live. Its drain is the scripted slot table's, as
/// the node's is the GPU slot table's.
#[derive(Debug)]
pub struct ScriptedAdmission {
    state: Mutex<AdmissionState>,
    devices: Arc<ScriptedDevices>,
}

impl ScriptedAdmission {
    /// An enabled node holding `template` at `digest`, draining with
    /// `devices`.
    #[must_use]
    pub fn new(template: &str, digest: &str, devices: Arc<ScriptedDevices>) -> Arc<Self> {
        Arc::new(Self {
            devices,
            state: Mutex::new(AdmissionState {
                controls: NodeControls {
                    enabled: true,
                    ..NodeControls::default()
                },
                templates: BTreeMap::from([(template.to_owned(), digest.to_owned())]),
                require: vec![
                    BoundRequirement {
                        bound: ScopeBound::FileWall,
                        kernel: false,
                    },
                    BoundRequirement {
                        bound: ScopeBound::NetworkClosed,
                        kernel: false,
                    },
                ],
                memory_ceiling_mib: None,
                pin_refusal: None,
                disk_free_mib: 1 << 20,
                disk_reserve_mib: 0,
                issuer_refusal: None,
                staging_limit_secs: 600,
                signals: BTreeMap::new(),
                sessions: BTreeMap::new(),
                receipt_keep_days: 30,
                readiness_every_secs: NodeJobSettings::default().readiness_every_secs,
                drain_clear_by: DrainClearBy::default(),
                mirrors: BTreeMap::new(),
                quiet_lease: QuietLease::default(),
            }),
        })
    }

    /// Sets the local controls.
    pub fn set_controls(&self, controls: NodeControls) {
        locked(&self.state).controls = controls;
    }

    /// Changes a template's digest (an edit of the root-owned file).
    pub fn set_template_digest(&self, template: &str, digest: &str) {
        locked(&self.state)
            .templates
            .insert(template.to_owned(), digest.to_owned());
    }

    /// The scope bounds every template requires (default: the file wall
    /// and the closed network, as R1's file defaults them).
    pub fn set_template_requires(&self, require: Vec<BoundRequirement>) {
        locked(&self.state).require = require;
    }

    /// The templates' memory ceiling, in MiB, that a placement's host memory
    /// must stay within (`None`: none).
    pub fn set_memory_ceiling_mib(&self, ceiling_mib: Option<u64>) {
        locked(&self.state).memory_ceiling_mib = ceiling_mib;
    }

    /// The template check's refusal for every pin.
    pub fn set_pin_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).pin_refusal = refusal.map(str::to_owned);
    }

    /// The payload disk's free space and its reserve.
    pub fn set_disk(&self, free_mib: u64, reserve_mib: u64) {
        let mut state = locked(&self.state);
        state.disk_free_mib = free_mib;
        state.disk_reserve_mib = reserve_mib;
    }

    /// The issuer's grant or standing refusal, as the fold reads it.
    pub fn set_issuer_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).issuer_refusal = refusal.map(str::to_owned);
    }

    /// The staging limit, in seconds.
    pub fn set_staging_limit_secs(&self, secs: u64) {
        locked(&self.state).staging_limit_secs = secs;
    }

    /// The template names `signal` as its checkpoint notice (`None`: no
    /// signal, the notice is a no-op).
    pub fn set_template_signal(&self, template: &str, signal: Option<&str>) {
        let mut state = locked(&self.state);
        match signal {
            Some(signal) => {
                state.signals.insert(template.to_owned(), signal.to_owned());
            }
            None => {
                state.signals.remove(template);
            }
        }
    }

    /// Makes `template` a session template whose run lasts at most
    /// `max_secs` from its launch (`None`: a job template again).
    pub fn set_template_session(&self, template: &str, max_secs: Option<u64>) {
        let mut state = locked(&self.state);
        match max_secs {
            Some(secs) => {
                state.sessions.insert(template.to_owned(), secs);
            }
            None => {
                state.sessions.remove(template);
            }
        }
    }

    /// Sets `jobs.receipts.keep_days`.
    pub fn set_receipt_keep_days(&self, days: u64) {
        locked(&self.state).receipt_keep_days = days;
    }

    /// Sets `jobs.readiness.every_secs`.
    pub fn set_readiness_every_secs(&self, secs: u64) {
        locked(&self.state).readiness_every_secs = secs;
    }

    /// Sets `machines.drain.clear_by`.
    pub fn set_drain_clear_by(&self, clear_by: DrainClearBy) {
        locked(&self.state).drain_clear_by = clear_by;
    }

    /// Names `mirror` as `template`'s mirror, for the readiness check.
    pub fn set_template_mirror(&self, template: &str, mirror: PathBuf) {
        locked(&self.state)
            .mirrors
            .insert(template.to_owned(), mirror);
    }

    /// Sets the quiet lease: the host's marker and the quiet templates.
    pub fn set_quiet_lease(&self, lease: QuietLease) {
        locked(&self.state).quiet_lease = lease;
    }
}

impl NodeAdmission for ScriptedAdmission {
    fn controls(&self) -> NodeControls {
        let mut controls = locked(&self.state).controls.clone();
        if controls.drained.is_none() {
            controls.drained = self.devices.drained();
        }
        controls
    }

    fn issuer_live(&self, _issuer: EntityId) -> Result<(), IssuerNotLive> {
        match locked(&self.state).issuer_refusal.clone() {
            None => Ok(()),
            Some(reason) => Err(IssuerNotLive {
                refusal: JobRefusal::IssuerStandingEnded,
                reason,
            }),
        }
    }

    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        let state = locked(&self.state);
        if let Some(refusal) = &state.pin_refusal {
            return Err(refusal.clone());
        }
        match state.templates.get(&pin.template) {
            Some(digest) if *digest == pin.template_digest => Ok(()),
            Some(_) => Err("template_digest_changed".to_owned()),
            None => Err("template_unknown".to_owned()),
        }
    }

    fn template_digest(&self, template: &str) -> Option<String> {
        locked(&self.state).templates.get(template).cloned()
    }

    fn admit_placement(
        &self,
        _pin: &WorkloadPin,
        placement: &DevicePlacement,
        _held_mib: u64,
    ) -> Result<(), String> {
        match locked(&self.state).memory_ceiling_mib {
            Some(ceiling) if placement.host_memory_mib > ceiling => {
                Err("request_above_ceiling: host_memory_mib".to_owned())
            }
            _ => Ok(()),
        }
    }

    fn template_requires(&self, template: &str) -> Option<Vec<BoundRequirement>> {
        let state = locked(&self.state);
        state
            .templates
            .contains_key(template)
            .then(|| state.require.clone())
    }

    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        let state = locked(&self.state);
        let needed = booked_mib
            .saturating_add(request_mib)
            .saturating_add(state.disk_reserve_mib);
        (state.disk_free_mib >= needed)
            .then_some(())
            .ok_or_else(|| "disk_short".to_owned())
    }

    fn job_settings(&self) -> NodeJobSettings {
        let state = locked(&self.state);
        NodeJobSettings {
            staging_limit_secs: state.staging_limit_secs,
            receipt_keep_days: state.receipt_keep_days,
            readiness_every_secs: state.readiness_every_secs,
            drain_clear_by: state.drain_clear_by,
            ..NodeJobSettings::default()
        }
    }

    fn template_signal(&self, template: &str) -> Option<String> {
        locked(&self.state).signals.get(template).cloned()
    }

    fn template_session_max_secs(&self, template: &str) -> Option<u64> {
        locked(&self.state).sessions.get(template).copied()
    }

    fn template_mirrors(&self) -> Vec<(String, PathBuf)> {
        locked(&self.state)
            .mirrors
            .iter()
            .map(|(template, mirror)| (template.clone(), mirror.clone()))
            .collect()
    }

    fn quiet_lease(&self) -> QuietLease {
        locked(&self.state).quiet_lease.clone()
    }
}

/// The machine's memory line, scripted: `total` bytes, no waiting.
#[derive(Debug)]
pub struct ScriptedFloor {
    total: u64,
    leased: Arc<AtomicU64>,
}

impl ScriptedFloor {
    /// A floor of `total_mib`.
    #[must_use]
    pub fn new(total_mib: u64) -> Arc<Self> {
        Arc::new(Self {
            total: total_mib.saturating_mul(1024 * 1024),
            leased: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The bytes leased now.
    #[must_use]
    pub fn leased_bytes(&self) -> u64 {
        self.leased.load(Ordering::SeqCst)
    }
}

struct ScriptedFloorLease {
    bytes: u64,
    leased: Arc<AtomicU64>,
}

impl Drop for ScriptedFloorLease {
    fn drop(&mut self) {
        self.leased.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl FloorLease for ScriptedFloorLease {
    fn grow(
        &mut self,
        more: u64,
        _deadline: Instant,
        _stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal> {
        self.bytes += more;
        self.leased.fetch_add(more, Ordering::SeqCst);
        Ok(())
    }

    fn materialized(&mut self, _reserved: u64, _actual: u64) {}

    fn shrink(&mut self, bytes: u64) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.leased.fetch_sub(bytes, Ordering::SeqCst);
    }

    fn grow_untimed(&mut self, more: u64, stopped: &dyn Fn() -> bool) -> Result<(), FloorRefusal> {
        self.grow(more, Instant::now(), stopped)
    }
}

impl MachineFloor for ScriptedFloor {
    fn check_irreducible_peak(&self, _pinned: u64, bytes: u64) -> Result<(), FloorRefusal> {
        (bytes <= self.total)
            .then_some(())
            .ok_or(FloorRefusal::Floor {
                needed: bytes,
                available: self.total,
            })
    }

    fn try_lease(&self, bytes: u64) -> Result<Option<Box<dyn FloorLease>>, FloorRefusal> {
        let leased = self.leased.load(Ordering::SeqCst);
        if leased.saturating_add(bytes) > self.total {
            return Ok(None);
        }
        self.leased.fetch_add(bytes, Ordering::SeqCst);
        Ok(Some(Box::new(ScriptedFloorLease {
            bytes,
            leased: Arc::clone(&self.leased),
        })))
    }

    fn track_allocated(&self, bytes: u64) -> Box<dyn FloorLease> {
        self.leased.fetch_add(bytes, Ordering::SeqCst);
        Box::new(ScriptedFloorLease {
            bytes,
            leased: Arc::clone(&self.leased),
        })
    }

    fn lease(
        &self,
        bytes: u64,
        _deadline: Instant,
        _stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn FloorLease>, FloorRefusal> {
        self.try_lease(bytes)?.ok_or(FloorRefusal::Deadline)
    }
}

/// A machine-key signer for tests: a content hash of the machine, the
/// domain and the message, so a signature by one machine never verifies as
/// another's.
#[derive(Debug, Clone, Copy)]
pub struct ScriptedSigner {
    machine: EntityId,
}

impl ScriptedSigner {
    /// The signer of `machine`.
    #[must_use]
    pub fn new(machine: EntityId) -> Arc<Self> {
        Arc::new(Self { machine })
    }

    /// The machine it signs as.
    #[must_use]
    pub fn machine(&self) -> EntityId {
        self.machine
    }

    /// The signature `machine` makes over `message` under `domain`.
    #[must_use]
    pub fn signature_of(machine: EntityId, domain: &[u8], message: &[u8]) -> [u8; 64] {
        let half = |part: u8| {
            ContentHasher::new()
                .update(b"oneiron scripted machine signer")
                .update(&[0])
                .update(machine.as_bytes())
                .update(domain)
                .update(&[0])
                .update(message)
                .update(&[part])
                .finish()
                .into_bytes()
        };
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&half(0));
        signature[32..].copy_from_slice(&half(1));
        signature
    }
}

impl MachineSignatures for ScriptedSigner {
    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(EntityId, [u8; 64]), MachineSignatureError> {
        Ok((
            self.machine,
            Self::signature_of(self.machine, domain, message),
        ))
    }

    fn verify(
        &self,
        machine: EntityId,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), MachineSignatureError> {
        (Self::signature_of(machine, domain, message) == *signature)
            .then_some(())
            .ok_or(MachineSignatureError::Mismatch { machine })
    }
}

/// The node's fold position, scripted: whether it holds the submit's heads.
#[derive(Debug, Default)]
pub struct ScriptedAuthority {
    stale: AtomicBool,
}

impl ScriptedAuthority {
    /// A fold that holds every position.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Whether the fold lags every submit's position.
    pub fn set_stale(&self, stale: bool) {
        self.stale.store(stale, Ordering::SeqCst);
    }
}

impl AuthorityPosition for ScriptedAuthority {
    fn folded(&self, _heads: &[String]) -> bool {
        !self.stale.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
struct StagerState {
    holding: bool,
    entered: u32,
    refusal: Option<String>,
    unstaged: Vec<(String, PathBuf)>,
}

/// Staging, scripted: completes at once, or waits in each stage until the
/// test lets it go, or refuses. It records each removal of staged code.
#[derive(Debug, Default)]
pub struct ScriptedStager {
    state: Mutex<StagerState>,
    changed: Condvar,
}

impl ScriptedStager {
    /// A stager that completes at once.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Whether each stage waits until [`Self::let_go`].
    pub fn hold(&self) {
        locked(&self.state).holding = true;
    }

    /// Lets every waiting and later stage complete.
    pub fn let_go(&self) {
        locked(&self.state).holding = false;
        self.changed.notify_all();
    }

    /// The reason every later stage refuses with.
    pub fn set_refusal(&self, refusal: Option<&str>) {
        locked(&self.state).refusal = refusal.map(str::to_owned);
    }

    /// Each `(key, payload directory)` whose staged code was removed, in
    /// call order.
    #[must_use]
    pub fn unstaged(&self) -> Vec<(String, PathBuf)> {
        locked(&self.state).unstaged.clone()
    }

    /// Waits until `count` stages have begun, up to `timeout`.
    #[must_use]
    pub fn wait_entered(&self, count: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = locked(&self.state);
        while state.entered < count {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

impl Stager for ScriptedStager {
    fn stage(&self, _order: &StageOrder, closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
        let mut state = locked(&self.state);
        state.entered += 1;
        self.changed.notify_all();
        while state.holding {
            if closed() {
                return Err(StageFailure::Closed);
            }
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(20))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if closed() {
            return Err(StageFailure::Closed);
        }
        state
            .refusal
            .clone()
            .map_or(Ok(()), |reason| Err(StageFailure::Refused(reason)))
    }

    fn unstage(&self, key: &str, payload_dir: &Path) {
        locked(&self.state)
            .unstaged
            .push((key.to_owned(), payload_dir.to_path_buf()));
    }
}
