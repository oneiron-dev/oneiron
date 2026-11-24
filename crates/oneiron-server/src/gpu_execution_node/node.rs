//! The execution node (pass 33, `33-exec-node/DESIGN.md` sections 5.2, 7.1,
//! 7.3 and 7.9): this machine's own answer to "may this issuer start work
//! here now", read fresh from its `[execution_node]` file, its controls at
//! the box, its GPU slot table and its own authority fold.
//!
//! - [`ExecutionNode::gate`] is the check every job stream passes before its
//!   request is answered (section 7.1, "who may send what"): the peer is
//!   proven for the protocol now, and it is one of the node's `issuers`; a
//!   request that admits work (`Reserve`, `Submit`) also needs this node's
//!   own job grant live in its own fold. The issuer's job grant and its
//!   standing are part of the proof: a removed machine, or one whose grant
//!   ended, is never proven.
//! - [`ExecutionNode::controls`] are the local controls: enabled (the file,
//!   and `disable` at the box), paused (`pause <why>` at the box, handed to
//!   the GPU slot table's pause on each tick and each `Availability`) and
//!   drained (the GPU slot table's drain, cleared only by `resume` at the
//!   box).
//! - [`ExecutionNode::admit_pin`] is the template check of reserve step 5.
//! - [`ExecutionNode::authority_tick`] reads the node's own fold on every
//!   mesh tick and hands a withdrawn grant or an ended standing to the
//!   node's keys (EN-4 A: a revoke stops what it authorised; an expiry does
//!   not).
//!
//! Each request and each tick decides on one snapshot of the file and its
//! markers ([`NodeSnapshot`]), so no answer mixes two versions of the file.
//!
//! The keys themselves (the journal, `Reserve`, `Release`, `Submit`, the
//! launch commit) are row R3a's, behind [`NodeKeys`]. Until a journal is
//! attached, the node answers `Node` and `Availability` and refuses every
//! request that names a key as `NotEnabled`, writing nothing.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use oneiron::authority::PeerMachine;
use oneiron::{EntityId, Vault};

use super::node_settings::{
    EXECUTION_NODE_FILE_DEFAULT, EXECUTION_NODE_FILE_ENV, ExecutionNodeSettings,
    STAGING_LIMIT_SECS_DEFAULT,
};
use super::slots::GpuSlotTable;
use super::wire::{
    JOB_ALPN, JobAnswer, JobRefusal, JobReserve, NodeAnswer, SignedJobSubmit, WorkloadPin,
};
use super::{GpuAvailability, GpuDiskReading};

/// Where Linux names this boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The suffix of the marker `pause <why>` writes beside the node's file
/// (`<file>.paused`); its first line is why.
pub const PAUSED_MARKER_EXTENSION: &str = "paused";

/// The suffix of the marker `disable` writes beside the node's file
/// (`<file>.disabled`); `disable --stop` writes [`DISABLED_STOP_LINE`] as
/// its first line.
pub const DISABLED_MARKER_EXTENSION: &str = "disabled";

/// The first line of the disabled marker when the node also stops every
/// job it runs.
pub const DISABLED_STOP_LINE: &str = "stop";

/// The node's file, from the server's configuration, else the environment,
/// else [`EXECUTION_NODE_FILE_DEFAULT`].
#[must_use]
pub fn execution_node_file(configured: Option<&Path>) -> PathBuf {
    configured.map_or_else(
        || {
            std::env::var_os(EXECUTION_NODE_FILE_ENV)
                .filter(|value| !value.is_empty())
                .map_or_else(|| PathBuf::from(EXECUTION_NODE_FILE_DEFAULT), PathBuf::from)
        },
        Path::to_path_buf,
    )
}

/// The marker beside `file` named `<file name>.<suffix>`: the whole file name
/// stays, so a marker never names the file itself.
#[must_use]
pub fn marker_beside(file: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(file.as_os_str());
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// The node's local controls, read at one moment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeControls {
    /// The file enables the node and no `disable` at the box stands.
    pub enabled: bool,
    /// Why the node takes no new work while paused at the box.
    pub paused: Option<String>,
    /// Why the node takes no new work until a person clears its drain.
    pub drained: Option<String>,
    /// `disable --stop` stands: every job the node runs is stopped.
    pub stop_requested: bool,
}

impl NodeControls {
    /// The refusal reason when the node takes no new work now.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        if !self.enabled {
            return Some("node_disabled".to_owned());
        }
        if let Some(why) = &self.paused {
            return Some(format!("node_paused: {why}"));
        }
        if let Some(why) = &self.drained {
            return Some(format!("node_drained: {why}"));
        }
        None
    }
}

/// The node's file and its controls, read at one moment: each request and
/// each tick decides on one snapshot.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    /// The file: `Ok(None)` when there is none, `Err` when it does not read
    /// or validate.
    pub settings: Result<Option<ExecutionNodeSettings>, String>,
    pub controls: NodeControls,
}

impl NodeSnapshot {
    /// The file's settings, when it reads and validates.
    #[must_use]
    pub fn settings(&self) -> Option<&ExecutionNodeSettings> {
        self.settings.as_ref().ok().and_then(Option::as_ref)
    }
}

/// Why the node's own fold no longer authorises work for an issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityEnded {
    /// This node's own job grant is not live in its fold.
    OwnGrant,
    /// The issuer's job grant or standing is not live in this node's fold.
    IssuerStanding { issuer: EntityId },
}

impl AuthorityEnded {
    /// The reason a revoked key carries.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::OwnGrant => "own_grant_ended".to_owned(),
            Self::IssuerStanding { issuer } => {
                format!("issuer_standing_ended: {}", issuer.to_hex())
            }
        }
    }

    fn refusal(&self) -> JobRefusal {
        match self {
            Self::OwnGrant => JobRefusal::OwnGrantEnded,
            Self::IssuerStanding { .. } => JobRefusal::IssuerStandingEnded,
        }
    }
}

/// What a job request asks of the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAsk {
    /// A key the node already holds (`oneiron/job-status/1`): answered while
    /// the node's file names the asker as an issuer, enabled or not, so the
    /// receipts of the jobs a `disable` stopped stay collectable.
    Status,
    /// `Node`: what the node offers, answered to an issuer the file names
    /// while the node is disabled too (it then says so).
    Offer,
    /// `Availability` or `Release`: the node must be enabled.
    Read,
    /// `Reserve` or `Submit`, after which work may follow: the node must be
    /// enabled, and its own job grant live in its own fold.
    Admit,
}

/// The node's keys: the journal, the key states, admission and the launch
/// commit (row R3a's `NodeJobs`). The job service hands it every request
/// that names a key, once the gate has passed; the authority tick hands it
/// a withdrawn grant or an ended standing. Every call may block on the
/// journal's disk.
pub trait NodeKeys: Send + Sync {
    /// `Reserve` from the proven issuer `peer`.
    fn reserve(&self, peer: EntityId, reserve: JobReserve) -> JobAnswer;

    /// `Release` from the proven issuer `peer`.
    fn release(&self, peer: EntityId, key: &str) -> JobAnswer;

    /// `Submit` from the proven issuer `peer`.
    fn submit(&self, peer: EntityId, signed: SignedJobSubmit) -> JobAnswer;

    /// Whether the start-up reconciliation has ended (`Node`'s `swept`).
    fn swept(&self) -> bool;

    /// The journal's epoch, lower hex; `None` while the history is lost.
    fn epoch(&self) -> Option<String>;

    /// The disk the node's live keys keep booked, in MiB.
    fn booked_disk_mib(&self) -> u64;

    /// The issuers of every key that has not ended: the tick checks each
    /// one's standing, whatever the file names now.
    fn live_issuers(&self) -> BTreeSet<EntityId>;

    /// EN-4 A: the fold no longer authorises `issuer`'s work here (`None`:
    /// no issuer's, as when this node's own grant was withdrawn). Every key
    /// of that issuer that has not ended ends: a key that has not launched
    /// closes, and a launched one is stopped as revoked with `why`.
    fn revoke_live_keys(&self, issuer: Option<EntityId>, why: &str);

    /// `disable --stop` at the box: every key that has not ended ends; a
    /// launched one is stopped.
    fn stop_live_keys(&self);
}

/// The execution node of this machine. Cloning it shares it.
#[derive(Clone)]
pub struct ExecutionNode {
    shared: Arc<NodeShared>,
}

struct NodeShared {
    file: PathBuf,
    vault: Arc<Vault>,
    slots: Arc<GpuSlotTable>,
    keys: OnceLock<Arc<dyn NodeKeys>>,
    /// What the last authority tick found withdrawn, so a change is logged
    /// once.
    last_tick: Mutex<Option<Vec<AuthorityEnded>>>,
}

impl std::fmt::Debug for ExecutionNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionNode")
            .field("file", &self.shared.file)
            .finish_non_exhaustive()
    }
}

impl ExecutionNode {
    /// The node of the machine whose vault is `vault`, configured by `file`
    /// (read fresh at every use), leasing GPUs from `slots`.
    #[must_use]
    pub fn new(file: PathBuf, vault: Arc<Vault>, slots: Arc<GpuSlotTable>) -> Self {
        Self {
            shared: Arc::new(NodeShared {
                file,
                vault,
                slots,
                keys: OnceLock::new(),
                last_tick: Mutex::new(None),
            }),
        }
    }

    /// Attaches the node's keys (row R3a's journal). Only the first attach
    /// counts; a later one is refused with the keys it brought.
    ///
    /// # Errors
    ///
    /// Keys are already attached.
    pub fn attach_keys(&self, keys: Arc<dyn NodeKeys>) -> Result<(), Arc<dyn NodeKeys>> {
        self.shared.keys.set(keys)
    }

    /// The node's keys, once attached.
    #[must_use]
    pub fn keys(&self) -> Option<&Arc<dyn NodeKeys>> {
        self.shared.keys.get()
    }

    /// The node's file.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.shared.file
    }

    /// The node's file, read and validated now: `Ok(None)` when there is
    /// none.
    ///
    /// # Errors
    ///
    /// Why the file does not read or does not validate.
    pub fn settings(&self) -> Result<Option<ExecutionNodeSettings>, String> {
        ExecutionNodeSettings::read(&self.shared.file)
    }

    /// The node's file and its controls, read now, once.
    #[must_use]
    pub fn snapshot(&self) -> NodeSnapshot {
        let settings = self.settings();
        if let Err(why) = &settings {
            tracing::warn!(%why, "the execution node's file does not read; the node runs no jobs");
        }
        let file = &self.shared.file;
        let disabled = read_marker(&marker_beside(file, DISABLED_MARKER_EXTENSION));
        let paused = read_marker(&marker_beside(file, PAUSED_MARKER_EXTENSION));
        let drained = match self.shared.slots.drained() {
            Ok(drained) => drained,
            Err(error) => Some(format!("drain_unreadable: {error}")),
        };
        let file_enabled = matches!(&settings, Ok(Some(settings)) if settings.enabled);
        let controls = NodeControls {
            enabled: file_enabled && disabled.is_none(),
            paused: paused.map(|line| line.unwrap_or_else(|| "paused".to_owned())),
            drained,
            stop_requested: disabled.flatten().as_deref() == Some(DISABLED_STOP_LINE),
        };
        NodeSnapshot { settings, controls }
    }

    /// Whether the node's file enables it now: the mesh listener serves the
    /// job protocols only when it does as the listener starts. A `disable`
    /// at the box leaves them served, so receipts stay collectable.
    #[must_use]
    pub fn serves(&self) -> bool {
        matches!(self.settings(), Ok(Some(settings)) if settings.enabled)
    }

    /// The local controls now.
    #[must_use]
    pub fn controls(&self) -> NodeControls {
        self.snapshot().controls
    }

    /// This machine's MACHINE id, once it has one.
    fn own_machine(&self) -> Option<EntityId> {
        match self.shared.vault.local_machine() {
            Ok(machine) => machine.map(|machine| machine.id),
            Err(error) => {
                tracing::warn!(%error, "the execution node cannot read its own MACHINE id");
                None
            }
        }
    }

    /// Whether `machine` holds a live grant on `alpn` in this node's own
    /// fold, by the same proof a stream from it passes: the endpoint its
    /// MACHINE row names proves that machine on `alpn` now (its grant live,
    /// its binding the key the fold trusts for it, the machine not removed).
    fn grant_live(&self, machine: EntityId, alpn: &[u8]) -> bool {
        let vault = &self.shared.vault;
        let Ok(Some(address)) = vault.mesh_machine(machine) else {
            return false;
        };
        matches!(
            vault.mesh_peer_machine(address.endpoint_key, alpn),
            Ok(PeerMachine::Proven { machine: proven, .. }) if proven == machine
        )
    }

    /// Whether this node's own fold authorises `issuer`'s new work here now:
    /// this node's own job grant, and the issuer's job grant and standing.
    ///
    /// # Errors
    ///
    /// [`AuthorityEnded`]: which of them is not live.
    pub fn authority_for(&self, issuer: EntityId) -> Result<(), AuthorityEnded> {
        let own_live = self
            .own_machine()
            .is_some_and(|own| self.grant_live(own, JOB_ALPN));
        if !own_live {
            return Err(AuthorityEnded::OwnGrant);
        }
        if !self.grant_live(issuer, JOB_ALPN) {
            return Err(AuthorityEnded::IssuerStanding { issuer });
        }
        Ok(())
    }

    /// Whether `machine`'s job grant was withdrawn by an act this node's
    /// fold holds (not merely expired). A read error withdraws nothing.
    fn job_grant_withdrawn(&self, machine: EntityId) -> bool {
        self.shared
            .vault
            .mesh_grant_withdrawn(machine, JOB_ALPN)
            .unwrap_or(false)
    }

    /// Design 7.3 reserve step 2, and the same check at the submit and in
    /// the launch commit: `issuer` is one of the issuers this node's file
    /// names, and the node's own fold authorises its work here now.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn issuer_live(&self, issuer: EntityId) -> Result<(), String> {
        let named = self
            .settings()
            .ok()
            .flatten()
            .is_some_and(|settings| settings.names_issuer(issuer));
        if !named {
            return Err("not_issuer".to_owned());
        }
        self.authority_for(issuer).map_err(|ended| ended.reason())
    }

    /// The check every job stream passes before its request is answered
    /// (design 7.1, "who may send what"), in this order: the peer behind
    /// `endpoint_key` is proven for `alpn` now (the proof carries its grant
    /// on `alpn` and its standing: a removed machine is never proven); the
    /// node's file reads and validates; the peer is one of the issuers it
    /// names; for [`GateAsk::Read`] and [`GateAsk::Admit`] the node is
    /// enabled; and for [`GateAsk::Admit`] this node's own job grant is live
    /// in its own fold. The request is then answered from the same snapshot.
    ///
    /// # Errors
    ///
    /// The refusal the stream is answered with.
    pub fn gate(
        &self,
        endpoint_key: [u8; 32],
        alpn: &[u8],
        ask: GateAsk,
    ) -> Result<(EntityId, NodeSnapshot), JobRefusal> {
        let peer = match self.shared.vault.mesh_peer_machine(endpoint_key, alpn) {
            Ok(PeerMachine::Proven { machine, .. }) => machine,
            _ => return Err(JobRefusal::PeerNotProven),
        };
        let snapshot = self.snapshot();
        let Some(settings) = snapshot.settings() else {
            return Err(JobRefusal::NotEnabled);
        };
        if !settings.names_issuer(peer) {
            return Err(JobRefusal::NotIssuer);
        }
        if matches!(ask, GateAsk::Read | GateAsk::Admit) && !snapshot.controls.enabled {
            return Err(JobRefusal::NotEnabled);
        }
        if ask == GateAsk::Admit {
            self.authority_for(peer).map_err(|ended| ended.refusal())?;
        }
        Ok((peer, snapshot))
    }

    /// Design 7.3 reserve step 5: the pin fits a template this node holds
    /// now, by digest, entry, scope, network, outputs, ceilings and
    /// parameters.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        match self.settings() {
            Ok(Some(settings)) => settings.admit_pin(pin),
            Ok(None) => Err("node_disabled".to_owned()),
            Err(why) => Err(format!("node_settings_unreadable: {why}")),
        }
    }

    /// The digest of the template named `template` now; `None` when this
    /// node holds no such template.
    #[must_use]
    pub fn template_digest(&self, template: &str) -> Option<String> {
        self.settings().ok().flatten()?.template_digest(template)
    }

    /// Design 7.3 reserve step 6: the payload disk's free space, less what
    /// live keys booked (`booked_mib`), covers `request_mib` plus the disk
    /// reserve, and the state directory keeps its own floor.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        let settings = match self.settings() {
            Ok(Some(settings)) => settings,
            Ok(None) => return Err("node_disabled".to_owned()),
            Err(why) => return Err(format!("node_settings_unreadable: {why}")),
        };
        let free = disk_free_bytes(&settings.work_dir)
            .map_err(|error| format!("disk_unreadable: {error}"))?;
        let needed = mib_bytes(booked_mib)
            .saturating_add(mib_bytes(request_mib))
            .saturating_add(settings.disk_reserve_bytes());
        if free < needed {
            return Err("disk_full".to_owned());
        }
        let state_free = disk_free_bytes(&settings.state_dir)
            .map_err(|error| format!("disk_unreadable: {error}"))?;
        if state_free < mib_bytes(settings.state_floor_mib) {
            return Err("state_disk_full".to_owned());
        }
        Ok(())
    }

    /// The longest staging may take before the launch, in seconds.
    #[must_use]
    pub fn staging_limit_secs(&self) -> u64 {
        self.settings()
            .ok()
            .flatten()
            .map_or(STAGING_LIMIT_SECS_DEFAULT, |settings| {
                settings.staging_limit_secs
            })
    }

    /// EM-11 = B: whether this node's own fold holds every one of `heads`,
    /// the issuer's main-log heads when it signed a submit. No heads, a
    /// malformed head or a store error hold nothing, so the launch waits
    /// and then refuses.
    #[must_use]
    pub fn folded(&self, heads: &[String]) -> bool {
        !heads.is_empty()
            && self
                .shared
                .vault
                .authority_folds_main_log_heads(heads)
                .unwrap_or(false)
    }

    /// What the node offers now (`Node`, design 7.1).
    #[must_use]
    pub fn node_answer(&self) -> NodeAnswer {
        self.node_answer_from(&self.snapshot())
    }

    /// What the node offers, as `snapshot` reads it.
    #[must_use]
    pub fn node_answer_from(&self, snapshot: &NodeSnapshot) -> NodeAnswer {
        let keys = self.keys();
        let (templates, disk_free_bytes, disk_reserve_bytes) = match snapshot.settings() {
            Some(settings) => (
                settings.template_offers().unwrap_or_else(|why| {
                    tracing::warn!(%why, "a template of the execution node does not encode");
                    Vec::new()
                }),
                disk_free_bytes(&settings.work_dir).unwrap_or(0),
                settings.disk_reserve_bytes(),
            ),
            None => (Vec::new(), 0, 0),
        };
        NodeAnswer {
            enabled: snapshot.controls.enabled,
            paused: snapshot.controls.paused.clone(),
            drained: snapshot.controls.drained.clone(),
            templates,
            disk_free_bytes,
            disk_reserved_bytes: self.booked_disk_bytes(),
            disk_reserve_bytes,
            epoch: keys.and_then(|keys| keys.epoch()),
            swept: keys.is_some_and(|keys| keys.swept()),
            boot_id: boot_id(),
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// The disk the node's live keys keep booked, in bytes.
    fn booked_disk_bytes(&self) -> u64 {
        self.keys()
            .map_or(0, |keys| mib_bytes(keys.booked_disk_mib()))
    }

    /// A fresh sample of the node's GPUs (`Availability`): a reading, not a
    /// hold.
    ///
    /// # Errors
    ///
    /// Why the driver could not be read.
    pub fn availability(&self, now_ms: u64) -> Result<GpuAvailability, String> {
        self.availability_from(&self.snapshot(), now_ms)
    }

    /// A fresh sample of the node's GPUs, as `snapshot` reads the node. The
    /// pause at the box is the slot table's pause too, so the sample shows
    /// it. The disk is the payload disk (`work_dir`) with the node's reserve
    /// and its keys' bookings, the figures a reserve is judged by, so the
    /// issuer's start gate refuses before any money is held (design 7.9).
    ///
    /// # Errors
    ///
    /// Why the driver could not be read.
    pub fn availability_from(
        &self,
        snapshot: &NodeSnapshot,
        now_ms: u64,
    ) -> Result<GpuAvailability, String> {
        self.shared
            .slots
            .set_paused(snapshot.controls.paused.clone());
        let mut availability = self
            .shared
            .slots
            .availability(now_ms)
            .map_err(|error| error.to_string())?;
        availability.disk = snapshot.settings().and_then(|settings| {
            disk_free_bytes(&settings.work_dir)
                .ok()
                .map(|free_bytes| GpuDiskReading {
                    free_bytes,
                    reserve_bytes: settings.disk_reserve_bytes(),
                    claimed_bytes: self.booked_disk_bytes(),
                })
        });
        Ok(availability)
    }

    /// One authority tick (design 7.1 and EN-4 A, every mesh tick): hands
    /// the pause at the box to the GPU slot table; then, while keys are
    /// attached, reads the node's own fold for this node's own job grant and
    /// for the standing of every issuer the file names or a live key was
    /// issued by, and hands a withdrawn grant or a removed machine to the
    /// keys, which stop the work it authorised. An expired grant stops
    /// nothing (EN-4 A). A `disable --stop` at the box stops every job. The
    /// stops run whatever the file says now, so a file turned off or broken
    /// never keeps a revoked job running. A change is logged once.
    pub fn authority_tick(&self) {
        let snapshot = self.snapshot();
        self.shared
            .slots
            .set_paused(snapshot.controls.paused.clone());
        let Some(keys) = self.keys() else {
            return;
        };
        let mut issuers = keys.live_issuers();
        if let Some(settings) = snapshot.settings() {
            issuers.extend(settings.issuers.iter().copied());
        }
        let own_withdrawn = self
            .own_machine()
            .is_some_and(|own| self.job_grant_withdrawn(own));
        let withdrawn: Vec<AuthorityEnded> = if own_withdrawn {
            vec![AuthorityEnded::OwnGrant]
        } else {
            issuers
                .into_iter()
                .filter(|issuer| self.job_grant_withdrawn(*issuer))
                .map(|issuer| AuthorityEnded::IssuerStanding { issuer })
                .collect()
        };
        self.log_tick_change(&withdrawn);
        for ended in &withdrawn {
            match ended {
                AuthorityEnded::OwnGrant => keys.revoke_live_keys(None, &ended.reason()),
                AuthorityEnded::IssuerStanding { issuer } => {
                    keys.revoke_live_keys(Some(*issuer), &ended.reason());
                }
            }
        }
        if snapshot.controls.stop_requested {
            keys.stop_live_keys();
        }
    }

    /// Logs what the tick found withdrawn when it differs from the last
    /// tick's finding.
    fn log_tick_change(&self, withdrawn: &[AuthorityEnded]) {
        let mut last = self
            .shared
            .last_tick
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.as_deref() == Some(withdrawn) {
            return;
        }
        *last = Some(withdrawn.to_vec());
        if withdrawn.is_empty() {
            tracing::info!("the execution node's own fold withdraws no job grant");
        }
        for ended in withdrawn {
            tracing::warn!(
                reason = %ended.reason(),
                "the execution node's own fold withdrew a job grant; the work it authorised stops"
            );
        }
    }
}

/// The first line of the marker at `path`: `None` when there is no marker,
/// `Some(None)` for an empty one. A marker that exists but does not read
/// still stands.
fn read_marker(path: &Path) -> Option<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(
            text.lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(str::to_owned),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(None),
    }
}

/// `mib` MiB in bytes.
fn mib_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1 << 20)
}

/// The bytes an unprivileged writer may still write on the filesystem that
/// holds `path`.
///
/// # Errors
///
/// The filesystem cannot be read.
#[cfg(unix)]
pub fn disk_free_bytes(path: &Path) -> std::io::Result<u64> {
    let stats = rustix::fs::statvfs(path)?;
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

/// The bytes an unprivileged writer may still write on the filesystem that
/// holds `path`: never known off unix.
///
/// # Errors
///
/// Always: off unix the node reads no disk.
#[cfg(not(unix))]
pub fn disk_free_bytes(_path: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::other("no disk reading off unix"))
}

/// This boot's id, empty where the system names none.
fn boot_id() -> String {
    std::fs::read_to_string(BOOT_ID_PATH)
        .map(|id| id.trim().to_owned())
        .unwrap_or_default()
}
