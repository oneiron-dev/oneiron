//! What the model runtime built, for the owner-facing status route.
use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;

use oneiron::ModelId;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{BrokerIsolation, ResourceClass, SpentKind, WorkClass, WorkerStatus};
use oneiron_driver::{AdmissionSnapshot, PressureState, ResidentSource};
use serde::Serialize;

use crate::config::models::{ModelRef, ProviderConfig, ProviderKind, role_key};

/// Every provider and seat the config named, and whether each can serve.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ModelsStatus {
    /// False when the config has no `[models]` section at all.
    pub configured: bool,
    pub providers: Vec<ProviderStatus>,
    pub seats: Vec<SeatStatus>,
    /// The models the owner's other nodes offer (FIX 3229), as raw calls
    /// reach them by id, in the live status only; none when the mesh
    /// discovered none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub discovered: Vec<DiscoveredStatus>,
    /// One row per configured model worker (`[models.workers]`): its
    /// readiness, and what it last reported. Apart from the providers' and
    /// seats' availability; none when no worker is configured.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<WorkerStatus>,
    /// One row per host/device admission queue, copied from live state.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceStatus>,
    /// Sealed inference snapshot parking (V2-R3), over the vaults this
    /// process serves, in the live status only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<SnapshotStatus>,
}

/// One device queue and its memory ledger, copied without a probe.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceStatus {
    pub device: String,
    pub capacity_mib: Option<u64>,
    pub queued_foreground: u64,
    pub queued_background: u64,
    pub active_grants: u64,
    pub paused: u64,
    pub holds_mib: u64,
    pub declared_mib: Option<u64>,
    pub resident_mib: Option<u64>,
    pub class_used_mib: Option<BTreeMap<String, u64>>,
    pub rows: Vec<DeviceRowStatus>,
    pub pressure: DevicePressureStatus,
    pub executors: Vec<DeviceExecutorStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceRowStatus {
    pub worker_id: String,
    pub declared: DeviceDeclarationStatus,
    pub resident_mib: Option<u64>,
    pub resident_source: Option<&'static str>,
    pub observed_at_unix_ms: Option<u64>,
    pub class: Option<ResourceClass>,
    pub mediated: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceDeclarationStatus {
    pub weights_mib: Option<u64>,
    pub kv_mib: Option<u64>,
    pub workspace_mib: Option<u64>,
    pub load_transient_mib: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DevicePressureStatus {
    pub state: &'static str,
    pub idle_worker: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceExecutorStatus {
    pub worker_id: String,
    pub external: bool,
    pub idle: bool,
    pub load_class: Option<WorkClass>,
}

impl DeviceStatus {
    #[must_use]
    pub fn from_snapshot(snapshot: AdmissionSnapshot) -> Self {
        let pressure = match &snapshot.pressure {
            PressureState::None => DevicePressureStatus {
                state: "none",
                idle_worker: None,
            },
            PressureState::UnloadedIdle(worker) => DevicePressureStatus {
                state: "unloaded_idle",
                idle_worker: Some(worker.clone()),
            },
            PressureState::WaitingGrant => DevicePressureStatus {
                state: "waiting_grant",
                idle_worker: None,
            },
            PressureState::UnknownCapacityAdmitted => DevicePressureStatus {
                state: "unknown_capacity_admitted",
                idle_worker: None,
            },
        };
        let rows = snapshot
            .ledger
            .rows
            .into_iter()
            .map(|row| {
                let resident = row.resident;
                DeviceRowStatus {
                    worker_id: row.worker_id,
                    declared: DeviceDeclarationStatus {
                        weights_mib: row.declared.weights_mib,
                        kv_mib: row.declared.kv_mib,
                        workspace_mib: row.declared.workspace_mib,
                        load_transient_mib: row.declared.load_transient_mib,
                    },
                    resident_mib: resident.map(|report| report.resident_mib),
                    resident_source: resident.map(|report| match report.source {
                        ResidentSource::WorkerReport => "worker_report",
                        ResidentSource::DeviceQuery => "device_query",
                    }),
                    observed_at_unix_ms: resident.and_then(|report| {
                        report
                            .observed_at
                            .duration_since(UNIX_EPOCH)
                            .ok()
                            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
                    }),
                    class: row.class,
                    mediated: row.mediated,
                }
            })
            .collect();
        let loads = snapshot.loads;
        Self {
            device: snapshot.device,
            capacity_mib: snapshot.capacity_mib,
            queued_foreground: snapshot.queued_foreground,
            queued_background: snapshot.queued_background,
            active_grants: snapshot.active_grants,
            paused: snapshot.paused,
            holds_mib: snapshot.ledger.holds_mib,
            declared_mib: snapshot.ledger.declared_mib,
            resident_mib: snapshot.ledger.resident_mib,
            class_used_mib: snapshot.ledger.class_used_mib.map(|used| {
                used.into_iter()
                    .map(|(class, mib)| (resource_class_name(class).to_owned(), mib))
                    .collect()
            }),
            rows,
            pressure,
            executors: snapshot
                .executors
                .into_iter()
                .map(|executor| DeviceExecutorStatus {
                    load_class: loads.get(&executor.worker_id).copied(),
                    worker_id: executor.worker_id,
                    external: executor.external,
                    idle: executor.idle,
                })
                .collect(),
        }
    }
}

fn resource_class_name(class: ResourceClass) -> &'static str {
    match class {
        ResourceClass::Chat => "chat",
        ResourceClass::Encoder => "encoder",
        ResourceClass::Embedder => "embedder",
        ResourceClass::Asr => "asr",
        ResourceClass::Tts => "tts",
    }
}

/// Sealed inference snapshot parking as this process stands, summed over
/// the vaults it serves: counts, bytes and outcomes only, never a manifest,
/// a digest or a vault id. A figure no source gave is `None`, never zero.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SnapshotStatus {
    /// Whether the host's policy parks sealed snapshots.
    pub enabled: bool,
    /// The host's per-vault disk budget.
    pub disk_budget_bytes: u64,
    /// The snapshots kept and the sealed bytes they hold; `None` when a
    /// vault's catalog could not be read.
    pub snapshots: Option<u64>,
    pub sealed_bytes: Option<u64>,
    /// Bytes reserved or staged for bodies being written.
    pub in_flight_bytes: Option<u64>,
    /// Snapshots evicted to stay inside a budget, and parks skipped for
    /// want of room, since this process started.
    pub evicted: Option<u64>,
    pub skipped: Option<u64>,
    /// Session releases sent whose acknowledgement is still owed: their
    /// bytes stay charged.
    pub release_owed: u64,
    /// Erase-driven releases not yet acknowledged.
    pub erase_copies_pending: u64,
    /// Worker incarnations a lock aborted and restarted since start.
    pub lock_restarts: u64,
    /// The last vault lock's release, when one ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_lock: Option<SnapshotReceipt>,
    /// Since this process started: published checkpoints exported to be
    /// parked, and those sealed and kept.
    pub parks: u64,
    pub seals: u64,
    /// Kept snapshots opened for a restore, and restores imported and made
    /// ready.
    pub opens: u64,
    pub imports: u64,
    /// Restored sessions whose first attach replayed the suffix past the
    /// state their snapshot carried (a sliding-window frontier between two
    /// page boundaries).
    pub replays: u64,
    /// Restores that matched a kept snapshot and ran cold.
    pub restores_cold: u64,
    /// Parks skipped, by reason.
    pub skips: SnapshotSkips,
}

/// Why parks were skipped since this process started, one count each.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SnapshotSkips {
    /// The vault's budget was off, zero, or held by pinned snapshots alone.
    pub budget: u64,
    /// The size the copy would take, or its device's room, was not known.
    pub unknown_room: u64,
    /// Its device had no room for the copy past the headroom.
    pub no_room: u64,
    /// It depended on a world whose sealed copies the owner keeps local.
    pub kept_local: u64,
    /// It was larger than the vault's whole budget.
    pub oversize: u64,
    /// What it was computed with was not named whole.
    pub unsupported: u64,
    /// It was too short to pay back its transfer.
    pub short: u64,
}

/// One vault lock's release, as the host ran it: ids and outcomes only.
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotReceipt {
    /// The one total bound the release ran under, in milliseconds.
    pub bound_ms: u64,
    /// Sessions released with their worker's acknowledgement.
    pub released: u64,
    /// The incarnations aborted, killed and restarted for an unanswered
    /// release, by worker id and epoch.
    pub aborted: Vec<oneiron::inference_snapshot::SnapshotWorkerAbort>,
    pub timed_out: bool,
    pub elapsed_ms: u64,
    /// The host's plaintext copies of the vault's snapshots when the lock
    /// began, and those still held when its release answered.
    pub host_copies: u64,
    pub host_copies_left: u64,
}

/// One model the mesh discovered: the node that offers it and its offer's
/// live health, as a rung's.
#[derive(Clone, Debug, Serialize)]
pub struct DiscoveredStatus {
    /// The id raw `/v1/llm` calls name it by.
    pub model: String,
    /// The machine id of the owner's node that offers it.
    pub peer: String,
    pub health: RungHealth,
}

impl ModelsStatus {
    pub(super) fn unconfigured() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderStatus {
    pub name: String,
    pub kind: &'static str,
    pub base_url: String,
    pub locality: oneiron::ModelLocality,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For a `key_secret` provider, how the credential broker that sends its
    /// calls is kept apart from this server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_isolation: Option<BrokerIsolation>,
    /// The unproven badge (ARCH-0069 `#broker-same-user-open`): the broker
    /// runs as this server's own user, so only its own closing keeps its
    /// memory from that user.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unproven: bool,
}

fn kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenaiCompat => "openai-compat",
        ProviderKind::AnthropicCompat => "anthropic-compat",
        ProviderKind::LocalOpenaiCompat => "local-openai-compat",
        ProviderKind::Oneironer => "oneironer",
        ProviderKind::Cartesia => "cartesia",
        ProviderKind::Elevenlabs => "elevenlabs",
        ProviderKind::Voxcpm2 => "voxcpm2",
        ProviderKind::Gemini => "gemini",
        ProviderKind::Soniox => "soniox",
    }
}

impl ProviderStatus {
    fn with(
        name: &str,
        provider: &ProviderConfig,
        state: &'static str,
        reason: Option<String>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            kind: kind_name(provider.kind),
            base_url: provider.base_url.clone(),
            locality: provider.locality,
            state,
            reason,
            broker_isolation: None,
            unproven: false,
        }
    }

    /// A provider that can serve, through a broker kept apart as `broker`
    /// says, if its key is in custody.
    pub(super) fn ready(
        name: &str,
        provider: &ProviderConfig,
        broker: Option<BrokerIsolation>,
    ) -> Self {
        Self {
            broker_isolation: broker,
            unproven: broker == Some(BrokerIsolation::SameUser),
            ..Self::with(name, provider, "ready", None)
        }
    }

    /// Accepted config the LLM slot builds no client for: a tagger entry,
    /// whose consumer is the tagger slot, or a media-only provider, whose
    /// clients are its media rungs'.
    pub(super) fn without_consumer(name: &str, provider: &ProviderConfig) -> Self {
        let (state, reason) = if provider.kind == ProviderKind::Oneironer {
            (
                "tagger_slot",
                "served by the tagger slot; the vault manifest's extraction_encoder binding selects it",
            )
        } else {
            (
                "media_only",
                "serves [models.media] rungs only; it answers no chat call",
            )
        };
        Self::with(name, provider, state, Some(reason.into()))
    }

    pub(super) fn unavailable(
        name: &str,
        provider: &ProviderConfig,
        error: &anyhow::Error,
    ) -> Self {
        Self::with(name, provider, "unavailable", Some(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatState {
    Ready,
    Unavailable,
    /// Every rung that was built rests because its provider is down.
    Down,
    /// No healthy rung is free to serve, but one is on probation after an
    /// outage and takes a call to check.
    Recovering,
}

#[derive(Clone, Debug, Serialize)]
pub struct SeatStatus {
    pub role: String,
    /// The single model id the engine pins for this seat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_model: Option<String>,
    pub state: SeatState,
    pub rungs: Vec<RungStatus>,
}

impl SeatStatus {
    pub(super) fn new(
        role: ModelRole,
        seat_model: Option<&ModelId>,
        state: SeatState,
        rungs: Vec<RungStatus>,
    ) -> Self {
        Self {
            role: role_key(role),
            seat_model: seat_model.map(ToString::to_string),
            state,
            rungs,
        }
    }

    /// The live seat: each built rung's `health` at its configured position,
    /// and a state worked out from that health (OF-305). A healthy rung that
    /// no limit holds keeps the seat Ready. With no such rung, a free rung on
    /// probation makes it Recovering, and every rung resting for its health
    /// makes it Down. A seat that only limits hold stays as it was built,
    /// since a hold is not an outage and each rung shows its own. A seat
    /// with no built rung stays Unavailable.
    pub(super) fn live(&mut self, health: Vec<(usize, RungHealth)>) {
        if health.is_empty() {
            return;
        }
        for (position, health) in &health {
            if let Some(rung) = self.rungs.get_mut(*position) {
                rung.health = Some(*health);
            }
        }
        let free = |state| {
            health
                .iter()
                .any(|(_, health)| health.state == state && health.limit.is_none())
        };
        if free(HealthState::Healthy) {
            self.state = SeatState::Ready;
        } else if free(HealthState::Recovering) {
            self.state = SeatState::Recovering;
        } else if health
            .iter()
            .all(|(_, health)| health.state == HealthState::Down)
        {
            self.state = SeatState::Down;
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RungStatus {
    pub provider: String,
    /// The provider's own spelling of the model.
    pub model: String,
    /// The id raw `/v1/llm` calls name this model by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_model: Option<String>,
    pub locality: oneiron::ModelLocality,
    pub available: bool,
    /// The live health of a rung that was built, in the live status only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<RungHealth>,
}

/// Where an offer's health stands (OF-305): in rotation, resting because
/// its provider is down, or on probation after that rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Down,
    Recovering,
}

/// One built rung's live health: its offer's state and its provider's
/// failures in a row. While it is down, when that rest ends. While it
/// recovers, its answers since and whether its one probation request is out
/// now. Any limit rest shows apart, as a hold rather than an outage.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RungHealth {
    pub state: HealthState,
    #[serde(skip_serializing_if = "is_zero")]
    pub strikes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "is_zero")]
    pub successes: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub probing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<LimitHold>,
}

impl RungHealth {
    /// Whether a call may go out on the rung now (FIX 2942): its offer is in
    /// rotation, or on probation with its one probation request free, and
    /// no limit holds it.
    pub(super) fn live_now(&self) -> bool {
        self.limit.is_none()
            && match self.state {
                HealthState::Healthy => true,
                HealthState::Recovering => !self.probing,
                HealthState::Down => false,
            }
    }
}

/// A limit refusal's rest on an offer: when it ends, what set that end, and
/// what was spent, if a window or credit was. Spent credit's end is
/// `u64::MAX`, for the owner to clear.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct LimitHold {
    pub until: u64,
    pub reset: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spent: Option<SpentKind>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl RungStatus {
    pub(super) fn new(model: &ModelRef, provider: &ProviderConfig) -> Self {
        Self {
            provider: model.provider.clone(),
            model: model.model.clone(),
            engine_model: super::engine_model_id(model, provider)
                .ok()
                .map(|id| id.to_string()),
            locality: provider.locality,
            available: true,
            health: None,
        }
    }
}
