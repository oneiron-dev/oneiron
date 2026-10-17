//! What the model runtime built, for the owner-facing status route.
use oneiron::ModelId;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{BrokerIsolation, SpentKind};
use serde::Serialize;

use crate::config::models::{ModelRef, ProviderConfig, ProviderKind, role_key};

/// Every provider and seat the config named, and whether each can serve.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ModelsStatus {
    /// False when the config has no `[models]` section at all.
    pub configured: bool,
    pub providers: Vec<ProviderStatus>,
    pub seats: Vec<SeatStatus>,
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
