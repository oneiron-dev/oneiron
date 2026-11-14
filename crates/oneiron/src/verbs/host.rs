//! The inputs and answers of the verb-table rows a host door answers: the
//! owner's `vault.packs.put`, `vault.packs.remove`,
//! `vault.connectors.subscriptions.*` and `vault.hooks.replay`, the `ai.*` model calls
//! past text, `ai.ask_image`, `ai.verdict` and `vault.artifacts.image.edit`. A
//! server answers each with its own state (the owner's proof, its model seats,
//! its decision ladder, its hook sandbox, its organ host); an embedded handle
//! answers a pack put as the vault's embedded owner and refuses the rest,
//! which have nothing to run on there.
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::llm::media::{AiOperation, MediaJobState, MediaPart, MediaResponse, MediaUsage};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::PackInstallReceipt;

mod ask_image;
mod hooks_replay;
mod image_edit;
mod local_pack_agent;
mod pack_setup;
pub use self::ask_image::*;
pub use self::hooks_replay::*;
pub use self::image_edit::*;
pub use self::local_pack_agent::*;
pub use self::pack_setup::*;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::host::{
    AiAnswer, AiCallRequest, AiImageMask, AiOptionsRequest, AiPart, AiVideoJobRequest, AiVoice,
    ChannelSubscriptionRequest, ChannelSubscriptionRevokeRequest, ChannelSubscriptionsRequest,
    PackBytesFile, PackFileDecodeError, PackFileInput, PackPutRequest, PackRemoveRequest,
    PackTextFile, decode_pack_files,
};

pub use crate::memory::hook_regen_doors::{PackPutOutcome, PackPutReceipt};

/// `vault.packs.put` under the owner's proof a host minted from the request.
pub fn put_pack_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(vault.put_pack(owner, input.into_files()?)?.into())
}

/// `vault.packs.put` on an embedded handle: the vault's embedded owner's put,
/// or, on an agent's handle, the agent's own put of `local`.
pub fn put_pack_embedded(
    memory: &Memory<'_>,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    if memory.actor_class() == crate::EdgeActorClass::Agent {
        return put_local_pack_as_agent(memory, input);
    }
    Ok(memory
        .put_pack_as_embedded_owner("vault.packs.put", input.into_files()?)?
        .into())
}

/// `vault.packs.remove` under the owner's proof a host minted from the
/// request: the pack's receipt leaves the Active catalog and every hook
/// binding of it stops; a built-in goes back to its Candidate. Answers the
/// removed receipt.
pub fn remove_pack_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackRemoveRequest,
) -> MemoryResult<PackInstallReceipt> {
    Ok(vault.remove_pack(owner, &input.pack)?)
}

/// `vault.packs.remove` on an embedded handle, as the vault's embedded owner.
pub fn remove_pack_embedded(
    memory: &Memory<'_>,
    input: PackRemoveRequest,
) -> MemoryResult<PackInstallReceipt> {
    let owner = memory.embedded_owner("vault.packs.remove")?;
    remove_pack_as_owner(memory.vault(), &owner, &input)
}

/// One connector event subscription of an agent, standing or revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptionRow {
    pub subscription: String,
    pub connector_key: String,
    pub connector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    pub active: bool,
}

/// `vault.connectors.subscriptions.list`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptions {
    pub agent: String,
    pub subscriptions: Vec<ChannelSubscriptionRow>,
}

/// `vault.connectors.subscriptions.revoke`'s answer: the subscription wakes
/// nothing more; its key stays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptionRevoked {
    pub subscription: String,
}

fn hex_id(field: &str, value: &str) -> MemoryResult<crate::EntityId> {
    crate::EntityId::from_hex(value.trim())
        .map_err(|_| MemoryError::bad_request(format!("{field} is a 32-hex id")))
}

/// A refusal the subscription doors explain is the caller's to fix.
fn subscription_error(error: crate::Error) -> MemoryError {
    match error {
        crate::Error::InvalidConfig(message) => MemoryError::bad_request(message),
        crate::Error::EntityNotFound => MemoryError::not_found("no such subscription"),
        other => other.into(),
    }
}

/// `vault.connectors.subscriptions.put` under the owner's proof: the agent
/// wakes on each message the channel's built-in pack routes to it, under
/// its own key for the channel (reused while Active, else minted).
pub fn subscribe_channel_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &ChannelSubscriptionRequest,
) -> MemoryResult<crate::connector_key::ChannelMessageSubscription> {
    let agent = hex_id("agent", &input.agent)?;
    vault
        .subscribe_agent_to_channel_messages(owner, agent, &input.channel)
        .map_err(subscription_error)
}

/// `vault.connectors.subscriptions.list` under the owner's proof: the
/// agent's connector event subscriptions, standing and revoked.
pub fn channel_subscriptions_as_owner(
    vault: &crate::Vault,
    _owner: &AuthenticatedOwner,
    input: &ChannelSubscriptionsRequest,
) -> MemoryResult<ChannelSubscriptions> {
    let agent = hex_id("agent", &input.agent)?;
    let subscriptions = vault
        .connector_event_subscriptions(agent)?
        .into_iter()
        .map(|(id, row)| ChannelSubscriptionRow {
            subscription: id.to_hex(),
            connector_key: row.connector_key.to_hex(),
            connector: row.filter.connector,
            event_kind: row.filter.event_kind,
            predicate: row.filter.predicate,
            active: row.active,
        })
        .collect();
    Ok(ChannelSubscriptions {
        agent: agent.to_hex(),
        subscriptions,
    })
}

/// `vault.connectors.subscriptions.revoke` under the owner's proof.
pub fn revoke_channel_subscription_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &ChannelSubscriptionRevokeRequest,
) -> MemoryResult<ChannelSubscriptionRevoked> {
    let id = hex_id("subscription", &input.subscription)?;
    vault
        .revoke_connector_event_subscription(owner, id)
        .map_err(subscription_error)?;
    Ok(ChannelSubscriptionRevoked {
        subscription: id.to_hex(),
    })
}

/// `vault.connectors.subscriptions.put` on an embedded handle, as the
/// vault's embedded owner.
pub fn subscribe_channel_embedded(
    memory: &Memory<'_>,
    input: ChannelSubscriptionRequest,
) -> MemoryResult<crate::connector_key::ChannelMessageSubscription> {
    let owner = memory.embedded_owner("vault.connectors.subscriptions.put")?;
    subscribe_channel_as_owner(memory.vault(), &owner, &input)
}

/// `vault.connectors.subscriptions.list` on an embedded handle.
pub fn channel_subscriptions_embedded(
    memory: &Memory<'_>,
    input: ChannelSubscriptionsRequest,
) -> MemoryResult<ChannelSubscriptions> {
    let owner = memory.embedded_owner("vault.connectors.subscriptions.list")?;
    channel_subscriptions_as_owner(memory.vault(), &owner, &input)
}

/// `vault.connectors.subscriptions.revoke` on an embedded handle.
pub fn revoke_channel_subscription_embedded(
    memory: &Memory<'_>,
    input: ChannelSubscriptionRevokeRequest,
) -> MemoryResult<ChannelSubscriptionRevoked> {
    let owner = memory.embedded_owner("vault.connectors.subscriptions.revoke")?;
    revoke_channel_subscription_as_owner(memory.vault(), &owner, &input)
}

/// The one hint every bare-vault host refusal gives: the engine's own
/// in-process served client reaches the served door under the caller's own
/// credential, so the act works wherever the engine runs.
pub(crate) const SERVED_CLIENT_HINT: &str = "Use the in-process served client \
     (connect_in_process / EmbeddedEngine::client) under your own credential, or a remote \
     client of a server that serves it.";

/// A row only a host's own state answers, refused on an embedded handle.
pub fn host_only<T, I>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!(
            "{verb} runs on a server's own model seats, decision ladder or hook sandbox; an embedded vault has none"
        ),
        &[SERVED_CLIENT_HINT],
    ))
}

/// `ai.options`'s answer: each text seat's rungs and each media row that
/// serves the operation over those inputs, and what the media meter has left.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiOptions {
    pub options: Vec<serde_json::Value>,
    pub media_units_left: Option<u64>,
}

/// `ai.video`'s answer: the provider job its clip renders as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoTicket {
    pub job: String,
    pub model: String,
    pub operation: AiOperation,
}

/// Where a video job stands; a finished one answers with its clip on every
/// poll until `ai.video.cancel` deletes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AiVideoJob {
    Queued,
    Running {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<u8>,
    },
    Done {
        answer: AiAnswer,
    },
    Failed {
        error: crate::LlmError,
    },
}

impl From<MediaJobState> for AiVideoJob {
    fn from(state: MediaJobState) -> Self {
        match state {
            MediaJobState::Queued => Self::Queued,
            MediaJobState::Running { progress } => Self::Running { progress },
            MediaJobState::Done { response } => Self::Done {
                answer: response.into(),
            },
            MediaJobState::Failed { error } => Self::Failed { error },
        }
    }
}

/// `ai.video.cancel`'s answer: the job its provider was told to stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoCancelled {
    pub job: String,
}

/// What a wrong `ai.verdict` would cost: a read that can be redone, or an
/// effect that leaves the vault. The bands escalate an outbound effect
/// sooner.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AiVerdictReversibility {
    #[default]
    ReversibleRead,
    OutboundEffect,
}

impl From<AiVerdictReversibility> for crate::llm::decision::Reversibility {
    fn from(value: AiVerdictReversibility) -> Self {
        match value {
            AiVerdictReversibility::ReversibleRead => Self::ReversibleRead,
            AiVerdictReversibility::OutboundEffect => Self::OutboundEffect,
        }
    }
}

pub use crate::receipt::AI_VERDICT_DEADLINE_MS;

/// `ai.verdict`'s input: one typed question through the host's decision
/// ladder (ARCH-0076), asked for the caller. The principal is the caller's
/// own actor, never a field here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiVerdictRequest {
    /// The question, as the ladder's providers read it.
    pub question: String,
    /// What the answer is (ARCH-0076): `{"kind": "noul"}`, yes or no with
    /// P(yes), when absent; `{"kind": "choice", "options": [...]}`, one of
    /// its labels; `{"kind": "score", "min": 1, "max": 5}`, one number in
    /// that range, in the units and direction the question names;
    /// `{"kind": "box"}` or `{"kind": "point"}`, where the question's target
    /// sits in `image`, as fractions of it from its top left (none when the
    /// target is absent, once the host's presence question says so).
    #[serde(default = "yes_no")]
    pub contract: crate::llm::decision::AnswerContract,
    /// Entity refs (short refs or 32-hex ids, each optionally `@<revision>`)
    /// the answer reads. Each must be readable by the caller; the providers
    /// read their views in the call's state, every text in them cut to fit
    /// it when the views do not fit whole (`evidence_cut_at_bytes`).
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What else the question reads, beside the evidence.
    #[serde(default)]
    pub state: Option<serde_json::Value>,
    /// The highest rung that may answer; `big` when absent. A verdict never
    /// queues an owner ask, so `human` is refused.
    #[serde(default)]
    pub ceiling: Option<crate::llm::decision::DecisionRung>,
    #[serde(default)]
    pub reversibility: AiVerdictReversibility,
    /// The call's clock, 1 to 60000 milliseconds;
    /// [`AI_VERDICT_DEADLINE_MS`] when absent.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// A routine driver step (OF-523, the CUA-S1 pattern): a Choice's
    /// `options` are the step's candidates (at most 61), and the ladder also
    /// offers NONE, reobserve and "too complicated, ask up"; a Box or a Point
    /// acts where it finds the target. The answer comes back as an `outcome`
    /// the program acts on.
    #[serde(default)]
    pub routine: bool,
    /// An image the question reads, by its view handle (`<asset>@<hash>`):
    /// a screenshot, as an evidence ref. Read under the caller's own scoped
    /// read; the question names it as `image`. An image call starts at the
    /// Local-vision rung. In a code run, a `blake3:` ref names a screenshot
    /// the run's browser holds, read from that browser as an evidence ref on
    /// the run.
    #[serde(default)]
    pub image: Option<String>,
    /// NONE or reobserve outcomes the subgoal's steps gave in a row before
    /// this one: the answer says when the next observation takes a
    /// screenshot.
    #[serde(default)]
    pub misses: u32,
    /// The subgoal's one clock, as the Unix milliseconds it ends at: every
    /// routine step of one subgoal names the same instant, so a reobserve or
    /// a retry never restarts it. One call still runs at most 60000
    /// milliseconds. The answer names the instant its own clock ends at.
    #[serde(default)]
    pub until_ms: Option<u64>,
}

fn yes_no() -> crate::llm::decision::AnswerContract {
    crate::llm::decision::AnswerContract::Noul
}

/// `ai.verdict`'s answer: the ladder's answer on the request's contract, its
/// probability (P(yes) for a yes/no, else the answer's confidence; none for a
/// Box or a Point whose coordinates were not read), the rung whose answer
/// stands (none when the call abstained), and the decision's receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiVerdict {
    pub answer: crate::llm::decision::DecisionAnswer,
    pub p: Option<f64>,
    pub rung: Option<crate::llm::decision::DecisionRung>,
    pub receipt: crate::llm::decision::DecisionReceipt,
    /// A Box or Point call's presence step, when the host asked it: its own
    /// P(yes) and receipt. The receipt above is the coordinates' when they
    /// were read, else this step's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<crate::llm::decision::TypedDecision>,
    /// A routine step's outcome: act on a candidate or at a point, NONE,
    /// reobserve, or ask up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<crate::llm::decision::RoutineOutcome>,
    /// A routine step's screenshot trigger: the subgoal's steps gave NONE or
    /// reobserve twice in a row, so the next observation takes a screenshot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub screenshot: bool,
    /// The Unix milliseconds this call's clock ended at: a routine program
    /// passes it on as the next step's `until_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// The bytes every text in the evidence views was cut to, when the views
    /// did not fit the ladder's state whole: the ladder read them cut. The
    /// refs, kinds and the caller's own state are never cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_cut_at_bytes: Option<u64>,
}

impl From<crate::llm::decision::TypedDecision> for AiVerdict {
    fn from(decision: crate::llm::decision::TypedDecision) -> Self {
        Self {
            answer: decision.answer,
            p: decision.probability,
            rung: decision.receipt.time.and_then(|time| time.answered),
            receipt: decision.receipt,
            presence: None,
            outcome: None,
            screenshot: false,
            until_ms: None,
            evidence_cut_at_bytes: None,
        }
    }
}
