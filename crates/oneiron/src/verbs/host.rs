//! The inputs and answers of the verb-table rows a host door answers: the
//! owner's `vault.packs.put`, `vault.packs.remove`,
//! `vault.connectors.subscriptions.*` and `vault.hooks.replay`, the `ai.*` model calls
//! past text, `ai.ask_image`, `ai.verdict` and `vault.artifacts.image.edit`. A
//! server answers each with its own state (the owner's proof, its model seats,
//! its decision ladder, its hook sandbox, its organ host); an embedded handle
//! answers a pack put as the vault's embedded owner and refuses the rest,
//! which have nothing to run on there.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::llm::media::{AiOperation, MediaJobState};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
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

#[doc(hidden)]
pub use oneiron_records::verbs::host::{
    AiOptions, AiVerdict, AiVideoCancelled, AiVideoJob, AiVideoTicket, ChannelSubscriptionRevoked,
    ChannelSubscriptionRow, ChannelSubscriptions,
};

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
