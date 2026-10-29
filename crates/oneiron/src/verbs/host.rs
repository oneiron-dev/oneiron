//! The inputs and answers of the verb-table rows a host door answers: the
//! owner's `vault.packs.put`, `vault.packs.remove`,
//! `vault.connectors.subscriptions.*` and `vault.hooks.replay`, the `ai.*` model calls
//! past text, `ai.ask_image` and `ai.verdict`. A server answers each with its own state (the
//! owner's proof, its model seats, its decision ladder, its hook sandbox); an
//! embedded handle answers a pack put as the vault's embedded owner and
//! refuses the rest, which have nothing to run on there.
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::llm::media::{AiOperation, MediaJobState, MediaPart, MediaResponse, MediaUsage};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallReceipt};

mod ask_image;
mod hooks_replay;
mod pack_setup;
pub use self::ask_image::*;
pub use self::hooks_replay::*;
pub use self::pack_setup::*;

/// One file of a pack folder, its content an explicit choice: text, stored as
/// its UTF-8 bytes, or any bytes (an image, a font, a Wasm module) as
/// standard base64. `vault.packs.put` and `POST /v1/owner/packs` both take it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PackFileInput {
    Text(PackTextFile),
    Bytes(PackBytesFile),
}

/// A pack file sent as text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackTextFile {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    pub text: String,
}

/// A pack file sent as bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackBytesFile {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    /// The file's bytes, RFC 4648 standard base64.
    pub content_base64: String,
}

/// A pack file whose `content_base64` does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pack file {path}: content_base64 is not standard base64")]
pub struct PackFileDecodeError {
    pub path: String,
}

impl PackFileInput {
    /// The file as the pack source reads it, its content decoded.
    ///
    /// # Errors
    /// [`PackFileDecodeError`] when its base64 does not decode.
    pub fn into_hub_file(self) -> Result<HubFile, PackFileDecodeError> {
        match self {
            Self::Text(file) => Ok(HubFile::new(file.path, file.text.into_bytes())),
            Self::Bytes(file) => match STANDARD.decode(file.content_base64.as_bytes()) {
                Ok(bytes) => Ok(HubFile::new(file.path, bytes)),
                Err(_) => Err(PackFileDecodeError { path: file.path }),
            },
        }
    }
}

/// A pack folder's files as the pack source reads them, each decoded before
/// the install door sees any of them.
///
/// # Errors
/// [`PackFileDecodeError`] naming the first file whose base64 does not decode.
pub fn decode_pack_files(files: Vec<PackFileInput>) -> Result<Vec<HubFile>, PackFileDecodeError> {
    files
        .into_iter()
        .map(PackFileInput::into_hub_file)
        .collect()
}

/// `vault.packs.put`'s input: the pack folder's files. The put installs the
/// folder, or replaces the pack installed under its name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackPutRequest {
    pub files: Vec<PackFileInput>,
}

impl PackPutRequest {
    /// The folder as the pack source reads it.
    ///
    /// # Errors
    /// A bad request naming the first file whose base64 does not decode.
    pub fn into_files(self) -> MemoryResult<Vec<HubFile>> {
        decode_pack_files(self.files).map_err(|error| MemoryError::bad_request(error.to_string()))
    }
}

/// What one pack put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackPutOutcome {
    Installed,
    /// Its code waits for its sandbox to qualify it.
    Candidate,
    /// The vault's install rules refused it; `reason` says why.
    Blocked,
}

/// `vault.packs.put`'s answer: the outcome, and the install receipt unless
/// the put was blocked.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackPutReceipt {
    pub outcome: PackPutOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Box<PackInstallReceipt>>,
}

impl From<PackInstallDisposition> for PackPutReceipt {
    fn from(disposition: PackInstallDisposition) -> Self {
        let (outcome, reason, receipt) = match disposition {
            PackInstallDisposition::Installed(receipt) => {
                (PackPutOutcome::Installed, None, Some(receipt))
            }
            PackInstallDisposition::Candidate(receipt) => {
                (PackPutOutcome::Candidate, None, Some(receipt))
            }
            PackInstallDisposition::Blocked { reason } => {
                (PackPutOutcome::Blocked, Some(reason), None)
            }
        };
        Self {
            outcome,
            reason,
            receipt,
        }
    }
}

/// `vault.packs.put` under the owner's proof a host minted from the request.
pub fn put_pack_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(vault.put_pack(owner, input.into_files()?)?.into())
}

/// `vault.packs.put` on an embedded handle: the vault's embedded owner's put.
pub fn put_pack_embedded(
    memory: &Memory<'_>,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(memory
        .put_pack_as_embedded_owner(input.into_files()?)?
        .into())
}

/// `vault.packs.remove`'s input: the installed pack to remove, by name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackRemoveRequest {
    pub pack: String,
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

/// `vault.connectors.subscriptions.put`'s input: the agent that answers a
/// built-in channel (OF-519), and the channel, `slack` or `line`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionRequest {
    /// The agent, as 32 hex.
    pub agent: String,
    pub channel: String,
}

/// `vault.connectors.subscriptions.list`'s input: whose subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionsRequest {
    /// The agent, as 32 hex.
    pub agent: String,
}

/// `vault.connectors.subscriptions.revoke`'s input: the subscription to stop.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionRevokeRequest {
    /// The subscription, as 32 hex.
    pub subscription: String,
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

/// One part of an `ai.*` call on the SDK wire: text, or bytes as base64.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AiPart {
    Text {
        text: String,
    },
    Image {
        media_type: String,
        data: String,
    },
    Audio {
        media_type: String,
        data: String,
    },
    /// A clip's bytes, or where its provider keeps it.
    Video {
        media_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uri: Option<String>,
    },
    Embedding {
        vector: Vec<f32>,
    },
}

impl AiPart {
    /// The part a call sends: text, or an image or audio with base64 data.
    /// A clip or a vector is an answer, never an input.
    #[must_use]
    pub fn into_media(self) -> Option<MediaPart> {
        let bytes = |data: &str| STANDARD.decode(data).ok().filter(|bytes| !bytes.is_empty());
        Some(match self {
            Self::Text { text } => MediaPart::Text { text },
            Self::Image { media_type, data } => MediaPart::Image {
                bytes: bytes(&data)?,
                media_type,
            },
            Self::Audio { media_type, data } => MediaPart::Audio {
                bytes: bytes(&data)?,
                media_type,
            },
            Self::Video { .. } | Self::Embedding { .. } => return None,
        })
    }

    #[must_use]
    pub fn from_media(part: MediaPart) -> Self {
        match part {
            MediaPart::Text { text } => Self::Text { text },
            MediaPart::Image { media_type, bytes } => Self::Image {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Audio { media_type, bytes } => Self::Audio {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Video {
                media_type,
                bytes,
                uri,
            } => Self::Video {
                media_type,
                data: (!bytes.is_empty()).then(|| STANDARD.encode(bytes)),
                uri,
            },
            MediaPart::Embedding { vector } => Self::Embedding { vector },
        }
    }
}

/// One `ai.*` media call: `ai.image`, `ai.video`, `ai.speech`,
/// `ai.transcribe` or `ai.embed`, as `POST /v1/ai/<operation>` takes it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiCallRequest {
    /// A row's id to use it alone, or its seat's id; the operation's seat
    /// when absent (`ai.options` lists both).
    #[serde(default)]
    pub model: Option<String>,
    /// The instruction, the script or the one text: a first text part.
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub input: Vec<AiPart>,
    /// The images an image call edits, or a video call starts from.
    #[serde(default)]
    pub references: Vec<AiPart>,
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
    /// A speech call's voice; the provider's default when absent. Any
    /// other call that names one is refused.
    #[serde(default)]
    pub voice: Option<AiVoice>,
    /// The caller's own idempotency key for the call (FIX 2962): a repeat
    /// of the same call under the same key answers the first's answer, or
    /// a video's first ticket, and is not paid for or rendered again. A
    /// call in a banked voice is never replayed. With none, every call
    /// goes out.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// The voice an `ai.speech` call names (OF-410): a provider's stock voice
/// by its name, or a banked identity. A banked voice renders on the first
/// rung of the call's ladder whose target holds its current clone or
/// reference, and on that rung alone; with none, or once withdrawn, the call
/// is refused rather than spoken in another voice (ARCH-0061 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AiVoice {
    /// A provider's own voice, by its name.
    Stock { name: String },
    /// A banked identity, rendered as its clone on the call's target.
    Bank {
        voice_id: String,
        #[serde(default)]
        include_generated: bool,
    },
}

/// One `ai.*` call's answer: the model that answered, its parts, and what
/// its provider counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AiAnswer {
    pub model: String,
    pub parts: Vec<AiPart>,
    pub usage: MediaUsage,
}

impl From<MediaResponse> for AiAnswer {
    fn from(response: MediaResponse) -> Self {
        Self {
            model: response.model.to_string(),
            parts: response.parts.into_iter().map(AiPart::from_media).collect(),
            usage: response.usage,
        }
    }
}

/// `ai.options`'s input: the operation whose rows to list (`text`, `image`,
/// `video`, `speech`, `transcribe`, `embed`), every one when absent, and the
/// modalities a call would send (`text`, `image`, `audio`, `video`,
/// `embedding`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiOptionsRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub inputs: Vec<String>,
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

/// A video job, by the ticket `ai.video` answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiVideoJobRequest {
    pub job: String,
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

/// `ai.verdict`'s clock, in milliseconds, when the request names none.
pub const AI_VERDICT_DEADLINE_MS: u64 = 10_000;

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
