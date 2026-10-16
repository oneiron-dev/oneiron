//! The inputs and answers of the verb-table rows a host door answers: the
//! owner's `vault.packs.put` and `vault.hooks.replay`, the `ai.*` model calls
//! past text and `ai.verdict`. A server answers each with its own state (the
//! owner's proof, its model seats, its decision ladder, its hook sandbox); an
//! embedded handle answers a pack put as the vault's embedded owner and
//! refuses the rest, which have nothing to run on there.
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::connector_key::ProviderConnectionChecks;
use crate::consent::AuthenticatedOwner;
use crate::lens::GeneratedUiStateSnapshot;
use crate::llm::media::{AiOperation, MediaJobState, MediaPart, MediaResponse, MediaUsage};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallReceipt};
use crate::skill_hub::pack_catalog::{PackSetupAnswer, PackSetupCardAction, PackSetupView};

/// One file of a pack folder.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackFileInput {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    pub text: String,
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
    #[must_use]
    pub fn into_files(self) -> Vec<HubFile> {
        self.files
            .into_iter()
            .map(|file| HubFile::new(file.path, file.text.into_bytes()))
            .collect()
    }
}

/// What one pack put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Ok(vault.put_pack(owner, input.into_files())?.into())
}

/// `vault.packs.put` on an embedded handle: the vault's embedded owner's put.
pub fn put_pack_embedded(
    memory: &Memory<'_>,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(memory
        .put_pack_as_embedded_owner(input.into_files())?
        .into())
}

/// A row only a host's own state answers, refused on an embedded handle.
pub fn host_only<T, I>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!(
            "{verb} runs on a server's own model seats, decision ladder or hook sandbox; an embedded vault has none"
        ),
        &["Call it through a remote client of a server that serves it."],
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
}

/// One `ai.*` call's answer: the model that answered, its parts, and what
/// its provider counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Where a video job stands; a finished one answers with its clip, once.
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
    /// The labels the answer is one of; a yes/no question when empty.
    #[serde(default)]
    pub options: Vec<String>,
    /// Entity refs (short refs or 32-hex ids, each optionally `@<revision>`)
    /// the answer reads. Each must be readable by the caller; the providers
    /// read their views in the call's state.
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
    /// A routine driver step (OF-523, the CUA-S1 pattern): `options` are the
    /// step's candidates (at most 61), and the ladder also offers NONE,
    /// reobserve and "too complicated, ask up". The answer comes back as an
    /// `outcome` the program acts on.
    #[serde(default)]
    pub routine: bool,
    /// An image the question reads, by its view handle (`<asset>@<hash>`):
    /// a screenshot, as an evidence ref. Read under the caller's own scoped
    /// read; the question names it as `image`. An image call starts at the
    /// Local-vision rung.
    #[serde(default)]
    pub image: Option<String>,
    /// Find the question's target in `image`: a Box answer (none when the
    /// target is absent). `options` stay empty; a routine Box acts at the
    /// box's centre.
    #[serde(default)]
    pub locate: bool,
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

/// `ai.verdict`'s answer: the ladder's answer, its probability, the rung
/// whose answer stands (none when the call abstained), and the decision's
/// receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiVerdict {
    pub answer: crate::llm::decision::DecisionAnswer,
    pub p: Option<f64>,
    pub rung: Option<crate::llm::decision::DecisionRung>,
    pub receipt: crate::llm::decision::DecisionReceipt,
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
}

impl From<crate::llm::decision::TypedDecision> for AiVerdict {
    fn from(decision: crate::llm::decision::TypedDecision) -> Self {
        Self {
            answer: decision.answer,
            p: decision.probability,
            rung: decision.receipt.time.and_then(|time| time.answered),
            receipt: decision.receipt,
            outcome: None,
            screenshot: false,
            until_ms: None,
        }
    }
}

/// `vault.hooks.replay`'s page size when the request names none.
pub const HOOKS_REPLAY_LIMIT_DEFAULT: usize = 64;
/// The most entries one `vault.hooks.replay` returns: the engine's own cap.
pub const HOOKS_REPLAY_LIMIT_MAX: usize = 256;

/// `vault.hooks.replay`'s input: the fact hook to replay, where to start and
/// how many entries to return.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HooksReplayRequest {
    /// The hook binding's 32-hex id.
    pub binding: String,
    /// The fact position to replay after (`claim_changelog:<hex32>` or
    /// `settlement:<hex16>`); every source from its start when absent.
    #[serde(default)]
    pub since: Option<String>,
    /// Entries to return, 1 to [`HOOKS_REPLAY_LIMIT_MAX`];
    /// [`HOOKS_REPLAY_LIMIT_DEFAULT`] when absent.
    #[serde(default)]
    pub limit: Option<usize>,
}

impl HooksReplayRequest {
    /// The page size this request names, refused outside its bounds.
    pub fn limit(&self) -> MemoryResult<usize> {
        let limit = self.limit.unwrap_or(HOOKS_REPLAY_LIMIT_DEFAULT);
        if limit == 0 || limit > HOOKS_REPLAY_LIMIT_MAX {
            return Err(MemoryError::bad_request_with(
                format!("limit must be between 1 and {HOOKS_REPLAY_LIMIT_MAX}"),
                &["Request a smaller page and continue from the last entry's position."],
            ));
        }
        Ok(limit)
    }
}

/// One past fact a hook takes, and what its body returns for it now.
/// Nothing landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookReplayRow {
    pub position: crate::runtime_hooks::FactPositionHex,
    pub kind: crate::runtime_hooks::FactKind,
    #[serde(with = "crate::serialize::entity_ref")]
    pub entity: crate::EntityId,
    pub result: HookReplayOutcome,
}

/// What a replayed entry gave: the body's outcome, or the history it lacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HookReplayOutcome {
    /// The body ran on this entry. Nothing landed.
    Ran {
        outcome_json: Option<String>,
        /// The outcome kind, or `refused` / `failed`.
        outcome: String,
        reason: Option<String>,
        /// The outcome the live run recorded, when one ran.
        recorded: Option<String>,
        /// The input came from the run's pinned memo row.
        from_memo: bool,
        /// No run pinned this entry's reads; they read current rows.
        reads_live: bool,
    },
    /// The entry's inputs are gone: replay will not read newer state instead.
    MissingHistory { reason: String },
}

impl From<crate::runtime_hooks::HookReplayEntry> for HookReplayRow {
    fn from(entry: crate::runtime_hooks::HookReplayEntry) -> Self {
        use crate::runtime_hooks::HookReplayResult;
        Self {
            position: entry.position,
            kind: entry.kind,
            entity: entry.entity,
            result: match entry.result {
                HookReplayResult::Ran {
                    outcome_json,
                    outcome,
                    reason,
                    recorded,
                    from_memo,
                    reads_live,
                } => HookReplayOutcome::Ran {
                    outcome_json,
                    outcome,
                    reason,
                    recorded,
                    from_memo,
                    reads_live,
                },
                HookReplayResult::MissingHistory { reason } => {
                    HookReplayOutcome::MissingHistory { reason }
                }
            },
        }
    }
}

/// `vault.hooks.replay` under the owner's proof a host minted from the
/// request, on `runtime`, the host's own hook sandbox: a dry run of the
/// binding's body over past facts, landing nothing.
pub fn replay_hooks_as_owner(
    vault: &crate::Vault,
    _owner: &crate::consent::AuthenticatedOwner,
    runtime: &dyn crate::runtime_hooks::HookBodyRuntime,
    input: &HooksReplayRequest,
) -> MemoryResult<Vec<HookReplayRow>> {
    let limit = input.limit()?;
    let binding = crate::EntityId::from_hex(input.binding.trim())
        .map_err(|_| MemoryError::bad_request("binding is a hook binding's 32-hex id"))?;
    let since = input
        .since
        .as_ref()
        .map(|position| crate::runtime_hooks::FactPositionHex(position.trim().to_owned()));
    let entries =
        vault
            .hooks_replay(runtime, binding, since, limit)
            .map_err(|error| match error {
                crate::Error::EntityNotFound => {
                    MemoryError::not_found(format!("no hook binding {}", input.binding.trim()))
                }
                crate::Error::InvalidConfig(message) => MemoryError::bad_request(message),
                other => other.into(),
            })?;
    Ok(entries.into_iter().map(HookReplayRow::from).collect())
}

/// Where a credential value goes during a pack's setup: the owner secrets
/// door. No `vault.packs.setup.*` verb and no card ever carries a value.
pub const PACK_SETUP_SECRETS_DOOR: &str = "/v1/owner/secrets/register";

/// `vault.packs.setup.prepare` and `vault.packs.setup.get`'s input: one
/// pack's guided setup (OF-378), by name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupRequest {
    pub pack: String,
    /// One exact source by content hash; else the Active source, or the
    /// pack's one Candidate.
    #[serde(default)]
    pub source: Option<String>,
}

/// `vault.packs.setup.verify`'s input: the connection to check.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupVerifyRequest {
    pub pack: String,
    #[serde(default)]
    pub source: Option<String>,
    pub connection: String,
}

/// `vault.packs.setup.answer`'s input: one typed answer, or one action from
/// the setup's cards with the card's `$state`; exactly one of them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupAnswerRequest {
    pub pack: String,
    #[serde(default)]
    pub source: Option<String>,
    /// `secret_stored` (pins the custody record the owner stored at the
    /// secrets door) or `bind_key`. An `allow` is the owner's own decision
    /// and this verb refuses it.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")]
    pub answer: Option<PackSetupAnswer>,
    #[serde(default)]
    pub card_action: Option<PackSetupCardActionInput>,
}

/// One action from a setup card: its action id and the card's `$state`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCardActionInput {
    pub action_id: String,
    #[serde(default)]
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
    pub state: GeneratedUiStateSnapshot,
}

/// What each `vault.packs.setup.*` verb answers, as the owner door
/// `/v1/owner/packs/setup` serves it: the setup, its GenUI cards and its
/// plain text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSetupReceipt {
    pub setup: PackSetupView,
    /// The setup's GenUI cards, as their wire JSON.
    pub cards: Vec<serde_json::Value>,
    pub text: String,
    /// Set when a card asked to store a credential: the owner stores the
    /// value at `door`, then a `secret_stored` answer pins its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_secret: Option<PackSetupStoreSecret>,
}

/// The owner secrets door to open for one declared credential name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupStoreSecret {
    pub door: String,
    pub connection: String,
    pub name: String,
    /// The binding the stored credential needs, with the read scope.
    pub effector: String,
}

impl PackSetupReceipt {
    fn new(setup: PackSetupView) -> MemoryResult<Self> {
        let cards = setup
            .cards()?
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "the pack setup's cards did not encode",
                    &["Report this SDK host-door failure."],
                )
            })?;
        Ok(Self {
            cards,
            text: setup.text(),
            setup,
            store_secret: None,
        })
    }
}

/// `vault.packs.setup.prepare` under the owner's proof: opens, or resumes,
/// the setup through [`crate::Vault::prepare_pack_setup`]. Opening grants
/// nothing.
pub fn prepare_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    PackSetupReceipt::new(vault.prepare_pack_setup(owner, &input.pack, input.source.as_deref())?)
}

/// `vault.packs.setup.get` under the owner's proof: the setup as it stands.
pub fn pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    PackSetupReceipt::new(vault.pack_setup(owner, &input.pack, input.source.as_deref())?)
}

/// `vault.packs.setup.verify` under the owner's proof: the engine's fixed
/// read-only provider check for the connection's declared check name.
pub fn verify_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupVerifyRequest,
) -> MemoryResult<PackSetupReceipt> {
    verify_pack_connection_as_owner(
        vault,
        owner,
        &input.pack,
        input.source.as_deref(),
        &input.connection,
    )
}

/// `vault.packs.setup.answer` under the owner's proof. A verb is an agent's
/// door, so it never answers `allow`: allowing a connection's permissions
/// mints standing consent grants, and that review is the owner's own, on the
/// setup's review card or at `POST /v1/owner/packs/setup/answer`. A card's
/// store action answers with the owner secrets door to open; a value never
/// passes here.
pub fn answer_pack_setup_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: &PackSetupAnswerRequest,
) -> MemoryResult<PackSetupReceipt> {
    let source = input.source.as_deref();
    let answer = match (&input.answer, &input.card_action) {
        (Some(answer), None) => answer.clone(),
        (None, Some(card)) => {
            let view = vault.pack_setup(owner, &input.pack, source)?;
            match view.card_action(&card.action_id, &card.state)? {
                PackSetupCardAction::Answer(answer) => answer,
                PackSetupCardAction::Verify { connection } => {
                    return verify_pack_connection_as_owner(
                        vault,
                        owner,
                        &input.pack,
                        source,
                        &connection,
                    );
                }
                PackSetupCardAction::StoreSecret {
                    connection,
                    secret,
                    effector,
                } => {
                    let mut receipt = PackSetupReceipt::new(view)?;
                    receipt.store_secret = Some(PackSetupStoreSecret {
                        door: PACK_SETUP_SECRETS_DOOR.to_owned(),
                        connection,
                        name: secret,
                        effector,
                    });
                    return Ok(receipt);
                }
            }
        }
        _ => {
            return Err(MemoryError::bad_request(
                "send exactly one of answer or card_action",
            ));
        }
    };
    if let PackSetupAnswer::Allow { connection, .. } = &answer {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("allowing the permissions of {connection} is the owner's own decision"),
            &[
                "Show the owner the setup's review card; the owner allows there or at POST /v1/owner/packs/setup/answer.",
            ],
        ));
    }
    PackSetupReceipt::new(vault.answer_pack_setup(owner, &input.pack, source, &answer)?)
}

fn verify_pack_connection_as_owner(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    pack: &str,
    source: Option<&str>,
    connection: &str,
) -> MemoryResult<PackSetupReceipt> {
    let checks = ProviderConnectionChecks::new()?;
    PackSetupReceipt::new(vault.verify_pack_connection(owner, pack, source, connection, &checks)?)
}

/// `vault.packs.setup.prepare` on an embedded handle, as the vault's
/// embedded owner.
pub fn prepare_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.prepare")?;
    prepare_pack_setup_as_owner(memory.vault(), &owner, &input)
}

/// `vault.packs.setup.get` on an embedded handle, as the vault's embedded
/// owner.
pub fn pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.get")?;
    pack_setup_as_owner(memory.vault(), &owner, &input)
}

/// `vault.packs.setup.answer` on an embedded handle, as the vault's
/// embedded owner; `allow` is refused here too.
pub fn answer_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupAnswerRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.answer")?;
    let vault = memory.vault();
    off_async_runtime("vault.packs.setup.answer", || {
        answer_pack_setup_as_owner(vault, &owner, &input)
    })
}

/// `vault.packs.setup.verify` on an embedded handle, as the vault's
/// embedded owner.
pub fn verify_pack_setup_embedded(
    memory: &Memory<'_>,
    input: PackSetupVerifyRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = memory.embedded_owner("vault.packs.setup.verify")?;
    let vault = memory.vault();
    off_async_runtime("vault.packs.setup.verify", || {
        verify_pack_setup_as_owner(vault, &owner, &input)
    })
}

/// A provider check is a blocking HTTPS call, which must not run on an
/// async runtime's thread: an embedded caller may be on one, so the call
/// runs on a thread of its own.
fn off_async_runtime<T: Send>(
    verb: &str,
    call: impl FnOnce() -> MemoryResult<T> + Send,
) -> MemoryResult<T> {
    std::thread::scope(|scope| scope.spawn(call).join()).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("{verb} did not finish"),
            &["Report this SDK host-door failure."],
        )
    })?
}
