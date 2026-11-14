//! Moved from `crates/oneiron/src/verbs/voice_bank.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::verbs::voice_records::render_history::VoiceDroppedTargetView;
pub use crate::verbs::voice_records::render_history::VoiceRenderEventView;
pub use crate::verbs::voice_records::views::VoiceBankInspection;
pub use crate::verbs::voice_records::views::VoiceClipSummary;
pub use crate::verbs::voice_records::views::VoiceIdentityView;
pub use crate::verbs::voice_records::views::VoicePackSummary;
pub use crate::verbs::voice_records::views::VoiceReferenceFenceView;
pub use crate::verbs::voice_records::views::VoiceRenderConsentView;
pub use crate::verbs::voice_records::views::VoiceTargetCloneView;
pub use crate::verbs::voice_records::views::VoiceTargetInspection;
pub use crate::verbs::voice_records::views::VoiceTargetRender;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron_consent_state::memory::voice_actor::VoiceRefSubjectKind;
use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentBasis;
use oneiron_consent_state::verbs::voice_records::consent::VoiceConsentState;
use oneiron_consent_state::verbs::voice_records::model::VoiceRefOrigin;
use oneiron_model::llm::ModelLocality;
use serde::Deserialize;
use serde::Serialize;

/// One reference clip on the wire, as `/v1/ai/voices/{voice_id}/packs` takes
/// it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankClipInput {
    /// The register the clip shows, unique in its pack.
    pub register: String,
    /// An `audio/*` media type.
    pub media_type: String,
    /// The clip's audio, standard base64.
    pub audio: String,
    /// What the clip says.
    pub transcript: String,
}

/// `vault.voices.packs.put`'s input: one immutable pack of the actor's own
/// voice. The first source pack makes the identity; a retry of the same pack
/// is a no-op, and a different pack under its id refuses. The bank, not the
/// input, decides whether the voice is a person's or a designed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankPackPutRequest {
    pub voice_id: String,
    pub pack_id: String,
    /// `captured` cites the subject's current render grant, a person's, by
    /// its event id; `designed` names its design tool's vendor; `generated`
    /// adds AI-made refs to a banked identity and never stands in for its
    /// source.
    pub origin: VoiceRefOrigin,
    pub clips: Vec<VoiceBankClipInput>,
}

/// What a pack put banked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankPackReceipt {
    pub voice_id: String,
    pub pack_id: String,
}

/// `vault.voices.render_consent`'s input: the actor's render decision on
/// their own voice, a real person's on their own person proof or a designed
/// voice's creator's. It may come before the first pack, which cites a
/// grant by its event id. A replay of a recorded decision answers its
/// original receipt; a different decision under its event id, or one older
/// than the current decision, refuses. Recognition consent never stands in
/// for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentRequest {
    pub voice_id: String,
    /// The decision's own id, unique within the voice's render history.
    pub event_id: String,
    /// When the decision was made, in unix seconds.
    pub occurred_at: u64,
    /// The farthest render target a grant lets the refs reach.
    pub reach: ModelLocality,
    /// Whether the voice is the actor's own real voice (`person`, when
    /// absent) or a designed one they created (`designed`). The bank binds
    /// it when it first holds the voice; a person's voice takes the person's
    /// own proof.
    #[serde(default = "VoiceRefSubjectKind::input_default")]
    pub subject_kind: VoiceRefSubjectKind,
    /// How a person's decision was captured; a designed voice's needs none.
    #[serde(default)]
    pub basis: Option<VoiceConsentBasis>,
    pub state: VoiceConsentState,
}

/// What a render decision recorded: its state, reach, revision and event id,
/// its place in the voice's render history, whether it replays a decision
/// already recorded, and each target clone this call dropped. The revision
/// and sequence are the original decision's on a replay, which drops none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentReceipt {
    pub voice_id: String,
    pub state: VoiceConsentState,
    pub reach: ModelLocality,
    /// Lowercase hex.
    pub revision: String,
    pub event_id: String,
    /// From 1, in the order the voice's decisions were recorded.
    pub sequence: u64,
    pub replayed: bool,
    pub evicted: Vec<VoiceVendorEviction>,
}

/// One target clone a withdrawal dropped, and what its vendor did with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceVendorEviction {
    pub target: String,
    pub vendor_voice_id: String,
    pub vendor: VoiceVendorDeleteStatus,
}

/// What a vendor did with a clone the bank dropped. The bank drops its
/// pointer first, so a clone the vendor kept is no current clone of the
/// voice, whatever this says. The voice's render history keeps the dropped
/// pointer, not this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceVendorDeleteStatus {
    /// The vendor deleted the clone, or it was already gone.
    Deleted,
    /// No configured clone wire reaches the target now: the clone may
    /// remain at the vendor.
    NoCloneWire,
    /// The vendor's delete failed: the clone may remain at the vendor.
    DeleteFailed,
    /// The bank held no clone pointer for the target.
    Absent,
}

/// `vault.voices.targets.provision`'s input: the voice and the configured
/// hosted target to clone it at. The target's locality is the host's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetProvisionRequest {
    pub voice_id: String,
    pub target: String,
    /// Whether generated packs join the source packs the clone is made from.
    #[serde(default)]
    pub include_generated: bool,
    /// The language the clips are spoken in, for a target that asks.
    #[serde(default)]
    pub language: Option<String>,
}

/// A target's current clone: the vendor's locator, when it was made, and
/// its fresh revision (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetReceipt {
    pub voice_id: String,
    pub target: String,
    pub vendor_voice_id: String,
    /// Unix seconds.
    pub cloned_at: u64,
    pub revision: String,
    /// The vendor holds the clone until the voice is verified there: no
    /// finished clone yet (FIX 1567, FIX 11479).
    pub awaiting_verification: bool,
}

/// `vault.voices.targets.evict`'s input: the voice and the target whose
/// clone to drop. The identity and its packs stay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetEvictRequest {
    pub voice_id: String,
    pub target: String,
}

/// What an eviction dropped: whether the bank held a clone pointer, and what
/// its vendor did with the clone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetEvictReceipt {
    pub voice_id: String,
    pub target: String,
    pub evicted: bool,
    pub vendor: VoiceVendorDeleteStatus,
}

/// `vault.voices.inspect`'s input: the voice, and the target to read it
/// for: a hosted target's current clone, a reference target's fence, or a
/// target this host does not render (FIX 4394).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankInspectRequest {
    pub voice_id: String,
    pub target: String,
    /// Whether the selection the clone is checked against counts generated
    /// packs, as the provisioning that made it did.
    #[serde(default)]
    pub include_generated: bool,
}

/// `vault.voices.lineage`'s input: the voice whose render history to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderLineageRequest {
    pub voice_id: String,
}
