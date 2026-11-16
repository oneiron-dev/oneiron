//! Moved from `crates/oneiron/src/verbs/host/pack_setup.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::pack_catalog::setup_session::PackSetupAnswer;
use oneiron_lens_wire::lens::generated_ui::GeneratedUiStateSnapshot;
use serde::Deserialize;
use serde::Serialize;

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
    /// secrets door), `bind_key`, or `allow`, which is the owner's own
    /// decision: this verb puts it to the owner as an ask.
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
