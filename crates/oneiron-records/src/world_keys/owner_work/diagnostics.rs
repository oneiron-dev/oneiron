//! Moved from `crates/oneiron/src/world_keys/owner_work/diagnostics.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::world_keys::bundle::carrier::UnmergedSection;
use oneiron_authority::authority::WorldKeyId;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::world_keys::owner_work::diagnostics::BundleHomeWarning;
use serde::Serialize;

/// What blocks one key of a re-assertion on its executor (FIX 4686).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReassertKeyState {
    /// Every recipient the settings allow holds a counted wrap of it.
    Wrapped,
    /// It opens here and `missing` recipients lack a counted wrap: the next
    /// pickup wraps them, unless the world's frontier proves too wide.
    WrapsPending { missing: usize },
    /// No pad of it is here.
    MissingPad,
    /// No record of this install's own, and no counted wrap to it, opens it
    /// here.
    NoOpeningRecordOrWrap,
    /// It opens here, but a record wrapping it to the recipients that lack a
    /// wrap would name more rows than one record may (OF-520), by the
    /// writer's own plan of this key for this request on this install's
    /// durable state (FIX 5552): the world's settings need merging from one
    /// machine that sees every edit.
    FrontierNeedsSplit,
    /// Counted records named other bytes or another owner for it: the
    /// re-assertion leaves it as it is.
    Conflicted,
    /// The fold holds it, but no record of this install's own names it here:
    /// the re-assertion does not reach it from this install, and whether this
    /// install wrapped it before is not known here.
    UnknownHistory,
}

/// One key of a re-assertion and its state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReassertKey {
    pub key: WorldKeyId,
    #[serde(flatten)]
    pub state: ReassertKeyState,
}

/// Why the executor's read checks could not run here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReassertUnread {
    /// This install's machine secret does not load: the pickup leaves the
    /// work pending for the same reason.
    NoMachineSecret,
    /// This install is no eligible reader mine here under its install key,
    /// or its identity or key changed: its next pickup answers the request.
    NotMineReader,
}

/// The world's current key on the executor, as the ensure step finds it
/// (FIX 5552): the step that follows once every key of a re-assertion is
/// wrapped again, and all an Ensure request does. Recomputed from this
/// install's durable state on every read; nothing is minted or wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnsureView {
    /// The world's current key here. `None` when it has none here and the
    /// ensure mints its first key: then `WrapsPending` counts every recipient
    /// its first records wrap to, and `FrontierNeedsSplit` says one record
    /// cannot name them all, so its record wraps to this install and the
    /// pinned root alone and the other readers wait for the world's settings
    /// to merge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<WorldKeyId>,
    #[serde(flatten)]
    pub state: ReassertKeyState,
}

/// A world's key work in Ensure mode on its executor (FIX 5552).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnsureDiagnostics {
    pub world: EntityId,
    /// Why the read checks did not run; `None` when they did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<ReassertUnread>,
    /// The world reads everywhere: it counts no key, and nothing blocks the
    /// ensure.
    pub reads_everywhere: bool,
    /// A door on this handle raised OF-520's question for this world since
    /// the handle opened: history, as a re-assertion's.
    pub question_raised: bool,
    /// The world's current key, or the first one the ensure would mint;
    /// `None` when the read checks did not run or the world reads everywhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensure: Option<EnsureView>,
}

/// What a relay pass found when it went for a publication's home (FIX
/// 4784). It never decides who executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishReach {
    /// The pass reached the home the request names, its proof standing here.
    Reached,
    /// The pass reached another home: this install's relay syncs with a home
    /// the request does not name.
    OtherHome,
    /// The pass reached a home whose proof does not stand here.
    HomeUnproven,
    /// The pass reached no home: offline, or the connection did not come up.
    Offline,
    /// The home refused the pass's bind, or answered in a shape it did not
    /// take.
    Refused,
}

/// The exact attempt an executor persisted before its commit and has not
/// resolved (FIX 4787): the generation and the sealed bundle's ciphertext
/// digest, each in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishAttemptView {
    pub generation: String,
    pub bundle_digest: String,
}

/// The last upload this install assembled for a publication's home, by
/// that request or the slot's own, as the relay observation keeps it (FIX
/// 19525): shown only when it carries a readable section unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnmergedUploadView {
    /// The vault second it was assembled, or restored from its committed
    /// attempt.
    pub at: u64,
    /// The generation it seals, in hex.
    pub generation: String,
    /// Each section of the home's newest generation it carries unchanged
    /// because the section did not open, decode or merge here: the
    /// erased-actor cleanup did not run on it, and the owner repairs it.
    pub unmerged_sections: Vec<UnmergedSection>,
}
