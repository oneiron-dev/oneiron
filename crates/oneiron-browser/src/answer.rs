//! What the run's door adds to a guest's answer (CUA-001): the record of a
//! person's takeover that ended, and the agent's move to another tab or
//! window, each once, on the agent's next answer, and, on every browser
//! answer, the engine that ran it (FIX 6680). A driver's own answer carries
//! none of them; the door writes them beside the answer's own fields, and
//! these types declare them, so a program reads them typed.

use crate::{BrowserEngine, DemonstrationOutput, TabSwitch};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One takeover as its receipt keeps it: who held the desktop, what the
/// agent had asked, when they took and returned it, and how many inputs
/// they sent. No screenshot: none was taken for the agent meanwhile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TakeoverRecord {
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    pub taken_at_ms: u64,
    pub returned_at_ms: u64,
    pub inputs: u64,
    /// The host's refusal of a page request the person's own input made,
    /// still pending when they handed the browser back (FIX 7409): theirs,
    /// never the answer to an act of the agent's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<crate::DestinationRefusal>,
}

/// The desktop's verbs moved to another window (CUA-001): an act opened a
/// window in front (a dialog, a document), or the window they read is gone
/// (a dialog closed, an app quit) and the session gave way to the window in
/// front. The next answer carries it once, as `switched`; moves before that
/// answer join into one, from the window the agent was last told of, with
/// the last move's `why`. The observations held were of the window before,
/// so the next observation is whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowSwitch {
    /// The window the desktop's verbs read now, as `windows` names it.
    pub window: String,
    /// Its app and title when the switch found it.
    pub app: String,
    pub title: String,
    /// The window they read before.
    pub from: String,
    pub why: WindowSwitchCause,
}

/// Why the desktop's verbs moved to another window, as a browser tab's
/// move says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WindowSwitchCause {
    /// An act opened a window in front.
    Opened,
    /// The window they read is gone.
    Closed,
}

/// A browser verb's answer as the run's door gives it: the verb's own
/// answer, the engine that ran it, and, once each, the takeover a person
/// ended and the agent's move to another tab since its last answer.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BrowserAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    /// The takeover that ended since the agent's last answer: its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverRecord>,
    /// The agent's verbs moved to another tab since its last answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched: Option<TabSwitch>,
    /// The engine the browser ran this verb on, read verbs included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<BrowserEngine>,
    /// A demonstration that ended since the agent's last answer without
    /// its stop (a handover, an engine switch, a lost guest), once, its
    /// draft naming no subgoal and no checks (CUA E9a); a person's span an
    /// opted-in handover recorded, as their handback drafted it (CUA E9b).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demonstration: Option<DemonstrationOutput>,
    /// The guest session's manifest, as the run's door adds it to every
    /// answer (FIX 5705).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_manifest: Option<SessionManifest>,
}

impl<T> BrowserAnswer<T> {
    /// The verb's own `answer`, as its driver gives it; the door adds the
    /// rest.
    #[must_use]
    pub fn of(answer: T) -> Self {
        Self {
            answer,
            takeover: None,
            switched: None,
            engine: None,
            demonstration: None,
            session_manifest: None,
        }
    }
}

/// A desktop verb's answer as the run's door gives it: the verb's own
/// answer, and, once each, the takeover a person ended and the agent's move
/// to another window since its last answer.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DesktopAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    /// The takeover that ended since the agent's last answer: its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverRecord>,
    /// The agent's verbs moved to another window since its last answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched: Option<WindowSwitch>,
    /// The guest session's manifest, as the run's door adds it to every
    /// answer (FIX 5705).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_manifest: Option<SessionManifest>,
}

impl<T> DesktopAnswer<T> {
    /// The verb's own `answer`, as its driver gives it; the door adds the
    /// rest.
    #[must_use]
    pub fn of(answer: T) -> Self {
        Self {
            answer,
            takeover: None,
            switched: None,
            session_manifest: None,
        }
    }
}

/// What a guest session proved about its fence, as the run's door names it
/// on every answer (FIX 5705): the container's own session manifest, as it
/// reads on the wire. The door sends that manifest; this is its shape. Its
/// guest-image release evidence (FIX 8253) rides beside these fields,
/// undeclared here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionManifest {
    pub backend: String,
    pub runtime: String,
    pub image: String,
    /// blake3 of the full runtime argument list, so a receipt names its
    /// flags.
    pub argv_digest: String,
    pub network: String,
    pub seccomp: SessionSeccomp,
    pub generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_proof: Option<SessionFenceProof>,
    /// Non-Linux or explicitly unfenced sessions never claim isolation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fence_unproven: bool,
}

/// Evidence the session verified before its guest made its first network
/// call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionFenceProof {
    pub ruleset_hash: String,
    pub seccomp_hash: String,
    pub network_routes: Vec<String>,
    pub network_evidence_digest: String,
    pub sandbox_generation: String,
    pub launcher_digest: String,
}

/// How the guest's own system calls are filtered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionSeccomp {
    /// The runtime's default profile.
    RuntimeDefault,
    /// The guest program runs its own namespace and seccomp sandbox.
    GuestSandbox,
    /// Engine Landlock and seccomp user-notification launcher.
    EngineFence,
}
