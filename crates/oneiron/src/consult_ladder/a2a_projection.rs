//! A2A wire projection over ladder terminal state.

use super::{
    ConsultLadderState, ConsultLineage, ConsultLineageRelation, LadderTerminalDisposition,
    LadderTerminalState,
};
use crate::entity_id::EntityId;

/// The five base A2A task states this projection targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2aBaseTaskState {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

impl A2aBaseTaskState {
    /// The A2A wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::InputRequired => "input-required",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The Oneiron extension fields a projected task carries. Oneiron's terminal
/// vocabulary is RICHER than A2A's, so the difference rides here rather than
/// being flattened into a base state that would lose it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OneironA2aExtensions {
    pub terminal_disposition: Option<String>,
    pub result_ref: Option<String>,
    pub counter_of: Option<String>,
    pub interruption_kind: Option<String>,
    /// ONE-1896. A2A has one `cancelled` token and no landing at all, so the
    /// two-rung protocol's distinctions ride here: `requested` (asked, still
    /// working), `rejected` (refused, still working), `landing` (accepted,
    /// finishing), `landed` (stopped by design), `forced` (hard stop). Without
    /// this a peer cannot tell a designed landing from a kill, and both would
    /// read as work that simply stopped.
    pub cancel_mode: Option<String>,
    /// Why the landing was triggered, when one is under way.
    pub landing_trigger: Option<String>,
    /// The exact point a successor resumes from, once recorded.
    pub resume_point: Option<String>,
    /// The durable artifact a successor should read FIRST, when the recorded
    /// resume point named one.
    ///
    /// Additive and defaulted, and carried beside the marker rather than
    /// folded into it: a successor that receives only the cursor has lost the
    /// identity of the work already produced and would redo it. This is a
    /// REFERENCE, never a payload body — the artifact stays opaque to the peer
    /// exactly as internal plans and tool calls do.
    pub resume_artifact_ref: Option<String>,
    /// Soft requests the worker has refused. Non-zero is the pathology signal
    /// a peer can act on without reading Oneiron's durable rows.
    pub cancel_rejections: u32,
}

/// One consult TASK projected onto A2A task vocabulary.
///
/// This is a PROJECTION for future adapters, not a conformance claim and not
/// an A2A server or client. Internal plans, prompts, and tool calls stay
/// opaque, exactly as RESEARCH-0254 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A2aTaskProjection {
    pub id: String,
    pub state: A2aBaseTaskState,
    pub extensions: OneironA2aExtensions,
}

/// Projects one ladder state onto A2A task vocabulary.
///
/// `Rejected` is a COMPLETED decision carrying `oneiron.terminal_disposition
/// = "rejected"`, never A2A `failed`; a counter is a NEW projected task
/// carrying `oneiron.counter_of`.
#[must_use]
pub fn project_to_a2a(
    task_ref: EntityId,
    state: &ConsultLadderState,
    lineage: Option<ConsultLineage>,
) -> A2aTaskProjection {
    let (base, mut extensions) = match state {
        ConsultLadderState::Working(_) => {
            (A2aBaseTaskState::Working, OneironA2aExtensions::default())
        }
        ConsultLadderState::Interrupted(interrupted) => (
            if interrupted.consent_required {
                A2aBaseTaskState::InputRequired
            } else {
                // Still progressing on the Oneiron side; no human input is
                // being waited on, so the base state stays `working` and the
                // reason rides the extension.
                A2aBaseTaskState::Working
            },
            OneironA2aExtensions {
                interruption_kind: Some(interrupted.kind.as_str().to_owned()),
                ..OneironA2aExtensions::default()
            },
        ),
        ConsultLadderState::Terminal(terminal) => a2a_terminal(terminal),
    };
    if let Some(lineage) = lineage
        && lineage.relation == ConsultLineageRelation::Counter
    {
        extensions.counter_of = Some(lineage.parent_task_ref.to_hex());
    }
    A2aTaskProjection {
        id: task_ref.to_hex(),
        state: base,
        extensions,
    }
}

fn a2a_terminal(terminal: &LadderTerminalState) -> (A2aBaseTaskState, OneironA2aExtensions) {
    let base = match terminal.disposition {
        LadderTerminalDisposition::Approved
        | LadderTerminalDisposition::Overridden
        // A rejection and a counter are DECISIONS that completed, not
        // failures. Mapping either onto A2A `failed` would tell a peer the
        // machine broke when the owner actually answered.
        | LadderTerminalDisposition::Rejected
        | LadderTerminalDisposition::Countered => A2aBaseTaskState::Completed,
        LadderTerminalDisposition::Failed => A2aBaseTaskState::Failed,
        // Awaiting the follow-on assignee named in the escalation receipt.
        LadderTerminalDisposition::Escalated => A2aBaseTaskState::InputRequired,
        LadderTerminalDisposition::Abandoned => A2aBaseTaskState::Cancelled,
    };
    let disposition = match terminal.disposition {
        // The OLD side of a counter reads as the rejection it is; the counter
        // link rides the NEW task's `counter_of` and this task's result_ref.
        LadderTerminalDisposition::Countered => LadderTerminalDisposition::Rejected,
        other => other,
    };
    (
        base,
        OneironA2aExtensions {
            terminal_disposition: Some(disposition.as_str().to_owned()),
            result_ref: Some(terminal.result_ref.to_hex()),
            ..OneironA2aExtensions::default()
        },
    )
}
