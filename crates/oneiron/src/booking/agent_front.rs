//! ONE-1816 [BK-05] the agent front.
//!
//! One turn in, one surface out. There is no chat loop and no text-to-commit
//! path: the model may parse scheduling constraints and nothing else, the
//! deterministic oracle chooses the times, and a program-generated button
//! carries the only slot action.

use crate::error::Error;
use crate::lens::{
    ButtonControl, GeneratedUiCard, LensAtom, LensAtomId, LensNode, LensRenderId, LensText,
    SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOptionValue, SelfUiValue,
    VoiceLineAtom,
};
use crate::llm::{BudgetLease, LlmBackend};
use crate::temporal::TimeRange;

use super::constraint::{
    BookingError, ConstraintObject, ConstraintParseConfig, ConstraintParseDisposition,
    ConstraintParseRequest, ConstraintSessionCaps, ConstraintSessionState, EventTypeKey,
    RankedSlot, SlotOracle, SolveRequest, SolveResult, parse_constraint_with_backend,
    validate_visitor_tz,
};

/// The only action a proposed slot can carry. Air Canada law: commit is ALWAYS
/// a button, never text, model output, a voice line, or a deflect.
pub const BOOKING_SLOT_BUTTON_ACTION: &str = "booking.select_slot";

/// Most slot buttons a single reply renders.
const MAX_RENDERED_SLOTS: usize = 3;

/// Bound on the opaque per-session reference.
const MAX_SESSION_REF_BYTES: usize = 128;

/// The complete capability set exposed to the model side of this front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintAgentCapability {
    ReadMask,
    Propose,
}

/// Read the mask, propose from it. Nothing holds, confirms, cancels, or sends.
pub const CONSTRAINT_AGENT_CAPABILITIES: [ConstraintAgentCapability; 2] = [
    ConstraintAgentCapability::ReadMask,
    ConstraintAgentCapability::Propose,
];

/// Every visible string this front can emit. Host-supplied configuration and
/// the localization seam — never shipped prompt or persona text.
pub struct ConstraintFrontCopy {
    pub speaker: String,
    pub slots_line: String,
    pub no_fit_line: String,
    pub off_topic_line: String,
}

impl ConstraintFrontCopy {
    fn validate(&self) -> Result<(), BookingError> {
        for (field, value) in [
            ("speaker", &self.speaker),
            ("slots_line", &self.slots_line),
            ("no_fit_line", &self.no_fit_line),
            ("off_topic_line", &self.off_topic_line),
        ] {
            if value.trim().is_empty() {
                return Err(BookingError::InvalidConfig(format!(
                    "constraint front copy {field} must be configured"
                )));
            }
        }
        Ok(())
    }
}

/// One visitor turn.
pub struct ConstraintTurnRequest {
    pub session_ref: String,
    pub event_type: EventTypeKey,
    pub window: TimeRange,
    pub detected_visitor_tz: String,
    pub free_text: String,
}

/// Slots the oracle chose, plus the card that renders them.
pub struct ConstraintSlotReply {
    /// Everything the oracle returned, untouched.
    pub solve_result: SolveResult,
    /// Exactly one `VoiceLineAtom` plus one `ButtonControl` per rendered slot.
    pub card: GeneratedUiCard,
}

/// The rung-2 envelope. It carries the same canonical constraint the oracle
/// saw and no raw free text.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ConstraintContinuation {
    pub event_type: EventTypeKey,
    pub visitor_tz: String,
    pub constraint: ConstraintObject,
    pub session_ref: String,
}

/// One structured scheduling-only deflect. It has no controls, so it cannot
/// carry an action of any kind.
pub struct ConstraintDeflect {
    pub card: GeneratedUiCard,
}

/// The three terminal shapes of a turn.
pub enum ConstraintFrontOutcome {
    Slots(ConstraintSlotReply),
    ContinueByEmail(ConstraintContinuation),
    Deflect(ConstraintDeflect),
}

/// Run one turn: admit, parse once, solve, render.
///
/// Admission is checked before an LLM request is built or sent AND before the
/// oracle is called, so an exhausted session costs neither a model call nor a
/// solve.
// The eight parameters are the ratified seam signature: oracle, backend, and
// lease are injected host capabilities, and config/caps/state/copy are the four
// independent dials. Bundling them would hide the capability boundary this
// ticket exists to make visible.
#[allow(clippy::too_many_arguments)]
pub async fn run_constraint_turn(
    oracle: &dyn SlotOracle,
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    parse_config: &ConstraintParseConfig,
    caps: &ConstraintSessionCaps,
    state: &mut ConstraintSessionState,
    copy: &ConstraintFrontCopy,
    request: ConstraintTurnRequest,
) -> Result<ConstraintFrontOutcome, BookingError> {
    copy.validate()?;
    validate_session_ref(&request.session_ref)?;
    validate_visitor_tz(&request.detected_visitor_tz)?;
    if request.window.start >= request.window.end {
        return Err(BookingError::InvalidConstraint(
            "booking window must satisfy start < end".to_owned(),
        ));
    }

    state.admit_turn(caps)?;
    state.admit_model_call(caps)?;

    let disposition = parse_constraint_with_backend(
        backend,
        lease,
        &ConstraintParseRequest {
            free_text: request.free_text,
            detected_visitor_tz: request.detected_visitor_tz.clone(),
            now_utc: request.window.start,
        },
        parse_config,
    )
    .await?;

    let (constraint, visitor_tz_override) = match disposition {
        // Terminal: one configured deflect, no solve and no second turn.
        ConstraintParseDisposition::OffTopic => {
            return Ok(ConstraintFrontOutcome::Deflect(ConstraintDeflect {
                card: deflect_card(&request.session_ref, copy)?,
            }));
        }
        ConstraintParseDisposition::Constraint {
            object,
            visitor_tz_override,
        } => (object, visitor_tz_override),
    };

    let visitor_tz = visitor_tz_override.unwrap_or(request.detected_visitor_tz);

    let solve_result = oracle.solve(&SolveRequest {
        event_type: request.event_type.clone(),
        window: request.window,
        constraint: Some(constraint.clone()),
        visitor_tz: visitor_tz.clone(),
    })?;

    if solve_result.slots.is_empty() {
        return Ok(ConstraintFrontOutcome::ContinueByEmail(
            ConstraintContinuation {
                event_type: request.event_type,
                visitor_tz,
                constraint,
                session_ref: request.session_ref,
            },
        ));
    }

    let rendered = top_ranked_slots(&solve_result.slots);
    let card = slots_card(&request.session_ref, copy, &rendered)?;
    Ok(ConstraintFrontOutcome::Slots(ConstraintSlotReply {
        solve_result,
        card,
    }))
}

/// The oracle owns both the times and their order. When it returns more than
/// [`MAX_RENDERED_SLOTS`], keep the top-ranked three and preserve the oracle's
/// relative order among them. Nothing is invented, rewritten, or rounded.
fn top_ranked_slots(slots: &[RankedSlot]) -> Vec<&RankedSlot> {
    if slots.len() <= MAX_RENDERED_SLOTS {
        return slots.iter().collect();
    }
    let mut by_rank: Vec<usize> = (0..slots.len()).collect();
    by_rank.sort_by(|left, right| {
        slots[*right]
            .rank
            .total_cmp(&slots[*left].rank)
            .then(left.cmp(right))
    });
    by_rank.truncate(MAX_RENDERED_SLOTS);
    by_rank.sort_unstable();
    by_rank.into_iter().map(|index| &slots[index]).collect()
}

fn validate_session_ref(value: &str) -> Result<(), BookingError> {
    if value.is_empty() || value.len() > MAX_SESSION_REF_BYTES {
        return Err(BookingError::InvalidConstraint(format!(
            "session ref must be 1..={MAX_SESSION_REF_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BookingError::InvalidConstraint(
            "session ref must use only ASCII alnum, '.', '_', or '-'".to_owned(),
        ));
    }
    Ok(())
}

fn slots_card(
    session_ref: &str,
    copy: &ConstraintFrontCopy,
    slots: &[&RankedSlot],
) -> Result<GeneratedUiCard, BookingError> {
    let mut root = voice_node(copy, &copy.slots_line)?;
    for (index, slot) in slots.iter().enumerate() {
        root.children.push(slot_button_node(index, slot)?);
    }
    card(session_ref, root)
}

fn deflect_card(
    session_ref: &str,
    copy: &ConstraintFrontCopy,
) -> Result<GeneratedUiCard, BookingError> {
    // No children: a deflect structurally cannot offer a control.
    card(session_ref, voice_node(copy, &copy.off_topic_line)?)
}

fn card(session_ref: &str, root: LensNode) -> Result<GeneratedUiCard, BookingError> {
    GeneratedUiCard::card(
        surface(LensRenderId::new(format!("booking-{session_ref}")))?,
        root,
    )
    .map_err(surface_error)
}

fn voice_node(copy: &ConstraintFrontCopy, line: &str) -> Result<LensNode, BookingError> {
    Ok(LensNode::new(
        surface(LensAtomId::new("booking-voice"))?,
        LensAtom::VoiceLine(VoiceLineAtom {
            speaker: surface(LensText::new(copy.speaker.clone()))?,
            text: surface(LensText::new(line.to_owned()))?,
            vad: None,
        }),
    ))
}

/// One program-generated button per slot. The label and the action arguments
/// are derived from the oracle's own UTC integers, so the surface formats the
/// time and the engine ships no user-facing English.
fn slot_button_node(index: usize, slot: &RankedSlot) -> Result<LensNode, BookingError> {
    Ok(LensNode::new(
        surface(LensAtomId::new(format!("booking-slot-{index}")))?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: surface(SelfUiControlId::new(format!("booking-slot-{index}")))?,
            label: surface(LensText::new(format!(
                "{}-{}",
                slot.start_utc, slot.end_utc
            )))?,
            action: SelfUiAction {
                command: surface(SelfUiActionId::new(BOOKING_SLOT_BUTTON_ACTION))?,
                args: vec![
                    SelfUiValue::Token(surface(SelfUiOptionValue::new(
                        slot.start_utc.to_string(),
                    ))?),
                    SelfUiValue::Token(surface(SelfUiOptionValue::new(slot.end_utc.to_string()))?),
                ],
            },
        })),
    ))
}

fn surface<T>(result: Result<T, Error>) -> Result<T, BookingError> {
    result.map_err(surface_error)
}

fn surface_error(error: Error) -> BookingError {
    BookingError::Surface(error.to_string())
}
