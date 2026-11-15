//! `vault.check_in.preflight` and `vault.check_in.open` (ARCH-0082 #composing
//! and #ladder; ROLES-CHECKIN P2.3b, piece 2f; Engine ruling P23-SHAPE = A):
//! before an act, an agent asks whether it may run now, and opens the
//! durable ask when it waits.
//!
//! Both take the verb whose act would run, where its effect sits and the
//! effect's digest. The act class is the verb row's own, the power comes
//! from the caller's own live owner Grant that lists the verb and the role
//! from the caller's live membership row on that Grant's vault, else the
//! Grant's own (or the caller is the vault owner), and the answer is go,
//! wait, propose, absent or unstated ([`CheckInVerdict`]); see
//! `crate::check_in::asker`.
//!
//! * `preflight` (a read, `read`) writes nothing. A wait names the handle
//!   only when the same saved call is already open.
//! * `open` (a write, `reversible_work`) opens the pending check-in when
//!   the act waits: its one write is the caller's own row and its `check_in`
//!   receipts, which let go at `until` and go with the asker's erase. A
//!   repeat of the same saved call (asker, verb, act class, scope, effect
//!   digest) returns the same handle and writes nothing (Q2 = A); an ask
//!   that let go, or whose act already ran, is asked afresh. Any other
//!   answer opens nothing.
//!
//! * `answer` (P2.3c, piece 2l; a write, `unstated`) settles one open ask:
//!   a person pinned on its current rung approves or denies the exact effect
//!   it waits on, on their own human proof, while their live grant and their
//!   own check-in still admit the act (`VerifiedChain::may_answer`). The
//!   first answer settles it, with one `answered` receipt; the same person's
//!   same answer over the same effect again returns that settlement and
//!   writes nothing; any other answer to a settled ask is refused, naming who
//!   answered to a person the ask pinned (Q8 = A). The answer claims no
//!   consent marker (Q7 = A). An inquiry's check-in is answered through its
//!   own verb, which settles the inquiry with it.
//!
//! No verb reads a handle back but a repeat `open` (Q11 = A); the act's own
//! gate that waits on a handle is PR 3.

use serde::{Deserialize, Serialize};

use crate::check_in::{
    AskVerdict, CheckInScope, HolderAnswer, HolderReply, NoAgentVerdict, OpenPendingCheckIn,
    PendingCheckIn, PendingState, ProofKind, VerifiedChain, answer_pending_check_in_in_txn,
    judge_ask_in_txn, keyed_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn,
    pending_check_in_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult,
};
use crate::store::GateDecisionId;
use crate::{EntityId, Vault};

/// The verb name, in its refusals.
const ANSWER_VERB: &str = "vault.check_in.answer";

/// `vault.check_in.preflight` input: the act an agent would run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInPreflightRequest {
    /// The verb whose act would run, as its row names it.
    pub verb: String,
    /// The world the effect sits in, by its id; none for the whole vault.
    #[serde(default)]
    pub world_ref: Option<String>,
    /// The project the effect sits in, by its id.
    #[serde(default)]
    pub project_ref: Option<String>,
    /// The digest of the exact effect, 64 hex. An answer settles this
    /// effect and no other.
    pub effect_digest: String,
}

/// `vault.check_in.open` input: the act an agent would run, and how long it
/// waits for an answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInOpenRequest {
    /// The verb whose act would run, as its row names it.
    pub verb: String,
    /// The world the effect sits in, by its id; none for the whole vault.
    #[serde(default)]
    pub world_ref: Option<String>,
    /// The project the effect sits in, by its id.
    #[serde(default)]
    pub project_ref: Option<String>,
    /// The digest of the exact effect, 64 hex. An answer settles this
    /// effect and no other.
    pub effect_digest: String,
    /// The asker's cutoff (Unix seconds): at it the ask lets go and nothing
    /// happens.
    #[serde(default)]
    pub until: Option<u64>,
    /// The asker's longer wait per person rung, in seconds; never under the
    /// act class's floor.
    #[serde(default)]
    pub wait_secs: Option<u64>,
    /// The act's domain undo, for an undoable act: when the chain ends in
    /// silence on an act asked when unsure, it may proceed with this undo;
    /// without one it holds.
    #[serde(default)]
    pub undo_plan: Option<String>,
}

/// What `vault.check_in.preflight` and `vault.check_in.open` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckInVerdict {
    /// The act may run now. `reason`: `read` (a read verb: the power is the
    /// whole check), `never_ask` or `own_proof`. `act_class`: none for a
    /// read verb.
    Go {
        reason: String,
        act_class: Option<String>,
    },
    /// The act waits for a proof from the ladder. `reason`: `always_ask`,
    /// `unsure`, `unsure_test_failed` or `model_not_allowed`; `mode` is the
    /// mode's wire token. `handle` is the durable ask: always on `open`; on
    /// `preflight` only when the same saved call is already open.
    Wait {
        reason: String,
        act_class: String,
        mode: String,
        handle: Option<Box<CheckInHandleView>>,
    },
    /// The caller lacks the power; a role it holds may propose the act to a
    /// holder.
    Propose { act_class: String },
    /// The caller lacks the power for this act; `why` says which check
    /// failed.
    Absent { why: String },
    /// The verb's row states no proven act class (`unstated`): nothing
    /// opens. Its default is ruled with the change path.
    Unstated,
}

/// One durable ask, as its asker reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckInHandleView {
    /// The pending check-in's id, 32 hex.
    pub handle: String,
    /// `open`, `answered`, `let_go`, `held`, `proceed_with_undo`,
    /// `window_passed` or `objection_held`.
    pub state: String,
    /// The holder's answer once answered: `approve` or `deny`.
    pub answer: Option<String>,
    /// Who answered, while the record names them.
    pub answered_by: Option<String>,
    /// The rung the ask entered last: `grantor`, `chain_holders` or
    /// `owner`.
    pub rung: Option<String>,
    /// The next instant a transition is due (Unix seconds); none once the
    /// ask is settled.
    pub next_due_at: Option<u64>,
    /// The asker's cutoff.
    pub until: Option<u64>,
    /// The basis on which the act may run: `approved`, `proceed_with_undo`
    /// or `window_passed`; none while it may not.
    pub eligible: Option<String>,
    /// Whether the act already ran on this ask.
    pub consumed: bool,
    /// Whether this call found the ask a call before it opened.
    pub repeat: bool,
}

/// `vault.check_in.preflight`: whether the caller's act may run now. Reads
/// one snapshot and writes nothing.
///
/// # Errors
///
/// BAD_REQUEST for a digest that is not 64 hex or a name no verb row has;
/// FORBIDDEN for a caller that is neither the live vault owner nor an agent;
/// storage errors.
pub fn check_in_preflight(
    memory: &Memory<'_>,
    input: CheckInPreflightRequest,
) -> MemoryResult<CheckInVerdict> {
    let effect_digest = digest_of(&input.effect_digest)?;
    let scope = CheckInScope {
        world_ref: input.world_ref,
        project_ref: input.project_ref,
    };
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let verdict = judge_ask_in_txn(memory, &txn, &input.verb, &scope)?;
    let handle = match &verdict {
        AskVerdict::Wait { asker, act, .. } => keyed_pending_check_in_in_txn(
            &vault.store,
            &txn,
            *asker,
            &input.verb,
            *act,
            &scope,
            &effect_digest,
        )?
        .map(|row| handle_view(&row, true)),
        _ => None,
    };
    Ok(verdict_view(verdict, handle))
}

/// `vault.check_in.open`: the caller's act, judged as `preflight` judges
/// it; when it waits, the pending check-in for it, opened in the same
/// writer, or the one the same saved call opened before.
///
/// # Errors
///
/// As [`check_in_preflight`]; an `until` already passed, a wait under the
/// act class's floor, or an undo plan for an act that is not undoable;
/// storage errors.
pub fn check_in_open(
    memory: &Memory<'_>,
    input: CheckInOpenRequest,
) -> MemoryResult<CheckInVerdict> {
    let effect_digest = digest_of(&input.effect_digest)?;
    let scope = CheckInScope {
        world_ref: input.world_ref,
        project_ref: input.project_ref,
    };
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|txn| {
        let verdict = judge_ask_in_txn(memory, txn, &input.verb, &scope)?;
        let AskVerdict::Wait {
            asker,
            grant,
            act,
            mode,
            reason,
        } = verdict
        else {
            return Ok(verdict_view(verdict, None));
        };
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let (row, opened) = open_keyed_pending_check_in_in_txn(
            vault,
            txn,
            OpenPendingCheckIn {
                asker,
                grant_ref: grant.to_hex(),
                verb: input.verb.clone(),
                act,
                scope: scope.clone(),
                effect_digest,
                mode,
                reason,
                asker_wait_secs: input.wait_secs,
                until: input.until,
                undo_plan: input.undo_plan.clone(),
                delay_window: None,
            },
            memory.invocation().map(|invocation| invocation.0),
            &VerifiedChain::new(&NoAgentVerdict),
            now,
        )?;
        Ok(verdict_view(verdict, Some(handle_view(&row, !opened))))
    })
}

/// `vault.check_in.answer` input: a holder's answer to one pending
/// check-in, over the exact effect it waits on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInAnswerRequest {
    /// The pending check-in's id, 32 hex, as `vault.check_in.open` named
    /// it.
    pub handle: String,
    /// `approve` or `deny`. A standing approval is no answer: it is a
    /// Grant the owner mints.
    pub answer: CheckInAnswerWord,
    /// The digest of the exact effect the answer is over, 64 hex: the one
    /// the ask waits on.
    pub effect_digest: String,
}

/// A holder's answer to a pending check-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckInAnswerWord {
    /// The act may run, over this effect, once.
    Approve,
    /// The act does not run.
    Deny,
}

impl CheckInAnswerWord {
    const fn holder_answer(self) -> HolderAnswer {
        match self {
            Self::Approve => HolderAnswer::Approve,
            Self::Deny => HolderAnswer::Deny,
        }
    }

    const fn from_holder_answer(answer: HolderAnswer) -> Self {
        match answer {
            HolderAnswer::Approve => Self::Approve,
            HolderAnswer::Deny => Self::Deny,
        }
    }
}

/// What `vault.check_in.answer` answers: the settlement of the ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckInSettlement {
    /// The pending check-in's id, 32 hex.
    pub handle: String,
    pub answer: CheckInAnswerWord,
    /// Who answered, while the record names them.
    pub answered_by: Option<String>,
    /// The rung the answer was given on: `grantor`, `chain_holders` or
    /// `owner`.
    pub rung: String,
    /// When the answer landed (Unix seconds).
    pub answered_at: u64,
    /// The proof the answer is: `human_confirm`, the holder's
    /// authenticated confirm.
    pub proof_kind: String,
    /// `approved` once approved: the act may run once over this effect;
    /// none after a denial.
    pub eligible: Option<String>,
    /// Whether this call found the same answer already given, and wrote
    /// nothing.
    pub repeat: bool,
}

/// `vault.check_in.answer` on an embedded handle: its own actor answers as
/// the person it is. A handle bound to the slip its caller presented
/// answers on that slip, bound to their proof; any other handle a transport
/// reached is refused, as is an actor that is not a live person.
///
/// # Errors
///
/// As [`check_in_answer_as_person`]; FORBIDDEN for an actor that is not a
/// live person on their own proof.
pub fn check_in_answer(
    memory: &Memory<'_>,
    input: CheckInAnswerRequest,
) -> MemoryResult<CheckInSettlement> {
    if memory.actor_class() != EdgeActorClass::Human {
        return Err(not_a_person());
    }
    let vault = memory.vault();
    let actor = memory.actor();
    let person = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(|_| not_a_person())?;
    let person = match memory.presented_credential() {
        Some(slip) => vault.bind_person_credential(person, slip.clone())?,
        None if memory.native_invocation() => person,
        None => return Err(not_a_person()),
    };
    check_in_answer_as_person(vault, &person, input)
}

/// `vault.check_in.answer` under `person`'s proof: the server's door, and
/// the embedded one's. In one writer it rechecks the proof, then settles the
/// open ask `handle` names with the answer over `effect_digest`
/// ([`answer_pending_check_in_in_txn`]: the exact effect, a person pinned on
/// the current rung whose wait has not ended, and the chain's live recheck
/// of their grant and own check-in), or, on a settled ask, echoes the same
/// person's same answer.
///
/// # Errors
///
/// BAD_REQUEST for a handle that is not 32 hex or a digest that is not 64
/// hex; NOT_FOUND for no such ask; FORBIDDEN for a dead proof, an inquiry's
/// ask, a person the ask does not pin now, another effect, an ask past its
/// `until` or its delay window, or a holder whose grant or own check-in no
/// longer admits the act; INVALID_STATE for a settled ask the same answer
/// does not echo; storage errors.
pub fn check_in_answer_as_person(
    vault: &Vault,
    person: &AuthenticatedOwner,
    input: CheckInAnswerRequest,
) -> MemoryResult<CheckInSettlement> {
    let id = EntityId::from_hex(&input.handle).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "handle is not 32 hex",
            &["Pass the handle vault.check_in.open answered, as 32 hex characters."],
        )
    })?;
    let effect_digest = digest_of(&input.effect_digest)?;
    let answer = input.answer.holder_answer();
    vault.try_with_write_txn_grouped(|txn| {
        let row = pending_check_in_in_txn(&vault.store, txn, &id)?.ok_or(Error::EntityNotFound)?;
        if row.verb == crate::inquiry::INQUIRY_ANSWER_VERB {
            return Err(answer_refused(
                "an inquiry's check-in is answered through vault.inquiry.answer",
            ));
        }
        if row.state != PendingState::Open {
            let by = person.revalidate_person_in_txn(vault, txn)?;
            return settled_answer(&row, by, answer, &effect_digest);
        }
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let row = answer_pending_check_in_in_txn(
            vault,
            txn,
            person,
            &id,
            HolderReply {
                effect_digest,
                answer,
            },
            &VerifiedChain::new(&NoAgentVerdict),
            now,
        )
        .map_err(|error| match error {
            Error::InvalidConfig(rule) => {
                answer_refused(rule.strip_prefix("check_in: ").unwrap_or(&rule))
            }
            other => other.into(),
        })?;
        settlement(&row, false)
    })
}

/// A settled ask's answer to `by`'s `answer` over `effect_digest`: the
/// recorded settlement when it is that same answer, else a refusal naming
/// who answered to a person the ask pinned, and naming nobody to anyone
/// else.
fn settled_answer(
    row: &PendingCheckIn,
    by: EntityId,
    answer: HolderAnswer,
    effect_digest: &[u8; 32],
) -> MemoryResult<CheckInSettlement> {
    if let PendingState::Answered {
        answer: given,
        by: Some(holder),
        ..
    } = &row.state
        && *holder == by
        && *given == answer
        && row.effect_digest == *effect_digest
    {
        return settlement(row, true);
    }
    let pinned = row
        .rungs
        .iter()
        .any(|entry| entry.holders.iter().any(|holder| holder.principal == by));
    if !pinned {
        return Err(answer_refused(
            "only a person pinned on the current rung answers",
        ));
    }
    let settled = match &row.state {
        PendingState::Answered {
            answer: given,
            by: holder,
            ..
        } => format!(
            "{} answered {}",
            holder.map_or_else(
                || "a holder whose record is erased".to_owned(),
                |holder| holder.to_hex()
            ),
            given.as_str()
        ),
        other => format!("it settled as {}", state_token(other)),
    };
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{ANSWER_VERB}: the check-in is settled: {settled}"),
        &["Read the settlement; a settled check-in takes no other answer."],
    ))
}

fn settlement(row: &PendingCheckIn, repeat: bool) -> MemoryResult<CheckInSettlement> {
    let PendingState::Answered {
        answer,
        by,
        rung,
        at,
    } = &row.state
    else {
        return Err(Error::InvariantViolation("an answered check-in").into());
    };
    Ok(CheckInSettlement {
        handle: row.id.to_hex(),
        answer: CheckInAnswerWord::from_holder_answer(*answer),
        answered_by: by.map(|by| by.to_hex()),
        rung: rung.as_str().to_owned(),
        answered_at: *at,
        proof_kind: ProofKind::HumanConfirm.as_str().to_owned(),
        eligible: row.eligible_basis().map(|basis| basis.as_str().to_owned()),
        repeat,
    })
}

fn not_a_person() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{ANSWER_VERB} is a live person's own act"),
        &["Answer as that person, on their own verified human credential."],
    )
}

fn answer_refused(rule: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{ANSWER_VERB} refused: {rule}"),
        &["Answer only a check-in that asks you now, over the exact effect it names."],
    )
}

fn digest_of(hex: &str) -> MemoryResult<[u8; 32]> {
    blake3::Hash::from_hex(hex)
        .map(|hash| *hash.as_bytes())
        .map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                "effect_digest is not 64 hex",
                &["Pass the digest of the exact effect as 64 hex characters."],
            )
        })
}

fn verdict_view(verdict: AskVerdict, handle: Option<CheckInHandleView>) -> CheckInVerdict {
    match verdict {
        AskVerdict::Go { reason, act } => CheckInVerdict::Go {
            reason: reason.as_str().to_owned(),
            act_class: act.map(|act| act.as_str().to_owned()),
        },
        AskVerdict::Wait {
            act, mode, reason, ..
        } => CheckInVerdict::Wait {
            reason: reason.as_str().to_owned(),
            act_class: act.as_str().to_owned(),
            mode: mode.as_str().to_owned(),
            handle: handle.map(Box::new),
        },
        AskVerdict::Propose { act } => CheckInVerdict::Propose {
            act_class: act.as_str().to_owned(),
        },
        AskVerdict::Absent { why } => CheckInVerdict::Absent {
            why: why.to_owned(),
        },
        AskVerdict::Unstated => CheckInVerdict::Unstated,
    }
}

fn handle_view(row: &PendingCheckIn, repeat: bool) -> CheckInHandleView {
    let (answer, answered_by) = match &row.state {
        PendingState::Answered { answer, by, .. } => {
            (Some(answer.as_str().to_owned()), by.map(|by| by.to_hex()))
        }
        _ => (None, None),
    };
    CheckInHandleView {
        handle: row.id.to_hex(),
        state: state_token(&row.state).to_owned(),
        answer,
        answered_by,
        rung: row
            .current_rung()
            .map(|entry| entry.rung.as_str().to_owned()),
        next_due_at: row.next_due_at(),
        until: row.until,
        eligible: row.eligible_basis().map(|basis| basis.as_str().to_owned()),
        consumed: row.consumed_at.is_some(),
        repeat,
    }
}

const fn state_token(state: &PendingState) -> &'static str {
    match state {
        PendingState::Open => "open",
        PendingState::Answered { .. } => "answered",
        PendingState::LetGo { .. } => "let_go",
        PendingState::Held { .. } => "held",
        PendingState::ProceedWithUndo { .. } => "proceed_with_undo",
        PendingState::WindowPassed { .. } => "window_passed",
        PendingState::ObjectionHeld { .. } => "objection_held",
    }
}
