//! `vault.check_in.preflight` and `vault.check_in.open` (ARCH-0082 #composing
//! and #ladder; ROLES-CHECKIN P2.3b, piece 2f; Engine ruling P23-SHAPE = A):
//! before an act, an agent asks whether it may run now, and opens the
//! durable ask when it waits.
//!
//! Both take the verb whose act would run, where its effect sits and the
//! effect's digest. The act class is the verb row's own, the role and the
//! power come from the caller's own live owner Grant that lists the verb (or
//! the caller is the vault owner), and the answer is go, wait, propose,
//! absent or unstated ([`CheckInVerdict`]); see `crate::check_in::asker`.
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
//! No verb reads a handle back but a repeat `open` (Q11 = A); the answer is
//! 2l, and the act's own gate that waits on a handle is PR 3.

use serde::{Deserialize, Serialize};

use crate::check_in::{
    AskVerdict, CheckInScope, NoAgentVerdict, OpenPendingCheckIn, PendingCheckIn, PendingState,
    VerifiedChain, judge_ask_in_txn, keyed_pending_check_in_in_txn,
    open_keyed_pending_check_in_in_txn,
};
use crate::error::Error;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};

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
