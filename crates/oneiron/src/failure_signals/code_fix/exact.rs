//! The request a code fix replays exactly (FIX 1662): the one the failing
//! call sent, as the vault kept it before the call, rather than one rebuilt
//! from the failure's instructions, briefing and task. A failure-ladder case
//! reads its failing attempt's last kept call: its replay capsule (an
//! executor or workflow step's), else a durable step's row. A blocked report
//! reads the request its row keeps, or the call of its run that the row
//! names by its hash. A request that no longer reads as the copy kept, or
//! that was never kept, leaves the replay to rebuild the call, and the
//! replay says so. A capsule the wall withheld its request from keeps no
//! copy, and says why (FIX 6348). An erased capsule's call is replayed by
//! no copy and no rebuild (FIX 6251). No copy of a call's request is read
//! unless the Coach's own Grant admits its capture (FIX 8704): one it does
//! not admit keeps its capsule as a reference only, and is rebuilt as a
//! call with no copy kept is; no other copy stands in for it. Under that
//! same admission the capsule's route prompt is read from its body beside
//! the request (FIX 6255), and the replay sends it on the call's rung: a
//! prompt that does not read leaves the call with no replay at all, never
//! one under no prompt or today's.

use serde::{Deserialize, Serialize};

use super::{CodeFixSource, failed_case_in};
use crate::attempt_queue::AttemptId;
use crate::code_run::{capsule_request, capsule_route_prompt, step_replay_capsules};
use crate::dreamer_runner::maintenance::code_fix::CoachReplayAdmission;
use crate::dreamer_runner::shadow_values::ShadowUnavailable;
use crate::dreamer_runner::step_replay::CapsuleRequest;
use crate::dreamer_runner::step_replay::ReplayRung;
use crate::dreamer_runner::step_replay::StepReplayCapsule;
use crate::dreamer_runner::step_replay::StoredRungBinding;
use crate::self_heal::blocked_reports::{SentRequest, blocked_source_in, step_sources_in};
use crate::{EntityId, Result, Vault};
use oneiron_model::llm::LlmRequest;

/// The request a failing call sent, as the vault kept it, for a replay that
/// sends it again inside the vault.
#[derive(Debug, Clone, PartialEq)]
pub struct ExactReplayRequest {
    /// The request, canonical, with its tool declarations: a replay keeps
    /// them, and runs no tool the answer names.
    pub request: LlmRequest,
    /// The rung that answered the call, with its route prompt as the
    /// capsule's body holds it (FIX 6255), when one did; a call no provider
    /// answered has none.
    pub rung: Option<ReplayRung>,
    /// Whether the copy is the request as sent. `false` when the side-row
    /// wall masked a secret in it, or in its rung's route prompt: the
    /// replay sends the custody handle, never the secret.
    pub as_sent: bool,
}

impl ExactReplayRequest {
    /// How a replay that sends it runs the failure.
    #[must_use]
    pub const fn fidelity(&self) -> ReplayFidelity {
        if self.as_sent {
            ReplayFidelity::Exact
        } else {
            ReplayFidelity::ExactMasked
        }
    }
}

/// How a code fix's replay ran the real failure (FIX 1662).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFidelity {
    /// The request the failing call sent, as it was sent.
    Exact,
    /// That request, with each secret in it, or in its rung's route prompt,
    /// masked into its custody handle.
    ExactMasked,
    /// Rebuilt from the failure's instructions, briefing and task: not the
    /// request the call sent.
    Rebuilt,
}

/// What the vault kept of the request a failing call sent (FIX 1662).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExactReplay {
    /// The request as kept.
    Kept(Box<ExactReplayRequest>),
    /// None was kept, or the copy no longer reads as kept: the replay
    /// rebuilds the call.
    NotKept,
    /// The call's capsule keeps no copy: the side-row wall withheld its
    /// request at capture, for `reasons` (FIX 6254, 6348). A durable step's
    /// row of the call, when one reads, is `fallback`; with none the replay
    /// rebuilds the call, as for `NotKept`.
    Withheld {
        reasons: Vec<String>,
        fallback: Option<Box<ExactReplayRequest>>,
    },
    /// The call's replay capsule was erased with its actor (FIX 6144): no
    /// replay of the call runs, rebuilt or not.
    Erased,
    /// The call's request is kept, but its rung's route prompt is withheld,
    /// retired or no longer reads (FIX 6255): as for `Erased`, no replay of
    /// the call runs, rebuilt or not, and no other prompt stands in.
    PromptUnavailable,
}

impl ExactReplay {
    fn of(copy: Option<ExactReplayRequest>) -> Self {
        copy.map_or(Self::NotKept, |copy| Self::Kept(Box::new(copy)))
    }

    /// Whether no replay of the call runs at all, rebuilt or not: its
    /// capsule was erased, or its route prompt is unavailable (FIX 6255).
    pub(crate) const fn runs_none(&self) -> bool {
        matches!(self, Self::Erased | Self::PromptUnavailable)
    }

    /// The request a replay sends: the copy kept, or a withheld capsule's
    /// step-row copy. `None` leaves the replay to rebuild the call, or once
    /// erased, to run none.
    pub(crate) fn request(&self) -> Option<&ExactReplayRequest> {
        match self {
            Self::Kept(request)
            | Self::Withheld {
                fallback: Some(request),
                ..
            } => Some(request),
            Self::NotKept
            | Self::Withheld { fallback: None, .. }
            | Self::Erased
            | Self::PromptUnavailable => None,
        }
    }
}

/// The failing call one code-fix invocation replays, chosen once (OF-380
/// L1): what the vault kept of its request, and its captured step, which an
/// engine pair runs from. A replay reads the kept request again before each
/// send (FIX 6659) and a pair reads the step again under its identity, but
/// neither chooses another call.
pub(crate) struct CodeFixReplaySelection {
    /// What the vault kept of the call's request.
    pub(crate) exact: ExactReplay,
    /// The call's replay capsule: the failing attempt's last kept call, or
    /// the one a blocked report names by its hash. `None` with no durable
    /// run, or none kept.
    pub(crate) capsule: Option<StepReplayCapsule>,
    /// The durable step row that supplied the kept request, when one did:
    /// its step hash, lease generation and call index within the attempt
    /// (FIX 6735). The attempt is re-derived from the source on every live
    /// read, so it is not pinned here. `None` when the capsule supplied
    /// it, no row did, or nothing was kept. Decomposed instead of the
    /// step-row key, which no other lane names.
    pub(crate) step: Option<([u8; 32], u64, u32)>,
}

impl CodeFixReplaySelection {
    /// What the vault keeps now of the call chosen once (FIX 6735): the
    /// same source, admission, receipt-row, erase, withheld and kept
    /// handling as the initial choose, but the pinned capsule and step row
    /// again by their storage identity, never the newest row. A missing
    /// row reads as not kept; a row captured since is never taken up.
    pub(crate) fn pinned_exact(
        &self,
        vault: &Vault,
        source: &CodeFixSource,
        admitted: Option<&CoachReplayAdmission>,
    ) -> Result<ExactReplay> {
        let txn = vault.store.env.read_txn()?;
        // The attempt, the hash, and the report's row, re-derived fresh,
        // exactly as the initial choose derives them.
        let (attempt, _digest, sent) = match source {
            CodeFixSource::Case { case_ref } => match failed_case_in(vault, &txn, case_ref)? {
                Some((case, _)) => (
                    Some(EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?),
                    None,
                    None,
                ),
                None => (None, None, None),
            },
            CodeFixSource::Blocked { receipt, run } => {
                let sent = blocked_source_in(vault, &txn, receipt)?
                    .and_then(|source| source.request)
                    .and_then(|request| request.sent);
                let digest = sent.as_ref().map(|sent| sent.digest);
                (*run, digest, sent)
            }
        };
        drop(txn);
        let row_keeps = sent.as_ref().is_some_and(|sent| sent.kept.is_some());
        match (admitted, sent, attempt) {
            // FIX 8704, key-bound: no copy without admission; an erased
            // pinned capsule still runs no replay at all.
            (None, ..) => {
                let erased = match (&self.capsule, attempt) {
                    (Some(pinned), Some(attempt)) => pinned_capsule(vault, attempt, pinned)?
                        .is_some_and(|again| again.content.actor().is_none()),
                    _ => false,
                };
                if !row_keeps && erased {
                    Ok(ExactReplay::Erased)
                } else {
                    Ok(ExactReplay::NotKept)
                }
            }
            // The report's own row keeps it, as at choose.
            (
                Some(_),
                Some(SentRequest {
                    digest: sent,
                    kept: Some(kept),
                }),
                _,
            ) => Ok(ExactReplay::of(as_kept(
                kept.request,
                None,
                sent,
                kept.stored,
            ))),
            (Some(_), _, Some(attempt)) => pinned_attempt_request(vault, attempt, self),
            (Some(_), _, None) => Ok(ExactReplay::NotKept),
        }
    }
}

/// What the vault kept of the request the failure `source` names, read
/// only under `admitted`, the Coach's admission to its capture. A request
/// the report's own row keeps is read there, under that row's own erase.
pub(crate) fn exact_replay(
    vault: &Vault,
    source: &CodeFixSource,
    admitted: Option<&CoachReplayAdmission>,
) -> Result<ExactReplay> {
    Ok(code_fix_replay_selection(vault, source, admitted)?.exact)
}

/// The failing call of the failure `source` names, chosen once
/// ([`CodeFixReplaySelection`]): its kept request, read where
/// [`exact_replay`] reads it, and the capsule of the call among its run's
/// kept calls. With no `admitted`, no copy of the request is read: the
/// replay rebuilds the call, unless its capsule reads erased.
pub(crate) fn code_fix_replay_selection(
    vault: &Vault,
    source: &CodeFixSource,
    admitted: Option<&CoachReplayAdmission>,
) -> Result<CodeFixReplaySelection> {
    let txn = vault.store.env.read_txn()?;
    // The attempt whose kept calls hold it, the hash of the one a report
    // names, when it names one, and what the report's own row keeps of it.
    let (attempt, digest, sent) = match source {
        CodeFixSource::Case { case_ref } => match failed_case_in(vault, &txn, case_ref)? {
            Some((case, _)) => (
                Some(EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?),
                None,
                None,
            ),
            None => (None, None, None),
        },
        CodeFixSource::Blocked { receipt, run } => {
            let sent = blocked_source_in(vault, &txn, receipt)?
                .and_then(|source| source.request)
                .and_then(|request| request.sent);
            let digest = sent.as_ref().map(|sent| sent.digest);
            (*run, digest, sent)
        }
    };
    drop(txn);
    let capsule = match attempt {
        Some(attempt) => failing_call(vault, attempt, digest)?,
        None => None,
    };
    let row_keeps = sent.as_ref().is_some_and(|sent| sent.kept.is_some());
    let (exact, step) = match (admitted, sent, attempt) {
        // FIX 8704: a capture the Coach is not admitted to is read by no
        // copy; an erased capsule's call still runs no replay at all.
        (None, ..) => {
            let erased = capsule
                .as_ref()
                .is_some_and(|capsule| capsule.content.actor().is_none());
            if !row_keeps && erased {
                (ExactReplay::Erased, None)
            } else {
                (ExactReplay::NotKept, None)
            }
        }
        // The report's own row keeps it.
        (
            Some(_),
            Some(SentRequest {
                digest: sent,
                kept: Some(kept),
            }),
            _,
        ) => (
            ExactReplay::of(as_kept(kept.request, None, sent, kept.stored)),
            None,
        ),
        (Some(_), _, Some(attempt)) => attempt_request(vault, attempt, digest, capsule.clone())?,
        (Some(_), _, None) => (ExactReplay::NotKept, None),
    };
    if let ExactReplay::Withheld { reasons, fallback } = &exact {
        // Local only (FIX 6348): why the capsule keeps no copy.
        tracing::debug!(
            ?reasons,
            step_copy = fallback.is_some(),
            "the failing call's capsule withheld its request"
        );
    }
    Ok(CodeFixReplaySelection {
        exact,
        capsule,
        step,
    })
}

/// The failing call's capsule among `attempt`'s kept calls: the one whose
/// hash is `digest`, or with none named, the last one it sent.
fn failing_call(
    vault: &Vault,
    attempt: EntityId,
    digest: Option<[u8; 32]>,
) -> Result<Option<StepReplayCapsule>> {
    Ok(step_replay_capsules(vault, attempt)?
        .into_iter()
        .rev()
        .find(|capsule| digest.is_none_or(|digest| capsule.request_hash == digest)))
}

/// `request` while it still reads as the copy kept, whose hash is `stored`;
/// it is the request as sent when that is `sent` too.
fn as_kept(
    request: LlmRequest,
    rung: Option<ReplayRung>,
    sent: [u8; 32],
    stored: [u8; 32],
) -> Option<ExactReplayRequest> {
    if request.canonical_hash().ok()? != stored {
        return None;
    }
    Some(ExactReplayRequest {
        request,
        rung,
        as_sent: stored == sent,
    })
}

/// The failing call among `attempt`'s kept calls: the one whose hash is
/// `digest`, or with none named, the last one it sent. Its replay capsule
/// `capsule` ([`failing_call`]) first, then a durable step's row. A capsule
/// whose copy reads as none is read again before a step's row stands in for
/// it, so an erase meanwhile reads as erased (FIX 6251). Beside the replay,
/// the step row that supplied its copy, when one did (FIX 6735).
fn attempt_request(
    vault: &Vault,
    attempt: EntityId,
    digest: Option<[u8; 32]>,
    capsule: Option<StepReplayCapsule>,
) -> Result<(ExactReplay, Option<([u8; 32], u64, u32)>)> {
    // The selected capsule, once it read as live but its copy as none, and
    // the rung its call sent on.
    let mut held = None;
    if let Some(capsule) = capsule {
        // An erased capsule's request went with its actor (FIX 6144): no
        // other copy stands in for it.
        if capsule.content.actor().is_none()
            || matches!(&capsule.request, CapsuleRequest::Kept { erased: true, .. })
        {
            return Ok((ExactReplay::Erased, None));
        }
        // The copy kept is the request as sent unless the wall masked a
        // secret in it or in its route prompt: its sent identity and its
        // stored hash then differ.
        let as_sent = capsule.as_sent();
        // The route prompt reads before the request (FIX 6255): a prompt
        // that does not read latches the call, so no step row's copy and no
        // rebuilt baseline stands in for it.
        let Ok(rung) = replay_rung(vault, &capsule)? else {
            return Ok((prompt_unavailable(vault, attempt, &capsule)?, None));
        };
        if let Some(request) = capsule_request(vault, &capsule)? {
            return Ok((
                ExactReplay::of(Some(ExactReplayRequest {
                    request,
                    rung,
                    as_sent,
                })),
                None,
            ));
        }
        held = Some((capsule, rung));
    }
    let steps = {
        let txn = vault.store.env.read_txn()?;
        step_sources_in(vault, &txn, AttemptId::from_bytes(attempt.as_bytes())?)?
    };
    // A held capsule's call is the one a step row may stand in for.
    let wanted = held
        .as_ref()
        .map(|(capsule, _)| capsule.request_hash)
        .or(digest);
    let chosen = steps
        .into_iter()
        .rev()
        .find(|(key, _)| wanted.is_none_or(|wanted| key.step == wanted));
    let (copy, step) = match chosen {
        Some((key, source)) => {
            let copy = as_kept(
                source.request.request,
                None,
                key.step,
                source.request.stored,
            );
            let step = copy.is_some().then_some((key.step, key.lease, key.call));
            (copy, step)
        }
        None => (None, None),
    };
    let Some((capsule, rung)) = held else {
        return Ok((ExactReplay::of(copy), step));
    };
    let copy = copy.map(|copy| on_capsule_rung(copy, &capsule, rung));
    // Read again after the step's row, before its copy stands in: an erase
    // since the first read takes the call, and no copy replays it.
    let erased = step_replay_capsules(vault, attempt)?
        .iter()
        .find(|again| {
            again.lease_generation == capsule.lease_generation && again.step == capsule.step
        })
        .is_some_and(|again| {
            again.content.actor().is_none()
                || matches!(&again.request, CapsuleRequest::Kept { erased: true, .. })
        });
    if erased {
        return Ok((ExactReplay::Erased, None));
    }
    Ok(match capsule.request {
        CapsuleRequest::Withheld { reasons } => (
            ExactReplay::Withheld {
                reasons,
                fallback: copy.map(Box::new),
            },
            step,
        ),
        CapsuleRequest::Kept { .. } => (ExactReplay::of(copy), step),
    })
}

/// A step row's `copy` standing in for `capsule`'s request (FIX 6255): it
/// sends on the capsule's `rung`, with the route prompt the capsule kept,
/// never the one configured now, and it is the call as sent only while
/// that prompt is too.
fn on_capsule_rung(
    mut copy: ExactReplayRequest,
    capsule: &StepReplayCapsule,
    rung: Option<ReplayRung>,
) -> ExactReplayRequest {
    copy.rung = rung;
    copy.as_sent &= capsule
        .binding
        .as_ref()
        .is_none_or(StoredRungBinding::prompt_as_sent);
    copy
}

/// The rung a replay of `capsule`'s call sends on (FIX 6255): its answering
/// rung, with the route prompt read from the capsule's body now, under the
/// same admission as its request; `Ok(None)` when no rung answered the
/// call. The reason the prompt does not read in its place.
fn replay_rung(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<std::result::Result<Option<ReplayRung>, ShadowUnavailable>> {
    let Some(binding) = &capsule.binding else {
        return Ok(Ok(None));
    };
    Ok(capsule_route_prompt(vault, capsule)?.map(|prompt| Some(ReplayRung::of(binding, prompt))))
}

/// What a capsule whose route prompt did not read keeps of its call (FIX
/// 6255), read again by its storage identity: `Erased` when an erase took
/// it meanwhile, else `PromptUnavailable`. Either way no replay runs.
fn prompt_unavailable(
    vault: &Vault,
    attempt: EntityId,
    capsule: &StepReplayCapsule,
) -> Result<ExactReplay> {
    let erased = pinned_capsule(vault, attempt, capsule)?
        .is_some_and(|again| again.content.actor().is_none());
    Ok(if erased {
        ExactReplay::Erased
    } else {
        ExactReplay::PromptUnavailable
    })
}

/// The pinned capsule again within `attempt` (FIX 6735): by its storage
/// identity, the lease generation and step the capsule table keys it by,
/// with its sent hash as defense against a same-key overwrite. `None`
/// when that row is gone or holds another request now.
fn pinned_capsule(
    vault: &Vault,
    attempt: EntityId,
    pinned: &StepReplayCapsule,
) -> Result<Option<StepReplayCapsule>> {
    Ok(step_replay_capsules(vault, attempt)?
        .into_iter()
        .find(|again| {
            again.lease_generation == pinned.lease_generation
                && again.step == pinned.step
                && again.request_hash == pinned.request_hash
        }))
}

/// The pinned step row's copy within `attempt` (FIX 6735): the row whose
/// full key is `pinned`, never the newest. `None` when it is gone or no
/// longer reads as kept.
fn pinned_step_copy(
    vault: &Vault,
    attempt: EntityId,
    pinned: ([u8; 32], u64, u32),
) -> Result<Option<ExactReplayRequest>> {
    let txn = vault.store.env.read_txn()?;
    let rows = step_sources_in(vault, &txn, AttemptId::from_bytes(attempt.as_bytes())?)?;
    Ok(rows
        .into_iter()
        .find(|(key, _)| key.step == pinned.0 && key.lease == pinned.1 && key.call == pinned.2)
        .and_then(|(key, source)| {
            as_kept(
                source.request.request,
                None,
                key.step,
                source.request.stored,
            )
        }))
}

/// The pinned call among `attempt`'s kept calls (FIX 6735): the pinned
/// capsule again by its storage identity, else the pinned step row alone
/// by its full key. A capsule whose copy reads as none is read again
/// before the pinned step's row stands in for it, as at choose.
fn pinned_attempt_request(
    vault: &Vault,
    attempt: EntityId,
    pinned: &CodeFixReplaySelection,
) -> Result<ExactReplay> {
    let Some(chosen) = &pinned.capsule else {
        // No capsule chosen: the pinned step row alone, never a capsule
        // captured since.
        let Some(step) = pinned.step else {
            return Ok(ExactReplay::NotKept);
        };
        return Ok(ExactReplay::of(pinned_step_copy(vault, attempt, step)?));
    };
    let Some(again) = pinned_capsule(vault, attempt, chosen)? else {
        return Ok(ExactReplay::NotKept);
    };
    if again.content.actor().is_none()
        || matches!(&again.request, CapsuleRequest::Kept { erased: true, .. })
    {
        return Ok(ExactReplay::Erased);
    }
    let as_sent = again.as_sent();
    // The route prompt reads before the request, as at choose (FIX 6255).
    let Ok(rung) = replay_rung(vault, &again)? else {
        return prompt_unavailable(vault, attempt, chosen);
    };
    if let Some(request) = capsule_request(vault, &again)? {
        return Ok(ExactReplay::of(Some(ExactReplayRequest {
            request,
            rung,
            as_sent,
        })));
    }
    let copy = match pinned.step {
        Some(step) => pinned_step_copy(vault, attempt, step)?,
        None => None,
    }
    .map(|copy| on_capsule_rung(copy, &again, rung));
    // Read again after the step's row, before its copy stands in.
    let erased = pinned_capsule(vault, attempt, chosen)?.is_some_and(|once| {
        once.content.actor().is_none()
            || matches!(&once.request, CapsuleRequest::Kept { erased: true, .. })
    });
    if erased {
        return Ok(ExactReplay::Erased);
    }
    Ok(match again.request {
        CapsuleRequest::Withheld { reasons } => ExactReplay::Withheld {
            reasons,
            fallback: copy.map(Box::new),
        },
        CapsuleRequest::Kept { .. } => ExactReplay::of(copy),
    })
}
