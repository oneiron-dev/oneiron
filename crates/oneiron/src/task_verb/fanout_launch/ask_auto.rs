//! A multi-recipient ask's Auto launch ruling (FIX 10181).
//! Entry: `AskAutoGate::decide`, outside the writer; `AskAutoGate::holds_in`,
//! in it.
//!
//! Under the vault's Auto fan-out setting, an ask to more than one recipient
//! takes the shared learned fan-out ruling a wave launch takes, where the
//! surface carries a host's decisions: taken before the writer opens, as
//! decision IO never holds it, and rechecked in the writer before anything is
//! minted. A ruling that surfaces the ask to a person, or a policy or
//! recipient set that moved since it was taken, holds the ask through the
//! existing launch hold; nothing refuses it. Asks whose every recipient
//! would answer the approval still go out, and the exceptional-width check
//! stays the separate, non-blocking one it is.

use std::time::Instant;

use super::*;
use crate::llm::decision::DecisionLadder;
use crate::retrieval_depth::RetrievalDeadline;
use crate::task_verb::TaskDecisions;

/// How the learned ruling words the question it puts for an ask.
const ASK_FANOUT_WORDING: &str = "Should this ask go out to all of its recipients without its \
owner's approval? Answer allow when its width and the history of asks like it show the owner \
would let it go out, deny when they show the owner would refuse it, and escalate-to-human when \
they settle neither.";

/// One ask's Auto ruling, as it was taken outside the writer: the fan-out
/// policy and the recipients it was taken over, and the learned answer.
pub(in crate::task_verb) struct AskAutoGate {
    governed: ResolvedFanoutPolicy,
    recipients: Vec<EntityId>,
    disposition: FanoutAutoDisposition,
}

impl AskAutoGate {
    /// Takes `actor`'s ruling on `input` through `decisions`, the host's own.
    /// `None` where no ruling applies: a fan-out mode other than Auto, an
    /// ask to fewer than two recipients, or one whose policy or recipients
    /// do not read here (its admission answers that as before). An absent
    /// or abstaining ladder, or a failing decider, surfaces the ask to a
    /// person, as a wave launch's does.
    pub(in crate::task_verb) fn decide(
        memory: &Memory<'_>,
        input: &TaskAskSpec,
        decisions: &TaskDecisions<'_>,
    ) -> Option<Self> {
        let vault = memory.vault();
        let (governed, recipients) = {
            let txn = vault.store.env.read_txn().ok()?;
            let governed = policy_in(vault, &txn, &ConsultFanOutScope::default()).ok()?;
            if governed.policy.mode != ConsultFanOutMode::Auto {
                return None;
            }
            let recipients = memory.ask_holders_in_txn(&txn, input).ok()?;
            (governed, recipients)
        };
        if recipients.len() < 2 {
            return None;
        }
        let actor = memory.actor();
        let launch_ref = EntityId::derive(
            LAUNCH_REF_DOMAIN,
            &[b"ask_auto", actor.as_bytes(), input.intent_key.as_bytes()],
        )
        .ok()?;
        let question = input.what.reference.short_ref();
        let plan = LaunchPayload::AdmittedAsk {
            group_ref: launch_ref,
            request_digest: String::new(),
            question: question.clone(),
            recipients: recipients.clone(),
        }
        .plan(launch_ref, actor, governed.policy.mode)
        .ok()?;
        let estimate = fanout_estimate(&plan).ok()?;
        let deadline = RetrievalDeadline::hard(Instant::now(), decisions.budget);
        let ruling = FanoutDecisions {
            ladder: ladder_view(&decisions.ladder),
            principal: actor,
            dial: decisions.dial,
            bands: decisions.bands.clone(),
            wording: ASK_FANOUT_WORDING.to_owned(),
            deadline: &deadline,
        };
        let (scope, _) = ask_check_keys(actor, launch_ref, &question);
        let disposition = LearningFanoutAutoDecider::new(
            vault,
            FanoutAskContext {
                task_ref: input.task_ref.unwrap_or(launch_ref),
                scope,
                trigger: FanoutAskTrigger::Budget {
                    magnitude: u64::from(estimate.total_count),
                },
                question: input.intent_key.clone(),
            },
            Some(&ruling),
        )
        .and_then(|decider| decider.decide(&plan, &estimate))
        .unwrap_or(FanoutAutoDisposition::SurfaceHuman);
        Some(Self {
            governed,
            recipients,
            disposition,
        })
    }

    /// Whether the ask holds for its launch approval, judged in the writer
    /// over `recipients`, its census now: the ruling surfaced it to a person,
    /// or the policy or recipients it was taken over moved since. An ask
    /// whose every recipient would answer that approval is never held.
    pub(in crate::task_verb) fn holds_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        recipients: &[EntityId],
        approval_project: Option<EntityId>,
    ) -> MemoryResult<bool> {
        let moved = policy_in(vault, txn, &ConsultFanOutScope::default())? != self.governed
            || recipients != self.recipients.as_slice();
        if !moved && self.disposition == FanoutAutoDisposition::Allow {
            return Ok(false);
        }
        Ok(!super::hold::recipients_approve_launch_in(
            vault,
            txn,
            recipients,
            approval_project,
        )?)
    }
}

/// The same ladder `ladder` is, by its references: the fan-out ruling takes
/// its own handle on the host's rungs.
fn ladder_view<'a>(ladder: &DecisionLadder<'a>) -> DecisionLadder<'a> {
    DecisionLadder {
        rule: ladder.rule,
        local: ladder.local,
        system_one: ladder.system_one,
        escalation: ladder.escalation,
        big: ladder.big,
        human: ladder.human,
        human_pin: ladder.human_pin.clone(),
        ask_to: ladder.ask_to,
        paired: ladder.paired,
        person: ladder.person,
        presence: ladder.presence,
        correlation: ladder.correlation,
    }
}
