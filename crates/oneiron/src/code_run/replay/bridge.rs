//! One host bridge call a code run's replay record captures: its request,
//! its outcome and the facts its host stamped on it, and the checks that
//! keep them one fact.

use rmpv::Value;

use super::super::payload::{
    decode_self_dispatch_outcome, self_call_request_value, self_dispatch_outcome_value,
};
use super::super::support::{expect_map, invalid_code_run_replay, map_get, str_value, u64_value};
use super::super::types::{
    SelfCall, SelfDispatchOutcome, SelfEffect, SelfSpeechCall, SelfSpeechResult,
};
use super::request_identity::is_erased_request;
use crate::Result;
use crate::receipt::{ActionInputs, call_bytes_digest};

/// One host bridge call captured for deterministic step replay.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeRunBridgeCall {
    pub seq: u64,
    pub effect: SelfEffect,
    pub request: Value,
    pub outcome: Value,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    /// The call's action digest over its effect, its canonical request and
    /// the input versions the host captured before it ran
    /// ([`ActionInputs::action_digest`], OF-568); `None` when the host
    /// captured none, or the call never ran.
    pub action_digest: Option<String>,
    /// The targets its host resolved for a spawn (FIX 9180), text-free;
    /// none for every other call.
    pub(crate) spawn_targets: super::spawn_replay::SpawnTargets,
    /// A verb hook's view of this outcome was served to the guest. Its own
    /// read rows are not witnessed yet, so source capture stays unknown.
    pub hook_view_served: bool,
    /// The dispatched rewritten call when a verb hook rewrote it (FIX 1442):
    /// the guest's original stays in `request`. `None` for legacy rows and
    /// un-rewritten calls.
    pub rewritten_request: Option<Value>,
}

impl CodeRunBridgeCall {
    /// Captures one typed `self.*` call and its host outcome.
    ///
    /// Replay compares `effect` and the canonical request payload before
    /// returning this stored outcome. A changed call cannot consume an old row.
    pub fn record(
        seq: u64,
        call: &SelfCall,
        outcome: &SelfDispatchOutcome,
        started_at_ms: u64,
        finished_at_ms: u64,
    ) -> Result<Self> {
        if finished_at_ms < started_at_ms {
            return Err(invalid_code_run_replay(
                "bridge call finished before it started",
            ));
        }

        let mut row = Self {
            seq,
            effect: call.effect(),
            request: self_call_request_value(call)?,
            outcome: self_dispatch_outcome_value(outcome)?,
            started_at_ms,
            finished_at_ms,
            action_digest: None,
            spawn_targets: super::spawn_replay::SpawnTargets::default(),
            hook_view_served: false,
            rewritten_request: None,
        };
        // FIX 6534: no live call spells the erased form, so none stands for one.
        if row.request_erased() {
            return Err(invalid_code_run_replay(
                "a live bridge request spells the erased form",
            ));
        }
        row.scrub_erased_ask()?;
        row.validate_speech_coherence()?;
        row.validate_spawn_coherence()?;
        row.validate_rewritten_coherence()?;
        Ok(row)
    }

    /// This row with the dispatched rewritten call beside the guest's
    /// original request (FIX 1442): `None` leaves the row as offered. A
    /// rewrite changes args, never the call: another effect is refused.
    pub fn with_rewritten_request(mut self, rewritten: Option<&SelfCall>) -> Result<Self> {
        let Some(rewritten) = rewritten else {
            return Ok(self);
        };
        if rewritten.effect() != self.effect {
            return Err(invalid_code_run_replay(
                "rewritten request changes its call's effect",
            ));
        }
        self.rewritten_request = Some(self_call_request_value(rewritten)?);
        self.validate_rewritten_coherence()?;
        Ok(self)
    }

    /// This row with its action digest over `inputs`, the versions the host
    /// captured before the call ran (OF-568); `None` leaves it unknown.
    #[must_use]
    pub fn with_inputs(mut self, inputs: Option<&ActionInputs>) -> Self {
        self.action_digest = inputs.and_then(|inputs| {
            let mut request = Vec::new();
            rmpv::encode::write_value(&mut request, &self.request).ok()?;
            Some(inputs.action_digest(self.effect.as_str(), &call_bytes_digest(&request)))
        });
        self
    }

    /// Validates every host-owned and outcome-owned axis of a speech row.
    ///
    /// The top-level effect, canonical request, decoded result and host stamp
    /// are one fact. Keeping this check on the row lets record construction,
    /// codec encode/decode and an in-memory replay cursor all enforce the same
    /// contract rather than trusting whichever boundary happened to run first.
    pub(in crate::code_run) fn validate_speech_coherence(&self) -> Result<()> {
        let outcome = decode_self_dispatch_outcome(&self.outcome)?;
        let expected_order = if self.effect.is_speech() {
            let order = u32::try_from(self.seq)
                .map_err(|_| invalid_code_run_replay("speech bridge seq exceeds u32"))?;
            self.validate_speech_stamp()?;
            Some(order)
        } else {
            None
        };

        match outcome {
            SelfDispatchOutcome::WakePolicyWritten(_)
                if self.effect == SelfEffect::WakePolicyWrite =>
            {
                Ok(())
            }
            SelfDispatchOutcome::WakePolicyWritten(_) => Err(invalid_code_run_replay(
                "wake policy result belongs to another effect",
            )),
            SelfDispatchOutcome::Denied(result)
                if self.effect == SelfEffect::WakePolicyWrite && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::Failed(result)
                if self.effect == SelfEffect::WakePolicyWrite && result.effect == self.effect =>
            {
                Ok(())
            }
            _ if self.effect == SelfEffect::WakePolicyWrite => Err(invalid_code_run_replay(
                "wake policy effect carries another success outcome",
            )),
            // `connector.answer`'s reply is the door's verb answer (ONE-2510).
            SelfDispatchOutcome::AgentVerb(_) if self.effect == SelfEffect::ConnectorAnswer => {
                Ok(())
            }
            // `vault.worlds.privacy.set`'s answer is the world-privacy door's
            // outcome, as a verb answer (FIX 4480).
            SelfDispatchOutcome::AgentVerb(_) if self.effect == SelfEffect::WorldPrivacySet => {
                Ok(())
            }
            // `tasks.consult.result`'s answer is the landed consult's terminal
            // register, as a verb answer (DOOR-063).
            SelfDispatchOutcome::AgentVerb(_) if self.effect == SelfEffect::ConsultResult => Ok(()),
            // `self.workflows.dispatch_bound`'s answer is the bound run's
            // view, as a verb answer (FIX 5316).
            SelfDispatchOutcome::AgentVerb(_) if self.effect == SelfEffect::WorkflowDispatch => {
                Ok(())
            }
            // A run repo row's answer is its door's output, as a verb answer
            // (FIX 6867).
            SelfDispatchOutcome::AgentVerb(_) if self.effect.is_repo() => Ok(()),
            SelfDispatchOutcome::AgentVerb(_) if self.effect != SelfEffect::AgentVerb => Err(
                invalid_code_run_replay("agent verb result belongs to another effect"),
            ),
            SelfDispatchOutcome::Fold(_) if self.effect != SelfEffect::Fold => Err(
                invalid_code_run_replay("fold answer belongs to another effect"),
            ),
            SelfDispatchOutcome::TaskRefusal(_) if self.effect != SelfEffect::TasksRefuse => Err(
                invalid_code_run_replay("task refusal belongs to another effect"),
            ),
            SelfDispatchOutcome::SkillCall(_) if self.effect != SelfEffect::SkillsCall => Err(
                invalid_code_run_replay("skill call answer belongs to another effect"),
            ),
            SelfDispatchOutcome::ReaderSpawn(_) if self.effect != SelfEffect::ReaderSpawn => Err(
                invalid_code_run_replay("reader spawn receipt belongs to another effect"),
            ),
            SelfDispatchOutcome::ReaderReport(_) if self.effect != SelfEffect::ReaderReport => Err(
                invalid_code_run_replay("reader report receipt belongs to another effect"),
            ),
            SelfDispatchOutcome::TaskWaitSet(_) if self.effect != SelfEffect::TasksWaitSet => Err(
                invalid_code_run_replay("task wait set answer belongs to another effect"),
            ),
            SelfDispatchOutcome::Summarize(_) if self.effect != SelfEffect::Summarize => Err(
                invalid_code_run_replay("summary answer belongs to another effect"),
            ),
            SelfDispatchOutcome::Leader(_)
                if !matches!(self.effect, SelfEffect::Leader | SelfEffect::LeaderSplit) =>
            {
                Err(invalid_code_run_replay(
                    "leader answer belongs to another effect",
                ))
            }
            SelfDispatchOutcome::StoredReply(super::SelfStoredReply {
                kind: super::SelfStoredReplyKind::TeamStartReceipt,
                ..
            }) if self.effect != SelfEffect::Team => Err(invalid_code_run_replay(
                "stored team receipt belongs to another effect",
            )),
            SelfDispatchOutcome::Team(_) if self.effect != SelfEffect::Team => Err(
                invalid_code_run_replay("team answer belongs to another effect"),
            ),
            SelfDispatchOutcome::TeamSubmitted(_) if self.effect != SelfEffect::Team => Err(
                invalid_code_run_replay("team submit answer belongs to another effect"),
            ),
            SelfDispatchOutcome::Speech(result) => {
                let Some(expected_order) = expected_order else {
                    return Err(invalid_code_run_replay(
                        "speech outcome belongs to a non-speech bridge effect",
                    ));
                };
                validate_speech_result(self.effect, expected_order, result)
            }
            // A speech attempt can fail at the gate or hit the fail-closed
            // barrier after an earlier durable wait. Those are replay-visible
            // outcomes, but they are not successful speech and therefore carry
            // no bubble identity to validate here. Denied/Failed still name the
            // attempted effect; a DurableWait intentionally carries the wait
            // that caused the barrier, which may be a different effect.
            SelfDispatchOutcome::Denied(result)
                if self.effect.is_speech() && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::Failed(result)
                if self.effect.is_speech() && result.effect == self.effect =>
            {
                Ok(())
            }
            SelfDispatchOutcome::DurableWait(_) if self.effect.is_speech() => Ok(()),
            // A successful non-speech result for a speech request is not a
            // weaker variant. It is an impossible cross-effect row and must
            // fail closed before a replay cursor can hand it to the guest.
            _ if self.effect.is_speech() => Err(invalid_code_run_replay(
                "speech bridge effect carries a non-speech success outcome",
            )),
            // Non-speech bridge effects retain their existing outcome family;
            // the speech-specific checks above do not narrow those rows.
            _ => Ok(()),
        }
    }

    /// A speech row's request is the call its host stamped: its text under
    /// the row's own seq and start clock. An erased request keeps no words
    /// to hold to the stamp (FIX 6534); its outcome still names its order.
    fn validate_speech_stamp(&self) -> Result<()> {
        if self.request_erased() {
            return Ok(());
        }
        let entries = expect_map(&self.request, "speech request must be a map")?;
        let text = str_value(map_get(entries, "text")?)?;
        let unstamped = match self.effect {
            SelfEffect::Speak => SelfCall::Speak(SelfSpeechCall::new(text)),
            SelfEffect::Think => SelfCall::Think(SelfSpeechCall::new(text)),
            SelfEffect::Express => SelfCall::Express(SelfSpeechCall::new(text)),
            _ => unreachable!("is_speech exhaustively names the speech family"),
        };
        let expected_call = unstamped.with_bridge_stamp(self.seq, self.started_at_ms);
        if self.request != self_call_request_value(&expected_call)? {
            return Err(invalid_code_run_replay(
                "speech request contradicts its host bridge stamp",
            ));
        }
        Ok(())
    }

    /// The rewritten request beside the original is coherent with this row
    /// (FIX 1442): a rewrite changes args, never the call, so the rewritten
    /// map carries its call's own shape; a speech rewrite carries the row's
    /// own bridge stamp; a spawn rewrite's ask stays well-formed. `None`
    /// (legacy rows, un-rewritten calls) skips.
    pub(in crate::code_run) fn validate_rewritten_coherence(&self) -> Result<()> {
        let Some(rewritten) = &self.rewritten_request else {
            return Ok(());
        };
        // FIX 6534: a rewrite's words go with its call's own, and an erased
        // pair keeps their two identities alone.
        match (self.request_erased(), is_erased_request(rewritten)) {
            (true, true) => return Ok(()),
            (false, false) => {}
            _ => {
                return Err(invalid_code_run_replay(
                    "a rewritten request is erased apart from its call's own",
                ));
            }
        }
        let original = expect_map(&self.request, "bridge request must be a map")?;
        let fields = expect_map(rewritten, "rewritten request must be a map")?;
        let mut original_keys: Vec<&str> = original
            .iter()
            .filter_map(|(key, _)| key.as_str())
            .collect();
        let mut rewritten_keys: Vec<&str> =
            fields.iter().filter_map(|(key, _)| key.as_str()).collect();
        original_keys.sort_unstable();
        rewritten_keys.sort_unstable();
        if original_keys != rewritten_keys {
            return Err(invalid_code_run_replay(
                "rewritten request changes its call's shape",
            ));
        }
        if self.effect.is_speech() {
            let order = u32::try_from(self.seq)
                .map_err(|_| invalid_code_run_replay("speech bridge seq exceeds u32"))?;
            if u64_value(map_get(fields, "order")?)? != u64::from(order)
                || u64_value(map_get(fields, "occurred_at")?)? != self.started_at_ms / 1000
            {
                return Err(invalid_code_run_replay(
                    "rewritten speech contradicts its host bridge stamp",
                ));
            }
        }
        if self.effect == SelfEffect::AgentsSpawn {
            let ask = match rewritten {
                Value::Map(entries) => super::spawn_replay::ask_of(entries),
                _ => None,
            };
            let erased = ask.is_some_and(super::spawn_replay::is_erased_ask);
            let barrier = ask.is_some_and(super::spawn_replay::is_barrier_ask);
            let live = ask.is_some_and(Value::is_str);
            if !erased && !barrier && !live && ask.is_some_and(|ask| !ask.is_nil()) {
                return Err(invalid_code_run_replay(
                    "rewritten spawn ask is not text, nil, or a typed marker",
                ));
            }
        }
        Ok(())
    }

    /// Whether this row is an explicit speech call that ACTUALLY emitted.
    ///
    /// The two conditions are separate on purpose. A speech row whose outcome
    /// is a durable wait or a failed trap is a call the fail-closed barrier
    /// refused: it is replay-visible, but no bubble exists for it, so it must
    /// not suppress the trailing plaintext fallback. Only a row carrying a
    /// speech OUTCOME says the run spoke — and the decoder refuses a speech
    /// outcome that claims `emitted: false`, so "decodes as speech" and
    /// "emitted" are one fact rather than two that could disagree.
    #[must_use]
    pub fn emitted_speech(&self) -> bool {
        self.effect.is_speech()
            && self.validate_speech_coherence().is_ok()
            && matches!(
                decode_self_dispatch_outcome(&self.outcome),
                Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
                    emitted: true,
                    ..
                }))
            )
    }

    /// The bubble position this row emitted at, when it emitted one.
    pub(crate) fn emitted_speech_order(&self) -> Option<u32> {
        if !self.emitted_speech() {
            return None;
        }
        match decode_self_dispatch_outcome(&self.outcome) {
            Ok(SelfDispatchOutcome::Speech(result)) => Some(result.order),
            _ => None,
        }
    }

    /// The visible TEXT this row spoke, when it emitted an addressed bubble.
    ///
    /// Read from the row's own request payload — the same canonical value
    /// replay compares a re-dispatched call against — so what the fallback
    /// treats as "already said" is exactly what the user could already see.
    /// Hidden `self.think` text deliberately returns `None`: a private thought
    /// that matches the terminal observation must not suppress its visible
    /// trailing fallback.
    #[must_use]
    pub fn emitted_visible_speech_text(&self) -> Option<&str> {
        if self.validate_speech_coherence().is_err() {
            return None;
        }
        let Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
            is_visible: true,
            emitted: true,
            ..
        })) = decode_self_dispatch_outcome(&self.outcome)
        else {
            return None;
        };
        // The bubble spoke the dispatched call: read the rewritten text when
        // a hook rewrote it (FIX 1442). An erased call keeps none (FIX 6534).
        let Some(Value::Map(entries)) = self.dispatched_request() else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("text"))
            .and_then(|(_, value)| value.as_str())
    }
}

fn validate_speech_result(
    bridge_effect: SelfEffect,
    expected_order: u32,
    result: SelfSpeechResult,
) -> Result<()> {
    if result.effect != bridge_effect {
        return Err(invalid_code_run_replay(
            "speech outcome effect contradicts its bridge effect",
        ));
    }
    if result.order != expected_order {
        return Err(invalid_code_run_replay(
            "speech outcome order contradicts its request",
        ));
    }
    let expected_visibility = bridge_effect
        .speech_utterance()
        .ok_or(invalid_code_run_replay(
            "speech outcome belongs to a non-speech effect",
        ))?
        .is_visible();
    if result.is_visible != expected_visibility {
        return Err(invalid_code_run_replay(
            "speech outcome visibility contradicts its bridge effect",
        ));
    }
    if !result.emitted {
        return Err(invalid_code_run_replay(
            "speech outcome claims no emitted bubble",
        ));
    }
    Ok(())
}
