//! The Coach's judge-swap upkeep on this server (OF-184). Its kept
//! judgments are the replay judge's decision journal, and the registered
//! judge's ladder answers them again; the engine rules the swap.
use std::cell::RefCell;
use std::collections::BTreeMap;

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::llm::decision::{DecisionAnswer, Reversibility, TypedDecision};
use oneiron::skill_optimize::{
    HeldOutReplayNotes, JudgeShadowAnswer, JudgeShadowCase, JudgeShadowHost,
};
use oneiron::{Error, Vault};

use crate::replay_judge::{JournalRow, ServeReplayJudge};
use crate::server::SyncServer;

/// Runs one leased `coach.judge_swap` attempt. With no registered judge
/// nothing is kept to swap, and the attempt settles.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    let host = JournalShadow {
        vault: server.vault(),
        judge,
        rows: RefCell::new(BTreeMap::new()),
    };
    let report = server.vault().run_coach_judge_swap(admitted, &host, now)?;
    tracing::debug!(?report, "the Coach's judge-swap pass");
    Ok(())
}

/// The journal's judgments, keyed by case, as the engine reads them.
struct JournalShadow<'a> {
    vault: &'a Vault,
    judge: &'static ServeReplayJudge,
    rows: RefCell<BTreeMap<String, JournalRow>>,
}

impl JudgeShadowHost for JournalShadow<'_> {
    fn kept_cases(&self, limit: usize) -> oneiron::Result<Vec<JudgeShadowCase>> {
        let mut rows = self.rows.borrow_mut();
        let mut cases = Vec::new();
        for row in crate::replay_judge::journal(self.vault, limit)?
            .into_iter()
            .rev()
        {
            let Some(judge) = judge_of(&row.decision) else {
                continue;
            };
            if matches!(row.decision.answer, DecisionAnswer::Abstain) {
                continue;
            }
            let case_ref = blake3::hash(
                format!("{}|{}|{}", row.at, row.question.id.to_hex(), row.state).as_bytes(),
            )
            .to_hex()
            .to_string();
            cases.push(JudgeShadowCase {
                case_ref: case_ref.clone(),
                source_family: source_family(&row),
                judge,
                answer: row.decision.answer.clone(),
            });
            rows.insert(case_ref, row);
        }
        Ok(cases)
    }

    fn rescore(&self, case: &JudgeShadowCase) -> oneiron::Result<Option<JudgeShadowAnswer>> {
        let rows = self.rows.borrow();
        let Some(row) = rows.get(&case.case_ref) else {
            return Ok(None);
        };
        let state: serde_json::Value = serde_json::from_str(&row.state)
            .map_err(|_| Error::CorruptedIndex("skill judge journal"))?;
        let decisions = self.judge.decisions();
        let decision = decisions.ladder.run(
            &row.question,
            decisions.principal,
            &row.decision.evidence,
            &state,
            decisions.dial,
            &decisions.bands,
            Reversibility::ReversibleRead,
            decisions.deadline,
        )?;
        if matches!(decision.answer, DecisionAnswer::Abstain) {
            return Ok(None);
        }
        Ok(judge_of(&decision).map(|judge| JudgeShadowAnswer {
            judge,
            answer: decision.answer,
        }))
    }
}

/// The rung that answered, `model@version`.
fn judge_of(decision: &TypedDecision) -> Option<String> {
    decision
        .receipt
        .providers
        .last()
        .map(|pin| format!("{}@{}", pin.model, pin.version))
}

/// The kind of run the judged state came from, else the question it asked.
fn source_family(row: &JournalRow) -> String {
    serde_json::from_str::<serde_json::Value>(&row.state)
        .ok()
        .and_then(|state| {
            state
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("question:{}", row.question.id.to_hex()))
}
