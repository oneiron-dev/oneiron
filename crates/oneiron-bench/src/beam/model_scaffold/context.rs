//! Context each answerer arm hands the shared answer call, apart from packs.
use super::Effort;
use crate::beam::{
    BeamResult, corpus_clock,
    llm_host::{ModelPin, ModelSession},
    report_model::{ContractCorpusRecord, CostComponentReport},
};
use oneiron::CallPurpose;
use std::path::Path;

pub(super) struct OwnTrace {
    pub text: String,
    /// Older steps were dropped to fit the effort's budget.
    pub cut: bool,
    /// A step stopped at the pinned output cap.
    pub capped: bool,
}

/// The trajectory-only arm: the reader takes `retrieval_steps` working steps
/// on one question. Each step sees the question and this question's own
/// earlier steps, never vault recall, corpus text or another question.
pub(super) fn own_trace(
    session: &ModelSession,
    pin: &ModelPin,
    prompt: &str,
    question: &str,
    effort: &Effort,
    costs: &mut Vec<CostComponentReport>,
) -> BeamResult<OwnTrace> {
    let mut steps = Vec::new();
    let mut capped = false;
    for _ in 0..effort.retrieval_steps {
        let (trace, _) = recent_steps(&steps, effort.token_budget)?;
        // One oversized step is clipped here too, as the answer call clips it.
        let trace = bounded_context(&trace, effort.token_budget);
        let input = serde_json::json!({"question": question, "trace": trace}).to_string();
        let (step, cost, cut) =
            session.invoke_capped(pin, CallPurpose::AnswerGen, prompt, &input)?;
        costs.push(cost);
        capped |= cut;
        steps.push(step);
    }
    let (text, cut) = recent_steps(&steps, effort.token_budget)?;
    Ok(OwnTrace { text, cut, capped })
}

/// The newest steps that fit `budget`, as a JSON array; the newest step
/// always stays (the shared bound clips it if it alone is too long).
fn recent_steps(steps: &[String], budget: usize) -> BeamResult<(String, bool)> {
    let mut start = 0;
    let mut text = serde_json::to_string(steps)?;
    while start + 1 < steps.len() && oneiron::count_context_pack_tokens(&text) > budget {
        start += 1;
        text = serde_json::to_string(&steps[start..])?;
    }
    Ok((text, start > 0))
}

pub(super) fn chat_history(
    corpus: &[ContractCorpusRecord],
    path: &Path,
    budget: usize,
) -> BeamResult<String> {
    let mut ordered = corpus
        .iter()
        .map(|item| {
            // load_dataset already validates timestamps with their source line.
            corpus_clock::occurred_at(item, path, 0).map(|at| (at, item))
        })
        .collect::<BeamResult<Vec<_>>>()?;
    ordered.sort_by_key(|(at, _)| *at);
    let mut history = String::new();
    for (_, item) in ordered.into_iter().rev() {
        let text = format!("{}\n{history}", item.text);
        if oneiron::count_context_pack_tokens(&text) > budget {
            break;
        }
        history = text;
    }
    Ok(history)
}

pub(super) fn bounded_context(text: &str, budget: usize) -> String {
    if oneiron::count_context_pack_tokens(text) <= budget {
        return text.to_owned();
    }
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();
    let (mut lo, mut hi) = (0, boundaries.len() - 1);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if oneiron::count_context_pack_tokens(&text[..boundaries[mid]]) <= budget {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    text[..boundaries[lo]].to_owned()
}

/// The pack dropped or cut items to fit its budget.
pub(super) fn pack_cut(pack: &crate::beam::arms::BudgetedContextPack) -> bool {
    pack.serialized_stats.items_truncated.count + pack.serialized_stats.items_dropped.count > 0
}

pub(super) fn measured_pack(
    vault: &oneiron::Vault,
    case: &crate::beam::model::FixtureCase,
    query_vector: Option<&[f32]>,
    now: u64,
) -> BeamResult<crate::beam::arms::BudgetedContextPack> {
    crate::beam::arms::run_budgeted_context_pack(
        || {
            crate::beam::arms::configured_context_pack_builder(vault, case, query_vector)
                .with_temporal_now(now)
        },
        vault,
        case,
    )
}
