//! Reported token facts, kept separate from the native line's charged units.
use std::collections::HashSet;

use oneiron::LlmResponse;
use oneiron::llm::run_admission::{RunEvent, RunReceipt};

pub(super) struct Usage {
    pub(super) tokens: u64,
    pub(super) complete: bool,
}

/// An answer's aggregate stands for its own physical receipts. Only the
/// additional observations are added to it; failed rungs keep their reports.
pub(super) fn reported(rows: &[RunReceipt], answer: Option<&LlmResponse>) -> Usage {
    let mut result = Usage {
        tokens: 0,
        complete: true,
    };
    let mut dispatched = HashSet::new();
    let mut settled = HashSet::new();
    let mut answer_kept = false;
    for row in rows {
        if let RunEvent::Dispatched { lease, .. } = &row.event {
            dispatched.insert(lease.as_str());
        }
        let RunEvent::Settled {
            lease,
            dispatched,
            usage,
            inference_calls,
            ..
        } = &row.event
        else {
            continue;
        };
        settled.insert(lease.as_str());
        if !dispatched {
            continue;
        }
        let matching = answer.filter(|answer| {
            !answer_kept
                && usage.as_ref().is_some_and(|usage| {
                    usage.input == answer.usage.input && usage.output == answer.usage.output
                })
        });
        if let Some(answer) = matching {
            answer_kept = true;
            result.complete &= !inference_calls.is_empty()
                && inference_calls.iter().all(|call| {
                    call.logical_prompt_tokens.is_some() && call.output_tokens.is_some()
                });
            let mut represented = answer.usage.inference_calls();
            let mut physical = 0_u64;
            for receipt in inference_calls {
                let tokens = receipt
                    .logical_prompt_tokens
                    .unwrap_or(0)
                    .saturating_add(receipt.output_tokens.unwrap_or(0));
                if let Some(at) = represented.iter().position(|reported| reported == receipt) {
                    represented.remove(at);
                    physical = physical.saturating_add(tokens);
                    continue;
                }
                result.tokens = result.tokens.saturating_add(tokens);
                result.complete &=
                    receipt.logical_prompt_tokens.is_some() && receipt.output_tokens.is_some();
            }
            let aggregate = answer
                .usage
                .input
                .total
                .saturating_add(answer.usage.output.total);
            result.tokens = result.tokens.saturating_add(aggregate.max(physical));
            result.complete &= represented.is_empty();
        } else {
            let mut physical = 0_u64;
            let mut complete = !inference_calls.is_empty();
            for receipt in inference_calls {
                physical = physical.saturating_add(
                    receipt
                        .logical_prompt_tokens
                        .unwrap_or(0)
                        .saturating_add(receipt.output_tokens.unwrap_or(0)),
                );
                complete &=
                    receipt.logical_prompt_tokens.is_some() && receipt.output_tokens.is_some();
            }
            let logical = usage
                .as_ref()
                .map(|usage| usage.input.total.saturating_add(usage.output.total));
            // If an answer was lost after settlement, its aggregate and the
            // physical observations may overlap. Their maximum is a lower
            // bound, not an invented sum or a complete-usage assertion.
            result.tokens = result
                .tokens
                .saturating_add(physical.max(logical.unwrap_or(0)));
            result.complete &= complete;
        }
    }
    result.complete &= dispatched.is_subset(&settled) && (answer.is_none() || answer_kept);
    result
}
