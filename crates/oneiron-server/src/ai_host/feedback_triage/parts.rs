//! A long revision's parts (FIX 7549): the window a request must fit on the
//! Coach's seat, and the item cut into spans whose requests each fit it,
//! end to end and on character boundaries. A span too long for the window
//! is cut smaller, never dropped, and there is no total on how many there
//! are. Each part goes to the model as the source's data, never as an
//! instruction.
use oneiron::EntityId;
use oneiron::ModelId;
use oneiron::feedback::{
    FeedbackTriageInput, FeedbackTriageNodeInput, FeedbackTriagePin, FeedbackTriageSourceRef,
    FeedbackTriageSpan, FeedbackTriageStep,
};
use oneiron::skill::LoadedSkillPack;
use serde::Serialize;

use super::{Run, unavailable};
use crate::ai_host::code_fix::HostModels;
use crate::server::SyncServer;

/// The input one request may fill: the model's window less the output it
/// reserves.
pub(super) struct Window {
    /// The model whose window it is.
    pub(super) model: String,
    /// Its tokens.
    pub(super) input_tokens: u64,
}

impl Window {
    /// The window a generation was cut for, while the seat's reads unknown.
    pub(super) fn from_pin(pin: &FeedbackTriagePin) -> Self {
        Self {
            model: pin.model.clone(),
            input_tokens: pin.input_tokens,
        }
    }
}

/// What the provider's tokenizer may count above the engine's on a model
/// whose ratio was never measured: up to twice as many, as compaction
/// reserves for a summary (FIX 10305).
const UNMEASURED_COUNT_FACTOR: u64 = 2;
/// The reply frame that margin leaves, as compaction's.
const REPLY_FRAME_TOKENS: u64 = 64;

/// The smallest window any rung of the Coach seat may serve a call on
/// (FIX 10303): each rung's catalog window less the output it reserves, in
/// the engine's own count (FIX 10305), less the prompt the rung prepends;
/// the seat model's own row when no rung's reads. `None` while no window is
/// known, and the item then goes whole, as it always has.
pub(super) fn window(server: &SyncServer, models: &HostModels<'_>) -> Option<Window> {
    let seat = server.ai.model_runtime().seat(models.coach())?;
    let vault = server.vault();
    let mut smallest: Option<Window> = None;
    for (model, prompt) in seat.rung_models() {
        let Some(input) = model_window(vault, &model) else {
            continue;
        };
        let prompt_tokens = prompt.as_deref().map_or(0, |prompt| {
            oneiron::count_context_pack_tokens(prompt) as u64
        });
        let input_tokens = input.saturating_sub(prompt_tokens);
        if smallest
            .as_ref()
            .is_none_or(|window| input_tokens < window.input_tokens)
        {
            smallest = Some(Window {
                model: model.as_str().to_owned(),
                input_tokens,
            });
        }
    }
    smallest.or_else(|| {
        model_window(vault, &seat.model).map(|input_tokens| Window {
            model: seat.model.as_str().to_owned(),
            input_tokens,
        })
    })
}

/// `model`'s window less the output its catalog row reserves (an output at
/// or past the window reserves nothing), in the engine's count: divided by
/// the tokens its tokenizer counts per o200k token where it counts more,
/// and while that ratio is unmeasured, cut to what twice the engine's count
/// and a reply frame fill. `None` while its row or window is unknown.
fn model_window(vault: &oneiron::Vault, model: &ModelId) -> Option<u64> {
    let row = match vault.model_registry_row(model) {
        Ok(row) => row?,
        Err(error) => {
            tracing::warn!(
                %model,
                kind = ?error.kind(),
                "a Coach seat model's row did not read; its window is unknown"
            );
            return None;
        }
    };
    let context = row.catalog.context_window_tokens;
    if context == 0 {
        return None;
    }
    let output = row
        .catalog
        .max_output_tokens
        .filter(|output| *output < context)
        .unwrap_or(0);
    let input = context - output;
    Some(match row.tokens_per_o200k {
        Some(ratio) if ratio > 1.0 => (input as f64 / ratio) as u64,
        Some(_) => input,
        None => (input / UNMEASURED_COUNT_FACTOR).saturating_sub(REPLY_FRAME_TOKENS),
    })
}

/// Whether the System `instruction` and the User `data` fit `input_tokens`,
/// counted once as one text.
pub(super) fn fits(input_tokens: u64, instruction: &str, data: &str) -> bool {
    oneiron::count_context_pack_tokens(&[instruction, data].join("\n")) as u64 <= input_tokens
}

/// The data one part reads: its span of the item's text, with the ids its
/// findings cite.
#[derive(Serialize)]
struct PartData<'a> {
    source_ref: &'a FeedbackTriageSourceRef,
    evidence: &'a EntityId,
    part: PartSpan,
    text: &'a str,
}

/// Where a part's text stands in the item's: bytes `start` to `end` of `of`.
#[derive(Serialize)]
struct PartSpan {
    start: u64,
    end: u64,
    of: u64,
}

fn data(
    source_ref: &FeedbackTriageSourceRef,
    evidence: &EntityId,
    span: FeedbackTriageSpan,
    of: u64,
    text: &str,
) -> oneiron::Result<String> {
    serde_json::to_string(&PartData {
        source_ref,
        evidence,
        part: PartSpan {
            start: span.start,
            end: span.end,
            of,
        },
        text,
    })
    .map_err(|_| unavailable("a feedback item's part could not be encoded"))
}

/// A part child's data, from the span its node names.
pub(super) fn node_data(input: &FeedbackTriageNodeInput) -> oneiron::Result<String> {
    let span = input
        .node
        .span
        .ok_or_else(|| unavailable("a feedback triage part names no span"))?;
    let text = input
        .text
        .as_deref()
        .ok_or_else(|| unavailable("a feedback triage part holds no text"))?;
    data(
        &input.source_ref,
        &input.evidence,
        span,
        input.item_bytes,
        text,
    )
}

/// The first character boundary of `text` past `at`.
fn next_boundary(text: &str, at: usize) -> usize {
    text.get(at..)
        .and_then(|rest| rest.chars().next())
        .map_or(text.len(), |first| at + first.len_utf8())
}

fn offset(at: u64) -> oneiron::Result<usize> {
    usize::try_from(at)
        .map_err(|_| unavailable("a feedback item's part lies past this host's reach"))
}

/// `within` of `item` cut, in order and whole, into spans whose part
/// requests each fit `input_tokens` beside `instruction`: from each start,
/// the longest run of characters found to fit. A window that cannot take
/// even one character beside the instruction fails the job, which stays
/// owed.
fn partition(
    input: &FeedbackTriageInput,
    item: &str,
    within: FeedbackTriageSpan,
    input_tokens: u64,
    instruction: &str,
) -> oneiron::Result<Vec<FeedbackTriageSpan>> {
    let of = item.len() as u64;
    let fitting = |start: usize, end: usize| -> oneiron::Result<bool> {
        let text = item
            .get(start..end)
            .ok_or_else(|| unavailable("a feedback item's part left a character boundary"))?;
        let span = FeedbackTriageSpan {
            start: start as u64,
            end: end as u64,
        };
        let data = data(&input.source_ref, &input.evidence, span, of, text)?;
        Ok(fits(input_tokens, instruction, &data))
    };
    let end = offset(within.end)?;
    let mut start = offset(within.start)?;
    let mut spans = Vec::new();
    while start < end {
        let mut low = next_boundary(item, start);
        if !fitting(start, low)? {
            return Err(unavailable(
                "the Coach's window holds its instruction but not one character of the item",
            ));
        }
        let mut high = end;
        if fitting(start, high)? {
            low = high;
        }
        // `low` fits and `high` does not, until no boundary lies between.
        while next_boundary(item, low) < high {
            let mut mid = low + (high - low) / 2;
            while !item.is_char_boundary(mid) {
                mid -= 1;
            }
            if mid <= low {
                mid = next_boundary(item, low);
            }
            if fitting(start, mid)? {
                low = mid;
            } else {
                high = mid;
            }
        }
        spans.push(FeedbackTriageSpan {
            start: start as u64,
            end: low as u64,
        });
        start = low;
    }
    Ok(spans)
}

/// Cuts a revision too long for the window into parts and parks its job on
/// them: a new generation, pinned to the arm `loaded` names and to `window`.
pub(super) fn begin(
    run: &Run<'_>,
    input: &FeedbackTriageInput,
    loaded: &LoadedSkillPack,
    instruction: &str,
    window: Window,
) -> oneiron::Result<()> {
    let item = input.item.text()?;
    let whole = FeedbackTriageSpan {
        start: 0,
        end: item.len() as u64,
    };
    let spans = partition(input, &item, whole, window.input_tokens, instruction)?;
    let pin = FeedbackTriagePin {
        skill: input.skill,
        entity: loaded.entity,
        version: loaded.record.version.clone(),
        model: window.model,
        input_tokens: window.input_tokens,
    };
    run.server
        .vault()
        .park_coach_feedback_triage(
            run.admitted,
            FeedbackTriageStep::Generation { pin, spans },
            run.now,
        )
        .map(drop)
}

/// An unanswered part's span cut again for a changed window; `None` while
/// it still fits whole.
pub(super) fn split(
    input: &FeedbackTriageInput,
    item: &str,
    span: FeedbackTriageSpan,
    input_tokens: u64,
    instruction: &str,
) -> oneiron::Result<Option<Vec<FeedbackTriageSpan>>> {
    let spans = partition(input, item, span, input_tokens, instruction)?;
    Ok((spans.len() > 1).then_some(spans))
}
