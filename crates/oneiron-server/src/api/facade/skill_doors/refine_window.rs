//! The tokens one skill-conversion refiner request may fill: the engine's
//! count of a text, and the window a seat's rungs leave for a request.
use crate::models::Seat;

/// `text`'s tokens in the engine's count.
pub(super) fn tokens(text: &str) -> u64 {
    u64::try_from(oneiron::count_context_pack_tokens(text)).unwrap_or(u64::MAX)
}

/// Whether the System `prompt` and the User `data` fit `window`, counted as
/// one text.
pub(super) fn fits(window: u64, prompt: &str, data: &str) -> bool {
    tokens(&[prompt, data].join("\n")) <= window
}

/// What the provider's tokenizer may count above the engine's on a model
/// whose ratio was never measured, and the reply frame that margin leaves,
/// as a Coach triage part's window takes them (FIX 10305).
const UNMEASURED_COUNT_FACTOR: u64 = 2;
const REPLY_FRAME_TOKENS: u64 = 64;

/// The tokens one refiner request may fill on `seat` (FIX 8989): the
/// smallest window any of its rungs may serve it on, less the prompt the
/// rung prepends, else its own model's. `None` while no window is known.
pub(super) fn refine_window(vault: &oneiron::Vault, seat: &Seat) -> Option<u64> {
    seat.rung_models()
        .into_iter()
        .filter_map(|(model, prompt)| {
            let input = input_tokens(vault, &model)?;
            Some(input.saturating_sub(prompt.as_deref().map_or(0, tokens)))
        })
        .min()
        .or_else(|| input_tokens(vault, &seat.model))
}

/// `model`'s window less the output its catalog row reserves, in the
/// engine's count: divided by the tokens its tokenizer counts per o200k
/// token where it counts more, and while that ratio is unmeasured, cut to
/// what twice the engine's count and a reply frame fill. `None` while its
/// row or window is unknown.
fn input_tokens(vault: &oneiron::Vault, model: &oneiron::ModelId) -> Option<u64> {
    let row = vault.model_registry_row(model).ok().flatten()?;
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
