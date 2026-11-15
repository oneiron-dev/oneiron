//! Fixed-code projection on the same dated workload, with each tokenizer.
use super::{CATALOG_CURRENCY, MONTH_SECS, ModelRegistryRow, SeatUsage, SeatWorkload};
use crate::usage::catalog_cost_rates;

/// A window's bill at a row's list price, in 10^-9 units per million
/// tokens, its two sides apart: the prompt side (input tokens, cached ones at
/// the row's quoted cache rates) and the answer side (output tokens); and
/// the window's length in seconds. `None` as for [`monthly`].
fn window_bill(
    row: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> Option<(u128, u128, u64)> {
    if !workload.complete {
        return None;
    }
    let rates = catalog_cost_rates(row.catalog.cost.as_ref()?, String::new()).filter(|rates| {
        rates.free_in_any_currency() || rates.currency.as_deref() == Some(CATALOG_CURRENCY)
    })?;
    let window = workload
        .until
        .checked_sub(workload.from)
        .filter(|window| *window > 0)?;
    let read = rates
        .cache_read_per_million
        .map(|rate| (usage.cache_read_tokens, rate));
    let write = rates
        .cache_write_per_million
        .map(|rate| (usage.cache_write_tokens, rate));
    // The prompt tokens left at the input price: all but the cached ones
    // priced at a rate of their own.
    let input = [read, write]
        .into_iter()
        .flatten()
        .try_fold(workload.input_tokens?, |input, (tokens, _)| {
            input.checked_sub(tokens)
        })?;
    let prompt = [Some((input, rates.input_per_million)), read, write]
        .into_iter()
        .flatten()
        .try_fold(0u128, |sum, (tokens, rate)| {
            sum.checked_add(u128::from(tokens) * u128::from(rate))
        })?;
    let answer = u128::from(workload.output_tokens?) * u128::from(rates.output_per_million);
    Some((prompt, answer, window))
}

/// A window's bill in 10^-9 units, as a month's.
fn month_of(bill_units: f64, window: u64) -> Option<f64> {
    Some(bill_units / 1e9 * MONTH_SECS as f64 / window as f64).filter(|bill| bill.is_finite())
}

/// A month of the workload at a row's list price; `None` when the window was
/// not metered throughout, the row's price does not read, or it is not quoted
/// in the offer's currency: a rate in another currency, or in none its
/// provider named, is never read as the offer's (FIX 9534), unless every rate
/// is zero, which is zero in any currency. A partial window is never
/// multiplied into a bill. The row's rates are read as a settlement
/// reads them (`catalog_cost_rates`), and the seat's cached prompt tokens in
/// `usage` are priced at the row's quoted cache rates; a cache rate the row
/// does not quote leaves those tokens at its input price.
pub(super) fn monthly(
    row: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> Option<f64> {
    let (prompt, answer, window) = window_bill(row, workload, usage)?;
    // In 10^-9 units, rounded up as a settlement's amount is.
    month_of(
        prompt.checked_add(answer)?.div_ceil(1_000_000) as f64,
        window,
    )
}

/// A month of the workload at a candidate `row`'s list price on projected
/// counts: the incumbent's prompt tokens scaled by the two rows' measured
/// prompt-shaped tokens per o200k token, and its answer tokens by their
/// answer-shaped ones (ARCH-0053:341). With either row lacking either ratio
/// the counts stay the incumbent's, and the figure is an estimate (`true`).
pub(super) fn candidate_monthly(
    incumbent: &ModelRegistryRow,
    row: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> (Option<f64>, bool) {
    let ratios = |row: &ModelRegistryRow| row.tokens_per_o200k.zip(row.answer_tokens_per_o200k);
    match (ratios(row), ratios(incumbent)) {
        (
            Some((candidate_prompt, candidate_answer)),
            Some((incumbent_prompt, incumbent_answer)),
        ) => {
            let bill = window_bill(row, workload, usage).and_then(|(prompt, answer, window)| {
                let per_million = prompt as f64 * candidate_prompt / incumbent_prompt
                    + answer as f64 * candidate_answer / incumbent_answer;
                // In 10^-9 units, rounded up as a settlement's amount is.
                month_of((per_million / 1e6).ceil(), window)
            });
            (bill, false)
        }
        _ => {
            let bill = monthly(row, workload, usage);
            (bill, bill.is_some())
        }
    }
}

/// Months until the one-off cost is paid back; `None` when any side is
/// unknown or nothing is saved.
pub(super) fn payback(
    before: Option<f64>,
    after: Option<f64>,
    one_off: Option<f64>,
) -> Option<f64> {
    let saving = before? - after?;
    let one_off = one_off?;
    (saving > 0.0).then(|| one_off / saving)
}
