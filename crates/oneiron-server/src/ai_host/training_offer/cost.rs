//! Fixed-code projection on the same dated workload, with each tokenizer.
use super::{CATALOG_CURRENCY, MONTH_SECS, ModelRegistryRow, SeatUsage, SeatWorkload};
use crate::usage::catalog_cost_rates;

/// A month of the workload at a row's list price; `None` when the window was
/// not metered throughout or the row's price does not read. A partial window
/// is never multiplied into a bill. The row's rates are read as a settlement
/// reads them (`catalog_cost_rates`), and the seat's cached prompt tokens in
/// `usage` are priced at the row's quoted cache rates; a cache rate the row
/// does not quote leaves those tokens at its input price.
pub(super) fn monthly(
    row: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> Option<f64> {
    if !workload.complete {
        return None;
    }
    let rates = catalog_cost_rates(row.catalog.cost.as_ref()?, CATALOG_CURRENCY, String::new())?;
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
    let per_million = [
        Some((input, rates.input_per_million)),
        Some((workload.output_tokens?, rates.output_per_million)),
        read,
        write,
    ]
    .into_iter()
    .flatten()
    .try_fold(0u128, |sum, (tokens, rate)| {
        sum.checked_add(u128::from(tokens) * u128::from(rate))
    })?;
    // In 10^-9 units, rounded up as a settlement's amount is.
    let bill = per_million.div_ceil(1_000_000) as f64 / 1e9;
    Some(bill * MONTH_SECS as f64 / window as f64).filter(|bill| bill.is_finite())
}

/// A month of the workload at a candidate `row`'s list price, its counts the
/// incumbent's scaled to the candidate's tokenizer: by the two rows'
/// measured tokens per o200k token. With either unmeasured the counts stay
/// the incumbent's, and the figure is an estimate (`true`).
pub(super) fn candidate_monthly(
    incumbent: &ModelRegistryRow,
    row: &ModelRegistryRow,
    workload: &SeatWorkload,
    usage: &SeatUsage,
) -> (Option<f64>, bool) {
    let bill = monthly(row, workload, usage);
    match (row.tokens_per_o200k, incumbent.tokens_per_o200k) {
        (Some(candidate), Some(incumbent)) => (
            bill.map(|bill| bill * candidate / incumbent)
                .filter(|bill| bill.is_finite()),
            false,
        ),
        _ => (bill, bill.is_some()),
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
