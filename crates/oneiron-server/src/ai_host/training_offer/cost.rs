//! Fixed-code projection on the same dated workload, with each tokenizer.
use super::{ModelRegistryRow, SeatWorkload, MONTH_SECS};

/// A month of the workload at a row's list price; `None` when the window was
/// not metered throughout or the row's price does not read. A partial window
/// is never multiplied into a bill.
pub(super) fn monthly(row: &ModelRegistryRow, workload: &SeatWorkload) -> Option<f64> {
    if !workload.complete {
        return None;
    }
    let price = row.catalog.cost.as_ref()?;
    let input: f64 = price.input_per_million.parse().ok()?;
    let output: f64 = price.output_per_million.parse().ok()?;
    let window = workload
        .until
        .checked_sub(workload.from)
        .filter(|window| *window > 0)?;
    let bill =
        (workload.input_tokens? as f64 * input + workload.output_tokens? as f64 * output) / 1e6;
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
) -> (Option<f64>, bool) {
    let bill = monthly(row, workload);
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
pub(super) fn payback(before: Option<f64>, after: Option<f64>, one_off: Option<f64>) -> Option<f64> {
    let saving = before? - after?;
    let one_off = one_off?;
    (saving > 0.0).then(|| one_off / saving)
}
