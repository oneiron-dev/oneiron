//! Catalog list prices as fixed-point usage rates. A catalog quotes decimal
//! currency units per million tokens; [`UsageCostRates`] holds 10^-9 units
//! per million tokens. The conversion is integer-only, never through a float.
use oneiron::llm::LlmCatalogCost;

use super::model::{UsageCostRates, currency_code};

/// 10^-9 currency units in one unit: [`super::Money`]'s scale.
const NANOS_PER_UNIT: u128 = 1_000_000_000;
/// Fraction digits a 10^-9 unit amount holds exactly.
const NANO_DIGITS: usize = 9;

/// The rates `cost` quotes, in 10^-9 units per million tokens of the
/// currency it names, or of none when its provider named none (FIX 9534),
/// stamped with `price_table_snapshot`. An unquoted cache rate stays
/// unknown, never zero. `None` when any quoted rate does not convert, or the
/// currency named is not a three-letter code.
pub fn catalog_cost_rates(
    cost: &LlmCatalogCost,
    price_table_snapshot: String,
) -> Option<UsageCostRates> {
    let optional =
        |text: Option<&str>| text.map_or(Some(None), |text| decimal_nanos(text).map(Some));
    let currency = match cost.currency.as_deref() {
        Some(code) if !currency_code(code) => return None,
        code => code.map(str::to_owned),
    };
    Some(UsageCostRates {
        currency,
        price_table_snapshot,
        input_per_million: decimal_nanos(&cost.input_per_million)?,
        output_per_million: decimal_nanos(&cost.output_per_million)?,
        cache_read_per_million: optional(cost.cache_read_per_million.as_deref())?,
        cache_write_per_million: optional(cost.cache_write_per_million.as_deref())?,
    })
}

/// `text`, a plain non-negative decimal (digits and at most one `.`), in
/// 10^-9 units. A remainder below one 10^-9 unit rounds up, so a quoted price
/// is never undercounted. `None` for any other spelling, or an amount past
/// `u64`.
fn decimal_nanos(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let digits = |text: &str| {
        text.bytes().try_fold(0u128, |sum, b| {
            sum.checked_mul(10)?.checked_add(u128::from(b - b'0'))
        })
    };
    let (exact, rest) = fraction.split_at(fraction.len().min(NANO_DIGITS));
    let mut nanos = digits(exact)? * 10u128.pow(u32::try_from(NANO_DIGITS - exact.len()).ok()?);
    if rest.bytes().any(|b| b != b'0') {
        nanos += 1;
    }
    let total = digits(whole)?
        .checked_mul(NANOS_PER_UNIT)?
        .checked_add(nanos)?;
    u64::try_from(total).ok()
}
