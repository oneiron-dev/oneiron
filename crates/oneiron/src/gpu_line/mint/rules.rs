//! The allowance rules the mint funds (design pass 32, section 4.3):
//! `payoff_share@1`, `even_split@1` and `posterior_sampling@1`.

use crate::EntityId;
use crate::gpu_line::fold::{BudgetPolicy, FamilyPayoff, InvalidCost, RuleRef};

/// `payoff_share`'s weight is `(wins + 1) * 2^PAYOFF_WEIGHT_SHIFT / (cost +
/// prior)`: the scale keeps every positive weight above zero.
pub const PAYOFF_WEIGHT_SHIFT: u32 = 60;

/// One family's cost under `invalid_cost`.
fn family_cost(input: &FamilyPayoff, invalid_cost: InvalidCost) -> u128 {
    let invalid = match invalid_cost {
        InvalidCost::CountsAsCost => input.invalid_secs,
        InvalidCost::CountsNowhere => 0,
    };
    u128::from(input.cost_secs) + u128::from(invalid)
}

/// The fewest low bits every weight drops so that `pool` times the highest
/// one, and the sum of all of them, fit a `u128`. All weights drop the same
/// bits, so their ratios hold. Inside the bounds of a valid line it is zero.
fn weight_shift(pool: u64, weights: &[u128]) -> u32 {
    let top = weights.iter().copied().max().unwrap_or(0);
    (0..u128::BITS)
        .find(|shift| {
            u128::from(pool).checked_mul(top >> shift).is_some()
                && weights
                    .iter()
                    .try_fold(0u128, |sum, weight| sum.checked_add(weight >> shift))
                    .is_some()
        })
        .unwrap_or(u128::BITS - 1)
}

/// `payoff_share@1` (section 4.3): confirmed promotions per GPU-second,
/// smoothed toward the base rate of the table's own families. Returns the
/// ceilings by family id and what nobody got.
///
/// `prior = max(first_rung_secs, C / max(W, 1))` over the families, and each
/// family's weight is `(wins + 1) * 2^60 / (cost + prior)`. The pool is
/// divided by weight, rounding down; the seconds left go one each to the
/// largest remainders, ties to the lowest family id. A family with no
/// history scores exactly the base rate. With no family the whole pool is
/// unallocated.
#[must_use]
pub fn payoff_share(
    pool: u64,
    families: &[&FamilyPayoff],
    first_rung_secs: u64,
    invalid_cost: InvalidCost,
) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let total_cost: u128 = families
        .iter()
        .map(|input| family_cost(input, invalid_cost))
        .sum();
    let total_wins: u128 = families.iter().map(|input| u128::from(input.wins)).sum();
    let prior = u128::from(first_rung_secs)
        .max(total_cost / total_wins.max(1))
        .max(1);
    let weights: Vec<u128> = families
        .iter()
        .map(|input| {
            let wins = u128::from(input.wins) + 1;
            let scaled = wins
                .checked_shl(PAYOFF_WEIGHT_SHIFT)
                .filter(|scaled| scaled >> PAYOFF_WEIGHT_SHIFT == wins)
                .unwrap_or(u128::MAX);
            scaled / (family_cost(input, invalid_cost) + prior)
        })
        .collect();
    let shift = weight_shift(pool, &weights);
    let weights: Vec<u128> = weights.iter().map(|weight| weight >> shift).collect();
    let sum: u128 = weights.iter().sum();
    if sum == 0 {
        return (
            families.iter().map(|input| (input.family, 0)).collect(),
            pool,
        );
    }
    let mut shares: Vec<(EntityId, u64, u128)> = families
        .iter()
        .zip(&weights)
        .map(|(input, weight)| {
            let scaled = u128::from(pool) * weight;
            let units = u64::try_from(scaled / sum).unwrap_or(pool);
            (input.family, units, scaled % sum)
        })
        .collect();
    let given: u64 = shares.iter().map(|(_, units, _)| *units).sum();
    let mut leftover = pool.saturating_sub(given);
    shares.sort_by(|left, right| right.2.cmp(&left.2).then(left.0.cmp(&right.0)));
    for share in &mut shares {
        if leftover == 0 {
            break;
        }
        share.1 += 1;
        leftover -= 1;
    }
    let mut ceilings: Vec<(EntityId, u64)> = shares
        .into_iter()
        .map(|(family, units, _)| (family, units))
        .collect();
    ceilings.sort_by_key(|(family, _)| *family);
    (ceilings, leftover)
}

/// `even_split@1` (section 4.3): the pool divided evenly over the families.
/// Returns the ceilings by family id and what nobody got.
///
/// Each family gets `pool / n`; the remainder, fewer seconds than families,
/// is unallocated. It reads no input. With no family the whole pool is
/// unallocated.
#[must_use]
pub fn even_split(pool: u64, families: &[&FamilyPayoff]) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let count = families.len() as u64;
    let per = pool / count;
    let mut ceilings: Vec<(EntityId, u64)> =
        families.iter().map(|input| (input.family, per)).collect();
    ceilings.sort_by_key(|(family, _)| *family);
    (ceilings, pool - count * per)
}

/// `posterior_sampling@1` (section 4.3): it gives uncertain families more
/// tries. Returns the ceilings by family id and what nobody got.
///
/// The pool is divided into `min(pool / first_rung_secs, posterior_max_slots)`
/// slots of `pool / slots` seconds; each slot goes to one family. Per slot
/// and family the mint draws `w + l + 1` u64 values from the BLAKE3 XOF keyed
/// by (line, period, rule, slot, family) and takes the `(w + 1)`-th smallest
/// as the family's score, a discrete stand-in for a Beta(w + 1, l + 1) sample.
/// The slot goes to the largest score, ties to the lowest family id. Wins and
/// losses past `posterior_max_evidence` are scaled down together. It reads
/// wins and losses only, never cost. With no family, or no slot, the whole
/// pool is unallocated.
#[must_use]
pub fn posterior_sampling(
    pool: u64,
    families: &[&FamilyPayoff],
    policy: &BudgetPolicy,
    line: &EntityId,
    period: u32,
    rule: RuleRef,
) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let cap = u128::from(policy.posterior_max_evidence);
    let mut ordered: Vec<(&FamilyPayoff, u64, u64)> = Vec::with_capacity(families.len());
    for input in families {
        let wins = u128::from(input.wins);
        let losses = u128::from(input.losses);
        let (scaled_wins, scaled_losses) = if wins + losses > cap {
            let total = wins + losses;
            (wins * cap / total, losses * cap / total)
        } else {
            (wins, losses)
        };
        ordered.push((*input, scaled_wins as u64, scaled_losses as u64));
    }
    ordered.sort_by_key(|(input, _, _)| input.family);
    let first = policy.first_rung_secs();
    let slots = if first == 0 {
        0
    } else {
        (pool / first).min(u64::from(policy.posterior_max_slots))
    };
    if slots == 0 {
        let ceilings: Vec<(EntityId, u64)> = ordered
            .iter()
            .map(|(input, _, _)| (input.family, 0))
            .collect();
        return (ceilings, pool);
    }
    let slot_secs = pool / slots;
    let mut won = vec![0u64; ordered.len()];
    let mut draws: Vec<u64> = Vec::with_capacity(cap as usize + 1);
    let mut byte_buf = [0u8; 8];
    for slot in 0..slots {
        let mut best = 0usize;
        let mut best_theta = 0u64;
        for (index, entry) in ordered.iter().enumerate() {
            let (input, scaled_wins, scaled_losses) = entry;
            let count = (*scaled_wins as usize) + (*scaled_losses as usize) + 1;
            draws.clear();
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron.gpu_line.posterior_sampling:v1");
            hasher.update(line.as_bytes());
            hasher.update(&period.to_le_bytes());
            hasher.update(rule.rule.as_str().as_bytes());
            hasher.update(&rule.version.to_le_bytes());
            hasher.update(&slot.to_le_bytes());
            hasher.update(input.family.as_bytes());
            let mut xof = hasher.finalize_xof();
            for _ in 0..count {
                xof.fill(&mut byte_buf);
                draws.push(u64::from_le_bytes(byte_buf));
            }
            let theta = *draws.select_nth_unstable(*scaled_wins as usize).1;
            if index == 0 || theta > best_theta {
                best = index;
                best_theta = theta;
            }
        }
        won[best] += 1;
    }
    let ceilings: Vec<(EntityId, u64)> = ordered
        .iter()
        .zip(won.iter())
        .map(|(entry, count)| (entry.0.family, (*count) * slot_secs))
        .collect();
    (ceilings, pool - slots * slot_secs)
}
