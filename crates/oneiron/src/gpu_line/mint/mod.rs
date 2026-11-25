//! The mint (design pass 32, sections 4.1 and 4.3): one period record from
//! the line as it stood and the results inside the window before the period
//! started. It is a pure function of its arguments and all its arithmetic is
//! integer, so a replay gives the same economic digest.

mod period;
mod policy;
mod rules;

pub use period::{
    MintError, SettledTally, economic_digest, line_allocation_id, mint_period,
    mint_period_with_proposal, period_balances,
};
pub use policy::{BUILT_RULES, GPU_SECONDS, LineInvalid, Pools, pools};
pub use rules::{PAYOFF_WEIGHT_SHIFT, even_split, payoff_share, posterior_sampling};
