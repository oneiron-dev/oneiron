//! Shared Beta posterior bandit seam. Defined in `oneiron-contracts`; every
//! `oneiron::posterior` path is unchanged.

pub use oneiron_contracts::posterior::Posterior;
pub(crate) use oneiron_contracts::posterior::{beta_mean, beta_std_dev};
