//! Typed owner doors over the vault RSI line: configure its soft and pinned
//! shares once, read both unit-labelled lines, top up one exact limiting
//! line, and hold or resume new loop work. The ledger in `rsi` owns every
//! admission rule; these doors only check the owner's proof and project.

use super::rsi::{RsiBudgetConfig, RsiBudgetError, RsiTopUp};
use crate::consent::AuthenticatedOwner;
use crate::{Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::budget::rsi_doors::{
    RsiExposureLineView, RsiLineRequest, RsiLineView, RsiShareView, RsiWorkLineView,
};

fn rsi_error(error: RsiBudgetError) -> crate::Error {
    match error {
        RsiBudgetError::Engine(error) => error,
        other => crate::Error::InvalidConfig(other.to_string()),
    }
}

fn line_view(vault: &Vault) -> Result<RsiLineView> {
    let config = vault.rsi_budget_config().map_err(rsi_error)?;
    let work = vault.rsi_budget().map_err(rsi_error)?;
    let exploration = vault.rsi_exploration().map_err(rsi_error)?;
    Ok(RsiLineView {
        work_line: RsiWorkLineView {
            unit: "tokens".to_owned(),
            limit: work.limit,
            spent: work.spent,
            reserved: work.reserved,
        },
        shares: config
            .shares
            .into_iter()
            .map(|(label, share)| RsiShareView {
                label,
                units: share.units,
                pinned: share.pinned,
            })
            .collect(),
        exposure_line: RsiExposureLineView {
            unit: "exposures".to_owned(),
            limit: exploration.exposure_limit,
            spent: exploration.spent_exposure,
            reserved: exploration.reserved_exposure,
        },
        suspended: work.suspended,
        check_in: None,
    })
}

/// Creates the vault RSI line once, with its soft and pinned shares.
pub fn configure_rsi_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &RsiBudgetConfig,
) -> Result<RsiLineView> {
    owner.revalidate(vault)?;
    vault
        .configure_rsi_budget(input.clone())
        .map_err(rsi_error)?;
    line_view(vault)
}

/// Reads both RSI lines, every share and the hold state.
pub fn rsi_line_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &RsiLineRequest,
) -> Result<RsiLineView> {
    owner.revalidate(vault)?;
    line_view(vault)
}

/// Raises one exact limiting line: the token limit, the exposure limit, or
/// one named share. Held work stays held until the owner resumes it.
///
/// The raise checks in (act class `spend_over_cap`, named at this door;
/// P25-SHAPE Q4 = A): the owner's own raise goes on their own proof, and
/// with the line's `check_in_ref` the owner applies an asker's approved
/// check-in for exactly this raise
/// ([`crate::check_in::rsi_top_up_effect_digest`]), spent in the top-up's
/// writer (2k10b). The answer names the decision.
///
/// # Errors
///
/// A `check_in_ref` that is no 32-hex id; a proof that no longer holds; the
/// top-up's refusals; a check-in that is not an approved ask for this raise.
pub fn top_up_rsi_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &RsiTopUp,
) -> Result<RsiLineView> {
    let applied = match input.check_in_ref() {
        Some(hex) => Some(crate::check_in::AppliedCheckIn {
            id: crate::EntityId::from_hex(hex).map_err(|_| {
                crate::Error::InvalidConfig("check_in_ref is not a check-in id".into())
            })?,
            verb: "vault.budgets.rsi.top_up",
            effect_digest: crate::check_in::rsi_top_up_effect_digest(input),
        }),
        None => None,
    };
    let decision = vault
        .top_up_rsi_budget_with_check_in(owner, input, applied.as_ref())
        .map_err(rsi_error)?;
    Ok(RsiLineView {
        check_in: Some(decision),
        ..line_view(vault)?
    })
}

/// Holds new loop work; admitted reservations can still settle honestly.
pub fn hold_rsi_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &RsiLineRequest,
) -> Result<RsiLineView> {
    owner.revalidate(vault)?;
    vault.suspend_rsi_budget(true).map_err(rsi_error)?;
    line_view(vault)
}

/// Releases the hold on new loop work, on the same line and receipts.
pub fn resume_rsi_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &RsiLineRequest,
) -> Result<RsiLineView> {
    owner.revalidate(vault)?;
    vault.resume_rsi_budget().map_err(rsi_error)?;
    line_view(vault)
}
