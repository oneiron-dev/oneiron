//! Typed owner doors over the vault RSI line: configure its soft and pinned
//! shares once, read both unit-labelled lines, top up one exact limiting
//! line, and hold or resume new loop work. The ledger in `rsi` owns every
//! admission rule; these doors only check the owner's proof and project.
use serde::{Deserialize, Serialize};

use super::rsi::{RsiBudgetConfig, RsiBudgetError, RsiTopUp};
use crate::consent::AuthenticatedOwner;
use crate::{Result, Vault};

/// The vault RSI line itself: no selector names another vault's line.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RsiLineRequest {}

/// One named share of the token line, advisory unless pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiShareView {
    pub label: String,
    pub units: u64,
    pub pinned: bool,
}

/// The token-denominated loop line.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiWorkLineView {
    pub unit: String,
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
}

/// The exposure-denominated exploration line, independent of token spend.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiExposureLineView {
    pub unit: String,
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
}

/// Both RSI lines, their shares and the hold that stops new loop work
/// without killing admitted work. Resource depletion reads here as
/// `suspended`, never as a terminal failure.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiLineView {
    pub work_line: RsiWorkLineView,
    pub shares: Vec<RsiShareView>,
    pub exposure_line: RsiExposureLineView,
    pub suspended: bool,
}

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
pub fn top_up_rsi_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &RsiTopUp,
) -> Result<RsiLineView> {
    owner.revalidate(vault)?;
    vault.top_up_rsi_budget(input.clone()).map_err(rsi_error)?;
    line_view(vault)
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
