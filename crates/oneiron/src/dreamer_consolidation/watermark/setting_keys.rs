//! The Meso round's turn cap as the owner's Setting key (restriction wave 14, C105; owner 16 Nov
//! 00:44: "optional freedom with good defaults everywhere"). The default is
//! [`DEFAULT_MESO_ROUND_TURN_CAP`], the cap every round kept before, so nothing moves until the
//! owner sets a row through `vault.settings.set`. The cap is at least one: a zero cap takes no
//! turn, so the backlog would never drain. Each round reads it in its own snapshot, and the
//! compound watermark records the exact cut whatever the cap.

use serde::{Deserialize, Serialize};

use super::DEFAULT_MESO_ROUND_TURN_CAP;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// Admissible TURNs one Meso round takes, at least one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct MesoRoundTurnCap(pub(crate) u64);

impl MesoRoundTurnCap {
    /// The least cap the key takes.
    const LEAST: u64 = 1;

    /// The cap as a count of TURNs, whole on every target the engine builds for.
    fn turns(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl SettingValue for MesoRoundTurnCap {
    fn check(self) -> Result<Self> {
        if self.0 < Self::LEAST {
            return Err(Error::InvalidConfig(
                "a Meso round's turn cap is at least 1".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// The cap every round kept before the key.
fn meso_round_turn_cap_default() -> MesoRoundTurnCap {
    MesoRoundTurnCap(DEFAULT_MESO_ROUND_TURN_CAP as u64)
}

/// What an unreadable row reads as: the least work that still drains, one TURN a round.
fn least_meso_round_turn_cap() -> MesoRoundTurnCap {
    MesoRoundTurnCap(MesoRoundTurnCap::LEAST)
}

crate::setting::setting_keys! {
    /// Admissible TURNs one Meso round takes (500 by default); a larger backlog drains across the
    /// following rounds, and one wake prepares one round's worth of queued TURNs.
    pub(crate) MESO_ROUND_TURN_CAP: MesoRoundTurnCap = "dreamer.consolidation.meso_round_turn_cap" {
        kind: Kind::new(meso_round_turn_cap_default)
            .strictest(least_meso_round_turn_cap)
            .tighter(lower_is_tighter::<MesoRoundTurnCap>),
    };
}

/// The Meso round's turn cap in force in `txn`: the owner's row, else the default.
pub(crate) fn meso_round_turn_cap_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<usize> {
    Ok(MESO_ROUND_TURN_CAP
        .read_in_txn(vault, txn, &[], None)?
        .value
        .turns())
}
