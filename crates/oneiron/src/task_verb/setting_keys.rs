//! The consult expiry's pack Setting key (owner ruling PACK-SETTINGS-ALL = B): the recovery
//! choices a lapsed consult's expiry artifact offers its asker. The default is the shipped
//! [`CONSULT_EXPIRY_RECOVERY`]. The owner changes the value; an agent's change waits on the
//! owner's approval.
//!
//! Direction: none. A choice is a menu entry, and nothing is sent to anyone until someone takes
//! one, so no menu contacts more people than another. A row that does not decode reads as the
//! shipped menu: the expiry sweep goes on.

use serde::{Deserialize, Serialize};

use super::consult_payload::ConsultRecovery;
use super::consult_result::CONSULT_EXPIRY_RECOVERY;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// One recovery an expiry offers, by its wire token
/// ([`ConsultRecovery::as_str`]). A menu names "try another peer" only: the peer is chosen by
/// whoever takes the recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsultRecoveryChoice {
    RetryAssignee,
    NudgeAssignee,
    TryPeer,
}

impl ConsultRecoveryChoice {
    const fn of(recovery: ConsultRecovery) -> Self {
        match recovery {
            ConsultRecovery::RetryAssignee => Self::RetryAssignee,
            ConsultRecovery::NudgeAssignee => Self::NudgeAssignee,
            ConsultRecovery::TryPeer(_) => Self::TryPeer,
        }
    }

    const fn recovery(self) -> ConsultRecovery {
        match self {
            Self::RetryAssignee => ConsultRecovery::RetryAssignee,
            Self::NudgeAssignee => ConsultRecovery::NudgeAssignee,
            Self::TryPeer => ConsultRecovery::TryPeer(None),
        }
    }
}

/// The recovery choices an expiry offers, in the order offered: at least one, each at most once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ConsultExpiryRecoveryMenu(pub(crate) Vec<ConsultRecoveryChoice>);

impl ConsultExpiryRecoveryMenu {
    /// The typed choices the expiry artifact carries.
    pub(crate) fn recovery(&self) -> Vec<ConsultRecovery> {
        self.0
            .iter()
            .copied()
            .map(ConsultRecoveryChoice::recovery)
            .collect()
    }
}

impl SettingValue for ConsultExpiryRecoveryMenu {
    fn check(self) -> Result<Self> {
        if self.0.is_empty() {
            return Err(Error::InvalidConfig(
                "a consult expiry offers at least one recovery".to_owned(),
            ));
        }
        for (index, choice) in self.0.iter().enumerate() {
            if self.0[..index].contains(choice) {
                return Err(Error::InvalidConfig(format!(
                    "a consult expiry offers {} once",
                    choice.recovery().as_str()
                )));
            }
        }
        Ok(self)
    }
}

fn shipped_menu() -> ConsultExpiryRecoveryMenu {
    ConsultExpiryRecoveryMenu(
        CONSULT_EXPIRY_RECOVERY
            .iter()
            .copied()
            .map(ConsultRecoveryChoice::of)
            .collect(),
    )
}

crate::setting::setting_keys! {
    /// The recovery choices a lapsed consult's expiry artifact offers its asker, in the order
    /// offered: any of retry_assignee, nudge_assignee and try_peer, each at most once (default
    /// all three, in that order). No direction: nothing is sent to anyone until someone takes a
    /// choice. An unreadable row reads as the default.
    pub(crate) TASK_CONSULT_EXPIRY_RECOVERY: ConsultExpiryRecoveryMenu =
        "task.consult.expiry_recovery" {
        kind: Kind::new(shipped_menu).strictest(shipped_menu),
    };
}

/// The recovery choices in force in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn consult_expiry_recovery_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<ConsultRecovery>> {
    Ok(TASK_CONSULT_EXPIRY_RECOVERY
        .read_in_txn(vault, txn, &[], None)?
        .value
        .recovery())
}
