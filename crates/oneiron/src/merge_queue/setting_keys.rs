//! The catalogue key `merge_queue` declares (DESIGN 15-setting-primitive, stage 4): the vault's
//! review policy for queue work that names no catalog of its own (FIX 8268).

use serde::{Deserialize, Serialize};

use super::review_policy::QueueReviewPolicy;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// What queue work that names no catalog of its own gets under the vault's review policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueueReviewChoice {
    /// No critic hold: the same checked queue lands it on green (`REVIEW_POLICY_DEFAULT`).
    LandOnGreen,
    /// It waits for this policy's critics on its lenses, or for the owner's Approve.
    Review(QueueReviewPolicy),
    /// It holds as `review_policy_unreadable`: what a row that does not read reads as. No one
    /// sets it.
    Held,
}

impl SettingValue for QueueReviewChoice {
    fn check(self) -> Result<Self> {
        match &self {
            Self::LandOnGreen => {}
            // A catalog is validated as every catalog is; its limits have no floor.
            Self::Review(policy) => {
                crate::critic::triage_critiques(&policy.catalog, &[], &[]).map_err(|error| {
                    Error::InvalidConfig(format!(
                        "the review policy's lens catalog does not validate: {error}"
                    ))
                })?;
            }
            Self::Held => {
                return Err(Error::InvalidConfig(
                    "`held` is what a review policy row that does not read reads as; set \
                     `land_on_green` or a `review`"
                        .into(),
                ));
            }
        }
        Ok(self)
    }
}

fn land_on_green() -> QueueReviewChoice {
    QueueReviewChoice::LandOnGreen
}

fn held() -> QueueReviewChoice {
    QueueReviewChoice::Held
}

/// The queue's drain wakes on each applied change, so a clear releases inherited waits at once.
fn wake_queue_drain(vault: &Vault) {
    vault.store.notify_attempt_observers();
}

crate::setting::setting_keys! {
    /// The vault's review policy for merge queue work that names no catalog of its own (FIX
    /// 8268). `land_on_green`, the default, lands that work on green through the same checks. A
    /// `review` (a lens catalog and its limits, which are the owner's to override, never floors)
    /// holds it for critics on those lenses or the owner's Approve; a proposal's own catalog
    /// stays its requirement beside it. A row that does not read reads `held`: inherited work
    /// waits until the key is set again.
    pub(crate) QUEUE_REVIEW_POLICY: QueueReviewChoice = "merge_queue.review_policy" {
        kind: Kind::new(land_on_green).strictest(held),
        after_commit: Some(wake_queue_drain),
    };
}
