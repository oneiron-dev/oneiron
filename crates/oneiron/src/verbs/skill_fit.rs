//! The owner's marketplace skill-fit setting (FIX 11089): the rule fit or the
//! owner-asked fit for ordinary skill installs. The engine writer owns the
//! setting, its nonce-qualified consent and its side-table row; this door
//! only exposes that act through the typed owner surface. Requested
//! permissions stay inert either way: the fit only decides whether an
//! install lands now or asks.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

use super::HubConsentReceipt;

/// The owner's skill-fit choice on the wire: the existing rule fit or the
/// owner-asked fit. A wire-only projection of
/// [`crate::skill_hub::SkillFitSetting`], never a second store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkillFitChoice {
    RuleFit,
    OwnerAsked,
}

impl From<SkillFitChoice> for crate::skill_hub::SkillFitSetting {
    fn from(choice: SkillFitChoice) -> Self {
        match choice {
            SkillFitChoice::RuleFit => Self::RuleFit,
            SkillFitChoice::OwnerAsked => Self::OwnerAsked,
        }
    }
}

/// `vault.skills.fit.set`'s input: the fit ordinary installs run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillFitSetRequest {
    pub setting: SkillFitChoice,
}

/// `vault.skills.fit.set`: the owner picks which fit an ordinary skill
/// install runs. The engine writer revalidates the proof, consents once and
/// spends that authorization in the same writer; this door preserves its
/// [`crate::consent::ConsentReceipt`] as a [`HubConsentReceipt`].
pub fn skill_fit_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillFitSetRequest,
) -> MemoryResult<HubConsentReceipt> {
    Ok(vault
        .set_marketplace_skill_fit(owner, input.setting.into())?
        .into())
}
