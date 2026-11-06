//! The owner's standing permission for stock-model automatic approvals.
//! Absence is OFF. The setting is permission, not evidence that an offer's
//! quality, price or download conditions have been met.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

const POLICY: SideTable<(), StockAutoapprovePolicy, Named> =
    SideTable::new(&side_table::STOCK_AUTOAPPROVE_POLICY);

/// One owner-authored policy value. A changed value gets a new revision;
/// turning OFF then ON cannot revive an earlier automatic authorization.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct StockAutoapprovePolicy {
    pub enabled: bool,
    /// The actual local policy change, not an owner authentication decision.
    /// An untouched, disabled policy has no revision.
    pub revision: Option<EntityId>,
}

pub(crate) fn stock_autoapprove_policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<StockAutoapprovePolicy> {
    Ok(POLICY.get(&vault.store, txn, &())?.unwrap_or_default())
}

impl Vault {
    /// The owner's one stock-autoapproval setting. An untouched vault reads OFF.
    /// This never reports an offer approved or a model applied.
    pub fn stock_autoapprove_policy(&self) -> Result<StockAutoapprovePolicy> {
        let txn = self.store.env.read_txn()?;
        stock_autoapprove_policy_in_txn(self, &txn)
    }

    /// Saves the owner's standing permission in the owner's authenticated write.
    /// Only a change writes a new revision and native policy-setting act. Later
    /// automatic answers cite this policy revision, never this authentication.
    pub fn set_stock_autoapprove_policy(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        enabled: bool,
    ) -> Result<StockAutoapprovePolicy> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let prior = stock_autoapprove_policy_in_txn(self, txn)?;
            if prior.enabled == enabled {
                return Ok(prior);
            }
            let policy = StockAutoapprovePolicy {
                enabled,
                revision: Some(self.store.clock.entity_id()?),
            };
            POLICY.put(&self.store, txn, &(), &policy)?;
            let signed = crate::policy_setting_doors::record_policy_setting_act_in_txn(
                self,
                txn,
                crate::policy_setting_doors::PolicySetting::StockAutoapprove,
                actor,
                surface,
                &prior,
                &policy,
            )?;
            if let Some(act) = signed {
                self.record_policy_setting_op_in_txn(txn, act);
            }
            Ok(policy)
        })
    }
}
