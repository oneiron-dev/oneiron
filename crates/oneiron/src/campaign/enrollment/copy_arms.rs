//! Campaign copy A/B arms (ARCH-0059 #copy-review): a program step may carry
//! an arm label, each member's send records the arm it carried, and the
//! campaign's outcome splits by arm.
//!
//! The A/B protocol itself (which arms, which members, when to stop) is the
//! campaign's own content, not engine machinery (ARCH-0059 §6): the author
//! assigns arms by step, and the engine splits no members. The outcome metric
//! is the campaign's reply-driven stage ladder: a member whose live
//! `crm.stage` head exists has been moved by a reply or later evidence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CampaignEnrollmentEvent, CampaignProgramStep};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The arm one member's send carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmSend {
    arm: String,
    program_ref: EntityId,
    step_ref: EntityId,
}

/// (campaign, member PERSON) → the arm that member's latest arm-tagged send
/// carried.
const ARM_SENDS: SideTable<(EntityId, EntityId), ArmSend, Named> =
    SideTable::new(&side_table::CAMPAIGN_COPY_ARM);

/// One arm's outcome on a campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignArmOutcome {
    /// The arm label, as the program step names it.
    pub arm: String,
    /// Members whose send carried this arm.
    pub members: u64,
    /// Of those, members with a live `crm.stage` head on the campaign: a
    /// reply or later evidence moved them onto the stage ladder.
    pub advanced: u64,
    /// Those advanced members by their live stage.
    pub stages: BTreeMap<String, u64>,
}

/// Records the arm `step` tags on the send the leg is about to make to
/// `event`'s member, once its envelope is frozen. A step with no arm records
/// nothing. A redrive writes nothing new: the row is put only when it is
/// absent or names another arm or step. An erased campaign or member gets no
/// row.
pub(super) fn record_arm_send_of(
    vault: &Vault,
    event: &CampaignEnrollmentEvent,
    step: &CampaignProgramStep,
) -> Result<()> {
    let Some(arm) = step.arm.as_ref() else {
        return Ok(());
    };
    let key = (event.campaign_ref, event.entity_ref);
    let row = ArmSend {
        arm: arm.clone(),
        program_ref: step.program_ref,
        step_ref: step.step_ref,
    };
    {
        let txn = vault.store.env.read_txn()?;
        if ARM_SENDS.get(&vault.store, &txn, &key)?.as_ref() == Some(&row) {
            return Ok(());
        }
    }
    vault.with_write_txn_grouped(|wtxn| {
        for id in [event.campaign_ref, event.entity_ref] {
            if vault.local_hard_delete_marker_exists_in_txn(wtxn, &id)? {
                return Ok(());
            }
        }
        ARM_SENDS.put(vault, wtxn, &key, &row)
    })
}

/// The outcome of each copy arm on `campaign_ref`, in arm order: how many
/// members each arm's sends reached, and how many of those a reply or later
/// evidence has moved onto the stage ladder. Reads claims and the arm rows
/// only; no model.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign is absent or owned by another
/// principal; storage and decode errors propagate, as does a torn stage
/// pipeline (two live heads for one member).
pub fn campaign_outcomes_by_arm(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
) -> Result<Vec<CampaignArmOutcome>> {
    if crate::campaign::surface::read_campaign(vault, authenticated_principal, campaign_ref)?
        .is_none()
    {
        return Err(Error::EntityNotFound);
    }
    let txn = vault.store.env.read_txn()?;
    let mut outcomes: BTreeMap<String, CampaignArmOutcome> = BTreeMap::new();
    for ((_, member), send) in ARM_SENDS.scan_from(&vault.store, &txn, campaign_ref.as_bytes())? {
        let outcome = outcomes
            .entry(send.arm.clone())
            .or_insert_with(|| CampaignArmOutcome {
                arm: send.arm.clone(),
                members: 0,
                advanced: 0,
                stages: BTreeMap::new(),
            });
        outcome.members += 1;
        if let Some((_, head)) =
            crate::campaign::stage::live_stage_head_in(vault, &txn, &member, &campaign_ref)?
        {
            outcome.advanced += 1;
            *outcome.stages.entry(head.stage.0).or_insert(0) += 1;
        }
    }
    Ok(outcomes.into_values().collect())
}
