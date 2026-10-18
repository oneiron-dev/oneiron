//! Calibration asks (OF-420; ARCH-0053 #the-judge, ARCH-0042's judge re-pin
//! protocol): "On uncertainty, optional human asks batch into the digest.
//! Human minutes bound them." The Coach's nightly pass puts each open
//! judge-swap disagreement, a kept case two judges answered differently that
//! no pick, settled outcome or tie-breaker has sided on, to every owner who
//! funded judge-ask minutes. The ask is the question the swap's hand-test
//! asks, so a digest pick is the same label: it joins the skill's judge
//! anchor, the next swap pass sides with it, and a pick that contradicts a
//! takeover re-pins it back. The incumbent's own retest flips, a kept case it
//! answered one way and, asked again, another, follow as uncertainty asks
//! between its two answers; their picks join the same anchor.
//!
//! The pass only proposes. The person's authenticated digest delivers the
//! asks and spends their minutes; a person who funded none is never asked.
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crate::skill_optimize::{self, JudgeAskReason, JudgeSwapSettledBy};
use crate::{EntityId, Error, Result, Vault};

/// The nightly calibration-ask pass, a closed-form Coach job.
pub const COACH_CALIBRATION_ASKS_FACET: &str = "coach.calibration_asks";

/// One open disagreement or retest flip, as the ask whose pick settles it.
struct Candidate {
    skill: EntityId,
    campaign: String,
    evidence: String,
    options: [String; 2],
    reason: JudgeAskReason,
}

/// Open disagreements, newest swap first, then the incumbent's retest flips,
/// newest first; each case once, leaving out the cases a label already
/// settled, a pick on the incumbent's retest flip of a swap case among them.
/// Within a swap, the receipt's order.
fn candidates(vault: &Vault) -> Result<Vec<Candidate>> {
    let mut receipts = skill_optimize::judge_swap_receipts(vault)?;
    receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.at));
    let mut asks = Vec::new();
    for receipt in &receipts {
        for case in &receipt.disagreements {
            // A pick on the incumbent's retest flip of the same case already
            // sides with one answer; the next swap pass settles it by that.
            if case.settled_by != JudgeSwapSettledBy::Open
                || skill_optimize::swap_case_retest_picked(vault, case)?
            {
                continue;
            }
            if let Some(ask) = skill_optimize::swap_case_ask(receipt, case) {
                asks.push((
                    ask,
                    case.case_ref.clone(),
                    JudgeAskReason::RevisionDisagreement,
                ));
            }
        }
    }
    for flip in skill_optimize::judge_retest_flips(vault)? {
        if let Some(ask) = skill_optimize::retest_flip_ask(&flip) {
            asks.push((ask, flip.case_ref, JudgeAskReason::Uncertainty));
        }
    }
    let mut seen = BTreeSet::new();
    let mut labelled: BTreeMap<(EntityId, String), BTreeSet<String>> = BTreeMap::new();
    let mut found = Vec::new();
    for ((skill, campaign, options), evidence, reason) in asks {
        if !seen.insert((campaign.clone(), evidence.clone())) {
            continue;
        }
        let settled = match labelled.entry((skill, campaign.clone())) {
            Entry::Occupied(kept) => kept.into_mut(),
            Entry::Vacant(slot) => slot.insert(
                skill_optimize::judge_label_anchor(vault, skill, &campaign)?
                    .into_iter()
                    .map(|label| label.ask.evidence)
                    .collect(),
            ),
        };
        if settled.contains(&evidence) {
            continue;
        }
        found.push(Candidate {
            skill,
            campaign,
            evidence,
            options,
            reason,
        });
    }
    Ok(found)
}

/// One pass: each owner with funded room gets the open questions they
/// were not yet asked, up to what their minutes buy beyond the asks already
/// waiting. Returns how many asks it proposed.
pub(super) fn run(vault: &Vault) -> Result<u32> {
    let owners = {
        let txn = vault.store.env.read_txn()?;
        crate::policy_model::owners_in_txn(vault, &txn)?
    };
    let mut rooms = Vec::new();
    for owner in owners {
        let room = skill_optimize::judge_ask_room(vault, owner)?;
        if room.room > 0 {
            rooms.push((owner, room));
        }
    }
    if rooms.is_empty() {
        return Ok(0);
    }
    let candidates = candidates(vault)?;
    let mut proposed = 0_u32;
    for (owner, room) in rooms {
        let mut left = room.room;
        for candidate in &candidates {
            if left == 0 {
                break;
            }
            let key = (
                candidate.skill,
                candidate.campaign.clone(),
                candidate.evidence.clone(),
            );
            if room.asked.contains(&key) {
                continue;
            }
            let ask = match candidate.reason {
                JudgeAskReason::RevisionDisagreement => skill_optimize::ask_judge_disagreement,
                JudgeAskReason::Uncertainty => skill_optimize::ask_judge_uncertainty,
                // A rubric re-grade is asked by the label re-check, never here.
                JudgeAskReason::RubricRecheck | JudgeAskReason::RubricRegrade => continue,
            };
            match ask(
                vault,
                candidate.skill,
                owner,
                &candidate.campaign,
                &candidate.evidence,
                &candidate.options[0],
                &candidate.options[1],
            ) {
                Ok(_) => {
                    left -= 1;
                    proposed = proposed.saturating_add(1);
                }
                // Words past the policy's context bound, or a skill or person
                // no longer live: not a question this pass can ask.
                Err(Error::InvalidConfig(_)) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(proposed)
}
