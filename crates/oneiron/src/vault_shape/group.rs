//! The apply's inbox group (ARCH-0070 `shape:plan-apply`): one group per
//! apply, keyed by its run-tree root, holding the items that wait for the
//! owner's word, so the owner answers one coherent change rather than a
//! scatter of rows. It sits beside the inbox's dreamer-run groups the way
//! the meeting check-ins do: a setup item is no CLAIM, so it files into no
//! pending-consent row. The journal is the filing and this is its
//! projection; the owner's answer resumes the journal through the owner's
//! doors, with the inbox's own bulk verbs.
use super::apply::{ShapeApplyReceipt, ShapeItemState, open};
use super::plan::{ShapePlanItem, ShapePlanSummary};
use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::inbox::InboxBulkVerb;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Why reject-all closes an item.
const SHAPE_OWNER_DECLINED: &str = "the owner declined it";

/// One apply's inbox group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeInboxGroup {
    /// The apply's run-tree root, hex.
    pub group_key: String,
    pub run_id: String,
    /// The plan's frontier: the apply's journal key.
    pub frontier: String,
    /// The whole apply at the plan card's resting depth.
    pub headline: String,
    pub created_at: u64,
    /// The items waiting for the owner's word, in landing order.
    pub members: Vec<ShapeInboxMember>,
}

/// One item waiting in an apply's inbox group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeInboxMember {
    /// The item's run-tree row, hex.
    pub attempt_id: String,
    pub item: ShapePlanItem,
    /// Pending, Proposed, or Filed with the widen inbox's reference.
    pub state: ShapeItemState,
}

/// `journal` as its inbox group, while an item waits.
fn shape_group(journal: &ShapeApplyReceipt) -> Option<ShapeInboxGroup> {
    let members: Vec<ShapeInboxMember> = journal
        .items
        .iter()
        .zip(&journal.run.items)
        .filter(|(entry, _)| open(&entry.state))
        .map(|(entry, row)| ShapeInboxMember {
            attempt_id: row.clone(),
            item: entry.item.clone(),
            state: entry.state.clone(),
        })
        .collect();
    if members.is_empty() {
        return None;
    }
    let summary = ShapePlanSummary::of(journal.items.iter().map(|entry| &entry.item));
    Some(ShapeInboxGroup {
        group_key: journal.run.root.clone(),
        run_id: journal.run.run_id.clone(),
        frontier: journal.frontier.clone(),
        headline: summary.resting_line(),
        created_at: journal.started_at,
        members,
    })
}

impl Vault {
    /// Every apply with an item waiting for the owner's word, one inbox
    /// group each, oldest first. A grant the owner already answered in the
    /// widen inbox reads as answered.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn inbox_shape_groups(&self) -> Result<Vec<ShapeInboxGroup>> {
        let now = self.store.clock.peek_recorded_at();
        let mut groups = Vec::new();
        for mut journal in self.open_shape_applies()? {
            self.reconcile_shape_filings(&mut journal, now)?;
            groups.extend(shape_group(&journal));
        }
        groups.sort_by(|a, b| (a.created_at, &a.group_key).cmp(&(b.created_at, &b.group_key)));
        Ok(groups)
    }

    /// The owner's answer to the apply whose group is `group_key`.
    /// Accept-all lands every waiting item, as an owner's apply approving
    /// each `seq` would. Reject-all closes each as declined and cancels its
    /// row. Review-each changes nothing and returns the journal to answer
    /// item by item through `vault.shape.apply`.
    ///
    /// # Errors
    ///
    /// No open apply has that group, an owner proof that no longer holds,
    /// or a store failure. A door's own refusal is the item's state.
    pub fn resolve_shape_inbox_group(
        &self,
        owner: &AuthenticatedOwner,
        slips: Option<&HostSlipIssuer>,
        group_key: &str,
        verb: InboxBulkVerb,
        now: u64,
    ) -> Result<ShapeApplyReceipt> {
        owner.revalidate(self)?;
        let mut journal = self
            .open_shape_applies()?
            .into_iter()
            .find(|journal| journal.run.root == group_key)
            .ok_or(Error::EntityNotFound)?;
        self.reconcile_shape_filings(&mut journal, now)?;
        match verb {
            InboxBulkVerb::AcceptAll => {
                let waiting: Vec<u32> = journal
                    .items
                    .iter()
                    .filter(|entry| open(&entry.state))
                    .map(|entry| entry.item.seq)
                    .collect();
                self.land_shape_journal(owner, slips, &mut journal, &waiting, now)?;
            }
            InboxBulkVerb::RejectAll => {
                for entry in &mut journal.items {
                    if open(&entry.state) {
                        entry.state = ShapeItemState::Refused {
                            reason: SHAPE_OWNER_DECLINED.to_owned(),
                        };
                    }
                }
                journal.done = true;
                self.put_shape_apply(&journal, now)?;
            }
            InboxBulkVerb::ReviewEach => {}
        }
        Ok(journal)
    }
}
