//! The needs-you notice of the lift proposals (OF-067). It is an inbox Ask
//! (`NOTIFICATION`), raised as the found-key notice is: non-blocking, one per
//! owner. A run that files proposals raises one notice for the proposals left
//! open, counted by cause, whose result points at `vault.secrets.lift_history`;
//! the next such run's notice replaces it, and it resolves, acknowledged for
//! each owner it was raised for, once no proposal is open. It names no row
//! and holds no value.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{PROPOSALS, SecretLiftHistoryProposal};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Producer name of the lift proposals' notice.
const NOTIFICATION_PRODUCER_SECRET_LIFT: &str = "secret.lift_proposals";

/// Where the notice sends the owner: the row that lists the proposals and
/// closes them.
const POINTER: &str = "vault.secrets.lift_history";

/// How the notice groups the open proposals it counts (CALLS, open): by why
/// the sweep left each. One notice covers every open proposal, raised by a
/// run that filed any and replaced by the next such run's.
const NOTICE_GROUP: fn(&SecretLiftHistoryProposal) -> &'static str = by_cause;

/// The notice raised last. Key: ().
const NOTICE: SideTable<(), LiftNotice, Named> = SideTable::new(&side_table::SECRET_LIFT_NOTICE);

/// The notice raised last: the run that raised it, and each owner's inbox
/// row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiftNotice {
    run_id: EntityId,
    /// `(notification, owner)`.
    raised: Vec<(EntityId, EntityId)>,
}

fn by_cause(proposal: &SecretLiftHistoryProposal) -> &'static str {
    proposal.cause.code()
}

/// At a run's end, in the transaction that writes its receipt. No open
/// proposal: the notice resolves. A run that filed proposals, or one that
/// finds open proposals and no notice, raises a notice for them, replacing
/// the one before.
pub(super) fn after_run_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    run_id: EntityId,
    filed: u64,
    at: u64,
) -> Result<()> {
    let open = open_groups_in_txn(vault, txn)?;
    if open.is_empty() {
        return resolve_in_txn(vault, txn);
    }
    if filed == 0 && NOTICE.contains(&vault.store, txn, &())? {
        return Ok(());
    }
    resolve_in_txn(vault, txn)?;
    let counts = open
        .iter()
        .map(|(group, count)| format!("{group}={count}"))
        .collect::<Vec<_>>()
        .join(",");
    let run = run_id.to_hex();
    let mut raised = Vec::new();
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        let notification = vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_SECRET_LIFT.to_owned(),
                    // The counts name the notice: a later run's differs.
                    event: format!("{run}:{counts}:{}", owner.to_hex()),
                    run: Some(run.clone()),
                    result: Some(POINTER.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(owner),
                created_at: at,
                origin_conversation: None,
            },
        )?;
        raised.push((notification, owner));
    }
    NOTICE.put(&vault.store, txn, &(), &LiftNotice { run_id, raised })
}

/// Resolves the notice once no proposal is open.
pub(super) fn settle_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    if !NOTICE.contains(&vault.store, txn, &())? || any_open_in_txn(vault, txn)? {
        return Ok(());
    }
    resolve_in_txn(vault, txn)
}

/// Acknowledges the notice for each owner it was raised for, through the
/// inbox's own row, and forgets it.
fn resolve_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let Some(notice) = NOTICE.get_lenient(&vault.store, txn, &())? else {
        return Ok(());
    };
    for (notification, owner) in notice.raised {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, txn, &notification)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let owner = owner.to_hex();
        if body.acked_by.get(&owner) == Some(&true) {
            continue;
        }
        body.seen_by.insert(owner.clone(), true);
        body.acked_by.insert(owner, true);
        vault.put_notification_in_txn(txn, &notification, &body)?;
    }
    NOTICE.delete(&vault.store, txn, &())?;
    Ok(())
}

/// The open proposals, counted by [`NOTICE_GROUP`].
fn open_groups_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<BTreeMap<&'static str, u64>> {
    let mut groups = BTreeMap::new();
    for row in PROPOSALS.iter_raw_from(&vault.store, txn, &[])? {
        let (_, bytes) = row?;
        if let Ok(proposal) = PROPOSALS.decode_value(&bytes)
            && proposal.is_open()
        {
            *groups.entry(NOTICE_GROUP(&proposal)).or_insert(0) += 1;
        }
    }
    Ok(groups)
}

fn any_open_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    for row in PROPOSALS.iter_raw_from(&vault.store, txn, &[])? {
        let (_, bytes) = row?;
        if PROPOSALS
            .decode_value(&bytes)
            .is_ok_and(|proposal| proposal.is_open())
        {
            return Ok(true);
        }
    }
    Ok(false)
}
