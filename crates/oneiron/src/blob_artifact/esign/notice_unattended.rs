//! FIX 6219 (Engine design B): a signing document's staged notices (pending,
//! completed, rejection, expiry) go out with no caller present, sent as the
//! principal their trail recorded while that principal still stands.
//!
//! The host's notice worker holds no credential of the principal's. Its
//! authority is the principal's own recorded send act (`notice_send_act`)
//! and the L02 standing check
//! ([`crate::authority::principal_standing_in_txn`]): a live person, or a
//! live agent one live Grant names that confers now and lists
//! `vault.esign.notices.dispatch`. Both are read once to bind the call, and
//! again in every snapshot it writes in: each recovery, claim and lease
//! return, and the sink snapshot that queues the delivery.
//!
//! The call then runs the door's own path
//! ([`crate::memory::Memory::esign_notices_dispatch`]): the same principal and
//! document binding, the same claim, lease and recovery, the same
//! per-notice outcomes, and each notice crosses the email send gate as that
//! principal, so OF-327 consent and the Gate rule it as they rule the
//! principal's own call. A gate that holds a notice leaves it staged for a
//! later try. A notice with no recorded send act, or whose principal no
//! longer stands, is not touched ([`UNBOUND_NOTICE_ACTION`]).
use std::collections::BTreeSet;

use super::notice_dispatch::{
    ESIGN_NOTICE_ATTEMPT_KIND, EsignNotice, NOTICE_LEASE_SECS, notice_lease_prefix,
};
use super::notice_door::EsignNoticesDispatchView;
use super::notice_scope::NoticeScope;
use super::notice_send_act::send_act_in;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::principal_standing_in_txn;
use crate::edge::EdgeActorClass;
use crate::memory::MemoryResult;
use crate::{EntityId, Result, Vault};

/// The verb an agent's Grant lists for its notices to go out with no caller:
/// the door's own row.
const NOTICE_DISPATCH_VERB: &str = "vault.esign.notices.dispatch";

/// The refusal a snapshot gives once the binding no longer holds.
const NO_LONGER_STANDS: &str =
    "the notices' recorded principal or its send act no longer stands for an unattended send";

/// What becomes of a staged notice no unattended send binds: no recorded
/// send act, a recorded act that names someone else, or a principal that no
/// longer stands (CALLS `FIX 6219 unbound notice`, accepted by the Engine
/// 10-20). It stays staged as it is, for its principal's own call; no
/// terminal failure and no owner takeover (FIX 6221 stays the owner's).
#[derive(Clone, Copy)]
enum UnboundNoticeAction {
    KeepStaged,
}

const UNBOUND_NOTICE_ACTION: UnboundNoticeAction = UnboundNoticeAction::KeepStaged;

/// One signing document's staged notices recorded for one principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsignNoticeGroup {
    pub document: EntityId,
    pub principal: EntityId,
}

/// What one unattended call made of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsignUnattendedNotices {
    /// The group's notices stay staged, untouched, for the caller-driven
    /// door: no unattended send binds, for the reason named.
    KeptStaged(&'static str),
    /// Sent as the recorded principal through the door's path. `under_grant`
    /// when an agent's Grant carried it.
    Dispatched {
        view: EsignNoticesDispatchView,
        under_grant: bool,
    },
}

/// One group's unattended binding: the recorded principal and class, judged
/// again in every snapshot the call writes in.
pub(super) struct UnattendedNotices<'a> {
    vault: &'a Vault,
    document: EntityId,
    principal: EntityId,
    class: EdgeActorClass,
    grant: Option<EntityId>,
}

/// Binds `group` in `txn`, or names why no unattended send binds it.
fn bind_in<'a>(
    vault: &'a Vault,
    txn: &heed::RoTxn<'_>,
    group: &EsignNoticeGroup,
) -> Result<std::result::Result<UnattendedNotices<'a>, &'static str>> {
    let Some(act) = send_act_in(vault, txn, group.document)? else {
        return Ok(Err("no send act is recorded for the document"));
    };
    if act.principal != group.principal {
        return Ok(Err("the recorded send act names another principal"));
    }
    let Some(standing) =
        principal_standing_in_txn(vault, txn, act.principal, act.class, NOTICE_DISPATCH_VERB)?
    else {
        return Ok(Err("the notices' principal no longer stands"));
    };
    Ok(Ok(UnattendedNotices {
        vault,
        document: group.document,
        principal: standing.principal,
        class: standing.class,
        grant: standing.grant,
    }))
}

impl UnattendedNotices<'_> {
    /// The binding judged again in `txn`: the same send act still recorded
    /// for the same principal and class, and that principal still standing.
    /// # Errors
    /// An authority refusal once it does not, or the reads' own failure.
    pub(super) fn stands_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        let recorded = send_act_in(self.vault, txn, self.document)?
            .is_some_and(|act| act.principal == self.principal && act.class == self.class);
        if recorded
            && principal_standing_in_txn(
                self.vault,
                txn,
                self.principal,
                self.class,
                NOTICE_DISPATCH_VERB,
            )?
            .is_some()
        {
            Ok(())
        } else {
            Err(crate::authority::authority_refused(NO_LONGER_STANDS))
        }
    }
}

impl Vault {
    /// The document and principal groups with a staged notice due now, in
    /// queue order: a queued notice, a retry past its wait, or a door claim
    /// of the group's principal left leased past its lease. A read only;
    /// [`Self::dispatch_esign_notices_unattended`] judges each group again.
    /// # Errors
    /// A queue read failure.
    pub fn esign_notice_groups_due(&self) -> Result<Vec<EsignNoticeGroup>> {
        let now = self.now_recorded_at();
        let mut seen = BTreeSet::new();
        let mut groups = Vec::new();
        for row in
            AttemptQueue::new(self).list_kind_bounded(ESIGN_NOTICE_ATTEMPT_KIND, usize::MAX)?
        {
            let Some(group) = group_of(&row) else {
                continue;
            };
            if is_due(&row, group.principal, now) && seen.insert((group.document, group.principal))
            {
                groups.push(group);
            }
        }
        Ok(groups)
    }

    /// Sends `group`'s due staged notices with no caller present, as their
    /// recorded principal, through the door's own path, while its recorded
    /// send act and its standing hold. A group no unattended send binds is
    /// left as it is.
    /// # Errors
    /// As [`crate::memory::Memory::esign_notices_dispatch`], or an authority refusal
    /// when the binding stopped holding during the call. A gate that holds
    /// or denies a notice is that notice's outcome, not an error.
    pub fn dispatch_esign_notices_unattended(
        &self,
        group: &EsignNoticeGroup,
    ) -> MemoryResult<EsignUnattendedNotices> {
        let bound = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            bind_in(self, &txn, group)?
        };
        let notices = match bound {
            Ok(notices) => notices,
            Err(reason) => {
                return Ok(match UNBOUND_NOTICE_ACTION {
                    UnboundNoticeAction::KeepStaged => EsignUnattendedNotices::KeptStaged(reason),
                });
            }
        };
        let (principal, class) = (notices.principal, notices.class);
        let under_grant = notices.grant.is_some();
        crate::memory::verify_actor_binding(self, principal, class)?;
        let view = self
            .memory(principal, class)
            .dispatch_notices_in(group.document, &NoticeScope::Unattended(notices))?;
        Ok(EsignUnattendedNotices::Dispatched { view, under_grant })
    }
}

/// The group a staged notice row belongs to; `None` for a row that names no
/// document or principal, which no door sends either.
fn group_of(row: &AttemptRecord) -> Option<EsignNoticeGroup> {
    let notice: EsignNotice = serde_json::from_slice(&row.payload).ok()?;
    Some(EsignNoticeGroup {
        document: EntityId::from_hex(&notice.document).ok()?,
        principal: EntityId::from_hex(notice.principal.as_deref()?).ok()?,
    })
}

/// Whether the door's path would take `row` up now: queued, a retry past its
/// wait, or a door claim of `principal` held past [`NOTICE_LEASE_SECS`].
fn is_due(row: &AttemptRecord, principal: EntityId, now: u64) -> bool {
    match row.state {
        AttemptState::Queued => true,
        AttemptState::Scheduled => row
            .scheduled_at
            .or(row.backoff_until)
            .is_none_or(|at| at <= now),
        AttemptState::Leased => {
            row.lease_owner
                .as_deref()
                .is_some_and(|owner| owner.starts_with(&notice_lease_prefix(principal)))
                && now.saturating_sub(row.updated_at) >= NOTICE_LEASE_SECS
        }
        _ => false,
    }
}
