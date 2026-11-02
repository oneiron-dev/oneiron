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
//! return, the writer that records a notice's gate decision, and the sink
//! snapshot that queues the delivery.
//!
//! The call then runs the door's own path
//! ([`crate::memory::Memory::esign_notices_dispatch`]): the same principal and
//! document binding, the same claim, lease and recovery, the same
//! per-notice outcomes, and each notice crosses the email send gate as that
//! principal, so OF-327 consent and the Gate rule it as they rule the
//! principal's own call. A gate that holds a notice leaves it staged for a
//! later try.
//!
//! FIX 6444 (Engine 09:39 ruling A): a group no recorded send act binds (no
//! act, or an act that names another principal) goes out when an explicit
//! work-authority carrier stands for its own principal: the principal is
//! the vault's live owner, or a live agent one live Grant the owner gave
//! names, that confers now and lists `vault.esign.notices.dispatch`
//! ([`WorkAuthority`]). No owner proof is minted for it; the carrier is
//! judged again in every snapshot, as a recorded act is. A group with no
//! carrier, or whose principal no longer stands, is not touched
//! ([`UNBOUND_NOTICE_ACTION`]).
use std::collections::BTreeSet;

use super::notice_dispatch::{
    ESIGN_NOTICE_ATTEMPT_KIND, EsignNotice, NOTICE_LEASE_SECS, notice_lease_prefix,
};
use super::notice_door::EsignNoticesDispatchView;
use super::notice_scope::NoticeScope;
use super::notice_send_act::{RecordedSendAct, send_act_in};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::{
    NoStanding, PACT_STANDING_LAPSED, PrincipalStanding, principal_standing_in_txn,
    principal_standing_or_lapse_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::memory::MemoryResult;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::{EntityId, Result, Vault};

/// The verb an agent's Grant lists for its notices to go out with no caller:
/// the door's own row.
const NOTICE_DISPATCH_VERB: &str = "vault.esign.notices.dispatch";

/// The refusal a snapshot gives once the binding no longer holds.
const NO_LONGER_STANDS: &str =
    "the notices' recorded principal or its send act no longer stands for an unattended send";

/// What becomes of a staged notice no unattended send binds: no recorded
/// send act and no work-authority carrier (FIX 6444), a recorded act that
/// names someone else and no carrier, or a principal that no longer stands
/// (CALLS `FIX 6219 unbound notice`, accepted by the Engine 10-20). It stays
/// staged as it is, for its principal's own call; no terminal failure and no
/// owner takeover (FIX 6221 stays the owner's).
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

/// What carries a group's unattended send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkAuthority {
    /// The principal's own recorded send act (FIX 6219).
    RecordedAct,
    /// FIX 6444: no recorded act binds the group, and its principal is the
    /// vault's live owner, sending its own notices as a person.
    Owner,
    /// FIX 6444: no recorded act binds the group, and one live Grant the
    /// owner gave its agent principal names it, confers now and lists
    /// [`NOTICE_DISPATCH_VERB`].
    Grant,
}

/// One group's unattended binding: the principal and class, and what
/// carries it, judged again in every snapshot the call writes in.
pub(super) struct UnattendedNotices<'a> {
    vault: &'a Vault,
    document: EntityId,
    principal: EntityId,
    class: EdgeActorClass,
    grant: Option<EntityId>,
    authority: WorkAuthority,
}

/// Binds `group` in `txn`, or names why no unattended send binds it.
fn bind_in<'a>(
    vault: &'a Vault,
    txn: &heed::RoTxn<'_>,
    group: &EsignNoticeGroup,
) -> Result<std::result::Result<UnattendedNotices<'a>, &'static str>> {
    let unbound = match send_act_in(vault, txn, group.document)? {
        None => "no send act is recorded for the document",
        Some(act) if act.principal != group.principal => {
            "the recorded send act names another principal"
        }
        Some(act) => return recorded_act_bind_in(vault, txn, group, act),
    };
    // FIX 6444: an explicit carrier for the group's own principal, else the
    // group stays as it is.
    Ok(carrier_in(vault, txn, group.principal)?
        .map(|(standing, authority)| UnattendedNotices {
            vault,
            document: group.document,
            principal: standing.principal,
            class: standing.class,
            grant: standing.grant,
            authority,
        })
        .ok_or(unbound))
}

/// FIX 6444: the explicit work-authority carrier that stands for
/// `principal` in `txn`: a live owner acting as a person, or a live agent
/// (an agent definition acting as agent, a base agent's MACHINE acting as
/// system) one live Grant names for [`NOTICE_DISPATCH_VERB`]. `None` for any
/// other principal, or one that does not stand.
fn carrier_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
) -> Result<Option<(PrincipalStanding, WorkAuthority)>> {
    let (class, authority) = match vault.get_entity_type_in_txn(txn, &principal)? {
        Some(ENTITY_TYPE_PERSON)
            if crate::policy_model::owners_in_txn(vault, txn)?.contains(&principal) =>
        {
            (EdgeActorClass::Human, WorkAuthority::Owner)
        }
        Some(ENTITY_TYPE_AGENT_DEF) => (EdgeActorClass::Agent, WorkAuthority::Grant),
        Some(ENTITY_TYPE_MACHINE) => (EdgeActorClass::System, WorkAuthority::Grant),
        _ => return Ok(None),
    };
    Ok(
        principal_standing_in_txn(vault, txn, principal, class, NOTICE_DISPATCH_VERB)?
            .map(|standing| (standing, authority)),
    )
}

/// Binds `group` under its principal's own recorded send `act` (FIX 6219).
fn recorded_act_bind_in<'a>(
    vault: &'a Vault,
    txn: &heed::RoTxn<'_>,
    group: &EsignNoticeGroup,
    act: RecordedSendAct,
) -> Result<std::result::Result<UnattendedNotices<'a>, &'static str>> {
    let standing = match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        act.principal,
        act.class,
        NOTICE_DISPATCH_VERB,
    )? {
        Ok(standing) => standing,
        Err(NoStanding::PactStandingLapsed) => return Ok(Err(PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => {
            return Ok(Err("the notices' principal no longer stands"));
        }
    };
    Ok(Ok(UnattendedNotices {
        vault,
        document: group.document,
        principal: standing.principal,
        class: standing.class,
        grant: standing.grant,
        authority: WorkAuthority::RecordedAct,
    }))
}

impl UnattendedNotices<'_> {
    /// Whether the binding holds in `txn`: the same send act still recorded
    /// for the same principal and class, or (FIX 6444) the principal still
    /// the vault's owner, and that principal still standing (an agent's
    /// Grant among it).
    /// # Errors
    /// The reads' own failure.
    pub(super) fn stands(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let carried = match self.authority {
            WorkAuthority::RecordedAct => send_act_in(self.vault, txn, self.document)?
                .is_some_and(|act| act.principal == self.principal && act.class == self.class),
            WorkAuthority::Owner => {
                crate::policy_model::owners_in_txn(self.vault, txn)?.contains(&self.principal)
            }
            WorkAuthority::Grant => true,
        };
        Ok(carried
            && principal_standing_in_txn(
                self.vault,
                txn,
                self.principal,
                self.class,
                NOTICE_DISPATCH_VERB,
            )?
            .is_some())
    }

    /// [`Self::stands`], a binding that no longer holds refused.
    /// # Errors
    /// An authority refusal once it does not hold, or the reads' own failure.
    pub(super) fn stands_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        if self.stands(txn)? {
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
    /// send act, or (FIX 6444) its owner or Grant work-authority carrier, and
    /// its standing hold. A group no unattended send binds is left as it is.
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
