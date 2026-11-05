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

use crate::attempt_state::AttemptState;
use crate::blob_artifact::esign::notice_send_act::RecordedSendAct;
use crate::principal_record::NoStanding;
use crate::principal_record::PACT_STANDING_LAPSED;
use crate::principal_record::PrincipalStanding;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_MACHINE;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;

/// The verb an agent's Grant lists for its notices to go out with no caller:
/// the door's own row.
pub const NOTICE_DISPATCH_VERB: &str = "vault.esign.notices.dispatch";

/// The refusal a snapshot gives once the binding no longer holds.
pub const NO_LONGER_STANDS: &str =
    "the notices' recorded principal or its send act no longer stands for an unattended send";

/// What becomes of a staged notice no unattended send binds: no recorded
/// send act and no work-authority carrier (FIX 6444), a recorded act that
/// names someone else and no carrier, or a principal that no longer stands
/// (CALLS `FIX 6219 unbound notice`, accepted by the Engine 10-20). It stays
/// staged as it is, for its principal's own call; no terminal failure and no
/// owner takeover (FIX 6221 stays the owner's).
#[derive(Clone, Copy)]
pub enum UnboundNoticeAction {
    KeepStaged,
}

pub const UNBOUND_NOTICE_ACTION: UnboundNoticeAction = UnboundNoticeAction::KeepStaged;

/// One signing document's staged notices recorded for one principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsignNoticeGroup {
    pub document: EntityId,
    pub principal: EntityId,
}

/// What carries a group's unattended send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkAuthority {
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
