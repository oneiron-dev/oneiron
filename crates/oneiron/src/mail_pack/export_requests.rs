//! An Owner's request for another member's personal mailbox in their next
//! whole-vault export (fix list row 15416; owner rulings EXPORT-MAILBOXES,
//! 2026-11-07 01:43 and 01:45, rule X; ARCH-0043 RD-28).
//!
//! In a vault a person owns, an Owner asks for one member's mailbox
//! (`vault.mail.export_request`), and the member gets one typed Ask,
//! Approve or Decline, put to them alone: no Owner, Admin, board or agent
//! answers it in their place, and it never climbs. The Ask is the decision
//! record; the request row says only whether the request is open or used.
//!
//! - **Approved**: the requesting Owner's next whole-vault export carries
//!   the mailbox, and uses the request in the write that tells the member,
//!   before a byte of the copy leaves. The export uses it whatever let the
//!   mailbox in, even when none of its rows went.
//! - **Not answered**: each export leaves the mailbox out and names it. The
//!   export never waits, and no time closes the request: an approval given
//!   later covers the Owner's next export.
//! - **Declined**, or **used**: closed. The Owner may ask again, which makes
//!   a new request and a new Ask.
//!
//! A request stands only where it was made: no image brings one back, though
//! an image may bring back its open Ask. A new request withdraws every Ask
//! still open from that Owner about that mailbox, so the member holds one
//! card for the pair. An erased Owner's or member's requests go, and every
//! open Ask from them or put to them is withdrawn, a request row naming it
//! or not.

use serde::{Deserialize, Serialize};

use super::doors::live_person_in;
use super::export_mailboxes::{
    MemberMailRequest, SharedVaultOwner, own_mailbox_in, shared_vault_owner_in,
};
use super::pack::require_pack_active_in;
use super::source::{MailSourceKind, SOURCES};
use crate::consent::AuthenticatedOwner;
use crate::llm::decision::{
    AnswerActor, AnswerContract, AskAct, AskRole, AskTo, DecisionAnswer, DecisionAsk,
    DecisionQuestion, DecisionRung, HolderKind, HumanAskReason, HumanDecisionRequest, ProviderPin,
    RoleRank, catalogue,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::workspace_roster::VaultStanding;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

/// Each Owner's current request for each mailbox, by the source and the
/// requesting Owner's PERSON.
const REQUESTS: SideTable<(EntityId, EntityId), MailExportRequestRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_EXPORT_REQUEST);

/// The vault's decision Asks, read here to find this family's: every write
/// to one goes through the Ask queue's own doors.
const DECISION_ASKS: SideTable<u64, DecisionAsk, Named> = SideTable::new(&side_table::DECISION_ASK);

/// The host-issued queue identity of a member's export request Ask.
const EXPORT_REQUEST_QUEUE: &str = "mail_pack.export_request";
const EXPORT_REQUEST_QUEUE_VERSION: &str = "v1";

/// The queue pin every member's export request Ask is queued under.
fn export_request_queue_pin() -> ProviderPin {
    ProviderPin {
        rung: DecisionRung::Human,
        model: EXPORT_REQUEST_QUEUE.to_owned(),
        version: EXPORT_REQUEST_QUEUE_VERSION.to_owned(),
    }
}

/// Whether `ask` is a member's export request Ask, open: this family's
/// question, queued under its pin, neither answered nor withdrawn.
fn open_export_request_ask(ask: &DecisionAsk) -> bool {
    ask.is_open()
        && ask.question.version == catalogue::MAIL_EXPORT_REQUEST.version
        && ask.queue_pin == export_request_queue_pin()
}

/// The answer that lets the mailbox into the Owner's next export.
const APPROVE: &str = "Approve";
/// The answer that closes the request.
const DECLINE: &str = "Decline";

/// One Owner's request for one member's mailbox: refs, times and a state,
/// never an address or a word of the mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailExportRequestRow {
    request: EntityId,
    /// The PERSON whose mailbox it is, who answers its Ask.
    mailbox_person: EntityId,
    /// The Owner's PERSON who asked.
    requester: EntityId,
    created_at: u64,
    /// The member's Ask: its arrival number and its id. Its correlation is
    /// `request`.
    ask_seq: u64,
    ask_id: EntityId,
    state: MailExportRequestRowState,
}

/// Whether a request is open or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum MailExportRequestRowState {
    Open,
    /// The whole-vault export `export` used it at `at`.
    Consumed {
        export: EntityId,
        at: u64,
    },
}

/// Where one request stands, read from its row and its Ask in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestStanding {
    /// Open; its person has not answered.
    Pending,
    /// Open; its person approved it.
    Approved,
    /// Its person declined it.
    Declined,
    /// An export used it.
    Consumed,
    /// Open, but its Ask was withdrawn, is gone or is not this request's,
    /// or the mailbox is no longer its person's.
    Lapsed,
}

/// The standing of `row` in `txn`, the mailbox's live person being `owner`.
/// An approval counts only from the Ask with exactly the row's identity and
/// correlation, answered Approve by the mailbox's live PERSON, as a person.
fn standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &MailExportRequestRow,
    owner: Option<EntityId>,
) -> Result<RequestStanding> {
    if matches!(row.state, MailExportRequestRowState::Consumed { .. }) {
        return Ok(RequestStanding::Consumed);
    }
    let Some(ask) = vault.decision_ask_in_txn(txn, row.ask_seq)? else {
        return Ok(RequestStanding::Lapsed);
    };
    if ask.id != row.ask_id
        || ask.correlation != Some(row.request)
        || ask.withdrawn_at.is_some()
        || owner != Some(row.mailbox_person)
    {
        return Ok(RequestStanding::Lapsed);
    }
    let Some(answer) = &ask.answer else {
        return Ok(RequestStanding::Pending);
    };
    Ok(match &answer.answer {
        DecisionAnswer::Choice(choice)
            if choice == APPROVE
                && answer.by == AnswerActor::Actor(row.mailbox_person)
                && answer.kind == HolderKind::Person =>
        {
            RequestStanding::Approved
        }
        DecisionAnswer::Choice(choice) if choice == DECLINE => RequestStanding::Declined,
        _ => RequestStanding::Lapsed,
    })
}

/// The live PERSON who owns the personal mailbox `source` in `txn`.
fn live_mailbox_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<Option<EntityId>> {
    let Some(owner) = SOURCES
        .get(&vault.store, txn, &source)?
        .filter(|row| row.kind == MailSourceKind::PersonalMailbox)
        .and_then(|row| row.owner)
    else {
        return Ok(None);
    };
    Ok(live_person_in(vault, txn, &owner)?.then_some(owner))
}

/// An approved request an export pass read, which its audit's write uses:
/// engine-owned, never wire input, and no read of the mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ApprovedMailExportRequest {
    pub(super) source: EntityId,
    pub(super) mailbox_person: EntityId,
    pub(super) requester: EntityId,
    pub(super) request: EntityId,
    ask_seq: u64,
    ask_id: EntityId,
}

/// Where `requester`'s request for the mailbox `source`, whose live PERSON
/// is `owner`, stands in `txn`, for an export: with the approved request
/// itself when its person approved it. A request used, withdrawn or lost is
/// none.
///
/// # Errors
///
/// Storage and codec failures.
pub(super) fn member_request_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    requester: EntityId,
    owner: Option<EntityId>,
) -> Result<(MemberMailRequest, Option<ApprovedMailExportRequest>)> {
    let Some(row) = REQUESTS.get(&vault.store, txn, &(source, requester))? else {
        return Ok((MemberMailRequest::NotRequested, None));
    };
    Ok(match standing_in(vault, txn, &row, owner)? {
        RequestStanding::Pending => (MemberMailRequest::Pending, None),
        RequestStanding::Declined => (MemberMailRequest::Declined, None),
        RequestStanding::Approved => (
            MemberMailRequest::Approved,
            Some(ApprovedMailExportRequest {
                source,
                mailbox_person: row.mailbox_person,
                requester,
                request: row.request,
                ask_seq: row.ask_seq,
                ask_id: row.ask_id,
            }),
        ),
        RequestStanding::Consumed | RequestStanding::Lapsed => {
            (MemberMailRequest::NotRequested, None)
        }
    })
}

/// Uses `approved` for the whole-vault export `export` at `at`, in the
/// export audit's own write `txn`: the request is read again there with its
/// Ask, and only one still open and approved, with the identity the export
/// read, is marked used.
///
/// # Errors
///
/// The approval the export read no longer stands (an export used it first,
/// or its mailbox or person changed); storage failures.
pub(super) fn use_approved_request_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    approved: &ApprovedMailExportRequest,
    export: EntityId,
    at: u64,
) -> Result<()> {
    let key = (approved.source, approved.requester);
    let owner = live_mailbox_person_in(vault, txn, approved.source)?;
    let mut row = match REQUESTS.get(&vault.store, txn, &key)? {
        Some(row)
            if row.request == approved.request
                && row.mailbox_person == approved.mailbox_person
                && row.ask_seq == approved.ask_seq
                && row.ask_id == approved.ask_id =>
        {
            row
        }
        _ => return Err(approval_gone()),
    };
    if standing_in(vault, txn, &row, owner)? != RequestStanding::Approved {
        return Err(approval_gone());
    }
    row.state = MailExportRequestRowState::Consumed { export, at };
    REQUESTS.put(&vault.store, txn, &key, &row)
}

fn approval_gone() -> Error {
    Error::InvalidConfig("a member's approval the export read no longer stands".into())
}

/// Withdraws, in `txn`, every member's export request Ask still open from
/// the Owner `requester` about the mailbox `source`, whether or not a
/// request row still names it (a restore takes request rows, not Asks), so
/// a new request leaves its person one card for that Owner and mailbox.
/// Its waiters are none: an export never waits on it.
fn withdraw_open_asks_for_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    requester: EntityId,
) -> Result<()> {
    for (seq, ask) in DECISION_ASKS.scan(&vault.store, txn)? {
        if !open_export_request_ask(&ask) || !ask.principal.is(requester) {
            continue;
        }
        let Some(request) = ask.correlation else {
            continue;
        };
        if request_question(request, source)?.id == ask.question.id {
            vault.withdraw_decision_ask_in_txn(txn, seq)?;
        }
    }
    Ok(())
}

/// The member's question for `request`, about the mailbox `source`: its id
/// derives from the family, the request and the mailbox.
fn request_question(request: EntityId, source: EntityId) -> Result<DecisionQuestion> {
    catalogue::MAIL_EXPORT_REQUEST.question(
        &[request.as_bytes()],
        format!(
            "An Owner of this vault asks to carry your mailbox (mail source {}) in their next \
             whole-vault export, that export only. Approve, or decline?",
            source.to_hex()
        ),
        AnswerContract::Choice {
            options: vec![APPROVE.to_owned(), DECLINE.to_owned()],
        },
    )
}

/// The member's Ask for `request`: Approve or Decline, from the Owner
/// `requester`, put to the mailbox's PERSON `person` alone, with no
/// prior answer, no consent effect and no climb.
fn request_ask(
    request: EntityId,
    source: EntityId,
    person: EntityId,
    requester: EntityId,
) -> Result<HumanDecisionRequest> {
    Ok(HumanDecisionRequest {
        question: request_question(request, source)?,
        principal: requester,
        evidence: Vec::new(),
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: export_request_queue_pin(),
        to: AskTo {
            role: AskRole::Responsible {
                actor: AnswerActor::Actor(person),
                project: None,
            },
            ceiling: RoleRank::Responsible,
            act: AskAct::Judgment,
        },
        correlation: Some(request),
    })
}

/// `vault.mail.export_request`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailExportRequest {
    /// The member's personal mailbox, 32-hex: the source an export's
    /// mailbox notice names.
    pub source_ref: String,
}

/// Where an Owner's request for a member's mailbox stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailExportRequestState {
    /// Asked; the member has not answered. Each export leaves the mailbox
    /// out meanwhile.
    Pending,
    /// The member approved it: the Owner's next whole-vault export carries
    /// the mailbox.
    Approved,
    /// The member declined it.
    Declined,
    /// An export of the Owner's used it.
    Consumed,
}

/// One Owner's request for one member's mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailExportRequestView {
    /// The request, 32-hex: the correlation of the member's Ask.
    pub request_ref: String,
    /// The mailbox's source, 32-hex.
    pub source_ref: String,
    pub state: MailExportRequestState,
}

fn request_view(
    row: &MailExportRequestRow,
    source: EntityId,
    state: MailExportRequestState,
) -> MailExportRequestView {
    MailExportRequestView {
        request_ref: row.request.to_hex(),
        source_ref: source.to_hex(),
        state,
    }
}

/// The refusal for a source that is no other member's personal mailbox.
fn unknown_member_mailbox() -> MemoryError {
    MemoryError::not_found("no other member's personal mailbox by that ref")
}

impl Memory<'_> {
    /// An Owner's request for another member's personal mailbox in their
    /// next whole-vault export (fix list row 15416), under the Owner's own
    /// proof, in a shared vault a person owns. The member gets one Ask,
    /// Approve or Decline, put to them alone. The Owner's request that is
    /// open, unanswered or approved, answers again as it stands; after a
    /// decline or a use, this makes a new request and a new Ask. Needs the
    /// pack installed Active.
    pub fn mail_export_request_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &MailExportRequest,
    ) -> MemoryResult<MailExportRequestView> {
        let source = EntityId::from_hex(&input.source_ref)?;
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            require_pack_active_in(vault, txn)?;
            let requester = owner.revalidate_in_txn(vault, txn)?;
            if requester != self.actor()
                || self.actor_class() != EdgeActorClass::Human
                || crate::workspace_roster::vault_standing_in(vault, txn, requester)?
                    != Some(VaultStanding::Owner)
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a member's mailbox is requested by the vault's Owner, through their own owner credential",
                    &[],
                ));
            }
            if shared_vault_owner_in(vault, txn)? != Some(SharedVaultOwner::Person) {
                return Err(MemoryError::bad_request(
                    "a member's mailbox is requested in a shared vault a person owns",
                ));
            }
            let row = SOURCES
                .get(&vault.store, txn, &source)?
                .filter(|row| row.kind == MailSourceKind::PersonalMailbox)
                .ok_or_else(unknown_member_mailbox)?;
            let Some(person) = row.owner else {
                return Err(unknown_member_mailbox());
            };
            if own_mailbox_in(vault, txn, row.owner, requester)? {
                return Err(MemoryError::bad_request(
                    "your own mailbox goes with your export; request another member's",
                ));
            }
            let member = match vault.shared_vault_creation_in_txn(txn)? {
                Some(creation) => matches!(
                    vault.membership_standing_in_txn(txn, creation.vault_id, &person)?,
                    Some(crate::federation::MembershipStanding::Member { .. })
                ),
                None => false,
            };
            if !live_person_in(vault, txn, &person)? || !member {
                return Err(unknown_member_mailbox());
            }
            let key = (source, requester);
            if let Some(current) = REQUESTS.get(&vault.store, txn, &key)? {
                match standing_in(vault, txn, &current, Some(person))? {
                    RequestStanding::Pending => {
                        return Ok(request_view(&current, source, MailExportRequestState::Pending));
                    }
                    RequestStanding::Approved => {
                        return Ok(request_view(&current, source, MailExportRequestState::Approved));
                    }
                    RequestStanding::Declined
                    | RequestStanding::Consumed
                    | RequestStanding::Lapsed => {}
                }
            }
            withdraw_open_asks_for_in_txn(vault, txn, source, requester)?;
            let request = vault.store.clock.entity_id()?;
            let ask_seq = vault.queue_decision_ask_in_txn(
                txn,
                &request_ask(request, source, person, requester)?,
                Some(&serde_json::json!({
                    "request_ref": request.to_hex(),
                    "source_ref": source.to_hex(),
                })),
            )?;
            let ask = vault
                .decision_ask_in_txn(txn, ask_seq)?
                .filter(|ask| ask.correlation == Some(request) && ask.is_open())
                .ok_or(Error::InvariantViolation(
                    "a member's export request Ask was not queued",
                ))?;
            let row = MailExportRequestRow {
                request,
                mailbox_person: person,
                requester,
                created_at: crate::unix_seconds_now(),
                ask_seq,
                ask_id: ask.id,
                state: MailExportRequestRowState::Open,
            };
            REQUESTS.put(&vault.store, txn, &key, &row)?;
            Ok(request_view(&row, source, MailExportRequestState::Pending))
        })
    }
}

/// An actor's erase takes out every request naming it, as the Owner who
/// asked or as the mailbox's person (FIX 3520), and withdraws every
/// member's export request Ask still open that is from it or put to it,
/// whether or not a request row still names that Ask (a restore takes
/// request rows, not Asks), in the erase's own write. The Asks' own scrub
/// runs first and leaves such an Ask naming no one where it named the
/// actor ([`crate::llm::decision::erase_ask_actor_in_txn`]), so an open Ask
/// of this family from no one or put to no one is withdrawn too: no one may
/// answer it, and its answer would be refused. Its waiters are none.
pub(crate) fn erase_export_request_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (key, row) in REQUESTS.scan(&vault.store, wtxn)? {
        if row.requester == *actor || row.mailbox_person == *actor {
            REQUESTS.delete(&vault.store, wtxn, &key)?;
        }
    }
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let names = |who: AnswerActor| who == AnswerActor::Erased || who.is(*actor);
    for (seq, ask) in DECISION_ASKS.scan(&vault.store, wtxn)? {
        let routed = matches!(
            ask.to.role,
            AskRole::Responsible { actor: who, .. } if names(who)
        );
        if open_export_request_ask(&ask) && (names(ask.principal) || routed) {
            vault.withdraw_decision_ask_in_txn(wtxn, seq)?;
        }
    }
    Ok(())
}
