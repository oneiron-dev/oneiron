//! The member side of an inquiry (federation.md #inquiry, #inquiry-checkin;
//! ARCH-0082 #inquiry; Engine ruling INQUIRE-SHAPE Q4, Q5 = A). The member's
//! vault admits an inquiry that arrived over its edge, reads the opened
//! scope at the edge's tier, lets the companion check it, and runs the
//! check-in ladder unchanged, with the company's guest actor as the asker
//! and the family's answer verb `vault.inquiry.answer` as the act
//! (`outbound_send`).
//!
//! * Admission: the company host's own live credential on this edge, the
//!   edge's grant live with its Connect pact Active, the asking vault the
//!   edge's company, and a new inquiry not yet expired. A repeat of a logged
//!   inquiry returns its current answer.
//! * The opened scope: the edge's opened WORLD alone, at the edge's tier
//!   (`unstamped`: a statement with no sensitivity stamp). Nothing else in
//!   the vault reaches the companion's judgment.
//! * The companion: a caller-supplied [`InquiryJudgment`]. The production
//!   default, [`UnsureInquiryJudgment`], is unsure, so every inquiry goes to
//!   the member until the model-backed judgment lands (its own PR).
//! * The ladder: role Guest holding the edge's power, in the edge's mode,
//!   made `manual` for an inquiry that asks to keep more than the edge
//!   allows. Go: the companion's statements answer, or `no_answer`. Wait: a
//!   pending check-in until the inquiry expires, joined to the inquiry, and
//!   the answer is `pending`.
//! * The member's turn ([`Vault::answer_inquiry`]): words answer and are
//!   filed in the opened scope for next time; a decline settles
//!   `no_answer`. A pending inquiry the asker sends again after the ladder
//!   let go or held settles `no_answer`: one shape for every reason.
//!
//! The member's saved decision for an edge is its terms' mode and allowed
//! keep; no separate standing row is read here.

use rmpv::Value;

use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::check_in::{
    ActClass, CheckInAnswer, CheckInMode, CheckInRequest, CheckInScope, GoReason, HolderAnswer,
    NoAgentVerdict, OpenPendingCheckIn, PendingCheckIn, PendingState, RolePreset, UnsureTest,
    VerifiedChain, advance_pending_check_in_in_txn, answer_pending_check_in_in_txn, check_in,
    open_pending_check_in_in_txn, pending_check_in_in_txn,
};
use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::federation::pact_admits_grant;
use crate::side_table::{self, Raw, SideTable};

use super::edge::{
    InquiryEdge, NewScopeItem, inquiry_edge_grant_in_txn, inquiry_edge_in_txn,
    open_inquiry_scope_item_in_txn, opened_statements_in_txn,
};
use super::log::{
    InquiryDecider, InquiryLogEntry, inquiry_log_entry_in_txn, log_inquiry_in_txn,
    settle_inquiry_in_txn,
};
use super::record::{
    Inquiry, InquiryAnswer, InquiryKeep, InquiryOutcome, InquiryStatement, StatementSource, refuse,
};
use super::terms::{InquiryCheckInMode, InquiryTierCeiling};

/// The verb an inquiry's pending check-in waits on: the family's one answer
/// verb (VS-ANSWER = A).
pub const INQUIRY_ANSWER_VERB: &str = "vault.inquiry.answer";

/// Inquiry edge and inquiry → the pending check-in the ladder opened.
const PENDING: SideTable<(EntityId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::INQUIRY_PENDING);

/// The scope-map key of a claim's sensitivity stamp (oneiron-store's
/// crate-private `CLAIM_SCOPE_SENSITIVITY_KEY`).
const SENSITIVITY_STAMP_KEY: &str = "sensitivity";

/// The tag the answer effect's digest starts with.
const EFFECT_DIGEST_TAG: &[u8] = b"oneiron.inquiry.answer.v1";

/// How many ladder transitions one repeat of a pending inquiry makes at
/// most. The ladder has four rungs; each transition climbs one or ends it.
const ADVANCE_LIMIT: usize = 8;

/// The companion's check of one inquiry against the opened scope (rung 1 of
/// the ladder; INQUIRE-SHAPE Q5 = A). It gets the question and the opened
/// statements the tier admitted, and nothing else of the vault.
pub trait InquiryJudgment {
    /// Whether `admitted` answers `question`, and with which statements.
    ///
    /// # Errors
    ///
    /// Any failure. The ladder then asks the member, as it does on any
    /// unsure test that fails.
    fn judge(&self, question: &str, admitted: &[String]) -> Result<InquiryJudgmentOutcome>;
}

/// What the companion's judgment found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InquiryJudgmentOutcome {
    /// Sure: these statements answer the question. They go out as the
    /// companion's (`companion_of_member`), never as the member's word. A
    /// blank statement is dropped; none left is unsure.
    Sure(Vec<String>),
    /// Unsure: the member is asked, unless the edge's mode says otherwise.
    Unsure,
}

/// The production judgment until the model-backed one lands: always unsure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnsureInquiryJudgment;

impl InquiryJudgment for UnsureInquiryJudgment {
    fn judge(&self, _question: &str, _admitted: &[String]) -> Result<InquiryJudgmentOutcome> {
        Ok(InquiryJudgmentOutcome::Unsure)
    }
}

/// The member's answer to an inquiry the ladder took to them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InquiryMemberAnswer {
    /// The member's words: they answer, and they are filed in the edge's
    /// opened scope for next time.
    Words(String),
    /// No, or nothing to say: `no_answer`.
    Decline,
}

/// The judgment as rung 1 of the ladder reads it.
enum Judged {
    Sure(Vec<InquiryStatement>),
    Unsure,
    Failed,
}

impl UnsureTest for Judged {
    fn is_sure(&self) -> Result<bool> {
        match self {
            Self::Sure(_) => Ok(true),
            Self::Unsure => Ok(false),
            Self::Failed => Err(refuse("the companion's judgment failed")),
        }
    }
}

impl Vault {
    /// Admits `inquiry`, which the company sent over the inquiry edge
    /// `grant` under `proof` (its host's own credential on that edge), in one
    /// writer, and returns its answer as it stands: `answered`, `no_answer`
    /// or `pending`. `judgment` is the companion's check; it runs only for a
    /// new inquiry. A repeat returns the logged answer, after the ladder's
    /// due transitions, and opens no second check-in.
    ///
    /// # Errors
    ///
    /// A credential, edge or pact that does not admit the inquiry; an
    /// inquiry from another vault than the edge's company; a new inquiry
    /// already expired; a repeat that carries another inquiry under the
    /// same id; storage errors.
    pub fn admit_inquiry(
        &self,
        grant: EntityId,
        proof: &VerifiedSlip,
        inquiry: &Inquiry,
        judgment: &dyn InquiryJudgment,
    ) -> Result<InquiryAnswer> {
        let entry = self.with_write_txn_grouped(|txn| {
            admit_inquiry_in_txn(self, txn, grant, proof, inquiry, judgment)
        })?;
        Ok(entry.answer)
    }

    /// The member's answer to the pending inquiry `inquiry_id` over the
    /// edge `grant`, given by `person`, in one writer: the inquiry's pending
    /// check-in is answered (approve for words, deny for a decline), the
    /// words are filed in the edge's opened scope as the member's, and the
    /// log settles `answered` with them, or `no_answer`.
    ///
    /// # Errors
    ///
    /// Blank words; no pending inquiry, or none the ladder took to the
    /// member; a person the check-in does not let answer, or an answer after
    /// the inquiry expired; words for an edge that is gone; storage errors.
    pub fn answer_inquiry(
        &self,
        person: &AuthenticatedOwner,
        grant: EntityId,
        inquiry_id: EntityId,
        answer: &InquiryMemberAnswer,
    ) -> Result<InquiryAnswer> {
        let words = match answer {
            InquiryMemberAnswer::Words(words) => {
                let words = words.trim();
                if words.is_empty() {
                    return Err(refuse("the member's answer has words"));
                }
                Some(words)
            }
            InquiryMemberAnswer::Decline => None,
        };
        let entry = self.with_write_txn_grouped(|txn| {
            answer_inquiry_in_txn(self, txn, person, grant, inquiry_id, words)
        })?;
        if words.is_some() {
            self.store.notify_proactivity_changes();
        }
        Ok(entry.answer)
    }

    /// The pending check-in the ladder opened for the inquiry `inquiry_id`
    /// over `edge`, as it stands; `None` when the inquiry never went to the
    /// member.
    ///
    /// # Errors
    ///
    /// A join to a missing check-in; storage errors.
    pub fn inquiry_pending_check_in(
        &self,
        edge: &EntityId,
        inquiry_id: &EntityId,
    ) -> Result<Option<PendingCheckIn>> {
        let txn = self.store.env.read_txn()?;
        let Some(id) = PENDING.get(&self.store, &txn, &(*edge, *inquiry_id))? else {
            return Ok(None);
        };
        pending_check_in_in_txn(&self.store, &txn, &id)?
            .map(Some)
            .ok_or(Error::CorruptedIndex("inquiry pending check-in"))
    }
}

/// [`Vault::admit_inquiry`] in the caller's writer; returns the log row.
pub(crate) fn admit_inquiry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    grant: EntityId,
    proof: &VerifiedSlip,
    inquiry: &Inquiry,
    judgment: &dyn InquiryJudgment,
) -> Result<InquiryLogEntry> {
    inquiry.validate()?;
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let edge = admitted_edge_in_txn(vault, txn, grant, proof, inquiry, now)?;
    if let Some(logged) = inquiry_log_entry_in_txn(&vault.store, txn, grant, inquiry.id)? {
        if logged.inquiry != *inquiry {
            return Err(refuse("a repeat of the inquiry id carries another inquiry"));
        }
        return advance_inquiry_in_txn(vault, txn, logged, now);
    }
    if inquiry.expires_at <= now {
        return Err(refuse("the inquiry has expired"));
    }
    let logged = log_inquiry_in_txn(&vault.store, txn, grant, inquiry, now)?;
    let admitted = opened_scope_texts_in_txn(vault, txn, &edge)?;
    let judged = judge(judgment, &inquiry.question, &admitted);
    let mode = inquiry_mode(
        edge.terms.check_in_mode,
        inquiry.keep,
        edge.terms.keep_allowed,
    );
    let request = CheckInRequest {
        act: ActClass::OutboundSend,
        role: RolePreset::Guest,
        holds_power: true,
        explicit_mode: Some(mode),
        standing_row: None,
    };
    match check_in(&request, &judged) {
        CheckInAnswer::Go(
            reason @ (GoReason::Sure | GoReason::NeverAsk | GoReason::StandingRow(_)),
        ) => {
            let decided_by = match reason {
                GoReason::StandingRow(row_ref) => InquiryDecider::StandingRow { row_ref },
                _ => InquiryDecider::Companion,
            };
            let answer = match judged {
                Judged::Sure(statements) => {
                    InquiryAnswer::answered(inquiry, statements, inquiry.expires_at)?
                }
                Judged::Unsure | Judged::Failed => InquiryAnswer::no_answer(inquiry),
            };
            settle_inquiry_in_txn(
                &vault.store,
                txn,
                grant,
                inquiry.id,
                answer,
                decided_by,
                now,
            )
        }
        CheckInAnswer::Wait(reason) => {
            let pending = open_pending_check_in_in_txn(
                vault,
                txn,
                OpenPendingCheckIn {
                    asker: edge.guest_actor,
                    grant_ref: grant.to_hex(),
                    verb: INQUIRY_ANSWER_VERB.to_owned(),
                    act: ActClass::OutboundSend,
                    scope: CheckInScope {
                        world_ref: Some(edge.terms.opened_world.to_hex()),
                        project_ref: None,
                    },
                    effect_digest: effect_digest(grant, inquiry)?,
                    mode,
                    reason,
                    asker_wait_secs: None,
                    until: Some(inquiry.expires_at),
                    undo_plan: None,
                    delay_window: None,
                },
                &VerifiedChain::new(&NoAgentVerdict),
                now,
            )?;
            PENDING.put(&vault.store, txn, &(grant, inquiry.id), &pending.id)?;
            settle_from_check_in_in_txn(vault, txn, logged, &pending, now)
        }
        CheckInAnswer::Go(GoReason::OwnProof) | CheckInAnswer::Propose | CheckInAnswer::Absent => {
            Err(refuse(
                "the check-in ladder gives an inquiry no answer path",
            ))
        }
    }
}

/// [`Vault::answer_inquiry`] in the caller's writer; `words` trimmed and
/// not blank, or `None` for a decline. Returns the settled log row.
pub(crate) fn answer_inquiry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: &AuthenticatedOwner,
    grant: EntityId,
    inquiry_id: EntityId,
    words: Option<&str>,
) -> Result<InquiryLogEntry> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let Some(logged) = inquiry_log_entry_in_txn(&vault.store, txn, grant, inquiry_id)? else {
        return Err(refuse("no logged inquiry to answer"));
    };
    if logged.answer.outcome() != InquiryOutcome::Pending {
        return Err(refuse("the inquiry is already settled"));
    }
    let Some(pending) = PENDING.get(&vault.store, txn, &(grant, inquiry_id))? else {
        return Err(refuse("the inquiry waits on no check-in"));
    };
    let holder_answer = if words.is_some() {
        HolderAnswer::Approve
    } else {
        HolderAnswer::Deny
    };
    let row = answer_pending_check_in_in_txn(
        vault,
        txn,
        person,
        &pending,
        &effect_digest(grant, &logged.inquiry)?,
        holder_answer,
        &VerifiedChain::new(&NoAgentVerdict),
        now,
    )?;
    let PendingState::Answered { by, .. } = row.state else {
        return Err(Error::CorruptedIndex("an answered inquiry check-in"));
    };
    let answer = match words {
        Some(words) => {
            let member = by.ok_or(Error::CorruptedIndex("an answered inquiry check-in"))?;
            let edge = inquiry_edge_in_txn(vault, txn, &grant)?
                .ok_or_else(|| refuse("the inquiry's edge is gone"))?;
            open_inquiry_scope_item_in_txn(
                vault,
                txn,
                &NewScopeItem {
                    claim: EntityId::now(),
                    member,
                    statement: words,
                    drawn_from: None,
                },
                &edge,
                now,
            )?;
            InquiryAnswer::answered(
                &logged.inquiry,
                vec![InquiryStatement::new(words, StatementSource::MemberWord)?],
                logged.inquiry.expires_at,
            )?
        }
        None => InquiryAnswer::no_answer(&logged.inquiry),
    };
    settle_inquiry_in_txn(
        &vault.store,
        txn,
        grant,
        inquiry_id,
        answer,
        InquiryDecider::Member { principal: by },
        now,
    )
}

/// The edge `grant`, when `proof` and `inquiry` may use it at `now`: the
/// credential is the company host's own, bound to this edge's grant and
/// live in `txn` (its holder, its grant's expiry and withdrawal, its pact);
/// the grant is a live inquiry edge, not expired or withdrawn, whose Connect
/// pact is Active; and the inquiry comes from the edge's company. One
/// refusal for every credential, edge or pact failure.
fn admitted_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    proof: &VerifiedSlip,
    inquiry: &Inquiry,
    now: u64,
) -> Result<InquiryEdge> {
    let not_admitted = || refuse("the credential does not admit an inquiry over this edge");
    let claims = proof.claims();
    if claims.grant_ref.as_deref() != Some(grant.to_hex().as_str())
        || proof.is_transferred()
        || !claims.channels.is_empty()
        || !vault.capability_slip_is_live_in_txn(txn, proof)?
    {
        return Err(not_admitted());
    }
    let Some((edge, decoded)) = inquiry_edge_grant_in_txn(vault, txn, &grant)? else {
        return Err(not_admitted());
    };
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if !decoded.is_live_at(now)
        || vault.guest_grant_withdrawn_in_txn(txn, &grant)?
        || !pact_admits_grant(&fold, &grant, &decoded)
    {
        return Err(not_admitted());
    }
    if inquiry.from.vault != bytes_to_hex_lower(&edge.company_vault_id) {
        return Err(refuse(
            "the inquiry comes from another vault than the edge's company",
        ));
    }
    Ok(edge)
}

/// The texts of `edge`'s opened scope its tier admits, in id order.
fn opened_scope_texts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    edge: &InquiryEdge,
) -> Result<Vec<String>> {
    Ok(
        opened_statements_in_txn(vault, txn, edge.terms.opened_world)?
            .into_iter()
            .filter(|opened| tier_admits(edge.terms.tier_ceiling, &opened.body))
            .map(|opened| opened.text)
            .collect(),
    )
}

/// Whether `ceiling` admits `body`. `unstamped` admits a claim with no
/// scope map, or a scope map with no sensitivity key; any stamp, and a
/// scope that is not a map, stays out.
fn tier_admits(ceiling: InquiryTierCeiling, body: &ClaimBody) -> bool {
    match ceiling {
        InquiryTierCeiling::Unstamped => match &body.scope {
            None => true,
            Some(Value::Map(entries)) => !entries
                .iter()
                .any(|(key, _)| key.as_str() == Some(SENSITIVITY_STAMP_KEY)),
            Some(_) => false,
        },
    }
}

/// `judgment`'s check of `question` over `admitted`, as rung 1 reads it.
fn judge(judgment: &dyn InquiryJudgment, question: &str, admitted: &[String]) -> Judged {
    match judgment.judge(question, admitted) {
        Ok(InquiryJudgmentOutcome::Sure(texts)) => {
            let statements: Vec<InquiryStatement> = texts
                .into_iter()
                .filter_map(|text| {
                    InquiryStatement::new(text, StatementSource::CompanionOfMember).ok()
                })
                .collect();
            if statements.is_empty() {
                Judged::Unsure
            } else {
                Judged::Sure(statements)
            }
        }
        Ok(InquiryJudgmentOutcome::Unsure) => Judged::Unsure,
        Err(_) => Judged::Failed,
    }
}

/// The mode the ladder runs an inquiry in: the edge's, made `manual` when
/// the inquiry asks to keep a copy and the edge allows only `task`.
fn inquiry_mode(
    mode: InquiryCheckInMode,
    keep: InquiryKeep,
    keep_allowed: InquiryKeep,
) -> CheckInMode {
    if keep == InquiryKeep::Copy && keep_allowed == InquiryKeep::Task {
        return CheckInMode::AlwaysAsk;
    }
    match mode {
        InquiryCheckInMode::AlwaysAsk => CheckInMode::AlwaysAsk,
        InquiryCheckInMode::AskWhenUnsure => CheckInMode::AskWhenUnsure,
        InquiryCheckInMode::NeverAsk => CheckInMode::NeverAsk,
    }
}

/// The digest of an inquiry's answer effect: statements of this vault
/// leaving over `grant` for exactly `inquiry`. An answer over any other
/// settles nothing.
fn effect_digest(grant: EntityId, inquiry: &Inquiry) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DIGEST_TAG);
    hasher.update(grant.as_bytes());
    hasher.update(&inquiry.encode_wire()?);
    Ok(*hasher.finalize().as_bytes())
}

/// A repeat of the logged `entry`: a pending one first makes the ladder's
/// due transitions, then settles as its check-in stands. Returns the row.
fn advance_inquiry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entry: InquiryLogEntry,
    now: u64,
) -> Result<InquiryLogEntry> {
    if entry.answer.outcome() != InquiryOutcome::Pending {
        return Ok(entry);
    }
    let Some(id) = PENDING.get(&vault.store, txn, &(entry.edge, entry.inquiry.id))? else {
        return Err(Error::CorruptedIndex("inquiry pending check-in"));
    };
    let chain = VerifiedChain::new(&NoAgentVerdict);
    for _ in 0..ADVANCE_LIMIT {
        if advance_pending_check_in_in_txn(vault, txn, &id, &chain, now)?.is_none() {
            break;
        }
    }
    let Some(row) = pending_check_in_in_txn(&vault.store, txn, &id)? else {
        return Err(Error::CorruptedIndex("inquiry pending check-in"));
    };
    settle_from_check_in_in_txn(vault, txn, entry, &row, now)
}

/// The pending `entry` as its check-in `row` stands: still open, it stays
/// pending; ended any other way than through [`answer_inquiry_in_txn`] (let
/// go at the inquiry's expiry, held at the chain's end, or answered by the
/// check-in's own door, which carries no words), it settles `no_answer`.
fn settle_from_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entry: InquiryLogEntry,
    row: &PendingCheckIn,
    now: u64,
) -> Result<InquiryLogEntry> {
    let decided_by = match row.state {
        PendingState::Open => return Ok(entry),
        PendingState::Answered { by, .. } => InquiryDecider::Member { principal: by },
        _ => InquiryDecider::LetGo,
    };
    settle_inquiry_in_txn(
        &vault.store,
        txn,
        entry.edge,
        entry.inquiry.id,
        InquiryAnswer::no_answer(&entry.inquiry),
        decided_by,
        now,
    )
}
