//! The sign act the dial does not open goes up its role chain (ARCH-0064 D6,
//! ARCH-0064a, ARCH-0076 #roles-everywhere).
//!
//! An automated recipient's Complete that the signing dial does not allow is
//! held, never dropped: one hold per recipient, counting each repeat call.
//! The host asks whether this one signature lands, first of the person the
//! agent signs for (or, with no principal named, the document's sender),
//! then up the chain to the vault owners: an ask its person leaves
//! unanswered for [`ESIGN_ASK_CLIMB_HOURS`] climbs. The ask is an e-signature act, so
//! at every rung only a natural person answers; a board or an agent holding
//! the role never does. No rule or model rung answers that question:
//! decide() advises and never grants, so the ask goes straight to the role
//! queue. An allowed hold signs as the call would have, on the document as
//! it stands at the answer, and its trail names who allowed it; a declined
//! one does not land, and the recipient's turn stays open for the
//! document's sender to void or send again. A recipient whose signature the
//! law keeps with a natural person is never automated, so it never reaches
//! this path.
use super::ceremony::sign;
use super::ledger::state_in;
use super::model::*;
use crate::llm::decision::catalogue;
use crate::llm::decision::{AnswerContract, AskRole, DecisionAsk, DecisionQuestion, RoleRank};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

/// Held automated sign act, one per recipient. Key: document hex32/recipient.
const HELD: SideTable<String, HeldSigning, Named> = SideTable::new(&side_table::ESIGN_HELD_SIGNING);

/// The answer that lands the held signature.
pub const HOLD_ALLOW: &str = "allow";
/// The answer that keeps the signature from landing.
pub const HOLD_DECLINE: &str = "decline";

/// Hours a held sign act's unanswered ask waits on the person it went to
/// before it climbs to the next role up its chain (CALLS "OF-415 held
/// signing climb"). At the vault owners it waits on: no unanswered ask
/// signs or lapses.
pub const ESIGN_ASK_CLIMB_HOURS: crate::learning_setting::SettingSpec =
    crate::learning_setting::SettingSpec {
        key: "esign.ask.climb_hours",
        min: 1.0,
        max: 720.0,
        seed: 24.0,
    };
/// The most bytes of the document title the question quotes.
const TITLE_MAX_BYTES: usize = 256;

/// Where one hold stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HeldSigningState {
    /// Held; the host's next pass asks its first role.
    Held,
    /// Waits in the role ask queue under `question` (hex).
    Asked { question: String },
    /// A role holder allowed it, and the signature landed.
    Allowed { at: u64 },
    /// A role holder declined it; the signature did not land.
    Declined { at: u64 },
    /// The document moved on before the answer could land: the recipient's
    /// turn passed or the document ended.
    Superseded { at: u64 },
}

/// A role holder's answer to one hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldSigningAnswer {
    /// Lands the signature: `by` answered as the holder of a `role`, and the
    /// signature's trail names both.
    Allow {
        by: EntityId,
        role: RoleRank,
    },
    Decline,
}

/// One recipient's held Complete, as the ceremony admitted it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldSigning {
    pub document: String,
    pub title: String,
    pub recipient: String,
    pub name: String,
    pub email: String,
    pub principal_ref: Option<String>,
    /// The recipient the call named to sign next.
    pub next: Option<String>,
    /// Who called: the recipient's actor, IP and user agent at the hold.
    pub actor: EsignAuditActor,
    pub held_at: u64,
    /// Complete calls this hold covers, the first included.
    pub calls: u64,
    pub state: HeldSigningState,
}

impl HeldSigning {
    #[must_use]
    pub fn open(&self) -> bool {
        matches!(
            self.state,
            HeldSigningState::Held | HeldSigningState::Asked { .. }
        )
    }

    /// The role this hold's ask starts at: the principal the agent signs
    /// for, or with none named, the document's sender; with neither, the
    /// vault owners. Signing documents carry no project, so no board rung
    /// sits between. A principal that is no live natural person (an
    /// organisation, an agent) is passed over for the next rung.
    ///
    /// # Errors
    /// The document's trail could not be read.
    pub fn first_role(&self, vault: &Vault) -> Result<AskRole> {
        let actor = match self.principal_ref.as_deref() {
            Some(principal) => EntityId::from_hex(principal).ok(),
            None => vault.esign_sender(EntityId::from_hex(&self.document)?)?,
        };
        Ok(actor.map_or(AskRole::Owner, |actor| AskRole::Responsible {
            actor,
            project: None,
        }))
    }

    /// The question asked about this hold, one per hold.
    ///
    /// # Errors
    /// The question does not validate.
    pub fn question(&self) -> Result<DecisionQuestion> {
        catalogue::ESIGN_HELD_SIGNING.question(
            &[
                self.document.as_bytes(),
                self.recipient.as_bytes(),
                &self.held_at.to_be_bytes(),
            ],
            format!(
                "An agent asks to complete the signature of {} <{}> on \"{}\" (document {}, \
                 recipient {}), and the signing dial does not allow an automated sign act. \
                 Allow this one signature, or decline it?",
                self.name, self.email, self.title, self.document, self.recipient
            ),
            AnswerContract::Choice {
                options: vec![HOLD_ALLOW.to_owned(), HOLD_DECLINE.to_owned()],
            },
        )
    }
}

/// How a signature's trail names the role its allower answered as.
fn role_name(role: RoleRank) -> &'static str {
    match role {
        RoleRank::Responsible => "responsible person",
        RoleRank::Board => "board member",
        RoleRank::Owner => "vault owner",
    }
}

fn key(document: &str, recipient: &str) -> String {
    format!("{document}/{recipient}")
}

fn clipped(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Holds one Complete the dial refused, or counts a repeat on its open hold.
#[allow(clippy::too_many_arguments)]
pub(super) fn hold(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    title: &str,
    recipient: &EsignRecipient,
    next: &Option<String>,
    actor: &EsignAuditActor,
    now: u64,
) -> Result<HeldSigning> {
    let key = key(&document.to_hex(), &recipient.id);
    let held = match HELD.get(&vault.store, txn, &key)? {
        Some(mut held) if held.open() => {
            held.calls = held.calls.saturating_add(1);
            held
        }
        _ => HeldSigning {
            document: document.to_hex(),
            title: clipped(title, TITLE_MAX_BYTES),
            recipient: recipient.id.clone(),
            name: clipped(&recipient.name, TITLE_MAX_BYTES),
            email: recipient.email.clone(),
            principal_ref: recipient.principal_ref.clone(),
            next: next.clone(),
            actor: actor.clone(),
            held_at: now,
            calls: 1,
            state: HeldSigningState::Held,
        },
    };
    HELD.put(&vault.store, txn, &key, &held)?;
    Ok(held)
}

fn open_hold(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: &str,
    recipient: &str,
    held_at: u64,
) -> Result<HeldSigning> {
    HELD.get(&vault.store, txn, &key(document, recipient))?
        .filter(|held| held.held_at == held_at && held.open())
        .ok_or_else(|| invalid("no open signing hold"))
}

impl Vault {
    /// Every held sign act this vault keeps, or only the open ones.
    ///
    /// # Errors
    /// The holds could not be read.
    pub fn esign_held_signings(&self, open_only: bool) -> Result<Vec<HeldSigning>> {
        let txn = self.store.env.read_txn()?;
        let mut holds = Vec::new();
        for row in HELD.iter_from(&self.store, &txn, &[])? {
            let (_, held) = row.map_err(|_| Error::CorruptedIndex("esign signing hold"))?;
            if !open_only || held.open() {
                holds.push(held);
            }
        }
        Ok(holds)
    }

    /// The actor a document was sent as: its trail's Sent row, when that
    /// names an entity.
    ///
    /// # Errors
    /// The trail could not be read.
    pub fn esign_sender(&self, document: EntityId) -> Result<Option<EntityId>> {
        Ok(self
            .esign_audit(document)?
            .into_iter()
            .find(|row| matches!(row.event, EsignEvent::Sent))
            .and_then(|row| EntityId::from_hex(&row.actor.actor).ok()))
    }

    /// Marks one hold as asked: its question waits in the role ask queue.
    ///
    /// # Errors
    /// The hold is no longer open, or the write failed.
    pub fn esign_hold_asked(
        &self,
        document: &str,
        recipient: &str,
        held_at: u64,
        question: EntityId,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let mut held = open_hold(self, txn, document, recipient, held_at)?;
            held.state = HeldSigningState::Asked {
                question: question.to_hex(),
            };
            HELD.put(&self.store, txn, &key(document, recipient), &held)
        })
    }

    /// Climbs a held sign act's unanswered `ask` one role up its chain once
    /// [`ESIGN_ASK_CLIMB_HOURS`] have passed since it was asked: a person who
    /// never answers passes the question on, through the climb that keeps
    /// the ask's natural-person filter and ceiling. An ask at the vault
    /// owners, or at no live holder, waits on. `true` when it climbed.
    ///
    /// # Errors
    /// The setting or the climb's write failed.
    pub fn climb_stale_esign_ask(&self, ask: &DecisionAsk) -> Result<bool> {
        if ask.answer.is_some()
            || ask
                .role
                .as_ref()
                .is_none_or(|role| role.role.rank() == RoleRank::Owner)
        {
            return Ok(false);
        }
        let hours = crate::learning_setting::setting_value(self, &ESIGN_ASK_CLIMB_HOURS)?;
        let waited = self.now_recorded_at().saturating_sub(ask.asked_at) as f64;
        if waited < hours * 3600.0 {
            return Ok(false);
        }
        Ok(self.climb_decision_ask(ask.seq)?.is_some())
    }

    /// Settles one hold with a role holder's answer. An allowed hold signs
    /// on the document as it stands now, after the same turn, expiry and
    /// field checks the call met; a document that moved on supersedes it.
    ///
    /// # Errors
    /// The hold is no longer open, an event of the document awaits its
    /// owner's answer (the next pass tries again), or the write failed.
    pub fn settle_esign_hold(
        &self,
        document: &str,
        recipient: &str,
        held_at: u64,
        answer: HeldSigningAnswer,
    ) -> Result<HeldSigning> {
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let mut held = open_hold(self, txn, document, recipient, held_at)?;
            held.state = match answer {
                HeldSigningAnswer::Decline => HeldSigningState::Declined { at: now },
                HeldSigningAnswer::Allow { by, role } => {
                    let id = EntityId::from_hex(document)?;
                    let state = state_in(self, txn, id)?;
                    let signed = EsignEvent::Signed {
                        recipient: recipient.to_owned(),
                        next: held.next.clone(),
                    };
                    let lands = state.status == DocumentStatus::Pending
                        && state.rejection.is_none()
                        && now < state.document.expires_at
                        && state.clone().apply(&signed, now).is_ok();
                    if lands {
                        let actor = EsignAuditActor {
                            actor: format!(
                                "{}; allowed by the {} {}",
                                held.actor.actor,
                                role_name(role),
                                by.to_hex()
                            ),
                            ..held.actor.clone()
                        };
                        sign(self, txn, id, &state, recipient, &held.next, actor, now)?;
                        HeldSigningState::Allowed { at: now }
                    } else {
                        HeldSigningState::Superseded { at: now }
                    }
                }
            };
            HELD.put(&self.store, txn, &key(document, recipient), &held)?;
            Ok(held)
        })
    }
}
