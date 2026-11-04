//! Trusted contact (OF-527): a person names another PERSON to hear a crisis
//! notice. Both sides consent, the contact attests they are an adult, and
//! either side revokes. Only a `RouteToHelp` the OF-333 gate settles for that
//! person fires it; the contact then hears the fact of concern, which the
//! host renders as its fixed check-in line, and nothing else.
//!
//! The rows live in engine-private side tables, so no claim writer, agent tool
//! or sync peer can stamp a consent: each one is written here, behind the proof
//! of the person it belongs to.

use serde::{Deserialize, Serialize};

use super::trusted_contact_notice::{
    TrustedContactNoticeAuthorization, consent_change_guard, erase_notices_naming_in_txn,
    inform_inboxes_in_txn, stage_notice_in_txn, withdraw_policy_notice_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::policy_model::PolicyModelConfig;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateSystemNoticeRecord, Store};

/// Key: (person, contact).
pub(super) const RELATIONS: SideTable<(EntityId, EntityId), TrustedContact, Named> =
    SideTable::new(&side_table::TRUSTED_CONTACT_RELATION);

const ASKS: SideTable<EntityId, TrustedContactAsk, Named> =
    SideTable::new(&side_table::TRUSTED_CONTACT_ASK);

/// Key: the `RouteToHelp` owner row's ref.
const TIERS: SideTable<String, TrustedContactTier, Named> =
    SideTable::new(&side_table::TRUSTED_CONTACT_TIER);

const MAX_TARGET_BYTES: usize = 512;

const MAX_ROW_REF_BYTES: usize = 256;

/// The refusal of a tier whose row is in the manifest but not a live
/// `RouteToHelp` row.
const TIER_ROW_NOT_ROUTE_TO_HELP: &str = "a tier names an active RouteToHelp owner policy row";

/// Whether the engine asks the person before it reaches their contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactDial {
    /// Ask first on either tier.
    AskFirst,
    /// Reach the contact at once on the imminent tier, and still ask first
    /// on the concern tier.
    JustCall,
}

/// How grave a `RouteToHelp` is. The tier belongs to this feature, not to the
/// gate: the owner names a row imminent, and every other row is a concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactTier {
    Concern,
    Imminent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactParty {
    Person,
    Contact,
}

/// Where the notice goes, on the existing outbound rails: `sender` is the
/// actor whose channel identity speaks, `channel` and `verb` a registered
/// outbound capability, and `target` the contact's address on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactReach {
    pub sender: EntityId,
    pub channel: String,
    pub verb: String,
    pub target: String,
}

/// The contact's consent, given with their word that they are an adult.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAcceptance {
    pub at: u64,
    pub adult: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactRevocation {
    pub at: u64,
    pub by: TrustedContactParty,
}

/// One person's trusted contact. Naming it is the person's consent; the
/// contact's is [`Self::accepted`], given to exactly this [`Self::version`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContact {
    pub person: EntityId,
    pub contact: EntityId,
    pub reach: TrustedContactReach,
    pub dial: TrustedContactDial,
    /// Counts the times the person named this contact. Naming again changes
    /// what the contact agreed to, so it needs their consent again.
    pub version: u64,
    pub named_at: u64,
    pub accepted: Option<TrustedContactAcceptance>,
    pub revoked: Option<TrustedContactRevocation>,
}

impl TrustedContact {
    /// Both sides consent, the contact is an adult, and neither has revoked.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.revoked.is_none() && self.accepted.is_some_and(|accepted| accepted.adult)
    }
}

/// "May I reach your trusted contact?", raised by a `RouteToHelp` the
/// person's dial or the row's tier says to ask about first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAsk {
    pub ask: EntityId,
    pub person: EntityId,
    pub contact: EntityId,
    /// The relation version asked about; a yes to an older one sends nothing.
    pub version: u64,
    pub tier: TrustedContactTier,
    pub asked_at: u64,
    pub answer: Option<TrustedContactAnswer>,
    /// When the naming asked about was revoked or replaced before an answer.
    /// It closes the ask: answering it sends nothing, and says so.
    pub superseded: Option<u64>,
}

impl TrustedContactAsk {
    /// Neither answered nor superseded.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.answer.is_none() && self.superseded.is_none()
    }
}

/// What the person's answer to one ask did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedContactAskOutcome {
    /// A yes: the notice is staged, and these notices tell the person and the
    /// model it was sent, as the gate's own fire does.
    Notified(Vec<GateSystemNoticeRecord>),
    /// A no: nothing is sent.
    Declined,
    /// The naming asked about was revoked or replaced: nothing is sent.
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAnswer {
    pub yes: bool,
    pub at: u64,
    /// The yes staged a notice: the relation was still live as asked about.
    pub notified: bool,
}

/// What one settled `RouteToHelp` did for its person: how many contacts were
/// sent the notice and how many the person is asked about. The gate tells the
/// person and the agent both.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedContactFire {
    pub(crate) notified: usize,
    pub(crate) asked: usize,
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("trusted contact: {reason}"))
}

fn not_a_party(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

fn validate_reach(reach: &TrustedContactReach) -> Result<()> {
    if !crate::outbound::is_canonical_outbound_verb(&reach.channel, &reach.verb) {
        return Err(invalid("the reach names no outbound channel verb"));
    }
    if reach.target.trim().is_empty()
        || reach.target.trim() != reach.target
        || reach.target.len() > MAX_TARGET_BYTES
    {
        return Err(invalid("the reach target is not an address"));
    }
    Ok(())
}

/// Closes every open ask about `person`'s naming of `contact`, in the
/// transaction that revokes or replaces that naming.
fn supersede_open_asks_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person: EntityId,
    contact: EntityId,
    now: u64,
) -> Result<()> {
    for (key, mut ask) in ASKS.scan(&vault.store, wtxn)? {
        if ask.person == person && ask.contact == contact && ask.is_open() {
            ask.superseded = Some(now);
            ASKS.put(&vault.store, wtxn, &key, &ask)?;
        }
    }
    Ok(())
}

/// The open ask about `relation`'s naming, or a new one at `tier`: one open
/// ask per naming, so a second crisis before the person answers is told to
/// them, not asked twice.
fn open_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    relation: &TrustedContact,
    tier: TrustedContactTier,
    now: u64,
) -> Result<EntityId> {
    let open = ASKS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .find(|(_, ask)| {
            ask.person == relation.person
                && ask.contact == relation.contact
                && ask.version == relation.version
                && ask.is_open()
        })
        .map(|(key, _)| key);
    if let Some(open) = open {
        return Ok(open);
    }
    let ask = EntityId::now();
    ASKS.put(
        &vault.store,
        wtxn,
        &ask,
        &TrustedContactAsk {
            ask,
            person: relation.person,
            contact: relation.contact,
            version: relation.version,
            tier,
            asked_at: now,
            answer: None,
            superseded: None,
        },
    )?;
    Ok(ask)
}

/// Whether the person answered yes to an ask about this naming of `contact`,
/// at `version`: that yes authorizes a notice for it whatever the dial.
pub(super) fn naming_answered_yes_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    contact: EntityId,
    version: u64,
) -> Result<bool> {
    Ok(ASKS.scan(store, txn)?.into_iter().any(|(_, ask)| {
        ask.person == person
            && ask.contact == contact
            && ask.version == version
            && ask.answer.is_some_and(|answer| answer.yes)
    }))
}

/// Takes every trusted-contact row naming `id` out with its erase (FIX
/// 9775): each relation it is either side of, each ask about such a
/// relation, and each notice staged to or about it, whose queued send is
/// cancelled and whose payload is emptied. Nothing names any other entity,
/// so its erase changes nothing here.
pub(crate) fn erase_trusted_contact_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (key, relation) in RELATIONS.scan(store, wtxn)? {
        if relation.person == *id || relation.contact == *id {
            RELATIONS.delete(store, wtxn, &key)?;
        }
    }
    for (key, ask) in ASKS.scan(store, wtxn)? {
        if ask.person == *id || ask.contact == *id {
            ASKS.delete(store, wtxn, &key)?;
        }
    }
    erase_notices_naming_in_txn(store, wtxn, id)
}

impl Vault {
    /// The person names `contact`, another live PERSON, as their trusted
    /// contact, reached on `reach`. The relation is not live until the
    /// contact accepts it. Naming the same contact again replaces it, and the
    /// contact's consent with it; a notice staged for the old naming is not
    /// sent, and an ask still open about it is superseded.
    pub fn name_trusted_contact(
        &self,
        person: &AuthenticatedOwner,
        contact: EntityId,
        reach: TrustedContactReach,
        dial: TrustedContactDial,
        now: u64,
    ) -> Result<TrustedContact> {
        validate_reach(&reach)?;
        let _order = consent_change_guard(self);
        self.with_write_txn(|wtxn| {
            let person = person.revalidate_person_in_txn(self, wtxn)?;
            if contact == person || !crate::consent::person_is_live_in_txn(self, wtxn, &contact)? {
                return Err(invalid("a trusted contact is another live person"));
            }
            let version = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .map_or(1, |prior| prior.version.saturating_add(1));
            let relation = TrustedContact {
                person,
                contact,
                reach,
                dial,
                version,
                named_at: now,
                accepted: None,
                revoked: None,
            };
            RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            supersede_open_asks_in_txn(self, wtxn, person, contact, now)?;
            Ok(relation)
        })
    }

    /// The contact accepts `person`'s naming, as an adult, at the `version`
    /// they were shown. Only the named contact's own proof accepts.
    pub fn accept_trusted_contact(
        &self,
        contact: &AuthenticatedOwner,
        person: EntityId,
        version: u64,
        adult: bool,
        now: u64,
    ) -> Result<TrustedContact> {
        if !adult {
            return Err(invalid("a trusted contact is an adult"));
        }
        self.with_write_txn(|wtxn| {
            let contact = contact.revalidate_person_in_txn(self, wtxn)?;
            let mut relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no one named this person a trusted contact"))?;
            if relation.version != version || relation.revoked.is_some() {
                return Err(invalid("this is not the naming the contact was shown"));
            }
            relation.accepted = Some(TrustedContactAcceptance { at: now, adult });
            RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            Ok(relation)
        })
    }

    /// Either side ends the relation. A revoked relation never fires, a
    /// notice already staged from it is not sent, and an ask still open about
    /// it is superseded: this waits for a send already under way, and none
    /// starts once it returns.
    pub fn revoke_trusted_contact(
        &self,
        party: &AuthenticatedOwner,
        person: EntityId,
        contact: EntityId,
        now: u64,
    ) -> Result<TrustedContact> {
        let _order = consent_change_guard(self);
        self.with_write_txn(|wtxn| {
            let actor = party.revalidate_person_in_txn(self, wtxn)?;
            let by = if actor == person {
                TrustedContactParty::Person
            } else if actor == contact {
                TrustedContactParty::Contact
            } else {
                return Err(not_a_party("only the person or their contact revokes"));
            };
            let mut relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no such trusted contact"))?;
            if relation.revoked.is_none() {
                relation.revoked = Some(TrustedContactRevocation { at: now, by });
                RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            }
            supersede_open_asks_in_txn(self, wtxn, person, contact, now)?;
            Ok(relation)
        })
    }

    /// The person changes whether they are asked first. It does not change what the
    /// contact agreed to receive, so their consent stands. The ask a change to
    /// ask-first raises is told in the default notice words; see
    /// [`Self::change_trusted_contact_dial`].
    pub fn set_trusted_contact_dial(
        &self,
        person: &AuthenticatedOwner,
        contact: EntityId,
        dial: TrustedContactDial,
    ) -> Result<TrustedContact> {
        self.change_trusted_contact_dial(
            person,
            contact,
            dial,
            &PolicyModelConfig::default(),
            crate::unix_seconds_now(),
        )
    }

    /// The person changes whether they are asked first (FIX 9774). Turned to
    /// ask-first, a notice a policy row authorized for this naming and not
    /// yet sent is withdrawn, and the person is asked about it instead: the
    /// ask lands in their inbox and the sending agent's, each body as
    /// `config` words it. This waits for a send already under way, and no
    /// send starts on the old dial once it returns.
    pub fn change_trusted_contact_dial(
        &self,
        person: &AuthenticatedOwner,
        contact: EntityId,
        dial: TrustedContactDial,
        config: &PolicyModelConfig,
        now: u64,
    ) -> Result<TrustedContact> {
        let _order = consent_change_guard(self);
        self.with_write_txn(|wtxn| {
            let person = person.revalidate_person_in_txn(self, wtxn)?;
            let mut relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no such trusted contact"))?;
            relation.dial = dial;
            RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            if dial == TrustedContactDial::AskFirst
                && let Some(tier) = withdraw_policy_notice_in_txn(self, wtxn, &relation, now)?
                && relation.is_live()
            {
                let ask = open_ask_in_txn(self, wtxn, &relation, tier, now)?;
                let notices = crate::policy_model::trusted_contact_notices(
                    TrustedContactFire {
                        notified: 0,
                        asked: 1,
                    },
                    config,
                );
                inform_inboxes_in_txn(self, wtxn, &relation, ask, &notices, now)?;
            }
            Ok(relation)
        })
    }

    /// Every relation the proven person is a side of: those they named, and
    /// those naming them.
    pub fn trusted_contacts(&self, party: &AuthenticatedOwner) -> Result<Vec<TrustedContact>> {
        let rtxn = self.store.env.read_txn()?;
        let actor = party.revalidate_person_in_txn(self, &rtxn)?;
        Ok(RELATIONS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, relation)| relation)
            .filter(|relation| relation.person == actor || relation.contact == actor)
            .collect())
    }

    /// The owner names the trusted-contact tier of one `RouteToHelp` policy
    /// row, active in the policy in force. A row the owner never names is a
    /// concern.
    pub fn set_trusted_contact_tier(
        &self,
        owner: &AuthenticatedOwner,
        row_ref: &str,
        tier: TrustedContactTier,
    ) -> Result<()> {
        if row_ref.trim().is_empty() || row_ref.len() > MAX_ROW_REF_BYTES {
            return Err(invalid("a tier names one policy row"));
        }
        self.with_write_txn(|wtxn| {
            owner.revalidate_in_txn(self, wtxn)?;
            // The row is read in this same transaction (FIX 4330): a ref no
            // owner row carries is not found, and one whose rows are all
            // retired or act otherwise than `RouteToHelp` is refused.
            match crate::gate::resolve_policy_manifest(&self.store, wtxn)?
                .owner_policy_row_routes_to_help(row_ref)
            {
                None => return Err(Error::EntityNotFound),
                Some(false) => return Err(invalid(TIER_ROW_NOT_ROUTE_TO_HELP)),
                Some(true) => {}
            }
            TIERS.put(&self.store, wtxn, &row_ref.to_owned(), &tier)
        })
    }

    /// The proven person's open asks.
    pub fn trusted_contact_asks(
        &self,
        person: &AuthenticatedOwner,
    ) -> Result<Vec<TrustedContactAsk>> {
        let rtxn = self.store.env.read_txn()?;
        let person = person.revalidate_person_in_txn(self, &rtxn)?;
        Ok(ASKS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, ask)| ask)
            .filter(|ask| ask.person == person && ask.is_open())
            .collect())
    }

    /// The person answers one ask, once. A yes stages the notice, authorized
    /// by this ask, and returns the notices that tell the person and the
    /// model it was sent, each body as `config` words it; the same notices
    /// land in the person's and the sending agent's inboxes. An ask whose
    /// naming was revoked or replaced is superseded, whatever the answer.
    pub fn answer_trusted_contact_ask(
        &self,
        person: &AuthenticatedOwner,
        ask: EntityId,
        yes: bool,
        config: &PolicyModelConfig,
        now: u64,
    ) -> Result<TrustedContactAskOutcome> {
        self.with_write_txn(|wtxn| {
            let person = person.revalidate_person_in_txn(self, wtxn)?;
            let mut pending = ASKS
                .get(&self.store, wtxn, &ask)?
                .filter(|pending| pending.person == person)
                .ok_or_else(|| not_a_party("this ask is not the person's"))?;
            if pending.answer.is_some() {
                return Err(invalid("this ask is already answered"));
            }
            let relation = RELATIONS
                .get(&self.store, wtxn, &(pending.person, pending.contact))?
                .filter(|relation| relation.is_live() && relation.version == pending.version);
            let Some(relation) = relation.filter(|_| pending.superseded.is_none()) else {
                if pending.superseded.is_none() {
                    pending.superseded = Some(now);
                    ASKS.put(&self.store, wtxn, &ask, &pending)?;
                }
                return Ok(TrustedContactAskOutcome::Superseded);
            };
            pending.answer = Some(TrustedContactAnswer {
                yes,
                at: now,
                notified: yes,
            });
            ASKS.put(&self.store, wtxn, &ask, &pending)?;
            if !yes {
                return Ok(TrustedContactAskOutcome::Declined);
            }
            let fire = stage_notice_in_txn(
                self,
                wtxn,
                &relation,
                ask,
                TrustedContactNoticeAuthorization::Ask {
                    ask_ref: ask.to_hex(),
                },
                now,
            )?;
            let notices = crate::policy_model::trusted_contact_notices(
                TrustedContactFire {
                    notified: 1,
                    asked: 0,
                },
                config,
            );
            inform_inboxes_in_txn(self, wtxn, &relation, fire, &notices, now)?;
            Ok(TrustedContactAskOutcome::Notified(notices))
        })
    }

    /// Fires `person`'s trusted contacts for one `RouteToHelp` the gate
    /// settled, in the gate's own transaction. Each live relation is notified
    /// at once on the imminent tier with just-call, authorized by the firing
    /// row, and asked about otherwise; either way the person and the sending
    /// agent are told in their inboxes, each body as the host's `config`
    /// words it. A proof that no longer stands binds no one: the help card
    /// still shows.
    pub(crate) fn fire_trusted_contacts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        person: &AuthenticatedOwner,
        row_ref: Option<&str>,
        config: &PolicyModelConfig,
        now: u64,
    ) -> Result<TrustedContactFire> {
        let person = match person.revalidate_person_in_txn(self, wtxn) {
            Ok(person) => person,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))) => {
                return Ok(TrustedContactFire::default());
            }
            Err(error) => return Err(error),
        };
        let tier = match row_ref {
            Some(row_ref) => TIERS.get(&self.store, wtxn, &row_ref.to_owned())?,
            None => None,
        }
        .unwrap_or(TrustedContactTier::Concern);
        // A notice sent without asking is authorized by the policy row that
        // fired it, at the tier the owner named for that row.
        let origin = row_ref.map(|row_ref| TrustedContactNoticeAuthorization::Policy {
            row_ref: row_ref.to_owned(),
            tier,
        });
        // What the person and the agent are told, per relation, in the
        // host's words, as the gate's receipt carries them (FIX 4422).
        let told =
            |fire: TrustedContactFire| crate::policy_model::trusted_contact_notices(fire, config);
        let mut fire = TrustedContactFire::default();
        for (_, relation) in RELATIONS.scan_from(&self.store, wtxn, person.as_bytes())? {
            if relation.person != person || !relation.is_live() {
                continue;
            }
            if relation.dial == TrustedContactDial::JustCall
                && tier == TrustedContactTier::Imminent
                && let Some(origin) = origin.clone()
            {
                // The fire that delivers: a fresh one, or the notice already
                // waiting for this naming (FIX 4423).
                let fresh = EntityId::now();
                let sent = stage_notice_in_txn(self, wtxn, &relation, fresh, origin, now)?;
                let notices = told(TrustedContactFire {
                    notified: 1,
                    asked: 0,
                });
                inform_inboxes_in_txn(self, wtxn, &relation, sent, &notices, now)?;
                fire.notified += 1;
                continue;
            }
            let asked = open_ask_in_txn(self, wtxn, &relation, tier, now)?;
            let notices = told(TrustedContactFire {
                notified: 0,
                asked: 1,
            });
            inform_inboxes_in_txn(self, wtxn, &relation, asked, &notices, now)?;
            fire.asked += 1;
        }
        Ok(fire)
    }
}
