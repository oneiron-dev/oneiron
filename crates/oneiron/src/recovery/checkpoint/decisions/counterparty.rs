//! What a send reads about its counterparty: the contacts the send gate
//! folds for a party, the do-not-contact rulings and owner overrides its
//! person reaches.
use super::{Decision, field};
use crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT;
use crate::channel_identity_provider::native_mail;
use crate::comm::{PREDICATE_COMM_SEND_OVERRIDE, SendOverrideMatch};
use crate::counterparty_contact::{normalize_channel_class, read_counterparty_contact_in_txn};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::{EntityId, Result, Vault};
use std::collections::BTreeSet;

/// How the send gate takes a send to a party on one channel class, from the
/// party's contacts, for a send with nothing else to say, and, on email, for
/// each native-mail sender as the actor it is bound to.
pub(super) struct SendContacts;

/// What the gate decides a send on from a party's contacts, and not the
/// receipt tokens that only record why.
pub(super) struct SendPosture {
    /// The hold a public first touch, or a native-mail send to a recipient
    /// the policy does not know, puts on the send.
    risk: ExternalEffectPolicyRisk,
    opted_out: bool,
    /// The owner's override of an opt-out the send matches.
    send_override: Option<SendOverrideMatch>,
    /// Whether a native-mail send is cold, and may borrow the owner's
    /// graduated grant.
    cold: bool,
    graduated: bool,
}

impl Decision for SendContacts {
    type Subject = (String, String, Option<(EntityId, EntityId)>);
    type Answer = SendPosture;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let known = Known::read(vaults)?;
        let mut subjects: BTreeSet<_> = known
            .parties_on_classes()
            .map(|(party, class)| (party, class, None))
            .collect();
        for party in &known.parties {
            for sender in &known.senders {
                subjects.insert((party.clone(), "email".to_owned(), Some(*sender)));
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let policy = vault.store.policy_as_next_opened()?;
        let txn = vault.store.env.read_txn()?;
        let store = &vault.store;
        let posture = |(party, class, sender): &Self::Subject| -> Result<SendPosture> {
            let mut effect = send(party, class, "send");
            if let Some((identity, actor)) = sender {
                effect.channel_identity_ref = Some(*identity);
                effect.actor.actor_ref = Some(actor.to_hex());
                effect.provenance.actor_entity_ref = Some(*actor);
            }
            let (effect, send_override) =
                crate::gate::hydrate_external_effect_contact(store, &txn, &effect, &policy)?;
            Ok(SendPosture {
                risk: effect.policy_risk,
                opted_out: effect.counterparty_opted_out,
                send_override,
                cold: native_mail::native_mail_cold_send_in_txn(store, &txn, &effect, &policy)?,
                graduated: native_mail::mail_graduated_in_txn(store, &txn, &effect, &policy)?,
            })
        };
        Ok(subjects
            .iter()
            .map(|subject| posture(subject).ok())
            .collect())
    }

    fn loosens(live: &SendPosture, restored: &SendPosture) -> bool {
        (live.risk == ExternalEffectPolicyRisk::HoldToProposal
            && restored.risk == ExternalEffectPolicyRisk::Normal)
            || (live.opted_out && !restored.opted_out)
            || (live.send_override.is_none() && restored.send_override.is_some())
            || (live.cold && !restored.cold)
            || (!live.graduated && restored.graduated)
    }
}

/// Whether a party's do-not-contact rulings hold an effect of one verb on one
/// channel class: the person its name resolves to, and the rulings that
/// person's `claim_of` edges reach.
pub(super) struct DoNotContact;

impl Decision for DoNotContact {
    type Subject = (String, String, String);
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let known = Known::read(vaults)?;
        let mut subjects = BTreeSet::new();
        for (party, class) in known.parties_on_classes() {
            for verb in &known.verbs {
                subjects.insert((party.clone(), class.clone(), verb.clone()));
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(party, class, verb)| {
                crate::campaign::claims::counterparty_do_not_contact_in_txn(
                    &vault.store,
                    &txn,
                    party,
                    Some(class),
                    verb,
                )
                .ok()
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        *live && !restored
    }

    fn refusal() -> Option<bool> {
        Some(true)
    }
}

/// The owner's override a send to an opted-out party matches on one channel
/// class, standing or bound to one send: the person the party resolves to,
/// and the overrides its `claim_of` edges reach.
pub(super) struct SendOverrides;

impl Decision for SendOverrides {
    type Subject = (String, String, Option<String>);
    type Answer = Option<SendOverrideMatch>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let known = Known::read(vaults)?;
        let mut subjects = BTreeSet::new();
        for (party, class) in known.parties_on_classes() {
            for send in &known.sends {
                subjects.insert((party.clone(), class.clone(), send.clone()));
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(party, class, send)| {
                crate::gate::counterparty_send_override_in_txn(
                    &vault.store,
                    &txn,
                    party,
                    class,
                    send.as_deref(),
                )
                .ok()
            })
            .collect())
    }

    fn loosens(live: &Self::Answer, restored: &Self::Answer) -> bool {
        live.is_none() && restored.is_some()
    }

    fn refusal() -> Option<Self::Answer> {
        Some(None)
    }
}

/// A send of `verb` to `party` on `class`, from no one in particular: what
/// the gate reads about the party is all that varies.
fn send(party: &str, class: &str, verb: &str) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: String::new(),
            actor_ref: None,
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles::default(),
        verb: verb.to_owned(),
        channel: class.to_owned(),
        channel_identity_ref: None,
        counterparty: Some(party.to_owned()),
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: ExternalEffectPolicyRisk::default(),
    }
}

/// What the counterparty decisions can be asked about in either vault.
struct Known {
    /// Every party a contact names, and every comm party.
    parties: BTreeSet<String>,
    /// Every channel class that tells contacts, rulings and overrides apart:
    /// each channel identity's, each one a ruling or override names, and one
    /// none names, where only a contact whose identity does not resolve
    /// applies.
    classes: BTreeSet<String>,
    /// Each native-mail sender, with the actor it is bound to.
    senders: BTreeSet<(EntityId, EntityId)>,
    /// A send, each scope a ruling names, and a verb none names.
    verbs: BTreeSet<String>,
    /// No send in particular, and each send a one-shot override is bound to.
    sends: BTreeSet<Option<String>>,
}

impl Known {
    fn read(vaults: [&Vault; 2]) -> Result<Self> {
        let mut known = Self {
            parties: BTreeSet::new(),
            classes: BTreeSet::from([String::new()]),
            senders: BTreeSet::new(),
            verbs: BTreeSet::from(["send".to_owned(), String::new()]),
            sends: BTreeSet::from([None]),
        };
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            let store = &vault.store;
            known
                .parties
                .extend(crate::comm::comm_party_keys_in_txn(store, &txn)?);
            for id in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_COUNTERPARTY_CONTACT, None)? {
                // One that does not decode fails every send closed alike.
                if let Ok(Some(contact)) = read_counterparty_contact_in_txn(store, &txn, &id?) {
                    known.parties.insert(contact.counterparty);
                }
            }
            for id in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
                let id = id?;
                let Some(raw) = store.port_entity_record(&txn, &id)? else {
                    continue;
                };
                let Ok(identity) = crate::channel_identity::decode_channel_identity_body(&raw.body)
                else {
                    continue;
                };
                known
                    .classes
                    .insert(normalize_channel_class(identity.channel()));
                if let Some(actor) = identity.binding().actor_ref()
                    && native_mail::is_native_mail_identity_in_txn(store, &txn, id)?
                {
                    known.senders.insert((id, actor));
                }
            }
            for (_, ruling) in
                vault.claims_with_predicate_in_txn(&txn, PREDICATE_COMM_DO_NOT_CONTACT)?
            {
                known
                    .classes
                    .extend(field(&ruling.value, "channel").map(normalize_channel_class));
                known
                    .verbs
                    .extend(field(&ruling.value, "scope").map(str::to_owned));
            }
            for (_, ruling) in
                vault.claims_with_predicate_in_txn(&txn, PREDICATE_COMM_SEND_OVERRIDE)?
            {
                known
                    .classes
                    .extend(field(&ruling.value, "channel_class").map(normalize_channel_class));
                known
                    .sends
                    .extend(field(&ruling.value, "send_ref").map(|send| Some(send.to_owned())));
            }
        }
        Ok(known)
    }

    /// Every party, on every class.
    fn parties_on_classes(&self) -> impl Iterator<Item = (String, String)> + '_ {
        self.parties.iter().flat_map(|party| {
            self.classes
                .iter()
                .map(move |class| (party.clone(), class.clone()))
        })
    }
}
