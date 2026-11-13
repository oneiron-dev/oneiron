//! The claims-read door the send gate asks (ARCH-0057 §3, cutover steps 3
//! and 4): in the gate's own transaction, the registry's enforced claim
//! classes, the live heads of those classes that hold one send, and the
//! owner's matching override head.
//!
//! A sanctioned read through ordinary store reads, never the private
//! prechecked-claim bypass. The registry selects the classes
//! ([`crate::comm::enforced_claim_classes_in_txn`]): the compiled
//! `comm.opt_out` and `comm.do_not_contact` rows, and any class an owner
//! stamped. The build knows how a head of its own classes names a send, so
//! those match through their family reads; any other class matches
//! generically, by subject and channel class.
//!
//! COUNTERPARTY_CONTACT is retired as an authority, not kept as a second one:
//! the contact family's own `counterparty_contact.opt_out` head is not a
//! source here. Every writer of it writes the party's `comm.opt_out` twin in
//! the same transaction (`Vault::opt_out_counterparty_contact`). The contacts
//! the send reaches are still read, rebuilt from their live
//! `counterparty_contact.*` heads, for the claim-backed `first_touch` and for
//! the owner's revocation, which is no opt-out and which no override lifts.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyContactStatus, normalize_channel_class,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::write_envelope::communication::{CommError, CommResult, SendOverrideMatch};

/// Receipt reason for a hold whose source is a `comm.do_not_contact` head.
pub(crate) const COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON: &str =
    "counterparty_opt_out_do_not_contact";

/// Receipt reason for a hold whose source is an owner-revoked contact.
pub(crate) const COUNTERPARTY_CONTACT_REVOKED_RECEIPT_REASON: &str = "counterparty_contact_revoked";

/// Receipt reason for a hold whose source is a head of an owner-stamped
/// class the build has no family read for.
pub(crate) const COUNTERPARTY_ENFORCEMENT_HOLD_RECEIPT_REASON: &str =
    "counterparty_enforcement_hold";

/// The value field a generically matched head names its channel class in.
const CHANNEL_CLASS_FIELD: &str = "channel_class";

/// One send, as the door matches heads against it.
pub(crate) struct SendTarget<'a> {
    /// The counterparty key the send names.
    pub(crate) party_ref: &'a str,
    /// The send's channel class, normalized.
    pub(crate) channel_class: &'a str,
    /// The effect's verb; a do-not-contact head may be scoped to one.
    pub(crate) verb: &'a str,
}

/// One class whose live heads hold the send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnforcementHead {
    /// The receipt reason the hold carries.
    pub(crate) receipt_reason: &'static str,
    /// Whether an owner override or the opt-out posture answers the hold.
    /// An owner-revoked contact is no opt-out, so neither lifts it.
    pub(crate) overridable: bool,
}

/// What the door answers for one send.
pub(crate) struct SendEnforcement {
    /// The contacts the send reaches, each rebuilt from its live
    /// `counterparty_contact.*` heads, in id order.
    pub(crate) contacts: Vec<CounterpartyContactRecord>,
    /// One entry per class that holds the send: the owner's revocation, then
    /// `comm.do_not_contact`, then `comm.opt_out`, then every other enforced
    /// class in predicate order.
    pub(crate) heads: Vec<EnforcementHead>,
}

impl SendEnforcement {
    /// Whether a head no override lifts holds the send.
    pub(crate) fn revoked(&self) -> bool {
        self.heads.iter().any(|head| !head.overridable)
    }
}

/// The registry-selected enforcement heads that hold `send`, read on the
/// caller's transaction.
///
/// # Errors
/// A store read failure, an undecodable claim body, or an undecodable comm
/// head: an unreadable source is not an answer of "nothing holds".
pub(crate) fn enforcement_heads_for_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    send: &SendTarget<'_>,
) -> Result<SendEnforcement> {
    let contacts = crate::counterparty_contact::counterparty_contacts_for_send_in_claims_in_txn(
        store,
        txn,
        send.party_ref,
        send.channel_class,
    )?;
    let mut heads = Vec::new();
    // An active sibling contact never clears a revoked one.
    if contacts
        .iter()
        .any(|record| record.status == CounterpartyContactStatus::Revoked)
    {
        heads.push(EnforcementHead {
            receipt_reason: COUNTERPARTY_CONTACT_REVOKED_RECEIPT_REASON,
            overridable: false,
        });
    }

    // Every PERSON that carries the counterparty's key, read once for every
    // class: the node-local party shortcut would fail open.
    let persons = store
        .record_hooks
        .do_not_contact_subjects_in_txn(store, txn, send.party_ref)?;
    let mut generic = Vec::new();
    for class in crate::comm::enforced_claim_classes_in_txn(store, txn)? {
        // A class that is not restrictive (the owner's `comm.send_override`)
        // answers a hold; it never makes one.
        if !class.restrictive {
            continue;
        }
        let predicate = class.predicate;
        if predicate == crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT {
            if store.record_hooks.subjects_do_not_contact_in_txn(
                store,
                txn,
                &persons,
                Some(send.channel_class),
                send.verb,
            )? {
                heads.push(EnforcementHead {
                    receipt_reason: COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON,
                    overridable: true,
                });
            }
        } else if predicate == crate::comm::PREDICATE_COMM_OPT_OUT {
            // A STOP's channel-scoped head, a party-wide head, or a STOP
            // this replica has not projected yet.
            if let Some(receipt_reason) = comm_result(store.record_hooks.send_stop_reason_in_txn(
                store,
                txn,
                &persons,
                send.party_ref,
                send.channel_class,
            ))? {
                heads.push(EnforcementHead {
                    receipt_reason,
                    overridable: true,
                });
            }
        } else {
            generic.push(predicate);
        }
    }
    if !generic.is_empty() {
        let subjects = party_subjects_in_txn(store, txn, &persons)?;
        for predicate in generic {
            if generic_class_holds_in_txn(store, txn, &predicate, &subjects, send.channel_class)? {
                heads.push(EnforcementHead {
                    receipt_reason: COUNTERPARTY_ENFORCEMENT_HOLD_RECEIPT_REASON,
                    overridable: true,
                });
            }
        }
    }
    Ok(SendEnforcement { contacts, heads })
}

/// The owner's `comm.send_override` head for this send, read on the caller's
/// transaction: the override heads the door pairs with an opt-out hold.
///
/// Expiry is measured on the engine's trusted clock, never a caller timestamp:
/// a one-shot override is expiry-bound at mint, and letting the requester
/// supply "now" would hand them the lifetime too. A comm-side failure is
/// propagated, never swallowed: an unreadable override head means the send
/// holds, exactly like no override at all, and never becomes a silent allow.
/// `now` is the caller's recording time; `None` samples the store clock here,
/// as a writer's judgment does. A read-only preflight passes its own peeked
/// time so that nothing moves the clock floor (FIX 22102).
pub(crate) fn send_override_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    send_ref: Option<&str>,
    now: Option<u64>,
) -> Result<Option<SendOverrideMatch>> {
    let Some(party) = comm_result(
        store
            .record_hooks
            .resolve_party_ref_from_store_in_txn(store, txn, party_ref),
    )?
    else {
        return Ok(None);
    };
    comm_result(store.record_hooks.send_override_for_send_in_txn(
        store,
        txn,
        &party,
        channel_class,
        send_ref,
        now.unwrap_or_else(|| store.clock.now_recorded_at()),
    ))
}

/// The subjects a generically matched head may sit on: every PERSON that
/// carries the send's key and the redirect shells merged into them, the
/// subjects a party's opt-out heads are read on.
fn party_subjects_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    persons: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let persons: BTreeSet<EntityId> = persons.iter().copied().collect();
    let mut subjects =
        crate::identity_redirect::inbound_redirect_shells_in_txn(store, txn, &persons)?;
    subjects.extend(persons);
    Ok(subjects)
}

/// Whether a live head of `predicate` sits on one of `subjects` and covers
/// `channel_class`. Read through the predicate's posting list, so the walk
/// is the class's own claims, not every claim of every subject. A head is
/// live while its lifecycle is Active, at any approval state, as a
/// do-not-contact head is.
fn generic_class_holds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
) -> Result<bool> {
    if subjects.is_empty() {
        return Ok(false);
    }
    for claim_id in crate::claim::claim_ids_for_predicate_in_txn(store, txn, predicate)? {
        let Some(raw) = store.port_entity_record(txn, &claim_id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw.body, true)?;
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let ClaimSubject::Entity(subject) = body.subject else {
            continue;
        };
        if subjects.contains(&subject) && head_covers_channel_class(&body.value, channel_class) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a generically matched head's value covers the send's class. A
/// value that names no class as a string (no `channel_class` field, an empty
/// one, or one of another type) covers every class: a reader who cannot prove
/// a restriction irrelevant treats it as relevant, as the contact class rule
/// does.
fn head_covers_channel_class(value: &Value, channel_class: &str) -> bool {
    let Value::Map(entries) = value else {
        return true;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(CHANNEL_CLASS_FIELD))
        .and_then(|(_, named)| named.as_str())
        .map(normalize_channel_class)
        .is_none_or(|named| named.is_empty() || named == channel_class)
}

/// Lowers a comm-family read failure into the gate's error type. An engine
/// error travels unchanged; a comm-shaped one (an undecodable head) becomes a
/// corrupted-index refusal rather than an answer.
fn comm_result<T>(result: CommResult<T>) -> Result<T> {
    result.map_err(|error| match error {
        CommError::Engine(error) => error,
        _ => Error::CorruptedIndex("comm send override head"),
    })
}
