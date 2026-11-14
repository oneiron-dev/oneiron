//! `residence.authority_overlay.offer` and `.keys` (census L5-22 1a-iii
//! commit 7): this node as the home through which the owner's machines
//! carry the authority overlay's erasable keys
//! (`crate::sync::authority_overlay_custody`).
//!
//! Only a machine of the owner's that proved itself on its socket is heard:
//! a machine the current fold trusts, under the proof key it proved. An
//! offer names the machine's inventory page and a session for the keys this
//! node sends it; the answer names this node's erased subjects, its keys the
//! machine lacks (sealed to that session), the keys it wants and a session
//! for them; `.keys` installs those. Key refs, subjects and seals only: no
//! key leaves these doors unsealed, and no seal is stored.
//!
//! The machine's half of the round is public here too
//! ([`offer_overlay_page`], [`apply_overlay_answer`]): a client runs it over
//! its own socket to the home.
//!
//! The wire spells refs, nonces and digests in lower-case hex
//! ([`overlay_wire_hex`]); the server reads and writes each call's
//! parameters, and the doors own every check and write.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::Result;
pub use crate::sync::authority_overlay_custody::{
    ErasedSubject, OVERLAY_PAGE_SUBJECTS, OverlayAnswer, OverlayKeySession, OverlayOffer,
    OverlayPageSession, OverlaySentKey, apply_overlay_answer, offer_overlay_page,
};
use crate::sync::authority_overlay_custody::{answer_offer, receive_keys};

use super::bundle::denied;

/// `bytes` in lower-case hex, as the overlay carrier's wire spells a ref, a
/// nonce, a digest or a subject's 16 bytes.
#[must_use]
pub fn overlay_wire_hex(bytes: &[u8]) -> String {
    super::bundle::hex(bytes)
}

/// `N` bytes the overlay carrier's wire spells in lower-case hex, and
/// nothing else.
#[must_use]
pub fn overlay_wire_from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    super::bundle::unhex(text)
}

/// Admits a machine of the owner's, as its socket proved it, and names it
/// and this node's own machine.
fn machine_and_home(vault: &Vault, peer: PeerMachine) -> Result<(EntityId, EntityId)> {
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    let machine = fold
        .trusted_machine(machine)
        .filter(|_| fold.machine_proof_key(machine) == Some(key))
        .map(|_| machine)
        .ok_or_else(denied)?;
    let home = crate::identity::read_machine_id_in_txn(vault, &txn)?.ok_or_else(denied)?;
    Ok((machine, home))
}

/// One page of the calling machine's overlay key round (census L5-22 1a-iii
/// commit 7): retires the subjects it erased, then answers this node's
/// erased subjects, its keys the machine lacks sealed to the machine's
/// session, the machine's keys it wants, and a session for them.
///
/// # Errors
///
/// A refused peer, or an install with no machine; a vault with no
/// authority genesis; a session key that does not import; storage, custody
/// and key-event faults.
pub fn authority_overlay_offer(
    vault: &Vault,
    peer: PeerMachine,
    offer: &OverlayOffer,
) -> Result<OverlayAnswer> {
    let (machine, home) = machine_and_home(vault, peer)?;
    answer_offer(vault, &home, &machine, offer)
}

/// Installs `keys`, the calling machine's keys this node wanted, sealed to
/// the session its last answer offered that machine, and closes that
/// session. Returns how many it installed; one that does not open or
/// install (an erased subject's among them) is not counted.
///
/// # Errors
///
/// A refused peer, or an install with no machine; no session open here for
/// that machine; storage errors.
pub fn authority_overlay_keys(
    vault: &Vault,
    peer: PeerMachine,
    keys: Vec<OverlaySentKey>,
) -> Result<u32> {
    let (machine, home) = machine_and_home(vault, peer)?;
    receive_keys(vault, &home, &machine, keys)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlayKeyRef {
    subject: String,
    key: String,
}

impl WireOverlayKeyRef {
    /// The subject and ref this wire entry names, if both parse.
    fn decode(self) -> Option<(EntityId, [u8; 32])> {
        Some((
            EntityId::from_hex(&self.subject).ok()?,
            overlay_wire_from_hex::<32>(&self.key)?,
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlayErased {
    subject: String,
    keys: Vec<String>,
    destroyed: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlaySession {
    ephemeral: String,
    nonce: String,
}

impl WireOverlaySession {
    /// The public session this wire entry names, if both fields decode.
    fn decode(self) -> Option<OverlayKeySession> {
        Some(OverlayKeySession {
            ephemeral: base64::engine::general_purpose::STANDARD
                .decode(&self.ephemeral)
                .ok()?,
            nonce: overlay_wire_from_hex::<32>(&self.nonce)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlaySentKey {
    subject: String,
    key: String,
    sealed: String,
}

impl WireOverlaySentKey {
    /// The carried key this wire entry names, if every field decodes.
    fn decode(self) -> Option<OverlaySentKey> {
        Some(OverlaySentKey {
            subject: EntityId::from_hex(&self.subject).ok()?,
            key_ref: overlay_wire_from_hex::<32>(&self.key)?,
            sealed: base64::engine::general_purpose::STANDARD
                .decode(&self.sealed)
                .ok()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlayOffer {
    digest: String,
    owed: bool,
    after: Option<String>,
    through: Option<String>,
    ready: Vec<WireOverlayKeyRef>,
    erased: Vec<WireOverlayErased>,
    session: WireOverlaySession,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlayAnswer {
    same: bool,
    through: Option<String>,
    erased: Vec<WireOverlayErased>,
    keys: Vec<WireOverlaySentKey>,
    wanted: Vec<WireOverlayKeyRef>,
    session: Option<WireOverlaySession>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOverlayKeys {
    keys: Vec<WireOverlaySentKey>,
}

/// One subject and ref in the shared wire form.
fn key_ref_to_wire(subject: &EntityId, key_ref: &[u8; 32]) -> Value {
    json!({"subject": subject.to_hex(), "key": overlay_wire_hex(key_ref)})
}

/// A public session in the shared wire form.
fn session_to_wire(session: &OverlayKeySession) -> Value {
    json!({
        "ephemeral": base64::engine::general_purpose::STANDARD.encode(&session.ephemeral),
        "nonce": overlay_wire_hex(&session.nonce),
    })
}

/// Each erased subject's known and destroyed refs in subject order.
fn erased_to_wire(erased: &BTreeMap<EntityId, ErasedSubject>) -> Vec<Value> {
    erased
        .iter()
        .map(|(subject, erased)| {
            json!({
                "subject": subject.to_hex(),
                "keys": erased.refs.iter().map(|key| overlay_wire_hex(key)).collect::<Vec<_>>(),
                "destroyed": erased.destroyed.iter().map(|key| overlay_wire_hex(key)).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// Each decoded erased subject, with repeated subjects kept once by id.
fn erased_from_wire(erased: Vec<WireOverlayErased>) -> Option<BTreeMap<EntityId, ErasedSubject>> {
    erased
        .into_iter()
        .map(|erased| {
            Some((
                EntityId::from_hex(&erased.subject).ok()?,
                ErasedSubject {
                    refs: erased
                        .keys
                        .iter()
                        .map(|key| overlay_wire_from_hex::<32>(key))
                        .collect::<Option<BTreeSet<_>>>()?,
                    destroyed: erased
                        .destroyed
                        .iter()
                        .map(|key| overlay_wire_from_hex::<32>(key))
                        .collect::<Option<BTreeSet<_>>>()?,
                },
            ))
        })
        .collect()
}

/// Each carried key's subject, ref and base64 seal, in input order.
fn sent_keys_to_wire(keys: &[OverlaySentKey]) -> Vec<Value> {
    keys.iter()
        .map(|key| {
            json!({
                "subject": key.subject.to_hex(),
                "key": overlay_wire_hex(&key.key_ref),
                "sealed": base64::engine::general_purpose::STANDARD.encode(&key.sealed),
            })
        })
        .collect()
}

/// The offer's shared residence wire form: ids and refs in hex, and its
/// session's ephemeral public key in standard base64.
#[must_use]
pub fn overlay_offer_to_wire(offer: &OverlayOffer) -> Value {
    json!({
        "digest": overlay_wire_hex(&offer.digest),
        "owed": offer.owed,
        "after": offer.after.map(|subject| subject.to_hex()),
        "through": offer.through.map(|subject| subject.to_hex()),
        "ready": offer.ready.iter().map(|(subject, key)| key_ref_to_wire(subject, key)).collect::<Vec<_>>(),
        "erased": erased_to_wire(&offer.erased),
        "session": session_to_wire(&offer.session),
    })
}

/// The offer a residence wire value names; none if a field is malformed.
/// Repeated ready keys and erased subjects collect under their own keys.
#[must_use]
pub fn overlay_offer_from_wire(value: Value) -> Option<OverlayOffer> {
    let wire: WireOverlayOffer = serde_json::from_value(value).ok()?;
    Some(OverlayOffer {
        digest: overlay_wire_from_hex::<32>(&wire.digest)?,
        owed: wire.owed,
        after: wire
            .after
            .map(|subject| EntityId::from_hex(&subject))
            .transpose()
            .ok()?,
        through: wire
            .through
            .map(|subject| EntityId::from_hex(&subject))
            .transpose()
            .ok()?,
        ready: wire
            .ready
            .into_iter()
            .map(WireOverlayKeyRef::decode)
            .collect::<Option<_>>()?,
        erased: erased_from_wire(wire.erased)?,
        session: wire.session.decode()?,
    })
}

/// The answer's shared residence wire form, with every carried key still
/// sealed and each session's ephemeral public key in standard base64.
#[must_use]
pub fn overlay_answer_to_wire(answer: &OverlayAnswer) -> Value {
    json!({
        "same": answer.same,
        "through": answer.through.map(|subject| subject.to_hex()),
        "erased": erased_to_wire(&answer.erased),
        "keys": sent_keys_to_wire(&answer.keys),
        "wanted": answer.wanted.iter().map(|(subject, key)| key_ref_to_wire(subject, key)).collect::<Vec<_>>(),
        "session": answer.session.as_ref().map(session_to_wire),
    })
}

/// The answer a residence wire value names; none if a field is malformed.
/// Repeated wanted keys and erased subjects collect under their own keys.
#[must_use]
pub fn overlay_answer_from_wire(value: Value) -> Option<OverlayAnswer> {
    let wire: WireOverlayAnswer = serde_json::from_value(value).ok()?;
    Some(OverlayAnswer {
        same: wire.same,
        through: wire
            .through
            .map(|subject| EntityId::from_hex(&subject))
            .transpose()
            .ok()?,
        erased: erased_from_wire(wire.erased)?,
        keys: wire
            .keys
            .into_iter()
            .map(WireOverlaySentKey::decode)
            .collect::<Option<_>>()?,
        wanted: wire
            .wanted
            .into_iter()
            .map(WireOverlayKeyRef::decode)
            .collect::<Option<_>>()?,
        session: match wire.session {
            Some(session) => Some(session.decode()?),
            None => None,
        },
    })
}

/// The carried keys' shared residence wire form, with seals in standard
/// base64 and no unsealed key material.
#[must_use]
pub fn overlay_keys_to_wire(keys: &[OverlaySentKey]) -> Value {
    json!({"keys": sent_keys_to_wire(keys)})
}

/// The carried keys a residence wire value names; none if a field is
/// malformed, including any subject, key ref or base64 seal.
#[must_use]
pub fn overlay_keys_from_wire(value: Value) -> Option<Vec<OverlaySentKey>> {
    let wire: WireOverlayKeys = serde_json::from_value(value).ok()?;
    wire.keys
        .into_iter()
        .map(WireOverlaySentKey::decode)
        .collect()
}
