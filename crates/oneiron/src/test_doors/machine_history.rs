//! A door for `tests/world_access_local_authority.rs`: a MACHINE claim that a
//! peer device of the same vault wrote, with the owner-signed machine history
//! its write mints (REVIEW-7793 round 2).
//!
//! The peer's write door stages the signed birth and the genesis handoff its
//! host root signs. Replayed on another node of the vault, they advance the
//! target's pin and build or heal the target's live row from the verified
//! history (FIX 3821, FIX 11926). Only a real write mints such a chain, and
//! its control rows are listed through a crate-private index.

use ed25519_dalek::{Signer as _, SigningKey};
use rmpv::Value;

use crate::authority::HostSlipIssuer;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::{
    ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
};
use crate::{EntityId, TimeRange, Vault};

/// The predicate of the peer's MACHINE claim: an ordinary one.
pub const PEER_MACHINE_CLAIM_PREDICATE: &str = "test.machine.signature";

/// What a peer device sends another node of its vault for one MACHINE claim.
pub struct PeerMachineHistory {
    /// The peer's signed authority history. The receiving node imports it
    /// first, so both nodes fold the same vault and the same owner root.
    pub authority_history: Vec<Vec<u8>>,
    /// The MACHINE entity that wrote the claim.
    pub machine: EntityId,
    /// The history's control rows as (id, raw row): the birth first, the
    /// handoff last.
    pub controls: Vec<(EntityId, Vec<u8>)>,
}

/// Roots `origin` under a host root of its own, enrols a MACHINE identity on
/// it, and writes as that MACHINE an ordinary claim at `target`.
///
/// # Errors
///
/// The root, enrolment or write refusal, and a control row the index names
/// that `origin` does not hold.
pub fn peer_machine_history(origin: &Vault, target: EntityId) -> Result<PeerMachineHistory> {
    let now = origin.store.clock.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let machine = EntityId::now();
    origin.put_entity(
        &machine,
        crate::registry::ENTITY_TYPE_MACHINE,
        at,
        now,
        b"machine",
    )?;
    let issuer = HostSlipIssuer::from_secret(b"peer machine host root")?;
    let _root = origin.ensure_host_root_slip(&issuer)?;
    let signing = SigningKey::from_bytes(&[226; 32]);
    origin.enroll_machine_identity(
        &issuer,
        machine,
        signing.verifying_key().to_bytes(),
        [17; 32],
        |transcript| Ok(signing.sign(transcript).to_bytes()),
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine output"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        PEER_MACHINE_CLAIM_PREDICATE,
        ClaimSubject::Entity(machine),
        Value::from("fact"),
        1.0,
    );
    let transcript = origin.machine_claim_transcript(&target, &candidate, &envelope)?;
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    origin
        .batch()
        .claim_candidate(&target, candidate, &signed, at, now)
        .commit()?;

    let txn = origin.store.env.read_txn()?;
    let mut ranked = Vec::new();
    for id in
        crate::claim::history_store::machine_history_ids_for_target(&origin.store, &txn, target)?
    {
        let raw = origin.get_raw_in(&txn, &id)?.ok_or(Error::EntityNotFound)?;
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let rank = match body.predicate.as_str() {
            "machine.birth" => 0,
            "machine.transition" => 1,
            _ => 2,
        };
        ranked.push((rank, id, raw));
    }
    drop(txn);
    ranked.sort_by_key(|(rank, id, _)| (*rank, *id));
    Ok(PeerMachineHistory {
        authority_history: origin.export_signed_authority_history()?,
        machine,
        controls: ranked.into_iter().map(|(_, id, raw)| (id, raw)).collect(),
    })
}
