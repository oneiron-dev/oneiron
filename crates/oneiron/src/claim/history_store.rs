//! Scoped, engine-owned CLAIM carriers for immutable MACHINE birth and transition evidence.
//!
//! The caller-chosen live claim id remains a projection. Its signed history
//! lives under content-derived ids in this reserved claim family, so replacing
//! a Loro entities-map value cannot rewrite or hide a previously seen event.

use rand_core::RngCore;
use rmpv::Value;

use super::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, TimeRange};

pub(crate) const MACHINE_BIRTH_PREDICATE: &str = "machine.birth";
pub(crate) const MACHINE_TRANSITION_PREDICATE: &str = "machine.transition";
pub(crate) const MACHINE_HANDOFF_PREDICATE: &str = "machine.handoff";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachineHistoryKind {
    Birth,
    Transition,
    Handoff,
}

pub(crate) fn machine_history_kind(predicate: &str) -> Option<MachineHistoryKind> {
    match predicate {
        MACHINE_BIRTH_PREDICATE => Some(MachineHistoryKind::Birth),
        MACHINE_TRANSITION_PREDICATE => Some(MachineHistoryKind::Transition),
        MACHINE_HANDOFF_PREDICATE => Some(MachineHistoryKind::Handoff),
        _ => None,
    }
}

/// Copy only the birth's audience/placement axes. Its validity and current
/// lifecycle must not hide audit/history once the projected claim is closed.
pub(crate) fn machine_history_claim(
    kind: MachineHistoryKind,
    target: EntityId,
    birth: &ClaimBody,
    signed_bytes: Vec<u8>,
) -> ClaimBody {
    let predicate = match kind {
        MachineHistoryKind::Birth => MACHINE_BIRTH_PREDICATE,
        MachineHistoryKind::Transition => MACHINE_TRANSITION_PREDICATE,
        MachineHistoryKind::Handoff => MACHINE_HANDOFF_PREDICATE,
    };
    let mut record = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(target),
        Value::Binary(signed_bytes),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    record.source = Some(ClaimSource::Observed);
    record.scope = birth.scope.clone();
    record.world = birth.world;
    record.rel = birth.rel;
    record.scope_facet = birth.scope_facet;
    record.scope_project = birth.scope_project;
    record
}

/// Control records cannot get a second lifecycle of their own. Semantic
/// projection happens on the target claim through the verified history.
pub(crate) fn machine_history_shape_matches(
    record: &ClaimBody,
    kind: MachineHistoryKind,
    target: EntityId,
    birth: &ClaimBody,
) -> bool {
    let signed = match &record.value {
        Value::Binary(bytes) => bytes.clone(),
        _ => return false,
    };
    let expected = machine_history_claim(kind, target, birth, signed);
    record == &expected
}

pub(crate) fn machine_history_scope_bytes(body: &ClaimBody) -> Result<Vec<u8>> {
    let value = Value::Array(vec![
        body.world
            .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        Value::Binary(body.scope_facet.as_bytes().to_vec()),
        Value::Binary(body.scope_project.as_bytes().to_vec()),
        body.rel
            .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        body.scope.clone().unwrap_or(Value::Nil),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| invalid_history())?;
    Ok(out)
}

fn invalid_history() -> Error {
    Error::InvalidClaimBody("invalid machine claim history record")
}

fn history_pending(replicated: bool) -> Error {
    if replicated {
        Error::Claim(crate::error::ClaimError::RemoteMachineHistoryPending)
    } else {
        Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete)
    }
}

/// A fresh peer may receive origin bytes after an authenticated handoff pin
/// but before its birth/event controls. Permit only the EXACT signed birth
/// named by that pin as provisional raw data; no read authorization follows.
fn pending_pin_names_signed_birth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    let packet = super::history_projection::trusted_machine_handoff(store, txn, *id)?;
    if packet.births.len() != 1 || packet.births[0].id != *id {
        return Ok(false);
    }
    let Some(Value::Map(entries)) = &body.evidence else {
        return Ok(false);
    };
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("machine_signature"));
    let Some((_, Value::Array(parts))) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Ok(false);
    }
    let [Value::Binary(key), Value::Binary(signature)] = parts.as_slice() else {
        return Ok(false);
    };
    let (Ok(key), Ok(signature)) = (key.as_slice().try_into(), signature.as_slice().try_into())
    else {
        return Ok(false);
    };
    let Ok(birth) = super::SignedClaimBirth::new(
        packet.vault_id,
        *id,
        crate::claim::encode_claim_body(body)?,
        key,
        signature,
    ) else {
        return Ok(false);
    };
    Ok(birth.digest == packet.births[0].digest)
}

/// Structural/origin door for the immutable scoped birth. No current roster
/// test belongs here: its authority may arrive after the signed origin.
pub(crate) struct MachineHistoryPut<'a> {
    pub(crate) id: &'a EntityId,
    pub(crate) entity_type: u8,
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
    pub(crate) data: &'a [u8],
    pub(crate) body: Option<&'a ClaimBody>,
    pub(crate) replicated: bool,
    pub(crate) posture: crate::HostingPrivacyPosture,
}

pub(crate) fn validate_machine_history_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    put: MachineHistoryPut<'_>,
) -> Result<()> {
    let MachineHistoryPut {
        id,
        entity_type,
        occurred,
        learned_at,
        data,
        body,
        replicated,
        posture,
    } = put;
    // Only the authenticated pin grants standing. An unpinned peer control
    // row is an untrusted hint and cannot veto a new local signed birth.
    if store
        .vault_meta
        .get(txn, &super::history_projection::pin_key(*id))?
        .is_some()
    {
        if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(Error::Claim(
                crate::error::ClaimError::InvalidMachineClaimProof,
            ));
        }
        let Some(incoming) = body else {
            return Err(invalid_history());
        };
        let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
        match super::history_projection::resolved_machine_history(store, txn, &fold, *id) {
            Ok(projection)
                if incoming == &super::history_projection::project_machine_claim(&projection) => {}
            Ok(_) => {
                return Err(Error::Claim(
                    crate::error::ClaimError::InvalidMachineClaimProof,
                ));
            }
            Err(Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete))
                if replicated && pending_pin_names_signed_birth(store, txn, id, incoming)? => {}
            Err(Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete)) => {
                return Err(history_pending(replicated));
            }
            Err(other) => return Err(other),
        }
    }
    let prior = store.entities.get(txn, id.as_bytes())?;
    let is_control = body.is_some_and(|body| machine_history_kind(&body.predicate).is_some());
    if let Some(raw) = &prior {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("machine history header"))?;
        let was_control = header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
                .is_ok_and(|body| machine_history_kind(&body.predicate).is_some());
        if (was_control || is_control)
            && (entity_type != header.entity_type
                || header.occurred_start != occurred.start
                || header.occurred_end != occurred.end
                || header.learned_at != learned_at
                || &raw[ENTITY_METADATA_HEADER_LEN..] != data)
        {
            return Err(invalid_history());
        }
    }
    let Some(body) = body else { return Ok(()) };
    match machine_history_kind(&body.predicate) {
        Some(MachineHistoryKind::Birth) => {
            let Value::Binary(bytes) = &body.value else {
                return Err(invalid_history());
            };
            let birth = super::SignedClaimBirth::decode(bytes).map_err(|_| invalid_history())?;
            if birth.event_id().map_err(|_| invalid_history())? != *id {
                return Err(invalid_history());
            }
            let original = crate::claim::decode_claim_body(&birth.initial_body, true)
                .map_err(|_| invalid_history())?;
            if !machine_history_shape_matches(
                body,
                MachineHistoryKind::Birth,
                birth.target,
                &original,
            ) {
                return Err(invalid_history());
            }
        }
        Some(MachineHistoryKind::Transition) => {
            let Value::Binary(bytes) = &body.value else {
                return Err(invalid_history());
            };
            let event = super::transition::decode_machine_claim_transition_event(bytes)
                .map_err(|_| invalid_history())?;
            super::transition::verify_machine_claim_transition_event(&event)
                .map_err(|_| invalid_history())?;
            if super::transition::machine_claim_transition_event_id(&event)
                .map_err(|_| invalid_history())?
                != *id
                || body.subject != ClaimSubject::Entity(event.target)
            {
                return Err(invalid_history());
            }
            let birth = birth_by_digest(store, txn, &event.birth_digest)?
                .ok_or_else(|| history_pending(replicated))?;
            if birth.vault_id != event.vault_id
                || birth.target != event.target
                || !machine_history_shape_matches(
                    body,
                    MachineHistoryKind::Transition,
                    event.target,
                    &crate::claim::decode_claim_body(&birth.initial_body, true)?,
                )
            {
                return Err(invalid_history());
            }
        }
        Some(MachineHistoryKind::Handoff) => {
            let Value::Binary(bytes) = &body.value else {
                return Err(invalid_history());
            };
            let packet =
                super::ClaimHistoryHandoff::decode(bytes).map_err(|_| invalid_history())?;
            let signature = crate::authority::AuthoritySignature {
                suite: packet.signer.suite(),
                public_key: packet.signer.clone(),
                signature: packet.signature.to_vec(),
            };
            if !crate::authority::verify_authority_signature(
                &signature,
                &packet.transcript().map_err(|_| invalid_history())?,
            ) {
                return Err(invalid_history());
            }
            let digest = packet.content_hash().map_err(|_| invalid_history())?;
            let expected =
                EntityId::from_bytes(digest[..16].try_into().map_err(|_| invalid_history())?)
                    .map_err(|_| invalid_history())?;
            if expected != *id
                || packet.births.len() != 1
                || body.subject != ClaimSubject::Entity(packet.births[0].id)
            {
                return Err(invalid_history());
            }
            let birth = birth_by_digest(store, txn, &packet.births[0].digest)?
                .ok_or_else(|| history_pending(replicated))?;
            let original = crate::claim::decode_claim_body(&birth.initial_body, true)?;
            if packet.births[0].id != birth.target
                || packet.vault_id != birth.vault_id
                || packet.scope != machine_history_scope_bytes(&original)?
                || !machine_history_shape_matches(
                    body,
                    MachineHistoryKind::Handoff,
                    birth.target,
                    &original,
                )
            {
                return Err(invalid_history());
            }
        }
        None => {}
    }
    Ok(())
}

pub(crate) fn birth_by_digest(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Option<super::SignedClaimBirth>> {
    let id = EntityId::from_bytes(digest[..16].try_into().map_err(|_| invalid_history())?)
        .map_err(|_| invalid_history())?;
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("machine birth header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(invalid_history());
    }
    let row = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if row.predicate != MACHINE_BIRTH_PREDICATE {
        return Err(invalid_history());
    }
    let Value::Binary(bytes) = row.value else {
        return Err(invalid_history());
    };
    let birth = super::SignedClaimBirth::decode(&bytes).map_err(|_| invalid_history())?;
    if birth.digest != *digest || birth.event_id().map_err(|_| invalid_history())? != id {
        return Err(invalid_history());
    }
    Ok(Some(birth))
}

pub(crate) fn reject_machine_history_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if store
        .vault_meta
        .get(txn, &super::history_projection::pin_key(*id))?
        .is_some()
    {
        // An owner erasure must retire the authenticated pin and coverage by
        // a dedicated signed deletion action, not a generic LWW tombstone.
        return Err(invalid_history());
    }
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && EntityMetadataHeader::parse(&raw)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            .is_ok_and(|body| machine_history_kind(&body.predicate).is_some())
    {
        return Err(invalid_history());
    }
    Ok(())
}

const TARGET_INDEX: &[u8] = b"claim:machine-history-target:v1:";

fn target_prefix(target: EntityId) -> Vec<u8> {
    [TARGET_INDEX, target.as_bytes()].concat()
}

/// Add one verified immutable control id to a target-local index. The index
/// is a navigation hint only; every fetched row is revalidated on read/fold.
pub(crate) fn maintain_machine_history_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    if machine_history_kind(&body.predicate).is_none() {
        return Ok(());
    }
    let ClaimSubject::Entity(target) = body.subject else {
        return Err(invalid_history());
    };
    let mut key = target_prefix(target);
    key.extend_from_slice(id.as_bytes());
    store.vault_meta.put(txn, &key, &[])?;
    Ok(())
}

pub(crate) fn machine_history_ids_for_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Vec<EntityId>> {
    let prefix = target_prefix(target);
    let mut ids = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let bytes: [u8; 16] = key[prefix.len()..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("machine history target index"))?;
        ids.push(EntityId::from_bytes(bytes)?);
        if ids.len() > 8192 {
            return Err(Error::IndexOverflow("machine claim history"));
        }
    }
    Ok(ids)
}

/// Stage the immutable birth and the first host-authenticated complete
/// history handoff in the same LMDB writer as the signed candidate. A retry
/// may only replay the IDENTICAL birth. The stored pin is local host trust;
/// a fresh peer must receive its own challenge-bound pin at pairing.
#[expect(
    clippy::too_many_arguments,
    reason = "birth, handoff and candidate share one LMDB writer and materialization context"
)]
pub(crate) fn stage_machine_birth_after_candidate(
    store: &Store,
    config: &crate::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    body: &ClaimBody,
    envelope: &crate::WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
    text_index_trusted: bool,
    had_prior: bool,
) -> Result<()> {
    let Some(proof) = envelope.machine_signature() else {
        return Ok(());
    };
    let signed_body = crate::claim::encode_claim_body(body)?;
    let signer_guard = store
        .machine_history_issuer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let issuer = signer_guard.as_ref().ok_or_else(invalid_history)?;
    let (vault_id, authority_head) = crate::authority::machine_history_host_context(
        store,
        config.privacy.posture,
        txn,
        &issuer.public_key(),
    )?;
    let birth = super::SignedClaimBirth::new(
        vault_id,
        target,
        signed_body,
        proof.public_key,
        proof.signature,
    )
    .map_err(|_| invalid_history())?;
    if store
        .vault_meta
        .get(txn, &super::history_projection::pin_key(target))?
        .is_some()
    {
        let existing = super::history_projection::machine_history_rows(store, txn, target)?;
        if existing.birth != birth {
            return Err(invalid_history());
        }
        return Ok(());
    }
    if had_prior {
        // A re-put cannot mint a new signed birth over prior mutable content.
        return Err(invalid_history());
    }
    // The target index is not authority: a peer may have planted an unpinned
    // self-signed birth control first. Do not let it veto local enrollment.
    // The newly signed birth is admitted only under this host's trusted pin.
    let birth_id = birth.event_id().map_err(|_| invalid_history())?;
    let birth_record = machine_history_claim(
        MachineHistoryKind::Birth,
        target,
        body,
        birth.encode().map_err(|_| invalid_history())?,
    );
    let mut nonce = [0; 32];
    let mut challenge = [0; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    rand_core::OsRng.fill_bytes(&mut challenge);
    let mut packet = super::ClaimHistoryHandoff {
        vault_id,
        genesis_hash: vault_id,
        scope: machine_history_scope_bytes(body)?,
        births: vec![super::ClaimBirth {
            id: target,
            digest: birth.digest,
        }],
        transitions: Vec::new(),
        heads: vec![birth.digest],
        authority_head,
        previous_handoff_hash: None,
        nonce,
        challenge,
        signer: issuer.public_key(),
        signature: [0; 64],
    };
    packet.signature =
        issuer.sign_claim_handoff(&packet.transcript().map_err(|_| invalid_history())?);
    let packet_bytes = packet.encode().map_err(|_| invalid_history())?;
    let handoff_hash = packet.content_hash().map_err(|_| invalid_history())?;
    let handoff_id = EntityId::from_bytes(
        handoff_hash[..16]
            .try_into()
            .map_err(|_| invalid_history())?,
    )
    .map_err(|_| invalid_history())?;
    let handoff_record = machine_history_claim(
        MachineHistoryKind::Handoff,
        target,
        body,
        packet_bytes.clone(),
    );
    let at = occurred;
    let mut ops = Vec::new();
    for (id, control) in [(birth_id, birth_record), (handoff_id, handoff_record)] {
        ops.push(crate::batch::BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: at,
            learned_at,
            data: crate::claim::encode_claim_body(&control)?,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        });
        ops.push(crate::batch::BatchOp::Edge {
            src: id,
            kind: crate::edge::EdgeKind::FacetOf,
            tgt: body.scope_facet,
            weight: 1.0,
            vad: crate::affect::Vad::NEUTRAL,
        });
    }
    // Same txn, no second writer. A failure rolls back both controls and the
    // staged candidate, including their projection indexes.
    crate::batch::apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        txn,
        ops,
        text_index_trusted,
        crate::batch::ApplyOpsGateMode::new(false, false),
    )?;
    let local_pin = super::ClaimHistoryHandoffPin {
        vault_id: &vault_id,
        genesis_hash: &vault_id,
        expected_signer: &packet.signer,
        scope: &packet.scope,
        previous_handoff_hash: None,
        challenge: &packet.challenge,
    };
    if !matches!(
        super::verify_claim_history_handoff(&packet, &local_pin, |_| {
            super::HandoffStanding::OwnerAndComplete
        }),
        super::HandoffVerification::Verified(_)
    ) {
        return Err(invalid_history());
    }
    store.vault_meta.put(
        txn,
        &super::history_projection::pin_key(target),
        &packet_bytes,
    )?;
    Ok(())
}
