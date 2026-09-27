//! Verified MACHINE history residence: exact birth + transition closure at a trusted pin.
//!
//! The mutable claim row is a projection, never evidence of its own current
//! authority. Missing bytes or a pin with unproved ancestry withhold reads.

use crate::authority::{AuthorityFold, AuthorityKey, ROLE_OWNER};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::transition::{
    ClaimTransitionProjection, SignedClaimTransitionEvent, TransitionFoldError,
    decode_machine_claim_transition_event, fold_machine_claim_transitions,
    machine_claim_transition_event_hash, machine_claim_transition_event_id,
};
use crate::error::{ClaimError, Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};
use rand_core::RngCore;
use rmpv::Value;

use super::history_store::{
    MachineHistoryKind, machine_history_ids_for_target, machine_history_kind,
    machine_history_shape_matches,
};
use super::{
    ClaimBody, ClaimHistoryHandoff, ClaimHistoryHandoffPin, HandoffStanding, HandoffVerification,
    SignedClaimBirth, VerifiedClaimHistoryHandoff, verify_claim_history_handoff,
};

fn missing() -> Error {
    Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
}
fn bad() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}
pub(crate) fn pin_key(target: EntityId) -> Vec<u8> {
    [
        b"claim:machine-history-pin:v1:".as_slice(),
        target.as_bytes(),
    ]
    .concat()
}

pub(crate) struct MachineHistoryRows {
    pub(crate) birth: SignedClaimBirth,
    pub(crate) events: Vec<SignedClaimTransitionEvent>,
}

/// Verified navigation from the target-local projection index. A malformed
/// index/record refuses; absence is typed incomplete, never an empty history.
pub(crate) fn machine_history_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<MachineHistoryRows> {
    // The target index is an UNTRUSTED navigation hint. It may contain
    // additional self-signed, unbound peer events. Only IDs named by the
    // previously authenticated handoff pin can affect a claim's fold; a
    // stray event cannot permanently poison a legitimate target.
    let pin = trusted_machine_handoff(store, txn, target)?;
    if pin.births.len() != 1 || pin.births[0].id != target {
        return Err(bad());
    }
    let mut expected = std::collections::BTreeSet::new();
    for hash in
        std::iter::once(pin.births[0].digest).chain(pin.transitions.iter().map(|event| event.hash))
    {
        expected.insert(
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?,
        );
    }
    if expected.len() != pin.transitions.len() + 1 {
        return Err(bad());
    }
    let mut birth = None;
    let mut events = Vec::new();
    for id in machine_history_ids_for_target(store, txn, target)? {
        if !expected.remove(&id) {
            continue;
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("machine history index row missing"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine history header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(bad());
        }
        let row = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let Value::Binary(bytes) = &row.value else {
            return Err(bad());
        };
        match machine_history_kind(&row.predicate) {
            Some(MachineHistoryKind::Birth) => {
                let found = SignedClaimBirth::decode(bytes).map_err(|_| bad())?;
                let original = super::decode_claim_body(&found.initial_body, true)?;
                if found.target != target
                    || found.event_id().map_err(|_| bad())? != id
                    || !machine_history_shape_matches(
                        &row,
                        MachineHistoryKind::Birth,
                        target,
                        &original,
                    )
                    || birth.replace(found).is_some()
                {
                    return Err(bad());
                }
            }
            Some(MachineHistoryKind::Transition) => {
                let found = decode_machine_claim_transition_event(bytes).map_err(|_| bad())?;
                if found.target != target
                    || machine_claim_transition_event_id(&found).map_err(|_| bad())? != id
                {
                    return Err(bad());
                }
                events.push(found);
            }
            Some(MachineHistoryKind::Handoff) => {
                // A handoff is authenticated against an out-of-band pin at
                // adoption; raw peer packets carry no standing by themselves.
                let packet = ClaimHistoryHandoff::decode(bytes).map_err(|_| bad())?;
                let hash = packet.content_hash().map_err(|_| bad())?;
                if packet.births.len() != 1
                    || packet.births[0].id != target
                    || EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?)
                        .map_err(|_| bad())?
                        != id
                {
                    return Err(bad());
                }
            }
            None => return Err(bad()),
        }
    }
    if !expected.is_empty() {
        return Err(missing());
    }
    let birth = birth.ok_or_else(missing)?;
    if birth.digest != pin.births[0].digest {
        return Err(bad());
    }
    let original = super::decode_claim_body(&birth.initial_body, true)?;
    for event in &events {
        let id = machine_claim_transition_event_id(event).map_err(|_| bad())?;
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex(
                "machine transition index row missing",
            ))?;
        let row = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if event.birth_digest != birth.digest
            || event.vault_id != birth.vault_id
            || !machine_history_shape_matches(
                &row,
                MachineHistoryKind::Transition,
                target,
                &original,
            )
        {
            return Err(bad());
        }
    }
    Ok(MachineHistoryRows { birth, events })
}

/// Require an exact signed predecessor chain for all archived handoff pins.
/// The present pin may advance only from an authenticated previously accepted
/// closure; a peer cannot splice an older/re-rooted packet into a new head.
pub(crate) fn verified_handoff_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    tip: &ClaimHistoryHandoff,
    fold: &AuthorityFold,
) -> Result<Vec<ClaimHistoryHandoff>> {
    let mut current = tip.clone();
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let hash = current.content_hash().map_err(|_| bad())?;
        if !seen.insert(hash) || chain.len() > 1024 {
            return Err(Error::InvalidClaimBody("handoff-chain loop"));
        }
        if current.vault_id != fold.vault_id.ok_or_else(missing)? {
            return Err(Error::InvalidClaimBody("handoff-chain vault mismatch"));
        }
        if !fold.valid_entries.contains(&current.authority_head)
            && !crate::authority::machine_history_authority_descends(
                store,
                txn,
                &current.authority_head,
                &tip.authority_head,
            )?
        {
            return Err(Error::InvalidClaimBody(
                if hash == tip.content_hash().map_err(|_| bad())? {
                    "handoff-chain tip authority head missing"
                } else {
                    "handoff-chain prior authority head missing"
                },
            ));
        }
        if current.births != tip.births {
            return Err(Error::InvalidClaimBody("handoff-chain birth mismatch"));
        }
        if current.scope != tip.scope {
            return Err(Error::InvalidClaimBody("handoff-chain scope mismatch"));
        }
        if !verify_handoff_signature(&current) {
            return Err(Error::InvalidClaimBody("handoff-chain signature mismatch"));
        }
        let parent = current.previous_handoff_hash;
        chain.push(current);
        let Some(parent) = parent else { break };
        let id =
            EntityId::from_bytes(parent[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or_else(missing)?;
        let h = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine handoff header"))?;
        if h.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("handoff-chain wrong type"));
        }
        let row = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if row.predicate != super::history_store::MACHINE_HANDOFF_PREDICATE {
            return Err(Error::InvalidClaimBody("handoff-chain wrong predicate"));
        }
        let Value::Binary(bytes) = row.value else {
            return Err(bad());
        };
        current = ClaimHistoryHandoff::decode(&bytes).map_err(|_| bad())?;
        if current.content_hash().map_err(|_| bad())? != parent {
            return Err(Error::InvalidClaimBody("handoff-chain bad parent hash"));
        }
    }
    chain.reverse();
    for pair in chain.windows(2) {
        if pair[1].transitions.len() < pair[0].transitions.len()
            || !pair[0]
                .transitions
                .iter()
                .all(|prior| pair[1].transitions.contains(prior))
        {
            return Err(Error::InvalidClaimBody("handoff-chain nonmonotone closure"));
        }
    }
    Ok(chain)
}

/// Read a handoff previously accepted against an out-of-band authenticated pin.
/// Its local record is custody of a verified packet, not a peer assertion.
pub(crate) fn trusted_machine_handoff(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<ClaimHistoryHandoff> {
    let raw = store
        .vault_meta
        .get(txn, &pin_key(target))?
        .ok_or_else(missing)?;
    ClaimHistoryHandoff::decode(&raw).map_err(|_| bad())
}

fn verify_handoff_signature(packet: &ClaimHistoryHandoff) -> bool {
    let signature = crate::authority::AuthoritySignature {
        suite: packet.signer.suite(),
        public_key: packet.signer.clone(),
        signature: packet.signature.to_vec(),
    };
    packet.transcript().is_ok_and(|transcript| {
        crate::authority::verify_authority_signature(&signature, &transcript)
    })
}

pub(crate) fn resolved_machine_history(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<ClaimTransitionProjection> {
    let rows = machine_history_rows(store, txn, target)?;
    let packet = trusted_machine_handoff(store, txn, target)?;
    if fold.vault_id != Some(rows.birth.vault_id)
        || packet.vault_id != rows.birth.vault_id
        || packet.births.len() != 1
        || packet.births[0].id != target
        || packet.births[0].digest != rows.birth.digest
        || packet.transitions.len() != rows.events.len()
    {
        return Err(missing());
    }
    let mut hashes = rows
        .events
        .iter()
        .map(machine_claim_transition_event_hash)
        .collect::<Result<Vec<_>>>()?;
    hashes.sort_unstable();
    if !hashes
        .iter()
        .zip(&packet.transitions)
        .all(|(hash, event)| hash == &event.hash)
    {
        return Err(missing());
    }
    let handoff_chain = verified_handoff_chain(store, txn, &packet, fold)?;
    let event_tips: Vec<_> = packet
        .heads
        .iter()
        .filter(|head| **head != rows.birth.digest)
        .copied()
        .collect();
    let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
    let initial_weight = matches!(original.subject, super::ClaimSubject::Entity(_)).then_some(
        crate::edge::EdgeKind::ClaimOf
            .default_weight()
            .unwrap_or(1.0),
    );
    fold_machine_claim_transitions(
        &original,
        &rows.birth.vault_id,
        target,
        &rows.birth.digest,
        initial_weight,
        &rows.events,
        &event_tips,
        |event| {
            let key = AuthorityKey::Ed25519(event.host_public_key);
            let event_hash = machine_claim_transition_event_hash(event).ok();
            let Some(index) = handoff_chain.iter().position(|packet| {
                packet.signer == key
                    && packet
                        .transitions
                        .iter()
                        .any(|row| Some(row.hash) == event_hash)
                    && (packet.authority_head == event.authority_head
                        || packet.previous_handoff_hash.is_none())
            }) else {
                return false;
            };
            if fold
                .roster
                .get(&key)
                .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
                && fold.valid_entries.contains(&event.authority_head)
            {
                return true;
            }
            // The successor's in-chain ReRoot is the causal witness, not a
            // timestamp. An old event absent from the exact predecessor
            // packet cannot be inserted after the root has been retired.
            handoff_chain.iter().skip(index + 1).any(|successor| {
                fold.roster
                    .get(&successor.signer)
                    .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
                    && successor
                        .transitions
                        .iter()
                        .any(|row| Some(row.hash) == event_hash)
                    && crate::authority::machine_history_authority_descends(
                        store,
                        txn,
                        &event.authority_head,
                        &successor.authority_head,
                    )
                    .unwrap_or(false)
            })
        },
    )
    .map_err(|error| match error {
        TransitionFoldError::MissingHistory | TransitionFoldError::FrontierMismatch => missing(),
        TransitionFoldError::InvalidBirth => {
            Error::InvalidClaimBody("machine history birth invalid")
        }
        TransitionFoldError::InvalidEvent => {
            Error::InvalidClaimBody("machine history event invalid")
        }
        TransitionFoldError::Unauthorized => {
            Error::InvalidClaimBody("machine history signer unauthorized")
        }
        TransitionFoldError::IncompatibleFork => {
            Error::InvalidClaimBody("machine history fork incompatible")
        }
        TransitionFoldError::Rollback => Error::InvalidClaimBody("machine history event rollback"),
    })
}

/// Pin a challenge-bound host packet before receiving any claim bytes.
/// Its rows may still be missing; the pin only WITHHOLDS that target until
/// the full signed closure is fetched and adopted. A peer cannot assert an
/// empty history or select its own signer through this door.
impl Vault {
    pub fn pin_machine_history_handoff_pending(
        &self,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
        issuer: &crate::authority::HostSlipIssuer,
    ) -> Result<[u8; 32]> {
        if packet.births.len() != 1
            || packet.births[0].id != target
            || packet.signer != issuer.public_key()
        {
            return Err(bad());
        }
        let txn = self.store.env.read_txn()?;
        let (vault_id, current_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            &txn,
            &issuer.public_key(),
        )?;
        if packet.vault_id != vault_id
            || !self
                .authority_fold_readonly_in_txn(&txn)?
                .valid_entries
                .contains(&packet.authority_head)
            || packet.authority_head != current_head
                && !crate::authority::machine_history_authority_descends(
                    &self.store,
                    &txn,
                    &packet.authority_head,
                    &current_head,
                )?
        {
            return Err(bad());
        }
        drop(txn);
        let verdict =
            verify_claim_history_handoff(packet, pin, |_| HandoffStanding::MissingParents);
        if !matches!(verdict, HandoffVerification::MissingParents) {
            return Err(bad());
        }
        let hash = packet.content_hash().map_err(|_| bad())?;
        let mut txn = self.store.env.write_txn()?;
        if let Some(raw) = self.store.vault_meta.get(&txn, &pin_key(target))? {
            let previous = ClaimHistoryHandoff::decode(&raw).map_err(|_| bad())?;
            if hash != previous.content_hash().map_err(|_| bad())?
                && packet.previous_handoff_hash != Some(previous.content_hash().map_err(|_| bad())?)
            {
                return Err(bad());
            }
        }
        self.store.vault_meta.put(
            &mut txn,
            &pin_key(target),
            &packet.encode().map_err(|_| bad())?,
        )?;
        txn.commit()?;
        Ok(hash)
    }
}

/// Adopt a host/pairing-authenticated exact closure. The untrusted packet
/// cannot select its own signer, scope, predecessor pin or challenge. All
/// referenced signed CLAIM controls must already be resident and verified.
impl Vault {
    pub fn adopt_machine_history_handoff(
        &self,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
    ) -> Result<VerifiedClaimHistoryHandoff> {
        let mut txn = self.store.env.write_txn()?;
        let rows = machine_history_rows(&self.store, &txn, target)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
        let exact = packet.births.len() == 1
            && packet.births[0].id == target
            && packet.births[0].digest == rows.birth.digest
            && packet.vault_id == rows.birth.vault_id
            && packet.scope == super::history_store::machine_history_scope_bytes(&original)?
            && packet.transitions.len() == rows.events.len()
            && rows.events.iter().all(|event| {
                let Ok(hash) = machine_claim_transition_event_hash(event) else {
                    return false;
                };
                let expected_parents = if event.predecessors.is_empty() {
                    vec![rows.birth.digest]
                } else {
                    event.predecessors.clone()
                };
                packet
                    .transitions
                    .iter()
                    .any(|listed| listed.hash == hash && listed.predecessors == expected_parents)
            });
        let verdict = verify_claim_history_handoff(packet, pin, |handoff| {
            if !exact
                || fold.vault_id != Some(handoff.vault_id)
                || !fold.valid_entries.contains(&handoff.authority_head)
            {
                return HandoffStanding::MissingParents;
            }
            let Ok(chain) = verified_handoff_chain(&self.store, &txn, handoff, &fold) else {
                return HandoffStanding::MissingParents;
            };
            if !chain
                .iter()
                .any(|packet| packet.births == handoff.births && packet.scope == handoff.scope)
            {
                return HandoffStanding::Refused;
            }
            let Some(root) = fold.roster.get(&handoff.signer) else {
                return HandoffStanding::Refused;
            };
            if root.revoked || root.roles & ROLE_OWNER == 0 {
                return HandoffStanding::Refused;
            }
            HandoffStanding::OwnerAndComplete
        });
        let HandoffVerification::Verified(verified) = verdict else {
            return Err(match verdict {
                HandoffVerification::MissingParents => missing(),
                _ => bad(),
            });
        };
        let previous = self
            .store
            .vault_meta
            .get(&txn, &pin_key(target))?
            .ok_or_else(missing)?;
        let prior = ClaimHistoryHandoff::decode(&previous).map_err(|_| bad())?;
        if packet.encode().map_err(|_| bad())?.as_slice() != previous.as_ref()
            && packet.previous_handoff_hash != Some(prior.content_hash().map_err(|_| bad())?)
        {
            return Err(bad());
        }
        self.store.vault_meta.put(
            &mut txn,
            &pin_key(target),
            &packet.encode().map_err(|_| bad())?,
        )?;
        // The live claim id is a derived view. Heal a stale or missing LWW
        // snapshot under the SAME authenticated pin before publishing it.
        let projection = resolved_machine_history(&self.store, &txn, &fold, target)?;
        let projected = project_machine_claim(&projection);
        let raw = self
            .store
            .entities
            .get(&txn, target.as_bytes())?
            .ok_or_else(missing)?
            .to_vec();
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine projection header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(bad());
        }
        let previous = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if previous != projected {
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut txn,
                vec![crate::batch::BatchOp::Put {
                    id: target,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: crate::TimeRange {
                        start: header.occurred_start,
                        end: projected
                            .valid_to
                            .unwrap_or(header.occurred_end)
                            .max(header.occurred_start),
                    },
                    learned_at: header.learned_at,
                    data: super::encode_claim_body(&projected)?,
                    allow_maintenance: true,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                false,
            )?;
        }
        txn.commit()?;
        Ok(verified)
    }
}

/// Explicit in-chain re-root carry-forward: the current host signs the exact
/// previously trusted scoped closure under its NEW authority head. An event
/// authored later by the retired root is outside this packet and cannot gain
/// historical standing by claiming an old timestamp/frontier.
impl Vault {
    pub fn carry_machine_history_after_re_root(
        &self,
        target: EntityId,
        issuer: &crate::authority::HostSlipIssuer,
        challenge: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut txn = self.store.env.write_txn()?;
        let rows = machine_history_rows(&self.store, &txn, target)?;
        let prior = trusted_machine_handoff(&self.store, &txn, target)?;
        let prior_hash = prior.content_hash().map_err(|_| bad())?;
        let (vault_id, authority_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            &txn,
            &issuer.public_key(),
        )?;
        if vault_id != rows.birth.vault_id
            || prior.vault_id != vault_id
            || prior.births.len() != 1
            || prior.births[0].id != target
            || prior.births[0].digest != rows.birth.digest
            || prior.transitions.len() != rows.events.len()
            || rows.events.iter().any(|event| {
                machine_claim_transition_event_hash(event)
                    .ok()
                    .is_none_or(|hash| !prior.transitions.iter().any(|row| row.hash == hash))
            })
        {
            return Err(missing());
        }
        let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
        if prior.scope != super::history_store::machine_history_scope_bytes(&original)? {
            return Err(bad());
        }
        let signature = crate::authority::AuthoritySignature {
            suite: prior.signer.suite(),
            public_key: prior.signer.clone(),
            signature: prior.signature.to_vec(),
        };
        if !crate::authority::verify_authority_signature(
            &signature,
            &prior.transcript().map_err(|_| bad())?,
        ) {
            return Err(bad());
        }
        let mut nonce = [0; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let mut next = prior;
        next.authority_head = authority_head;
        next.previous_handoff_hash = Some(prior_hash);
        next.nonce = nonce;
        next.challenge = challenge;
        next.signer = issuer.public_key();
        next.signature = [0; 64];
        next.signature = issuer.sign_claim_handoff(&next.transcript().map_err(|_| bad())?);
        let pin = ClaimHistoryHandoffPin {
            vault_id: &vault_id,
            genesis_hash: &vault_id,
            expected_signer: &next.signer,
            scope: &next.scope,
            previous_handoff_hash: Some(prior_hash),
            challenge: &challenge,
        };
        if !matches!(
            verify_claim_history_handoff(&next, &pin, |_| HandoffStanding::OwnerAndComplete),
            HandoffVerification::Verified(_)
        ) {
            return Err(bad());
        }
        let bytes = next.encode().map_err(|_| bad())?;
        let hash = next.content_hash().map_err(|_| bad())?;
        let id =
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let record = super::history_store::machine_history_claim(
            MachineHistoryKind::Handoff,
            target,
            &original,
            bytes.clone(),
        );
        let now = self.store.clock.now_recorded_at();
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            vec![
                crate::batch::BatchOp::Put {
                    id,
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    occurred: crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data: super::encode_claim_body(&record)?,
                    allow_maintenance: false,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                },
                crate::batch::BatchOp::Edge {
                    src: id,
                    kind: crate::edge::EdgeKind::FacetOf,
                    tgt: original.scope_facet,
                    weight: 1.0,
                    vad: crate::affect::Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::new(false, false),
        )?;
        self.store
            .vault_meta
            .put(&mut txn, &pin_key(target), &bytes)?;
        txn.commit()?;
        Ok(hash)
    }
}

/// An authenticated origin and derived current state are distinct facts.
/// A caller cannot treat the current projection as the body MACHINE signed.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMachineClaim {
    pub claim_id: EntityId,
    pub signed_origin: ClaimBody,
    pub current: ClaimBody,
    pub birth_digest: [u8; 32],
    pub transition_heads: Vec<[u8; 32]>,
    pub handoff_digest: [u8; 32],
}

/// Projects the live CLAIM id under its authenticated history. The verifier
/// never accepts a caller body merely because its key is enrolled.
impl Vault {
    pub fn resolved_machine_claim(&self, target: EntityId) -> Result<ResolvedMachineClaim> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let projection = resolved_machine_history(&self.store, &txn, &fold, target)?;
        let rows = machine_history_rows(&self.store, &txn, target)?;
        let handoff = trusted_machine_handoff(&self.store, &txn, target)?;
        Ok(ResolvedMachineClaim {
            claim_id: target,
            signed_origin: projection.birth.clone(),
            current: project_machine_claim(&projection),
            birth_digest: rows.birth.digest,
            transition_heads: projection.frontier,
            handoff_digest: handoff.content_hash().map_err(|_| bad())?,
        })
    }
}

/// Derive the public claim id's current body from immutable authored content
/// plus the closed, authenticated operation history. No peer-supplied body
/// or Loro LWW position participates in this projection.
pub(crate) fn project_machine_claim(projection: &ClaimTransitionProjection) -> ClaimBody {
    let mut body = projection.birth.clone();
    body.approval = projection.approval;
    body.lifecycle = projection.lifecycle;
    body.valid_to = projection.valid_to;
    body.confidence = projection.confidence;
    body.stale = projection.stale;
    if projection.demotion_rung.is_some() || projection.scope_band_floor.is_some() {
        let mut scope = match body.scope.take() {
            Some(Value::Map(entries)) => entries,
            _ => Vec::new(),
        };
        if let Some(rung) = projection.demotion_rung {
            scope.retain(|(key, _)| key.as_str() != Some(super::CLAIM_SCOPE_DEMOTION_RUNG_KEY));
            let label = match rung {
                super::ClaimDemotionRung::Decayed => "decayed",
                super::ClaimDemotionRung::Weakened => "weakened",
                super::ClaimDemotionRung::Stale => "stale",
            };
            scope.push((
                Value::from(super::CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                Value::from(label),
            ));
        }
        if let Some(band) = projection.scope_band_floor {
            scope.retain(|(key, _)| key.as_str() != Some("sensitivity"));
            scope.push((Value::from("sensitivity"), Value::from(band)));
        }
        body.scope = Some(Value::Map(scope));
    }
    body
}
