//! Verified MACHINE history residence: exact birth + transition closure at a trusted pin.
//!
//! The mutable claim row is a projection, never evidence of its own current
//! authority. Missing bytes or a pin with unproved ancestry withhold reads.
//! A pin is the tip of a handoff chain whose packets each carry one delta;
//! the claim's whole history is the union of the chain's deltas.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::{AuthorityFold, AuthorityKey, ROLE_OWNER};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::transition::{
    ClaimTransitionProjection, SignedClaimTransitionEvent, TransitionFoldError,
    decode_machine_claim_transition_event, fold_machine_claim_transitions,
    machine_claim_transition_event_hash, machine_claim_transition_event_id,
};
use crate::error::{ClaimError, Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use rand_core::RngCore;
use rmpv::Value;

use super::history_handoff::{DeltaClosure, handoff_delta_closure};
use super::history_store::{
    MachineHistoryKind, machine_history_ids_for_target, machine_history_kind,
    machine_history_shape_matches,
};
use super::{
    ClaimBody, ClaimHistoryHandoff, ClaimHistoryHandoffPin, HandoffKind, HandoffStanding,
    HandoffVerification, SignedClaimBirth, VerifiedClaimHistoryHandoff,
    verify_claim_history_handoff,
};

fn missing() -> Error {
    Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
}
fn bad() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}
pub(crate) const PIN_PREFIX: &[u8] = b"claim:machine-history-pin:v1:";

pub(crate) fn pin_key(target: EntityId) -> Vec<u8> {
    [PIN_PREFIX, target.as_bytes()].concat()
}

/// Retired: a host re-root once recorded its carry here, local to the vault
/// that moved. The carry is now a `ReRootCarry` packet in the history's own
/// chain. Nothing writes or reads this table; a delete still clears a row an
/// earlier build left, so restore keeps classifying the family.
pub(crate) const CARRY: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_CARRY);

pub(crate) struct MachineHistoryRows {
    pub(crate) birth: SignedClaimBirth,
    pub(crate) events: Vec<SignedClaimTransitionEvent>,
    /// The tip's handoff chain, oldest first, ending at the tip.
    pub(crate) chain: Vec<ClaimHistoryHandoff>,
    /// The whole history: every transition of every delta in the chain, by
    /// hash, with its predecessors ([`chain_transitions`]).
    pub(crate) transitions: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
}

impl MachineHistoryRows {
    /// Heads of the packet before the tip, read from that verified packet:
    /// the tip's pinned previous heads. Empty at genesis.
    pub(crate) fn previous_heads(&self) -> &[[u8; 32]] {
        self.chain
            .iter()
            .rev()
            .nth(1)
            .map_or(&[][..], |packet| packet.heads.as_slice())
    }
}

/// Verified navigation from the target-local projection index, for the
/// history the trusted pin names. A malformed index/record refuses; absence
/// is typed incomplete, never an empty history.
pub(crate) fn machine_history_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<MachineHistoryRows> {
    let pin = trusted_machine_handoff(store, txn, target)?;
    machine_history_rows_at(store, txn, target, &pin)
}

/// [`machine_history_rows`] for the history `tip`'s chain names, where `tip`
/// is a candidate not pinned yet (adoption). Its ancestors are read from
/// stored packets; an absent one is incomplete.
pub(crate) fn machine_history_rows_at(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    tip: &ClaimHistoryHandoff,
) -> Result<MachineHistoryRows> {
    // The target index is an UNTRUSTED navigation hint. It may contain
    // additional self-signed, unbound peer events. Only IDs named by the
    // authenticated tip's chain can affect a claim's fold; a stray event
    // cannot permanently poison a legitimate target.
    if tip.births.len() != 1 || tip.births[0].id != target {
        return Err(bad());
    }
    let chain = read_handoff_chain(store, txn, tip)?;
    let transitions = chain_transitions(&chain)?;
    let mut expected = BTreeSet::new();
    for hash in std::iter::once(tip.births[0].digest).chain(transitions.keys().copied()) {
        expected.insert(
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?,
        );
    }
    if expected.len() != transitions.len() + 1 {
        return Err(bad());
    }
    let mut birth = None;
    let mut events = Vec::new();
    for id in machine_history_ids_for_target(store, txn, target)? {
        if !expected.remove(&id) {
            continue;
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
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
    if birth.digest != tip.births[0].digest {
        return Err(bad());
    }
    let original = super::decode_claim_body(&birth.initial_body, true)?;
    for event in &events {
        let id = machine_claim_transition_event_id(event).map_err(|_| bad())?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?.ok_or(
            Error::CorruptedIndex("machine transition index row missing"),
        )?;
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
    Ok(MachineHistoryRows {
        birth,
        events,
        chain,
        transitions,
    })
}

/// The handoff chain behind `tip`, oldest first, ending at `tip`: the one
/// reader of a claim's stored packets. Each link must name its parent's exact
/// content hash, and every packet must repeat the tip's birth anchor, vault,
/// genesis and scope. Each delta must close over the heads of the packet
/// before it ([`handoff_delta_closure`]), and no transition may appear in two
/// packets or repeat a birth digest. An absent ancestor is incomplete; a
/// present but wrong chain refuses. The walk counts its packets against a
/// threshold row and reads on: no chain is too long to read (rule 5).
pub(crate) fn read_handoff_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    tip: &ClaimHistoryHandoff,
) -> Result<Vec<ClaimHistoryHandoff>> {
    let scope = tip
        .births
        .first()
        .map_or_else(Vec::new, |birth| birth.id.as_bytes().to_vec());
    let mut count = ScanCount::start(store, txn, EngineScan::MachineHandoffChain, &scope)?;
    let mut current = tip.clone();
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        count.row();
        let hash = current.content_hash().map_err(|_| bad())?;
        if !seen.insert(hash) {
            return Err(Error::InvalidClaimBody("handoff-chain loop"));
        }
        if current.vault_id != tip.vault_id || current.genesis_hash != tip.genesis_hash {
            return Err(Error::InvalidClaimBody("handoff-chain vault mismatch"));
        }
        if current.births != tip.births {
            return Err(Error::InvalidClaimBody("handoff-chain birth mismatch"));
        }
        if current.scope != tip.scope {
            return Err(Error::InvalidClaimBody("handoff-chain scope mismatch"));
        }
        let parent = current.previous_handoff_hash;
        chain.push(current);
        let Some(parent) = parent else { break };
        let id =
            EntityId::from_bytes(parent[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let raw =
            crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?.ok_or_else(missing)?;
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
    count.defer(store);
    chain.reverse();
    // Closure across the chain: each delta extends the heads before it with
    // transitions no earlier packet carried.
    let mut carried: BTreeSet<[u8; 32]> = tip.births.iter().map(|birth| birth.digest).collect();
    let mut previous_heads: &[[u8; 32]] = &[];
    for packet in &chain {
        if handoff_delta_closure(packet, previous_heads) != DeltaClosure::Closed {
            return Err(Error::InvalidClaimBody("handoff-chain delta closure"));
        }
        if !packet
            .transitions
            .iter()
            .all(|transition| carried.insert(transition.hash))
        {
            return Err(Error::InvalidClaimBody("handoff-chain replayed transition"));
        }
        previous_heads = packet.heads.as_slice();
    }
    Ok(chain)
}

/// The whole history a handoff chain carries: every transition of every
/// delta, by hash, with its predecessors. A plain map, never a synthetic
/// packet, so no packet bound applies to a long history.
pub(crate) fn chain_transitions(
    chain: &[ClaimHistoryHandoff],
) -> Result<BTreeMap<[u8; 32], Vec<[u8; 32]>>> {
    let mut transitions = BTreeMap::new();
    for transition in chain.iter().flat_map(|packet| &packet.transitions) {
        if transitions
            .insert(transition.hash, transition.predecessors.clone())
            .is_some()
        {
            return Err(Error::InvalidClaimBody("handoff-chain replayed transition"));
        }
    }
    Ok(transitions)
}

const TIP_HEAD_MISSING: &str = "handoff-chain tip authority head missing";
const PRIOR_HEAD_MISSING: &str = "handoff-chain prior authority head missing";

/// Whether a [`verified_handoff_chain`] error waits on what this vault does
/// not hold yet, an ancestor packet or an authority head, rather than on a
/// wrong chain (FIX 3823).
fn chain_awaits(error: &Error) -> bool {
    matches!(
        error,
        Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
    ) || matches!(
        error,
        Error::InvalidClaimBody(reason) if [TIP_HEAD_MISSING, PRIOR_HEAD_MISSING].contains(reason)
    )
}

/// Require an exact signed predecessor chain for all archived handoff pins.
/// The present pin may advance only from an authenticated previously accepted
/// closure; a peer cannot splice an older/re-rooted packet into a new head.
/// On top of [`read_handoff_chain`]'s shape, every packet must be signed and
/// name an authority head this vault holds or that the tip's descends from.
pub(crate) fn verified_handoff_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    tip: &ClaimHistoryHandoff,
    fold: &AuthorityFold,
) -> Result<Vec<ClaimHistoryHandoff>> {
    let chain = read_handoff_chain(store, txn, tip)?;
    let vault_id = fold.vault_id.ok_or_else(missing)?;
    for (index, current) in chain.iter().enumerate() {
        if current.vault_id != vault_id {
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
            return Err(Error::InvalidClaimBody(if index + 1 == chain.len() {
                TIP_HEAD_MISSING
            } else {
                PRIOR_HEAD_MISSING
            }));
        }
        if !verify_handoff_signature(current) {
            return Err(Error::InvalidClaimBody("handoff-chain signature mismatch"));
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

pub(crate) fn verify_handoff_signature(packet: &ClaimHistoryHandoff) -> bool {
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
    let (projection, carriers) = machine_history(store, txn, fold, target)?;
    // A carrier awaiting its owner's answer leaves the history incomplete, as
    // one that has not arrived does: no approval projects from it yet.
    for id in carriers {
        if !crate::gate::claim_consolidation_eligible_in_txn(
            store,
            txn,
            &id,
            crate::gate::ConsolidationReader::MachineHistory,
        )? {
            return Err(missing());
        }
    }
    Ok(projection)
}

/// The history a restrictive transition stages on: every carrier, held or
/// not, so a revoke, demotion or narrowing lands while a carrier awaits its
/// owner's answer. Only restrictive staging reads it.
pub(crate) fn machine_history_for_restriction(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<ClaimTransitionProjection> {
    machine_history(store, txn, fold, target).map(|(projection, _)| projection)
}

/// Whether a local write of `incoming` to `target` is a restriction staged on
/// a held history: the whole history projects it, and it keeps the live row's
/// approval or rejects it, so no approval projects from a held carrier.
pub(crate) fn restricts_held_machine_history(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    incoming: &ClaimBody,
) -> Result<bool> {
    let projection = match machine_history_for_restriction(store, txn, fold, target) {
        Ok(projection) => projection,
        Err(Error::Claim(
            ClaimError::MachineClaimHistoryIncomplete | ClaimError::InvalidMachineClaimProof,
        )) => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &target)? else {
        return Ok(false);
    };
    let live =
        super::decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(bad)?, true)?;
    Ok(project_machine_claim(&projection) == *incoming
        && (incoming.approval == live.approval
            || incoming.approval == super::ClaimApprovalStatus::Rejected))
}

/// Whether the resident events are exactly the chain's union: one event per
/// listed transition, each with the predecessor set the chain lists for its
/// hash (a root event lists the birth digest).
fn events_match_chain(rows: &MachineHistoryRows) -> bool {
    rows.transitions.len() == rows.events.len()
        && rows.events.iter().all(|event| {
            let Ok(hash) = machine_claim_transition_event_hash(event) else {
                return false;
            };
            let expected_parents = if event.predecessors.is_empty() {
                vec![rows.birth.digest]
            } else {
                event.predecessors.clone()
            };
            rows.transitions.get(&hash) == Some(&expected_parents)
        })
}

/// The verified, folded history of `target`, and the ids of every carrier it
/// was folded from: the birth, the present pin, each handoff in its chain
/// and each transition of the chain's union.
fn machine_history(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<(ClaimTransitionProjection, Vec<EntityId>)> {
    let rows = machine_history_rows(store, txn, target)?;
    let packet = trusted_machine_handoff(store, txn, target)?;
    if fold.vault_id != Some(rows.birth.vault_id)
        || packet.vault_id != rows.birth.vault_id
        || packet.births.len() != 1
        || packet.births[0].id != target
        || packet.births[0].digest != rows.birth.digest
        || !events_match_chain(&rows)
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
        .zip(rows.transitions.keys())
        .all(|(hash, listed)| hash == listed)
    {
        return Err(missing());
    }
    let handoff_chain = verified_handoff_chain(store, txn, &packet, fold)?;
    let mut hashes = vec![rows.birth.digest, packet.content_hash().map_err(|_| bad())?];
    hashes.extend(rows.transitions.keys().copied());
    for handoff in &handoff_chain {
        hashes.push(handoff.content_hash().map_err(|_| bad())?);
    }
    let carriers = hashes
        .iter()
        .map(|hash| {
            EntityId::from_bytes(hash[..16].try_into().map_err(|_| bad())?).map_err(|_| bad())
        })
        .collect::<Result<Vec<_>>>()?;
    let event_tips: Vec<_> = packet
        .heads
        .iter()
        .filter(|head| **head != rows.birth.digest)
        .copied()
        .collect();
    let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
    // The signed birth's own ClaimOf weight, the one the materializer gave
    // the edge.
    let initial_weight = super::claim_initial_claim_of_weight(&original).map_err(|_| bad())?;
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
            // timestamp. Every later packet carries the event in its
            // ancestry, since its delta extends the introducing packet's
            // heads; its own delta never repeats the event. An old event
            // absent from the exact introducing packet cannot be inserted
            // after the root has been retired.
            handoff_chain.iter().skip(index + 1).any(|successor| {
                fold.roster
                    .get(&successor.signer)
                    .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
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
    .map(|projection| (projection, carriers))
}

/// Pin a challenge-bound host packet before receiving any claim bytes.
/// Its rows may still be missing; the pin only WITHHOLDS that target until
/// the full signed closure is fetched and adopted. A peer cannot assert an
/// empty history or select its own signer through this door. A successor of
/// the stored pin must name that pin's heads as its previous heads.
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
            let previous_hash = previous.content_hash().map_err(|_| bad())?;
            if hash != previous_hash
                && (packet.previous_handoff_hash != Some(previous_hash)
                    || pin.previous_heads != previous.heads.as_slice())
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

/// How an adopted candidate must stand to the stored pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Succession {
    /// The out-of-band door: a stored pin is required, and the candidate is
    /// that pin or its immediate successor on the pin's own heads.
    Strict,
    /// A device receiving its own vault's history
    /// (`history_pin_exchange`): the stored pin, if any, must lie on the
    /// candidate's verified chain, so the trusted prefix is kept; with none,
    /// the chain from genesis is the first pin.
    OwnReceive,
}

/// Adopt a host/pairing-authenticated exact closure. The untrusted packet
/// cannot select its own signer, scope, predecessor pin, previous heads or
/// challenge. Its whole chain and every signed CLAIM control the chain names
/// must already be resident and verified.
impl Vault {
    pub fn adopt_machine_history_handoff(
        &self,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
    ) -> Result<VerifiedClaimHistoryHandoff> {
        let mut txn = self.store.env.write_txn()?;
        let verified = self.adopt_machine_history_handoff_in_txn(
            &mut txn,
            target,
            packet,
            pin,
            Succession::Strict,
        )?;
        txn.commit()?;
        Ok(verified)
    }

    /// The one adoption core, in the caller's writer: verify `packet`'s
    /// whole chain and closure against `pin`, check it succeeds the stored
    /// pin as `succession` says, store it, and heal the live CLAIM row under
    /// it. On an error the caller drops whatever this staged.
    pub(crate) fn adopt_machine_history_handoff_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
        packet: &ClaimHistoryHandoff,
        pin: &ClaimHistoryHandoffPin<'_>,
        succession: Succession,
    ) -> Result<VerifiedClaimHistoryHandoff> {
        // The candidate's own chain names the rows: its whole history, not
        // its delta and not the old pin's.
        let rows = machine_history_rows_at(&self.store, txn, target, packet)?;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let original = super::decode_claim_body(&rows.birth.initial_body, true)?;
        let exact = packet.births.len() == 1
            && packet.births[0].id == target
            && packet.births[0].digest == rows.birth.digest
            && packet.vault_id == rows.birth.vault_id
            && packet.scope == super::history_store::machine_history_scope_bytes(&original)?
            && events_match_chain(&rows);
        // A local storage error inside the callback leaves through this.
        let mut local = None;
        let read: &heed::RoTxn<'_> = txn;
        let verdict = verify_claim_history_handoff(packet, pin, |handoff| {
            if !exact
                || fold.vault_id != Some(handoff.vault_id)
                || !fold.valid_entries.contains(&handoff.authority_head)
            {
                return HandoffStanding::MissingParents;
            }
            // The chain's shape already proved itself above: a wrong chain
            // refused there. An absent ancestor or authority not yet held
            // waits; a bad signature or vault refuses (FIX 3823).
            let chain = match verified_handoff_chain(&self.store, read, handoff, &fold) {
                Ok(chain) => chain,
                Err(error) if chain_awaits(&error) => return HandoffStanding::MissingParents,
                Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                    return HandoffStanding::Refused;
                }
                Err(error) => {
                    local = Some(error);
                    return HandoffStanding::MissingParents;
                }
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
        if let Some(error) = local {
            return Err(error);
        }
        let HandoffVerification::Verified(verified) = verdict else {
            return Err(match verdict {
                HandoffVerification::MissingParents => missing(),
                _ => bad(),
            });
        };
        let bytes = packet.encode().map_err(|_| bad())?;
        let stored = self
            .store
            .vault_meta
            .get(txn, &pin_key(target))?
            .map(std::borrow::Cow::into_owned);
        match succession {
            Succession::Strict => {
                let previous = stored.ok_or_else(missing)?;
                let prior = ClaimHistoryHandoff::decode(&previous).map_err(|_| bad())?;
                if bytes != previous
                    && (packet.previous_handoff_hash
                        != Some(prior.content_hash().map_err(|_| bad())?)
                        || pin.previous_heads != prior.heads.as_slice())
                {
                    return Err(bad());
                }
            }
            // The stored pin is a packet of the candidate's verified chain,
            // or the candidate is another branch and the pin stays.
            Succession::OwnReceive => {
                if let Some(previous) = stored
                    && !rows
                        .chain
                        .iter()
                        .any(|link| link.encode().is_ok_and(|encoded| encoded == previous))
                {
                    return Err(bad());
                }
            }
        }
        self.store.vault_meta.put(txn, &pin_key(target), &bytes)?;
        // The live claim id is a derived view. Heal a stale or missing LWW
        // snapshot under the SAME authenticated pin before publishing it.
        let projection = resolved_machine_history(&self.store, txn, &fold, target)?;
        let projected = project_machine_claim(&projection);
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &target)?
        else {
            // Own receive pins a verified history before its live row lands,
            // so the row is admitted under the pin when it does.
            return match succession {
                Succession::OwnReceive => Ok(verified),
                Succession::Strict => Err(missing()),
            };
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine projection header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(bad());
        }
        let previous = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        // A superseded history's same-id successor owns the live row.
        let successor = projection.admits_successor_by(crate::memory::claim_author(&previous))
            && !crate::authority::machine_claim_needs_history(&self.store, txn, &previous)?;
        if previous != projected && !successor {
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
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
        Ok(verified)
    }
}

/// Explicit in-chain re-root carry-forward: the current host signs an empty
/// delta on the exact previously trusted chain under its NEW authority head,
/// with the same birth anchor and heads. An event authored later by the
/// retired root is outside this chain and cannot gain historical standing by
/// claiming an old timestamp/frontier. The packet is a plain `Handoff`: only
/// `re_root_host` signs a `ReRootCarry`, the same empty delta.
impl Vault {
    pub fn carry_machine_history_after_re_root(
        &self,
        target: EntityId,
        issuer: &crate::authority::HostSlipIssuer,
        challenge: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut txn = self.store.env.write_txn()?;
        let hash = self.carry_machine_history_in_txn(
            &mut txn,
            target,
            issuer,
            challenge,
            HandoffKind::Handoff,
        )?;
        txn.commit()?;
        Ok(hash)
    }

    pub(crate) fn carry_machine_history_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
        issuer: &crate::authority::HostSlipIssuer,
        challenge: [u8; 32],
        kind: HandoffKind,
    ) -> Result<[u8; 32]> {
        let rows = machine_history_rows(&self.store, txn, target)?;
        let prior = trusted_machine_handoff(&self.store, txn, target)?;
        let prior_hash = prior.content_hash().map_err(|_| bad())?;
        let (vault_id, authority_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            txn,
            &issuer.public_key(),
        )?;
        if vault_id != rows.birth.vault_id
            || prior.vault_id != vault_id
            || prior.births.len() != 1
            || prior.births[0].id != target
            || prior.births[0].digest != rows.birth.digest
            || rows.transitions.len() != rows.events.len()
            || rows.events.iter().any(|event| {
                machine_claim_transition_event_hash(event)
                    .ok()
                    .is_none_or(|hash| !rows.transitions.contains_key(&hash))
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
        let previous_heads = prior.heads.clone();
        // An empty delta: the carry adds no transition, so the heads stay.
        let mut next = prior;
        next.kind = kind;
        next.transitions = Vec::new();
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
            previous_heads: &previous_heads,
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
        )?;
        let now = self.store.clock.now_recorded_at();
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
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
        self.store.vault_meta.put(txn, &pin_key(target), &bytes)?;
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
    // A signed weakening moves the number; it then reads in its own house
    // band, never the birth's (FIX 7761).
    if projection.confidence.to_bits() != body.confidence.to_bits() {
        body.set_confidence(projection.confidence, None);
    }
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
