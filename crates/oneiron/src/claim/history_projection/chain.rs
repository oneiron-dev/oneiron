//! Reading and verifying a pinned history: its rows, its handoff chain and its projection.

use std::borrow::Cow;

use super::*;

/// Where the history readers read a target's controls: the store, or what
/// the last advance of the target carried (`history_advance`, FIX 4296).
/// Each answers exactly as the store does in the same transaction.
pub(crate) trait ControlRows {
    /// Every control id in `target`'s index, in key order.
    fn index_ids(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Vec<EntityId>>;

    /// The stored row at `id`, if any.
    fn row<'a>(
        &'a self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Cow<'a, [u8]>>>;

    /// Whether `packet`'s signature verifies.
    fn handoff_signed(&self, packet: &ClaimHistoryHandoff) -> bool {
        verify_handoff_signature(packet)
    }
}

/// The store itself.
pub(crate) struct StoreRows;

impl ControlRows for StoreRows {
    fn index_ids(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Vec<EntityId>> {
        machine_history_ids_for_target(store, txn, target)
    }

    fn row<'a>(
        &'a self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Cow<'a, [u8]>>> {
        Ok(crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?.map(Cow::Owned))
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
    machine_history_rows_from(&StoreRows, store, txn, target)
}

/// [`machine_history_rows`] read through `rows`.
pub(crate) fn machine_history_rows_from(
    rows: &dyn ControlRows,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<MachineHistoryRows> {
    let pin = trusted_machine_handoff(store, txn, target)?;
    machine_history_rows_at(rows, store, txn, target, &pin)
}

/// [`machine_history_rows`] for the history `tip`'s chain names, where `tip`
/// is a candidate not pinned yet (adoption), read through `rows`. Its
/// ancestors are read from stored packets; an absent one is incomplete.
pub(crate) fn machine_history_rows_at(
    rows: &dyn ControlRows,
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
    let chain = read_handoff_chain_from(rows, store, txn, tip)?;
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
    for id in rows.index_ids(store, txn, target)? {
        if !expected.remove(&id) {
            continue;
        }
        let raw = rows
            .row(store, txn, &id)?
            .ok_or(Error::CorruptedIndex("machine history index row missing"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine history header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(bad());
        }
        let row = super::super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let Value::Binary(bytes) = &row.value else {
            return Err(bad());
        };
        match machine_history_kind(&row.predicate) {
            Some(MachineHistoryKind::Birth) => {
                let found = SignedClaimBirth::decode(bytes).map_err(|_| bad())?;
                let original = super::super::decode_claim_body(&found.initial_body, true)?;
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
    let original = super::super::decode_claim_body(&birth.initial_body, true)?;
    for event in &events {
        let id = machine_claim_transition_event_id(event).map_err(|_| bad())?;
        let raw = rows.row(store, txn, &id)?.ok_or(Error::CorruptedIndex(
            "machine transition index row missing",
        ))?;
        let row = super::super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
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
    read_handoff_chain_from(&StoreRows, store, txn, tip)
}

/// [`read_handoff_chain`] read through `rows`.
pub(crate) fn read_handoff_chain_from(
    rows: &dyn ControlRows,
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
        let raw = rows.row(store, txn, &id)?.ok_or_else(missing)?;
        let h = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("machine handoff header"))?;
        if h.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("handoff-chain wrong type"));
        }
        let row = super::super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if row.predicate != super::super::history_store::MACHINE_HANDOFF_PREDICATE {
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
    verified_handoff_chain_from(&StoreRows, store, txn, tip, fold)
}

/// [`verified_handoff_chain`] read through `rows`.
pub(crate) fn verified_handoff_chain_from(
    rows: &dyn ControlRows,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    tip: &ClaimHistoryHandoff,
    fold: &AuthorityFold,
) -> Result<Vec<ClaimHistoryHandoff>> {
    let chain = read_handoff_chain_from(rows, store, txn, tip)?;
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
        if !rows.handoff_signed(current) {
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
    resolved_machine_history_from(&StoreRows, store, txn, fold, target)
}

/// [`resolved_machine_history`] read through `rows`.
pub(crate) fn resolved_machine_history_from(
    rows: &dyn ControlRows,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<ClaimTransitionProjection> {
    let (projection, carriers) = machine_history(rows, store, txn, fold, target)?;
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
    machine_history(&StoreRows, store, txn, fold, target).map(|(projection, _)| projection)
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
    let live = super::super::decode_claim_body(
        raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(bad)?,
        true,
    )?;
    Ok(project_machine_claim(&projection) == *incoming
        && (incoming.approval == live.approval
            || incoming.approval == super::super::ClaimApprovalStatus::Rejected))
}
