//! Own-vault machine-history pin exchange (FIX 3821): a device adopts its
//! vault's machine-claim histories as their rows sync, with no out-of-band
//! pin.
//!
//! Trust comes from the packets' signatures and this device's own authority
//! fold, never from the transport. The receiver derives every pin field
//! itself: the vault id and genesis from its fold; the expected signer only
//! once the fold holds the tip's signer as a live owner root and its host
//! context passes; the scope from the verified signed birth; the previous
//! hash and heads from the verified chain, never from the candidate's own
//! fields. The challenge is the candidate's own signed one, read as an
//! issuance label ([`own_receive_challenge`]). So this path proves no
//! receiver freshness: a fresh receiver cannot tell the latest tip from an
//! older one, and a stored pin is never rolled back. The strict public doors
//! (`pin_machine_history_handoff_pending`, `adopt_machine_history_handoff`)
//! keep their challenge-bound contract.
//!
//! No transport gate: both landing hooks (window ingest and explicit
//! replay) run on every landing, whatever the import tier. A foreign vault's
//! packet fails the vault-id binding here, and guest admission already
//! withholds machine-history rows
//! (`federation::foreign_world::guest_claim_withheld`).
//!
//! Succession: the newest connected tip of the target's resident chain is
//! adopted in ONE step, never packet by packet. The stored pin, if any, must
//! lie on that tip's chain, so the trusted prefix is kept. Only the tip's
//! signer must be a live owner; earlier signers may have been re-rooted
//! away. Several such tips (a signed fork), or a stored pin on another
//! branch, keep the stored pin ([`PinExchangeOutcome::Conflict`]); nothing
//! picks by arrival, hash, time or challenge.
//!
//! CALLS (L02, open): "FIX 3821 own-receive pin", "FIX 3821 no transport
//! gate", "FIX 3821 one-step tip adoption".

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::authority::ROLE_OWNER;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{ClaimError, Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};

use super::history_projection::{
    Succession, machine_history_rows_at, pin_key, verify_handoff_signature,
};
use super::history_store::{
    MACHINE_HANDOFF_PREDICATE, indexed_machine_history_target, machine_history_ids_for_target,
    machine_history_indexed, machine_history_kind, machine_history_scope_bytes,
};
use super::{ClaimHistoryHandoff, ClaimHistoryHandoffPin};

/// What one exchange did for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinExchangeOutcome {
    /// The row is neither a machine-history control nor a claim with one.
    NotMachineHistory,
    /// The stored pin is the newest adoptable tip, or is ahead of it. At the
    /// tip, its history was verified again and its live row healed.
    Unchanged(EntityId),
    /// Nothing adoptable yet: a packet, event or birth, or the authority it
    /// needs, has not landed.
    Pending(EntityId),
    /// The tip is the stored pin now: the first pin, or a successor of the
    /// stored one.
    Adopted(EntityId),
    /// A signed fork, or a stored pin off the tip's chain: the stored pin
    /// stays.
    Conflict(EntityId),
    /// The newest owner-signed chain does not verify; the stored pin stays.
    Refused(EntityId),
}

impl PinExchangeOutcome {
    /// The target this outcome is about, if any.
    pub(crate) fn target(&self) -> Option<EntityId> {
        match self {
            Self::NotMachineHistory => None,
            Self::Unchanged(target)
            | Self::Pending(target)
            | Self::Adopted(target)
            | Self::Conflict(target)
            | Self::Refused(target) => Some(*target),
        }
    }
}

/// The challenge the own-receive pin expects of `packet`: its own signed
/// challenge, read as an issuance label. It gives NO receiver-freshness
/// proof: production challenges are random bytes (OsRng) that no receiver
/// asked for. CALLS: "FIX 3821 own-receive pin".
fn own_receive_challenge(packet: &ClaimHistoryHandoff) -> [u8; 32] {
    packet.challenge
}

/// The `CorruptedIndex` reasons the history readers give for a resident
/// peer row or its navigation-index entry. They refuse the exchange; any
/// other `CorruptedIndex` is this device's own storage and propagates.
const PEER_ROW_CORRUPTION: [&str; 5] = [
    "machine history index row missing",
    "machine history header",
    "machine transition index row missing",
    "machine handoff header",
    "machine projection header",
];

fn invalid() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}

/// An exchange error as its outcome: an incomplete history waits, a wrong
/// one refuses, and only a local failure is an error.
fn settle(error: Error, target: EntityId) -> Result<PinExchangeOutcome> {
    match error {
        Error::Claim(
            ClaimError::MachineClaimHistoryIncomplete | ClaimError::RemoteMachineHistoryPending,
        ) => Ok(PinExchangeOutcome::Pending(target)),
        Error::Claim(_) | Error::InvalidClaimBody(_) => Ok(PinExchangeOutcome::Refused(target)),
        Error::CorruptedIndex(reason) if PEER_ROW_CORRUPTION.contains(&reason) => {
            Ok(PinExchangeOutcome::Refused(target))
        }
        other => Err(other),
    }
}

/// The target's resident handoff packets by content hash: each a decoded
/// `machine.handoff` control whose id is its content hash and whose one
/// birth is `target`. The index is a navigation hint, so any other row it
/// names is passed over here; the adoption core reads the chosen chain
/// strictly.
fn resident_handoffs(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<BTreeMap<[u8; 32], ClaimHistoryHandoff>> {
    let mut packets = BTreeMap::new();
    for id in machine_history_ids_for_target(store, txn, target)? {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
            continue;
        };
        if !EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        {
            continue;
        }
        let Ok(row) = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
            continue;
        };
        let Value::Binary(bytes) = &row.value else {
            continue;
        };
        if row.predicate != MACHINE_HANDOFF_PREDICATE {
            continue;
        }
        let Ok(packet) = ClaimHistoryHandoff::decode(bytes) else {
            continue;
        };
        let Ok(hash) = packet.content_hash() else {
            continue;
        };
        if packet.births.len() == 1
            && packet.births[0].id == target
            && hash[..16] == id.as_bytes()[..]
        {
            packets.insert(hash, packet);
        }
    }
    Ok(packets)
}

/// Whether `wanted` is `from` or one of its ancestors among `packets`.
fn on_chain(
    packets: &BTreeMap<[u8; 32], ClaimHistoryHandoff>,
    from: [u8; 32],
    wanted: [u8; 32],
) -> bool {
    let mut at = Some(from);
    let mut steps = 0_usize;
    while let Some(hash) = at {
        if hash == wanted {
            return true;
        }
        steps += 1;
        if steps > packets.len() {
            return false;
        }
        at = packets
            .get(&hash)
            .and_then(|packet| packet.previous_handoff_hash);
    }
    false
}

/// The packets whose chain reaches a genesis packet through `packets`.
fn connected_to_genesis(packets: &BTreeMap<[u8; 32], ClaimHistoryHandoff>) -> BTreeSet<[u8; 32]> {
    let mut known = BTreeMap::<[u8; 32], bool>::new();
    for start in packets.keys() {
        let mut walk = Vec::new();
        let mut at = *start;
        let reaches = loop {
            if let Some(reaches) = known.get(&at) {
                break *reaches;
            }
            let Some(packet) = packets.get(&at) else {
                break false;
            };
            walk.push(at);
            match packet.previous_handoff_hash {
                None => break true,
                Some(_) if walk.len() > packets.len() => break false,
                Some(previous) => at = previous,
            }
        };
        for hash in walk {
            known.insert(hash, reaches);
        }
    }
    known
        .into_iter()
        .filter_map(|(hash, reaches)| reaches.then_some(hash))
        .collect()
}

impl Vault {
    /// The pin-exchange hook for one landed row, inside the writer that
    /// landed it: a machine-history control (birth, transition or handoff)
    /// advances its target, and so does a CLAIM row whose body needs a
    /// machine history or whose id the target index names, since the
    /// target row may land last. Any other row is `NotMachineHistory` at
    /// once (a non-CLAIM after its header, an absent or deleted row before
    /// any body decode). Window ingest and explicit replay call it.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn receive_own_machine_history_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<PinExchangeOutcome> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
        else {
            return Ok(PinExchangeOutcome::NotMachineHistory);
        };
        if !EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
            || !crate::vault::live_entity_row_in_txn(&self.store, txn, id)?.is_live()
        {
            return Ok(PinExchangeOutcome::NotMachineHistory);
        }
        let Ok(body) = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
            return Ok(PinExchangeOutcome::NotMachineHistory);
        };
        let target = if machine_history_kind(&body.predicate).is_some() {
            match indexed_machine_history_target(&self.store, txn, *id, &body)? {
                Some(target) => target,
                None => return Ok(PinExchangeOutcome::NotMachineHistory),
            }
        } else if crate::authority::machine_claim_needs_history(&self.store, txn, &body)?
            || machine_history_indexed(&self.store, txn, *id)?
        {
            *id
        } else {
            return Ok(PinExchangeOutcome::NotMachineHistory);
        };
        let outcome = self.advance_own_machine_history_in_txn(txn, target)?;
        if matches!(
            outcome,
            PinExchangeOutcome::Conflict(_) | PinExchangeOutcome::Refused(_)
        ) {
            tracing::debug!(
                claim = ?outcome.target().as_ref().map(EntityId::to_hex),
                ?outcome,
                "machine history pin kept"
            );
        }
        Ok(outcome)
    }

    /// Adopt the newest connected, owner-signed tip of `target`'s resident
    /// handoff chain in one step, under a pin derived from this device's own
    /// fold and the verified chain (module doc). The adoption runs in a
    /// nested savepoint of `txn`, committed only on success. An incomplete
    /// history is `Pending` and a wrong one `Refused`; only a local storage
    /// failure is an `Err`, so a raw row never fails its ingest because its
    /// history cannot be adopted yet. L03's FIX 3820 ancestor fetch calls
    /// this after each fetched round.
    pub(crate) fn advance_own_machine_history_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
    ) -> Result<PinExchangeOutcome> {
        self.exchange_in_txn(txn, target)
            .or_else(|error| settle(error, target))
    }

    fn exchange_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
    ) -> Result<PinExchangeOutcome> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let Some(vault_id) = fold.vault_id else {
            return Ok(PinExchangeOutcome::Pending(target));
        };
        let mut packets = resident_handoffs(&self.store, txn, target)?;
        let stored = match self.store.vault_meta.get(txn, &pin_key(target))? {
            Some(raw) => {
                let packet = ClaimHistoryHandoff::decode(&raw).map_err(|_| invalid())?;
                let hash = packet.content_hash().map_err(|_| invalid())?;
                packets.entry(hash).or_insert(packet);
                Some(hash)
            }
            None => None,
        };
        // Candidates: packets of this vault that reach genesis, signed by a
        // root the fold holds as a live owner at a head it holds.
        let connected = connected_to_genesis(&packets);
        let candidates: BTreeSet<[u8; 32]> = packets
            .iter()
            .filter(|(hash, packet)| {
                connected.contains(*hash)
                    && packet.vault_id == vault_id
                    && packet.genesis_hash == vault_id
                    && fold.valid_entries.contains(&packet.authority_head)
                    && fold
                        .roster
                        .get(&packet.signer)
                        .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
                    && verify_handoff_signature(packet)
            })
            .map(|(hash, _)| *hash)
            .collect();
        // A candidate under another candidate is not a tip.
        let mut below = BTreeSet::new();
        for hash in &candidates {
            let mut at = packets
                .get(hash)
                .and_then(|packet| packet.previous_handoff_hash);
            while let Some(previous) = at {
                if !below.insert(previous) {
                    break;
                }
                at = packets
                    .get(&previous)
                    .and_then(|packet| packet.previous_handoff_hash);
            }
        }
        let mut tips = candidates.difference(&below).copied();
        let tip_hash = match (tips.next(), tips.next()) {
            (None, _) => return Ok(PinExchangeOutcome::Pending(target)),
            (Some(tip), None) => tip,
            // A signed fork: never pick by arrival, hash, time or challenge.
            (Some(_), Some(_)) => return Ok(PinExchangeOutcome::Conflict(target)),
        };
        let outcome = match stored {
            None => PinExchangeOutcome::Adopted(target),
            Some(stored) if stored == tip_hash => PinExchangeOutcome::Unchanged(target),
            Some(stored) if on_chain(&packets, tip_hash, stored) => {
                PinExchangeOutcome::Adopted(target)
            }
            // The stored pin is ahead of every adoptable packet: no rollback.
            Some(stored) if on_chain(&packets, stored, tip_hash) => {
                return Ok(PinExchangeOutcome::Unchanged(target));
            }
            Some(_) => return Ok(PinExchangeOutcome::Conflict(target)),
        };
        let Some(tip) = packets.remove(&tip_hash) else {
            return Ok(PinExchangeOutcome::Pending(target));
        };
        // The expected signer is the tip's own only once its host context
        // passes at a head the tip's authority head equals or precedes, as
        // the pending door checks; never the birth's MACHINE key.
        let (host_vault, current_head) = crate::authority::machine_history_host_context(
            &self.store,
            self.privacy_posture(),
            txn,
            &tip.signer,
        )?;
        if host_vault != vault_id
            || (tip.authority_head != current_head
                && !crate::authority::machine_history_authority_descends(
                    &self.store,
                    txn,
                    &tip.authority_head,
                    &current_head,
                )?)
        {
            return Ok(PinExchangeOutcome::Refused(target));
        }
        // Scope from the verified signed birth; the previous hash and heads
        // from the previous packet of the verified chain.
        let rows = machine_history_rows_at(&self.store, txn, target, &tip)?;
        if rows.birth.vault_id != vault_id || rows.birth.target != target {
            return Ok(PinExchangeOutcome::Refused(target));
        }
        let scope = machine_history_scope_bytes(&super::decode_claim_body(
            &rows.birth.initial_body,
            true,
        )?)?;
        let previous_handoff_hash = rows
            .chain
            .iter()
            .rev()
            .nth(1)
            .map(|previous| previous.content_hash().map_err(|_| invalid()))
            .transpose()?;
        let challenge = own_receive_challenge(&tip);
        let pin = ClaimHistoryHandoffPin {
            vault_id: &vault_id,
            genesis_hash: &vault_id,
            expected_signer: &tip.signer,
            scope: &scope,
            previous_handoff_hash,
            previous_heads: rows.previous_heads(),
            challenge: &challenge,
        };
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        self.adopt_machine_history_handoff_in_txn(
            &mut savepoint,
            target,
            &tip,
            &pin,
            Succession::OwnReceive,
        )?;
        savepoint.commit()?;
        Ok(outcome)
    }
}
