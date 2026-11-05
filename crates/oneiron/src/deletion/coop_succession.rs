//! Core half of `deletion::coop_succession`: its store-layer items live in `oneiron_store::deletion::coop_succession` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::coop_succession::*;

use super::coop_delivery::{
    COOP_DELETION_PEER_PATH, COOP_DELETION_REPLY_PEER_PATH, CooperativeDeletionDelivery,
    CooperativeDeletionIngress,
};
use super::coop_request::{
    COOP_DELETION_BODY_MAX_BYTES, binary, decode, encode, envelope_signature, fields, invalid,
    peek_cooperative_deletion_pact, uint,
};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use oneiron_authority::authority::{
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityVaultId, DeviceAuthority,
    FederationPactState, ROLE_OWNER, authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron_contracts::authority::AuthorityEntryHash;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The rows a recipient kept, by pact and row hash: each a canonical signed
/// ReRoot row of the pact's peer, on the walk from the key the pact pinned.
const SUCCESSION: SideTable<([u8; 32], AuthorityEntryHash), Vec<u8>, Named> =
    SideTable::new(&side_table::COOPERATIVE_DELETION_SUCCESSION);

/// Why a walk refused its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkRefusal {
    /// A row is not canonical, not well signed, not the peer's, or not an edge.
    Invalid,
    /// One key hands on to two successors, or the walk comes back to a key it left.
    Fork,
}

impl WalkRefusal {
    /// What a peer route answers for this refusal.
    const fn ingress(self) -> CooperativeDeletionIngress {
        match self {
            Self::Invalid => CooperativeDeletionIngress::Unauthenticated,
            Self::Fork => CooperativeDeletionIngress::Conflict,
        }
    }
}

/// Walks `rows` from `pinned` (FIX 3014). Every row must be a canonical,
/// well-signed row of `peer_vault_id` that [`succession_edge`] admits. From
/// `pinned`, each step takes the one row the current key signed to the key
/// it names. A key that signed two different rows forks the walk, as does
/// a step back to a key the walk left. Rows no key on the walk signed are
/// checked and take no step. Self-contained: it reads no fold and no log.
fn walk(
    pinned: &AuthorityKey,
    peer_vault_id: &AuthorityVaultId,
    rows: &[Vec<u8>],
) -> std::result::Result<Walk, WalkRefusal> {
    let mut edges: BTreeMap<AuthorityKey, (AuthorityKey, AuthorityEntryHash, &Vec<u8>)> =
        BTreeMap::new();
    for bytes in rows {
        let entry = decode_authority_log_entry_body(bytes).map_err(|_| WalkRefusal::Invalid)?;
        let hash = authority_entry_hash(&entry).map_err(|_| WalkRefusal::Invalid)?;
        if entry.vault_id != Some(*peer_vault_id) {
            return Err(WalkRefusal::Invalid);
        }
        let next = succession_edge(&entry)
            .ok_or(WalkRefusal::Invalid)?
            .key
            .clone();
        match edges.get(entry.signer_key()) {
            Some((_, known, _)) if *known == hash => {}
            Some(_) => return Err(WalkRefusal::Fork),
            None => {
                edges.insert(entry.signer_key().clone(), (next, hash, bytes));
            }
        }
    }
    let mut end = pinned.clone();
    let mut reached = BTreeSet::from([pinned.clone()]);
    let mut walked = Vec::new();
    while let Some((next, hash, bytes)) = edges.get(&end) {
        if !reached.insert(next.clone()) {
            return Err(WalkRefusal::Fork);
        }
        walked.push((*hash, Vec::clone(bytes)));
        end = next.clone();
    }
    Ok(Walk { end, rows: walked })
}

/// The rows this vault kept for `pact_id`, in key order.
fn kept_rows(vault: &Vault, txn: &heed::RoTxn<'_>, pact_id: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    SUCCESSION
        .iter_from(&vault.store, txn, pact_id.as_slice())?
        .map(|row| row.map(|(_, bytes)| bytes))
        .collect()
}

impl Vault {
    /// The pages a claimed try's peer takes before its signed bytes (FIX
    /// 3014): the signed ReRoot rows that hand this vault's root on to the
    /// key that signed the try, in chain order from the genesis root's own
    /// handoff, since this vault cannot tell which root the peer pinned.
    /// `None` when no handoff names that key: a vault that never re-rooted
    /// sends the try alone, as before.
    ///
    /// # Errors
    ///
    /// Storage errors, and a try whose bytes or destination are not a
    /// courtesy ask's or answer's.
    pub fn cooperative_deletion_succession(
        &self,
        delivery: &CooperativeDeletionDelivery,
    ) -> Result<Option<CooperativeDeletionSuccession>> {
        let pact_id = peek_cooperative_deletion_pact(&delivery.bytes)?;
        let envelope = decode(&delivery.bytes)?;
        let signer = envelope_signature(fields(&envelope, &["body", "signature"])?[1])?.public_key;
        let rows = self.root_handoff_to(&signer)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let origin = delivery
            .destination
            .strip_suffix(COOP_DELETION_REPLY_PEER_PATH)
            .or_else(|| delivery.destination.strip_suffix(COOP_DELETION_PEER_PATH))
            .ok_or_else(invalid)?;
        Ok(Some(CooperativeDeletionSuccession {
            destination: format!("{origin}{COOP_DELETION_SUCCESSION_PEER_PATH}"),
            pages: pages(&pact_id, rows)?,
        }))
    }

    /// Keeps one page of a former peer's root succession (FIX 3014), sent
    /// ahead of an ask or an answer. The page's rows and those kept before
    /// are walked from the key this vault pinned for the page's pact; the
    /// rows on the walk are kept for that pact, and the rest are checked and
    /// dropped. A page that does not verify, or names no pact here, is
    /// `Unauthenticated`; one that forks a kept row is a `Conflict`; one
    /// that adds nothing is `AlreadyFiled`. The pact's pinned key and the
    /// authority log are never touched.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn receive_cooperative_deletion_succession(
        &self,
        bytes: &[u8],
    ) -> Result<CooperativeDeletionIngress> {
        let Ok((pact_id, rows)) = decode_page(bytes) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        let fold = self.authority_fold()?;
        let Some(pact) = fold.federation_pacts.get(&pact_id) else {
            return Ok(CooperativeDeletionIngress::Unauthenticated);
        };
        // The page alone first, so a stranger's rows never take the writer.
        if let Err(refusal) = walk(&pact.peer_owner_key, &pact.peer_vault_id, &rows) {
            return Ok(refusal.ingress());
        }
        self.with_write_txn_grouped(|txn| {
            let mut evidence = kept_rows(self, txn, &pact_id)?;
            evidence.extend(rows.iter().cloned());
            let walked = match walk(&pact.peer_owner_key, &pact.peer_vault_id, &evidence) {
                Ok(walked) => walked,
                Err(refusal) => return Ok(refusal.ingress()),
            };
            let mut added = false;
            for (hash, row) in &walked.rows {
                let key = (pact_id, *hash);
                if !SUCCESSION.contains(&self.store, txn, &key)? {
                    SUCCESSION.put(&self.store, txn, &key, row)?;
                    added = true;
                }
            }
            Ok(if added {
                CooperativeDeletionIngress::Filed
            } else {
                CooperativeDeletionIngress::AlreadyFiled
            })
        })
    }

    /// The one key a courtesy ask or answer under `pact_id` verifies
    /// against (FIX 3014): the key `pact` pinned, exactly as before, until a
    /// kept row hands it on, then the root the kept rows walk it to. A key a
    /// kept row handed on signs no more courtesy under the pact (a call: a
    /// retired root's word is not taken once its successor is proved). The
    /// pact itself is never re-pinned. `None` when the kept rows no longer
    /// walk, which only a damaged store shows.
    pub(super) fn courtesy_pact_signer(
        &self,
        pact_id: &[u8; 32],
        pact: &FederationPactState,
    ) -> Result<Option<AuthorityKey>> {
        let rtxn = self.store.env.read_txn()?;
        let rows = kept_rows(self, &rtxn, pact_id)?;
        if rows.is_empty() {
            return Ok(Some(pact.peer_owner_key.clone()));
        }
        Ok(walk(&pact.peer_owner_key, &pact.peer_vault_id, &rows)
            .ok()
            .map(|walked| walked.end))
    }
}
