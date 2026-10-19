//! Payload-free batch receipts, kept after durable work completes.
use super::{
    DeferredWork, FederationBurstBaselineState, FederationBurstDecision,
    FederationBurstDisposition, FederationBurstReceipt, FederationBurstWorkState, FederationPeer,
    corrupt,
};
use crate::{Result, Vault};

fn key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = b"m:federation-receipt:v1:".to_vec();
    key.extend_from_slice(id);
    key
}

pub(super) fn load(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: &FederationPeer,
    id: &[u8; 32],
) -> Result<Option<FederationBurstReceipt>> {
    let Some(bytes) = vault.store.sync_queue.get(txn, &key(id))? else {
        return Ok(None);
    };
    let row: FederationBurstReceipt = rmp_serde::from_slice(&bytes).map_err(|_| corrupt())?;
    if row.batch_ref != blake3::Hash::from(*id).to_hex().to_string()
        || row.principal != peer.principal()
        || row.grant != peer.grant()
    {
        return Err(corrupt());
    }
    Ok(Some(row))
}

fn put(vault: &Vault, txn: &mut heed::RwTxn<'_>, row: &FederationBurstReceipt) -> Result<()> {
    let id = crate::deletion::parse_hex::<32>(&row.batch_ref).ok_or_else(corrupt)?;
    let bytes = rmp_serde::to_vec_named(row).map_err(|_| corrupt())?;
    vault.store.sync_queue.put(txn, &key(&id), &bytes)?;
    Ok(())
}

pub(super) fn record(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    peer: &FederationPeer,
    work: &DeferredWork,
    decision: FederationBurstDecision,
    baseline: FederationBurstBaselineState,
) -> Result<()> {
    let batch_ref = blake3::Hash::from(work.id).to_hex().to_string();
    let disposition = match decision {
        FederationBurstDecision::Allow(_) => FederationBurstDisposition::Allow,
        FederationBurstDecision::Defer { .. } => FederationBurstDisposition::Defer {
            replay_ref: batch_ref.clone(),
        },
        FederationBurstDecision::IsolateAndPropose { bundle_id, .. } => {
            FederationBurstDisposition::IsolateAndPropose {
                bundle_ref: format!(
                    "federation-review:{}",
                    blake3::Hash::from(bundle_id).to_hex()
                ),
                replay_ref: batch_ref.clone(),
            }
        }
    };
    put(
        vault,
        txn,
        &FederationBurstReceipt {
            batch_ref,
            principal: peer.principal(),
            grant: peer.grant(),
            window_key: work.window.clone(),
            disposition,
            state: FederationBurstWorkState::Pending,
            baseline,
        },
    )
}

pub(super) fn settle(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    peer: &FederationPeer,
    work: &DeferredWork,
    rejected: bool,
) -> Result<()> {
    if let Some(mut receipt) = load(vault, txn, peer, &work.id)? {
        if receipt.state != FederationBurstWorkState::Pending {
            return Ok(());
        }
        receipt.state = if rejected {
            FederationBurstWorkState::Rejected
        } else {
            FederationBurstWorkState::Imported
        };
        put(vault, txn, &receipt)?;
    }
    Ok(())
}

impl Vault {
    /// The owner inspects retained work without impersonating its peer.
    pub fn federation_burst_disposition_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        peer: &FederationPeer,
        batch_ref: &str,
    ) -> Result<FederationBurstReceipt> {
        let id = crate::deletion::parse_hex::<32>(batch_ref)
            .ok_or_else(|| crate::Error::InvalidConfig("invalid batch_ref".into()))?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        peer.revalidate_in_txn(self, &txn)?;
        load(self, &txn, peer, &id)?.ok_or(crate::Error::EntityNotFound)
    }

    /// Only this peer's own batch can be read through a peer door.
    pub fn federation_burst_disposition(
        &self,
        peer: &FederationPeer,
        batch_ref: &str,
    ) -> Result<FederationBurstReceipt> {
        let id = crate::deletion::parse_hex::<32>(batch_ref)
            .ok_or_else(|| crate::Error::InvalidConfig("invalid batch_ref".into()))?;
        let txn = self.store.env.read_txn()?;
        peer.revalidate_in_txn(self, &txn)?;
        load(self, &txn, peer, &id)?.ok_or(crate::Error::EntityNotFound)
    }
}
