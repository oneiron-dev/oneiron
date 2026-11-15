//! The vault's one linked hosted peer (L10-16; canon cross-arch-0024
//! `#path-e`): `oneiron link` adds the cloud's always-on machine of this
//! vault, and `oneiron unlink` takes it away. The row is the owner's record
//! of that link: the hosted-node link he issued for it, the control plane
//! that runs the peer and its id there, and the machine the peer's redeem
//! enrolled and the slip it minted, both recorded in the redeem's own
//! transaction. An unlink revokes the peer here at once and keeps the row
//! until the control plane has taken the peer's removal, so a removal it did
//! not take is asked again.
//!
//! The peer's slip is for the owner's PERSON with no actor class, the
//! device-grade credential canon names (RULING LINK-PEER-AUTHORITY = B): the
//! HTTP redeem admits that holder, and no owner door takes the slip, which
//! names no human. Other slips of the owner share that holder, so an unlink
//! revokes the peer's own by its id, never by holder.

use super::code::pairing_row_key;
use super::*;
use crate::side_table::Named;

/// The vault's one linked peer. Key: ().
const LINKED_PEER: SideTable<(), LinkedPeer, Named> = SideTable::new(&side_table::LINKED_PEER);

/// How long the peer's slip lives, as `oneiron token pair` asks by default;
/// the vault's credential ceiling caps it.
const PEER_SLIP_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60;

/// The owner's record of the vault's linked hosted peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkedPeer {
    /// The control plane's origin the peer was asked of.
    pub cloud_origin: String,
    /// The pending pairing row of the peer's link, by its keyed code hash.
    link_key: String,
    /// When the owner linked the peer, in unix seconds.
    pub linked_at: u64,
    /// The peer's id at the control plane, once it took the request.
    pub peer_id: Option<String>,
    /// The machine the peer's redeem enrolled, once it redeemed.
    pub machine: Option<crate::EntityId>,
    /// The id of the slip the peer's redeem minted, once it redeemed: an
    /// unlink revokes it by this id. The slip takes no renewal, which only a
    /// human's slip may.
    pub slip: Option<[u8; 32]>,
    /// When an unlink revoked the peer here. The row stays until the
    /// control plane takes the peer's removal.
    pub unlinked_at: Option<u64>,
}

/// What [`Vault::issue_linked_peer_link`] did.
pub enum LinkedPeerIssued {
    /// The link to hand the control plane, and the holder its one-line form
    /// names: the owner's PERSON.
    Issued {
        link: PairingLink,
        holder: crate::EntityId,
    },
    /// The vault already holds a linked peer, or one whose unlink is still
    /// owed: nothing was minted.
    AlreadyLinked(LinkedPeer),
}

impl Vault {
    /// The owner links a hosted peer: one hosted-node link
    /// ([`Self::issue_hosted_node_pairing_link`]) whose slip is for the
    /// owner's PERSON with no actor class and carries every verb, as a
    /// machine link's does, and the vault's one linked-peer row naming that
    /// link, so the redeem that spends it records the machine it enrols and
    /// the slip it mints. While a row stands, linked or with its unlink
    /// still owed, nothing is minted.
    ///
    /// # Errors
    /// The owner proof's own, the link's own, and storage faults.
    pub fn issue_linked_peer_link(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        surface: ActSurface,
        cloud_origin: &str,
    ) -> Result<LinkedPeerIssued> {
        let holder = {
            let txn = self.store.env.read_txn()?;
            let holder = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            if let Some(peer) = LINKED_PEER.get(&self.store, &txn, &())? {
                return Ok(LinkedPeerIssued::AlreadyLinked(peer));
            }
            holder
        };
        let principal = PairingPrincipal {
            holder_ref: Some(holder.to_hex()),
            ..PairingPrincipal::default()
        };
        let link = self.issue_hosted_node_pairing_link(
            issuer,
            owner,
            surface,
            Scope::top(),
            PEER_SLIP_LIFETIME_SECS,
            principal,
        )?;
        let link_key = pairing_row_key(issuer, &link.code)?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        // Another link landed between the check and this writer: this
        // link's code was never handed out, so it goes unspent.
        if let Some(peer) = LINKED_PEER.get(&self.store, &txn, &())? {
            PAIRING_PENDING.delete(&self.store, &mut txn, &link_key)?;
            txn.commit()?;
            return Ok(LinkedPeerIssued::AlreadyLinked(peer));
        }
        let peer = LinkedPeer {
            cloud_origin: cloud_origin.to_owned(),
            link_key,
            linked_at: self.instant_in_txn(&txn)?.secs(),
            peer_id: None,
            machine: None,
            slip: None,
            unlinked_at: None,
        };
        LINKED_PEER.put(&self.store, &mut txn, &(), &peer)?;
        txn.commit()?;
        Ok(LinkedPeerIssued::Issued { link, holder })
    }

    /// The vault's linked peer, as the owner reads it; `None` when it has
    /// none.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub fn linked_peer_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Option<LinkedPeer>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        LINKED_PEER.get(&self.store, &txn, &())
    }

    /// Records the peer's id at the control plane on the row of the link it
    /// took: the one whose code is `code`, matched by its keyed hash, so an
    /// id never lands on another link's row. A row an unlink already reached
    /// keeps no id it did not have; `None` when no such row stands.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub fn record_linked_peer_id_as_owner(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        code: &str,
        peer_id: &str,
    ) -> Result<Option<LinkedPeer>> {
        let link_key = pairing_row_key(issuer, code)?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let Some(mut peer) = LINKED_PEER.get(&self.store, &txn, &())? else {
            return Ok(None);
        };
        if peer.link_key != link_key || peer.unlinked_at.is_some() {
            return Ok(None);
        }
        peer.peer_id = Some(peer_id.to_owned());
        LINKED_PEER.put(&self.store, &mut txn, &(), &peer)?;
        txn.commit()?;
        Ok(Some(peer))
    }

    /// The owner unlinks the peer here, in one transaction: a link not yet
    /// redeemed is spent unread, and the row is marked unlinked (at its
    /// first unlink's time, when an earlier one is still owed to the control
    /// plane). Revoking the machine and its slips, and asking the control
    /// plane, are the caller's next steps; [`Self::forget_linked_peer_as_owner`]
    /// drops the row once the control plane took the removal. `None` when
    /// the vault has no linked peer.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub fn unlink_linked_peer_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Option<LinkedPeer>> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let Some(mut peer) = LINKED_PEER.get(&self.store, &txn, &())? else {
            return Ok(None);
        };
        PAIRING_PENDING.delete(&self.store, &mut txn, &peer.link_key)?;
        if peer.unlinked_at.is_none() {
            peer.unlinked_at = Some(self.instant_in_txn(&txn)?.secs());
        }
        LINKED_PEER.put(&self.store, &mut txn, &(), &peer)?;
        txn.commit()?;
        Ok(Some(peer))
    }

    /// Drops the row of a peer an unlink reached, once the control plane
    /// took its removal; `false` when no unlinked row stands.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub fn forget_linked_peer_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let unlinked = LINKED_PEER
            .get(&self.store, &txn, &())?
            .is_some_and(|peer| peer.unlinked_at.is_some());
        if unlinked {
            LINKED_PEER.delete(&self.store, &mut txn, &())?;
            txn.commit()?;
        }
        Ok(unlinked)
    }
}

/// Records `machine` and the id of the slip the redeem minted, `slip`, on
/// the linked peer whose link the redeem of `row_key` spends, in that
/// redeem's transaction; any other redeem leaves the row alone.
pub(super) fn record_redeemed_machine_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row_key: &str,
    machine: crate::EntityId,
    slip: [u8; 32],
) -> Result<()> {
    let Some(mut peer) = LINKED_PEER.get(&vault.store, txn, &())? else {
        return Ok(());
    };
    if peer.link_key != row_key || peer.unlinked_at.is_some() {
        return Ok(());
    }
    peer.machine = Some(machine);
    peer.slip = Some(slip);
    LINKED_PEER.put(&vault.store, txn, &(), &peer)
}
