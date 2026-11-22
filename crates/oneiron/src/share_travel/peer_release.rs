//! The rows this vault released to a grant's peer in another vault
//! (CROSS-VAULT-DELETE-SELECTOR-ANSWER-RELEASE). Each send boundary to another
//! vault records them before its bytes leave: a Connect delivery and a guest
//! document before they are signed, a selector socket answer after its last
//! door's verdict. The filter that decides which of the owner's deletes
//! travel to that peer reads them (`sync/selector/authorize/
//! peer_tombstone_release.rs`). A record claims no delivery: it bounds what a
//! delete tells the peer to a row the peer was sent. It keeps two ids and a
//! time, and outlives the row's own erase, since the delete travels after the
//! row is gone.

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};
use crate::{Result, Vault};

const PEER_RELEASE: SideTable<(EntityId, EntityId), u64, Named> =
    SideTable::new(&side_table::SHARE_PEER_RELEASE);

/// The rows one export to another vault releases under its selector's grant,
/// recorded before the export's bytes leave ([`Vault::record_peer_release`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelease {
    grant: EntityId,
    rows: Vec<EntityId>,
}

impl PeerRelease {
    pub(crate) fn new(grant: EntityId, rows: Vec<EntityId>) -> Self {
        Self { grant, rows }
    }
}

impl Vault {
    /// Records each row of `release` as released to its grant's peer, in one
    /// write of its own; a row released before keeps its first release time.
    /// The caller sends nothing when this fails, so no copy leaves without
    /// the record that lets the owner's delete of it follow.
    pub fn record_peer_release(&self, release: &PeerRelease) -> Result<()> {
        if release.rows.is_empty() {
            return Ok(());
        }
        let at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            for row in &release.rows {
                let key = (release.grant, *row);
                if !PEER_RELEASE.contains(&self.store, txn, &key)? {
                    PEER_RELEASE.put(&self.store, txn, &key, &at)?;
                }
            }
            Ok(())
        })
    }
}

/// Whether this vault recorded `row` as released to `grant`'s peer, read in
/// `txn`.
pub(crate) fn peer_release_recorded_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    grant: &EntityId,
    row: &EntityId,
) -> Result<bool> {
    PEER_RELEASE.contains(&vault.store, txn, &(*grant, *row))
}
