//! Which record tombstones a filter for another vault releases
//! (CROSS-VAULT-DELETE-NEVER-ADMITTED = A, Oneiron lead 21 Nov 06:1x): while
//! the share is live, the owner's delete travels as an update and removes the
//! peer's copy; membership and topology tombstones stay out.
//!
//! A tombstone names a row's id and its delete's reason and time. The row's
//! body is gone, so the checks that released the live row to another vault
//! (`release.rs`, its use limits, its word sources) cannot run again. A delete
//! therefore leaves only for a row this vault already released to the grant's
//! peer: a prepared guest-window export under that grant listed it
//! (`share_travel::guest_window_rows_prepared_for_grant`). That bounds what the
//! delete tells the peer to a row the peer was sent. The peer's own delivery
//! ledger then decides whether its copy goes
//! (`sync/selector/admission/peer_tombstones.rs`).

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::deletion::decode_tombstone_value;
use crate::deletion::tombstone_scope::deleted_record_scope_in;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::share_travel::guest_window_rows_prepared_for_grant;
use crate::sync::selector::admission::is_membership_or_topology_kind;

/// The record tombstones one filter for another vault releases under its
/// selector's grant.
pub(super) struct PeerTombstoneRelease<'g> {
    grant: &'g EntityId,
    /// The rows the prepared exports under `grant` listed, read once, at the
    /// first tombstone that gets that far.
    prepared: Option<BTreeSet<EntityId>>,
}

impl<'g> PeerTombstoneRelease<'g> {
    pub(super) fn new(grant: &'g EntityId) -> Self {
        Self {
            grant,
            prepared: None,
        }
    }

    /// Whether the tombstone `value`, keyed `raw_key` and naming `id`, leaves
    /// for the grant's peer. All of these must hold:
    /// - the key is the id's canonical spelling;
    /// - the value is a v2 tombstone with an engine reason and a delete
    ///   request;
    /// - the scope that request's delete captured names the row's type, and
    ///   that type is no membership or topology kind
    ///   ([`is_membership_or_topology_kind`], the list the peer's admission
    ///   reads too);
    /// - a prepared export under the grant listed the row.
    ///
    /// A read that fails withholds the tombstone.
    pub(super) fn releases(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        raw_key: &str,
        id: &EntityId,
        value: &[u8],
    ) -> bool {
        self.released(vault, txn, raw_key, id, value)
            .unwrap_or(false)
    }

    fn released(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        raw_key: &str,
        id: &EntityId,
        value: &[u8],
    ) -> Result<bool> {
        if id.to_hex() != raw_key {
            return Ok(false);
        }
        let decoded = decode_tombstone_value(value);
        let (Some(_), Some(request)) = (decoded.reason, decoded.request_id) else {
            return Ok(false);
        };
        let Some(captured) = deleted_record_scope_in(&vault.store, txn, id, &request)? else {
            return Ok(false);
        };
        if captured
            .entity_type
            .is_none_or(is_membership_or_topology_kind)
        {
            return Ok(false);
        }
        if self.prepared.is_none() {
            self.prepared = Some(guest_window_rows_prepared_for_grant(
                vault, txn, self.grant,
            )?);
        }
        Ok(self.prepared.as_ref().is_some_and(|rows| rows.contains(id)))
    }
}
