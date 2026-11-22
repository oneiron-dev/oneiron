//! Which record tombstones a Connect delivery's or a selector socket answer's
//! filter releases to another vault (CROSS-VAULT-DELETE-NEVER-ADMITTED = A,
//! Oneiron lead 21 Nov 06:1x): while the share is live, the owner's delete
//! travels as an update and removes the peer's copy; membership and topology
//! tombstones stay out.
//!
//! A tombstone names a row's id and its delete's reason and time. The row's
//! body is gone, so the checks that released the live row to another vault
//! (`release.rs`, its use limits, its word sources) cannot run again. A delete
//! therefore leaves only for a row this vault already released to the grant's
//! peer: a release record under that grant names it
//! (`share_travel::peer_release_recorded_in`, written at every send boundary
//! to another vault; CROSS-VAULT-DELETE-SELECTOR-ANSWER-RELEASE), or, for a
//! row sent before those records were written, a prepared guest-window export
//! under that grant listed it
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
use crate::share_travel::{guest_window_rows_prepared_for_grant, peer_release_recorded_in};
use crate::sync::selector::admission::is_membership_or_topology_kind;

/// The record tombstones one filter of a copy to another vault releases
/// under its selector's grant.
pub(super) struct PeerTombstoneRelease<'g> {
    grant: &'g EntityId,
    /// The rows the prepared exports under `grant` listed, read once, at the
    /// first tombstone that gets that far and that no release record names:
    /// `Some(None)` once that read
    /// failed, which withholds every later tombstone of this filter too,
    /// without a second scan.
    prepared: Option<Option<BTreeSet<EntityId>>>,
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
    /// - a release record under the grant names the row, or a prepared
    ///   export under the grant listed it.
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
        let grant = self.grant;
        if peer_release_recorded_in(vault, txn, grant, id)? {
            return Ok(true);
        }
        let prepared = self
            .prepared
            .get_or_insert_with(|| guest_window_rows_prepared_for_grant(vault, txn, grant).ok());
        Ok(prepared.as_ref().is_some_and(|rows| rows.contains(id)))
    }
}
