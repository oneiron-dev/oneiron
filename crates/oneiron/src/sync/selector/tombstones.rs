//! Which window tombstones a selector export carries beside the rows it keeps
//! (FIX 10161). A grant that reads every record takes every tombstone the
//! open fallback carries, as before. A narrower grant takes one only where the
//! scope its delete captured is a scope the grant reads. A member who is not
//! an Owner takes one only of a row it reads at the relationship gate
//! (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL).

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::access_grant::AccessContext;
use crate::deletion::decode_tombstone_value;
use crate::deletion::tombstone_scope::{deleted_relationship_read_in, deleted_scope_in};
use crate::entity_id::EntityId;
use crate::federation::{Scope, ScopeAxis};

/// What a narrower grant gets of a tombstone whose delete left no scope it
/// can judge here: no captured row, a row bound to another request, a value
/// that names no request, or a failed read (a call).
const UNPROVEN_TOMBSTONE_EXPORTED: bool = false;

/// The tombstone rule of one export, for the tombstones of rows it does not
/// keep.
pub(super) struct TombstoneExport<'g> {
    grant: &'g Scope,
    /// No facet filter, no band filter and the All-world selector: the
    /// fallback that carries tombstones beyond the kept rows.
    open: bool,
    /// The grant reads every record, so the fallback shows it nothing it
    /// could not read.
    unrestricted: bool,
}

impl<'g> TombstoneExport<'g> {
    pub(super) fn new(grant: &'g Scope, open: bool) -> Self {
        // Judged as the kept rows are, with every axis open but the verb.
        let every_record = Scope {
            verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
            ..Scope::top()
        };
        Self {
            grant,
            open,
            unrestricted: grant.admits("read", &every_record, &Scope::top()),
        }
    }

    /// Whether the tombstone `value` of `id`, a row this export does not
    /// keep, still travels.
    pub(super) fn admits(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        id: &EntityId,
        value: &[u8],
    ) -> bool {
        if !self.open {
            return false;
        }
        if self.unrestricted {
            return true;
        }
        let Some(request) = decode_tombstone_value(value).request_id else {
            return UNPROVEN_TOMBSTONE_EXPORTED;
        };
        match deleted_scope_in(&vault.store, txn, id, &request) {
            Ok(Some(scope)) => self.grant.admits("read", &scope, &Scope::top()),
            Ok(None) | Err(_) => UNPROVEN_TOMBSTONE_EXPORTED,
        }
    }
}

/// Whether the selector's member reads the row that the tombstone `value` of
/// `id` removes, as the relationship read its delete captured decides
/// (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL). The capture was taken while the
/// row was live, so it decides before any body the window still holds.
/// `Some(true)` for an Owner's member (`None`), which reads every row, and for
/// a capture older than the read, whose tombstone travels as the rules above
/// judge it. `Some(false)` for a failed read. `None` when no capture is bound
/// to the tombstone's request (it names none, there is no row, or the row is
/// bound to another request): the caller judges what the window still holds.
pub(super) fn member_reads_by_capture(
    vault: &Vault,
    txn: &RoTxn<'_>,
    member: Option<&AccessContext<'_>>,
    id: &EntityId,
    value: &[u8],
) -> Option<bool> {
    let Some(member) = member else {
        return Some(true);
    };
    let request = decode_tombstone_value(value).request_id?;
    match deleted_relationship_read_in(&vault.store, txn, id, &request) {
        Ok(Some(Some(read))) => Some(read.allowed_by(member)),
        Ok(Some(None)) => Some(true),
        Ok(None) => None,
        Err(_) => Some(false),
    }
}
