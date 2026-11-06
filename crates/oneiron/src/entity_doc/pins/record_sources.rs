//! Closed lifetime of transport facts affected by the owner's actual history cut.

use heed::RwTxn;
use loro::VersionVector;

use super::{EntityDoc, storage};
use crate::EntityId;
use crate::store::Store;

/// Constructed only after the owner door computed its constrained shallow cut.
/// The sink consumes the original writer, not a later transaction or snapshot.
pub(crate) struct RecordDocumentHistoryCut<'write, 'env> {
    store: &'write Store,
    txn: &'write mut RwTxn<'env>,
    entity: EntityId,
    incarnation: String,
    before: VersionVector,
    after: VersionVector,
}

impl<'write, 'env> RecordDocumentHistoryCut<'write, 'env> {
    pub(super) fn new(
        store: &'write Store,
        txn: &'write mut RwTxn<'env>,
        entity: EntityId,
        head: &storage::Head,
        source: &EntityDoc,
        purged: &EntityDoc,
    ) -> Self {
        Self {
            store,
            txn,
            entity,
            incarnation: head.incarnation.clone(),
            before: source.doc.shallow_since_vv().to_vv(),
            after: purged.doc.shallow_since_vv().to_vv(),
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        &'write Store,
        &'write mut RwTxn<'env>,
        EntityId,
        String,
        VersionVector,
        VersionVector,
    ) {
        (
            self.store,
            self.txn,
            self.entity,
            self.incarnation,
            self.before,
            self.after,
        )
    }
}
