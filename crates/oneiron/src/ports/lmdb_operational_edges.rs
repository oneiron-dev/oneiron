//! Provenance cache updates after the claim lifecycle has authorized the change.
use super::EdgeStoreMaintenance;
use crate::edge::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    EdgeProvenanceFlags,
};
use crate::error::{ClaimError, Error, Result};
use crate::provenance::EdgeRef;
use crate::store::Store;
use heed::RwTxn;
impl EdgeStoreMaintenance for Store {
    fn port_revision_link(
        &self,
        txn: &mut RwTxn<'_>,
        source: &crate::EntityId,
        kind: crate::EdgeKind,
        target: &crate::EntityId,
        created_at: u64,
    ) -> Result<bool> {
        use crate::edge::{EdgeKind, encode_edge_value};
        if !matches!(
            kind,
            EdgeKind::ChildOf | EdgeKind::DerivedFrom | EdgeKind::Supersedes
        ) {
            return Err(Error::InvariantViolation("revision link kind"));
        }
        let value = encode_edge_value(
            kind,
            kind.default_weight().unwrap_or(1.0),
            created_at,
            crate::affect::Vad::NEUTRAL,
            None,
        )?;
        let out = Store::encode_edge_key(source, kind, target);
        let incoming = Store::encode_edge_key(target, kind, source);
        let changed = self
            .edges_out
            .get(txn, &out)?
            .is_none_or(|old| old.as_ref() != value.as_slice())
            || self
                .edges_in
                .get(txn, &incoming)?
                .is_none_or(|old| old.as_ref() != value.as_slice());
        self.edges_out.put(txn, &out, &value)?;
        self.edges_in.put(txn, &incoming, &value)?;
        if kind == EdgeKind::DerivedFrom {
            super::integrity::record_derived_edge_in_txn(self, txn, source, target)?;
        }
        if changed {
            crate::ppr::invalidate_ppr_for_edge(self, txn, source, target)?;
        }
        Ok(changed)
    }

    fn port_edge_stamp_provenance(
        &self,
        wtxn: &mut RwTxn<'_>,
        subject: &EdgeRef,
        flags: EdgeProvenanceFlags,
    ) -> Result<()> {
        let key_out = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        let key_in = Store::encode_edge_key(&subject.target, subject.kind, &subject.source);

        let existing = self
            .edges_out
            .get(wtxn, &key_out)?
            .map(|value| value.to_vec())
            .ok_or(Error::EdgeNotFound)?;
        let mut value = match existing.len() {
            EDGE_VALUE_SEMANTIC_LEN | EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => {
                let mut value = existing;
                value.resize(EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 0);
                value
            }
            EDGE_VALUE_STRUCTURAL_LEN => {
                return Err(Error::Claim(ClaimError::ProvenanceOnStructuralEdge {
                    kind: subject.kind as u8,
                }));
            }
            _ => return Err(Error::CorruptedIndex("edge value")),
        };
        value[24] = flags.confirmation_status as u8;
        value[25] = flags.actor_class as u8;

        self.edges_out.put(wtxn, &key_out, &value)?;
        self.edges_in.put(wtxn, &key_in, &value)?;
        Ok(())
    }
    fn port_edge_clear_provenance(&self, wtxn: &mut RwTxn<'_>, subject: &EdgeRef) -> Result<bool> {
        let key_out = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        let key_in = Store::encode_edge_key(&subject.target, subject.kind, &subject.source);

        let existing = self
            .edges_out
            .get(wtxn, &key_out)?
            .map(|value| value.to_vec())
            .ok_or(Error::EdgeNotFound)?;
        let value = match existing.len() {
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => {
                let mut value = existing;
                value.truncate(EDGE_VALUE_SEMANTIC_LEN);
                value
            }
            EDGE_VALUE_SEMANTIC_LEN => return Ok(false),
            EDGE_VALUE_STRUCTURAL_LEN => {
                return Err(Error::Claim(ClaimError::ProvenanceOnStructuralEdge {
                    kind: subject.kind as u8,
                }));
            }
            _ => return Err(Error::CorruptedIndex("edge value")),
        };

        self.edges_out.put(wtxn, &key_out, &value)?;
        self.edges_in.put(wtxn, &key_in, &value)?;
        Ok(true)
    }
}

impl super::EdgeStoreReadiness for crate::Vault {
    fn port_blocks_insert(
        &self,
        txn: &mut RwTxn<'_>,
        from: crate::EntityId,
        to: crate::EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<()> {
        crate::code_memory::validate_blocks_insert(self, txn, from, to, context)?;
        let kind = crate::EdgeKind::Blocks;
        let weight = kind
            .default_weight()
            .ok_or(Error::InvariantViolation("blocks weight"))?;
        let at = super::recorded_at_in_txn(&self.store, txn)?;
        let value =
            crate::edge::encode_edge_value(kind, weight, at, crate::affect::Vad::NEUTRAL, None)?;
        self.store
            .edges_out
            .put(txn, &Store::encode_edge_key(&from, kind, &to), &value)?;
        self.store
            .edges_in
            .put(txn, &Store::encode_edge_key(&to, kind, &from), &value)?;
        crate::ppr::invalidate_ppr_for_edge(&self.store, txn, &from, &to)?;
        crate::ppr::increment_graph_version(&self.store, txn)
    }
    fn port_blocks_remove(
        &self,
        txn: &mut RwTxn<'_>,
        from: crate::EntityId,
        to: crate::EntityId,
        context: crate::code_memory::BlocksWriteContext<'_>,
    ) -> Result<bool> {
        crate::code_memory::validate_blocks_retirement(self, txn, context)?;
        let kind = crate::EdgeKind::Blocks;
        let existed = self
            .store
            .edges_out
            .delete(txn, &Store::encode_edge_key(&from, kind, &to))?;
        self.store
            .edges_in
            .delete(txn, &Store::encode_edge_key(&to, kind, &from))?;
        if existed {
            crate::ppr::invalidate_ppr_for_edge(&self.store, txn, &from, &to)?;
            crate::ppr::increment_graph_version(&self.store, txn)?;
        }
        Ok(existed)
    }
}
