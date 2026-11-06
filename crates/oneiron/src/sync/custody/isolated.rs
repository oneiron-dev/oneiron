//! An isolated window's raw custody carriers, judged on its root writer.

use super::{
    CUSTODY_MAP, CustodyInputBatch, CustodyPieceBatch, ExportOutputBatch, INPUT_ROW_PREFIX,
    WitnessBatch, export_output, holds_custody_map, witness,
};
use crate::sync::types::WindowKey;
use crate::world_keys::MachineSecret;
use crate::{Result, Vault};
use loro::{LoroDoc, LoroValue, ValueOrContainer};

pub(in crate::sync) struct IsolatedCustody {
    inputs: Vec<(String, Vec<u8>)>,
    witnesses: Vec<(String, Vec<u8>)>,
    outputs: Vec<(String, Vec<u8>)>,
    pieces: Vec<(String, Vec<u8>)>,
    secret: Option<MachineSecret>,
}

impl IsolatedCustody {
    pub(in crate::sync) fn prepare(vault: &Vault, doc: &LoroDoc, key: &WindowKey) -> Option<Self> {
        if key.world().is_some() || !holds_custody_map(doc) {
            return None;
        }
        let mut rows = Vec::new();
        doc.get_map(CUSTODY_MAP).for_each(|map_key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && export_output::parts::part_row_collection_admitted(&bytes)
            {
                rows.push((map_key.to_owned(), bytes.to_vec()));
            }
        });
        let (inputs, rows): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|(key, _)| key.starts_with(INPUT_ROW_PREFIX));
        let (witnesses, rows): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|(key, _)| key.starts_with(witness::WITNESS_ROW_PREFIX));
        let (outputs, pieces): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|(key, _)| key.starts_with(export_output::EXPORT_OUTPUT_ROW_PREFIX));
        Some(Self {
            inputs,
            witnesses,
            outputs,
            pieces,
            secret: vault.machine_secret_outside_txn().ok(),
        })
    }

    pub(in crate::sync) fn stage_in_txn(
        &self,
        vault: &Vault,
        doc: &LoroDoc,
        key: &WindowKey,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<usize> {
        let mut written = 0;
        if let Some(inputs) = CustodyInputBatch::prepare_in_txn(vault, txn, &self.inputs)? {
            written += inputs.stage_in_txn(vault, txn)?;
        }
        if let Some(witnesses) = WitnessBatch::prepare_in_txn(vault, txn, &self.witnesses)? {
            written += witnesses.stage_in_txn(vault, txn)?;
        }
        written += ExportOutputBatch::prepare_in_txn(vault, txn, doc, &self.outputs)?
            .stage_in_txn(vault, txn)?;
        if !self.pieces.is_empty() {
            written += CustodyPieceBatch::prepare_in_txn(
                vault,
                txn,
                key.as_str(),
                &self.pieces,
                false,
                self.secret.as_ref(),
            )?
            .stage_in_txn(vault, txn)?;
        }
        Ok(written)
    }
}
