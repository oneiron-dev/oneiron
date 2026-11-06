//! Native custody preparation against a caller-owned authority snapshot.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{
    CustodyPieces, CustodyTransition, RelayedInput, completed_custody_groups_in_txn,
    holds_custody_carrier_in_txn,
};
use crate::world_keys::MachineSecret;

use super::{
    input_awaits, input_row, stage_custody_inputs_in_txn, stage_custody_pieces_in_txn, witness,
};

pub(in crate::sync) struct CustodyInputBatch {
    machine: EntityId,
    due: Vec<RelayedInput>,
}

impl CustodyInputBatch {
    pub(in crate::sync) fn prepare_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        rows: &[(String, Vec<u8>)],
    ) -> Result<Option<Self>> {
        let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
            return Ok(None);
        };
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let mut due: Vec<RelayedInput> = Vec::new();
        for (map_key, bytes) in rows {
            let Some(input) = RelayedInput::decode(bytes) else {
                continue;
            };
            let key = input.row_key();
            if *map_key == input_row(&key)
                && input_awaits(&fold, machine, &input)
                && witness::input_genuine(vault, txn, &input)?
                && witness::input_slot_open(vault, txn, &key)?
            {
                due.push(input);
            }
        }
        if due.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self { machine, due }))
    }

    pub(in crate::sync) fn stage_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<usize> {
        stage_custody_inputs_in_txn(vault, wtxn, self.machine, &self.due)
    }
}

pub(in crate::sync) struct CustodyPieceBatch {
    arrived: Vec<CustodyTransition>,
    whole: Vec<(CustodyPieces, Option<zeroize::Zeroizing<Vec<u8>>>)>,
}

impl CustodyPieceBatch {
    pub(in crate::sync) fn prepare_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        window: &str,
        rows: &[(String, Vec<u8>)],
        skip_held: bool,
        secret: Option<&MachineSecret>,
    ) -> Result<Self> {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let mut arrived = Vec::new();
        for (map_key, bytes) in rows {
            let transition = match CustodyTransition::decode(bytes) {
                Ok(transition) if transition.row_key() == *map_key => transition,
                _ => {
                    tracing::warn!(window, key = %map_key, "custody transition malformed; left out");
                    continue;
                }
            };
            if skip_held && holds_custody_carrier_in_txn(vault, txn, &transition)? {
                continue;
            }
            if let Err(error) = transition.verify(&fold) {
                tracing::warn!(window, key = %map_key, error = %error, "custody transition does not stand on its request here; left out");
                continue;
            }
            arrived.push(transition);
        }
        // A piece alone has no custody effect: only a group the pieces
        // make with those kept here, whole and standing as one, does.
        let mut whole = Vec::new();
        for group in completed_custody_groups_in_txn(vault, txn, &arrived)? {
            if group.verify(&fold).is_err() {
                continue;
            }
            // A value sealed under its carrier key (FIX 7402) opens once
            // that key is answered here; until then the group is kept.
            let value = match (secret, fold.vault_id) {
                (Some(secret), Some(vault_id)) => {
                    vault.open_custody_value(&group, &vault_id, secret)
                }
                _ => None,
            };
            whole.push((group, value));
        }
        Ok(Self { arrived, whole })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.arrived.is_empty()
    }

    pub(in crate::sync) fn stage_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<usize> {
        stage_custody_pieces_in_txn(vault, wtxn, &self.arrived, &self.whole)
    }
}
