//! A short tray list reads a short run of the tray, never the whole tray
//! (F13 H80).

use super::*;
use crate::config::VaultConfig;
use crate::error::Result;
use crate::side_table::SideTableDbs;
use crate::store::GateDecisionId;

fn pending(claim: u8, created_at: u64) -> PendingGateConsentRecord {
    PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id: [claim; 16],
        decision_id: GateDecisionId::from_bytes([claim; 16]),
        created_at,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
        reason_codes: vec!["gate.pending.test".to_owned()],
        dreamer_run_id: None,
    }
}

#[test]
fn a_one_consent_list_never_reads_the_rest_of_the_tray() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), VaultConfig::device())?;
    vault.with_write_txn(|wtxn| {
        for (claim, created_at) in [(0x71, 1), (0x72, 2), (0x73, 3)] {
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &pending(claim, created_at))?;
        }
        // The newest consent's row no longer reads: only a list that reaches
        // it can fail.
        let key = [PENDING_GATE_CONSENT_KEY_PREFIX, &[0x73; 16]].concat();
        vault.store.side_vault_meta().put(wtxn, &key, &[0xC1])?;
        Ok(())
    })?;

    let listed = vault.store.pending_gate_consents(1)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].claim_id, [0x71; 16]);
    // A list that asks for every consent reaches the unreadable row and says
    // so; the bound never hides it.
    assert!(vault.store.pending_gate_consents(usize::MAX).is_err());
    Ok(())
}
