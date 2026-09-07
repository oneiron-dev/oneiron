use super::*;
use crate::gate::doors::gate_decision_matches_pending_candidate;

#[test]
fn external_effect_pending_lookup_stops_at_uncommitted_match() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    // Build a real candidate without committing it, then pin its ledger order.
    let mut expected = {
        let mut wtxn = vault.store.env.write_txn()?;
        coalescing_effect_record(&vault.store, &mut wtxn, &effect, &policy)?
    };
    assert_eq!(expected.outcome, "pending");
    expected.decision_id = GateDecisionId::from_bytes([0x41; 16]);
    expected.created_at = 1;
    let mut decoy = expected.clone();
    decoy.decision_id = GateDecisionId::from_bytes([0x40; 16]);
    decoy.actor_ref = Some("other-sender".to_owned());
    let mut later_match = expected.clone();
    later_match.decision_id = GateDecisionId::from_bytes([0x42; 16]);

    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decoy)?;
        assert_eq!(
            vault.store.find_gate_decision_id_in_txn(&*wtxn, |record| {
                gate_decision_matches_pending_candidate(record, &expected)
            })?,
            None,
            "sharing the diff and policy hash is not an exact match",
        );
        vault.store.append_gate_decision_in_txn(wtxn, &expected)?;
        vault
            .store
            .append_gate_decision_in_txn(wtxn, &later_match)?;
        // A collect-first or continue-after-match lookup would decode this row.
        let mut malformed_key = b"gate_decision:v0:".to_vec();
        malformed_key.extend_from_slice(&[0x43; 16]);
        vault
            .store
            .vault_meta
            .put(wtxn, &malformed_key, b"not-msgpack")?;

        let mut visited = Vec::new();
        assert_eq!(
            vault.store.find_gate_decision_id_in_txn(&*wtxn, |record| {
                visited.push(record.decision_id);
                gate_decision_matches_pending_candidate(record, &expected)
            })?,
            Some(expected.decision_id),
        );
        assert_eq!(visited, vec![decoy.decision_id, expected.decision_id]);
        // Pin the production Pending call as well as the helper. Neither the
        // matching row nor the malformed suffix is committed in this txn.
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?,
            expected,
        );

        let mut full_scan_count = 0;
        assert!(matches!(
            vault.store.for_each_gate_decision_in_txn(&*wtxn, |_| {
                full_scan_count += 1;
                Ok(())
            }),
            Err(Error::CorruptedIndex("gate decision ledger")),
        ));
        assert_eq!(
            full_scan_count, 3,
            "full iteration still reaches the suffix"
        );
        assert!(matches!(
            vault.store.find_gate_decision_id_in_txn(&*wtxn, |_| false),
            Err(Error::CorruptedIndex("gate decision ledger")),
        ));
        // The cursor is gone. Remove only the malformed fixture and verify
        // lookup neither appended a retry nor removed or rewrote existing rows.
        assert!(vault.store.vault_meta.delete(wtxn, &malformed_key)?);
        assert_eq!(
            coalescing_ledger_in_txn(&vault.store, &*wtxn)?,
            vec![decoy.clone(), expected.clone(), later_match.clone()],
        );
        Ok(())
    })?;
    Ok(())
}
