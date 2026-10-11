//! The lookup behind a claim write's receipt: the newest decision about a
//! claim among the newest ledger rows, found through the claim index and
//! authenticated on read.

use super::*;

fn lookup(vault: &Vault, claim: &[u8; 16], scan: usize) -> Result<Option<GateDecisionId>> {
    vault.store.latest_gate_decision_for_claim(claim, scan)
}

/// What the page reader picks: every row of the window decoded, the claim's
/// largest decision id.
fn page_pick(vault: &Vault, claim: &[u8; 16], scan: usize) -> Result<Option<GateDecisionId>> {
    Ok(vault
        .store
        .gate_decisions(scan)?
        .into_iter()
        .filter(|record| record.claim_id.as_ref() == Some(claim))
        .map(|record| record.decision_id)
        .max_by_key(|decision_id| decision_id.to_hex()))
}

/// Rewrites one stored ledger row in place.
fn edit_row(
    vault: &Vault,
    decision_id: GateDecisionId,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Result<()> {
    let key = gate_decision_key(decision_id);
    let mut wtxn = vault.store.env.write_txn()?;
    let mut raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .expect("ledger row")
        .into_owned();
    edit(&mut raw);
    vault.store.vault_meta.put(&mut wtxn, &key, &raw)?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn the_claim_lookup_picks_the_receipt_the_page_reader_picks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path().join("vault"), VaultConfig::device())?;
    let claims = [[0x41; 16], [0x42; 16], [0x43; 16], [0x44; 16]];
    let id = |n| synthetic_gate_decision_id(0x98, n);
    // Twelve receipts spread over the first three claims, then one bound to
    // no claim; the fourth claim has none.
    let mut rows: Vec<_> = (1..=12u64)
        .map(|n| {
            claim_bound_gate_decision(
                id(n),
                n,
                &claims[usize::try_from(n * 7 % 3).expect("index")],
            )
        })
        .collect();
    rows.push(gate_decision(id(13), 13, None));
    append_gate_decisions(&vault, &rows)?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?
        );
    }
    for indexed in [true, false] {
        if !indexed {
            strip_claim_index_and_flag(&vault)?;
        }
        for scan in [0, 1, 2, 3, 5, 13, 512] {
            for claim in &claims {
                assert_eq!(
                    lookup(&vault, claim, scan)?,
                    page_pick(&vault, claim, scan)?,
                    "claim {:#04x}, window {scan}, indexed {indexed}",
                    claim[0]
                );
            }
        }
    }
    Ok(())
}

/// Astra on #1398: D3 is claim A's newest receipt, D2 is B's, D1 is A's
/// older one. D3's header is changed to name B; its key and body still say A.
/// A's lookup must fail, not fall back to D1.
#[test]
fn a_receipt_whose_header_names_another_claim_fails_its_own_claims_lookup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path().join("vault"), VaultConfig::device())?;
    let (a, b) = ([0x3a; 16], [0x3b; 16]);
    let id = |n| synthetic_gate_decision_id(0x96, n);
    append_gate_decisions(
        &vault,
        &[
            claim_bound_gate_decision(id(1), 1, &a),
            claim_bound_gate_decision(id(2), 2, &b),
            claim_bound_gate_decision(id(3), 3, &a),
        ],
    )?;
    assert_eq!(lookup(&vault, &a, 512)?, Some(id(3)));
    edit_row(&vault, id(3), |raw| raw[5..21].copy_from_slice(&b))?;
    assert!(
        lookup(&vault, &a, 512).is_err(),
        "A's newest receipt fails to authenticate"
    );
    // B's own receipt still authenticates: a corrupt row of another claim
    // does not fail a lookup.
    assert_eq!(lookup(&vault, &b, 512)?, Some(id(2)));
    // Without a complete index the page reader decodes the window, and fails.
    strip_claim_index_and_flag(&vault)?;
    assert!(lookup(&vault, &a, 512).is_err());
    Ok(())
}

/// Astra on #1398: claim A's only receipt is the oldest row of the window and
/// fails authentication. A lookup that read again after the failure would see
/// the window moved past it by one newer receipt, and answer none. The
/// failure stands unless its own snapshot shows the row's key retired.
#[test]
fn a_receipt_that_fails_authentication_fails_the_lookup_though_the_window_moves() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(
        dir.path().join("vault"),
        VaultConfig::device(),
    )?);
    let (a, b) = ([0x3c; 16], [0x3d; 16]);
    let id = |n| synthetic_gate_decision_id(0x97, n);
    let mut rows = vec![claim_bound_gate_decision(id(1), 1, &a)];
    rows.extend((2..=4).map(|n| claim_bound_gate_decision(id(n), n, &b)));
    append_gate_decisions(&vault, &rows)?;
    assert_eq!(lookup(&vault, &a, 4)?, Some(id(1)));
    // One ciphertext byte flipped; the header still names A.
    edit_row(&vault, id(1), |raw| {
        let last = raw.len() - 1;
        raw[last] ^= 1;
    })?;
    let writer = Arc::clone(&vault);
    arm_before_gate_claim_reread(move || {
        append_gate_decisions(&writer, &[claim_bound_gate_decision(id(5), 5, &b)])
            .expect("a newer receipt");
    });
    assert!(lookup(&vault, &a, 4).is_err(), "the failure stands");
    Ok(())
}
