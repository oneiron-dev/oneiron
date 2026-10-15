//! Scoring constants, blend weights, and dreamer working-set basics.

use super::*;
use crate::store::{
    RetrievalBlendWeightDataWindow, RetrievalBlendWeightTableEntry, RetrievalBlendWeights,
};

#[test]
fn checkpoint_preserves_exact_nonbootstrap_blend_weights() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let copies = crate::test_support::restore_tempdir();
    let expected = RetrievalBlendWeightTableEntry {
        version: 1,
        weights: RetrievalBlendWeights::new(0.125, 0.25, 0.5, 0.125),
        tuned_at: 200,
        provenance: BTreeMap::from([
            ("source".to_owned(), "checkpoint fixture".to_owned()),
            (
                "algorithm".to_owned(),
                "ret010d.reward_weighted_bandit.v1".to_owned(),
            ),
        ]),
        data_window: RetrievalBlendWeightDataWindow::default(),
    };
    let bytes = rmp_serde::to_vec_named(&expected).unwrap();
    vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .put(txn, b"retr_blend_weights:v0:active", &bytes)?;
        Ok(())
    })?;
    assert_eq!(vault.retrieval_blend_weight_table()?, expected);
    let image = dir.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 300)?;
    drop(vault);
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &copies.path().join("restored"),
        embedding_test_config(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        400,
    )?;
    assert_eq!(restored.retrieval_blend_weight_table()?, expected);
    let txn = restored.store.env.read_txn()?;
    assert_eq!(
        restored
            .store
            .vault_meta
            .get(&txn, b"retr_blend_weights:v0:active")?
            .as_deref(),
        Some(bytes.as_slice())
    );
    Ok(())
}
