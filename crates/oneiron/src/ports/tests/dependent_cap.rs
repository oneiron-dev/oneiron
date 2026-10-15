//! A source with more dependents than the old 100,000-row scan cap reads and
//! erases without a count refusal (rule 5; Sol R2 F11 on #1465).

use crate::config::VaultConfig;
use crate::error::Result;
use crate::ports::{DependencyIndex, SourceSpan};
use crate::registry::ENTITY_TYPE_TURN;
use crate::{EntityId, TimeRange};

/// One past the cap `scan_dependents` refused at.
const PAST_THE_OLD_CAP: u32 = 100_001;

/// Repro: at 12b3df9a8 both the dependency listing and the user delete of
/// such a source fail with `IndexOverflow("source dependents")`, and the
/// source is never erased.
#[test]
fn a_source_past_the_old_dependent_scan_cap_reads_and_erases() -> Result<()> {
    let mut config = VaultConfig::device();
    config.map_size = 4 << 30;
    let (_tmp, vault) = crate::test_util::open_test_vault_with(config);
    let source = crate::test_util::entity(0x5C);
    vault.put_entity(
        &source,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&serde_json::json!({ "txt": "a busy source" })).expect("body"),
    )?;
    let span = SourceSpan {
        document: source,
        frontier: vault
            .read_entity_header(&source)?
            .expect("source header")
            .learned_at,
    };
    let dependents: Vec<EntityId> = (0..PAST_THE_OLD_CAP)
        .map(|n| {
            let mut bytes = [0x5D; 16];
            bytes[12..].copy_from_slice(&n.to_be_bytes());
            EntityId::from_bytes(bytes)
        })
        .collect::<Result<_>>()?;
    let mut txn = vault.store.env.write_txn()?;
    for dependent in &dependents {
        crate::ports::record_dependency_in_txn(&vault.store, &mut txn, span, dependent)?;
    }
    txn.commit()?;

    let txn = vault.store.env.read_txn()?;
    let listed = vault.store.port_dependency_list_by_source(&txn, span)?;
    assert_eq!(
        listed.len(),
        dependents.len(),
        "a read lists every dependent"
    );
    drop(txn);

    assert!(vault.delete_entity(&source)?, "the erase is never refused");
    let txn = vault.store.env.read_txn()?;
    for dependent in &dependents {
        assert!(
            crate::ports::stale_in_txn(&vault.store, &txn, dependent)?,
            "every dependent is withdrawn once the delete returns"
        );
    }
    Ok(())
}
