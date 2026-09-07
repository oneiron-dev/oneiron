//! Archive visibility must not turn the bounded beam into a full graph walk.

use super::*;
use crate::Vault;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

#[test]
fn archived_connectors_preserve_early_stop_and_never_become_matches() -> Result<()> {
    const NODES: usize = 64;
    let dir = tempfile::tempdir()?;
    let config = VaultConfig {
        dimensions: 4,
        embedding_model: Some("test/model@v1".to_owned()),
        map_size: 64 * 1024 * 1024,
        hnsw: crate::config::HnswConfig {
            ef_search: 2,
            ..crate::config::HnswConfig::default()
        },
        ..VaultConfig::device()
    };
    let vault = Vault::open(dir.path(), config)?;
    let ids: Vec<_> = (0..NODES).map(|_| EntityId::now()).collect();
    for id in &ids {
        vault.put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }
    let mut txn = vault.store.env.write_txn()?;
    for (index, id) in ids.iter().enumerate() {
        let vector: [f32; 4] = match index {
            1 => [1.0, 2.0, 0.0, 0.0],
            2 => [1.0, 0.0, 0.0, 0.0],
            3 => [1.0, 0.1, 0.0, 0.0],
            _ => [0.0, 1.0, 0.0, 0.0],
        };
        let bytes: Vec<_> = vector.iter().flat_map(|v| v.to_le_bytes()).collect();
        vault.store.vectors.put(&mut txn, id.as_bytes(), &bytes)?;
        // Raw visibility fixtures isolate beam behavior from cleanup admission.
        vault.store.sync_state.put(
            &mut txn,
            crate::deletion::archive_tombstone_key(id).as_str(),
            &[5],
        )?;
        let neighbors = match index {
            0 => vec![ids[1], ids[2]],
            1 => vec![ids[4]],
            2 => vec![ids[3]],
            3 => Vec::new(),
            n if n + 1 < NODES => vec![ids[n + 1]],
            _ => Vec::new(),
        };
        write_neighbors(&vault.store, &mut txn, id, &neighbors)?;
    }
    vault
        .store
        .hnsw_meta
        .put(&mut txn, ENTRY_POINT_KEY, ids[0].as_bytes())?;
    vault
        .store
        .hnsw_meta
        .put(&mut txn, COUNT_KEY, &(NODES as u64).to_le_bytes())?;
    txn.commit()?;

    for live_connector_target in [false, true] {
        if live_connector_target {
            let mut txn = vault.store.env.write_txn()?;
            vault.store.sync_state.delete(
                &mut txn,
                crate::deletion::archive_tombstone_key(&ids[3]).as_str(),
            )?;
            txn.commit()?;
        }
        let txn = vault.store.env.read_txn()?;
        let mut ops = 0;
        let found = beam_search(
            &vault.store,
            &txn,
            &[1.0, 0.0, 0.0, 0.0],
            ids[0],
            BeamOptions {
                ef: 2,
                lenient_neighbors: true,
                check_existence: true,
                score_dims: 4,
            },
            4,
            &mut ops,
        )?;
        // Node 1 was queued before closer nodes filled the traversal heap.
        // It must hit early-stop, not expand the long archived tail, even
        // when there are fewer live rows than ef (including zero).
        assert!(ops <= 8, "archived rows disabled early-stop: {ops} ops");
        let expected = if live_connector_target {
            vec![ids[3]]
        } else {
            Vec::new()
        };
        assert_eq!(
            found.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            expected
        );
        let matches = hnsw_search(
            &vault.store,
            &vault.config,
            &txn,
            &[1.0, 0.0, 0.0, 0.0],
            2,
            false,
        )?;
        assert_eq!(
            matches.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            expected
        );
    }
    Ok(())
}
