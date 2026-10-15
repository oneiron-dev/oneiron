//! Focused pure-leaf tests. Integration must export the module to discover them.

use super::*;

fn id(n: u32) -> EntityId {
    let mut bytes = [0; 16];
    bytes[0] = 1;
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    EntityId::from_bytes(bytes).expect("fixture ID")
}

fn meta(version: u64) -> CommunityCacheMeta {
    CommunityCacheMeta {
        schema: 0,
        graph_version: version,
        gamma: 1.0,
        generated_at: 42,
    }
}

fn fixture() -> CommunitySnapshot {
    let mut fine = vec![(1..=8).map(id).collect(), (9..=16).map(id).collect()];
    fine.extend((17..=100).map(|n| vec![id(n)]));
    let mut coarse = vec![(1..=16).map(id).collect()];
    coarse.extend((17..=100).map(|n| vec![id(n)]));
    CommunitySnapshot::from_partitions(meta(7), &fine, &coarse).expect("snapshot")
}

#[test]
fn cache_roundtrip_uses_only_pinned_logical_keys_and_fixed_metadata() {
    let snapshot = fixture();
    let rows = snapshot.encode_rows().expect("rows");
    assert!(
        rows.keys()
            .all(|k| k.starts_with(PPR_COMMUNITY_CACHE_PREFIX.as_bytes()))
    );
    let value = &rows[META_KEY.as_bytes()];
    assert_eq!(value.len(), 29);
    assert_eq!(&value[21..29], &100_u64.to_le_bytes());
    assert_eq!(&value[1..9], &7_u64.to_le_bytes());
    assert_eq!(&value[9..13], &1.0_f32.to_le_bytes());
    let key = format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", id(1).to_hex()).into_bytes();
    let m = snapshot.nodes[&id(1)];
    assert_eq!(&rows[&key][..16], m.fine.as_bytes());
    assert_eq!(&rows[&key][16..], m.coarse.as_bytes());
    let mut rows: Vec<_> = rows.into_iter().collect();
    rows.reverse();
    assert_eq!(
        CommunitySnapshot::decode_rows(&rows, 7, 100).expect("decode"),
        snapshot
    );
    assert_eq!(
        CommunitySnapshot::decode_rows(&rows, 8, 100),
        Err(CommunityError::Version)
    );
    assert!(CommunitySnapshot::decode_rows(&rows, 7, 99).is_err());
    assert!(PprCommunityCache::new(&snapshot, 8).is_err());
}

#[test]
fn cache_rejects_truncation_unknown_schema_duplicates_and_torn_rows() {
    let snapshot = fixture();
    let rows: Vec<_> = snapshot.encode_rows().expect("rows").into_iter().collect();
    for i in 0..rows.len() {
        let mut bad = rows.clone();
        bad[i].1.pop();
        assert!(
            CommunitySnapshot::decode_rows(&bad, 7, 100).is_err(),
            "truncated row {i}"
        );
        let mut missing = rows.clone();
        missing.remove(i);
        assert!(
            CommunitySnapshot::decode_rows(&missing, 7, 100).is_err(),
            "missing row {i}"
        );
    }
    let mut duplicate = rows.clone();
    duplicate.push(rows[0].clone());
    assert!(CommunitySnapshot::decode_rows(&duplicate, 7, 100).is_err());
    let mut bad = rows.clone();
    bad.iter_mut()
        .find(|(k, _)| k.as_slice() == META_KEY.as_bytes())
        .expect("meta")
        .1[0] = 1;
    assert!(CommunitySnapshot::decode_rows(&bad, 7, 100).is_err());
    let mut bad = rows;
    bad.push((b"ppr_community_cache:v0:unknown".to_vec(), vec![]));
    assert!(CommunitySnapshot::decode_rows(&bad, 7, 100).is_err());
}

#[test]
fn cache_rejects_noncanonical_members_reserved_ids_and_cross_level_aliasing() {
    let snapshot = fixture();
    let rows = snapshot.encode_rows().expect("rows");
    let mut reversed: Vec<_> = rows.clone().into_iter().collect();
    let (_, members) = reversed
        .iter_mut()
        .find(|(k, v)| k.starts_with(b"ppr_community_cache:v0:members:") && v.len() > 16)
        .expect("members");
    members.reverse();
    assert!(CommunitySnapshot::decode_rows(&reversed, 7, 100).is_err());
    let mut reserved: Vec<_> = rows.into_iter().collect();
    let (key, _) = reserved
        .iter_mut()
        .find(|(k, _)| k.starts_with(b"ppr_community_cache:v0:node:"))
        .expect("node");
    *key = format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", "0".repeat(32)).into_bytes();
    assert!(CommunitySnapshot::decode_rows(&reserved, 7, 100).is_err());
    let mut alias = snapshot;
    let coarse = alias.nodes[&id(1)].coarse;
    for n in 1..=8 {
        alias.nodes.get_mut(&id(n)).expect("node").fine = coarse;
    }
    assert!(alias.validate(7).is_err());
    assert!(
        CommunitySnapshot::from_partitions(
            meta(1),
            &[vec![id(1), id(2)]],
            &[vec![id(1)], vec![id(2)]]
        )
        .is_err()
    );
}

#[test]
fn metadata_graph_count_is_writer_derived_bounded_and_full_decode_cross_checked() {
    let snapshot = fixture();
    let mut rows = snapshot.encode_rows().expect("rows");
    let raw = rows.get_mut(META_KEY.as_bytes()).expect("metadata");
    let (_, count) = CommunityCacheMeta::decode_row(raw, 100).expect("metadata");
    assert_eq!(count, snapshot.nodes.len());
    raw[21..29].copy_from_slice(&99_u64.to_le_bytes());
    assert!(CommunityCacheMeta::decode_row(raw, 100).is_ok());
    let rows: Vec<_> = rows.into_iter().collect();
    assert_eq!(
        CommunitySnapshot::decode_rows(&rows, 7, 100),
        Err(CommunityError::Cache)
    );
    for count in [101_u64, u64::MAX] {
        let mut raw = snapshot.encode_rows().expect("rows")[META_KEY.as_bytes()].clone();
        raw[21..29].copy_from_slice(&count.to_le_bytes());
        assert!(CommunityCacheMeta::decode_row(&raw, 100).is_err());
    }
}
