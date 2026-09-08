use super::*;
use heed::{DatabaseFlags, Env, EnvOpenOptions};

fn env_with_db(flags: DatabaseFlags) -> (tempfile::TempDir, Env, Database<Bytes, Bytes>) {
    let dir = tempfile::tempdir().expect("overlay db test temp dir");
    // SAFETY: `dir` is a freshly created, unique temp directory owned by
    // this test; no other `Env` maps the same path, this is the sole
    // opener, and the handle outlives the returned databases. heed's
    // `open` is unsafe only against concurrent/duplicate mappings of one
    // path, which cannot occur here.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(16 * 1024 * 1024)
            .max_dbs(1)
            .open(dir.path())
            .expect("open overlay db test env")
    };
    let mut wtxn = env.write_txn().expect("open setup write txn");
    let db = env
        .database_options()
        .types::<Bytes, Bytes>()
        .name("rows")
        .flags(flags)
        .create(&mut wtxn)
        .expect("create overlay db test database");
    wtxn.commit().expect("commit overlay db setup");
    (dir, env, db)
}

fn commit_put(
    overlay: &Arc<SessionOverlay>,
    keyspace: OverlayKeyspace,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    let segment = overlay.install_txn_segment()?;
    overlay.put(keyspace, key, value)?;
    segment.commit()
}

#[test]
fn composed_view_reuses_one_snapshot_across_successive_gets() -> Result<()> {
    let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
    let overlay = SessionOverlay::new(4096);
    commit_put(&overlay, OverlayKeyspace::Entities, b"a", b"old")?;
    let snapshot = Arc::new(overlay.snapshot()?);
    let view = OverlayDb::composed(base, overlay.clone(), snapshot, OverlayKeyspace::Entities);
    let rtxn = env.read_txn()?;

    assert_eq!(view.get(&rtxn, b"a")?.as_deref(), Some(&b"old"[..]));
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<()> {
                let segment = overlay.install_txn_segment()?;
                overlay.delete(OverlayKeyspace::Entities, b"a")?;
                overlay.put(OverlayKeyspace::Entities, b"b", b"new")?;
                segment.commit()
            })
            .join()
            .expect("overlay apply thread panicked")
    })?;
    assert_eq!(view.get(&rtxn, b"a")?.as_deref(), Some(&b"old"[..]));
    assert_eq!(view.get(&rtxn, b"b")?, None);
    Ok(())
}

#[test]
fn composed_delete_only_stages_tombstones_for_visible_keys() -> Result<()> {
    let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
    let mut setup_txn = env.write_txn()?;
    base.put(&mut setup_txn, b"base", b"present")?;
    setup_txn.commit()?;

    let overlay = SessionOverlay::new(4096);
    let snapshot = Arc::new(overlay.snapshot()?);
    let view = OverlayDb::composed(base, overlay.clone(), snapshot, OverlayKeyspace::Entities);
    let mut wtxn = env.write_txn()?;
    let segment = overlay.install_txn_segment()?;

    assert!(!view.delete(&mut wtxn, b"absent")?);
    let after_absent = overlay.snapshot()?;
    assert_eq!(
        after_absent
            .merge_plan(OverlayKeyspace::Entities, |_| true)
            .rows
            .len(),
        0
    );
    assert_eq!(after_absent.bytes_used(), 0);

    assert!(view.delete(&mut wtxn, b"base")?);
    let after_present = Arc::new(overlay.snapshot()?);
    assert_eq!(
        after_present
            .merge_plan(OverlayKeyspace::Entities, |_| true)
            .rows
            .len(),
        1
    );
    let staged_view = OverlayDb::composed(base, overlay, after_present, OverlayKeyspace::Entities);
    assert_eq!(staged_view.get(&wtxn, b"base")?, None);

    wtxn.commit()?;
    segment.commit()?;
    Ok(())
}

#[test]
fn empty_overlay_streams_base_rows_as_borrowed() -> Result<()> {
    const ROW_COUNT: usize = 512;
    let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
    let mut wtxn = env.write_txn()?;
    for index in 0..ROW_COUNT {
        let key = (index as u64).to_be_bytes();
        let value = vec![index as u8; 1024];
        base.put(&mut wtxn, &key, &value)?;
    }
    wtxn.commit()?;

    let overlay = SessionOverlay::new(4096);
    let snapshot = Arc::new(overlay.snapshot()?);
    let view = OverlayDb::composed(base, overlay, snapshot, OverlayKeyspace::Entities);
    let rtxn = env.read_txn()?;
    let mut borrowed_count = 0_usize;
    let mut owned_count = 0_usize;
    for row in view.iter(&rtxn)? {
        let (key, value) = row?;
        if matches!(key, Cow::Borrowed(_)) && matches!(value, Cow::Borrowed(_)) {
            borrowed_count += 1;
        } else {
            owned_count += 1;
        }
    }
    assert_eq!(borrowed_count, ROW_COUNT);
    assert_eq!(owned_count, 0);
    Ok(())
}

#[test]
fn absent_exact_duplicate_delete_keeps_present_sibling() -> Result<()> {
    let (_dir, env, base) = env_with_db(DatabaseFlags::DUP_SORT);
    let key = b"term";
    let mut present = vec![0_u8; 16];
    present[15] = 7;
    present.extend_from_slice(b"fields-a");
    let mut absent = present[..16].to_vec();
    absent.extend_from_slice(b"fields-b");
    let mut wtxn = env.write_txn()?;
    base.put(&mut wtxn, key, &present)?;
    wtxn.commit()?;

    let overlay = SessionOverlay::new(4096);
    let snapshot = Arc::new(overlay.snapshot()?);
    let view = OverlayDb::composed(
        base,
        overlay.clone(),
        snapshot,
        OverlayKeyspace::TextPostings,
    );
    let mut wtxn = env.write_txn()?;
    let segment = overlay.install_txn_segment()?;
    assert!(!view.delete_one_duplicate(&mut wtxn, key, &absent)?);
    wtxn.commit()?;
    segment.commit()?;

    let fresh = OverlayDb::composed(
        base,
        overlay.clone(),
        Arc::new(overlay.snapshot()?),
        OverlayKeyspace::TextPostings,
    );
    let rtxn = env.read_txn()?;
    let values = fresh
        .get_duplicates(&rtxn, key)?
        .expect("present duplicate survives")
        .map(|row| row.map(|(_, value)| value.into_owned()))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], present);
    Ok(())
}

#[test]
fn merged_duplicate_stream_rejects_out_of_order_entity_ids() -> Result<()> {
    type EmptyBase = std::iter::Empty<heed::Result<(&'static [u8], &'static [u8])>>;

    let mut higher = vec![0_u8; 16];
    higher[15] = 2;
    higher.push(0);
    let mut lower = vec![0_u8; 16];
    lower[15] = 1;
    lower.push(0);
    let snapshot = Arc::new(SessionOverlay::new(4096).snapshot()?);
    let inner: MergedRows<'static, EmptyBase> = MergedRows::new(
        None,
        SnapshotMergePlan {
            clear_base: true,
            deleted_keys: BTreeSet::new(),
            rows: vec![SnapshotMergeRow::Duplicate {
                key: b"term".to_vec(),
                identity: duplicate_identity(&lower).to_vec(),
                deleted: BTreeSet::new(),
                present: Some(lower),
            }],
        },
        Direction::Forward,
        snapshot,
    );
    let merged = PrefetchedMergedRows {
        first: Some((Cow::Owned(b"term".to_vec()), Cow::Owned(higher))),
        inner,
        last_duplicate_identity: None,
    };

    let rows = merged.collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    match &rows[0] {
        Ok((key, value)) => {
            assert_eq!(key.as_ref(), b"term");
            assert_eq!(value.len(), 17);
            assert_eq!(value[15], 2);
        }
        Err(other) => panic!("first duplicate unexpectedly failed: {other}"),
    }
    match &rows[1] {
        Err(Error::CorruptedIndex(message)) => {
            assert_eq!(*message, "duplicate posting entries for one entity");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("out-of-order duplicate unexpectedly emitted"),
    }
    Ok(())
}
