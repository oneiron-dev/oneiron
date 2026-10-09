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
