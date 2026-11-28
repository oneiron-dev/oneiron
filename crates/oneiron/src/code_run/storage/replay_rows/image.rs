//! The replay rows as custody and restore read them: one logical row per run under its head key, in
//! its canonical whole bytes, split into head and items again when written back
//! (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT).

use super::*;

/// The replay row's bytes at the full row key `key`, if present: joined for a head, as stored otherwise.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn canonical_bytes_at(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    if !is_row_key(key) {
        return Ok(dbs
            .side_vault_meta()
            .get(txn, key)?
            .map(|bytes| bytes.into_owned()));
    }
    let Some(run) = run_id_of_key(key) else {
        return Ok(dbs
            .side_vault_meta()
            .get(txn, key)?
            .map(|bytes| bytes.into_owned()));
    };
    joined_bytes(dbs, txn, &run)
}

/// The vault_meta row's image value: `None` skips an item key, a head key's canonical bytes,
/// or the value as it rests for any other row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn image_value<'a>(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    value: &'a [u8],
) -> Result<Option<Cow<'a, [u8]>>> {
    if is_item_key(key) {
        return Ok(None);
    }
    if !is_row_key(key) {
        return Ok(Some(Cow::Borrowed(value)));
    }
    Ok(canonical_bytes_at(dbs, txn, key)?.map(Cow::Owned))
}

/// Splits every head-key value in `rows` that starts a record map into its head value plus its
/// item rows, for a restore whose image holds canonical whole bytes. Markers and non-map values
/// stay as they are; a value that does not split stays whole.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn split_image_rows(rows: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    let mut items = Vec::new();
    for (key, value) in rows.iter_mut() {
        if !is_row_key(key) {
            continue;
        }
        if !matches!(value.first(), Some(0x80..=0x8f | 0xde | 0xdf)) {
            continue;
        }
        let Some(run) = run_id_of_key(key) else {
            continue;
        };
        let Ok((_, families)) = split_canonical(value) else {
            continue;
        };
        let Ok(record) = decode(value) else {
            continue;
        };
        let Ok(head) = ReplayHead::of(&record) else {
            continue;
        };
        let Ok(head_bytes) = HEADS.encode_value(&head) else {
            continue;
        };
        *value = head_bytes;
        for (family, elements) in ReplayFamily::ALL.into_iter().zip(families.iter()) {
            for (index, bytes) in elements.iter().enumerate() {
                let Ok(uindex) = u64::try_from(index) else {
                    continue;
                };
                items.push((
                    ITEMS.key_bytes(&ReplayItemKey {
                        run,
                        family,
                        index: uindex,
                    }),
                    bytes.clone(),
                ));
            }
        }
    }
    if !items.is_empty() {
        // The image's rows stay in key order: item keys sort after the heads and among other tables.
        rows.extend(items);
        rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    }
    Ok(())
}

/// Writes `bytes` at the full replay row key `key`, past the wall as stored: split when they start
/// a record map, or a marker with every item of the run deleted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_canonical_bytes_at(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    bytes: &[u8],
) -> Result<()> {
    if !is_row_key(key) {
        note_written(bytes.len());
        return dbs.side_vault_meta().put(wtxn, key, bytes);
    }
    let Some(run) = run_id_of_key(key) else {
        note_written(bytes.len());
        return dbs.side_vault_meta().put(wtxn, key, bytes);
    };
    let starts_map = matches!(bytes.first(), Some(0x80..=0x8f | 0xde | 0xdf));
    if !starts_map {
        dbs.side_vault_meta().put(wtxn, key, bytes)?;
        note_written(bytes.len());
        delete_stale_items(dbs, wtxn, &run, [0, 0, 0, 0])?;
        return Ok(());
    }
    let (_, families) = split_canonical(bytes).map_err(|error| seam_error(HEADS.decl(), error))?;
    let mut counts = [0_u64; 4];
    for (slot, items) in families.iter().enumerate() {
        counts[slot] = u64::try_from(items.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run replay item count"))?;
    }
    let decoded = decode(bytes)?;
    let head = ReplayHead::of(&decoded)?;
    put_raw_head(dbs, wtxn, &run, &head)?;
    for (family, items) in ReplayFamily::ALL.into_iter().zip(families.iter()) {
        for (index, bytes) in items.iter().enumerate() {
            let Ok(uindex) = u64::try_from(index) else {
                return Err(Error::ArithmeticOverflow("code-run replay item index"));
            };
            let key = ReplayItemKey {
                run,
                family,
                index: uindex,
            };
            put_raw_item(dbs, wtxn, &key, bytes)?;
        }
    }
    delete_stale_items(dbs, wtxn, &run, counts)?;
    Ok(())
}
