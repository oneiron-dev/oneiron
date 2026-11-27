//! The executor's append: the replay rows a guarded put writes when the record only grew, flat in
//! the run's length (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT).

use super::*;

/// Writes each of `fenced`'s `count` `family` items whose bytes differ from the item `stored`
/// holds at its index, through the wall; every full key written. An index past the stored count
/// has no stored item and is written.
fn put_changed_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    head_key: &[u8],
    stored: &ReplayHead,
    fenced: &CodeRunReplayRecord,
    family: ReplayFamily,
    count: usize,
) -> Result<Vec<Vec<u8>>> {
    let run = fenced.run_id;
    let stored_items = family_items(dbs, wtxn, &run, family, stored.counts[family.slot()])?;
    let mut keys = Vec::new();
    for index in 0..count {
        let bytes = encode_code_run_replay_item(fenced, family, index)
            .map_err(|error| seam_error(HEADS.decl(), error))?;
        if stored_items.get(index) == Some(&bytes) {
            continue;
        }
        let key = ReplayItemKey {
            run,
            family,
            index: index as u64,
        };
        keys.push(put_admitted_item(dbs, wtxn, head_key, &key, &bytes)?);
    }
    Ok(keys)
}

/// Appends `fenced` onto `stored`, writing only what moved, as [`put_fenced`] lands it: the head,
/// new items, fence-changed and changed calls, and each checkpoint, output and binding whose bytes
/// differ from its stored item. A stored prefix call stays as the wall admitted it (OF-067) while
/// it stands for the live call at its index ([`stored_call_over`]), keeping any reply rows a
/// delivery added since (FIX 5455); a call the record marks changed that it no longer stands for
/// gives way to the live call, the call that ran (L8-23). Every other family is the caller's, as
/// a whole put writes it, so a guarded write that replaces a stored checkpoint or output persists
/// it. The bytes an append writes are flat in the run's length; it reads the stored checkpoint,
/// output and binding items to diff them, and the stored item of each call marked changed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_append(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    stored: &ReplayHead,
    written: &CodeRunReplayRecord,
    fenced: &CodeRunReplayRecord,
) -> Result<Vec<Vec<u8>>> {
    validate_code_run_replay_record(fenced)?;
    let birth = stored.birth_world()?.or(fenced.birth_world);
    let fenced_for_head: Cow<'_, CodeRunReplayRecord> = if birth == fenced.birth_world {
        Cow::Borrowed(fenced)
    } else {
        let mut owned = fenced.clone();
        owned.birth_world = birth;
        Cow::Owned(owned)
    };
    let head = ReplayHead::of(&fenced_for_head)?;
    let run = fenced.run_id;
    let head_key = HEADS.key_bytes(&run);
    note_written(HEADS.put_as_stored(dbs, wtxn, &run, &head)?.len());
    let mut keys = vec![head_key.clone()];
    let fenced_changed = !std::ptr::eq(fenced, written);
    let stored_calls = usize::try_from(stored.counts[0])
        .map_err(|_| Error::CorruptedIndex("code-run replay head count"))?;
    for (index, call) in fenced.bridge_calls.iter().enumerate() {
        let key = ReplayItemKey {
            run,
            family: ReplayFamily::BridgeCalls,
            index: index as u64,
        };
        let new_or_fenced = index >= stored_calls
            || (fenced_changed && written.bridge_calls.get(index) != Some(call));
        let (landed, bytes) = if new_or_fenced {
            (Cow::Borrowed(call), encode_call_item(call)?)
        } else if written.changed_calls.contains(index as u64) {
            let Some(stored_bytes) = ITEMS.get_bytes(dbs, wtxn, &key)? else {
                return Err(Error::CorruptedIndex("code-run replay item index"));
            };
            match stored_call_over(call, decode_call_item(&stored_bytes)?)? {
                Some(kept) => {
                    let bytes = encode_call_item(&kept)?;
                    if bytes == stored_bytes {
                        continue;
                    }
                    (Cow::Owned(kept), bytes)
                }
                None => (Cow::Borrowed(call), encode_call_item(call)?),
            }
        } else {
            continue;
        };
        keys.push(super::fenced::put_call_item(
            dbs,
            wtxn,
            &head_key,
            &key,
            &landed,
            &bytes,
            CallWall::Fenced,
        )?);
    }
    for (family, count) in [
        (ReplayFamily::StepCheckpoints, fenced.step_checkpoints.len()),
        (ReplayFamily::Outputs, fenced.outputs.len()),
        (ReplayFamily::Bindings, fenced.bindings.len()),
    ] {
        keys.extend(put_changed_items(
            dbs, wtxn, &head_key, stored, fenced, family, count,
        )?);
    }
    let counts = [
        u64::try_from(fenced.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
        u64::try_from(fenced.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
        u64::try_from(fenced.outputs.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
        u64::try_from(fenced.bindings.len())
            .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
    ];
    // An append never shrinks the calls, checkpoints or outputs (`appends_to`); only the
    // bindings can, so their stale rows are deleted by key and no other family needs a scan.
    for index in counts[3]..stored.counts[3] {
        let key = ITEMS.key_bytes(&ReplayItemKey {
            run,
            family: ReplayFamily::Bindings,
            index,
        });
        dbs.side_vault_meta().delete(wtxn, &key)?;
        keys.push(key);
    }
    Ok(keys)
}

/// The stored call `kept`, with the reply rows a delivery added to `call` since (FIX 5455), when
/// `kept` still stands for `call`, the live call at its index: the same seq, effect and stamps,
/// and a request replay meets `call`'s request with (L8-23). `None` when the live call replaced
/// it, a pure change or an owner's refire of a resumed step that ran live at its recorded seq.
///
/// # Errors
///
/// A request the side-row wall cannot compare.
fn stored_call_over(
    call: &CodeRunBridgeCall,
    mut kept: CodeRunBridgeCall,
) -> Result<Option<CodeRunBridgeCall>> {
    let stands = call.seq == kept.seq
        && call.effect == kept.effect
        && call.started_at_ms == kept.started_at_ms
        && call.finished_at_ms == kept.finished_at_ms
        && held_row_stands_for(call, &kept)?;
    if !stands {
        return Ok(None);
    }
    if let Some(rows) = wait_rows(&call.outcome) {
        keep_wait_rows(&mut kept.outcome, &rows);
    }
    Ok(Some(kept))
}
