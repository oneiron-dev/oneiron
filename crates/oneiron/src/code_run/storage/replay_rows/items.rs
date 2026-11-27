//! The replay item rows: their key and value, the side-row wall's admission of one item under its
//! head's origin, and the reads and writes of one run's items (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT).

use super::*;

/// One item row's key: its run, family and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayItemKey {
    /// The run holding the item.
    pub(crate) run: EntityId,
    /// The item's family.
    pub(crate) family: ReplayFamily,
    /// The item's index in its family.
    pub(crate) index: u64,
}

impl ReplayItemKey {
    /// The key prefix for `run`'s `family` items: id16 plus tag, in index order under it.
    pub(crate) fn family_prefix(run: &EntityId, family: ReplayFamily) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.extend_from_slice(run.as_bytes());
        out.push(family.tag());
        out
    }

    /// The key prefix for `run`'s items in every family: id16.
    pub(crate) fn run_prefix(run: &EntityId) -> Vec<u8> {
        run.as_bytes().to_vec()
    }
}

impl SideKey for ReplayItemKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.run.as_bytes());
        out.push(self.family.tag());
        out.extend_from_slice(&self.index.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (run, rest) = bytes.split_at_checked(16)?;
        let (tag, index) = rest.split_at_checked(1)?;
        let family = ReplayFamily::from_tag(tag[0])?;
        let index = u64::from_be_bytes(index.try_into().ok()?);
        let run = EntityId::from_bytes(run.try_into().ok()?).ok()?;
        Some(Self { run, family, index })
    }
}

/// One item row's bytes: one family's element as it sits inside the whole encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayItem(
    /// The element's MessagePack bytes.
    pub(crate) Vec<u8>,
);

impl RawValue for ReplayItem {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.clone())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self(bytes.to_vec()))
    }
}

/// The one MessagePack value an item's `bytes` hold, with nothing after it.
pub(super) fn item_value(bytes: &[u8]) -> Result<rmpv::Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("code-run replay item bytes"))?;
    if !cursor.is_empty() {
        return Err(Error::CorruptedIndex("code-run replay item bytes"));
    }
    Ok(value)
}

/// The bridge call a stored call item's `bytes` hold.
pub(super) fn decode_call_item(bytes: &[u8]) -> Result<CodeRunBridgeCall> {
    decode_bridge_call(&item_value(bytes)?)
}

/// `call`'s item bytes: the call as it sits inside the whole encoding.
pub(super) fn encode_call_item(call: &CodeRunBridgeCall) -> Result<Vec<u8>> {
    encode_code_run_bridge_call_bytes(call).map_err(|error| seam_error(HEADS.decl(), error))
}

/// Whether `masked` still reads as one `family` element, for the wall's check of a masked copy.
fn decodes_item(masked: &[u8], family: ReplayFamily) -> bool {
    let mut cursor = masked;
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    if !cursor.is_empty() {
        return false;
    }
    match family {
        ReplayFamily::BridgeCalls => match decode_bridge_call(&value) {
            Ok(call) => validate_bridge_call(&call).is_ok(),
            Err(_) => false,
        },
        ReplayFamily::StepCheckpoints => decode_step_checkpoint(&value).is_ok(),
        ReplayFamily::Outputs => match decode_raw_output(&value) {
            Ok(output) => validate_raw_output(&output).is_ok(),
            Err(_) => false,
        },
        ReplayFamily::Bindings => match decode_binding(&value) {
            Ok(binding) => CodeRunResultBinding::is_valid_name(&binding.name),
            Err(_) => false,
        },
    }
}

/// The historical lift sweep's admission of the stored replay item `row` at the full key `key`
/// (OF-067): through its run's head origin and checked as one element of its family, as the
/// item's own write admits it. `None` when `key` is not a replay item key.
pub(crate) fn admit_lifted_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    row: &[u8],
) -> Option<Result<Option<Vec<u8>>>> {
    let item = ReplayItemKey::decode_key(key.strip_prefix(ITEMS.decl().prefix)?)?;
    let head_key = HEADS.key_bytes(&item.run);
    Some(crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        &head_key,
        row,
        |masked| decodes_item(masked, item.family),
    ))
}

/// Writes `bytes` raw at the item `key`, past the wall: the caller admitted them already.
pub(super) fn put_raw_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &ReplayItemKey,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let full = ITEMS.key_bytes(key);
    dbs.side_vault_meta().put(wtxn, &full, bytes)?;
    note_written(bytes.len());
    Ok(full)
}

/// Writes one item through its head's wall origin: admitted, or as given when the wall leaves it.
pub(super) fn put_admitted_item(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    head_key: &[u8],
    key: &ReplayItemKey,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let admitted = crate::batch::secret_scan::admit_side_row(
        dbs,
        wtxn,
        &side_table::CODE_RUN_REPLAY,
        head_key,
        bytes,
        |masked| decodes_item(masked, key.family),
    )?;
    let stored = admitted.as_deref().unwrap_or(bytes);
    put_raw_item(dbs, wtxn, key, stored)
}

/// Deletes `run`'s stored items past `counts`, in [`ReplayFamily::ALL`] order; every full key deleted.
/// The scan reads the transaction, so the stale keys are collected first and deleted after it.
pub(super) fn delete_stale_items(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    run: &EntityId,
    counts: [u64; 4],
) -> Result<Vec<Vec<u8>>> {
    let mut stale = Vec::new();
    for row in ITEMS.iter_raw_from(dbs, wtxn, &ReplayItemKey::run_prefix(run))? {
        let (suffix, _) = row?;
        let Some(key) = ReplayItemKey::decode_key(&suffix) else {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        };
        if key.index >= counts[key.family.slot()] {
            stale.push(ITEMS.key_bytes(&key));
        }
    }
    for full in &stale {
        dbs.side_vault_meta().delete(wtxn, full)?;
    }
    Ok(stale)
}

/// `run`'s `family` items in index order, checked exactly `0..count`: a gap or an extra row is corrupted.
pub(super) fn family_items(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: &EntityId,
    family: ReplayFamily,
    count: u64,
) -> Result<Vec<Vec<u8>>> {
    let mut items = Vec::new();
    for row in ITEMS.iter_raw_from(dbs, txn, &ReplayItemKey::family_prefix(run, family))? {
        let (suffix, bytes) = row?;
        let Some(key) = ReplayItemKey::decode_key(&suffix) else {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        };
        if key.run != *run || key.family != family {
            return Err(Error::CorruptedIndex("code-run replay item key"));
        }
        items.push((key.index, bytes));
    }
    if items.len() as u64 != count {
        return Err(Error::CorruptedIndex("code-run replay item index"));
    }
    let mut ordered = Vec::with_capacity(items.len());
    for (position, (index, bytes)) in items.into_iter().enumerate() {
        if index != position as u64 {
            return Err(Error::CorruptedIndex("code-run replay item index"));
        }
        ordered.push(bytes);
    }
    Ok(ordered)
}
