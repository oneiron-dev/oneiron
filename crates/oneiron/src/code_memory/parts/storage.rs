// ---------------------------------------------------------------------------
// Keys, codecs, and row-family helpers (private: raw keys never cross the API)
// ---------------------------------------------------------------------------

fn record_error() -> Error {
    Error::CorruptedIndex("code memory record")
}

fn validate_slot_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > CODE_MEMORY_SLOT_NAME_MAX_BYTES {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "slot name must be non-empty and within the pinned length bound",
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "slot name must be trimmed and free of control characters",
        });
    }
    Ok(())
}

/// Mirrors the live code-symbol manifest path rule: repository-relative,
/// normalized, bounded by `CODEBASE_FILE_PATH_MAX_BYTES`.
fn validate_locator_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > CODEBASE_FILE_PATH_MAX_BYTES
        || path.trim() != path
        || path.chars().any(char::is_control)
    {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be non-empty, trimmed, bounded, and free of control characters",
        });
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be repository-relative",
        });
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "locator path must be normalized and cannot contain . or .. segments",
        });
    }
    Ok(())
}

fn validate_time_range(range: TimeRange, field: &'static str) -> Result<()> {
    if range.start > range.end {
        return Err(Error::CodeMemoryInvalidAnchor { reason: field });
    }
    Ok(())
}

fn entity_type_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// The symbol anchor is the identity anchor. No path may be supplied in its
/// place, and nothing here derives a symbol from a locator.
fn validate_code_symbol_anchor(store: &Store, txn: &RoTxn<'_>, symbol_id: &EntityId) -> Result<()> {
    if entity_type_in_txn(store, txn, symbol_id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
        return Ok(());
    }
    Err(Error::CodeMemoryInvalidAnchor {
        reason: "code-memory anchors must name a live CODE_SYMBOL entity",
    })
}

fn key_with_symbol(prefix: &[u8], symbol_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN + 1);
    key.extend_from_slice(prefix);
    key.extend_from_slice(symbol_id.as_bytes());
    key.push(KEY_SEPARATOR);
    key
}

fn key_with_slot(prefix: &[u8], symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    let mut key = key_with_symbol(prefix, symbol_id);
    key.extend_from_slice(slot.as_str().as_bytes());
    key
}

fn key_with_payload(
    prefix: &[u8],
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    let mut key = key_with_slot(prefix, symbol_id, slot);
    key.push(KEY_SEPARATOR);
    key.push(payload.tag());
    key.extend_from_slice(payload.entity_id().as_bytes());
    key
}

fn slot_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(SLOT_KEY_PREFIX, symbol_id)
}

fn slot_key(symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    key_with_slot(SLOT_KEY_PREFIX, symbol_id, slot)
}

fn attachment_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(ATTACHMENT_KEY_PREFIX, symbol_id)
}

fn attachment_slot_prefix(symbol_id: &EntityId, slot: &CodeMemorySlotName) -> Vec<u8> {
    let mut key = key_with_slot(ATTACHMENT_KEY_PREFIX, symbol_id, slot);
    key.push(KEY_SEPARATOR);
    key
}

fn attachment_key(
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    key_with_payload(ATTACHMENT_KEY_PREFIX, symbol_id, slot, payload)
}

fn always_on_symbol_prefix(symbol_id: &EntityId) -> Vec<u8> {
    key_with_symbol(ALWAYS_ON_KEY_PREFIX, symbol_id)
}

fn always_on_key(
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
) -> Vec<u8> {
    key_with_payload(ALWAYS_ON_KEY_PREFIX, symbol_id, slot, payload)
}

/// `TRANSFER_KEY_PREFIX + from + to + observed_at_be + sha256(canonical
/// transfer encoding)`: a byte-identical replay is an idempotent upsert of
/// its own key, while distinct transfers cannot collide.
fn transfer_key(transfer: &AnchorTransfer) -> Vec<u8> {
    let mut key = Vec::with_capacity(TRANSFER_KEY_PREFIX.len() + 16 + 16 + 8 + 32);
    key.extend_from_slice(TRANSFER_KEY_PREFIX);
    key.extend_from_slice(transfer.from_symbol_id.as_bytes());
    key.extend_from_slice(transfer.to_symbol_id.as_bytes());
    key.extend_from_slice(&transfer.observed_at.to_be_bytes());
    key.extend_from_slice(&sha256(&encode_transfer_identity(transfer)));
    key
}

fn sha256(bytes: &[u8]) -> [u8; CODE_MEMORY_CONTENT_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    push_u16(out, u16::try_from(text.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(text.as_bytes());
}

fn push_time_range(out: &mut Vec<u8>, range: TimeRange) {
    push_u64(out, range.start);
    push_u64(out, range.end);
}

fn push_payload(out: &mut Vec<u8>, payload: CodeMemoryPayloadRef) {
    out.push(payload.tag());
    out.extend_from_slice(payload.entity_id().as_bytes());
}

fn push_locator(out: &mut Vec<u8>, locator: &CodeMemoryLocator) {
    push_text(out, &locator.path_at_revision);
    match &locator.revision {
        CodeMemoryRevision::Commit(commit) => {
            out.push(REVISION_TAG_COMMIT);
            push_text(out, commit);
        }
        CodeMemoryRevision::ForkHash(fork_hash) => {
            out.push(REVISION_TAG_FORK_HASH);
            out.extend_from_slice(fork_hash);
        }
    }
    push_time_range(out, locator.validity);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(record_error)?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(record_error)?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| record_error())?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| record_error())?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| record_error())?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn entity_id(&mut self) -> Result<EntityId> {
        let bytes: [u8; ENTITY_ID_LEN] = self
            .take(ENTITY_ID_LEN)?
            .try_into()
            .map_err(|_| record_error())?;
        EntityId::from_bytes(bytes).map_err(|_| record_error())
    }

    fn content_hash(&mut self) -> Result<[u8; CODE_MEMORY_CONTENT_HASH_LEN]> {
        self.take(CODE_MEMORY_CONTENT_HASH_LEN)?
            .try_into()
            .map_err(|_| record_error())
    }

    fn text(&mut self, max_bytes: usize) -> Result<String> {
        let len = usize::from(self.u16()?);
        if len > max_bytes {
            return Err(record_error());
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| record_error())
    }

    fn time_range(&mut self) -> Result<TimeRange> {
        let start = self.u64()?;
        let end = self.u64()?;
        if start > end {
            return Err(record_error());
        }
        Ok(TimeRange { start, end })
    }

    fn payload(&mut self) -> Result<CodeMemoryPayloadRef> {
        let tag = self.u8()?;
        let id = self.entity_id()?;
        CodeMemoryPayloadRef::from_tag(tag, id)
    }

    fn locator(&mut self) -> Result<CodeMemoryLocator> {
        let path_at_revision = self.text(CODEBASE_FILE_PATH_MAX_BYTES)?;
        let revision = match self.u8()? {
            REVISION_TAG_COMMIT => CodeMemoryRevision::Commit(self.text(COMMIT_HASH_MAX_HEX_LEN)?),
            REVISION_TAG_FORK_HASH => {
                let fork_hash: CodebaseForkHash = self
                    .take(CODEBASE_FORK_HASH_LEN)?
                    .try_into()
                    .map_err(|_| record_error())?;
                CodeMemoryRevision::ForkHash(fork_hash)
            }
            _ => return Err(record_error()),
        };
        let validity = self.time_range()?;
        let locator = CodeMemoryLocator {
            path_at_revision,
            revision,
            validity,
        };
        locator.validate().map_err(|_| record_error())?;
        Ok(locator)
    }

    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(record_error())
        }
    }
}

fn encode_slot(slot: &CodeMemorySlot) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(u8::from(slot.conflict_visible));
    push_text(&mut out, slot.name.as_str());
    push_u16(
        &mut out,
        u16::try_from(slot.values.len()).unwrap_or(u16::MAX),
    );
    for value in &slot.values {
        push_payload(&mut out, value.payload);
        out.extend_from_slice(value.actor_id.as_bytes());
        push_time_range(&mut out, value.valid_time);
        push_u64(&mut out, value.recorded_at);
        out.extend_from_slice(&value.content_hash);
        out.extend_from_slice(value.provenance_claim_id.as_bytes());
    }
    out
}

fn decode_slot(bytes: &[u8]) -> Result<CodeMemorySlot> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let conflict_visible = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(record_error()),
    };
    let name = CodeMemorySlotName::new(reader.text(CODE_MEMORY_SLOT_NAME_MAX_BYTES)?)
        .map_err(|_| record_error())?;
    let count = usize::from(reader.u16()?);
    if count > CODE_MEMORY_MAX_VALUES_PER_SLOT {
        return Err(record_error());
    }
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<_> = None;
    let mut dedupe_keys = BTreeSet::new();
    for _ in 0..count {
        let value = CodeMemorySlotValue {
            payload: reader.payload()?,
            actor_id: reader.entity_id()?,
            valid_time: reader.time_range()?,
            recorded_at: reader.u64()?,
            content_hash: reader.content_hash()?,
            provenance_claim_id: reader.entity_id()?,
        };
        let sort_key = value.sort_key();
        if previous.as_ref().is_some_and(|prev| *prev >= sort_key) {
            return Err(record_error());
        }
        if !dedupe_keys.insert(value.dedupe_key()) {
            return Err(record_error());
        }
        previous = Some(sort_key);
        values.push(value);
    }
    reader.finish()?;
    if conflict_visible != (values.len() >= 2) {
        return Err(record_error());
    }
    Ok(CodeMemorySlot {
        name,
        values,
        conflict_visible,
    })
}

fn encode_attachment_row(locator: &CodeMemoryLocator, provenance_claim_id: EntityId) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    push_locator(&mut out, locator);
    out.extend_from_slice(provenance_claim_id.as_bytes());
    out
}

fn decode_attachment_row(bytes: &[u8]) -> Result<(CodeMemoryLocator, EntityId)> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let locator = reader.locator()?;
    let provenance_claim_id = reader.entity_id()?;
    reader.finish()?;
    Ok((locator, provenance_claim_id))
}

fn encode_always_on(contract: &AlwaysOnCodeMemoryContract) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(contract.kind.tag());
    out.extend_from_slice(contract.symbol_id.as_bytes());
    push_text(&mut out, contract.slot.as_str());
    push_payload(&mut out, contract.payload);
    out.extend_from_slice(contract.actor_id.as_bytes());
    push_time_range(&mut out, contract.valid_time);
    push_u64(&mut out, contract.recorded_at);
    out.extend_from_slice(contract.provenance_claim_id.as_bytes());
    out
}

fn decode_always_on(bytes: &[u8]) -> Result<AlwaysOnCodeMemoryContract> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let kind = CodeMemoryContractKind::from_tag(reader.u8()?)?;
    let symbol_id = reader.entity_id()?;
    let slot = CodeMemorySlotName::new(reader.text(CODE_MEMORY_SLOT_NAME_MAX_BYTES)?)
        .map_err(|_| record_error())?;
    let payload = reader.payload()?;
    let actor_id = reader.entity_id()?;
    let valid_time = reader.time_range()?;
    let recorded_at = reader.u64()?;
    let provenance_claim_id = reader.entity_id()?;
    reader.finish()?;
    Ok(AlwaysOnCodeMemoryContract {
        symbol_id,
        slot,
        payload,
        kind,
        actor_id,
        valid_time,
        recorded_at,
        provenance_claim_id,
    })
}

/// The canonical bytes hashed into a transfer receipt's key. Deliberately
/// EXCLUDES `moved_attachments`, which is derived, so a byte-identical replay
/// of the same declared transfer lands on the same key.
fn encode_transfer_identity(transfer: &AnchorTransfer) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TRANSFER_DIGEST_DOMAIN);
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(transfer.kind.tag());
    out.extend_from_slice(transfer.from_symbol_id.as_bytes());
    out.extend_from_slice(transfer.to_symbol_id.as_bytes());
    push_locator(&mut out, &transfer.from_locator);
    push_locator(&mut out, &transfer.to_locator);
    out.extend_from_slice(transfer.actor_id.as_bytes());
    push_u64(&mut out, transfer.observed_at);
    out.extend_from_slice(transfer.provenance_claim_id.as_bytes());
    out
}

fn encode_transfer_record(record: &AnchorTransferRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODE_MEMORY_RECORD_VERSION);
    out.push(record.kind.tag());
    out.extend_from_slice(record.from_symbol_id.as_bytes());
    out.extend_from_slice(record.to_symbol_id.as_bytes());
    push_locator(&mut out, &record.from_locator);
    push_locator(&mut out, &record.to_locator);
    out.extend_from_slice(record.actor_id.as_bytes());
    push_u64(&mut out, record.observed_at);
    out.extend_from_slice(record.provenance_claim_id.as_bytes());
    push_u32(
        &mut out,
        u32::try_from(record.moved_attachments).unwrap_or(u32::MAX),
    );
    out
}

fn decode_transfer_record(bytes: &[u8]) -> Result<AnchorTransferRecord> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != CODE_MEMORY_RECORD_VERSION {
        return Err(record_error());
    }
    let kind = AnchorTransferKind::from_tag(reader.u8()?)?;
    let from_symbol_id = reader.entity_id()?;
    let to_symbol_id = reader.entity_id()?;
    let from_locator = reader.locator()?;
    let to_locator = reader.locator()?;
    let actor_id = reader.entity_id()?;
    let observed_at = reader.u64()?;
    let provenance_claim_id = reader.entity_id()?;
    let moved_attachments = reader.u32()? as usize;
    reader.finish()?;
    Ok(AnchorTransferRecord {
        kind,
        from_symbol_id,
        to_symbol_id,
        from_locator,
        to_locator,
        actor_id,
        observed_at,
        provenance_claim_id,
        moved_attachments,
    })
}

fn read_slot(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
) -> Result<Option<CodeMemorySlot>> {
    let Some(raw) = store.vault_meta.get(txn, &slot_key(symbol_id, slot))? else {
        return Ok(None);
    };
    decode_slot(&raw).map(Some)
}

fn write_slot(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &slot_key(symbol_id, &slot.name), &encode_slot(slot))
}

pub(crate) fn read_slots_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<CodeMemorySlot>> {
    let mut slots = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &slot_symbol_prefix(symbol_id))?
    {
        let (_, value) = entry?;
        slots.push(decode_slot(&value)?);
    }
    slots.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    Ok(slots)
}

pub(crate) fn read_always_on_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<AlwaysOnCodeMemoryContract>> {
    let mut contracts = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &always_on_symbol_prefix(symbol_id))?
    {
        let (_, value) = entry?;
        contracts.push(decode_always_on(&value)?);
    }
    contracts.sort_by(|left, right| (&left.slot, left.payload).cmp(&(&right.slot, right.payload)));
    Ok(contracts)
}

fn write_always_on(
    store: &Store,
    txn: &mut RwTxn<'_>,
    contract: &AlwaysOnCodeMemoryContract,
) -> Result<()> {
    let key = always_on_key(&contract.symbol_id, &contract.slot, contract.payload);
    store.vault_meta.put(txn, &key, &encode_always_on(contract))
}

/// Attachment-index rows for `(symbol, slot)` are EXACTLY the payload set
/// present in the written slot body: a payload that lost the actor-scoped
/// dedupe never keeps a row.
///
/// THE LOCATOR HALF IS PER PAYLOAD, NOT PER OPERATION. `locator` is the
/// locator of the operation now running, and it labels ONLY the payloads in
/// `relabelled_payloads` (the source-originating set of a transfer) plus the
/// payloads this operation introduces — the ones that carry no row yet. Every
/// other surviving payload keeps the locator its own row already holds, so a
/// later attach in the same slot cannot restamp an older payload's
/// path/revision/validity and a transfer cannot restamp a destination-only
/// payload that was never moved. Identity remains the symbol either way; this
/// keeps the locator half of the dual anchor lossless.
fn derive_attachment_rows(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
    locator: &CodeMemoryLocator,
    relabelled_payloads: &BTreeSet<CodeMemoryPayloadRef>,
) -> Result<()> {
    // Read the surviving payloads' own locators BEFORE the prefix delete: the
    // rewrite below is the only place they could otherwise be lost.
    let mut retained: BTreeMap<CodeMemoryPayloadRef, CodeMemoryLocator> = BTreeMap::new();
    for payload in slot.payloads() {
        if relabelled_payloads.contains(&payload) {
            continue;
        }
        let Some(raw) = store
            .vault_meta
            .get(txn, &attachment_key(symbol_id, &slot.name, payload))?
        else {
            continue;
        };
        let (existing, _) = decode_attachment_row(&raw)?;
        retained.insert(payload, existing);
    }

    delete_prefix(store, txn, &attachment_slot_prefix(symbol_id, &slot.name))?;
    for payload in slot.payloads() {
        let Some(provenance) = slot.provenance_for_payload(payload) else {
            continue;
        };
        let row_locator = retained.get(&payload).unwrap_or(locator);
        store.vault_meta.put(
            txn,
            &attachment_key(symbol_id, &slot.name, payload),
            &encode_attachment_row(row_locator, provenance),
        )?;
    }
    Ok(())
}

pub(crate) fn read_attachments_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<CodeMemoryAttachment>> {
    let mut attachments = Vec::new();
    for slot in read_slots_for_symbol(store, txn, symbol_id)? {
        for payload in slot.payloads() {
            let key = attachment_key(symbol_id, &slot.name, payload);
            let Some(raw) = store.vault_meta.get(txn, &key)? else {
                continue;
            };
            let (locator, provenance_claim_id) = decode_attachment_row(&raw)?;
            attachments.push(CodeMemoryAttachment {
                anchor: CodeMemoryAnchor {
                    symbol_id: *symbol_id,
                    locator,
                },
                slot: slot.name.clone(),
                payload,
                provenance_claim_id,
            });
        }
    }
    Ok(attachments)
}

