fn entity_type_in_txn(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };

    Ok(Some(raw.entity_type))
}

/// The symbol anchor is the identity anchor. No path may be supplied in its
/// place, and nothing here derives a symbol from a locator.
fn validate_code_symbol_anchor(store: &Store, txn: &RoTxn<'_>, symbol_id: &EntityId) -> Result<()> {
    if entity_type_in_txn(store, txn, symbol_id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
        return Ok(());
    }
    Err(Error::Code(CodeError::CodeMemoryInvalidAnchor {
        reason: "code-memory anchors must name a live CODE_SYMBOL entity",
    }))
}

fn read_slot(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlotName,
) -> Result<Option<CodeMemorySlot>> {
    SLOT.get(store, txn, &slot_key(symbol_id, slot))
}

fn write_slot(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
    slot: &CodeMemorySlot,
) -> Result<()> {
    SLOT.put(store, txn, &slot_key(symbol_id, &slot.name), slot)
}

/// Streams `symbol_id`'s slot bodies in canonical order, decoding ONE at a
/// time and stopping the moment `visit` reports it has what it needs.
///
/// `should_decode` runs after the cursor has yielded a row but BEFORE its body
/// is decoded. That pre-decode door is load-bearing for bounded callers: a
/// denied-value budget can stop the next slot from being decoded at all.
///
/// THIS IS THE BOUNDED READER. [`read_slots_for_symbol`] materializes EVERY
/// slot body for the symbol before its caller sees the first one, and there is
/// no per-symbol slot-count ceiling anywhere in this module — so a reader whose
/// own work is bounded (the L2 pull's `request.limit`) could still be made to
/// decode and allocate an unbounded number of stored slot bodies first. A
/// caller that can stop early must be able to stop the DECODE, not just the
/// loop over an already-built `Vec`. One decoded body is still bounded by the
/// fixed [`CODE_MEMORY_MAX_VALUES_PER_SLOT`] per-slot value cap.
///
/// CANONICAL ORDER IS PRESERVED, not approximated. A slot key is
/// `table prefix | symbol | KEY_SEPARATOR | slot name` ([`slot_key`]) and
/// [`validate_slot_name`] rejects control characters, so no separator byte can
/// occur inside a name: the prefix cursor already yields rows in slot-name byte
/// order, which is exactly the order [`read_slots_for_symbol`] sorts into.
fn stream_slots_for_symbol<ShouldDecode, Visit>(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
    mut should_decode: ShouldDecode,
    mut visit: Visit,
) -> Result<()>
where
    ShouldDecode: FnMut() -> bool,
    Visit: FnMut(CodeMemorySlot) -> Result<ControlFlow<()>>,
{
    // Undecoded rows: `should_decode` must gate the decode itself (see the
    // doc comment above).
    for entry in SLOT.iter_raw_from(store, txn, &slot_symbol_prefix(symbol_id))? {
        if !should_decode() {
            break;
        }
        let (_, value) = entry?;
        if visit(SLOT.decode_value(&value)?)?.is_break() {
            break;
        }
    }
    Ok(())
}

/// Every slot body on `symbol_id`, in canonical slot-name order.
///
/// The eager reader, for the callers that genuinely need the whole set (the
/// public slot/attachment readers). Built on [`stream_slots_for_symbol`] so the
/// two cannot drift apart, and it keeps its own defensive sort: the decoded
/// name is what the order is a contract about, and the cursor orders by the KEY.
pub(crate) fn read_slots_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<CodeMemorySlot>> {
    let mut slots = Vec::new();
    stream_slots_for_symbol(
        store,
        txn,
        symbol_id,
        || true,
        |slot| {
            slots.push(slot);
            Ok(ControlFlow::Continue(()))
        },
    )?;
    slots.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    Ok(slots)
}

pub(crate) fn read_always_on_for_symbol(
    store: &Store,
    txn: &RoTxn<'_>,
    symbol_id: &EntityId,
) -> Result<Vec<AlwaysOnCodeMemoryContract>> {
    let mut contracts: Vec<AlwaysOnCodeMemoryContract> = ALWAYS_ON
        .scan_from(store, txn, &always_on_symbol_prefix(symbol_id))?
        .into_iter()
        .map(|(_, contract)| contract)
        .collect();
    contracts.sort_by(|left, right| (&left.slot, left.payload).cmp(&(&right.slot, right.payload)));
    Ok(contracts)
}

fn write_always_on(
    store: &Store,
    txn: &mut RwTxn<'_>,
    contract: &AlwaysOnCodeMemoryContract,
) -> Result<()> {
    let key = always_on_key(&contract.symbol_id, &contract.slot, contract.payload);
    ALWAYS_ON.put(store, txn, &key, contract)
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
        let Some((existing, _)) =
            ATTACHMENT.get(store, txn, &attachment_key(symbol_id, &slot.name, payload))?
        else {
            continue;
        };
        retained.insert(payload, existing);
    }

    ATTACHMENT.delete_from(store, txn, &attachment_slot_prefix(symbol_id, &slot.name))?;
    for payload in slot.payloads() {
        let Some(provenance) = slot.provenance_for_payload(payload) else {
            continue;
        };
        let row_locator = retained
            .get(&payload)
            .cloned()
            .unwrap_or_else(|| locator.clone());
        ATTACHMENT.put(
            store,
            txn,
            &attachment_key(symbol_id, &slot.name, payload),
            &(row_locator, provenance),
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
            let Some((locator, provenance_claim_id)) = ATTACHMENT.get(store, txn, &key)? else {
                continue;
            };
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
