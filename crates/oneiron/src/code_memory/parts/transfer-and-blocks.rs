// ---------------------------------------------------------------------------
// Section 3 — explicit rename/copy anchor transfer
// ---------------------------------------------------------------------------

/// Rename re-points; Copy clones. Nothing else transfers an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorTransferKind {
    Rename,
    Copy,
}

impl AnchorTransferKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Rename => TRANSFER_TAG_RENAME,
            Self::Copy => TRANSFER_TAG_COPY,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            TRANSFER_TAG_RENAME => Ok(Self::Rename),
            TRANSFER_TAG_COPY => Ok(Self::Copy),
            _ => Err(record_error()),
        }
    }
}

/// An EXPLICIT, already-reviewed rename/copy mapping. Path or fingerprint
/// resemblance never produces one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTransfer {
    pub kind: AnchorTransferKind,
    pub from_symbol_id: EntityId,
    pub to_symbol_id: EntityId,
    pub from_locator: CodeMemoryLocator,
    pub to_locator: CodeMemoryLocator,
    pub actor_id: EntityId,
    pub observed_at: u64,
    pub provenance_claim_id: EntityId,
}

/// What one applied transfer moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorTransferReceipt {
    /// Source slot-value cardinality measured BEFORE destination merge. A
    /// fully deduped transfer is legal and still reports a nonzero count.
    /// A legal CONTRACT-ONLY transfer reports zero: the count measures slot
    /// values, and always-on rows are a separate family.
    pub moved_attachments: usize,
}

/// Decoded, queryable transfer history. Raw metadata keys never cross the
/// public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTransferRecord {
    pub kind: AnchorTransferKind,
    pub from_symbol_id: EntityId,
    pub to_symbol_id: EntityId,
    pub from_locator: CodeMemoryLocator,
    pub to_locator: CodeMemoryLocator,
    pub actor_id: EntityId,
    pub observed_at: u64,
    pub provenance_claim_id: EntityId,
    pub moved_attachments: usize,
}

/// Applies one explicit anchor transfer in the caller's single transaction.
///
/// Order is fixed: validate both endpoints as live, distinct `CODE_SYMBOL`
/// entities; validate each locator's own bounded structure (never that a
/// locator "belongs to" a symbol); load source slots/always-on rows BY
/// SYMBOL ID and never by path; plan every destination merge and bound check
/// BEFORE any durable write; write destination state; upsert the
/// deterministic receipt; and only then, for `Rename`, retire the source
/// rows. `Copy` leaves the source untouched.
///
/// EITHER FAMILY QUALIFIES. Slot values and always-on contracts are moved
/// independently, so a symbol carrying only standalone contracts transfers
/// normally; only a source with neither is the typed refusal.
///
/// NOTHING AT THE DESTINATION IS OVERWRITTEN. Colliding slot values resolve
/// through `merge_union`, a colliding `(symbol, slot, payload)` contract
/// leaves the destination row exactly as registered, and destination-only
/// payloads keep their own attachment locators.
pub fn transfer_code_memory_anchor(
    store: &Store,
    txn: &mut RwTxn<'_>,
    transfer: &AnchorTransfer,
) -> Result<AnchorTransferReceipt> {
    if transfer.from_symbol_id == transfer.to_symbol_id {
        return Err(Error::CodeMemoryInvalidAnchorTransfer {
            from: transfer.from_symbol_id,
            to: transfer.to_symbol_id,
            reason: "transfer endpoints must be distinct symbols",
        });
    }
    for symbol in [&transfer.from_symbol_id, &transfer.to_symbol_id] {
        if entity_type_in_txn(store, txn, symbol)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchorTransfer {
                from: transfer.from_symbol_id,
                to: transfer.to_symbol_id,
                reason: "both transfer endpoints must be live CODE_SYMBOL entities",
            });
        }
    }
    transfer.from_locator.validate()?;
    transfer.to_locator.validate()?;

    // Step 3 — load by symbol id. `moved_attachments` is the SOURCE slot-value
    // cardinality measured here, before any destination merge, so the count
    // never depends on post-merge origin reconstruction.
    let source_slots = read_slots_for_symbol(store, txn, &transfer.from_symbol_id)?;
    let source_contracts = read_always_on_for_symbol(store, txn, &transfer.from_symbol_id)?;
    let moved_attachments: usize = source_slots.iter().map(|slot| slot.values.len()).sum();
    // A symbol carrying ONLY standalone always-on contracts is a legal
    // registration (`register_always_on_contract` never requires a slot
    // value), so it must be transferable too. The refusal is reserved for a
    // source that carries NOTHING on either family.
    if moved_attachments == 0 && source_contracts.is_empty() {
        return Err(Error::CodeMemoryInvalidAnchorTransfer {
            from: transfer.from_symbol_id,
            to: transfer.to_symbol_id,
            reason: "source symbol carries no slot value or always-on contract to transfer",
        });
    }

    // Step 4 — plan every destination write, enforcing both bounds before a
    // single durable byte moves. Each plan carries the payload set that
    // ORIGINATES IN THE SOURCE: those payloads, and only those, take this
    // transfer's `to_locator` at the destination.
    let mut planned_slots = Vec::with_capacity(source_slots.len());
    for source_slot in &source_slots {
        let destination = read_slot(store, txn, &transfer.to_symbol_id, &source_slot.name)?
            .unwrap_or_else(|| CodeMemorySlot::empty(source_slot.name.clone()));
        let moved_payloads: BTreeSet<CodeMemoryPayloadRef> =
            source_slot.payloads().into_iter().collect();
        planned_slots.push((destination.merge_union(source_slot)?, moved_payloads));
    }

    let planned_contracts =
        plan_transferred_contracts(store, txn, &transfer.to_symbol_id, &source_contracts)?;

    // Step 5 — destination rows are derived from the MERGED contents, never
    // from the incoming source stream.
    for (slot, moved_payloads) in &planned_slots {
        write_slot(store, txn, &transfer.to_symbol_id, slot)?;
        derive_attachment_rows(
            store,
            txn,
            &transfer.to_symbol_id,
            slot,
            &transfer.to_locator,
            moved_payloads,
        )?;
    }
    for contract in &planned_contracts {
        write_always_on(store, txn, contract)?;
    }

    // Step 6 — deterministic receipt. A byte-identical replay upserts its own
    // key; distinct transfers cannot collide.
    let record = AnchorTransferRecord {
        kind: transfer.kind,
        from_symbol_id: transfer.from_symbol_id,
        to_symbol_id: transfer.to_symbol_id,
        from_locator: transfer.from_locator.clone(),
        to_locator: transfer.to_locator.clone(),
        actor_id: transfer.actor_id,
        observed_at: transfer.observed_at,
        provenance_claim_id: transfer.provenance_claim_id,
        moved_attachments,
    };
    store.vault_meta.put(
        txn,
        &transfer_key(transfer),
        &encode_transfer_record(&record),
    )?;

    // Step 7 — Rename retires the source only after every target write and the
    // receipt succeeded. Copy leaves the source completely intact.
    if transfer.kind == AnchorTransferKind::Rename {
        delete_prefix(
            store,
            txn,
            &attachment_symbol_prefix(&transfer.from_symbol_id),
        )?;
        delete_prefix(store, txn, &slot_symbol_prefix(&transfer.from_symbol_id))?;
        delete_prefix(
            store,
            txn,
            &always_on_symbol_prefix(&transfer.from_symbol_id),
        )?;
    }

    Ok(AnchorTransferReceipt { moved_attachments })
}

/// Plans the destination always-on writes of one transfer. Read-only: it
/// decides what may be written and never writes.
///
/// A source contract whose `(symbol, slot, payload)` key ALREADY exists at
/// the destination is dropped from the plan. Contract collisions resolve
/// exactly like slot collisions do: the destination registration stands, its
/// kind/actor/time/provenance are never overwritten with the source's, and
/// there is no last-writer-wins path. The per-symbol bound therefore counts
/// only the keys this transfer genuinely adds.
fn plan_transferred_contracts(
    store: &Store,
    txn: &RoTxn<'_>,
    to_symbol_id: &EntityId,
    source_contracts: &[AlwaysOnCodeMemoryContract],
) -> Result<Vec<AlwaysOnCodeMemoryContract>> {
    let registered = read_always_on_for_symbol(store, txn, to_symbol_id)?;
    let mut keys: HashSet<Vec<u8>> = registered
        .into_iter()
        .map(|contract| always_on_key(to_symbol_id, &contract.slot, contract.payload))
        .collect();
    let mut planned = Vec::with_capacity(source_contracts.len());
    for contract in source_contracts {
        let mut moved = contract.clone();
        moved.symbol_id = *to_symbol_id;
        if !keys.insert(always_on_key(to_symbol_id, &moved.slot, moved.payload)) {
            continue;
        }
        if keys.len() > CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
            return Err(Error::CodeMemoryLimitExceeded {
                kind: "always-on contracts per symbol",
                limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS,
            });
        }
        planned.push(moved);
    }
    Ok(planned)
}

/// Decoded transfer history touching `of` on either endpoint.
pub(crate) fn read_transfer_records(
    store: &Store,
    txn: &RoTxn<'_>,
    of: &EntityId,
) -> Result<Vec<AnchorTransferRecord>> {
    let mut records = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, TRANSFER_KEY_PREFIX)? {
        let (_, value) = entry?;
        let record = decode_transfer_record(&value)?;
        if record.from_symbol_id == *of || record.to_symbol_id == *of {
            records.push(record);
        }
    }
    records.sort_by_key(|record| {
        (
            record.observed_at,
            record.from_symbol_id,
            record.to_symbol_id,
            record.kind.tag(),
        )
    });
    Ok(records)
}

// ---------------------------------------------------------------------------
// Section 4 — `EdgeKind::Blocks`: closed, gated, acyclic, durable, non-PPR
// ---------------------------------------------------------------------------

/// Authority context for the dedicated readiness-edge doors.
///
/// Deliberately built from the LIVE vocabulary — [`WriteActor`] for actor
/// identity/class and [`ClaimSource`] for host-stamped source trust. The
/// caller supplies no raw allow/deny boolean and no parallel trust enum.
#[derive(Debug, Clone, Copy)]
pub struct BlocksWriteContext<'a> {
    pub actor: &'a WriteActor,
    pub source: ClaimSource,
}

/// Binds the asserted actor class to the STORED actor entity type and clears
/// the host-stamped source, mirroring
/// `claim::put::validate_code_run_write_actor_binding_in_txn`.
///
/// Allowed iff the validated class is `Human` or `Agent` AND
/// `!source.requires_explicit_auto_permit()`. An unresolvable actor or a
/// forged class is the typed actor denial; a `System` actor is refused even
/// when it resolves cleanly.
fn authorize_blocks_write(
    store: &Store,
    txn: &RoTxn<'_>,
    context: BlocksWriteContext<'_>,
) -> Result<()> {
    let actor_type = entity_type_in_txn(store, txn, &context.actor.entity_ref())?.ok_or(
        Error::CodeMemoryBlocksActorDenied("write actor entity does not resolve"),
    )?;
    validate_actor_class(actor_type, context.actor.actor_class()).map_err(|_| {
        Error::CodeMemoryBlocksActorDenied(
            "asserted actor class is not bound to the actor entity type",
        )
    })?;
    if context.actor.actor_class() == EdgeActorClass::System {
        return Err(Error::CodeMemoryBlocksActorDenied(
            "readiness dependencies are a Human/Agent judgement",
        ));
    }
    if context.source.requires_explicit_auto_permit() {
        return Err(Error::CodeMemoryBlocksSourceUntrusted {
            source_kind: context.source.as_str(),
        });
    }
    Ok(())
}

/// Is `target` reachable from `start` over `Blocks` edges ONLY?
///
/// Kind-local by construction: the walk rides the landed kind-filtered,
/// cap-bounded peer scan, so a `child_of` / `derived_from` path between the
/// same endpoints can never fabricate a readiness cycle. Overflow is the
/// typed [`Error::IndexOverflow`], never a partial acyclicity proof.
pub(crate) fn blocks_path_exists(
    vault: &Vault,
    txn: &RoTxn<'_>,
    start: EntityId,
    target: EntityId,
) -> Result<bool> {
    let mut visited: HashSet<EntityId> = HashSet::from([start]);
    let mut frontier: VecDeque<EntityId> = VecDeque::from([start]);
    let mut traversed_steps = 0usize;

    while let Some(current) = frontier.pop_front() {
        let peers = vault.filtered_edge_peers(
            txn,
            &vault.store.edges_out,
            &current,
            EdgeKind::Blocks,
            None,
            "blocks readiness walk",
        )?;
        for peer in peers {
            if traversed_steps >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("blocks readiness walk"));
            }
            traversed_steps += 1;
            if peer == target {
                return Ok(true);
            }
            if visited.insert(peer) {
                frontier.push_back(peer);
            }
        }
    }

    Ok(false)
}

/// The ONLY `blocks` write door.
///
/// `from` blocks `to`. Authority, ENDPOINT TYPING, the acyclicity proof, both
/// index mutations, PPR invalidation, and the graph-version increment all
/// share the caller's ONE `RwTxn` — no `BatchBuilder` (which owns its own
/// commit) and no generic public edge door is involved.
///
/// Endpoints are typed the same way attach, transfer, and pull type theirs:
/// both must resolve to a LIVE `CODE_SYMBOL`. Readiness is a judgement about
/// code, so a ghost id or a live entity of any other type is the typed anchor
/// refusal and never a persisted edge.
pub(crate) fn insert_blocks_edge(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    from: EntityId,
    to: EntityId,
    context: BlocksWriteContext<'_>,
) -> Result<()> {
    authorize_blocks_write(&vault.store, txn, context)?;
    if from == to {
        return Err(Error::CodeMemoryBlocksCycle { from, to });
    }
    for endpoint in [&from, &to] {
        if entity_type_in_txn(&vault.store, txn, endpoint)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchor {
                reason: "readiness edge endpoints must be live CODE_SYMBOL entities",
            });
        }
    }
    if blocks_path_exists(vault, txn, to, from)? {
        return Err(Error::CodeMemoryBlocksCycle { from, to });
    }

    let weight = EdgeKind::Blocks
        .default_weight()
        .expect("Blocks has a canonical structural weight");
    let value = encode_edge_value(
        EdgeKind::Blocks,
        weight,
        crate::unix_seconds_now(),
        Vad::NEUTRAL,
        None,
    )?;
    // Identical bytes into both directions, mirroring `batch::edge_apply`.
    let key_out = Store::encode_edge_key(&from, EdgeKind::Blocks, &to);
    let key_in = Store::encode_edge_key(&to, EdgeKind::Blocks, &from);
    vault.store.edges_out.put(txn, &key_out, &value)?;
    vault.store.edges_in.put(txn, &key_in, &value)?;

    ppr::invalidate_ppr_for_edge(&vault.store, txn, &from, &to)?;
    ppr::increment_graph_version(&vault.store, txn)?;
    Ok(())
}

/// The ONLY `blocks` retirement door. Same authority steps, both index rows
/// deleted, same in-transaction side effects. Generic `Vault::delete_edge`
/// stays reserved-rejecting for this kind.
pub(crate) fn remove_blocks_edge(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    from: EntityId,
    to: EntityId,
    context: BlocksWriteContext<'_>,
) -> Result<bool> {
    authorize_blocks_write(&vault.store, txn, context)?;
    let key_out = Store::encode_edge_key(&from, EdgeKind::Blocks, &to);
    let key_in = Store::encode_edge_key(&to, EdgeKind::Blocks, &from);
    let existed_out = vault.store.edges_out.delete(txn, &key_out)?;
    let deleted_in = vault.store.edges_in.delete(txn, &key_in)?;
    if !existed_out {
        let _ = deleted_in;
        return Ok(false);
    }
    ppr::invalidate_ppr_for_edge(&vault.store, txn, &from, &to)?;
    ppr::increment_graph_version(&vault.store, txn)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
