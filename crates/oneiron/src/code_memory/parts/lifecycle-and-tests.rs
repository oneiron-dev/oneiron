// ---------------------------------------------------------------------------
// Deletion lifecycle — no code-memory row outlives the entity it names
// ---------------------------------------------------------------------------

/// Deletes every code-memory row that NAMES `id`, inside the caller's
/// deletion transaction.
///
/// An entity can occupy this module's key space in two unrelated roles, and a
/// delete has to close both or a public reader keeps answering for something
/// that no longer exists:
///
/// * ANCHOR — `id` was the `CODE_SYMBOL` the rows hang off. Slot, attachment,
///   and always-on keys are `id`-prefixed; transfer receipts name it on
///   either endpoint. Without this sweep `code_memory_slots`,
///   `code_memory_attachments`, `code_memory_always_on_contracts`, and
///   `code_memory_transfers` all keep serving a dead anchor.
/// * PAYLOAD — `id` was the NOTE/CLAIM a slot value or an always-on
///   registration pointed AT. Those keys are prefixed by some OTHER symbol,
///   so only a payload-id sweep reaches them. Leaving them behind would keep
///   readers exposing dangling refs, and — because registration counts KEYS
///   rather than live entities — would let dead rows consume a live symbol's
///   [`CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS`] budget permanently.
///
/// Unconditional by design: the deindex door reaches this seam for ids whose
/// entity record is already gone (its index-only arm), where the anchor type
/// can no longer be read back. Corrupt rows stay a typed error rather than a
/// silent skip, exactly as every other codec site in this module.
pub(crate) fn delete_code_memory_rows_for_entity_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    delete_prefix(store, txn, &slot_symbol_prefix(id))?;
    delete_prefix(store, txn, &attachment_symbol_prefix(id))?;
    delete_prefix(store, txn, &always_on_symbol_prefix(id))?;
    delete_transfer_records_naming(store, txn, id)?;
    delete_attachment_and_always_on_rows_for_payload(store, txn, id)?;
    drop_payload_from_slot_bodies(store, txn, id)
}

/// Transfer receipts are keyed `from | to | observed_at | digest`
/// ([`transfer_key`]), so the `to` half is not prefix-addressable: the family
/// is scanned and both endpoint segments are compared on the RAW key. Reading
/// the key rather than decoding the body keeps an unrelated entity's deletion
/// independent of any one receipt's decodability.
fn delete_transfer_records_naming(
    store: &Store,
    txn: &mut RwTxn<'_>,
    symbol_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, TRANSFER_KEY_PREFIX)? {
        let (key, _) = entry?;
        let endpoints = &key[TRANSFER_KEY_PREFIX.len()..];
        if endpoints.len() < 2 * ENTITY_ID_LEN {
            continue;
        }
        if &endpoints[..ENTITY_ID_LEN] == symbol_id.as_bytes()
            || &endpoints[ENTITY_ID_LEN..2 * ENTITY_ID_LEN] == symbol_id.as_bytes()
        {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

/// Attachment and always-on keys both END in `tag | payload id`
/// ([`key_with_payload`]), so the trailing [`ENTITY_ID_LEN`] bytes ARE the
/// payload id: one suffix match reaches both payload tags under any owning
/// symbol and any slot name.
fn delete_attachment_and_always_on_rows_for_payload(
    store: &Store,
    txn: &mut RwTxn<'_>,
    payload_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for prefix in [ATTACHMENT_KEY_PREFIX, ALWAYS_ON_KEY_PREFIX] {
        for entry in store.vault_meta.prefix_iter(&*txn, prefix)? {
            let (key, _) = entry?;
            if key.len() > prefix.len() + ENTITY_ID_LEN && key.ends_with(payload_id.as_bytes()) {
                keys.push(key.to_vec());
            }
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

/// Slot BODIES carry their payload refs inside the encoded value, so every
/// slot in the vault is decoded and the surviving values are re-encoded in
/// place. `normalize` re-derives `conflict_visible` from the survivors — the
/// decoder rejects a body whose flag disagrees with its value count — and a
/// slot with no survivor loses its row rather than persisting as an empty
/// body.
fn drop_payload_from_slot_bodies(
    store: &Store,
    txn: &mut RwTxn<'_>,
    payload_id: &EntityId,
) -> Result<()> {
    let mut rewrites: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, SLOT_KEY_PREFIX)? {
        let (key, value) = entry?;
        let mut slot = decode_slot(&value)?;
        let before = slot.values.len();
        slot.values
            .retain(|value| value.payload.entity_id() != *payload_id);
        if slot.values.len() == before {
            continue;
        }
        slot.normalize();
        let replacement = (!slot.values.is_empty()).then(|| encode_slot(&slot));
        rewrites.push((key.to_vec(), replacement));
    }
    for (key, replacement) in rewrites {
        match replacement {
            Some(body) => store.vault_meta.put(txn, &key, &body)?,
            None => {
                store.vault_meta.delete(txn, &key)?;
            }
        }
    }
    Ok(())
}

fn count_prefix(store: &Store, txn: &RoTxn<'_>, prefix: &[u8]) -> Result<usize> {
    let mut count = 0usize;
    for entry in store.vault_meta.prefix_iter(txn, prefix)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn delete_prefix(store: &Store, txn: &mut RwTxn<'_>, prefix: &[u8]) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*txn, prefix)? {
        let (key, _) = entry?;
        keys.push(key.to_vec());
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! In-module coverage is deliberately limited to codec/key construction,
    //! the PURE merge algebra, and crate-seam side-effect mirrors the public
    //! API cannot observe. Every behavioural contract test lives in
    //! `tests/code_memory.rs` and reaches only `Vault`.

    use super::*;
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::store::GRAPH_VERSION_KEY;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("valid entity id")
    }

    fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn slot_name() -> CodeMemorySlotName {
        CodeMemorySlotName::new("interface.contract").expect("valid slot name")
    }

    fn locator() -> CodeMemoryLocator {
        CodeMemoryLocator {
            path_at_revision: "crates/oneiron/src/code_memory.rs".to_owned(),
            revision: CodeMemoryRevision::Commit("abc123def456".to_owned()),
            validity: range(1_780_000_000),
        }
    }

    fn value(payload: u8, actor: u8, content: u8, recorded_at: u64) -> CodeMemorySlotValue {
        CodeMemorySlotValue {
            payload: CodeMemoryPayloadRef::NoteEntity(id(payload)),
            actor_id: id(actor),
            valid_time: range(recorded_at),
            recorded_at,
            content_hash: [content; CODE_MEMORY_CONTENT_HASH_LEN],
            provenance_claim_id: id(payload.wrapping_add(1)),
        }
    }

    fn slot_with(values: Vec<CodeMemorySlotValue>) -> CodeMemorySlot {
        let mut slot = CodeMemorySlot::empty(slot_name());
        for value in values {
            slot.insert_multi_value(value).expect("value fits");
        }
        slot
    }

    /// Codec: a slot round-trips exactly, and its encoding is CANONICAL — two
    /// slots holding the same value set encode to identical bytes whatever
    /// order the values arrived in.
    #[test]
    fn slot_encoding_round_trips_and_is_order_independent() {
        let first = value(0x21, 0x31, 0x41, 100);
        let second = value(0x22, 0x32, 0x43, 200);
        let forward = slot_with(vec![first.clone(), second.clone()]);
        let backward = slot_with(vec![second, first]);

        assert_eq!(encode_slot(&forward), encode_slot(&backward));
        let decoded = decode_slot(&encode_slot(&forward)).expect("slot decodes");
        assert_eq!(decoded, forward);
        assert!(decoded.conflict_visible);
    }

    /// Codec fail-closed: an unknown version byte, a truncated body, trailing
    /// garbage, and a lying conflict flag are all refused outright.
    #[test]
    fn slot_decoding_is_fail_closed() {
        let one = encode_slot(&slot_with(vec![value(0x23, 0x33, 0x45, 300)]));

        let mut wrong_version = one.clone();
        wrong_version[0] = CODE_MEMORY_RECORD_VERSION + 1;
        assert!(decode_slot(&wrong_version).is_err());
        assert!(decode_slot(&one[..one.len() - 1]).is_err());

        let mut trailing = one.clone();
        trailing.push(0);
        assert!(decode_slot(&trailing).is_err());
        assert!(decode_slot(&one).is_ok());

        let two = encode_slot(&slot_with(vec![
            value(0x24, 0x34, 0x46, 400),
            value(0x25, 0x35, 0x48, 500),
        ]));
        let mut lying = two.clone();
        lying[1] = 0;
        assert!(
            decode_slot(&lying).is_err(),
            "a false conflict flag beside two live values must never decode"
        );
        assert!(decode_slot(&two).is_ok());
    }

    /// Keys: identity is the SYMBOL. Every family is symbol-prefixed, the
    /// payload TAG participates so a note and a claim ref cannot collide, and
    /// no key construction takes a path at all.
    #[test]
    fn keys_are_symbol_prefixed_and_never_path_derived() {
        let symbol = id(0x51);
        let other = id(0x52);
        let note = CodeMemoryPayloadRef::NoteEntity(id(0x53));
        let claim = CodeMemoryPayloadRef::Claim(id(0x53));

        let mut symbol_prefixed = key_with_symbol(SLOT_KEY_PREFIX, &symbol);
        symbol_prefixed.pop();
        assert!(slot_key(&symbol, &slot_name()).starts_with(&symbol_prefixed));
        assert!(attachment_key(&symbol, &slot_name(), note).starts_with(ATTACHMENT_KEY_PREFIX));
        assert!(always_on_key(&symbol, &slot_name(), note).starts_with(ALWAYS_ON_KEY_PREFIX));

        assert_ne!(
            slot_key(&symbol, &slot_name()),
            slot_key(&other, &slot_name())
        );
        assert_ne!(
            always_on_key(&symbol, &slot_name(), note),
            always_on_key(&symbol, &slot_name(), claim)
        );

        // The whole dual-anchor rule in one assertion: the locator's path is
        // nowhere in the key that carries attachment identity.
        let path = locator().path_at_revision.into_bytes();
        let key = attachment_key(&symbol, &slot_name(), note);
        assert!(!key.windows(path.len()).any(|window| window == path));
    }

    /// A transfer receipt key is deterministic in the declared transfer, so a
    /// byte-identical replay upserts one row; any changed field moves it.
    #[test]
    fn transfer_keys_are_deterministic_and_collision_free() {
        let transfer = AnchorTransfer {
            kind: AnchorTransferKind::Rename,
            from_symbol_id: id(0x61),
            to_symbol_id: id(0x62),
            from_locator: locator(),
            to_locator: locator(),
            actor_id: id(0x63),
            observed_at: 1_780_000_100,
            provenance_claim_id: id(0x64),
        };
        let replay = transfer.clone();
        assert_eq!(transfer_key(&transfer), transfer_key(&replay));

        let mut copied = transfer;
        copied.kind = AnchorTransferKind::Copy;
        assert_ne!(transfer_key(&replay), transfer_key(&copied));
    }

    /// PURE merge algebra over the canonical encoded output: associative,
    /// commutative, and idempotent, including two actor/content-colliding
    /// values that differ only in `valid_time`.
    #[test]
    fn merge_union_is_associative_commutative_idempotent() {
        let mut colliding = value(0x26, 0x36, 0x4A, 600);
        colliding.valid_time = TimeRange {
            start: 600,
            end: 900,
        };
        let first = slot_with(vec![
            value(0x26, 0x36, 0x4A, 600),
            value(0x27, 0x37, 0x4C, 700),
        ]);
        let second = slot_with(vec![colliding]);
        let third = slot_with(vec![value(0x28, 0x38, 0x4E, 800)]);

        let left = first
            .merge_union(&second)
            .expect("merge")
            .merge_union(&third)
            .expect("merge");
        let right = first
            .merge_union(&second.merge_union(&third).expect("merge"))
            .expect("merge");
        assert_eq!(encode_slot(&left), encode_slot(&right), "associative");
        assert_eq!(
            encode_slot(&first.merge_union(&second).expect("merge")),
            encode_slot(&second.merge_union(&first).expect("merge")),
            "commutative"
        );
        assert_eq!(
            encode_slot(&left),
            encode_slot(&left.merge_union(&left).expect("merge")),
            "idempotent"
        );
    }

    /// Two actors, identical bytes: two values survive with actor, time, and
    /// provenance intact and conflict visible. Nothing elects a winner.
    #[test]
    fn equal_bytes_from_different_actors_never_collapse() {
        let merged = slot_with(vec![value(0x29, 0x39, 0x4F, 900)])
            .merge_union(&slot_with(vec![value(0x2A, 0x3A, 0x4F, 950)]))
            .expect("merge");

        assert_eq!(merged.values.len(), 2);
        assert!(merged.conflict_visible);
        let actors: BTreeSet<EntityId> = merged.values.iter().map(|value| value.actor_id).collect();
        assert_eq!(actors, BTreeSet::from([id(0x39), id(0x3A)]));
    }

    /// One actor, identical bytes: the canonical MINIMUM survives whatever
    /// order the values arrive in. This is the no-LWW guarantee at the
    /// algebra level — the LATER value is not the winner.
    #[test]
    fn actor_scoped_collision_keeps_the_canonical_minimum() {
        let older = value(0x2B, 0x3B, 0x4B, 1_000);
        let newer = value(0x2C, 0x3B, 0x4B, 2_000);

        for order in [
            vec![older.clone(), newer.clone()],
            vec![newer, older.clone()],
        ] {
            let mut slot = CodeMemorySlot::empty(slot_name());
            let outcomes: Vec<SlotInsertOutcome> = order
                .into_iter()
                .map(|value| slot.insert_multi_value(value).expect("insert"))
                .collect();
            assert_eq!(outcomes[0], SlotInsertOutcome::Inserted);
            assert_eq!(outcomes[1], SlotInsertOutcome::DeduplicatedWithinActor);
            assert_eq!(slot.values.len(), 1);
            assert_eq!(slot.values[0], older, "canonical minimum survives");
            assert!(!slot.conflict_visible);
        }
    }

    /// The capacity bound is transactional at the algebra level: the 257th
    /// DISTINCT value errors typed and leaves the encoded slot unchanged.
    #[test]
    fn slot_capacity_is_transactional() {
        let mut slot = CodeMemorySlot::empty(slot_name());
        for index in 0..CODE_MEMORY_MAX_VALUES_PER_SLOT {
            let mut candidate = value(0x2D, 0x3D, 0x4D, 1_100);
            candidate.content_hash[0] = u8::try_from(index % 251).expect("byte");
            candidate.content_hash[1] = u8::try_from(index / 251).expect("byte");
            slot.insert_multi_value(candidate).expect("value fits");
        }
        let before = encode_slot(&slot);

        let mut overflow = value(0x2E, 0x3D, 0x4D, 1_200);
        overflow.content_hash = [0xFE; CODE_MEMORY_CONTENT_HASH_LEN];
        let error = slot
            .insert_multi_value(overflow)
            .expect_err("the 257th distinct value must be refused");
        assert!(matches!(
            error,
            Error::CodeMemoryLimitExceeded {
                kind: "slot values",
                limit: CODE_MEMORY_MAX_VALUES_PER_SLOT
            }
        ));
        assert_eq!(encode_slot(&slot), before);
    }

    /// Attachment-index rows mirror the WRITTEN body exactly: the payload of
    /// a value that lost the actor-scoped dedupe keeps no row and no
    /// provenance.
    #[test]
    fn attachment_rows_never_reference_a_deduped_payload() {
        let survivor = value(0x2B, 0x3F, 0x49, 1_000);
        let loser = value(0x2C, 0x3F, 0x49, 2_000);
        let slot = slot_with(vec![survivor.clone(), loser.clone()]);

        assert_eq!(slot.payloads(), vec![survivor.payload]);
        assert_eq!(
            slot.provenance_for_payload(survivor.payload),
            Some(survivor.provenance_claim_id)
        );
        assert_eq!(slot.provenance_for_payload(loser.payload), None);
    }

    // -- crate-seam side-effect mirrors -----------------------------------

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        (dir, vault)
    }

    fn seed_symbol(vault: &Vault, byte: u8) -> EntityId {
        let symbol = id(byte);
        vault
            .put_entity(&symbol, ENTITY_TYPE_CODE_SYMBOL, range(1), 1, b"symbol")
            .expect("seed CODE_SYMBOL");
        symbol
    }

    fn graph_version(vault: &Vault) -> u64 {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let Some(raw) = vault
            .store
            .hnsw_meta
            .get(&rtxn, GRAPH_VERSION_KEY)
            .expect("graph version read")
        else {
            return 0;
        };
        let bytes: [u8; 8] = raw.as_ref().try_into().expect("u64 graph version");
        u64::from_le_bytes(bytes)
    }

    /// CRATE SEAM (invisible through `Vault`): one successful dedicated
    /// `Blocks` write puts IDENTICAL bytes into BOTH edge indexes and bumps
    /// the PPR graph version exactly once, mirroring the landed
    /// edge-mutation side effects.
    #[test]
    fn blocks_write_mirrors_edge_side_effects() {
        let (_dir, vault) = test_vault();
        let blocker = seed_symbol(&vault, 0x71);
        let blocked = seed_symbol(&vault, 0x72);
        let person = id(0x73);
        vault
            .put_entity(&person, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .expect("seed PERSON");
        let actor = WriteActor::new(person, EdgeActorClass::Human);

        let before = graph_version(&vault);
        vault
            .insert_blocks_edge(
                blocker,
                blocked,
                BlocksWriteContext {
                    actor: &actor,
                    source: ClaimSource::UserStated,
                },
            )
            .expect("a Human actor on a trusted source passes the dedicated door");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        let out = vault
            .store
            .edges_out
            .get(
                &rtxn,
                &Store::encode_edge_key(&blocker, EdgeKind::Blocks, &blocked),
            )
            .expect("edges_out read")
            .expect("outbound row");
        let inbound = vault
            .store
            .edges_in
            .get(
                &rtxn,
                &Store::encode_edge_key(&blocked, EdgeKind::Blocks, &blocker),
            )
            .expect("edges_in read")
            .expect("inbound row");
        assert_eq!(
            out.as_ref(),
            inbound.as_ref(),
            "both indexes agree bytewise"
        );
        drop(rtxn);

        assert_eq!(
            graph_version(&vault),
            before + 1,
            "graph version increments exactly once"
        );
    }

    /// CRATE SEAM: the acyclicity walk is KIND-LOCAL. An ordinary structural
    /// path between the same endpoints is invisible to it, so it can never
    /// fabricate a readiness cycle.
    #[test]
    fn blocks_reachability_walk_is_kind_local() {
        let (_dir, vault) = test_vault();
        let left = seed_symbol(&vault, 0x74);
        let right = seed_symbol(&vault, 0x75);
        vault
            .put_edge(&left, EdgeKind::DerivedFrom, &right, 0.2)
            .expect("an ordinary structural edge still writes through the generic door");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        assert!(!blocks_path_exists(&vault, &rtxn, left, right).expect("walk"));
    }

    /// CRATE SEAM (unreachable through `Vault`): the deindex door's INDEX-ONLY
    /// arm — the one that returns before it ever reads an entity record —
    /// sweeps this module's rows too.
    ///
    /// The public API cannot produce this state, because attaching requires a
    /// live `CODE_SYMBOL` anchor; a symbol whose entity row is already gone is
    /// exactly what that arm exists for, and the anchor TYPE is no longer
    /// readable there. Deleting the entity row directly is the only way to
    /// hand the arm L2 material to clean up.
    #[test]
    fn index_only_deindex_still_clears_code_memory_rows() {
        let (_dir, vault) = test_vault();
        let symbol = seed_symbol(&vault, 0x76);
        vault
            .attach_code_memory(AttachCodeMemory {
                anchor: CodeMemoryAnchor {
                    symbol_id: symbol,
                    locator: locator(),
                },
                slot: slot_name(),
                value: value(0x77, 0x78, 0x79, 100),
            })
            .expect("attach");

        vault
            .with_write_txn(|wtxn| {
                vault.store.entities.delete(wtxn, symbol.as_bytes())?;
                Ok(())
            })
            .expect("drop only the anchor entity row");

        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &symbol)
            })
            .expect("index-only deindex");

        let rtxn = vault.store.env.read_txn().expect("read txn");
        let slots = read_slots_for_symbol(&vault.store, &rtxn, &symbol).expect("slots");
        let rows = read_attachments_for_symbol(&vault.store, &rtxn, &symbol).expect("rows");
        assert!(slots.is_empty(), "the index-only arm sweeps slot bodies");
        assert!(rows.is_empty(), "and the attachment index with them");
    }
}
