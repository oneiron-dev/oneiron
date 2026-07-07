//! ONE-1544 / RCPT-7 (OF-369, B2 RS9): context receipt field-set on
//! emit-adjacent receipts.
//!
//! Record-not-replay law: the substrate replays facts-at-T, but derived
//! views (the activation set, the board as shown) drift with embedder /
//! index / ranker versions, so they are RECORDED at emit time and never
//! recomputed. OF-326 interaction: emit-adjacent receipts in an off-record
//! session are session-local and deleted with the transcript.

use oneiron::{
    ContextReceiptFields, EiriMemoryBoard, EiriMemoryBoardBudget, EntityId, GrantMintIntent,
    GrantMintIntentScope, HnswConfig, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    PromptRecompileStamp, ReceiptQuery, ReceiptRecord, Result, SessionLocalReceiptLog, TimeRange,
    Vault, VaultConfig, append_context_receipt_fields, context_pack::assemble_eiri_memory_board,
    eiri_memory_board_state_ref, outbound_intent_receipt, resolve_eiri_v3_prompt,
    types::ENTITY_TYPE_TURN, workspace_prompt_package_root,
};

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
}

fn entity(seed: u8) -> EntityId {
    let mut bytes = [seed; 16];
    bytes[0] = seed.max(1);
    EntityId::from_bytes(bytes).expect("test entity id")
}

fn put_memory(vault: &Vault, seed: u8, text: &str) -> Result<()> {
    let id = entity(seed);
    let vector = [f32::from(seed) / 255.0, 0.5, 0.25, 0.125];
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            u64::from(seed),
            text.as_bytes(),
        )
        .text(&id, &[("body", text)])
        .vector(&id, &vector)
        .commit()?;
    Ok(())
}

fn assembled_board(vault: &Vault) -> Result<EiriMemoryBoard> {
    let pack = vault.context_pack().search_text("matcha", 8).run()?;
    Ok(assemble_eiri_memory_board(
        &pack,
        EiriMemoryBoardBudget::new(8, 2, 8, 8, 8, 8),
        None,
    ))
}

fn persona_stamp() -> PromptRecompileStamp {
    let package_root = workspace_prompt_package_root().expect("monorepo prompt package");
    resolve_eiri_v3_prompt(package_root)
        .expect("eiri v3 prompt resolves")
        .stamp
}

fn emit_intent(trigger_ref: &str) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com")
            .on_behalf_of("owner"),
        OutboundIntentTrigger::agent_immediate(trigger_ref).job_ref("brief:tea-party"),
    )
}

#[test]
fn emit_receipt_answers_what_did_she_know_from_the_receipt_alone() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    put_memory(&vault, 0x21, "matcha ritual")?;
    put_memory(&vault, 0x22, "matcha whisk and a warm bowl")?;
    put_memory(&vault, 0x23, "matcha powder from the spring harvest fair")?;

    let board = assembled_board(&vault)?;
    assert!(!board.rows.is_empty(), "activation set is non-empty");

    let stamp = persona_stamp();
    let context = ContextReceiptFields::from_assembly(&stamp, &board)?
        .substrate_ref(format!("model:{}", entity(0x77).to_hex()))
        .model("test-model-v1")
        .reasoning_effort("medium")
        .prompt_input_ref("prompt:cafe1234");

    let mut receipt = outbound_intent_receipt(
        "outbound:intent:tea-invite",
        "intent:tea-invite",
        &emit_intent("session:tea-invite"),
        1_000,
        "delivered_to_channel",
    );
    append_context_receipt_fields(&mut receipt, &context)?;

    // "What did she know when she said that" is answered from the receipt
    // alone: round-trip through storage bytes, then read the field-set with
    // no board, stamp, or vault in hand.
    let stored = serde_json::to_string(&receipt).expect("receipt serializes");
    let restored: ReceiptRecord = serde_json::from_str(&stored).expect("receipt deserializes");
    let recorded = restored
        .context_receipt_fields()
        .expect("emit receipt carries the context field-set");

    assert_eq!(
        recorded.persona_compile_stamp,
        format!("{}:{}", stamp.schema_version, stamp.resolved_fingerprint)
    );
    assert_eq!(
        recorded.activated_memory_ids,
        board
            .rows
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        recorded.board_state_ref,
        eiri_memory_board_state_ref(&board)?
    );
    assert_eq!(
        recorded.substrate_ref.as_deref(),
        Some(format!("model:{}", entity(0x77).to_hex()).as_str())
    );
    assert_eq!(recorded.model.as_deref(), Some("test-model-v1"));
    assert_eq!(recorded.reasoning_effort.as_deref(), Some("medium"));
    assert_eq!(
        recorded.prompt_input_ref.as_deref(),
        Some("prompt:cafe1234")
    );
    Ok(())
}

#[test]
fn index_rebuild_does_not_change_a_stored_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    put_memory(&vault, 0x21, "matcha ritual")?;
    put_memory(&vault, 0x22, "matcha whisk and a warm bowl")?;
    put_memory(&vault, 0x23, "matcha powder from the spring harvest fair")?;

    let board_at_emit = assembled_board(&vault)?;
    let context = ContextReceiptFields::from_assembly(&persona_stamp(), &board_at_emit)?
        .model("test-model-v1");

    let mut receipt = outbound_intent_receipt(
        "outbound:intent:tea-invite",
        "intent:tea-invite",
        &emit_intent("session:tea-invite"),
        1_000,
        "delivered_to_channel",
    );
    append_context_receipt_fields(&mut receipt, &context)?;
    let stored = serde_json::to_string(&receipt).expect("receipt serializes");

    // The substrate and its indexes move on after the emit: new memories
    // land (ranking ahead of the emit-time rows) and the vector index is
    // rebuilt.
    put_memory(&vault, 0x11, "matcha matcha matcha, always matcha")?;
    put_memory(&vault, 0x12, "matcha matcha morning, matcha evening")?;
    vault.maintain().rebuild_hnsw().run()?;

    let board_after_rebuild = assembled_board(&vault)?;
    let fresh = ContextReceiptFields::from_assembly(&persona_stamp(), &board_after_rebuild)?;
    assert_ne!(
        fresh.board_state_ref, context.board_state_ref,
        "the drifted board no longer matches the board as shown at emit"
    );
    assert_ne!(
        fresh.activated_memory_ids, context.activated_memory_ids,
        "the drifted activation set no longer matches the emit-time set"
    );

    // Record, not replay: the stored receipt still answers with the
    // emit-time context, byte for byte.
    let restored: ReceiptRecord = serde_json::from_str(&stored).expect("receipt deserializes");
    assert_eq!(restored, receipt);
    assert_eq!(
        restored.context_receipt_fields().as_ref(),
        Some(&context),
        "stored receipts keep the recorded derived view across index rebuilds"
    );
    Ok(())
}

#[test]
fn off_record_session_emit_receipts_are_deleted_at_session_close() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    put_memory(&vault, 0x21, "matcha ritual")?;
    put_memory(&vault, 0x22, "matcha whisk and a warm bowl")?;

    let board = assembled_board(&vault)?;
    let context = ContextReceiptFields::from_assembly(&persona_stamp(), &board)?;

    let session_emit = |receipt_id: &str, trigger_ref: &str| -> Result<ReceiptRecord> {
        let mut receipt = outbound_intent_receipt(
            receipt_id,
            trigger_ref,
            &emit_intent(trigger_ref),
            1_000,
            "delivered_to_channel",
        );
        append_context_receipt_fields(&mut receipt, &context)?;
        Ok(receipt)
    };

    let mut log = SessionLocalReceiptLog::off_record("session:off-record-1");
    log.record(session_emit(
        "outbound:intent:secret-one",
        "session:secret-one",
    )?)?;
    log.record(session_emit(
        "outbound:intent:secret-two",
        "session:secret-two",
    )?)?;
    assert_eq!(
        log.receipts().len(),
        2,
        "session-local while the room lives"
    );

    let closed = log.close();
    assert!(closed.off_record);
    assert_eq!(closed.deleted, 2, "deleted with the transcript");
    assert!(
        closed.retained.is_empty(),
        "activated_memory_ids must not outlive the off-record room"
    );

    // The same emits in an on-record session are retained at close, context
    // field-set intact.
    let mut log = SessionLocalReceiptLog::on_record("session:on-record-1");
    log.record(session_emit(
        "outbound:intent:kept-one",
        "session:kept-one",
    )?)?;
    let closed = log.close();
    assert!(!closed.off_record);
    assert_eq!(closed.deleted, 0);
    assert_eq!(closed.retained.len(), 1);
    assert_eq!(
        closed.retained[0].context_receipt_fields().as_ref(),
        Some(&context)
    );
    Ok(())
}

#[test]
fn non_emit_receipts_never_carry_the_context_field_set() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let grant_id = entity(0xD9);
    vault.mint_standing_outbound_grant(
        &grant_id,
        &GrantMintIntent {
            principal_ref: "owner".to_owned(),
            origin_component_id: "bundle-approve-party".to_owned(),
            origin_action_id: "approve_bundle_brief_verb_class".to_owned(),
            origin_receipt_ref: Some("gate:bundle-party".to_owned()),
            scope: GrantMintIntentScope::BriefVerbClass {
                brief_ref: "brief:tea-party".to_owned(),
                verb_class: "send".to_owned(),
            },
        },
        90,
    )?;

    let receipts = vault.receipts(ReceiptQuery::new(50))?;
    assert!(!receipts.is_empty());
    for receipt in receipts {
        assert!(
            !receipt.receipt_kind.is_emit_adjacent(),
            "family projections carry no emit receipts today"
        );
        assert_eq!(receipt.context_receipt_fields(), None);
        for key in [
            "persona_compile_stamp",
            "activated_memory_ids",
            "board_state_ref",
            "substrate_ref",
            "model",
            "reasoning_effort",
            "prompt_input_ref",
        ] {
            assert!(
                !receipt.fields.contains_key(key),
                "{} leaked the context field {key}",
                receipt.receipt_id
            );
        }
    }
    Ok(())
}
