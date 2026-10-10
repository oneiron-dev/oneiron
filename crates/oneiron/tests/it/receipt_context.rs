//! ONE-1544 / RCPT-7 (OF-369, B2 RS9): context receipt field-set on
//! emit-adjacent receipts.
//!
//! Record-not-replay law: the substrate replays facts-at-T, but derived
//! views (the activation set, the board as shown) drift with embedder /
//! index / ranker versions, so they are RECORDED at emit time and never
//! recomputed. OF-326 interaction: emit-adjacent receipts in an off-record
//! session are session-local and deleted with the transcript.

use crate::common::entity;
use oneiron::{
    HnswConfig, MemoriesBudget, MemoriesSection, Result, TimeRange, Vault, VaultConfig,
    context_board::project_memories_section, prompt::SessionPromptParts,
    prompt::assemble_session_prompt, receipt::ContextReceiptFields, registry::ENTITY_TYPE_TURN,
};

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
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

fn assembled_board(vault: &Vault) -> Result<MemoriesSection> {
    let pack = vault.context_pack().search_text("matcha", 8).run()?;
    Ok(project_memories_section(
        &pack,
        MemoriesBudget::new(8, 2, 8, 8, 8, 8),
        None,
        None,
    ))
}

#[test]
fn host_section_edits_change_receipt_prompt_identity_without_changing_file_provenance() -> Result<()>
{
    let (_tmp, vault) = temp_vault()?;
    put_memory(&vault, 0x21, "matcha ritual")?;
    let board = assembled_board(&vault)?;
    let package = tempfile::tempdir()?;
    let prompt = package.path().join("session.md");
    std::fs::write(&prompt, "host-supplied standing instructions\n")?;

    let assemble = |policy: &str| {
        assemble_session_prompt(
            &prompt,
            package.path(),
            SessionPromptParts {
                activated_memory: vec!["same activated memory".to_owned()],
                history: Vec::new(),
                host_sections: vec![format!("# Policy\nUse policy {policy}")],
            },
        )
    };
    let first = assemble("A")?;
    let second = assemble("B")?;
    let repeat = assemble("A")?;
    assert_ne!(first.system_prompt, second.system_prompt);
    assert_eq!(first.system_prompt, repeat.system_prompt);
    assert_eq!(
        first.stamp.source_fingerprint,
        second.stamp.source_fingerprint
    );
    assert_eq!(
        first.stamp.resolved_fingerprint,
        second.stamp.resolved_fingerprint
    );
    assert_ne!(
        first.stamp.assembled_fingerprint,
        second.stamp.assembled_fingerprint
    );
    assert_eq!(
        first.stamp.assembled_fingerprint,
        repeat.stamp.assembled_fingerprint
    );

    let first_receipt = ContextReceiptFields::from_assembly(&first.stamp, &board)?;
    let second_receipt = ContextReceiptFields::from_assembly(&second.stamp, &board)?;
    let repeat_receipt = ContextReceiptFields::from_assembly(&repeat.stamp, &board)?;
    assert_ne!(
        first_receipt.persona_compile_stamp,
        second_receipt.persona_compile_stamp
    );
    assert_eq!(
        first_receipt.persona_compile_stamp,
        repeat_receipt.persona_compile_stamp
    );
    assert_eq!(
        first_receipt.board_state_ref,
        second_receipt.board_state_ref
    );
    Ok(())
}
