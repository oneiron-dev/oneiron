use super::*;

#[test]
fn decay_and_summaries_never_lose_source_or_write_claims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let raw = b"tool output\0\xff exact bytes";
    let source;
    {
        let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
        source = store_output(&vault, raw)?;
        assert_eq!(source, store_output(&vault, raw)?);
    }
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let entry = OutputContextEntry {
        source,
        created_turn: 1,
        overview: "short overview".into(),
    };
    let wire = serde_json::to_vec(&entry).unwrap();
    assert!(!wire.windows(11).any(|w| w == b"tool output"));
    let policy = OutputDecayPolicy {
        overview_after_turns: 2,
        stub_after_turns: 5,
    };
    assert_eq!(entry.view(&vault, 1, policy)?.bytes, raw);
    assert_eq!(entry.view(&vault, 3, policy)?.tier, OutputTier::Overview);
    let stub = entry.view(&vault, 6, policy)?;
    assert_eq!(stub.tier, OutputTier::Stub);
    assert!(stub.bytes.is_empty());
    let OutputAffordance::Reexpand(reference) = stub.affordances[0] else {
        panic!("reexpand");
    };
    assert_eq!(restore_output(&vault, reference)?, raw);
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    assert_eq!(
        summarize_output(&vault, source, b"recipe-v1", |_| Ok("summary".into()))?,
        "summary"
    );
    assert_eq!(
        summarize_output(&vault, source, b"recipe-v1", |_| panic!("must use cache"))?,
        "summary"
    );
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?,
        before
    );
    let wrong = OutputRef {
        byte_len: source.byte_len + 1,
        ..source
    };
    assert!(restore_output(&vault, wrong).is_err());
    Ok(())
}
