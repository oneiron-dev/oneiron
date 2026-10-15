//! #1465 R3 check (Engine ruling 2): arrival order never changes what an erase takes.

use super::*;

/// Bug repro (#1465 R3, Sol 5; Astra 3): a text derived from bytes a hard erase took here ends the
/// same whether its DerivedFrom edge arrives before its body or after it: its words are not
/// readable, a hard erase's fence stands on it, and a local put of it is refused. The edge that
/// arrives first leaves an obligation keyed by the text's id, which its arrival discharges.
#[test]
fn a_derived_text_ends_the_same_whichever_of_it_and_its_edge_arrives_first() -> Result<()> {
    const WORDS: &[u8] = b"words from the erased bytes";
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let asset = fixture.asset()?;
    vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    let (_dir, peer) = open_test_vault_with(embedding_test_config());
    let texts = [EntityId::now(), EntityId::now()];
    for text in &texts {
        peer.put_entity(text, ENTITY_TYPE_ASSET_TEXT, at(40), 40, WORDS)?;
    }
    let edge = |text: &EntityId| {
        vault.with_write_txn_grouped(|txn| {
            vault.scrub_text_derived_from_erased_in_txn(txn, text, &asset)
        })
    };
    // The text first, then its edge.
    replicate(&peer, vault, &texts[..1])?;
    assert!(edge(&texts[0])?, "the edge left the text it names");
    // The edge first, then the text.
    assert!(
        edge(&texts[1])?,
        "an edge before its text left nothing to scrub it"
    );
    replicate(&peer, vault, &texts[1..])?;

    let outcome = |text: &EntityId| -> Result<(bool, bool, bool)> {
        let readable = vault
            .get_raw(text)?
            .is_some_and(|raw| raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN);
        let fenced = {
            let txn = vault.store.env.read_txn()?;
            crate::blob_artifact::erase_fenced(&vault.store, &txn, text)?
        };
        let put_refused = matches!(
            vault.put_entity(text, ENTITY_TYPE_ASSET_TEXT, at(50), 50, WORDS),
            Err(Error::Artifact(ArtifactError::BlobContentErased))
        );
        Ok((readable, fenced, put_refused))
    };
    assert_eq!(outcome(&texts[0])?, (false, true, true));
    assert_eq!(
        outcome(&texts[1])?,
        outcome(&texts[0])?,
        "the edge arriving first changed what the erase took"
    );
    Ok(())
}
