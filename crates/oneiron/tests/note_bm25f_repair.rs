#![cfg(oneiron_test_support)]
//! FIX 7789: missing-posting self-heal proves a NOTE with BM25F fields counted.

use oneiron::edge::EdgeActorClass;
use oneiron::write_envelope::WriteActor;
use oneiron::{Vault, VaultConfig};

#[test]
fn note_with_bm25f_fields_self_heals_a_lost_posting_on_deindex() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);

    let note = vault
        .create_note("research", "an ordinary afternoon entry", actor)
        .expect("NOTE");
    vault
        .memory(owner, EdgeActorClass::Human)
        .set_note_title(note, "alpha")
        .expect("set title");
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty() && published.refreshed.iter().any(|(id, _)| *id == note),
        "the title edit publishes at idle: {published:?}"
    );

    let hits = vault.search_text("alpha", 10).expect("text search");
    assert!(
        hits.iter().any(|hit| hit.id == note),
        "the title posting finds the NOTE: {hits:?}"
    );

    oneiron::test_doors::note_bm25f_repair::deindex_after_lost_posting(&vault, &note, "alpha")
        .expect("the self-heal proves the NOTE counted in its pooled stats");

    let hits = vault.search_text("alpha", 10).expect("text search after deindex");
    assert!(
        !hits.iter().any(|hit| hit.id == note),
        "the deindexed NOTE is no longer found: {hits:?}"
    );
}
