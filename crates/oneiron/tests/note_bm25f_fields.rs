//! FIX 7789 (ARCH-0032 #bm25f): a NOTE's title is a BM25F field of its own.
//!
//! Before the fix a NOTE's text index published its body alone, pooled with
//! every other text, so a word that only its title holds was not found by a
//! text search at all.

use oneiron::edge::EdgeActorClass;
use oneiron::write_envelope::WriteActor;
use oneiron::{Vault, VaultConfig};

#[test]
fn note_title_word_ranks_above_the_same_word_in_a_body() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);

    let titled = vault
        .create_note("research", "an ordinary afternoon entry", actor)
        .expect("titled NOTE");
    vault
        .memory(owner, EdgeActorClass::Human)
        .set_note_title(titled, "Quillwort")
        .expect("set title");
    let bodied = vault
        .create_note(
            "research",
            "quillwort grows beside an ordinary afternoon pond",
            actor,
        )
        .expect("bodied NOTE");
    // An edited NOTE's text publishes at idle, not at the edit: publish the
    // title edit as the idle loop does (no vector in this vault), then search.
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty() && published.refreshed.iter().any(|(id, _)| *id == titled),
        "the title edit publishes at idle: {published:?}"
    );

    let hits: Vec<_> = vault
        .search_text("quillwort", 10)
        .expect("text search")
        .iter()
        .map(|hit| hit.id)
        .collect();
    assert!(hits.contains(&bodied), "the body hit is found: {hits:?}");
    assert_eq!(
        hits.first(),
        Some(&titled),
        "the title hit ranks first (title weight 2.0, body 1.0): {hits:?}"
    );
}
