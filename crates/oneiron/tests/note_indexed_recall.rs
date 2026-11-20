//! An owner's recall finds a NOTE by its words (ARCH-0032: a research NOTE is
//! vault-readable), and still leaves an owner-only NOTE out of ordinary
//! retrieval.
//!
//! A recall reads each hit at its indexed revision. A native NOTE's indexed
//! revision reads as the logical body, its core with its prose. Before the
//! fix two read gates judged those bytes with the strict core codec, which
//! refuses a body that carries prose, so the recall dropped every NOTE it
//! found: context-pack hydration and the scoped read lane's re-check of a
//! revision that is not its live row.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test
//! note_indexed_recall`.

use oneiron::edge::EdgeActorClass;
use oneiron::memory::RecallRequest;
use oneiron::task_verb::sdk::recall_unembedded;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Vault, VaultConfig};

/// A vault with one NOTE of `kind` holding `markdown`, its text published as
/// the idle loop publishes it (no vector in this vault), and the owner.
fn vault_with_note(kind: &str, markdown: &str) -> (tempfile::TempDir, Vault, EntityId, EntityId) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let note = vault.create_note(kind, markdown, actor).expect("NOTE");
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty(),
        "every staged text publishes: {published:?}"
    );
    (dir, vault, owner, note)
}

/// The ids of the records the owner's recall of `query` answers.
fn recalled_ids(vault: &Vault, owner: EntityId, query: &str) -> Vec<String> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let pack = recall_unembedded(
        &memory,
        RecallRequest {
            query: query.to_owned(),
            ..RecallRequest::default()
        },
    )
    .expect("recall");
    pack.items
        .iter()
        .filter_map(|item| item.record.as_ref())
        .map(|record| record.id.clone())
        .collect()
}

#[test]
fn an_owner_recall_finds_a_research_note_by_its_words() {
    let (_dir, vault, owner, note) =
        vault_with_note("research", "We set the quillwort budget for the quarter.");

    let ids = recalled_ids(&vault, owner, "quillwort");

    assert!(
        ids.contains(&note.to_hex()),
        "the recall answers the NOTE that holds the word: {ids:?}"
    );
}

#[test]
fn an_owner_only_note_stays_out_of_ordinary_recall() {
    let (_dir, vault, owner, note) =
        vault_with_note("diary", "Today the quillwort budget was set.");

    let ids = recalled_ids(&vault, owner, "quillwort");

    assert!(
        !ids.contains(&note.to_hex()),
        "ordinary retrieval leaves an owner-only NOTE out: {ids:?}"
    );
}
