//! Authored reply shapes in the shipped verb-tree base.

use oneiron::verbs::tree::VerbTree;
use oneiron::{Vault, VaultConfig};

fn shipped_tree() -> &'static VerbTree {
    static TREE: std::sync::OnceLock<VerbTree> = std::sync::OnceLock::new();
    TREE.get_or_init(|| VerbTree::shipped().expect("the shipped verb tree parses"))
}

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("create a fresh vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(directory.path(), config).expect("open a fresh owned vault");
    (directory, vault)
}

fn entry<'a>(text: &'a str, signature_start: &str) -> &'a str {
    text.split("\n\n")
        .find(|block| block.starts_with(signature_start))
        .unwrap_or_else(|| panic!("missing base entry {signature_start}"))
}

#[test]
fn the_base_entries_state_the_reply_shapes() {
    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let options = vault.verb_view_options().expect("the view options read");
    let options = options.as_options();
    let view = tree.default_view(&options);
    let hydrate = entry(&view.text, "vault.hydrate(");
    assert!(hydrate.contains("StoredResult"), "{hydrate}");
    assert!(hydrate.contains("source_revision_ref}"), "{hydrate}");

    let recall = entry(&view.text, "vault.recall(");
    assert!(recall.contains("held?:"), "{recall}");
    assert!(recall.contains("source_revision_ref?"), "{recall}");

    let remember = entry(&view.text, "vault.remember(");
    assert!(remember.contains("scope"), "{remember}");
    let edit = tree
        .expand("vault.notes.edit", &options)
        .expect("vault.notes.edit expands");
    assert!(edit.contains(r#"kind: "whole_text""#), "{edit}");
}
