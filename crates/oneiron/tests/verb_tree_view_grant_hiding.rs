//! Grant hiding in the shipped verb tree.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

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

fn shipped_verb_paths() -> BTreeSet<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sdk/verbs");
    fs::read_dir(dir)
        .expect("read the shipped verb manifests")
        .filter_map(|entry| {
            entry
                .expect("read a manifest entry")
                .file_name()
                .to_str()
                .expect("verb manifests have UTF-8 names")
                .strip_suffix(".json")
                .map(str::to_owned)
        })
        .collect()
}

fn dotted_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.')
        .map(|token| token.trim_end_matches('.'))
        .filter(|token| token.contains('.'))
}

fn in_subtree(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn hide_subtree(verbs: &BTreeSet<String>, path: &str, grant: &str) -> BTreeMap<String, String> {
    verbs
        .iter()
        .filter(|verb| in_subtree(verb, path))
        .map(|verb| (verb.clone(), grant.to_owned()))
        .collect()
}

#[test]
fn the_default_view_names_no_grant_hidden_path() {
    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let verbs = shipped_verb_paths();
    let options = vault.verb_view_options().expect("the view options read");
    let plain = tree.default_view(&options.as_options());
    let mut seen = BTreeSet::new();
    for path in dotted_tokens(&plain.text).filter(|path| seen.insert(*path)) {
        let hidden = hide_subtree(&verbs, path, "test:hidden");
        if hidden.is_empty() {
            continue; // Not a verb or a prefix of one.
        }
        let options = options.clone().with_hidden(hidden);
        let view = tree.default_view(&options.as_options());
        let mention = dotted_tokens(&view.text).find(|token| in_subtree(token, path));
        assert!(
            mention.is_none(),
            "hidden path {path} is named: {mention:?}"
        );
    }
}

#[test]
fn a_mixed_branch_expands_to_its_visible_descendants() {
    let verbs = shipped_verb_paths();
    assert!(verbs.contains("tasks.create"), "tasks.create is a verb row");
    assert!(
        verbs.contains("tasks.create.from_message"),
        "tasks.create.from_message is a verb row"
    );

    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let plain = vault.verb_view_options().expect("the view options read");
    let hidden = BTreeMap::from([("tasks.create".to_owned(), "tasks:create".to_owned())]);
    let narrowed = plain.clone().with_hidden(hidden);
    let options = narrowed.as_options();
    let branch = tree
        .expand("tasks.create", &options)
        .expect("the mixed branch still expands");
    assert!(branch.contains("tasks.create.from_message"), "{branch}");
    assert!(!branch.contains("(callable itself)"), "{branch}");
    let tasks = tree.expand("tasks", &options).expect("tasks expands");
    assert!(
        tasks.lines().any(|line| {
            line.starts_with("tasks.create ")
                && line.contains("verb")
                && line.contains("from_message")
        }),
        "tasks.create stays listed as a branch: {tasks}"
    );

    let hidden = hide_subtree(&verbs, "tasks.create", "tasks:create");
    let options = plain.with_hidden(hidden);
    let refusal = tree
        .expand("tasks.create", &options.as_options())
        .expect_err("an emptied branch is refused");
    assert_eq!(refusal.code.as_str(), "OUTSIDE_GRANT");
}
