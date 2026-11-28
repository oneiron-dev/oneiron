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

const STRICT_TINY_INDEX_JSON: &str = r#"{"revision":"strict-tiny-1",
"verbs":{"hidden.only":{"description":"Hidden only.","input":"EmptyRequest","output":"unknown","example":null},
"tasks.accept":{"description":"Accepts one task.","input":"EmptyRequest","output":"unknown","example":"return await verbs.expand(\"hidden\") // expand-marker"},
"tasks.create":{"description":"Hidden parent.","input":"HiddenType","output":"unknown","example":null},
"tasks.create.from_message":{"description":"Keeps the thing. \nSee tasks.create for the hidden parent zephyr.","input":"EmptyRequest","output":"unknown","example":"await tasks.create({ spec: \"zephyr-example-marker\" })"},
"tasks.update":{"description":"Updates one task.","input":"EmptyRequest","output":"unknown","example":null},
"vault.notes.create":{"description":"Creates a note.","input":"CreateNoteRequest","output":"unknown","example":"await vault.notes.create({ kind: \"research\", markdown: \"hi\" })"},
"vault.notes.edit":{"description":"Edits one note quixotic.","input":"EmptyRequest","output":"unknown","example":"await vault.notes.edit({ marker: \"hidden-edit-marker\" })"},
"verbs.expand":{"description":"Expands one path.","input":"EmptyRequest","output":"unknown","example":null}},
"types":{"CreateNoteRequest":"type CreateNoteRequest = { kind: string };","HiddenType":"type HiddenType = { secret: string };"},
"families":{"hidden":"hidden family","tasks":"task family","vault":"vault family","verbs":"discovery family"},
"vault_capabilities":{},"head":"TINY TREE · {TOTAL} verbs · {BASE_COUNT} base",
"base":{"vault.notes.create":"vault.notes.create({ kind: string })\n  kind is one of {note_kinds}.\n  See vault.notes.edit for edits."}}"#;

fn register_strict_therapy_kind(vault: &Vault) {
    use oneiron::note::{ContextDefault, ExtractionDefault, NoteKindDescriptor, RetentionDefault};
    let descriptor = NoteKindDescriptor {
        pack: "testpack".into(),
        kind: "testpack/therapy".into(),
        extraction: ExtractionDefault::Allowed,
        context: ContextDefault::RelationshipScoped,
        retention: RetentionDefault::Durable,
        archive_after_days: None,
    };
    vault
        .register_note_kind(&descriptor)
        .expect("therapy kind registers");
}

/// The strict projection counts, names and shows examples only for admitted rows.
///
/// Red: remove the `admitted.0.contains(*path)` predicate in `VerbTree::discovery_view`;
/// the strict head counts the omitted rows and fails the `5 verbs` assertion.
#[test]
fn strict_projection_never_counts_names_or_examples_outside_grant() {
    use oneiron::verbs::tree::{AdmittedRows, NoteKindAudience};
    let tree = VerbTree::from_index_json(STRICT_TINY_INDEX_JSON).expect("tiny index parses");
    let (_directory, vault) = fresh_vault();
    register_strict_therapy_kind(&vault);
    let admitted: AdmittedRows = [
        "tasks.create.from_message",
        "tasks.accept",
        "tasks.update",
        "vault.notes.create",
        "verbs.expand",
    ]
    .into_iter()
    .collect();
    let view = tree.discovery_view(
        admitted,
        vault.verb_view_options().expect("options"),
        NoteKindAudience::NonOwner,
    );

    let default = view.expand("").expect("strict default renders");
    assert_eq!(
        default.lines().next().expect("head"),
        "TINY TREE · 5 verbs · 2 base",
        "{default}"
    );
    for present in [
        "vault.notes.create",
        "  accept create(1) update",
        "\"research\"",
        "kind is one of",
    ] {
        assert!(
            default.contains(present),
            "default names {present}: {default}"
        );
    }
    for absent in [
        "vault.notes.edit",
        "testpack/therapy",
        "zephyr",
        "expand-marker",
        "hidden-edit-marker",
        "quixotic",
        "HiddenType",
        "hidden.only",
        "not shown",
        "not expanded",
    ] {
        assert!(
            !default.contains(absent),
            "default hides {absent}: {default}"
        );
    }
    for prefix in ["tasks  3 verbs", "vault  1 verbs", "verbs  1 verbs"] {
        assert!(
            default.lines().any(|line| line.starts_with(prefix)),
            "family {prefix}: {default}"
        );
    }
    assert!(
        !default.lines().any(|line| line.starts_with("hidden  ")),
        "hidden family out: {default}"
    );

    let mixed = view.expand("tasks.create").expect("mixed branch expands");
    assert!(
        mixed
            .lines()
            .next()
            .expect("first")
            .starts_with("tasks.create · 1 verbs"),
        "{mixed}"
    );
    assert!(
        mixed.contains("tasks.create.from_message")
            && !mixed.contains("(callable itself)")
            && !mixed.contains("zephyr"),
        "{mixed}"
    );
    let tasks = view.expand("tasks").expect("tasks expands");
    assert!(
        tasks
            .lines()
            .next()
            .expect("first")
            .starts_with("tasks · 3 verbs"),
        "{tasks}"
    );
    assert!(
        tasks
            .lines()
            .any(|line| line == "tasks.create  1 verb: from_message"),
        "{tasks}"
    );
    for present in ["tasks.accept", "tasks.update"] {
        assert!(tasks.contains(present), "tasks names {present}: {tasks}");
    }
    let leaf = view
        .expand("tasks.create.from_message")
        .expect("admitted leaf expands");
    assert!(leaf.contains("Keeps the thing"), "{leaf}");
    for absent in [
        "See tasks.create",
        "zephyr",
        "zephyr-example-marker",
        "await tasks.create(",
    ] {
        assert!(!leaf.contains(absent), "leaf hides {absent}: {leaf}");
    }
    let accept = view.expand("tasks.accept").expect("accept expands");
    assert!(accept.contains("Accepts one task."), "{accept}");
    for absent in ["expand-marker", "verbs.expand(\"hidden\")"] {
        assert!(!accept.contains(absent), "accept hides {absent}: {accept}");
    }
    let note = view
        .expand("vault.notes.create")
        .expect("NOTE leaf expands");
    assert!(note.contains("\"research\""), "{note}");
    for absent in ["testpack/therapy", "vault.notes.edit"] {
        assert!(!note.contains(absent), "NOTE hides {absent}: {note}");
    }

    let hidden_type = view.expand("HiddenType").expect_err("omitted type refuses");
    let missing_type = view
        .expand("DefinitelyNotAType")
        .expect_err("unknown type refuses");
    assert_eq!(
        (hidden_type.code.as_str(), hidden_type.message),
        (missing_type.code.as_str(), missing_type.message)
    );
    assert_eq!(hidden_type.code.as_str(), "UNKNOWN_PATH");
    assert!(
        !hidden_type.message.contains("HiddenType"),
        "{}",
        hidden_type.message
    );
    let kept = view
        .expand("CreateNoteRequest")
        .expect("admitted type expands");
    assert!(
        kept.contains("type CreateNoteRequest = { kind: string };"),
        "{kept}"
    );

    let all = view.search("task", None, None);
    assert_eq!(
        all.lines().next().expect("header"),
        "3 verbs match; best 3:",
        "{all}"
    );
    for present in ["tasks.create.from_message", "tasks.accept", "tasks.update"] {
        assert!(all.contains(present), "search names {present}: {all}");
    }
    for absent in [
        "tasks.create(",
        "vault.notes.create",
        "zephyr",
        "HiddenType",
    ] {
        assert!(!all.contains(absent), "search hides {absent}: {all}");
    }
    let limited = view.search("task", Some("tasks"), Some(2));
    assert_eq!(
        limited.lines().next().expect("header"),
        "3 verbs match; best 2:",
        "{limited}"
    );
    assert!(limited.lines().any(|line| line == "1 more"), "{limited}");

    let zero = view.search("zxqy", None, None);
    let bodies = [
        view.search("quixotic", None, None),
        view.search("zephyr", None, None),
        view.search("tasks.create", None, None),
        view.search("task", Some("hidden"), None),
        view.search("task", Some("no.such.branch"), None),
    ];
    for body in bodies {
        assert_eq!(body, zero, "byte-identical no-match");
    }
    for absent in [
        "quixotic",
        "zephyr",
        "zxqy",
        "hidden",
        "no.such.branch",
        "vault",
        "tasks.create",
        "HiddenType",
    ] {
        assert!(!zero.contains(absent), "no-match hides {absent}: {zero}");
    }
    let missing = view.expand("no.such.verb").expect_err("missing refuses");
    assert_eq!(missing.code.as_str(), "UNKNOWN_PATH");
    let refusals = [
        view.expand("vault.notes.edit").expect_err("hidden leaf"),
        view.expand("hidden").expect_err("hidden branch"),
        hidden_type,
    ];
    for refusal in refusals {
        assert_eq!(
            (refusal.code.as_str(), refusal.message),
            ("UNKNOWN_PATH", missing.message)
        );
    }
    for absent in ["vault.notes.edit", "hidden", "no.such.verb", "HiddenType"] {
        assert!(
            !missing.message.contains(absent),
            "refusal echoes no {absent}: {}",
            missing.message
        );
    }
}

/// Installed NOTE kinds list to the owner only; without `vault.notes.create` no kinds line renders.
///
/// Red: build a NonOwner projection's NOTE kinds from the vault's full kinds instead of `shipped()`;
/// the NonOwner `testpack/therapy` absence assertion fails.
#[test]
fn strict_view_lists_installed_note_kinds_to_the_owner_only() {
    use oneiron::verbs::tree::NoteKindAudience;
    let tree = shipped_tree();
    let (_directory, vault) = fresh_vault();
    register_strict_therapy_kind(&vault);
    let options = vault.verb_view_options().expect("options");
    for (audience, sees_installed) in [
        (NoteKindAudience::Owner, true),
        (NoteKindAudience::NonOwner, false),
    ] {
        let view = tree.discovery_view(
            ["vault.notes.create"].into_iter().collect(),
            options.clone(),
            audience,
        );
        for path in ["", "vault.notes.create"] {
            let body = view.expand(path).expect("note create is admitted");
            assert!(
                body.contains("kind is one of") && body.contains("\"research\""),
                "{body}"
            );
            assert_eq!(body.contains("testpack/therapy"), sees_installed, "{body}");
        }
        let withheld = tree.discovery_view(
            ["tasks.accept"].into_iter().collect(),
            options.clone(),
            audience,
        );
        let body = withheld.expand("").expect("default without note create");
        for absent in ["kind is one of", "\"research\"", "testpack/therapy"] {
            assert!(
                !body.contains(absent),
                "{audience:?} hides {absent}: {body}"
            );
        }
        let refusal = withheld
            .expand("vault.notes.create")
            .expect_err("create is not admitted");
        assert_eq!(refusal.code.as_str(), "UNKNOWN_PATH");
    }
}
