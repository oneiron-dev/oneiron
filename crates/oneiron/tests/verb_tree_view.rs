//! Verb-tree view integration tests (PR 3b-1, step 5a).
//!
//! The default view, `verbs.expand` and `verbs.search` through the brief's public API only
//! (`oneiron::verbs::tree`, `Vault::verb_view_options`). The vault fixture is copied from
//! `crates/oneiron/tests/note_subject_reference.rs` (`fresh_vault`: `Vault::open_owned` with
//! four dimensions and no embedder).

use std::collections::{BTreeMap, BTreeSet};

use oneiron::note::{ContextDefault, ExtractionDefault, NoteKindDescriptor, RetentionDefault};
use oneiron::verbs::tree::{NoteKindLine, TreeRefusalCode, VerbTree, ViewOptions};
use oneiron::{Vault, VaultConfig};

/// The design's 10 base paths in order (DESIGN 7). Test expectation only: the implementation's
/// single list lives beside the setting key.
fn design_base() -> Vec<String> {
    [
        "vault.recall",
        "vault.hydrate",
        "vault.remember",
        "vault.claims.retract",
        "vault.notes.create",
        "vault.writes.pending",
        "self.actor",
        "self.focus.refresh",
        "verbs.expand",
        "verbs.search",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("create a fresh vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(directory.path(), config).expect("open a fresh owned vault");
    (directory, vault)
}

fn view_options<'a>(
    base: &'a [String],
    expanded: &'a [String],
    budget_tok: u32,
    note_kinds: &'a [NoteKindLine],
    hidden: &'a BTreeMap<String, String>,
) -> ViewOptions<'a> {
    ViewOptions {
        base,
        expanded,
        budget_tok,
        note_kinds,
        hidden,
    }
}

fn shipped_tree() -> &'static VerbTree {
    static TREE: std::sync::OnceLock<VerbTree> = std::sync::OnceLock::new();
    TREE.get_or_init(|| VerbTree::shipped().expect("the shipped verb tree parses"))
}

/// The `{TOTAL}` number from a rendered head line (`ONEIRON VERBS · 1,640 verbs ...`).
fn total_from_view(text: &str) -> usize {
    let head = text.lines().next().expect("the view has a head line");
    let after_dot = head.split('·').nth(1).expect("the head names its total");
    let number = after_dot
        .split_whitespace()
        .next()
        .expect("the total leads its clause");
    number
        .replace(',', "")
        .parse()
        .expect("the total parses as a number")
}

fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut quote: Option<char> = None;
    for (index, ch) in text.char_indices() {
        if let Some(open) = quote {
            if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            '{' | '[' | '(' | '<' => depth += 1,
            '}' | ']' | ')' | '>' => depth -= 1,
            _ => {}
        }
        if ch == separator && depth == 0 {
            parts.push(&text[start..index]);
            start = index + ch.len_utf8();
        }
    }
    if !text[start..].trim().is_empty() {
        parts.push(&text[start..]);
    }
    parts
}

/// Field names inside `{ ... }`, split by `separator` (`','` for `takes:`/first lines, `';'`
/// for type declarations). Returns all names and the required ones (no `?`).
fn parse_brace_fields(line: &str, separator: char) -> Option<(Vec<String>, Vec<String>)> {
    let start = line.find('{')?;
    let end = line.rfind('}')?;
    if end <= start {
        return None;
    }
    let inside = line[start + 1..end].trim();
    if inside.is_empty() {
        return Some((Vec::new(), Vec::new()));
    }
    let mut all = Vec::new();
    let mut required = Vec::new();
    for part in split_top_level(inside, separator) {
        let trimmed = part.trim();
        if trimmed.is_empty() || trimmed.starts_with('+') {
            continue;
        }
        let (name_part, _) = trimmed.split_once(':')?;
        let name_part = name_part.trim();
        let optional = name_part.ends_with('?');
        let name = name_part
            .strip_suffix('?')
            .unwrap_or(name_part)
            .trim()
            .to_owned();
        if name.is_empty() {
            return None;
        }
        if !optional {
            required.push(name.clone());
        }
        all.push(name);
    }
    Some((all, required))
}

fn extract_expand_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(found) = rest.find("verbs.expand(\"") {
        let after = &rest[found + "verbs.expand(\"".len()..];
        let Some(end) = after.find('"') else {
            break;
        };
        paths.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    paths
}

fn is_valid_dotted(path: &str) -> bool {
    !path.is_empty()
        && path.split('.').all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|first| first.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

fn extract_dotted_paths(text: &str) -> Vec<String> {
    let mut starts: Vec<usize> = text
        .match_indices("vault.")
        .map(|(index, _)| index)
        .chain(text.match_indices("self.").map(|(index, _)| index))
        .collect();
    starts.sort_unstable();
    let mut paths = Vec::new();
    for start in starts {
        let mut end = start;
        while end < text.len()
            && matches!(
                text.as_bytes()[end],
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.'
            )
        {
            end += 1;
        }
        let candidate = text[start..end].trim_end_matches('.');
        if is_valid_dotted(candidate) {
            paths.push(candidate.to_owned());
        }
    }
    paths
}

#[test]
fn default_view_is_the_same_bytes_for_the_same_inputs() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let first = tree.default_view(&view_options(&base, &expanded, 4000, &note_kinds, &hidden));
    let second = tree.default_view(&view_options(&base, &expanded, 4000, &note_kinds, &hidden));
    assert_eq!(first.text, second.text, "same inputs give the same bytes");
    assert_eq!(
        first.tokens, second.tokens,
        "same inputs give the same token count"
    );
    assert_eq!(
        first.not_expanded, second.not_expanded,
        "same inputs drop the same entries"
    );
    assert!(first.text.ends_with('\n'), "the view ends in a newline");
}

#[test]
fn an_expanded_path_adds_only_its_block() {
    let tree = shipped_tree();
    let base = design_base();
    let none: Vec<String> = Vec::new();
    let with_tasks = vec!["tasks".to_owned()];
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let plain = tree.default_view(&view_options(&base, &none, 4000, &note_kinds, &hidden));
    let expanded = tree.default_view(&view_options(
        &base,
        &with_tasks,
        4000,
        &note_kinds,
        &hidden,
    ));
    assert!(
        !plain.text.contains("EXPANDED FOR THIS VAULT"),
        "the plain view has no expanded block"
    );
    assert!(
        expanded.text.contains("EXPANDED FOR THIS VAULT"),
        "the expanded view names its block"
    );
    let tasks = tree
        .expand(
            "tasks",
            &view_options(&base, &none, 4000, &note_kinds, &hidden),
        )
        .expect("tasks expands");
    assert!(
        expanded.text.contains(tasks.as_str()),
        "the expanded view carries the branch text verbatim"
    );
    let insert = format!("\n\nEXPANDED FOR THIS VAULT (setting code_mode.view)\n{tasks}");
    assert_eq!(
        expanded.text.replace(insert.as_str(), ""),
        plain.text,
        "removing the added block recovers the plain view"
    );
    assert!(
        plain.text.contains("vault.recall({"),
        "the plain view shows its base"
    );
    assert!(
        expanded.text.contains("vault.recall({"),
        "the expansion keeps the base"
    );
    let plain_tokens = plain.tokens;
    let expanded_tokens = expanded.tokens;
    assert!(
        expanded_tokens > plain_tokens,
        "one block adds tokens: plain {plain_tokens}, expanded {expanded_tokens}"
    );
    let dropped = &expanded.not_expanded;
    assert!(dropped.is_empty(), "nothing dropped: {dropped:?}");
}

#[test]
fn over_budget_expanded_entries_fall_back_to_names_with_a_notice() {
    let tree = shipped_tree();
    let base = design_base();
    let none: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let plain = tree.default_view(&view_options(&base, &none, 4000, &note_kinds, &hidden));
    let budget: u32 =
        u32::try_from(plain.tokens + 64).expect("the plain view plus its notice fits in a u32");
    let wanted = vec!["tasks".to_owned(), "vault.mail".to_owned()];
    let tight = tree.default_view(&view_options(&base, &wanted, budget, &note_kinds, &hidden));
    assert!(
        tight
            .text
            .contains("not expanded for size: tasks, vault.mail"),
        "dropped paths in setting order"
    );
    assert_eq!(
        tight.not_expanded, wanted,
        "drops reported in setting order"
    );
    let tokens = tight.tokens;
    assert!(
        tokens <= budget as usize,
        "the tightened view fits: {tokens} within {budget}"
    );
    assert!(
        !tight.text.contains("EXPANDED FOR THIS VAULT"),
        "every entry dropped replaces the block"
    );
    assert!(
        !tight.text.contains("the base alone is"),
        "the notice itself still fits"
    );
}

#[test]
fn a_base_over_budget_is_kept_and_says_by_how_much() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let view = tree.default_view(&view_options(&base, &expanded, 10, &note_kinds, &hidden));
    assert!(
        view.text.contains("vault.recall({"),
        "the base is kept over budget"
    );
    assert!(
        view.text.contains("the base alone is"),
        "the base over budget says so"
    );
    assert!(
        view.text.contains("over code_mode.view.budget_tok 10"),
        "the notice names the budget"
    );
    let tokens = view.tokens;
    assert!(tokens > 10, "the tiny budget is exceeded: {tokens} tokens");
}

#[test]
fn note_kinds_come_from_the_vault_registry() {
    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let descriptors = [
        (
            "testpack/durable",
            ContextDefault::VaultReadable,
            RetentionDefault::Durable,
            None,
        ),
        (
            "testpack/session",
            ContextDefault::VaultReadable,
            RetentionDefault::SessionSealed,
            None,
        ),
        (
            "testpack/archived",
            ContextDefault::RelationshipScoped,
            RetentionDefault::ArchiveAfterDays,
            Some(30),
        ),
        (
            "testpack/hidden",
            ContextDefault::ExplicitOnly,
            RetentionDefault::Durable,
            None,
        ),
    ];
    for (kind, context, retention, archive_after_days) in descriptors {
        vault
            .register_note_kind(&NoteKindDescriptor {
                pack: "testpack".to_owned(),
                kind: kind.to_owned(),
                extraction: ExtractionDefault::Allowed,
                context,
                retention,
                archive_after_days,
            })
            .expect("the pack kind registers");
    }
    let options = vault.verb_view_options().expect("the view options read");
    let view = tree.default_view(&options.as_options());
    let block = view
        .text
        .split("\n\n")
        .find(|block| block.starts_with("vault.notes.create("))
        .expect("the create entry renders");
    assert!(
        block.contains("\"testpack/durable\""),
        "a durable kind lists bare: {block}"
    );
    assert!(
        block.contains("\"testpack/session\" (this session only)"),
        "a sealed kind names its retention: {block}"
    );
    assert!(
        block.contains("\"testpack/archived\" (archived after 30 days)"),
        "an archiving kind names its days: {block}"
    );
    assert!(
        !view.text.contains("testpack/hidden"),
        "an explicit-only kind stays out"
    );
}

#[test]
fn view_setting_defaults_are_the_design_defaults() {
    let (_directory, vault) = fresh_vault();
    let options = vault.verb_view_options().expect("the view options read");
    let borrowed = options.as_options();
    let expected = design_base();
    assert_eq!(
        borrowed.base,
        expected.as_slice(),
        "the 10 base paths in order"
    );
    assert!(borrowed.expanded.is_empty(), "no expansion by default");
    assert_eq!(borrowed.budget_tok, 4000, "the default budget");
}

#[test]
fn expand_empty_is_the_default_view() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let view = tree.default_view(&options);
    let again = tree.expand("", &options).expect("empty expands");
    assert_eq!(again, view.text, "empty is the default view");
}

#[test]
fn expand_a_branch_lists_its_children_at_lines() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let tasks = tree.expand("tasks", &options).expect("tasks expands");
    let header = tasks.lines().next().expect("the branch header");
    assert!(
        header.starts_with("tasks ·"),
        "the header names the branch: {header}"
    );
    assert!(
        header.contains("verbs"),
        "the header counts verbs: {header}"
    );
    assert!(
        header.contains("verbs.expand"),
        "the header points deeper: {header}"
    );
    assert!(
        tasks.contains("tasks.accept("),
        "direct verbs render at lines"
    );
    assert!(
        tasks.contains("tasks.create("),
        "direct verbs render at lines"
    );
    let consult = tasks
        .lines()
        .find(|line| line.starts_with("tasks.consult "))
        .expect("the consult branch line");
    assert!(
        consult.contains("verb"),
        "a child branch renders at names: {consult}"
    );
}

#[test]
fn expand_a_verb_gives_its_full_level() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let full = tree
        .expand("vault.claims.retract", &options)
        .expect("the verb expands");
    assert!(
        full.contains("vault.claims.retract(input:"),
        "the signature line: {full}"
    );
    assert!(
        full.contains("Retracts one active claim"),
        "the description"
    );
    assert!(
        full.contains("type ClaimRefRequest"),
        "the input type renders"
    );
    assert!(full.contains("claim_ref"), "the input field renders");
    assert!(full.contains("example:"), "one example renders");
    let example = full
        .lines()
        .find(|line| line.starts_with("  example:"))
        .expect("the example line");
    assert!(
        example.contains("vault.claims.retract"),
        "the example line names the verb: {example}"
    );
}

#[test]
fn expand_a_type_gives_it_and_the_types_it_names() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let receipt = tree
        .expand("CommitReceipt", &options)
        .expect("the type expands");
    assert!(
        receipt.contains("type CommitReceipt"),
        "the declaration renders: {receipt}"
    );
    assert!(receipt.contains("claim_short_id"), "its field renders");
    let referenced = receipt
        .lines()
        .find(|line| line.starts_with("type RecordRef"))
        .expect("the short referenced declaration renders");
    assert!(
        referenced.contains("short_id"),
        "the referenced fields render: {referenced}"
    );
}

#[test]
fn expand_a_bad_path_answers_unknown_path_with_nearest() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let refusal = tree
        .expand("vault.claim.retrac", &options)
        .expect_err("a bad path is refused");
    assert!(
        matches!(refusal.code, TreeRefusalCode::UnknownPath),
        "unknown path code"
    );
    assert_eq!(refusal.code.as_str(), "UNKNOWN_PATH", "the wire spelling");
    let message = &refusal.message;
    assert!(
        message.contains("vault.claim.retrac"),
        "the message names the path: {message}"
    );
    assert!(!refusal.nearest.is_empty(), "nearest paths offered");
    assert_eq!(
        refusal.nearest[0], "vault.claims.retract",
        "the closest verb first"
    );
    assert!(refusal.needs.is_none(), "no grants for an unknown path");
    let missing_type = tree
        .expand("NoSuchTypeXyz", &options)
        .expect_err("a bad type is refused");
    let type_message = &missing_type.message;
    assert!(
        type_message.contains("no type named NoSuchTypeXyz"),
        "the type message: {type_message}"
    );
    assert!(missing_type.nearest.len() <= 5, "at most five nearby types");
}

#[test]
fn search_ranks_full_matches_first_and_marks_base_verbs() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let found = tree
        .search("retract claim", None, None, &options)
        .expect("search answers");
    let mut lines = found.lines();
    let header = lines.next().expect("the header line");
    assert!(
        header.contains("retract claim"),
        "the header names the query: {header}"
    );
    let first = lines.next().expect("a first hit");
    assert!(
        first.contains("vault.claims.retract"),
        "the full match ranks first: {first}"
    );
    assert!(
        first.contains("[base: in your setup text]"),
        "a base verb is marked: {first}"
    );
}

#[test]
fn search_under_and_limit_narrow_the_answer() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let found = tree
        .search("claim", Some("vault.claims"), Some(2), &options)
        .expect("a narrowed search answers");
    let header = found.lines().next().expect("the header line");
    assert!(
        header.contains("under vault.claims"),
        "the header names the scope: {header}"
    );
    let hits: Vec<&str> = found
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("vault.claims."))
        .collect();
    assert_eq!(hits.len(), 2, "the limit holds");
    for hit in &hits {
        assert!(
            hit.starts_with("vault.claims."),
            "every hit sits under the branch: {hit}"
        );
    }
    if found.contains("more;") {
        assert!(
            found.contains("raise the limit"),
            "the trailer offers a wider search"
        );
    }
}

#[test]
fn search_with_no_match_answers_a_sentence() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let query = "qzxwkj vvfppzz";
    let answer = tree
        .search(query, None, None, &options)
        .expect("no match still answers");
    assert!(
        answer.starts_with("0 verbs match"),
        "the no-match sentence: {answer}"
    );
    assert!(answer.contains(query), "the sentence names the query");
    assert!(
        answer.contains("verbs.expand"),
        "the sentence points to a branch"
    );
}

#[test]
fn a_hidden_path_is_left_out_and_expand_names_the_grant_it_needs() {
    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let plain_options = vault.verb_view_options().expect("the view options read");
    let plain = tree.default_view(&plain_options.as_options());
    let mut hidden = BTreeMap::new();
    hidden.insert(
        "vault.claims.retract".to_owned(),
        "claims:retract".to_owned(),
    );
    hidden.insert(
        "tasks.consult.result".to_owned(),
        "tasks:consult".to_owned(),
    );
    let hidden_options = vault
        .verb_view_options()
        .expect("the view options read")
        .with_hidden(hidden);
    let narrowed = tree.default_view(&hidden_options.as_options());
    let plain_total = total_from_view(&plain.text);
    let narrowed_total = total_from_view(&narrowed.text);
    assert_eq!(
        narrowed_total + 2,
        plain_total,
        "hidden verbs leave the counts"
    );
    assert!(
        plain.text.contains("vault.claims.retract({"),
        "the plain view shows its base verb"
    );
    assert!(
        !narrowed.text.contains("vault.claims.retract({"),
        "the hidden verb leaves the view"
    );
    assert!(
        !narrowed
            .text
            .lines()
            .filter(|line| line.starts_with("not shown"))
            .any(|line| line.contains("vault.claims.retract")),
        "a grant-hidden base path is not named"
    );
    let options = hidden_options.as_options();
    let missing = tree
        .search("retract claim", None, None, &options)
        .expect("search answers");
    assert!(
        !missing.contains("vault.claims.retract"),
        "the hidden verb leaves search"
    );
    let sibling = tree
        .search("claim", Some("vault.claims"), Some(20), &options)
        .expect("a scoped search answers");
    assert!(
        sibling.contains("vault.claims.list"),
        "a visible sibling stays in search"
    );
    assert!(
        !sibling.contains("vault.claims.retract"),
        "the hidden verb stays out of its scope"
    );
    let branch = tree
        .expand("vault.claims", &options)
        .expect("the branch expands");
    assert!(
        !branch.contains("vault.claims.retract"),
        "the hidden verb leaves its branch"
    );
    assert!(
        branch.contains("vault.claims.list"),
        "a visible sibling stays in its branch"
    );
    let verb_refusal = tree
        .expand("vault.claims.retract", &options)
        .expect_err("the hidden verb is refused");
    assert!(
        matches!(verb_refusal.code, TreeRefusalCode::OutsideGrant),
        "a hidden verb is outside its grant"
    );
    assert_eq!(
        verb_refusal.code.as_str(),
        "OUTSIDE_GRANT",
        "the wire spelling"
    );
    let verb_message = &verb_refusal.message;
    assert!(
        verb_message.contains("vault.claims.retract"),
        "the message names the path: {verb_message}"
    );
    assert!(
        verb_message.contains("claims:retract"),
        "the message names the grant: {verb_message}"
    );
    assert_eq!(
        verb_refusal.needs.as_deref(),
        Some("claims:retract"),
        "needs names the grant"
    );
    let branch_refusal = tree
        .expand("tasks.consult", &options)
        .expect_err("an emptied branch is refused");
    assert!(
        matches!(branch_refusal.code, TreeRefusalCode::OutsideGrant),
        "an emptied branch is outside its grant"
    );
    assert_eq!(
        branch_refusal.needs.as_deref(),
        Some("tasks:consult"),
        "the branch needs its grant"
    );
    let under_refusal = tree
        .search("claim", Some("tasks.consult"), None, &options)
        .expect_err("a hidden scope is refused");
    assert!(
        matches!(under_refusal.code, TreeRefusalCode::OutsideGrant),
        "a hidden scope is outside its grant"
    );
}

#[test]
fn every_base_text_names_real_fields_and_paths() {
    let tree = shipped_tree();
    let base = design_base();
    let expanded: Vec<String> = Vec::new();
    let note_kinds: Vec<NoteKindLine> = Vec::new();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &expanded, 4000, &note_kinds, &hidden);
    let view = tree.default_view(&options);
    for path in &base {
        let first_prefix = format!("{path}(");
        let first = view
            .text
            .lines()
            .find(|line| line.starts_with(first_prefix.as_str()))
            .expect("every base path renders its first line");
        let Some(takes) = tree.verb_takes(path) else {
            continue;
        };
        if takes.contains('{') {
            let (real_all, real_required) =
                parse_brace_fields(&takes, ',').expect("the takes line parses");
            let (base_all, _) = parse_brace_fields(first, ',').expect("the base first line parses");
            for field in &base_all {
                assert!(
                    real_all.contains(field),
                    "the {path} base names only real fields: {field} not in {real_all:?}"
                );
            }
            for field in &real_required {
                assert!(
                    base_all.contains(field),
                    "the {path} base names every required field: missing {field}"
                );
            }
            continue;
        }
        let Some(inner) = takes.find('<').and_then(|open| {
            takes
                .rfind('>')
                .map(|close| takes[open + 1..close].to_owned())
        }) else {
            continue;
        };
        let declaration = tree
            .expand(inner.as_str(), &options)
            .expect("the envelope inner type expands");
        let inner_first = declaration
            .lines()
            .next()
            .expect("the inner declaration renders");
        let (inner_all, inner_required) =
            parse_brace_fields(inner_first, ';').expect("the inner declaration parses");
        let (base_all, _) = parse_brace_fields(first, ',').expect("the base first line parses");
        for field in &base_all {
            assert!(
                inner_all.contains(field),
                "the {path} base names only inner fields: {field} missing from {inner}"
            );
        }
        for field in &inner_required {
            assert!(
                base_all.contains(field),
                "the {path} base names every required inner field: missing {field} from {inner}"
            );
        }
    }
    let mut mentioned = BTreeSet::new();
    for path in extract_expand_paths(&view.text) {
        mentioned.insert(path);
    }
    for path in extract_dotted_paths(&view.text) {
        mentioned.insert(path);
    }
    for path in &mentioned {
        assert!(
            tree.expand(path, &options).is_ok(),
            "a mentioned path exists: {path}"
        );
    }
}

#[test]
fn the_default_view_fits_its_default_budget() {
    let (_directory, vault) = fresh_vault();
    let tree = shipped_tree();
    let options = vault.verb_view_options().expect("the view options read");
    let view = tree.default_view(&options.as_options());
    let tokens = view.tokens;
    assert!(
        tokens <= 4000,
        "the default view fits its budget: {tokens} tokens"
    );
}

#[test]
fn verb_takes_and_example_for_vault_get() {
    let tree = shipped_tree();
    let takes = tree
        .verb_takes("vault.get")
        .expect("vault.get names what it takes");
    assert!(takes.contains("vault.get"), "takes names the verb: {takes}");
    assert!(
        takes.contains("entity_ref: string"),
        "takes names entity_ref with its type: {takes}"
    );
    let example = tree
        .verb_example("vault.get")
        .expect("vault.get has an example");
    assert!(
        example.contains("vault.get"),
        "the example names the verb: {example}"
    );
    assert!(
        example.contains("entity_ref"),
        "the example uses entity_ref: {example}"
    );
}

#[test]
fn a_grant_hidden_path_is_not_named_but_an_unknown_one_is() {
    let tree = shipped_tree();
    let mut base = design_base();
    base.push("vault.no_such_verb".to_owned());
    let expanded = ["tasks.consult".to_owned()];
    let hidden = BTreeMap::from([
        ("vault.remember".to_owned(), "write".to_owned()),
        (
            "tasks.consult.result".to_owned(),
            "tasks:consult".to_owned(),
        ),
    ]);
    let view = tree.default_view(&view_options(&base, &expanded, 4000, &[], &hidden));
    let notices: Vec<_> = view
        .text
        .lines()
        .filter(|line| line.starts_with("not shown"))
        .collect();
    assert_eq!(notices.len(), 1, "one skip notice: {notices:?}");
    assert_eq!(
        notices[0],
        "not shown (not in the tree): vault.no_such_verb"
    );
    assert!(
        notices
            .iter()
            .all(|line| !line.contains("vault.remember") && !line.contains("tasks.consult")),
        "the skip notice omits grant-hidden paths"
    );
    assert!(
        !view
            .text
            .lines()
            .any(|line| line.starts_with("vault.remember(")),
        "the hidden base entry is left out"
    );
}

#[test]
fn every_path_a_branch_expansion_prints_expands() {
    let tree = shipped_tree();
    let base = design_base();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &[], 4000, &[], &hidden);
    let tasks = tree.expand("tasks", &options).expect("tasks expands");
    assert!(!tasks.contains(".*"), "no wildcard paths: {tasks}");
    let branch = tasks
        .lines()
        .find(|line| line.starts_with("tasks.create "))
        .expect("the tasks.create branch line");
    assert!(branch.contains("under this callable verb"), "{branch}");
    for line in tasks.lines() {
        let path = line.split([' ', '(']).next().expect("the line has a path");
        assert!(
            tree.expand(path, &options).is_ok(),
            "cannot expand the path on: {line}"
        );
    }
}

#[test]
fn a_full_signature_keeps_the_stored_result_card() {
    let tree = shipped_tree();
    let base = design_base();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &[], 4000, &[], &hidden);
    let full = tree
        .expand("vault.hydrate", &options)
        .expect("vault.hydrate expands");
    let signature = full
        .lines()
        .next()
        .expect("the first line is the signature");
    assert!(signature.starts_with("vault.hydrate("), "{signature}");
    assert!(signature.contains(" | StoredResult>"), "{signature}");
}

#[test]
fn the_remember_base_text_falls_back_to_the_actor_ref() {
    let tree = shipped_tree();
    let base = design_base();
    let hidden = BTreeMap::new();
    let view = tree.default_view(&view_options(&base, &[], 4000, &[], &hidden));
    assert!(
        view.text
            .contains("subject_ref: me.person_ref ?? me.actor_ref")
    );
    assert!(
        view.text
            .contains(r#"if ("actor_ref" in me) await vault.remember("#)
    );
    assert!(!view.text.contains("subject_ref: me.person_ref,"));
}

#[test]
fn the_self_fold_example_passes_a_span() {
    let tree = shipped_tree();
    let base = design_base();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &[], 4000, &[], &hidden);
    let example = tree
        .verb_example("self.fold")
        .expect("self.fold has an example");
    assert!(example.starts_with("await self.fold(["), "{example}");
    let full = tree
        .expand("self.fold", &options)
        .expect("self.fold expands");
    let example_line = full
        .lines()
        .find(|line| line.starts_with("  example:"))
        .expect("the expansion shows an example");
    assert!(example_line.contains("self.fold(["), "{example_line}");
}

#[test]
fn a_search_retry_quotes_the_query_as_json() {
    let tree = shipped_tree();
    let base = design_base();
    let hidden = BTreeMap::new();
    let options = view_options(&base, &[], 4000, &[], &hidden);
    let query = "\"vault\"";
    for under in [Some("vault.notes"), None] {
        let answer = tree
            .search(query, under, Some(1), &options)
            .expect("search answers");
        if under.is_some() {
            assert!(
                answer.lines().any(|line| line.contains("verbs.search(")),
                "the scoped search suggests a retry: {answer}"
            );
        }
        for line in answer.lines() {
            if let Some((_, rest)) = line.split_once("verbs.search(") {
                let decoded = serde_json::Deserializer::from_str(rest)
                    .into_iter::<String>()
                    .next();
                assert!(
                    matches!(decoded, Some(Ok(ref first)) if first == query),
                    "the first argument is the original query as JSON: {line} ({decoded:?})"
                );
            }
        }
    }
}
