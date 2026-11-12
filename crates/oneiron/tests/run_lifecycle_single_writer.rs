//! Single-writer guard for the run lifecycle (untangle slices E1, E2 and E3).
//!
//! Every write to one of the seven lifecycle fields of an attempt row
//! (`state`, `active_pause`, `lease_owner`, `scheduled_at`, `settled_at`,
//! `attempt_count`, `cancel_state`) must live in
//! `src/attempt_queue/lifecycle.rs`, inside an associated function of
//! `RunLifecycle`. This test reads the walked files as plain text and fails
//! on any write it finds there, so a direct write cannot slip back in.
//!
//! Scope: every `.rs` file under `src` is walked, sorted, with three skips:
//! `src/attempt_queue/lifecycle.rs`, the single writer; test code by path (a
//! `tests` directory, a file named `tests.rs` or `*_tests.rs`, and
//! `src/test_doors/`), whose fixtures write rows directly; and
//! `src/ports/memory/`, the stale test port that does not compile. E1
//! scanned one file and E2 five; E3 walks the tree.
//!
//! Fields: assignments to `active_pause` and `scheduled_at`, with
//! `AttemptRecord {` literals, are scanned in every walked file: no other
//! struct assigns those names in production code. `state`, `lease_owner`,
//! `settled_at`, `attempt_count` and every `cancel_state` rule (assignments,
//! mutating calls, `&mut` borrows) apply only under `src/attempt_queue/` and
//! in `src/recovery/checkpoint/rebuild.rs`: other structs carry those names
//! (the run reader's branch view in `src/task_verb/run_doors.rs` has a
//! `cancel_state` of its own, which a reader's redaction may assign). When
//! another production struct starts assigning a name of the first group,
//! this test names the line: move the name to the second group. A walk that
//! silently finds nothing must not pass: the test fails unless it scanned
//! the eleven E3 files and the five of E1 and E2 by name (see
//! [`REQUIRED_FILES`]).
//!
//! Detection, per line (standard library only, no regex crate):
//!
//! * Assignments: `.FIELD` as a whole identifier (so `.states` does not
//!   match `.state`), with an optional descendant path below it
//!   (`.cancel_state.pressure.pending`, `receipts[0].trigger`), followed by
//!   `=` or a compound operator (`+=`, `<<=`, ...). A following `==`, `!=`,
//!   `<=`, `>=` is a comparison and `=>` is a match arm: neither flags.
//!   Struct-literal fields (`state: Scheduled`) have no leading dot and never
//!   match; reads (`.state.as_str()`) end at `(` and never match.
//! * Mutating calls: a method from [`MUTATING_METHODS`] called on a
//!   `.cancel_state`-rooted path (`.cancel_state.receipts.push(`). Read-only
//!   calls (`clone`, `len`, `as_ref`, ...) are not in the list.
//! * Mutable borrows: `&mut` of a `.cancel_state`-rooted path
//!   (`&mut record.cancel_state.pressure`, `&mut row.cancel_state`). A plain
//!   `&mut record` (no `.cancel_state` below it) is not a finding.
//! * Fresh rows: an `AttemptRecord {` expression literal. Told apart from a
//!   `use` (skipped explicitly), from a type use (`-> Result<AttemptRecord>`,
//!   `&AttemptRecord`: no `{` follows the name), from a return type (a name
//!   right after `->` is a return type, not a literal), from an item header
//!   (`impl AttemptRecord {`, `impl Trait for AttemptRecord {`,
//!   `struct AttemptRecord {`), from a `let`/`if let` destructure (only
//!   `let`/`let mut` precedes the name on the line) and from a `match`-arm
//!   pattern (a `=>` follows the name on the same line).
//!
//! Full-line comments (`//`, `///`, `//!`) are skipped; a trailing `//`
//! comment and the contents of string and char literals are masked before
//! matching, so neither can flag (a `'` counts as a char literal only in
//! the `'x'` / `'\..'` shape, so lifetimes like `&'a` are ignored).
//!
//! Known limits: the scan is line-based, so a write whose left-hand path
//! spans two lines is missed; block comments (`/* */`) are not stripped
//! and can produce false positives; a write through
//! a local alias of a `cancel_state` member (`pressure.pending = ..` where
//! `pressure: &mut AttemptCancelPressure`) has no `.cancel_state` on its
//! line and is not seen. The borrow rule flags the line that makes such an
//! alias from a row, so the alias cannot be made where that rule applies. An
//! inline `#[cfg(test)]` module is scanned like production code: the guard
//! does no brace matching, so a lifecycle write there would flag (keep test
//! writes in `tests/` files). A whole-row replacement (`*record = ..`, the
//! store codec's secret mask) has no `.FIELD` on its line and is not seen.
//! A qualified function return type ending in `AttemptRecord` with its
//! body brace on the same line flags as a literal (one such line exists,
//! in test code skipped by path).

use std::path::PathBuf;

/// Files the walk must have scanned, sorted: E1 one, E2 four, E3 eleven.
/// A rename that drops one fails the test.
const REQUIRED_FILES: &[&str] = &[
    "src/attempt_queue/cancel/ops.rs",
    "src/attempt_queue/cancel/terminal.rs",
    "src/attempt_queue/completion.rs",
    "src/attempt_queue/engine/defer.rs",
    "src/attempt_queue/engine/enqueue_record.rs",
    "src/attempt_queue/engine/mutate.rs",
    "src/attempt_queue/engine/reclaim.rs",
    "src/attempt_queue/engine/redirect.rs",
    "src/attempt_queue/engine/requeue.rs",
    "src/attempt_queue/engine/successor.rs",
    "src/attempt_queue/engine/workflow.rs",
    "src/attempt_queue/result.rs",
    "src/attempt_queue/settlement.rs",
    "src/attempt_queue/validate/cancel_receipt_landing.rs",
    "src/attempt_queue/validate/field_validators.rs",
    "src/recovery/checkpoint/rebuild.rs",
];

/// The seven lifecycle fields. (`updated_at`, `backoff_until`, `last_error`,
/// `events` and `history` are not lifecycle fields: sites keep writing them.)
/// All seven are scanned under `src/attempt_queue/` and in
/// `src/recovery/checkpoint/rebuild.rs`, with the mutating-call and borrow
/// rules; elsewhere only [`SPECIFIC_FIELDS`] and the literal rule.
const LIFECYCLE_FIELDS: &[&str] = &[
    "state",
    "active_pause",
    "lease_owner",
    "scheduled_at",
    "settled_at",
    "attempt_count",
    "cancel_state",
];

/// Lifecycle fields whose assignments are scanned in every walked file: no
/// other struct assigns them in production code.
const SPECIFIC_FIELDS: &[&str] = &["active_pause", "scheduled_at"];

/// In-place mutators looked for on `.cancel_state`-rooted member paths.
/// Found today: `push` only (`src/attempt_queue/lifecycle.rs:723`,
/// `record.cancel_state.receipts.push(receipt)`, moved there with E2).
/// The rest are the same member types' sibling mutators,
/// guarded so a write cannot hide behind a synonym. Read-only calls seen on
/// these paths today (`clone`, `len`, `last`, `as_ref`, `is_some`, `is_none`,
/// `remaining_units`, ...) are deliberately absent.
const MUTATING_METHODS: &[&str] = &[
    "push",
    "insert",
    "remove",
    "pop",
    "clear",
    "truncate",
    "extend",
    "append",
    "retain",
    "swap_remove",
    "take",
];

/// No lifecycle write outside `lifecycle.rs`: fails naming file, line number
/// and line. Before the E1 port it found 21 assignments and the retry
/// successor's literal in `engine/mutate.rs`; at the E2 head it names 29
/// lines in the eleven E3 files. A required file the walk missed, or an
/// empty one, fails too, so a rename cannot make this pass.
#[test]
fn no_lifecycle_writes_outside_lifecycle_rs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);
    files.sort();
    let mut failures: Vec<String> = Vec::new();
    let mut scanned: Vec<String> = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("walked file is under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        if is_skipped(&rel) {
            continue;
        }
        scanned.push(rel.clone());
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!("{rel}: cannot read file ({error})"));
                continue;
            }
        };
        let narrow = in_ambiguous_scope(&rel);
        let fields = if narrow {
            LIFECYCLE_FIELDS
        } else {
            SPECIFIC_FIELDS
        };
        for (index, line) in text.lines().enumerate() {
            let lineno = index + 1;
            if line.trim_start().starts_with("//") {
                continue;
            }
            let code = mask_line(line);
            if let Some(field) = find_field_assignment_in(&code, fields) {
                failures.push(format!(
                    "{rel}:{lineno}: assignment to .{field}: {}",
                    line.trim()
                ));
            }
            if narrow && let Some(method) = find_mutating_call(&code) {
                failures.push(format!(
                    "{rel}:{lineno}: mutating call .{method}( on .cancel_state path: {}",
                    line.trim()
                ));
            }
            if narrow && has_mut_cancel_borrow(&code) {
                failures.push(format!(
                    "{rel}:{lineno}: &mut borrow of .cancel_state path: {}",
                    line.trim()
                ));
            }
            if is_record_literal(line, &code) {
                failures.push(format!(
                    "{rel}:{lineno}: AttemptRecord struct literal: {}",
                    line.trim()
                ));
            }
        }
    }
    for &required in REQUIRED_FILES {
        if !scanned.iter().any(|rel| rel == required) {
            failures.push(format!("{required}: required file was not walked"));
        } else {
            match std::fs::read_to_string(root.join(required)) {
                Ok(text) if text.trim().is_empty() => {
                    failures.push(format!("{required}: file is empty"));
                }
                Err(error) => {
                    failures.push(format!("{required}: cannot read file ({error})"));
                }
                Ok(_) => {}
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "lifecycle writes outside lifecycle.rs ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Appends every `.rs` file under `dir`, recursively (standard library
/// only). The caller sorts the result so the failure list is stable. Links
/// to directories are not descended into; an unreadable directory fails
/// loudly rather than walking nothing.
fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read directory {} ({error})", dir.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("cannot read entry in {} ({error})", dir.display()));
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot read type of {} ({error})", path.display()));
        if file_type.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Whether the walked file `rel` (crate-relative, forward slashes) is out
/// of scope: the single writer, test code, or the stale test port.
fn is_skipped(rel: &str) -> bool {
    if rel == "src/attempt_queue/lifecycle.rs" {
        return true;
    }
    if rel.starts_with("src/ports/memory/") || rel.starts_with("src/test_doors/") {
        return true;
    }
    if rel.split('/').any(|component| component == "tests") {
        return true;
    }
    if let Some(name) = rel.rsplit('/').next() {
        if name == "tests.rs" || name.ends_with("_tests.rs") {
            return true;
        }
    }
    false
}

/// Whether `rel` is scanned for the names other structs share: `state`,
/// `lease_owner`, `settled_at`, `attempt_count` and the `cancel_state` rules.
fn in_ambiguous_scope(rel: &str) -> bool {
    rel.starts_with("src/attempt_queue/") || rel == "src/recovery/checkpoint/rebuild.rs"
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Detection text for one source line: the `//` comment is cut and the
/// contents of string and char literals are blanked, positions preserved.
/// Only ASCII bytes are inspected, so non-ASCII text passes through
/// untouched (no UTF-8 multibyte sequence contains an ASCII byte).
fn mask_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        out[j] = b' ';
                        if j + 1 < bytes.len() {
                            out[j + 1] = b' ';
                        }
                        j += 2;
                    } else if bytes[j] == b'"' {
                        break;
                    } else {
                        out[j] = b' ';
                        j += 1;
                    }
                }
                i = if j < bytes.len() { j + 1 } else { bytes.len() };
            }
            b'\'' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                    if let Some(rel) = bytes[i + 2..].iter().position(|b| *b == b'\'') {
                        let end = i + 2 + rel;
                        out[i + 1..end].fill(b' ');
                        i = end + 1;
                    } else {
                        break;
                    }
                } else if i + 2 < bytes.len() && bytes[i + 2] == b'\'' {
                    out[i + 1] = b' ';
                    i += 3;
                } else {
                    // A lifetime (`&'a`), not a char literal.
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                out[i..].fill(b' ');
                break;
            }
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Consumes a `(.ident[index])*` tail starting at `j`; returns the index
/// after the last segment. A `.` not followed by an identifier ends the tail
/// (so `.state.as_str()` stops after `as_str`, at the `(`).
fn consume_segments(bytes: &[u8], mut j: usize) -> usize {
    while j < bytes.len() && bytes[j] == b'.' {
        let mut k = j + 1;
        let start = k;
        while k < bytes.len() && is_ident_byte(bytes[k]) {
            k += 1;
        }
        if k == start || !is_ident_start(bytes[start]) {
            break;
        }
        j = k;
        if j < bytes.len() && bytes[j] == b'[' {
            if let Some(rel) = bytes[j + 1..].iter().position(|b| *b == b']') {
                j = j + 1 + rel + 1;
            } else {
                break;
            }
        }
    }
    j
}

/// Whether an assignment operator (`=` or a compound `op=`, never a
/// comparison `==` `!=` `<=` `>=` and never a fat arrow `=>`) sits at `p`
/// after blanks.
fn is_assignment_at(bytes: &[u8], mut p: usize) -> bool {
    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
        p += 1;
    }
    if p >= bytes.len() {
        return false;
    }
    let next = bytes.get(p + 1).copied().unwrap_or(0);
    let next2 = bytes.get(p + 2).copied().unwrap_or(0);
    match bytes[p] {
        b'=' => next != b'=' && next != b'>',
        b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' => next == b'=',
        b'<' | b'>' => {
            if next == b'=' {
                false
            } else {
                next == bytes[p] && next2 == b'='
            }
        }
        _ => false,
    }
}

/// The lifecycle field of `fields` the line assigns to, if any: `.FIELD` as
/// a whole identifier with an optional descendant path below it, followed by
/// an assignment operator (see [`is_assignment_at`]).
fn find_field_assignment_in<'a>(code: &str, fields: &[&'a str]) -> Option<&'a str> {
    let bytes = code.as_bytes();
    for &field in fields {
        let needle = [".", field].concat();
        let mut start = 0;
        while let Some(rel) = code[start..].find(needle.as_str()) {
            let at = start + rel;
            let after = at + needle.len();
            if after >= bytes.len() || !is_ident_byte(bytes[after]) {
                let tail = consume_segments(bytes, after);
                if is_assignment_at(bytes, tail) {
                    return Some(field);
                }
            }
            start = after;
        }
    }
    None
}

/// The mutating method the line calls on a `.cancel_state`-rooted member
/// path, if any: each `.ident` below `.cancel_state` is checked against
/// [`MUTATING_METHODS`] with a `(` after it.
fn find_mutating_call(code: &str) -> Option<&'static str> {
    let bytes = code.as_bytes();
    let mut start = 0;
    while let Some(rel) = code[start..].find(".cancel_state") {
        let at = start + rel;
        let after = at + ".cancel_state".len();
        if after < bytes.len() && is_ident_byte(bytes[after]) {
            start = after;
            continue;
        }
        let mut p = after;
        while p < bytes.len() && bytes[p] == b'.' {
            let mut k = p + 1;
            let name_start = k;
            while k < bytes.len() && is_ident_byte(bytes[k]) {
                k += 1;
            }
            if k == name_start || !is_ident_start(bytes[name_start]) {
                break;
            }
            let name = &code[name_start..k];
            let mut q = k;
            if q < bytes.len() && bytes[q] == b'[' {
                if let Some(rel) = bytes[q + 1..].iter().position(|b| *b == b']') {
                    q = q + 1 + rel + 1;
                } else {
                    break;
                }
            }
            let mut r = q;
            while r < bytes.len() && (bytes[r] == b' ' || bytes[r] == b'\t') {
                r += 1;
            }
            if r < bytes.len() && bytes[r] == b'(' {
                for &method in MUTATING_METHODS {
                    if method == name {
                        return Some(method);
                    }
                }
            }
            p = q;
            if p >= bytes.len() || bytes[p] != b'.' {
                break;
            }
        }
        start = after;
    }
    None
}

/// Whether the line holds a `&mut` borrow of a `.cancel_state`-rooted path
/// (`&mut record.cancel_state.pressure`, `&mut row.cancel_state`). A plain
/// `&mut record` (no `.cancel_state` below it) is not a finding.
fn has_mut_cancel_borrow(code: &str) -> bool {
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(rel) = bytes[i..].iter().position(|b| *b == b'&') else {
            break;
        };
        let at = i + rel;
        let mut p = at + 1;
        while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
            p += 1;
        }
        if p + 3 > bytes.len() || bytes[p] != b'm' || bytes[p + 1] != b'u' || bytes[p + 2] != b't' {
            i = at + 1;
            continue;
        }
        if p + 3 < bytes.len() && is_ident_byte(bytes[p + 3]) {
            i = at + 1;
            continue;
        }
        let mut q = p + 3;
        while q < bytes.len() && (bytes[q] == b' ' || bytes[q] == b'\t') {
            q += 1;
        }
        if q >= bytes.len() || !is_ident_start(bytes[q]) {
            i = at + 1;
            continue;
        }
        let mut e = q;
        while e < bytes.len()
            && (is_ident_byte(bytes[e]) || bytes[e] == b'.' || bytes[e] == b'[' || bytes[e] == b']')
        {
            e += 1;
        }
        let Some(path) = code.get(q..e) else {
            i = at + 1;
            continue;
        };
        let mut start = 0;
        while let Some(rel) = path[start..].find(".cancel_state") {
            let found = start + rel;
            let after = found + ".cancel_state".len();
            if after >= path.len() || !is_ident_byte(path.as_bytes()[after]) {
                return true;
            }
            start = after;
        }
        i = at + 1;
    }
    false
}

/// Whether the line holds an `AttemptRecord {` expression literal (see the
/// module docs for how imports, type uses and patterns are told apart).
fn is_record_literal(line: &str, code: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
        return false;
    }
    let bytes = code.as_bytes();
    let mut start = 0;
    while let Some(rel) = code[start..].find("AttemptRecord") {
        let at = start + rel;
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            start = at + "AttemptRecord".len();
            continue;
        }
        let mut brace = at + "AttemptRecord".len();
        while brace < bytes.len() && (bytes[brace] == b' ' || bytes[brace] == b'\t') {
            brace += 1;
        }
        if brace >= bytes.len() || bytes[brace] != b'{' {
            start = at + "AttemptRecord".len();
            continue;
        }
        let before = code[..at].trim_end();
        if is_let_pattern(before) || is_item_header(before) || is_return_type(before) {
            start = at + "AttemptRecord".len();
            continue;
        }
        if code[brace..].contains("=>") {
            start = at + "AttemptRecord".len();
            continue;
        }
        return true;
    }
    false
}

/// Whether `before` (the line up to an `AttemptRecord` token, right-trimmed)
/// ends a `let` destructure: `let` / `let mut`, including `if let` and
/// `while let`.
fn is_let_pattern(before: &str) -> bool {
    ends_with_keyword(before, &["let mut", "let"])
}

/// Whether `before` ends an item header that names the type: `impl`,
/// `impl Trait for`, `struct`.
fn is_item_header(before: &str) -> bool {
    ends_with_keyword(before, &["impl", "for", "struct"])
}

/// Whether `before` ends with a return arrow: a name right after `->` is a
/// return type, not a literal.
fn is_return_type(before: &str) -> bool {
    before.ends_with("->")
}

/// Whether `before` ends with one of `keywords` as whole words.
fn ends_with_keyword(before: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|keyword| {
        before
            .strip_suffix(*keyword)
            .is_some_and(|rest| rest.is_empty() || !is_ident_byte(rest.as_bytes()[rest.len() - 1]))
    })
}
