//! Every file of this crate that reaches a fallback ladder, and where the
//! world of the call it sends comes from (owner ruling 2026-10-14, "Models":
//! no silent fallback to a cloud model; Engine ruling 2026-10-15, the class
//! check). A call that names no world is held by the vault-wide floor while
//! any world stays on the device, so a new caller that names no world fails
//! closed; this list makes each caller name its source.
//!
//! The check reads the crate's own source and needs no crate-private item.
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! ladder_caller_census`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Each file outside the ladder (`models/ladder.rs`, `models/ladder/`) that
/// calls a ladder's sending method, and where the world of the request it
/// sends comes from. "none" is the floor: the call names no world, so the
/// floor holds a fallback off the cloud while any world stays on the device.
/// It does not keep a picked model or a first rung on the device. A wrapper
/// (`HostModels`, `RunBackend`, `MediaRuntime`, the chat `Recorder`) has the
/// row: its callers hand it messages or an envelope its row names.
const LADDER_CALLERS: [(&str, &str); 50] = [
    (
        "ai_host/coach_health.rs",
        "none: the drafter's request has a default scope (the floor)",
    ),
    (
        "ai_host/code_fix.rs",
        "HostModels: none, its requests have a default scope; an exact replay re-sends a kept request that only host code writes: a step's (none), the executor's envelope, or a step door's (cleared)",
    ),
    (
        "ai_host/code_mode.rs",
        "the executor's envelope: none, or a scoped child's loan scope, which names its branch's world and narrows its parent's",
    ),
    (
        "ai_host/commitment_reminder_wording.rs",
        "none: a default scope (the floor)",
    ),
    (
        "ai_host/compaction/serve.rs",
        "none for the house request (a default scope); a live fork keeps the live call's scope: chat's (none) or the executor's envelope",
    ),
    (
        "ai_host/connector_event/worker.rs",
        "none: a default scope (the floor)",
    ),
    (
        "ai_host/contribution.rs",
        "a replay capsule's kept request, which only host code writes: the executor's envelope or a step's (none)",
    ),
    (
        "ai_host/contribution/audit.rs",
        "none: the judge's request has a default scope; an exact pinned call",
    ),
    (
        "ai_host/dreamer.rs",
        "the engine's envelope, through a run backend: none, readable grants, or the world of the record or branch a pass works on",
    ),
    (
        "ai_host/dreamer/free_time.rs",
        "the engine's envelope, through a run backend, as in ai_host/dreamer.rs",
    ),
    (
        "ai_host/dreamer/request_sources.rs",
        "the engine's envelope, forwarded unchanged, as in ai_host/dreamer.rs",
    ),
    (
        "ai_host/dreamer_thing.rs",
        "the executor's envelope, through a run backend: none, or a scoped child's loan scope",
    ),
    (
        "ai_host/eval_measurement/legs.rs",
        "none: the arm's request has a default scope; an exact pinned call",
    ),
    (
        "ai_host/local_vision.rs",
        "none: a default scope (the floor)",
    ),
    (
        "ai_host/shadow_runner/model.rs",
        "a replay capsule's or a blocked step's kept request, which only host code writes: the executor's envelope, a step's (none), or a step door's (cleared)",
    ),
    (
        "ai_host/step.rs",
        "none, as nothing proves its text's worlds: the floor; a continuation re-sends the saved request this file wrote",
    ),
    (
        "ai_host/step/secret_use.rs",
        "the step's request from ai_host/step.rs: none",
    ),
    (
        "ai_host/stewardship/draft.rs",
        "none: a default scope (the floor)",
    ),
    (
        "ai_host/weave_lens.rs",
        "none: the engine's lens request has a default scope",
    ),
    (
        "api/ai/chat/model_call.rs",
        "the chat Recorder: none, chat_request has a default scope; a reused prefix re-sends a breakpoint request chat itself sent",
    ),
    ("api/ai/vision.rs", "none: a default scope (the floor)"),
    (
        "api/anonymous_chat.rs",
        "none: a default scope, and the engine checker's prompt; anonymous_call hands the request to one offer, never a fallback",
    ),
    (
        "api/booking/free_text.rs",
        "none: the engine's booking parser builds a default scope",
    ),
    (
        "api/context_board/reply.rs",
        "none: a default scope, and admission clears any world; an exact pinned call",
    ),
    (
        "api/facade/content_policy_doors.rs",
        "none: the engine's policy prompt has a default scope",
    ),
    (
        "api/facade/model_manifest_doors.rs",
        "the owner's own request, its world kept (Engine 2026-11-12): an exact pinned call that never falls back",
    ),
    (
        "api/facade/model_step_doors.rs",
        "none, as a caller's named world does not vouch for its text: admission clears it before the step is stored, and a resume re-sends that input",
    ),
    (
        "api/facade/model_stream_doors.rs",
        "none: admission clears the caller's world",
    ),
    (
        "api/facade/skill_doors.rs",
        "none: a default scope, and admission clears any world",
    ),
    (
        "api/llm.rs",
        "none, as a caller's named world does not vouch for its text: admission clears it",
    ),
    (
        "api/mcp_gateway/code_mode_verbs/field_writer.rs",
        "none: a default scope (the floor)",
    ),
    (
        "api/memory_reason/host/call.rs",
        "none: the reasoning and rerank requests have a default scope",
    ),
    (
        "api/openai_proxy/choices.rs",
        "none: proxied admission clears the caller's world before choices copy the request",
    ),
    (
        "big_rung.rs",
        "none: the big model's request has a default scope",
    ),
    (
        "big_rung/note.rs",
        "none: the big model's note has a default scope",
    ),
    (
        "commands/hook_regen.rs",
        "none: a default scope (the floor)",
    ),
    (
        "models/declared.rs",
        "none, as a host's named world does not vouch for its text: the floor",
    ),
    (
        "models/media.rs",
        "MediaRuntime: none, as every media door clears the caller's world and the host's own media requests name none",
    ),
    (
        "models/media/agent.rs",
        "an agent's media stream, admitted through the media door, which clears its world: none",
    ),
    (
        "models/media/calls.rs",
        "MediaRuntime, as in models/media.rs: none; a kept job keeps that request",
    ),
    (
        "models/media/replay.rs",
        "a kept media job's request, written by MediaRuntime from a door that cleared its world: none",
    ),
    (
        "models/raw.rs",
        "one host-injected offer, never a fallback; the executor's envelope, as in ai_host/code_mode.rs",
    ),
    (
        "models/run_backend.rs",
        "the engine's envelope: none, readable grants, or the world of the record or branch a pass works on",
    ),
    (
        "saved_query_sweep.rs",
        "none: the judge's envelope has a default scope, through a run backend",
    ),
    (
        "server/core/pattern_workflow.rs",
        "none: the launch request has a default scope",
    ),
    (
        "server/recall_rerank.rs",
        "none: the floor, beside rerank's own row check",
    ),
    (
        "server/space_move.rs",
        "none: the probe has a default scope, and the transcription clears its world",
    ),
    (
        "server/space_move/repo_index_derivation.rs",
        "none: a default scope (the floor)",
    ),
    (
        "voice_host/backend.rs",
        "none: the engine's voice and safeguard prompts have a default scope",
    ),
    (
        "voice_host/brain.rs",
        "none: chat_request has a default scope",
    ),
];

/// The names by which a request reaches a ladder's rungs from outside the
/// ladder: the sending methods of `OfferLadder` and `ReplayLadder`, and
/// `anonymous_call`, which hands its caller the bound request and the one
/// offer to send it to. No other type in this crate defines these names, so a
/// call is matched on any receiver.
const OWN_NAMES: [&str; 29] = [
    "anonymous_call",
    "generate_admitted",
    "generate_by",
    "generate_exact",
    "generate_exact_by",
    "generate_exact_observed_while",
    "generate_exact_recorded_by",
    "generate_exact_recorded_streamed_while",
    "generate_exact_recorded_while",
    "generate_exact_while",
    "generate_exact_while_warm",
    "generate_exact_within",
    "generate_recorded_by",
    "generate_recorded_streamed_while",
    "generate_recorded_while",
    "generate_served_by",
    "generate_served_while",
    "generate_served_within",
    "generate_step_attempt",
    "generate_step_attempt_while",
    "generate_while",
    "generate_within",
    "media_by",
    "media_by_released",
    "media_released",
    "open_media_stream",
    "stream_by",
    "stream_recorded",
    "stream_recorded_by",
];

/// Sending methods whose names other types of this crate define too
/// (`LlmBackend::generate` and `stream`, `ModelRuntime::media`,
/// `HostModels::generate_served`). A call of one is matched only on a receiver
/// bound as `ladder` (`ladder`, `self.ladder`, `call.ladder`), or by path.
const SHARED_NAMES: [&str; 4] = ["generate", "generate_served", "media", "stream"];

/// A backend over a ladder, built before the envelopes it will send.
const BACKEND_CONSTRUCTOR: &str = "RunBackend::new(";

/// Methods of the ladder named like a send that send nothing.
const NOT_SENDING: [&str; 1] = [
    // A hint for a refused media call: which offers a retry may reach.
    "media_retry",
];

/// The attributes that keep an item out of the shipped build.
const TEST_ONLY: [&str; 2] = ["#[cfg(test)]", "#[cfg(oneiron_test_support)]"];

/// The ladder's own files: its callers are what this check lists.
fn is_ladder(name: &str) -> bool {
    name == "models/ladder.rs" || name.starts_with("models/ladder/")
}

fn sources(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Where the comment that opens at `at` ends.
fn comment_end(chars: &[char], at: usize) -> usize {
    if chars[at + 1] == '/' {
        return chars[at..]
            .iter()
            .position(|c| *c == '\n')
            .map_or(chars.len(), |end| at + end);
    }
    let (mut depth, mut next) = (1, at + 2);
    while depth > 0 && next < chars.len() {
        match (chars[next], chars.get(next + 1)) {
            ('/', Some('*')) => (depth, next) = (depth + 1, next + 2),
            ('*', Some('/')) => (depth, next) = (depth - 1, next + 2),
            _ => next += 1,
        }
    }
    next
}

/// The index just past the first `close` at or after `from`.
fn end_of(chars: &[char], from: usize, close: &[char]) -> usize {
    (from..chars.len())
        .find(|end| chars[*end..].starts_with(close))
        .map_or(chars.len(), |end| end + close.len())
}

/// Where the literal that opens at `at` ends, if one opens there: a string,
/// a raw string, or a char (a lifetime is no literal).
fn literal_end(chars: &[char], at: usize) -> Option<usize> {
    match chars[at] {
        '"' => {
            let mut next = at + 1;
            while next < chars.len() && chars[next] != '"' {
                next += if chars[next] == '\\' { 2 } else { 1 };
            }
            Some(next + 1)
        }
        'r' if at == 0 || !is_ident(chars[at - 1]) || chars[at - 1] == 'b' => {
            let hashes = chars[at + 1..].iter().take_while(|c| **c == '#').count();
            (chars.get(at + 1 + hashes) == Some(&'"')).then(|| {
                let close: Vec<char> = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                end_of(chars, at + 2 + hashes, &close)
            })
        }
        '\'' if chars.get(at + 1) == Some(&'\\') => Some(end_of(chars, at + 3, &['\''])),
        '\'' if chars.get(at + 2) == Some(&'\'') => Some(at + 3),
        _ => None,
    }
}

/// The source with its comments taken out and every literal emptied, so
/// neither a comment nor a message text reads as a call.
fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut code = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let opens_comment = chars[at] == '/' && matches!(chars.get(at + 1), Some('/' | '*'));
        if opens_comment {
            at = comment_end(&chars, at);
        } else if let Some(end) = literal_end(&chars, at) {
            code.push_str("\"\"");
            at = end;
        } else {
            code.push(chars[at]);
            at += 1;
        }
    }
    code
}

/// The length of the item that opens `item`: up to its first `;` or its
/// first braced block outside brackets, or to a closing bracket it did not
/// open (an attribute on a field ends at its list's end).
fn item_len(item: &str) -> usize {
    let mut depth = 0_i32;
    for (at, c) in item.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return at,
            ')' | ']' => depth -= 1,
            ';' if depth == 0 => return at + 1,
            '{' if depth == 0 => return at + block_len(&item[at..]),
            _ => {}
        }
    }
    item.len()
}

/// The length of the braced block that opens `block`.
fn block_len(block: &str) -> usize {
    let mut depth = 0;
    for (at, c) in block.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 1 => return at + 1,
            '}' => depth -= 1,
            _ => {}
        }
    }
    block.len()
}

/// The module an item declares out of line (`mod name;`), if it does.
fn out_of_line_module(item: &str) -> Option<String> {
    let mut rest = item.trim();
    while rest.starts_with("#[") {
        rest = rest[rest.find(']')? + 1..].trim_start();
    }
    if let Some(visibility) = rest.strip_prefix("pub") {
        let visibility = visibility.trim_start();
        rest = match visibility.strip_prefix('(') {
            Some(scope) => &scope[scope.find(')')? + 1..],
            None => visibility,
        };
    }
    let name = rest
        .trim_start()
        .strip_prefix("mod ")?
        .strip_suffix(';')?
        .trim();
    name.chars().all(is_ident).then(|| name.to_owned())
}

/// The code with every test-only item taken out, and the names of the
/// test-only modules it declares out of line. A file marked test-only as a
/// whole ships nothing.
fn shipped(code: &str) -> (String, Vec<String>) {
    let whole_file = TEST_ONLY
        .iter()
        .any(|mark| code.contains(&mark.replacen('#', "#!", 1)));
    if whole_file {
        return (String::new(), Vec::new());
    }
    let (mut kept, mut modules, mut rest) = (String::new(), Vec::new(), code);
    while let Some((at, mark)) = TEST_ONLY
        .iter()
        .filter_map(|mark| rest.find(mark).map(|at| (at, mark)))
        .min()
    {
        kept.push_str(&rest[..at]);
        let item = &rest[at + mark.len()..];
        let len = item_len(item);
        modules.extend(out_of_line_module(&item[..len]));
        rest = &item[len..];
    }
    kept.push_str(rest);
    (kept, modules)
}

/// Where the files of module `module`, declared in file `name`, sit.
fn module_prefix(name: &str, module: &str) -> String {
    let stem = name.trim_end_matches(".rs");
    let parent = match stem.rsplit_once('/') {
        Some((dir, "mod")) => format!("{dir}/"),
        None if matches!(stem, "lib" | "main" | "mod") => String::new(),
        _ => format!("{stem}/"),
    };
    format!("{parent}{module}")
}

/// Each source file of this crate's shipped build, by its path under `src`,
/// with its shipped code.
fn shipped_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut read = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let name = file
            .strip_prefix(&root)
            .expect("a file under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("a source file");
        let (code, modules) = shipped(&code_only(&text));
        test_modules.extend(modules.iter().map(|module| module_prefix(&name, module)));
        read.push((name, code));
    }
    read.retain(|(name, _)| {
        let declared_test = test_modules.iter().any(|prefix| {
            name.strip_prefix(prefix.as_str())
                .is_some_and(|rest| rest == ".rs" || rest.starts_with('/'))
        });
        let named_test = name.ends_with("tests.rs")
            || name.starts_with("tests/")
            || name.contains("/tests/")
            || name.ends_with("test_support.rs");
        !declared_test && !named_test
    });
    read
}

/// The text of a call into the ladder, as matched with every whitespace taken
/// out, so a call split over lines is found too.
fn entry_points() -> Vec<String> {
    let own = OWN_NAMES.iter().map(|name| format!(".{name}("));
    let shared = SHARED_NAMES.iter().map(|name| format!("ladder.{name}("));
    let by_path = OWN_NAMES.iter().chain(&SHARED_NAMES).flat_map(|name| {
        [
            format!("OfferLadder::{name}("),
            format!("ReplayLadder::{name}("),
        ]
    });
    own.chain(shared)
        .chain(by_path)
        .chain([BACKEND_CONSTRUCTOR.to_owned()])
        .collect()
}

/// Engine ruling 2026-10-15, the class check: each file of this crate's own
/// code that can reach a fallback ladder is listed with where its world comes
/// from, so none reaches one unjudged.
#[test]
fn every_ladder_caller_names_where_its_world_comes_from() {
    let entries = entry_points();
    let callers: BTreeSet<String> = shipped_sources()
        .into_iter()
        .filter(|(name, code)| {
            let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            !is_ladder(name) && entries.iter().any(|entry| code.contains(entry.as_str()))
        })
        .map(|(name, _)| name)
        .collect();
    let listed: BTreeSet<String> = LADDER_CALLERS
        .iter()
        .map(|(file, _)| (*file).to_owned())
        .collect();
    let missing: Vec<&String> = callers.difference(&listed).collect();
    let gone: Vec<&String> = listed.difference(&callers).collect();
    assert!(
        missing.is_empty() && gone.is_empty(),
        "a ladder caller is missing from the list: {missing:?}; or gone: {gone:?}"
    );
    assert_eq!(
        listed.len(),
        LADDER_CALLERS.len(),
        "a caller is listed twice"
    );
}

/// The methods a file of the ladder defines that code outside the ladder can
/// call, with each one's visibility, whitespace made single.
fn reachable_methods(name: &str, code: &str) -> Vec<String> {
    let code = code.split_whitespace().collect::<Vec<_>>().join(" ");
    let reachable: &[&str] = if name == "models/ladder.rs" {
        &["pub", "pub(crate)", "pub(super)", "pub(in crate::models)"]
    } else {
        &["pub", "pub(crate)", "pub(in crate::models)"]
    };
    let mut methods = Vec::new();
    for (at, _) in code.match_indices("fn ") {
        if code[..at].ends_with(is_ident) {
            continue;
        }
        let mut before = code[..at].trim_end();
        while let Some(rest) = ["async", "const", "unsafe"]
            .iter()
            .find_map(|word| before.strip_suffix(word))
        {
            before = rest.trim_end();
        }
        let visible = reachable.iter().any(|vis| {
            before
                .strip_suffix(vis)
                .is_some_and(|rest| !rest.ends_with(is_ident))
        });
        let method: String = code[at + 3..]
            .chars()
            .take_while(|c| is_ident(*c))
            .collect();
        if visible {
            methods.push(method);
        }
    }
    methods
}

fn is_sending_name(method: &str) -> bool {
    let sends = ["generate", "stream", "media"]
        .iter()
        .any(|prefix| method.starts_with(prefix))
        || method == "open_media_stream"
        || method == "anonymous_call";
    sends && !NOT_SENDING.contains(&method)
}

/// The class check's entry list keeps up with the ladder: every sending
/// method a caller outside the ladder can reach is one it matches, and it
/// matches no method the ladder no longer has.
#[test]
fn every_sending_method_of_the_ladder_is_an_entry_point() {
    let defined: BTreeSet<String> = shipped_sources()
        .into_iter()
        .filter(|(name, _)| is_ladder(name))
        .flat_map(|(name, code)| reachable_methods(&name, &code))
        .filter(|method| is_sending_name(method))
        .collect();
    let matched: BTreeSet<String> = OWN_NAMES
        .iter()
        .chain(&SHARED_NAMES)
        .map(|name| (*name).to_owned())
        .collect();
    let unmatched: Vec<&String> = defined.difference(&matched).collect();
    let stale: Vec<&String> = matched.difference(&defined).collect();
    assert!(
        unmatched.is_empty() && stale.is_empty(),
        "a ladder sending method is not an entry point: {unmatched:?}; or no longer exists: {stale:?}"
    );
}

/// The scan reads code only: comments, literals and test-only items are out,
/// and a test-only module declared out of line is named.
#[test]
fn the_scan_reads_shipped_code_only() {
    let text = concat!(
        "// ladder.generate(a)\n",
        "/* ladder.stream(b) /* nested */ */\n",
        "let s = \"ladder.generate(c)\"; let r = r#\"x.generate_exact(\"#;\n",
        "let c = '\"'; fn f<'a>(x: &'a str) {}\n",
        "#[cfg(test)]\nmod tests { fn t() { ladder.generate(d); } }\n",
        "#[cfg(oneiron_test_support)]\npub(crate) mod doors;\n",
        "#[cfg(test)]\nfn helper(x: [u8; 2]) { x.generate_exact(e); }\n",
        "fn shipped() { call.ladder.generate_exact(f); }\n",
    );
    let (code, modules) = shipped(&code_only(text));
    assert_eq!(modules, ["doors"]);
    let flat: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(flat.matches(".generate_exact(").count(), 1, "{flat}");
    assert!(!flat.contains("ladder.generate("), "{flat}");
    assert!(!flat.contains("ladder.stream("), "{flat}");
    assert!(flat.contains("fnf<'a>(x:&'astr){}"), "{flat}");
    assert_eq!(module_prefix("models/mod.rs", "doors"), "models/doors");
    assert_eq!(
        module_prefix("models/media.rs", "doors"),
        "models/media/doors"
    );
    assert_eq!(module_prefix("lib.rs", "doors"), "doors");
}
