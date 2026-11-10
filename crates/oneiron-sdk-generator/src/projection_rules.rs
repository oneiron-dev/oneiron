//! The projection rules and refusals a verb author depends on, checked on the generator's real outputs: on the
//! repository's own verb table, and on a copy of its inputs with some rows changed.
//!
//! A copy holds the verb files and `type_names.json` as files a test may change, and links every other input (the
//! `CRATES` source directories and the `INPUTS` files) to the repository's own. So a copy also proves that the
//! generator reads nothing beyond `CRATES` and `INPUTS`, the lists `oneiron-sdk-build` keys its runs by. The edited
//! copy changes six rows that no rule here shares, and each test reads only its own rows' text.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::py::json::{DumpOptions, dumps, loads};
use crate::py::value::{Dict, Value};
use crate::{CRATES, INPUTS, Outputs, outputs};

const CORE: &str = "crates/oneiron/src/verbs/generated/sdk_generated.rs";
const CORE_NAMES: &str = "crates/oneiron/src/generated/core_verb_names.rs";
const CATALOG: &str = "crates/oneiron/src/verbs/generated/verb_catalog.rs";
const ROUTES: &str = "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs";
const DISPATCH: &str = "crates/oneiron-server/src/api/facade/generated/dispatch.rs";
const MCP: &str = "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs";
const REMOTE: &str = "crates/oneiron-remote/src/generated/agent_verbs.rs";
const NAPI: &str = "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs";
const PYO3: &str = "crates/oneiron-py/src/generated/agent_verbs.rs";
const UNIFFI: &str = "crates/oneiron-uniffi/src/generated/facade_generated.rs";
const TS_VERBS: &str = "packages/oneiron/src/facade-verbs.ts";
const TS_NATIVE: &str = "packages/oneiron/src/native-verbs.ts";
const CLIENT: &str = "packages/oneiron-client/src/facade.ts";
const PY: &str = "crates/oneiron-py/python/oneiron/_facade_verbs.py";
const PYI: &str = "crates/oneiron-py/python/oneiron/_facade_verbs.pyi";

/// The repository the crate sits in.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// A copy of the generator's inputs under the temporary directory, removed when dropped.
struct Tree {
    root: PathBuf,
}

impl Drop for Tree {
    fn drop(&mut self) {
        // `remove_dir_all` removes a link, never what it points to.
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Tree {
    /// The verb files and `type_names.json` copied, every other input linked to the repository's.
    fn new(label: &str) -> Self {
        let repository = repository();
        let root = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-{label}-{}",
            std::process::id()
        ));
        if fs::symlink_metadata(&root).is_ok() {
            fs::remove_dir_all(&root).expect("an earlier copy removed");
        }
        let verbs = root.join("scripts/sdk/verbs");
        fs::create_dir_all(&verbs).expect("the verb directory");
        for entry in fs::read_dir(repository.join("scripts/sdk/verbs")).expect("the verb table") {
            let path = entry.expect("a verb file").path();
            fs::copy(&path, verbs.join(path.file_name().expect("a file name")))
                .expect("a verb file copied");
        }
        fs::copy(
            repository.join("scripts/sdk/type_names.json"),
            root.join("scripts/sdk/type_names.json"),
        )
        .expect("type_names.json copied");
        let tree = Self { root };
        for (_, dir) in CRATES {
            tree.link(&repository, dir);
        }
        for path in INPUTS {
            if !path.starts_with("scripts/sdk/") {
                tree.link(&repository, path);
            }
        }
        tree
    }

    /// `path` in the copy as a link to the repository's. A path already inside a linked directory is there through
    /// that link: nothing is created inside one, so no test writes into the repository.
    fn link(&self, repository: &Path, path: &str) {
        let mut at = self.root.clone();
        for part in Path::new(path).components() {
            at.push(part);
            if fs::symlink_metadata(&at).is_ok_and(|meta| meta.file_type().is_symlink()) {
                return;
            }
        }
        let target = self.root.join(path);
        fs::create_dir_all(target.parent().expect("a parent")).expect("a directory");
        std::os::unix::fs::symlink(repository.join(path), &target).expect("a link");
    }

    fn verb_file(&self, name: &str) -> PathBuf {
        assert!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && !Path::new(name).is_absolute()
                && !name.contains(['/', '\\']),
            "a verb file name must be one safe file-name component: {name:?}"
        );
        self.root
            .join("scripts/sdk/verbs")
            .join(format!("{name}.json"))
    }

    /// The verb row `name`.
    fn row(&self, name: &str) -> Dict {
        let path = self.verb_file(name);
        let text = fs::read_to_string(&path).expect("a verb file");
        match loads(&text) {
            Ok(Value::Dict(row)) => row,
            _ => panic!("{}: not a JSON object", path.display()),
        }
    }

    /// Writes `row` as the verb file of its own name.
    fn write(&self, row: &Dict) {
        let name = row["name"].as_str().expect("a row name").to_owned();
        let text = dumps(&Value::Dict(row.clone()), DumpOptions::default());
        fs::write(self.verb_file(&name), text).expect("a verb file written");
    }

    fn remove(&self, name: &str) {
        fs::remove_file(self.verb_file(name)).expect("a verb file removed");
    }

    /// The generator's outputs for the copy, or its refusal as the line it prints.
    fn outputs(&self) -> Result<Outputs, String> {
        outputs(&self.root).map_err(|error| error.to_string())
    }
}

#[test]
fn a_row_name_cannot_escape_the_temporary_tree() {
    let tree = Tree::new("unsafe-row-name");
    let outside = tree.root.with_extension("json");
    assert!(!outside.exists());
    let outside_name = outside
        .file_stem()
        .expect("an outside file name")
        .to_str()
        .expect("a UTF-8 file name");
    let mut embed = tree.row("ai.embed");
    for name in ["../../x".to_owned(), format!("../../../../{outside_name}")] {
        embed.insert("name".into(), Value::Str(name));
        assert!(std::panic::catch_unwind(|| tree.write(&embed)).is_err());
    }
    assert!(!tree.root.join("scripts/x.json").exists());
    assert!(!outside.exists());
}

/// `row[key]` as a dict, to change in place.
fn dict<'r>(row: &'r mut Dict, key: &str) -> &'r mut Dict {
    match row.get_mut(key) {
        Some(Value::Dict(inner)) => inner,
        _ => panic!("`{key}` is no object"),
    }
}

/// The outputs of the repository's own inputs.
fn baseline() -> &'static Outputs {
    static BASELINE: OnceLock<Outputs> = OnceLock::new();
    BASELINE.get_or_init(|| outputs(&repository()).expect("the repository's outputs"))
}

/// The outputs of a copy with six rows changed, one per rule below.
fn edited() -> &'static Outputs {
    static EDITED: OnceLock<Outputs> = OnceLock::new();
    EDITED.get_or_init(|| {
        let tree = Tree::new("edited");
        // A memory row and a board row leave the table.
        tree.remove("vault.rooms.claim");
        tree.remove("self.focus.refresh");
        // A row is renamed (file and name).
        let mut offers = tree.row("vault.rooms.offers");
        offers.insert("name".into(), Value::Str("vault.rooms.bids".into()));
        tree.write(&offers);
        tree.remove("vault.rooms.offers");
        // The owner-grade admission leaves vault.export.
        let mut export = tree.row("vault.export");
        assert!(
            dict(&mut export, "admission")
                .shift_remove("owner_grade")
                .is_some_and(|flag| flag.is_true()),
            "vault.export states owner_grade"
        );
        tree.write(&export);
        // vault.recall's limit default changes, on its argument only.
        let mut recall = tree.row("vault.recall");
        let Some(Value::List(args)) = dict(&mut recall, "binding").get_mut("args") else {
            panic!("vault.recall has binding.args");
        };
        let limit = args
            .iter_mut()
            .find_map(|arg| match arg {
                Value::Dict(arg) if arg.get("name").is_some_and(|name| name.is_str("limit")) => {
                    Some(arg)
                }
                _ => None,
            })
            .expect("vault.recall's limit argument");
        assert!(
            limit
                .get("default")
                .is_some_and(|default| *default == Value::Int(10))
        );
        limit.insert("default".into(), Value::Int(17));
        tree.write(&recall);
        // A page row names other rows and cursor keys, and no way back.
        let mut participants = tree.row("vault.rooms.participants");
        let mut page = Dict::new();
        page.insert("rows".into(), Value::Str("items".into()));
        page.insert("cursor".into(), Value::Str("next".into()));
        participants.insert("page".into(), Value::Dict(page));
        tree.write(&participants);
        tree.outputs().expect("the edited copy's outputs")
    })
}

fn text<'o>(outputs: &'o Outputs, path: &str) -> &'o str {
    outputs
        .get(path)
        .unwrap_or_else(|| panic!("no output {path}"))
}

/// The text of a generated item, from `start` to the next item `marker` begins.
fn item<'t>(text: &'t str, start: &str, marker: &str) -> &'t str {
    let at = text.find(start).unwrap_or_else(|| panic!("no {start:?}"));
    let rest = &text[at + start.len()..];
    &rest[..rest.find(marker).unwrap_or(rest.len())]
}

/// A row's spellings across the outputs: `a.b_c`, `a_b_c`, `aBC`, `ABC`.
fn spellings(name: &str) -> [String; 4] {
    let snake = name.replace('.', "_");
    let mut camel = String::new();
    let mut upper = false;
    for c in snake.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            camel.extend(c.to_uppercase());
            upper = false;
        } else {
            camel.push(c);
        }
    }
    let mut pascal = camel.clone();
    if let Some(first) = pascal.get(..1).map(str::to_uppercase) {
        pascal.replace_range(..1, &first);
    }
    [name.to_owned(), snake, camel, pascal]
}

/// No output spells `name` in any of its forms.
fn assert_absent(outputs: &Outputs, name: &str) {
    for (path, text) in outputs.iter() {
        for spelling in spellings(name) {
            assert!(!text.contains(&spelling), "{path} still holds {spelling}");
        }
    }
}

/// A row removed from the table leaves every output: its core function, its HTTP route and handler, its MCP tool
/// and catalog entry, and its remote, N-API, PyO3, UniFFI, TypeScript and Python bindings.
#[test]
fn a_row_removed_from_the_table_leaves_every_output() {
    let surfaces = [
        (CORE, "pub fn vault_rooms_claim("),
        (CATALOG, "Self::VaultRoomsClaim => \"vault.rooms.claim\""),
        (ROUTES, ".route(\"/vault.rooms.claim\""),
        (DISPATCH, "async fn vault_rooms_claim("),
        (MCP, "\"vault.rooms.claim\" =>"),
        (REMOTE, "pub fn vault_rooms_claim("),
        (NAPI, "pub fn vault_rooms_claim("),
        (PYO3, " fn vault_rooms_claim(&self"),
        (UNIFFI, "fn vault_rooms_claim(&self, input"),
        (TS_VERBS, ".vaultRoomsClaim("),
        (TS_NATIVE, "vaultRoomsClaim(input: unknown)"),
        (CLIENT, "\"vault.rooms.claim\""),
        (PY, "self._client.vault_rooms_claim("),
        (PYI, "def claim(self, room_ref: str, turn_ref: str)"),
    ];
    for (path, spelling) in surfaces {
        assert!(
            text(baseline(), path).contains(spelling),
            "{path}: {spelling}"
        );
        assert!(
            !text(edited(), path).contains(spelling),
            "{path}: {spelling}"
        );
    }
    assert_absent(edited(), "vault.rooms.claim");
}

/// A board row's engine function runs on the run's board, its MCP tool runs it through the board, and it reaches
/// the wire only through its host projection; it leaves every output with its row.
#[test]
fn a_board_row_runs_on_the_board_and_leaves_with_its_row() {
    let core = text(baseline(), CORE);
    assert!(core.contains("pub fn self_focus_refresh<S: crate::board_verb::LiveBoardSource>("));
    let mcp = text(baseline(), MCP);
    assert!(mcp.contains("\"self.focus.refresh\" =>"));
    assert!(
        item(
            mcp,
            "async fn mcp_verb_row_self_focus_refresh(",
            "\n#[inline(never)]"
        )
        .contains("execute_mcp_board_verb(")
    );
    let remote = text(baseline(), REMOTE);
    assert!(remote.contains(
        "pub fn self_focus_refresh(&self, input: &oneiron::task_verb::sdk::LiveRunRequest<oneiron::task_verb::sdk::BoardRefreshRequest>)"
    ));
    assert!(!remote.contains("input: &oneiron::task_verb::sdk::BoardRefreshRequest)"));
    assert!(text(baseline(), CORE_NAMES).contains("\"self.focus.refresh\""));
    assert_absent(edited(), "self.focus.refresh");
}

/// `"mcp": "none"` keeps a row's SDK function and serves no MCP tool for it; only a browser or scoped-child row
/// states it, and a memory row that does is refused.
#[test]
fn mcp_none_keeps_the_sdk_function_and_serves_no_mcp_tool() {
    let core = text(baseline(), CORE);
    assert!(core.contains("pub fn self_dreamer_thing_extract("));
    assert!(text(baseline(), CATALOG).contains("\"self.dreamer.thing.extract\""));
    assert!(!text(baseline(), MCP).contains("self.dreamer.thing.extract"));
    let tree = Tree::new("mcp-none");
    let mut list = tree.row("vault.rooms.list");
    list.insert("mcp".into(), Value::Str("none".into()));
    tree.write(&list);
    assert_eq!(
        tree.outputs().err().as_deref(),
        Some(
            "ValueError: vault.rooms.list: only a browser or scoped-child row states \"mcp\": \"none\", and every \
             such row does"
        )
    );
}

/// `admission.owner_grade` puts the owner door before the engine call, on HTTP and on MCP; without it the row is
/// an ordinary facade call.
#[test]
fn owner_grade_admission_puts_the_owner_door_first() {
    let handler = |outputs: &'static Outputs| {
        item(
            text(outputs, DISPATCH),
            "\nasync fn vault_export(",
            "\nasync fn ",
        )
    };
    let tool = |outputs: &'static Outputs| {
        item(
            text(outputs, MCP),
            "async fn mcp_verb_row_vault_export(",
            "\n#[inline(never)]",
        )
    };
    let owned = handler(baseline());
    for spelling in [
        "auth.is_owner_grade()",
        "auth.verified_slip()",
        "vault_export_answer(",
    ] {
        assert!(owned.contains(spelling), "{spelling}");
    }
    assert!(!owned.contains("facade_invoke"));
    assert!(tool(baseline()).contains("auth.is_owner_grade()"));
    let plain = handler(edited());
    assert!(plain.contains("facade_invoke"));
    assert!(!plain.contains("is_owner_grade"));
    assert!(!tool(edited()).contains("is_owner_grade"));
}

/// Every checked host door names the proof its door runs first; the generator refuses one that does not.
#[test]
fn a_checked_host_door_without_its_proof_is_refused() {
    let tree = Tree::new("host-door-proof");
    let mut embed = tree.row("ai.embed");
    assert!(embed.get("host_door").is_some_and(Value::is_true));
    assert!(embed.shift_remove("host_door_proof").is_some());
    tree.write(&embed);
    assert_eq!(
        tree.outputs().err().as_deref(),
        Some("ValueError: checked host doors without `host_door_proof`: ['ai.embed']")
    );
}

/// A page row's `rows` key is what the MCP cap counts and its `cursor` ends the page; only a row that says how it
/// goes back (`resume`) names its continuation.
#[test]
fn a_page_row_names_what_the_mcp_cap_counts() {
    let tool = |outputs: &'static Outputs, name: &str| {
        item(
            text(outputs, MCP),
            &format!("async fn mcp_verb_row_{}(", name.replace('.', "_")),
            "\n#[inline(never)]",
        )
        .to_owned()
    };
    let page = tool(edited(), "vault.rooms.participants");
    for spelling in [
        ".rows_at(\"items\")",
        "output.items.len()",
        "output.next.is_some()",
    ] {
        assert!(page.contains(spelling), "{spelling}");
    }
    assert!(!page.contains(".resumed_by(") && !page.contains(".resumed_within("));
    assert!(
        tool(baseline(), "vault.rooms.messages")
            .contains(".resumed_by(\"next_after\", \"turn_ref\")")
    );
}

/// A count default is stated once, on its argument: core's constant and every binding that spells a default take
/// it from there, and the remote client names core's constant.
#[test]
fn a_count_default_comes_from_its_argument() {
    for (outputs, limit) in [(baseline(), 10), (edited(), 17)] {
        assert!(text(outputs, CORE_NAMES).contains(&format!(
            "pub const VAULT_RECALL_LIMIT_DEFAULT: usize = {limit};"
        )));
        let ts = item(text(outputs, TS_VERBS), "recall: (query: string", "\n");
        assert!(ts.contains(&format!("opts.limit ?? {limit}")), "{ts}");
        for path in [PY, PYI] {
            let py = item(text(outputs, path), "def recall(self, query: str", "\n");
            assert!(
                py.contains(&format!("limit: int = {limit}")),
                "{path}: {py}"
            );
        }
        for (path, conversion) in [
            (
                NAPI,
                format!(
                    "let limit = limit.map(limit_to_engine).transpose().map_err(facade_error)?.unwrap_or({limit});"
                ),
            ),
            (PYO3, format!("let limit = limit.unwrap_or({limit});")),
        ] {
            let native = item(text(outputs, path), "fn vault_recall(", "}\n");
            assert!(native.contains(&conversion), "{path}: {native}");
        }
        let remote = item(text(outputs, REMOTE), "pub fn vault_recall(", "\npub fn ");
        assert!(
            remote.contains("VAULT_RECALL_LIMIT_DEFAULT")
                && !remote.contains(&format!("unwrap_or({limit})"))
        );
    }
}

/// A row's name names every binding: renamed, each output spells the new name and none the old one.
#[test]
fn a_row_s_name_names_every_binding() {
    let surfaces = [
        (CORE, "pub fn vault_rooms_bids("),
        (CATALOG, "Self::VaultRoomsBids => \"vault.rooms.bids\""),
        (ROUTES, ".route(\"/vault.rooms.bids\""),
        (DISPATCH, "async fn vault_rooms_bids("),
        (MCP, "\"vault.rooms.bids\" =>"),
        (REMOTE, "pub fn vault_rooms_bids("),
        (NAPI, "pub fn vault_rooms_bids("),
        (PYO3, " fn vault_rooms_bids(&self"),
        (UNIFFI, "fn vault_rooms_bids(&self, input"),
        (TS_VERBS, ".vaultRoomsBids("),
        (TS_NATIVE, "vaultRoomsBids(input: unknown)"),
        (CLIENT, "\"vault.rooms.bids\""),
        (PY, "def bids(self, spec)"),
        (PYI, "def bids(self, spec"),
    ];
    for (path, spelling) in surfaces {
        let old_spelling = spelling.replace("bids", "offers").replace("Bids", "Offers");
        assert!(
            text(baseline(), path).contains(&old_spelling),
            "{path}: {old_spelling}"
        );
        assert!(
            text(edited(), path).contains(spelling),
            "{path}: {spelling}"
        );
    }
    assert_absent(edited(), "vault.rooms.offers");
}

/// A facade handler decodes and checks each call's input once: a handler that runs the shared facade invoke leaves
/// the input check to it, and `describe`, which runs no invoke, checks its input itself.
#[test]
fn a_facade_handler_decodes_each_call_once() {
    let dispatch = text(baseline(), DISPATCH);
    let handlers: Vec<&str> = dispatch.split("\nasync fn ").skip(1).collect();
    let invoking: Vec<&&str> = handlers
        .iter()
        .filter(|handler| handler.contains("facade_invoke"))
        .collect();
    assert!(!invoking.is_empty());
    for handler in invoking {
        assert!(
            !handler.contains("sdk::validate_input("),
            "{}",
            handler.split('(').next().unwrap_or_default()
        );
    }
    let describe = handlers
        .iter()
        .find(|handler| handler.starts_with("describe("))
        .expect("the describe handler");
    assert!(describe.contains("sdk::validate_input(\"describe\", &value)?;"));
    assert!(!describe.contains("facade_invoke"));
}
