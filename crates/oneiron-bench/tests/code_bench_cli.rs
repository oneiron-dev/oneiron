//! `oneiron-bench beam code-bench-pack` (plan L4-02, CODE-BENCH; ARCH-0042
//! #code-bench; Engine ruling L4-02-RUN-GO = A, Sat 14 Nov 20:57): the
//! harness writes each ready cell's world, prompt, tools and MCP servers,
//! and lists every other cell with what it lacks. "A missing piece marks
//! that arm not ready; nothing is faked." On a tree without the subcommand
//! the binary answers "unknown BEAM invocation" and exits non-zero.
//!
//! `beam code-bench` grades what the writers left: the PR's sealed tests,
//! copied from its merge commit over the tree, the diff size without them,
//! and the transcript's turns, tokens, files opened, time and breaches of
//! the arm's profile. A failed run is kept and counted. An attempt must grow
//! from the root commit the pack made, the test commands leave no process
//! behind, and a denied shell command counts however it is started.
//!
//! Each test builds a throwaway repository, so no test builds the engine.
//! A loopback MCP stub stands in for a declared server: the pack probes
//! every declared server with `tools/list` before a cell that needs it is
//! ready, and allows each arm only the tools it lists by their exact names.
//!
//! `cargo test --locked -p oneiron-bench --test code_bench_cli`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/code_bench.tasks.v1.json"
);
const INTENT: &str = "Add the line `two` to src/lib.txt.";
/// The token the MCP stub takes; the pack reads it from `TOKEN_ENV`.
const STUB_TOKEN: &str = "code-bench-stub-token";
const TOKEN_ENV: &str = "CODE_BENCH_TOKEN";
/// Never set for the pack.
const UNSET_TOKEN_ENV: &str = "CODE_BENCH_UNSET_TOKEN";
/// Set to a token the stub refuses.
const WRONG_TOKEN_ENV: &str = "CODE_BENCH_WRONG_TOKEN";

struct World {
    dir: tempfile::TempDir,
    repo: PathBuf,
    base: String,
    merged: String,
}

/// A command that reads no host or user Git configuration.
fn isolated(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "owen")
        .env("GIT_AUTHOR_EMAIL", "owen@example.com")
        .env("GIT_COMMITTER_NAME", "owen")
        .env("GIT_COMMITTER_EMAIL", "owen@example.com");
    command
}

fn git(repo: &Path, args: &[&str]) -> Output {
    isolated("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git runs")
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    let output = git(repo, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// `base` holds src/lib.txt, the codemap and an old tests/grade.sh;
/// `merged` adds a line and the grade script that checks it.
fn world() -> World {
    world_with_grader("grep -q two src/lib.txt\n")
}

/// `world()` with `grader` as the merge commit's tests/grade.sh.
fn world_with_grader(grader: &str) -> World {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    for folder in ["src", "tests", "docs/codemap"] {
        std::fs::create_dir_all(repo.join(folder)).unwrap();
    }
    git_text(&repo, &["init", "-q"]);
    std::fs::write(repo.join("src/lib.txt"), "one\n").unwrap();
    std::fs::write(repo.join("docs/codemap/index.md"), "# codemap\n").unwrap();
    std::fs::write(repo.join("tests/grade.sh"), "grep -q zero src/lib.txt\n").unwrap();
    git_text(&repo, &["add", "-A"]);
    git_text(
        &repo,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"],
    );
    let base = git_text(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(repo.join("src/lib.txt"), "one\ntwo\n").unwrap();
    std::fs::write(repo.join("tests/grade.sh"), grader).unwrap();
    git_text(&repo, &["add", "-A"]);
    git_text(
        &repo,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "merged"],
    );
    let merged = git_text(&repo, &["rev-parse", "HEAD"]);
    World {
        dir,
        repo,
        base,
        merged,
    }
}

fn task(world: &World, id: &str, intent: Option<&str>) -> Value {
    json!({
        "id": id,
        "pr": 1,
        "base": world.base,
        "merged": world.merged,
        "intent": intent,
        "tests": [{"argv": ["sh", "tests/grade.sh"]}],
        "sealed": ["tests/grade.sh"],
    })
}

/// ARCH-0042's table over three tasks of the throwaway repository; `beta`
/// is the collaboration task.
fn manifest(world: &World, intent: Option<&str>, repairs_max: u64) -> PathBuf {
    let mut beta = task(world, "beta", intent);
    beta["collaboration"] = json!({"parts": [
        {"writer": "w1", "intent": intent, "files": ["src/lib.txt"]},
        {"writer": "w2", "intent": intent, "files": ["src/lib.txt"]},
        {"writer": "w3", "intent": intent, "files": ["src/lib.txt"]},
    ]});
    let manifest = json!({
        "version": 1,
        "repo": "example/repo",
        "cut": "2026-11-10T00:00:00+09:00",
        "cap_minutes": 60,
        "prompt_budget": 30,
        "tasks": [task(world, "alpha", intent), beta, task(world, "gamma", intent)],
        "checks": {
            "memory": {"arms": ["no_memory", "vault_memory"]},
            "navigation": {"arms": ["grep_only", "symbol_graph"], "third": "no_memory"},
            "collaboration": {"arms": ["oneiron_writers", "git_worktrees"], "task": "beta", "writers": 3},
            "prep": 3,
            "repairs_max": repairs_max,
        },
    });
    let path = world
        .dir
        .path()
        .join(format!("manifest-{repairs_max}.json"));
    std::fs::write(&path, manifest.to_string()).unwrap();
    path
}

/// Runs `beam code-bench-pack` on a plan over `manifest`, writing to
/// `<tmp>/<out>`; `pieces` adds the plan's MCP pieces.
fn pack(world: &World, manifest: &Path, out: &str, pieces: &Value) -> Output {
    let mut plan = json!({
        "manifest": manifest,
        "out": world.dir.path().join(out),
        "repo_dir": world.repo,
    });
    for (key, value) in pieces.as_object().unwrap() {
        plan[key] = value.clone();
    }
    let path = world.dir.path().join(format!("plan-{out}.json"));
    std::fs::write(&path, plan.to_string()).unwrap();
    isolated(env!("CARGO_BIN_EXE_oneiron-bench"))
        .env(TOKEN_ENV, STUB_TOKEN)
        .env(WRONG_TOKEN_ENV, "not-the-stub-token")
        .env_remove(UNSET_TOKEN_ENV)
        .args(["beam", "code-bench-pack"])
        .arg(&path)
        .output()
        .expect("the bench binary runs")
}

/// A loopback MCP server for the pack's probe, listing `tools` to the
/// bearer token `STUB_TOKEN` and answering 401 to any other. It answers
/// `initialize`, accepts notifications, and runs until the test ends.
fn mcp_stub(tools: &[&str]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let tools: Vec<Value> = tools
        .iter()
        .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
        .collect();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = answer_mcp(stream, &tools);
        }
    });
    url
}

/// One HTTP/1.1 request, one answer, then the connection closes.
fn answer_mcp(mut stream: TcpStream, tools: &[Value]) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let (mut length, mut authorized) = (0, false);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        match name.to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().unwrap_or(0),
            "authorization" => authorized = value.trim() == format!("Bearer {STUB_TOKEN}"),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let (status, reply) = if !authorized {
        ("401 Unauthorized", String::new())
    } else if request.get("id").is_none() {
        ("202 Accepted", String::new())
    } else {
        let id = request["id"].clone();
        let reply = match request["method"].as_str() {
            Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "code-bench-stub", "version": "1"},
            }}),
            Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}),
            _ => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such method"}})
            }
        };
        ("200 OK", reply.to_string())
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
        reply.len()
    )
}

/// A loopback URL nothing listens on.
fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}/mcp", listener.local_addr().unwrap())
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect()
}

fn index(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "code-bench-pack failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn cell<'a>(index: &'a Value, id: &str) -> &'a Value {
    index["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cell| cell["id"] == id)
        .unwrap_or_else(|| panic!("no cell {id} in {index:#}"))
}

/// The components a not-ready cell names.
fn gaps(cell: &Value) -> Vec<String> {
    cell["not_ready"]
        .as_array()
        .unwrap()
        .iter()
        .map(|state| state["component"].as_str().unwrap().to_owned())
        .collect()
}

fn reasons(cell: &Value) -> String {
    cell["not_ready"].to_string()
}

#[test]
fn the_checked_in_manifest_states_the_ruled_table() {
    let world = world();
    let index = index(&pack(&world, Path::new(FIXTURE), "out", &json!({})));

    let tasks: Vec<&str> = index["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|task| task["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        tasks,
        [
            "settle-supersession",
            "world-set-partition",
            "declared-cardinality"
        ]
    );
    assert_eq!(
        index["arms"],
        json!([
            "no_memory",
            "vault_memory",
            "grep_only",
            "symbol_graph",
            "oneiron_writers",
            "git_worktrees"
        ])
    );
    assert_eq!(
        index["prompts"],
        json!({"cells": 18, "prep": 3, "repairs_max": 9, "planned": 30, "budget": 30})
    );

    let cells = index["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 18, "{index:#}");
    for cell in cells {
        assert_eq!(cell["ready"], false, "{cell:#}");
        assert!(cell["dir"].is_null(), "{cell:#}");
        assert!(reasons(cell).contains("intent not written"), "{cell:#}");
        let gaps = gaps(cell);
        let needed = match cell["arm"].as_str().unwrap() {
            "vault_memory" => Some("memory_vault"),
            "symbol_graph" => Some("code_snapshot"),
            "oneiron_writers" => Some("oneiron_code_path"),
            _ => None,
        };
        if let Some(needed) = needed {
            assert!(gaps.iter().any(|gap| gap == needed), "{cell:#}");
        }
    }
    let navigation_third = cells
        .iter()
        .filter(|cell| cell["check"] == "navigation" && cell["arm"] == "no_memory")
        .count();
    assert_eq!(navigation_third, 0, "the third arm runs once, in memory");
    assert_eq!(
        index["shared"][0],
        json!({
            "check": "navigation",
            "task": "settle-supersession",
            "arm": "no_memory",
            "cell": "memory/settle-supersession/no_memory"
        })
    );
    let written: Vec<_> = std::fs::read_dir(world.dir.path().join("out"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        written,
        ["index.json"],
        "no cell is written when none is ready"
    );
}

#[test]
fn a_manifest_over_the_prompt_budget_is_refused() {
    let world = world();
    let output = pack(
        &world,
        &manifest(&world, Some(INTENT), 10),
        "out",
        &json!({}),
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("prompt_budget"), "{stderr}");
    assert!(
        stderr.contains("31 planned prompts (18 cells + 3 prep + repairs_max 10)"),
        "{stderr}"
    );
    assert!(!world.dir.path().join("out").exists());
}

#[test]
fn a_ready_cell_hides_the_sealed_tests() {
    let world = world();
    let index = index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));

    let grep_only = cell(&index, "navigation/alpha/grep_only");
    assert_eq!(grep_only["ready"], true, "{grep_only:#}");
    let dir = PathBuf::from(grep_only["dir"].as_str().unwrap());
    let prompt = std::fs::read_to_string(dir.join("PROMPT.md")).unwrap();
    assert!(prompt.contains(INTENT), "{prompt}");
    assert!(prompt.contains("60 minutes"), "{prompt}");
    let settings: Value =
        serde_json::from_slice(&std::fs::read(dir.join("settings.json")).unwrap()).unwrap();
    assert!(
        settings["permissions"]["allow"]
            .as_array()
            .unwrap()
            .contains(&json!("Grep"))
    );
    let mcp: Value = serde_json::from_slice(&std::fs::read(dir.join("mcp.json")).unwrap()).unwrap();
    assert_eq!(mcp, json!({"mcpServers": {}}));

    // The pack built the world before any writer starts; no script in the
    // cell names the source repository, and the sandbox must start and
    // denies every read of it.
    assert!(
        !dir.join("world.sh").exists(),
        "no world script in the cell"
    );
    let tree = dir.join("tree");
    assert_eq!(PathBuf::from(grep_only["tree"].as_str().unwrap()), tree);
    let source = std::fs::canonicalize(&world.repo).unwrap();
    let source = source.to_str().unwrap();
    for file in ["PROMPT.md", "mcp.json", "cell.json"] {
        let text = std::fs::read_to_string(dir.join(file)).unwrap();
        assert!(!text.contains(source), "{file} names the source repository");
    }
    let sandbox = &settings["sandbox"];
    assert_eq!(sandbox["enabled"], true, "{settings:#}");
    assert_eq!(sandbox["failIfUnavailable"], true, "{settings:#}");
    assert_eq!(sandbox["allowUnsandboxedCommands"], false, "{settings:#}");
    assert_eq!(strings(&sandbox["filesystem"]["denyRead"]), [source]);
    let deny = strings(&settings["permissions"]["deny"]);
    assert!(
        deny.contains(&format!("Read(/{source}/**)").as_str()),
        "{settings:#}"
    );
    assert!(
        deny.contains(&format!("Edit(/{source}/**)").as_str()),
        "{settings:#}"
    );
    let root = git_text(&tree, &["rev-parse", "HEAD"]);
    assert_eq!(grep_only["world_root"], root.as_str());
    assert_eq!(
        read_json(&dir.join("cell.json"))["world_root"],
        root.as_str()
    );
    assert_eq!(
        std::fs::read_to_string(tree.join("src/lib.txt")).unwrap(),
        "one\n"
    );
    assert!(tree.join("docs/codemap/index.md").is_file());
    assert!(
        !tree.join("tests/grade.sh").exists(),
        "the sealed test is gone"
    );
    assert!(
        !git(
            &tree,
            &["cat-file", "-e", &format!("{}^{{commit}}", world.merged)]
        )
        .status
        .success(),
        "the merged commit is out of the writer's reach"
    );
    let log = git_text(&tree, &["log", "--format=%s"]);
    assert_eq!(log, format!("code-bench world: alpha at {}", world.base));

    let symbol_graph = cell(&index, "navigation/alpha/symbol_graph");
    assert_eq!(symbol_graph["ready"], false);
    assert_eq!(gaps(symbol_graph), ["code_snapshot"]);
    assert_eq!(cell(&index, "memory/alpha/no_memory")["ready"], true);
    assert!(
        index["cells"]
            .as_array()
            .unwrap()
            .iter()
            .all(|cell| cell["id"] != "navigation/alpha/no_memory")
    );
    assert_eq!(
        gaps(cell(&index, "memory/alpha/vault_memory")),
        ["memory_vault"]
    );
    assert_eq!(
        gaps(cell(&index, "collaboration/beta/oneiron_writers/w2")),
        ["oneiron_code_path"]
    );

    let writer = cell(&index, "collaboration/beta/git_worktrees/w2");
    assert_eq!(writer["ready"], true, "{writer:#}");
    let writer_prompt =
        std::fs::read_to_string(PathBuf::from(writer["dir"].as_str().unwrap()).join("PROMPT.md"))
            .unwrap();
    assert!(
        writer_prompt.contains("writer `w2` of 3"),
        "{writer_prompt}"
    );
    let arm = world
        .dir
        .path()
        .join("out/collaboration/beta/git_worktrees");
    for name in ["w1", "w2", "w3"] {
        let tree = arm.join(name).join("tree");
        assert_eq!(git_text(&tree, &["branch", "--show-current"]), name);
        assert!(!tree.join("tests/grade.sh").exists());
    }
    assert!(
        git(&arm.join("repo"), &["rev-parse", "--verify", "integration"])
            .status
            .success()
    );
    let writer_settings = read_json(&arm.join("w2/settings.json"));
    let shared = std::fs::canonicalize(arm.join("repo")).unwrap();
    assert!(
        strings(&writer_settings["sandbox"]["filesystem"]["allowWrite"])
            .contains(&shared.to_str().unwrap()),
        "a writer's worktree commits land in the arm's shared repository: {writer_settings:#}"
    );
}

#[test]
fn a_memory_vault_seeded_after_the_cut_is_not_ready() {
    let world = world();
    let manifest = manifest(&world, Some(INTENT), 9);
    let url = mcp_stub(&["memory.recall"]);
    let vault = |seeded_through: &str, token_env: &str| {
        json!({"memory_vault": {
            "url": url,
            "token_env": token_env,
            "seeded_through": seeded_through,
        }})
    };

    let late = index(&pack(
        &world,
        &manifest,
        "late",
        &vault("2026-11-11T00:00:00+09:00", TOKEN_ENV),
    ));
    let cell_late = cell(&late, "memory/alpha/vault_memory");
    assert_eq!(cell_late["ready"], false);
    assert_eq!(gaps(cell_late), ["memory_vault"]);
    assert!(
        reasons(cell_late).contains("seeded_through"),
        "{cell_late:#}"
    );

    let early = index(&pack(
        &world,
        &manifest,
        "early",
        &vault("2026-11-09T23:59:59+09:00", TOKEN_ENV),
    ));
    let cell_early = cell(&early, "memory/alpha/vault_memory");
    assert_eq!(cell_early["ready"], true, "{cell_early:#}");
    let dir = PathBuf::from(cell_early["dir"].as_str().unwrap());
    let mcp: Value = serde_json::from_slice(&std::fs::read(dir.join("mcp.json")).unwrap()).unwrap();
    assert_eq!(
        mcp["mcpServers"]["oneiron-memory"],
        json!({
            "type": "http",
            "url": url,
            "headers": {"Authorization": "Bearer ${CODE_BENCH_TOKEN}"},
        })
    );

    let refused = pack(
        &world,
        &manifest,
        "refused",
        &vault("2026-11-09T00:00:00+09:00", "not-an-env-name"),
    );
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("memory_vault.token_env"), "{stderr}");
}

/// Canon: "A missing piece marks that arm not ready; nothing is faked." A
/// declared server that does not answer, refuses the token, or lists none
/// of the arm's tools is not a ready piece.
#[test]
fn a_declared_server_that_does_not_answer_is_not_ready() {
    let world = world();
    let manifest = manifest(&world, Some(INTENT), 9);
    let vault = |url: &str, token_env: &str| {
        json!({"memory_vault": {
            "url": url,
            "token_env": token_env,
            "seeded_through": "2026-11-09T00:00:00+09:00",
        }})
    };
    let memory = mcp_stub(&["memory.recall", "self.memory.read"]);
    let other = mcp_stub(&["vault.code.checkout.claim"]);
    let cases = [
        (
            "dead",
            vault(&dead_url(), TOKEN_ENV),
            "did not answer initialize",
        ),
        ("unset", vault(&memory, UNSET_TOKEN_ENV), "is not set"),
        (
            "wrong",
            vault(&memory, WRONG_TOKEN_ENV),
            "answered HTTP 401",
        ),
        (
            "other",
            vault(&other, TOKEN_ENV),
            "lists none of the tools of arm vault_memory",
        ),
    ];
    for (out, pieces, reason) in cases {
        let index = index(&pack(&world, &manifest, out, &pieces));
        let cell = cell(&index, "memory/alpha/vault_memory");
        assert_eq!(cell["ready"], false, "{out}: {cell:#}");
        assert_eq!(gaps(cell), ["memory_vault"], "{out}: {cell:#}");
        assert!(reasons(cell).contains(reason), "{out}: {cell:#}");
        assert!(
            !reasons(cell).contains(STUB_TOKEN),
            "{out}: a reason never holds the token"
        );
        assert!(cell["dir"].is_null(), "{out}: {cell:#}");
    }
}

/// The arm's settings allow each tool its server listed that the arm
/// admits, by its exact name, never the whole server.
#[test]
fn a_ready_arm_may_call_only_its_listed_tools() {
    let world = world();
    let url = mcp_stub(&[
        "memory.recall",
        "self.memory.read",
        "vault.code.checkout.claim",
    ]);
    let index = index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({"memory_vault": {
            "url": url,
            "token_env": TOKEN_ENV,
            "seeded_through": "2026-11-09T00:00:00+09:00",
        }}),
    ));

    let vault = cell(&index, "memory/alpha/vault_memory");
    assert_eq!(vault["ready"], true, "{vault:#}");
    let settings = read_json(&PathBuf::from(vault["dir"].as_str().unwrap()).join("settings.json"));
    let allow = strings(&settings["permissions"]["allow"]);
    for tool in [
        "mcp__oneiron-memory__memory.recall",
        "mcp__oneiron-memory__memory_recall",
        "mcp__oneiron-memory__self.memory.read",
        "mcp__oneiron-memory__self_memory_read",
    ] {
        assert!(allow.contains(&tool), "{tool} missing: {settings:#}");
    }
    assert!(
        allow
            .iter()
            .all(|tool| *tool != "mcp__oneiron-memory" && !tool.contains("checkout")),
        "{settings:#}"
    );
    let no_memory = cell(&index, "memory/alpha/no_memory");
    let settings =
        read_json(&PathBuf::from(no_memory["dir"].as_str().unwrap()).join("settings.json"));
    assert!(
        strings(&settings["permissions"]["allow"])
            .iter()
            .all(|tool| !tool.starts_with("mcp__")),
        "{settings:#}"
    );
}

const TRANSCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/code_bench/transcript.stream.jsonl"
);
/// The verb rows the symbol and graph arm calls.
const SYMBOL_GRAPH_VERBS: [&str; 11] = [
    "self.code.symbols.definitions",
    "self.code.symbols.neighbors",
    "graph_fs.cat",
    "graph_fs.find",
    "graph_fs.grep",
    "graph_fs.head",
    "graph_fs.ls",
    "graph_fs.read_file",
    "graph_fs.read_link",
    "graph_fs.readdir",
    "graph_fs.wc",
];

/// The tree the pack built for a ready cell.
fn packed_tree(index: &Value, id: &str) -> PathBuf {
    let cell = cell(index, id);
    assert_eq!(cell["ready"], true, "{cell:#}");
    let tree = PathBuf::from(cell["tree"].as_str().unwrap());
    assert!(tree.join(".git").exists(), "{cell:#}");
    tree
}

/// Packs the throwaway repository with a code snapshot whose engine commit
/// holds the arm's verb rows, served by a stub that lists them.
fn symbol_graph_index(world: &World, out: &str) -> Value {
    for verb in SYMBOL_GRAPH_VERBS {
        let row = world.repo.join(format!("scripts/sdk/verbs/{verb}.json"));
        std::fs::create_dir_all(row.parent().unwrap()).unwrap();
        std::fs::write(row, json!({"name": verb}).to_string()).unwrap();
    }
    git_text(&world.repo, &["add", "-A"]);
    git_text(
        &world.repo,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "engine"],
    );
    let engine = git_text(&world.repo, &["rev-parse", "HEAD"]);
    index(&pack(
        world,
        &manifest(world, Some(INTENT), 9),
        out,
        &json!({"code_snapshot": {
            "url": mcp_stub(&SYMBOL_GRAPH_VERBS),
            "token_env": TOKEN_ENV,
            "engine_commit": engine,
            "bases": [world.base],
        }}),
    ))
}

/// Runs `beam code-bench` on `attempts` against the plan `pack` wrote for
/// `<tmp>/<out>`.
fn grade(world: &World, out: &str, attempts: &Value) -> Output {
    let path = world.dir.path().join(format!("attempts-{out}.json"));
    let file = json!({
        "plan": world.dir.path().join(format!("plan-{out}.json")),
        "attempts": attempts,
    });
    std::fs::write(&path, file.to_string()).unwrap();
    isolated(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args(["beam", "code-bench"])
        .arg(&path)
        .output()
        .expect("the bench binary runs")
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "code-bench failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn summary<'a>(report: &'a Value, check: &str, arm: &str) -> &'a Value {
    report["arms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|line| line["check"] == check && line["arm"] == arm)
        .unwrap_or_else(|| panic!("no {check}/{arm} line in {report:#}"))
}

#[test]
fn the_sealed_grader_passes_the_merged_change_and_fails_the_base() {
    let world = world();
    let index = index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));
    let solved = packed_tree(&index, "navigation/alpha/grep_only");
    std::fs::write(solved.join("src/lib.txt"), "one\ntwo\n").unwrap();
    let untouched = packed_tree(&index, "navigation/gamma/grep_only");

    let report = report(&grade(
        &world,
        "out",
        &json!([
            {"cell": "navigation/alpha/grep_only", "tree": solved},
            {"cell": "navigation/gamma/grep_only", "tree": untouched},
        ]),
    ));

    let rows = report["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{report:#}");
    assert_eq!(rows[0]["tests_pass"], true, "{report:#}");
    assert_eq!(rows[0]["pass"], true);
    assert_eq!(
        rows[0]["diff"],
        json!({"files": 1, "added": 1, "removed": 0}),
        "the sealed test is never counted in the diff"
    );
    assert_eq!(
        rows[1]["tests_pass"], false,
        "the base fails the sealed test"
    );
    assert_eq!(rows[1]["pass"], false);
    assert_eq!(
        rows[1]["diff"],
        json!({"files": 0, "added": 0, "removed": 0})
    );
    let line = summary(&report, "navigation", "grep_only");
    assert_eq!(line["attempts"], 2, "a failed run is kept and counted");
    assert_eq!(line["passes"], 1);
    assert_eq!(line["failures"], 1);
    assert_eq!(line["baseline"], true);
}

#[test]
fn a_writers_own_copy_of_a_sealed_test_never_grades() {
    let world = world();
    let index = index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));
    let tree = packed_tree(&index, "memory/alpha/no_memory");
    std::fs::create_dir_all(tree.join("tests")).unwrap();
    std::fs::write(tree.join("tests/grade.sh"), "exit 0\n").unwrap();

    let report = report(&grade(
        &world,
        "out",
        &json!([{"cell": "memory/alpha/no_memory", "tree": tree}]),
    ));

    let row = &report["rows"][0];
    assert_eq!(row["tests_pass"], false, "{report:#}");
    assert_eq!(row["pass"], false);
    assert_eq!(row["diff"]["files"], 0, "{report:#}");
    assert_eq!(
        std::fs::read_to_string(tree.join("tests/grade.sh")).unwrap(),
        "grep -q two src/lib.txt\n",
        "the merge commit's copy replaced the writer's"
    );
    assert_eq!(
        summary(&report, "navigation", "no_memory")["attempts"],
        1,
        "the codemap cell is also the navigation check's third arm"
    );
}

#[test]
fn the_transcript_gives_turns_tokens_files_and_breaches() {
    let world = world();
    let index = symbol_graph_index(&world, "out");
    let cell_id = "navigation/alpha/symbol_graph";
    let dir = PathBuf::from(cell(&index, cell_id)["dir"].as_str().unwrap());
    let settings: Value =
        serde_json::from_slice(&std::fs::read(dir.join("settings.json")).unwrap()).unwrap();
    assert!(
        settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .contains(&json!("Grep"))
    );
    let tree = packed_tree(&index, cell_id);

    let report = report(&grade(
        &world,
        "out",
        &json!([{"cell": cell_id, "tree": tree, "transcript": TRANSCRIPT}]),
    ));

    let row = &report["rows"][0];
    assert_eq!(
        row["transcript"],
        json!({
            "turns": 3,
            "input_tokens": 650,
            "output_tokens": 60,
            "files_opened": 2,
            "elapsed_secs": 45.0,
            "source_control_secs": 5.0,
            "usable_tree_secs": 40.0,
            "breaches": ["Grep"],
            "unreadable_lines": 0,
        }),
        "{report:#}"
    );
    assert_eq!(row["profile_breach"], true);
    assert_eq!(row["pass"], false, "a breach never grades as a pass");
    assert_eq!(
        summary(&report, "navigation", "symbol_graph")["breaches"],
        1
    );
}

#[test]
fn a_second_repair_in_one_arm_group_is_refused() {
    let world = world();
    index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));
    let missing = world.dir.path().join("no-tree");

    let output = grade(
        &world,
        "out",
        &json!([
            {"cell": "memory/alpha/no_memory", "tree": missing},
            {"cell": "memory/alpha/no_memory", "tree": missing, "repair_of": "memory/alpha/no_memory"},
            {"cell": "memory/gamma/no_memory", "tree": missing},
            {"cell": "memory/gamma/no_memory", "tree": missing, "repair_of": "memory/gamma/no_memory"},
        ]),
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("a second repair in arm group memory/no_memory"),
        "{stderr}"
    );
}

/// The grader checks the root commit the pack made, not a subject a writer
/// can copy: a fresh repository of the merged tree under the world's
/// subject is refused.
#[test]
fn a_tree_that_does_not_grow_from_the_packed_world_is_refused() {
    let world = world();
    index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));
    let forged = world.dir.path().join("forged");
    std::fs::create_dir_all(forged.join("src")).unwrap();
    git_text(&forged, &["init", "-q"]);
    std::fs::write(forged.join("src/lib.txt"), "one\ntwo\n").unwrap();
    git_text(&forged, &["add", "-A"]);
    let subject = format!("code-bench world: alpha at {}", world.base);
    git_text(
        &forged,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", &subject],
    );

    let output = grade(
        &world,
        "out",
        &json!([{"cell": "navigation/alpha/grep_only", "tree": forged}]),
    );

    assert!(!output.status.success(), "the forged world graded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not grow from the world of task `alpha`"),
        "{stderr}"
    );
}

/// Whether the process `pid` still runs (a zombie has ended).
#[cfg(target_os = "linux")]
fn running(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X")
    })
}

/// A sealed test that starts a background process leaves none behind: the
/// grader kills the command's whole process group, as it does at the cap.
#[cfg(target_os = "linux")]
#[test]
fn the_sealed_tests_leave_no_process_behind() {
    let world = world_with_grader(
        "sleep 300 >/dev/null 2>&1 &\necho $! > background.pid\ngrep -q two src/lib.txt\n",
    );
    let index = index(&pack(
        &world,
        &manifest(&world, Some(INTENT), 9),
        "out",
        &json!({}),
    ));
    let tree = packed_tree(&index, "memory/alpha/no_memory");
    std::fs::write(tree.join("src/lib.txt"), "one\ntwo\n").unwrap();

    let report = report(&grade(
        &world,
        "out",
        &json!([{"cell": "memory/alpha/no_memory", "tree": tree}]),
    ));

    assert_eq!(report["rows"][0]["tests_pass"], true, "{report:#}");
    let pid = std::fs::read_to_string(tree.join("background.pid")).unwrap();
    let pid = pid.trim();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while running(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let left = running(pid);
    if left {
        let _ = Command::new("kill").args(["-9", pid]).status();
    }
    assert!(
        !left,
        "the sealed test's background process {pid} still runs"
    );
}

/// Denied commands count however they are started (a wrapper, a path, a
/// nested shell, a command substitution, xargs or find -exec), quoted text
/// is not a command, and a graph read's file is read from the serving
/// engine's `arguments.spec.path`.
#[test]
fn the_transcript_reads_wrapped_commands_and_graph_payloads() {
    let world = world();
    let index = symbol_graph_index(&world, "out");
    let cell_id = "navigation/alpha/symbol_graph";
    let tree = packed_tree(&index, cell_id);
    let calls = [
        (
            "mcp__oneiron-code__graph_fs.read_file",
            json!({"schema_version": "1", "arguments": {"spec": {"path": "src/graph.txt"}}}),
        ),
        (
            "mcp__oneiron-code__graph_fs_head",
            json!({"path": "src/old.txt"}),
        ),
        ("Bash", json!({"command": "env rg needle src"})),
        ("Bash", json!({"command": "/usr/bin/grep -r needle ."})),
        ("Bash", json!({"command": "timeout 5 rg needle"})),
        ("Bash", json!({"command": "bash -c 'git -C . grep needle'"})),
        (
            "Bash",
            json!({"command": "git ls-files | xargs -n1 grep -l needle"}),
        ),
        ("Bash", json!({"command": "echo \"$(LC_ALL=C rg needle)\""})),
        (
            "Bash",
            json!({"command": "find src -name '*.rs' -exec egrep -l needle {} +"}),
        ),
        (
            "Bash",
            json!({"command": "echo rg; git status; cargo check"}),
        ),
        (
            "Bash",
            json!({"command": "git commit -q -m 'drop (rg) and grep; use graph reads'"}),
        ),
    ];
    let lines: Vec<String> = calls
        .iter()
        .enumerate()
        .map(|(number, (name, input))| {
            json!({
                "type": "assistant",
                "message": {
                    "id": format!("msg_{number}"),
                    "content": [{"type": "tool_use", "id": format!("tu_{number}"), "name": name, "input": input}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            })
            .to_string()
        })
        .collect();
    let transcript = world.dir.path().join("wrapped.stream.jsonl");
    std::fs::write(&transcript, lines.join("\n")).unwrap();

    let report = report(&grade(
        &world,
        "out",
        &json!([{"cell": cell_id, "tree": tree, "transcript": transcript}]),
    ));

    let metrics = &report["rows"][0]["transcript"];
    assert_eq!(metrics["files_opened"], 2, "{report:#}");
    assert_eq!(metrics["breaches"], json!(vec!["Bash"; 7]), "{report:#}");
}
