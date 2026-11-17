//! `oneiron-bench beam code-bench-pack` (plan L4-02, CODE-BENCH; ARCH-0042
//! #code-bench; Engine ruling L4-02-RUN-GO = A, Sat 14 Nov 20:57): the
//! harness writes each ready cell's world, prompt, tools and MCP servers,
//! and lists every other cell with what it lacks. "A missing piece marks
//! that arm not ready; nothing is faked." On a tree without the subcommand
//! the binary answers "unknown BEAM invocation" and exits non-zero.
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
    std::fs::write(repo.join("tests/grade.sh"), "grep -q two src/lib.txt\n").unwrap();
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
