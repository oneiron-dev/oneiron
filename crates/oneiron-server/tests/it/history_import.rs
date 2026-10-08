//! `oneiron import <source> <path>` through the shipped binary, for each of
//! the four sources (owner, 2026-10-08): import, the messages are there, a
//! search finds a known phrase, a re-import adds nothing, and an appended
//! session adds only its new messages. The fixtures under
//! `tests/fixtures/history/` are small invented exports and session logs in
//! each source's real layout.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron::edge::EdgeActorClass;
use oneiron::memory::{Effort, RecallScope};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use oneiron::{Vault, VaultConfig};
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/history")
}

/// A fresh vault and the config file `init` wrote for it.
struct Home {
    dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("test fixture");
        let vault = dir.path().join("vault");
        let config = dir.path().join("oneiron.toml");
        let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["init", vault.to_str().expect("test fixture")])
            .args([
                "--config",
                config.to_str().expect("test fixture"),
                "--embedder",
                "none",
            ])
            .output()
            .expect("test fixture");
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        Self { dir, vault, config }
    }

    /// Runs `oneiron import <source> <path> [--dry-run]` and returns its report.
    fn import(&self, source: &str, path: &Path, dry_run: bool) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(["import", source])
            .arg(path)
            .arg("--config")
            .arg(&self.config)
            .env_remove("ONEIRON_VAULT_PATH");
        if dry_run {
            command.arg("--dry-run");
        }
        let output = command.output().expect("test fixture");
        assert!(
            output.status.success(),
            "import {source}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("a JSON report on stdout")
    }

    /// The vault's data file, byte for byte.
    fn vault_bytes(&self) -> Vec<u8> {
        std::fs::read(self.vault.join("data.mdb")).expect("test fixture")
    }

    fn open(&self) -> Vault {
        Vault::open_owned(&self.vault, VaultConfig::server()).expect("open vault")
    }

    fn count(&self, entity_type: u8) -> u64 {
        self.open()
            .count_entities_by_type(entity_type)
            .expect("test fixture")
    }

    /// The imported messages the owner's recall finds for `phrase` and that
    /// hold it: the read a client's search reaches (`/v1/core/facade/recall`).
    fn search(&self, phrase: &str) -> usize {
        let vault = self.open();
        let owner = vault.ensure_embedded_owner_actor().expect("test fixture");
        let pack = vault
            .memory(owner, EdgeActorClass::Human)
            .recall(
                phrase,
                Effort::Light,
                &RecallScope::default(),
                20,
                None,
                None,
            )
            .expect("test fixture");
        let phrase = phrase.to_lowercase();
        pack.items
            .iter()
            .filter(|item| {
                item.kind.eq_ignore_ascii_case("message")
                    && item.value_text.to_lowercase().contains(&phrase)
            })
            .count()
    }
}

fn totals(report: &Value) -> (u64, u64, u64, u64) {
    let totals = &report["totals"];
    let field = |name: &str| totals[name].as_u64().expect("test fixture");
    (
        field("new"),
        field("skipped"),
        field("changed"),
        field("refused"),
    )
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("test fixture");
    for entry in std::fs::read_dir(from).expect("test fixture") {
        let entry = entry.expect("test fixture");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("test fixture").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("test fixture");
        }
    }
}

fn append(log: &Path, lines: &Path) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(log)
        .expect("test fixture");
    file.write_all(&std::fs::read(lines).expect("test fixture"))
        .expect("test fixture");
}

/// A ChatGPT export zip holding `conversations.json` under a folder, as the
/// download does.
fn zip_export(json: &Path, zip_path: &Path) {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(zip_path).expect("test fixture"));
    zip.start_file(
        "export/conversations.json",
        zip::write::FileOptions::default(),
    )
    .expect("test fixture");
    zip.write_all(&std::fs::read(json).expect("test fixture"))
        .expect("test fixture");
    zip.start_file("export/chat.html", zip::write::FileOptions::default())
        .expect("test fixture");
    zip.write_all(b"<html></html>").expect("test fixture");
    zip.finish().expect("test fixture");
}

#[test]
fn chatgpt_export_imports_once_and_a_later_export_adds_only_new_messages() {
    let home = Home::new();
    let zip_path = home.dir.path().join("chatgpt-export.zip");
    zip_export(
        &fixtures().join("chatgpt/export-1/conversations.json"),
        &zip_path,
    );

    // Main path and the kept regeneration: two conversations, six messages.
    let first = home.import("chatgpt", &zip_path, false);
    assert_eq!(totals(&first), (6, 0, 0, 0));
    assert_eq!(first["conversations"].as_array().unwrap().len(), 2);
    let not_kept = &first["totals"]["not_kept"];
    assert_eq!(
        not_kept["system"], 1,
        "the hidden system prompt is not landed"
    );
    assert_eq!(not_kept["tool_calls"], 1);
    assert_eq!(not_kept["tool_results"], 1);
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 6);
    assert_eq!(home.search("cherry blossoms"), 1);

    let again = home.import("chatgpt", &zip_path, false);
    assert_eq!(totals(&again), (0, 6, 0, 0));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 6);

    let later = fixtures().join("chatgpt/export-2/conversations.json");
    let dry = home.import("chatgpt", &later, true);
    assert_eq!(totals(&dry), (2, 6, 0, 0));
    assert_eq!(
        home.count(ENTITY_TYPE_MESSAGE),
        6,
        "a dry run writes nothing"
    );
    assert_eq!(dry["ledger"], 6);

    let grown = home.import("chatgpt", &later, false);
    assert_eq!(totals(&grown), (2, 6, 0, 0));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 8);
    assert_eq!(home.search("ryokan"), 2);
}

#[test]
fn claude_export_imports_once_and_a_later_export_adds_only_new_messages() {
    let home = Home::new();
    let first = home.import("claude", &fixtures().join("claude/export-1"), false);
    assert_eq!(totals(&first), (4, 0, 0, 0));
    let not_kept = &first["totals"]["not_kept"];
    assert_eq!(not_kept["tool_calls"], 1);
    assert_eq!(not_kept["thinking"], 1);
    assert_eq!(not_kept["attachments"], 1);
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 4);
    assert_eq!(home.search("nail polish"), 1);

    let again = home.import("claude", &fixtures().join("claude/export-1"), false);
    assert_eq!(totals(&again), (0, 4, 0, 0));

    let later = fixtures().join("claude/export-2/conversations.json");
    let grown = home.import("claude", &later, false);
    assert_eq!(totals(&grown), (2, 4, 0, 0));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 6);
}

#[test]
fn claude_code_sessions_import_with_sidechains_and_resumed_copies_once() {
    let home = Home::new();
    let projects = home.dir.path().join("projects");
    copy_tree(&fixtures().join("claude-code/projects"), &projects);
    // A link out of the history: the walk must not follow it.
    let outside = home.dir.path().join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::copy(
        fixtures().join("claude-code/append.jsonl"),
        outside.join("0f0e0d0c-0b0a-4908-8706-050403020100.jsonl"),
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        &outside,
        projects.join("-Users-ana-code-garden-planner/linked"),
    )
    .unwrap();

    let rooms = home.count(ENTITY_TYPE_CONVERSATION);
    let before = home.vault_bytes();
    let dry = home.import("claude-code", &projects, true);
    assert_eq!(
        totals(&dry),
        (19, 2, 0, 0),
        "the copies count once, as they land"
    );
    assert_eq!(home.vault_bytes(), before, "a dry run writes nothing");

    // Main session 9 (a slash command's arguments and three queued prompts
    // among them: one kept as an attachment, one only in the queue, one
    // without a mode; a withdrawn one is not), its inline sidechain 2, its
    // subagent 2, a workflow run's agent 2, an older release's agent log
    // beside the sessions 2, and the resumed session 2 of its own beside the
    // 2 copies it carries of the original.
    let first = home.import("claude-code", &projects, false);
    assert_eq!(totals(&first), (19, 2, 0, 0));
    assert_eq!(
        first["files"]["read"], 5,
        "the session, three subagent logs and the resumed log"
    );
    assert_eq!(first["files"]["passed"], 1, "the workflow run's journal");
    let kinds: Vec<&str> = first["conversations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|conversation| conversation["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"sidechain") && kinds.contains(&"subagent"));
    let not_kept = &first["totals"]["not_kept"];
    assert_eq!(not_kept["tool_calls"], 2, "Write and Bash");
    assert_eq!(not_kept["tool_results"], 2);
    assert_eq!(
        not_kept["injected"], 4,
        "the caveat, a bare slash command, a date reminder, a queue wrapper"
    );
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 19);
    assert_eq!(home.count(ENTITY_TYPE_CONVERSATION), rooms + 6);
    assert!(home.search("basil") >= 1);
    assert_eq!(home.search("watering reminder fires twice"), 1);
    assert_eq!(home.search("check the frost warning"), 1);
    assert_eq!(
        home.search("rainfall per bed"),
        1,
        "a prompt kept only in the queue"
    );
    assert_eq!(
        home.search("repot the fig"),
        2,
        "the queued prompt once, and the reply"
    );
    assert_eq!(
        home.search("compost"),
        0,
        "a withdrawn prompt is not landed"
    );
    assert_eq!(
        home.search("chili peppers"),
        0,
        "nothing under the link was read"
    );

    let again = home.import("claude-code", &projects, false);
    assert_eq!(totals(&again), (0, 21, 0, 0));

    append(
        &projects.join("-Users-ana-code-garden-planner/5d0c0a7e-1111-4222-8333-944455556666.jsonl"),
        &fixtures().join("claude-code/append.jsonl"),
    );
    let grown = home.import("claude-code", &projects, false);
    assert_eq!(totals(&grown), (2, 21, 0, 0));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 21);
    assert_eq!(home.search("chili peppers"), 2);
}

#[test]
fn codex_rollouts_keep_each_message_once_and_appended_rollouts_add_only_new() {
    let home = Home::new();
    let sessions = home.dir.path().join("sessions");
    copy_tree(&fixtures().join("codex/sessions"), &sessions);

    // The 2025 rollout lands the request out of its IDE wrapper, its reply,
    // and a request that starts with markup the person typed, with its reply.
    // The classic parent lands its question (an IDE-wrapped item and the
    // event echoing it) and its two-block reply (echoed one event per block)
    // once each. Two forks carry the parent's meta and id-less history again:
    // the copies are skipped, and each lands its own two, though both start
    // with the same words. The spawned agent lands its task and reply, whose
    // event reuses a fork's per-session item id without becoming its revision.
    let first = home.import("codex", &sessions, false);
    assert_eq!(totals(&first), (12, 4, 0, 0));
    let kinds: Vec<&str> = first["conversations"]
        .as_array()
        .expect("conversations")
        .iter()
        .map(|conversation| conversation["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        kinds,
        ["main", "main", "subagent", "subagent", "subagent"],
        "the forks and the spawned agent are their own threads"
    );
    let not_kept = &first["totals"]["not_kept"];
    assert_eq!(
        not_kept["duplicates"], 7,
        "the events echoing kept messages"
    );
    assert_eq!(
        not_kept["injected"], 6,
        "two environment blocks and four IDE wrappers"
    );
    assert_eq!(not_kept["system"], 1, "the developer instructions");
    assert_eq!(not_kept["tool_calls"], 2);
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 12);
    assert_eq!(
        home.search("try rust_decimal"),
        2,
        "the same words typed in two forks are two messages"
    );
    assert_eq!(home.search("Money type"), 1);
    assert_eq!(
        home.search("not centered"),
        1,
        "typed markup is the person's"
    );
    assert_eq!(home.search("call sites"), 1);
    assert_eq!(
        home.search("Active file"),
        0,
        "the IDE context is not landed"
    );
    assert_eq!(
        home.search("ledger total drift"),
        1,
        "the item, its event and the fork's copy are one message"
    );
    assert_eq!(home.search("integer cents"), 1, "one reply, not three");

    let again = home.import("codex", &sessions, false);
    assert_eq!(totals(&again), (0, 16, 0, 0));

    append(
        &sessions.join(
            "2026/09/14/rollout-2026-09-14T10-00-00-0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl",
        ),
        &fixtures().join("codex/append.jsonl"),
    );
    let grown = home.import("codex", &sessions, false);
    assert_eq!(totals(&grown), (2, 16, 0, 0));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), 14);
    assert_eq!(home.search("regression test"), 1);
}
