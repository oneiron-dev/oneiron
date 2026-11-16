//! The Agent Plugins package (`plugins/agent-plugins`; ARCH-0028
//! #plugin-start-order step 2, #plugin-agent-plugins): one package for the
//! clients that read Agent Plugins 1.0 (Codex, Cursor, VS Code with
//! Copilot). It carries the vault's tools over MCP and the skill. Hooks are
//! per client, so none ship here yet; they join later under each client's
//! own reverse-domain folder (spec §8).
//!
//! The package is checked against Agent Plugins 1.0.0 as published at
//! <https://raw.githubusercontent.com/agentplugins/agent-plugins-spec/main/spec/1.0.0.md>
//! (sha256 97a658b7dca3ce1b…, read 2026-11-14): the closed `plugin.json`
//! (§5), the closed `mcp.json` (§7.2.1), skill discovery (§7.1) and
//! placeholder expansion (§9.2: only `${PLUGIN_ROOT}` and `${PLUGIN_DATA}`).
//! The MCP entry and the skill's setup command parse with the `oneiron`
//! binary's own CLI, and the entry launched the way a client launches it,
//! before any credential is minted, fails with a message that names the
//! file and the command that mints it.
//!
//! Run with: `cargo test --locked -p oneiron-server --test agent_plugins_package`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::Parser as _;
use oneiron_server::cli::Cli;
use serde_json::{Map, Value};

/// The canonical Agent Plugins 1.0.0 identifiers (spec §5.2, §7.2.1).
const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
/// The only top-level fields `plugin.json` may hold (spec §5.2).
const MANIFEST_FIELDS: [&str; 10] = [
    "$schema",
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "extensions",
];
/// The fields of a stdio server entry (spec §7.2.1).
const STDIO_FIELDS: [&str; 5] = ["type", "command", "args", "env", "cwd"];
/// The two placeholders a client expands (spec §9.2).
const PLACEHOLDERS: [&str; 2] = ["${PLUGIN_ROOT}", "${PLUGIN_DATA}"];
/// What a client sets the placeholders to, for the parse checks.
const TEST_PLUGIN_ROOT: &str = "/home/plugin-test/.agents/plugins/oneiron";
const TEST_PLUGIN_DATA: &str = "/home/plugin-test/.agents/plugins/data/oneiron";
/// The file the MCP entry reads its credential from, under the data folder.
const CREDENTIAL_FILE_NAME: &str = "agent.cred";
/// The clients this package is for. The skill names them only as a list.
const CLIENTS: [&str; 3] = ["Codex", "Cursor", "Copilot"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn plugin_root() -> PathBuf {
    repo_root().join("plugins/agent-plugins")
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&read_text(path))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn object<'a>(value: &'a Value, what: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{what} is not a JSON object"))
}

fn keys(map: &Map<String, Value>) -> BTreeSet<&str> {
    map.keys().map(String::as_str).collect()
}

/// A plugin name under spec §5.5.
fn is_plugin_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && !name.contains("--")
        && !name.contains("..")
}

/// A skill name under the Agent Skills format the spec defers to (§7.1):
/// lowercase letters, digits and single hyphens, neither first nor last.
fn is_skill_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// Every `${...}` in `text` that a client would leave as literal text: all
/// but the two placeholders of spec §9.2.
fn foreign_placeholders(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        let tail = &rest[at..];
        let end = tail.find('}').map_or(tail.len(), |close| close + 1);
        let placeholder = &tail[..end];
        if !PLACEHOLDERS.contains(&placeholder) {
            found.push(placeholder.to_owned());
        }
        rest = &tail[end..];
    }
    found
}

/// One single, non-recursive replacement of each placeholder (spec §9.2).
fn expand(text: &str, root: &str, data: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix("${PLUGIN_ROOT}") {
            out.push_str(root);
            rest = after;
        } else if let Some(after) = tail.strip_prefix("${PLUGIN_DATA}") {
            out.push_str(data);
            rest = after;
        } else {
            out.push_str("${");
            rest = &tail[2..];
        }
    }
    out.push_str(rest);
    out
}

/// The shell words of one command: whitespace splits words outside double
/// quotes, and the quotes go. A command holding any other shell syntax is
/// refused, so this split is the shell's.
fn shell_words(command: &str) -> Vec<String> {
    for forbidden in [
        '\'', '\\', '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?',
    ] {
        assert!(
            !command.contains(forbidden),
            "{command:?} holds {forbidden:?}, more shell than the skill's commands use"
        );
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut in_word = false;
    for c in command.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                word.push(c);
                in_word = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quote in {command:?}");
    if in_word {
        words.push(word);
    }
    words
}

fn parse(argv: &[String]) -> Result<(), String> {
    Cli::try_parse_from(argv)
        .map(drop)
        .map_err(|error| error.to_string())
}

/// The value after `flag` in `argv`, when `flag` is there.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    let at = argv.iter().position(|word| word == flag)?;
    Some(
        argv.get(at + 1)
            .unwrap_or_else(|| panic!("{flag} has no value"))
            .as_str(),
    )
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().copied().map(String::from).collect()
}

/// The one MCP server entry, `mcpServers.oneiron`.
fn oneiron_server_entry() -> Value {
    let config = read_json(&plugin_root().join("mcp.json"));
    config["mcpServers"]["oneiron"].clone()
}

/// The entry's `args`, unexpanded.
fn entry_args(server: &Value) -> Vec<String> {
    server["args"]
        .as_array()
        .expect("args is a list")
        .iter()
        .map(|arg| arg.as_str().expect("each arg is a string").to_owned())
        .collect()
}

/// The skill's frontmatter, and its body.
fn frontmatter(skill: &str) -> (&str, &str) {
    skill
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .expect("the skill opens with frontmatter")
}

fn frontmatter_field<'a>(front: &'a str, key: &str) -> &'a str {
    front
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("the frontmatter names {key}"))
}

/// The text of the `## {heading}` section, up to the next `## `.
fn section<'a>(markdown: &'a str, heading: &str) -> &'a str {
    let start = markdown
        .find(&format!("\n## {heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading:?}"));
    let body = &markdown[start + 1..];
    let end = body[3..].find("\n## ").map_or(body.len(), |at| at + 3);
    &body[..end]
}

#[test]
fn the_package_is_an_agent_plugins_1_0_package() {
    // The checks below can fail: the spec's own examples (§5.5).
    for name in ["my-plugin", "acme.tools", "lint3r", "a"] {
        assert!(is_plugin_name(name), "{name:?}");
    }
    for name in ["My-Plugin", "-start", "has--double", "too.many..dots", ""] {
        assert!(!is_plugin_name(name), "{name:?}");
    }

    // The root holds the manifest, the MCP configuration and the skills, and
    // no other format's manifest, so a client that detects formats by their
    // files (VS Code) reads this one as Agent Plugins.
    let entries: BTreeSet<String> = std::fs::read_dir(plugin_root())
        .expect("the package folder exists")
        .map(|entry| {
            entry
                .expect("a folder entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    assert_eq!(
        entries,
        BTreeSet::from(["mcp.json", "plugin.json", "skills"].map(String::from)),
    );

    // plugin.json: closed, and naming the 1.0.0 schema (§5.2-§5.4).
    let manifest = read_json(&plugin_root().join("plugin.json"));
    let fields = object(&manifest, "plugin.json");
    let unknown: Vec<&str> = keys(fields)
        .into_iter()
        .filter(|key| !MANIFEST_FIELDS.contains(key))
        .collect();
    assert!(unknown.is_empty(), "fields outside spec §5.2: {unknown:?}");
    assert_eq!(manifest["$schema"], PLUGIN_SCHEMA);
    let name = manifest["name"].as_str().expect("name is a string");
    assert!(is_plugin_name(name), "{name:?} breaks spec §5.5");
    for key in [
        "version",
        "description",
        "homepage",
        "repository",
        "license",
    ] {
        if let Some(value) = fields.get(key) {
            assert!(value.as_str().is_some_and(|text| !text.is_empty()), "{key}");
        }
    }
    if let Some(author) = fields.get("author") {
        for (key, value) in object(author, "author") {
            assert!(
                ["name", "email", "url"].contains(&key.as_str()),
                "author.{key}"
            );
            assert!(value.is_string(), "author.{key}");
        }
    }
    if let Some(keywords) = fields.get("keywords") {
        assert!(
            keywords
                .as_array()
                .is_some_and(|list| list.iter().all(Value::is_string)),
            "keywords is a list of strings"
        );
    }
    // The same plugin as the Claude Code package: one name, one source.
    let claude = read_json(&repo_root().join("plugins/claude-code/.claude-plugin/plugin.json"));
    for key in ["name", "author", "homepage", "repository", "license"] {
        assert_eq!(manifest[key], claude[key], "{key}");
    }

    // mcp.json: exactly $schema and mcpServers (§7.2.1), one stdio entry.
    let config = read_json(&plugin_root().join("mcp.json"));
    assert_eq!(
        keys(object(&config, "mcp.json")),
        BTreeSet::from(["$schema", "mcpServers"])
    );
    assert_eq!(config["$schema"], MCP_SCHEMA);
    let servers = object(&config["mcpServers"], "mcpServers");
    assert_eq!(keys(servers), BTreeSet::from(["oneiron"]));
    for (server_name, server) in servers {
        let entry = object(server, server_name);
        let unknown: Vec<&str> = keys(entry)
            .into_iter()
            .filter(|key| !STDIO_FIELDS.contains(key))
            .collect();
        assert!(
            unknown.is_empty(),
            "{server_name}: fields outside a stdio entry: {unknown:?}"
        );
        assert_eq!(server["type"], "stdio", "{server_name}");
        // One executable token: a bare name the platform looks up, or a path
        // inside the package. No placeholder: `command` is never expanded.
        let command = server["command"].as_str().expect("command is a string");
        assert!(
            command.starts_with("./")
                || !(command.is_empty() || command.contains(['/', '\\', ' '])),
            "{server_name}: {command:?} is not one executable token"
        );
        assert!(!command.contains("${"), "{server_name}: {command:?}");
        if let Some(cwd) = server.get("cwd") {
            let cwd = cwd.as_str().expect("cwd is a string");
            assert!(
                cwd.starts_with("./")
                    || PLACEHOLDERS
                        .iter()
                        .any(|root| cwd == *root || cwd.starts_with(&format!("{root}/"))),
                "{server_name}: cwd {cwd:?}"
            );
        }
    }

    // skills/: each immediate child holding SKILL.md is one skill, named by
    // its folder (§7.1 and the Agent Skills format).
    let mut skills = BTreeSet::new();
    for entry in std::fs::read_dir(plugin_root().join("skills")).expect("skills/ is a folder") {
        let path = entry.expect("a folder entry").path();
        let skill_file = path.join("SKILL.md");
        assert!(skill_file.is_file(), "{} holds no SKILL.md", path.display());
        let folder = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 name")
            .to_owned();
        let text = read_text(&skill_file);
        let (front, _) = frontmatter(&text);
        assert_eq!(frontmatter_field(front, "name"), folder);
        assert!(is_skill_name(&folder), "{folder:?}");
        let description = frontmatter_field(front, "description");
        assert!(
            !description.is_empty() && description.len() <= 1024,
            "{description:?}"
        );
        skills.insert(folder);
    }
    assert_eq!(skills, BTreeSet::from(["oneiron".to_owned()]));
}

#[test]
fn the_mcp_entry_is_oneiron_mcp_with_the_credential_in_the_plugin_data_folder() {
    // The check below can fail: the Claude Code plugin's `${HOME}` path would
    // reach `oneiron mcp` as literal text under an Agent Plugins client.
    assert_eq!(
        foreign_placeholders("${HOME}/.config/oneiron/claude-code.cred"),
        ["${HOME}"]
    );
    assert_eq!(
        expand("${PLUGIN_DATA}/a ${PLUGIN_ROOT} ${HOME}", "/r", "/d"),
        "/d/a /r ${HOME}"
    );

    let server = oneiron_server_entry();
    assert_eq!(server["command"], "oneiron");
    let args = entry_args(&server);
    for arg in &args {
        assert!(
            foreign_placeholders(arg).is_empty(),
            "{arg:?} holds a placeholder no Agent Plugins client expands"
        );
        assert!(!arg.starts_with('~'), "{arg:?}: no client expands ~");
    }
    // The credential comes from the data folder; env is visible package
    // data and never carries one (§9.2).
    assert!(server.get("env").is_none(), "{server}");

    let mut argv = vec!["oneiron".to_owned()];
    argv.extend(
        args.iter()
            .map(|arg| expand(arg, TEST_PLUGIN_ROOT, TEST_PLUGIN_DATA)),
    );
    assert_eq!(argv[1], "mcp");
    assert_eq!(flag_value(&argv, "--surface"), Some("tool-first"));
    assert_eq!(flag_value(&argv, "--auth-mode"), None, "an agent slip");
    assert_eq!(
        flag_value(&argv, "--credential-file"),
        Some(format!("{TEST_PLUGIN_DATA}/{CREDENTIAL_FILE_NAME}").as_str())
    );
    if let Err(error) = parse(&argv) {
        panic!("{argv:?} does not parse: {error}");
    }
}

#[test]
fn the_skill_is_host_neutral_and_its_setup_mints_the_file_the_entry_reads() {
    let skill = read_text(&plugin_root().join("skills/oneiron/SKILL.md"));
    let (front, body) = frontmatter(&skill);
    assert_eq!(frontmatter_field(front, "name"), "oneiron");

    // One skill for every client: it names no single one. Claude Code has
    // its own package; the clients here appear only together, as a list.
    assert!(!skill.contains("Claude"), "the skill names Claude");
    for paragraph in skill.split("\n\n") {
        let named: Vec<&str> = CLIENTS
            .into_iter()
            .filter(|client| paragraph.contains(client))
            .collect();
        assert!(
            named.is_empty() || named.len() == CLIENTS.len(),
            "{paragraph:?} names {named:?} alone"
        );
    }

    // The recall guidance is the Claude Code skill's, word for word, so the
    // two cannot drift.
    let claude_skill = read_text(&repo_root().join("plugins/claude-code/skills/oneiron/SKILL.md"));
    assert_eq!(section(body, "Recall"), section(&claude_skill, "Recall"));

    // Every `vault.*` and `self.*` the skill names in backticks is a verb.
    let verbs_dir = repo_root().join("scripts/sdk/verbs");
    let named: BTreeSet<&str> = skill
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|token| token.starts_with("vault.") || token.starts_with("self."))
        .collect();
    assert!(
        named.contains("vault.recall") && named.contains("vault.remember"),
        "{named:?}"
    );
    for verb in &named {
        assert!(
            verbs_dir.join(format!("{verb}.json")).is_file(),
            "the skill names {verb}, which scripts/sdk/verbs/ does not hold"
        );
    }

    // Every `oneiron` line in the skill's code blocks parses, and the setup
    // mints exactly the file the MCP entry reads, under the data folder.
    let server = oneiron_server_entry();
    let entry_argv: Vec<String> = entry_args(&server)
        .iter()
        .map(|arg| expand(arg, TEST_PLUGIN_ROOT, TEST_PLUGIN_DATA))
        .collect();
    let read_file = flag_value(&entry_argv, "--credential-file")
        .expect("the entry reads a credential file")
        .to_owned();
    let mut in_block = false;
    let mut minted = BTreeSet::new();
    for line in skill.lines().map(str::trim) {
        if line.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if !in_block || !line.starts_with("oneiron ") {
            continue;
        }
        let line = line
            .replace("<client>", "codex")
            .replace("<data-folder>", TEST_PLUGIN_DATA);
        let argv = shell_words(&line);
        if let Err(error) = parse(&argv) {
            panic!("the skill's {line:?} does not parse: {error}");
        }
        if argv[1..3] == words(&["token", "agent"]) {
            let out = flag_value(&argv, "--out").expect("a mint writes a credential file");
            // The agent saves what it learns, so its credential may write.
            assert_ne!(flag_value(&argv, "--tier"), Some("read-only"), "{line:?}");
            minted.insert(out.to_owned());
        }
    }
    assert!(!in_block, "an unclosed code block");
    assert_eq!(minted, BTreeSet::from([read_file]));
}

#[test]
fn a_client_launch_before_the_mint_fails_naming_the_file_and_the_mint_command() {
    // A client creates the data folder before it launches the server (§9.1),
    // expands the placeholders in args, sets PLUGIN_ROOT and PLUGIN_DATA,
    // and runs it in the plugin root when the entry names no cwd (§7.2.1).
    let home = tempfile::tempdir().expect("a temporary folder");
    let data = home.path().join("plugins-data").join("oneiron");
    std::fs::create_dir_all(&data).expect("the data folder");
    let root = plugin_root().canonicalize().expect("the package folder");
    let (root_text, data_text) = (
        root.to_str().expect("a UTF-8 path"),
        data.to_str().expect("a UTF-8 path"),
    );
    let server = oneiron_server_entry();
    assert!(server.get("cwd").is_none(), "{server}");
    let args: Vec<String> = entry_args(&server)
        .iter()
        .map(|arg| expand(arg, root_text, data_text))
        .collect();
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(args)
        .current_dir(root_text)
        .env("PLUGIN_ROOT", root_text)
        .env("PLUGIN_DATA", data_text)
        .env_remove("ONEIRON_URL")
        .env_remove("ONEIRON_SECRET")
        .env_remove("ONEIRON_BINDING_KEY")
        .stdin(Stdio::null())
        .output()
        .expect("run oneiron");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    // stdout is the MCP channel: a failed start writes nothing there.
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let credential = data.join(CREDENTIAL_FILE_NAME);
    assert!(!credential.exists());
    // The client shows this stderr: it names the full path to mint to, and
    // the command that mints it.
    assert!(
        stderr.contains(&credential.display().to_string()),
        "stderr names no {}: {stderr}",
        credential.display()
    );
    assert!(
        stderr.contains("oneiron token agent"),
        "stderr names no mint command: {stderr}"
    );
}
