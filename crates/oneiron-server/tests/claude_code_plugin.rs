//! The Claude Code plugin (`plugins/claude-code`; ARCH-0028
//! #plugin-agent-plugins, ARCH-0067 row 34): the install pair, the
//! user-level skill and the MCP registration, plus the built hook lanes,
//! wrapped in Claude Code's plugin format and listed in this repository's own
//! marketplace (#plugin-listing, A for the alpha).
//!
//! Every command the plugin runs, and every setup command its skill gives,
//! parses with the `oneiron` binary's own CLI, so a renamed flag or
//! subcommand fails here and not in a person's session. Every verb the skill
//! names is a verb the engine has.
//!
//! Run with: `cargo test --locked -p oneiron-server --test claude_code_plugin`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Parser as _;
use oneiron_server::cli::Cli;
use serde_json::Value;

/// The `$HOME` the plugin's paths are read under.
const TEST_HOME: &str = "/home/plugin-test";
/// The credential the MCP server entry reads: the agent's own, for its tools.
const AGENT_CREDENTIAL: &str = "/home/plugin-test/.config/oneiron/claude-code.cred";
/// The credential the session-start hook reads: read-only, for its recall.
const HOOKS_CREDENTIAL: &str = "/home/plugin-test/.config/oneiron/claude-code-hooks.cred";
/// `oneiron hook`'s own `--timeout` when the command names none
/// (`HookCommonArgs::timeout`).
const HOOK_DEFAULT_TIMEOUT_SECS: f64 = 8.0;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn plugin_root() -> PathBuf {
    repo_root().join("plugins/claude-code")
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&read_text(path))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Claude Code runs a hook command through the shell and expands `${VAR}` in
/// `.mcp.json`. The plugin uses `${HOME}` alone.
fn expand_home(text: &str) -> String {
    text.replace("${HOME}", TEST_HOME)
}

/// The shell words of one command: whitespace splits words outside double
/// quotes, and the quotes go. A command holding any other shell syntax is
/// refused, so this split is the shell's.
fn shell_words(command: &str) -> Vec<String> {
    for forbidden in ['\'', '\\', '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?'] {
        assert!(
            !command.contains(forbidden),
            "{command:?} holds {forbidden:?}, more shell than the plugin's commands use"
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
    Some(argv.get(at + 1).unwrap_or_else(|| panic!("{flag} has no value")).as_str())
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().copied().map(String::from).collect()
}

#[test]
fn the_marketplace_lists_the_plugin_folder() {
    let marketplace = read_json(&repo_root().join(".claude-plugin/marketplace.json"));
    assert_eq!(marketplace["name"], "oneiron");
    assert!(marketplace["owner"]["name"].as_str().is_some_and(|name| !name.is_empty()));
    let plugins = marketplace["plugins"].as_array().expect("plugins is a list");
    let entry = plugins
        .iter()
        .find(|plugin| plugin["name"] == "oneiron")
        .expect("the marketplace lists the oneiron plugin");
    let source = entry["source"].as_str().expect("a relative source path");
    assert!(source.starts_with("./"), "{source:?} is not relative to the marketplace");
    let folder = repo_root().join(source);
    assert_eq!(
        folder.canonicalize().expect("the source folder exists"),
        plugin_root().canonicalize().expect("the plugin folder exists"),
    );

    let manifest = read_json(&plugin_root().join(".claude-plugin/plugin.json"));
    assert_eq!(manifest["name"], "oneiron");
    assert!(manifest["description"].as_str().is_some_and(|text| !text.is_empty()));
    for part in [".mcp.json", "hooks/hooks.json", "skills/oneiron/SKILL.md"] {
        assert!(plugin_root().join(part).is_file(), "the plugin carries {part}");
    }
}

#[test]
fn every_hook_command_parses_with_the_oneiron_cli() {
    let hooks = read_json(&plugin_root().join("hooks/hooks.json"));
    let events = hooks["hooks"].as_object().expect("hooks.hooks is an object");
    // The built lanes (docs/ops/claude-code-hooks.md): the four events and the
    // `oneiron hook` event each runs. A new event is added here on purpose.
    let expected = BTreeMap::from([
        ("PreCompact", "hand-over"),
        ("SessionEnd", "hand-over"),
        ("SessionStart", "session-start"),
        ("Stop", "hand-over"),
    ]);
    assert_eq!(
        events.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected.keys().copied().collect::<BTreeSet<_>>(),
    );
    for (event, hook_event) in expected {
        let groups = events[event].as_array().expect("an event holds a list");
        let commands: Vec<&Value> = groups
            .iter()
            .flat_map(|group| group["hooks"].as_array().expect("a group holds hooks"))
            .collect();
        assert_eq!(commands.len(), 1, "{event} runs one oneiron hook");
        let hook = commands[0];
        assert_eq!(hook["type"], "command", "{event}");
        let host_timeout = hook["timeout"].as_f64().expect("each hook names its timeout");
        let argv = shell_words(&expand_home(hook["command"].as_str().expect("a command")));
        assert_eq!(
            argv[..5],
            words(&["oneiron", "hook", "--host", "claude-code", hook_event]),
            "{event}"
        );
        if let Err(error) = parse(&argv) {
            panic!("{event}: {argv:?} does not parse: {error}");
        }
        // The hook gives up before Claude Code would stop it, so it always
        // exits 0 on its own and never shows as a hook error.
        let own_timeout = flag_value(&argv, "--timeout")
            .map_or(HOOK_DEFAULT_TIMEOUT_SECS, |secs| secs.parse().expect("seconds"));
        assert!(
            own_timeout < host_timeout,
            "{event}: oneiron's {own_timeout} s is not under Claude Code's {host_timeout} s"
        );
        let credential = flag_value(&argv, "--credential-file");
        if hook_event == "session-start" {
            assert_eq!(credential, Some(HOOKS_CREDENTIAL), "{event}");
        } else {
            // A hand-over needs no credential (it writes one queue file).
            assert_eq!(credential, None, "{event}");
        }
    }

    // The check above can fail: a mistyped event is refused by the same parse.
    assert!(parse(&words(&["oneiron", "hook", "--host", "claude-code", "sessionstart"])).is_err());
    assert!(parse(&words(&["oneiron", "hook", "--host", "claude", "session-start"])).is_err());
}

#[test]
fn the_mcp_server_is_the_stdio_bridge_with_the_agent_credential() {
    let config = read_json(&plugin_root().join(".mcp.json"));
    let servers = config["mcpServers"].as_object().expect("mcpServers is an object");
    assert_eq!(servers.keys().map(String::as_str).collect::<Vec<_>>(), ["oneiron"]);
    let server = &servers["oneiron"];
    assert_eq!(server["command"], "oneiron");
    let mut argv = vec!["oneiron".to_owned()];
    argv.extend(
        server["args"]
            .as_array()
            .expect("args is a list")
            .iter()
            .map(|arg| expand_home(arg.as_str().expect("each arg is a string"))),
    );
    assert_eq!(argv[1], "mcp");
    assert_eq!(flag_value(&argv, "--surface"), Some("tool-first"));
    assert_eq!(flag_value(&argv, "--credential-file"), Some(AGENT_CREDENTIAL));
    if let Err(error) = parse(&argv) {
        panic!("{argv:?} does not parse: {error}");
    }
    // The tools and the hooks hold separate credentials, so either can be
    // revoked alone.
    assert_ne!(AGENT_CREDENTIAL, HOOKS_CREDENTIAL);
}

#[test]
fn the_skill_names_only_verbs_the_engine_has_and_its_setup_parses() {
    let skill = read_text(&plugin_root().join("skills/oneiron/SKILL.md"));
    let front = skill
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .map(|(front, _)| front)
        .expect("the skill opens with frontmatter");
    let field = |key: &str| {
        front
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(": "))
            .unwrap_or_else(|| panic!("the frontmatter names {key}"))
    };
    assert_eq!(field("name"), "oneiron");
    let description = field("description");
    assert!(!description.is_empty() && description.len() <= 1024, "{description:?}");

    // Every `vault.*` and `self.*` the skill names in backticks is a verb.
    let verbs_dir = repo_root().join("scripts/sdk/verbs");
    let named: BTreeSet<&str> = skill
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|token| token.starts_with("vault.") || token.starts_with("self."))
        .collect();
    assert!(named.contains("vault.recall") && named.contains("vault.remember"), "{named:?}");
    for verb in &named {
        assert!(
            verb.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.'),
            "{verb:?}"
        );
        assert!(
            verbs_dir.join(format!("{verb}.json")).is_file(),
            "the skill names {verb}, which scripts/sdk/verbs/ does not hold"
        );
    }

    // Every `oneiron` line in the skill's code blocks parses, and the setup
    // mints exactly the two credentials the plugin reads.
    let mut in_block = false;
    let mut minted = BTreeSet::new();
    let mut commands = 0;
    for line in skill.lines().map(str::trim) {
        if line.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if !in_block || !line.starts_with("oneiron ") {
            continue;
        }
        commands += 1;
        let argv = shell_words(&line.replace("~/", &format!("{TEST_HOME}/")));
        if let Err(error) = parse(&argv) {
            panic!("the skill's {line:?} does not parse: {error}");
        }
        if argv[1..3] == words(&["token", "agent"]) {
            let out = flag_value(&argv, "--out").expect("a mint writes a credential file");
            let tier = flag_value(&argv, "--tier");
            if out == HOOKS_CREDENTIAL {
                assert_eq!(tier, Some("read-only"), "the hooks only read");
            }
            minted.insert(out.to_owned());
        }
    }
    assert!(!in_block, "an unclosed code block");
    assert!(commands >= 2, "the skill gives its setup commands");
    assert_eq!(
        minted,
        BTreeSet::from([AGENT_CREDENTIAL.to_owned(), HOOKS_CREDENTIAL.to_owned()])
    );
}
