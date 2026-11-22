//! Seams for `tests/continue_command.rs`, reached through
//! `crate::test_doors::continue_command`: the hand-off commit, the session
//! log discovery, and the command's steps against a scripted vault, since
//! its own vault is a hosted one reached through `oneiron mcp`.

use super::*;

pub use super::hand_off::test_support::{push_hand_off, push_hand_off_signed_in};

/// How the scripted vault and the push answer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Script {
    /// The selection can push: a paired slip, or an OAuth selection
    /// on its continue sign-in.
    pub can_push: bool,
    /// The push fails.
    pub push_fails: bool,
    /// The start's answer never comes back, as when the connection is
    /// lost after the vault bound the work.
    pub start_unanswered: bool,
}

/// What one scripted run of the command did.
pub struct Scripted {
    /// What it printed.
    pub output: String,
    /// Its error, if it failed.
    pub error: Option<String>,
    /// The steps that left the process, in order: each verb's name, and
    /// `git-receive-pack` for the push.
    pub calls: Vec<&'static str>,
    /// The session id and the subagent log stems the import carried.
    pub sent: Option<(String, Vec<String>)>,
}

/// The hand-off commit of the repo that holds `dir`, and its parent,
/// built with `within` left before the deadline.
pub fn hand_off_commit(dir: &Path, within: Duration) -> Result<(String, Option<String>), String> {
    hand_off::hand_off_commit(dir, "a test hand-off", Instant::now() + within)
        .map(|hand_off| (hand_off.commit, hand_off.parent))
        .map_err(|error| format!("{error:#}"))
}

/// The session log the command finds for `dir` with no `--transcript`,
/// when Claude Code's project folders are under `projects`.
pub fn discovered_session(projects: &Path, dir: &Path) -> Result<PathBuf, String> {
    transcript::newest_session(projects, dir, Instant::now() + DEADLINE)
        .map_err(|error| format!("{error:#}"))
}

/// Runs the command in `dir`, sending the session log `transcript`,
/// against a vault whose check answers ready, whose import lands it, and
/// whose start binds it, save where `script` says otherwise.
pub fn run_scripted(dir: &Path, transcript: &Path, script: Script) -> Scripted {
    let mut remote = ScriptedRemote {
        script,
        calls: Vec::new(),
        sent: None,
    };
    let plan = Plan {
        dir: dir.to_path_buf(),
        repo: "demo".to_owned(),
        runner: "claude-code".to_owned(),
        note: None,
        transcript: Some(transcript.to_path_buf()),
        deadline: Instant::now() + DEADLINE,
    };
    let mut out = Vec::new();
    let ran = run(&mut remote, &plan, &mut out);
    Scripted {
        output: String::from_utf8_lossy(&out).into_owned(),
        error: ran.err().map(|error| format!("{error:#}")),
        calls: remote.calls,
        sent: remote.sent,
    }
}

struct ScriptedRemote {
    script: Script,
    calls: Vec<&'static str>,
    sent: Option<(String, Vec<String>)>,
}

impl ContinueRemote for ScriptedRemote {
    fn check(
        &mut self,
        request: &ContinueOutsideWorkCheckRequest,
    ) -> anyhow::Result<ContinueOutsideWorkCheckView> {
        self.calls.push("vault.runners.continue.check");
        Ok(ContinueOutsideWorkCheckView::Ready {
            seat: 0,
            runner: request.runner.clone(),
        })
    }

    fn ready_push(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(self.script.can_push, "{PUSH_NEEDS_SLIP}");
        Ok(())
    }

    fn carried_bytes(&self) -> usize {
        usize::MAX
    }

    fn import(
        &mut self,
        request: &HookTranscriptImportRequest,
    ) -> anyhow::Result<HookTranscriptImportView> {
        self.calls.push("vault.imports.hook_transcript");
        self.sent = Some((
            request.session.clone(),
            request
                .subagents
                .iter()
                .map(|subagent| subagent.stem.clone())
                .collect(),
        ));
        Ok(HookTranscriptImportView {
            conversation: "0".repeat(32),
            conversations: Vec::new(),
            review: None,
        })
    }

    fn push(&mut self, _: &HandOff, _: &str, _: &str) -> anyhow::Result<()> {
        self.calls.push("git-receive-pack");
        anyhow::ensure!(
            !self.script.push_fails,
            "the custody repo refused the push (503 Service Unavailable): down"
        );
        Ok(())
    }

    fn start(&mut self, _: &ContinueOutsideWorkRequest) -> anyhow::Result<ContinueOutsideWorkView> {
        self.calls.push("vault.runners.continue");
        if self.script.start_unanswered {
            return Err(CallUnconfirmed {
                verb: "vault.runners.continue".to_owned(),
                origin: "https://vault.example".to_owned(),
                invocation: "1".repeat(32),
                why: "tools/call failed: the connection closed before an answer".to_owned(),
            }
            .into());
        }
        Ok(ContinueOutsideWorkView::Bound {
            binding: "binding".to_owned(),
            seat: 0,
            attempt: "attempt".to_owned(),
            task: "task".to_owned(),
            checkout: "checkout".to_owned(),
            existing: false,
        })
    }
}
