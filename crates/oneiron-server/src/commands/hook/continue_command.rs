//! `oneiron continue --cloud` (census L10-17): moves the Claude Code session
//! working in this repo to the hosted vault this machine selected (`oneiron
//! hosted`), where it goes on on the node's own runner seat.
//!
//! The steps run in order. The first that fails ends the command with a line
//! saying the work did NOT move, so the session goes on here as before
//! (CLR-001). The command never stops the local session itself.
//!
//! 1. **Check.** `vault.runners.continue.check` answers whether the node runs
//!    the runner: a seat the provider's terms allow there, the custody repo,
//!    the seat's quota.
//! 2. **A slip to push with.** The custody repo takes a push from a paired
//!    slip alone (L10-17-PR3-PUSH = A), so an OAuth or owner selection stops
//!    here and the message names what is missing.
//! 3. **Memory.** `vault.imports.hook_transcript` lands the session's log and
//!    its subagents' logs ([`transcript`]); its answer names the
//!    conversation. A log that did not land whole (a turn refused, or one
//!    waiting behind another import) stops here.
//! 4. **Workspace.** A hand-off commit of the working tree ([`hand_off`])
//!    goes to `refs/heads/oneiron/continue/<conversation>` of the custody
//!    repo.
//! 5. **Start.** `vault.runners.continue`. "Safe to close this machine" is
//!    printed only when it answers bound. A start whose answer never came
//!    back (the bridge read none in time, or none it could read) may have
//!    bound the work, so it ends neither way: the command says the start is
//!    UNCONFIRMED and names the hand-off and the call, so a later start of
//!    the same hand-off answers where it stands ([`StartUnconfirmed`]).
//!
//! Every git the command runs, and the push, ends by the command's deadline.
//!
//! Each verb is one MCP tool call through `oneiron mcp`, as the hooks'
//! recall makes it, so the bridge alone reads the credential the selection
//! names. The push reads the paired slip itself, since git's custody door
//! is not an MCP tool.

mod hand_off;
mod transcript;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use oneiron::dispatch_byoa::{
    ContinueOutsideWorkCheckRequest, ContinueOutsideWorkCheckView, ContinueOutsideWorkRequest,
    ContinueOutsideWorkView, SkippedRunnerSeatView,
};
use oneiron::ingest::history::{
    HookTranscriptConversation, HookTranscriptImportRequest, HookTranscriptImportView,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use self::hand_off::{CustodyRepo, HandOff};
use super::hosted_selection::{self, HostedAuthMode, HostedDiscovery, HostedVault};
use super::recall::{Bridge, RpcRefusal};
use crate::cli::ContinueArgs;
use crate::commands::credential_file::PairedCredentialFile;
use crate::commands::mcp_bridge::{INVOCATION_META, UNANSWERED_ERROR_KINDS, mint_invocation};

/// How long the whole hand-off may take, the import of a long session and
/// the push of a large tree included.
const DEADLINE: Duration = Duration::from_secs(30 * 60);
/// The tool-first argument shape every call speaks
/// (`crate::mcp`'s `MCP_TOOL_ARGS_SCHEMA_VERSION`).
const TOOL_ARGS_VERSION: &str = "mcp_tool_args.v1";
/// The consent policy every call of the command names.
const POLICY_REF: &str = "policy:continue-cloud";
/// The custody ref a conversation's hand-off lands on, before its id.
const CONTINUE_REF_PREFIX: &str = "refs/heads/oneiron/continue/";
/// The line every failure ends with.
const NOT_MOVED: &str = "The work did NOT move: this session goes on here as before.";
/// What an OAuth or owner selection lacks (L10-17-PR3-PUSH = A).
const PUSH_NEEDS_SLIP: &str = "pushing the work needs a paired slip with a git_push Grant on \
     the repo, and the selected vault is signed in another way";

/// `oneiron continue --cloud`.
pub fn continue_work(args: ContinueArgs) -> anyhow::Result<()> {
    let vault = match hosted_selection::discover() {
        HostedDiscovery::Selected(vault) => vault,
        HostedDiscovery::NotLoggedIn => anyhow::bail!(
            "no hosted vault is recorded on this machine; sign in with `oneiron hosted login` first"
        ),
        HostedDiscovery::NoSelection => {
            anyhow::bail!("no hosted vault is selected; pick one with `oneiron hosted select`")
        }
        HostedDiscovery::Unavailable(why) => {
            anyhow::bail!("the hosted vault selection cannot be read: {why}")
        }
    };
    let deadline = Instant::now() + DEADLINE;
    let plan = Plan {
        dir: std::env::current_dir()?,
        repo: args.repo,
        runner: args.runner,
        note: args.note,
        transcript: args.transcript,
        deadline,
    };
    let oneiron = super::oneiron(None);
    let mut out = std::io::stdout().lock();
    let mut remote = match Hosted::open(
        &oneiron,
        &vault,
        POLICY_REF.to_owned(),
        Stdio::inherit(),
        deadline,
    ) {
        Ok(remote) => remote,
        Err(error) => {
            writeln!(out, "{NOT_MOVED}")?;
            return Err(error);
        }
    };
    let ran = run(&mut remote, &plan, &mut out);
    remote.bridge.close();
    ran
}

/// What one run of the command hands off.
pub(crate) struct Plan {
    /// Where it runs: inside the repo whose working tree moves.
    pub(crate) dir: PathBuf,
    /// The custody repo's served name, as its push URL's `{repo}`.
    pub(crate) repo: String,
    /// The runner the session goes on in, e.g. `claude-code`.
    pub(crate) runner: String,
    /// A note for the run, if any.
    pub(crate) note: Option<String>,
    /// The session log to send; `None` finds the newest of this repo's.
    pub(crate) transcript: Option<PathBuf>,
    /// When the hand-off must have ended: every git it runs is stopped then.
    pub(crate) deadline: Instant,
}

/// The steps that leave this process: the hosted vault's three verbs and
/// the push to its custody repo.
pub(crate) trait ContinueRemote {
    fn check(
        &mut self,
        request: &ContinueOutsideWorkCheckRequest,
    ) -> anyhow::Result<ContinueOutsideWorkCheckView>;
    /// Whether the selection can push: a paired slip.
    fn can_push(&self) -> bool;
    fn import(
        &mut self,
        request: &HookTranscriptImportRequest,
    ) -> anyhow::Result<HookTranscriptImportView>;
    /// Pushes the hand-off to `git_ref` of the custody repo `repo`.
    fn push(&mut self, hand_off: &HandOff, repo: &str, git_ref: &str) -> anyhow::Result<()>;
    fn start(
        &mut self,
        request: &ContinueOutsideWorkRequest,
    ) -> anyhow::Result<ContinueOutsideWorkView>;
}

/// Runs the steps of `plan` against `remote`, saying each on `out`; on any
/// failure the last line is [`NOT_MOVED`], save a start whose answer never
/// came back, which ends with what [`StartUnconfirmed`] says.
pub(crate) fn run(
    remote: &mut dyn ContinueRemote,
    plan: &Plan,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let ran = steps(remote, plan, out);
    if let Err(error) = &ran {
        match error.downcast_ref::<StartUnconfirmed>() {
            Some(start) => writeln!(out, "{}", start.next_steps())?,
            None => writeln!(out, "{NOT_MOVED}")?,
        }
    }
    ran
}

fn steps(remote: &mut dyn ContinueRemote, plan: &Plan, out: &mut dyn Write) -> anyhow::Result<()> {
    let checked = remote.check(&ContinueOutsideWorkCheckRequest {
        repo: plan.repo.clone(),
        runner: plan.runner.clone(),
    })?;
    match checked {
        ContinueOutsideWorkCheckView::Ready { seat, runner } => {
            writeln!(
                out,
                "Checked: seat {seat} of the vault's node runs {runner}."
            )?;
        }
        ContinueOutsideWorkCheckView::NoRunnerSeat { runner } => {
            anyhow::bail!("{}", no_runner_seat(&runner))
        }
        ContinueOutsideWorkCheckView::NoSeat { skipped } => anyhow::bail!("{}", no_seat(&skipped)),
        ContinueOutsideWorkCheckView::Exhausted { back_at, skipped } => {
            anyhow::bail!("{}", exhausted(back_at, &skipped))
        }
    }
    anyhow::ensure!(remote.can_push(), "{PUSH_NEEDS_SLIP}");

    let session = transcript::read(plan.transcript.as_deref(), &plan.dir, plan.deadline)?;
    writeln!(
        out,
        "Sending session {} ({} subagent logs) from {}.",
        session.request.session,
        session.request.subagents.len(),
        session.path.display()
    )?;
    let imported = remote.import(&session.request)?;
    writeln!(
        out,
        "Imported: conversation {}{}.",
        imported.conversation,
        imported
            .review
            .as_deref()
            .map(|review| format!(", review {review}"))
            .unwrap_or_default()
    )?;
    let partial: Vec<&HookTranscriptConversation> = imported
        .conversations
        .iter()
        .filter(|conversation| conversation.refused > 0 || conversation.pending > 0)
        .collect();
    anyhow::ensure!(partial.is_empty(), "{}", not_landed_whole(&partial));

    let git_ref = format!("{CONTINUE_REF_PREFIX}{}", imported.conversation);
    let message = format!(
        "oneiron continue: hand-off of Claude Code session {}\n\nConversation {}.",
        session.request.session, imported.conversation
    );
    let hand_off = hand_off::hand_off_commit(&plan.dir, &message, plan.deadline)?;
    writeln!(
        out,
        "Hand-off commit {} (parent {}); pushing it to {git_ref} of {}.",
        hand_off.commit,
        hand_off.parent.as_deref().unwrap_or("none"),
        plan.repo
    )?;
    remote.push(&hand_off, &plan.repo, &git_ref)?;
    writeln!(out, "Pushed.")?;

    let request = ContinueOutsideWorkRequest {
        repo: plan.repo.clone(),
        git_ref,
        commit: hand_off.commit.clone(),
        conversation: imported.conversation,
        runner: plan.runner.clone(),
        note: plan.note.clone(),
    };
    let answered = remote.start(&request);
    let started = match answered {
        Ok(started) => started,
        Err(error) => match error.downcast::<CallUnconfirmed>() {
            Ok(call) => return Err(StartUnconfirmed { call, request }.into()),
            Err(error) => return Err(error),
        },
    };
    match started {
        ContinueOutsideWorkView::Bound {
            seat,
            attempt,
            task,
            existing,
            ..
        } => {
            let again = if existing { ", started before" } else { "" };
            writeln!(
                out,
                "Safe to close this machine: the work goes on in Oneiron Cloud on seat {seat} \
                 (task {task}, attempt {attempt}{again})."
            )?;
            Ok(())
        }
        ContinueOutsideWorkView::NoRunnerSeat { runner } => {
            anyhow::bail!("{}", no_runner_seat(&runner))
        }
        ContinueOutsideWorkView::NoSeat { skipped } => anyhow::bail!("{}", no_seat(&skipped)),
        ContinueOutsideWorkView::Exhausted { back_at, skipped } => {
            anyhow::bail!("{}", exhausted(back_at, &skipped))
        }
    }
}

/// A call the vault may have acted on whose answer this command never read:
/// none came before the deadline, the bridge said it got none it could read
/// ([`UNANSWERED_ERROR_KINDS`]), or the one that came holds no output this
/// command reads.
#[derive(Debug)]
pub(crate) struct CallUnconfirmed {
    /// The verb called.
    pub(crate) verb: String,
    /// The vault's origin, where the call went.
    pub(crate) origin: String,
    /// The call's invocation id ([`INVOCATION_META`]).
    pub(crate) invocation: String,
    /// What the bridge said.
    pub(crate) why: String,
}

impl std::fmt::Display for CallUnconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {} (invocation {}) got no answer this command could read: {}",
            self.verb, self.origin, self.invocation, self.why
        )
    }
}

impl std::error::Error for CallUnconfirmed {}

/// The start of a pushed hand-off whose answer never came back: the vault
/// may have bound the work, or not. The same start again binds nothing new
/// and answers where the work stands (`continue_outside_work`: the same
/// request twice binds the same work), so its coordinates are kept for that
/// check. Running the whole command again would build a new hand-off commit,
/// and so a second run of the session if this one is bound.
#[derive(Debug)]
pub(crate) struct StartUnconfirmed {
    call: CallUnconfirmed,
    request: ContinueOutsideWorkRequest,
}

impl StartUnconfirmed {
    /// The lines the command ends with in place of [`NOT_MOVED`].
    fn next_steps(&self) -> String {
        let request = &self.request;
        format!(
            "The start is UNCONFIRMED: the vault may have bound the work, or not, and this \
             machine cannot tell which. Do not close it, and do not run `oneiron continue \
             --cloud` again yet: a new hand-off commit would start a second run if this one is \
             bound.\n\
             The hand-off: commit {} on {} of the custody repo {} at {}, conversation {}, runner \
             {}; the start's invocation {}.\n\
             To learn where it stands, call vault.runners.continue again with that repo, git_ref, \
             commit, conversation and runner: a bound start answers its binding again, with no \
             second write, and any other answer means it did not start.",
            request.commit,
            request.git_ref,
            request.repo,
            self.call.origin,
            request.conversation,
            request.runner,
            self.call.invocation,
        )
    }
}

impl std::fmt::Display for StartUnconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the start is unconfirmed: {}", self.call)
    }
}

impl std::error::Error for StartUnconfirmed {}

/// Whether a bridge call's failure leaves the request's fate unknown: no
/// answer came before the deadline or the bridge ended first, or the bridge
/// said it got no answer it could read. A request the bridge never took
/// (its stdin closed) and every refusal the vault answers are known.
fn unanswered(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::sync::mpsc::RecvTimeoutError>()
        .is_some()
        || error.downcast_ref::<RpcRefusal>().is_some_and(|refusal| {
            refusal
                .kind
                .as_deref()
                .is_some_and(|kind| UNANSWERED_ERROR_KINDS.contains(&kind))
        })
}

/// Why the session's log did not land whole: each conversation with a turn
/// refused or waiting behind another import.
fn not_landed_whole(partial: &[&HookTranscriptConversation]) -> String {
    let each: Vec<String> = partial
        .iter()
        .map(|conversation| {
            let reasons = if conversation.refusal_reasons.is_empty() {
                String::new()
            } else {
                format!(" ({})", conversation.refusal_reasons.join(", "))
            };
            format!(
                "{}: {} turns refused{reasons}, {} waiting behind another import",
                conversation.native_id, conversation.refused, conversation.pending
            )
        })
        .collect();
    format!(
        "the session's log did not land whole, so the session cannot go on there: {}; run the \
         command again once the waiting turns land",
        each.join("; ")
    )
}

fn no_runner_seat(runner: &str) -> String {
    format!("the vault's node has no seat for {runner}; sign {runner} in on that node first")
}

fn no_seat(skipped: &[SkippedRunnerSeatView]) -> String {
    format!(
        "no seat on the vault's node may run this session: {}",
        passed_over(skipped)
    )
}

fn exhausted(back_at: Option<u64>, skipped: &[SkippedRunnerSeatView]) -> String {
    let until = back_at.map(|at| format!(" until {at}")).unwrap_or_default();
    format!(
        "every seat on the vault's node that could run this session is spent{until}: {}",
        passed_over(skipped)
    )
}

/// Each seat passed over, with why.
fn passed_over(skipped: &[SkippedRunnerSeatView]) -> String {
    if skipped.is_empty() {
        return "no seat was tried".to_owned();
    }
    skipped
        .iter()
        .map(|seat| format!("seat {} ({}) {}", seat.seat, seat.runner, seat.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The hooks' hand-over to the selected hosted vault: the Claude Code session
/// log at `log` and its subagents' logs, landed through
/// `vault.imports.hook_transcript` as step 3 lands them, over one `oneiron
/// mcp` as the selection's own credential, in its own mode, under the
/// consent `policy_ref` names. The bridge's stderr goes nowhere, as the
/// local import's does: a hand-over's output is not the host's.
pub(super) fn hand_over_hosted(
    oneiron: &Path,
    vault: &HostedVault,
    log: &Path,
    policy_ref: String,
    deadline: Instant,
) -> anyhow::Result<()> {
    let session = transcript::read_hook_log(log)?;
    let mut remote = Hosted::open(oneiron, vault, policy_ref, Stdio::null(), deadline)?;
    let imported = remote.call::<HookTranscriptImportView>(
        "vault.imports.hook_transcript",
        &session.request,
        "land this session's log in the selected vault",
    );
    remote.bridge.close();
    imported.map(drop)
}

/// The selected hosted vault, spoken to through one `oneiron mcp`.
struct Hosted<'a> {
    vault: &'a HostedVault,
    bridge: Bridge,
    calls: u64,
    /// The consent policy every call names.
    policy_ref: String,
    /// When the push must have ended, as the bridge's calls must.
    deadline: Instant,
}

impl<'a> Hosted<'a> {
    /// `oneiron mcp` at the vault's origin as the selection's credential,
    /// past its handshake, its calls naming `policy_ref`. Its own refusal
    /// goes to `stderr`.
    fn open(
        oneiron: &Path,
        vault: &'a HostedVault,
        policy_ref: String,
        stderr: Stdio,
        deadline: Instant,
    ) -> anyhow::Result<Self> {
        let mut bridge = Bridge::start(
            oneiron,
            &vault.origin,
            vault.recall_auth(),
            deadline,
            stderr,
        )?;
        if let Err(error) = bridge.initialize() {
            bridge.close();
            return Err(error.context(format!(
                "the hosted vault at {} did not answer",
                vault.origin
            )));
        }
        Ok(Self {
            vault,
            bridge,
            calls: 1,
            policy_ref,
            deadline,
        })
    }

    /// One tool call of `verb` with `spec`, its output. A refusal names the
    /// verb and the vault's reason; a call whose answer never came back, or
    /// came back unreadable, is a [`CallUnconfirmed`].
    fn call<O: DeserializeOwned>(
        &mut self,
        verb: &str,
        spec: &impl Serialize,
        purpose: &str,
    ) -> anyhow::Result<O> {
        self.calls += 1;
        // One logical call under one invocation id (ARCH-0080 §3): made once,
        // never retried.
        let invocation = mint_invocation();
        let mut meta = Map::new();
        meta.insert(
            INVOCATION_META.to_owned(),
            Value::String(invocation.clone()),
        );
        let vault = self.vault;
        let unconfirmed = |why: String| CallUnconfirmed {
            verb: verb.to_owned(),
            origin: vault.origin.clone(),
            invocation: invocation.clone(),
            why,
        };
        let answered = self.bridge.call(
            self.calls,
            "tools/call",
            json!({
                "name": verb,
                "arguments": {
                    "schema_version": TOOL_ARGS_VERSION,
                    "consent": {"policy_ref": self.policy_ref, "purpose": purpose},
                    "arguments": {"spec": spec},
                },
                "_meta": meta,
            }),
        );
        let result = match answered {
            Ok(result) => result,
            Err(error) if unanswered(&error) => {
                return Err(unconfirmed(format!("{error:#}")).into());
            }
            Err(error) => return Err(error.context(verb.to_owned())),
        };
        if result.get("isError") == Some(&Value::Bool(true)) {
            let said = result
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .unwrap_or("no reason given");
            anyhow::bail!("{verb} stopped: {said}");
        }
        let Some(output) = result.pointer("/structuredContent/output").cloned() else {
            return Err(unconfirmed("it answered no output".to_owned()).into());
        };
        serde_json::from_value(output).map_err(|error| {
            unconfirmed(format!(
                "it answered an output this command cannot read: {error}"
            ))
            .into()
        })
    }
}

impl ContinueRemote for Hosted<'_> {
    fn check(
        &mut self,
        request: &ContinueOutsideWorkCheckRequest,
    ) -> anyhow::Result<ContinueOutsideWorkCheckView> {
        self.call(
            "vault.runners.continue.check",
            request,
            "check whether this session can continue on the selected vault",
        )
    }

    fn can_push(&self) -> bool {
        self.vault.auth_mode == HostedAuthMode::Slip
    }

    fn import(
        &mut self,
        request: &HookTranscriptImportRequest,
    ) -> anyhow::Result<HookTranscriptImportView> {
        self.call(
            "vault.imports.hook_transcript",
            request,
            "land this session's log so it continues on the selected vault",
        )
    }

    fn push(&mut self, hand_off: &HandOff, repo: &str, git_ref: &str) -> anyhow::Result<()> {
        let slip = PairedCredentialFile::read(&self.vault.credential_file)?;
        hand_off::push(
            &hand_off.top,
            &CustodyRepo {
                origin: &self.vault.origin,
                repo,
                token: &slip.token,
                seed: &slip.seed,
            },
            &hand_off.commit,
            git_ref,
            self.deadline,
        )
    }

    fn start(
        &mut self,
        request: &ContinueOutsideWorkRequest,
    ) -> anyhow::Result<ContinueOutsideWorkView> {
        self.call(
            "vault.runners.continue",
            request,
            "start this session on the selected vault's runner seat",
        )
    }
}

/// Seams for `tests/continue_command.rs`, reached through
/// `crate::test_doors::continue_command`: the hand-off commit, the session
/// log discovery, and the command's steps against a scripted vault, since
/// its own vault is a hosted one reached through `oneiron mcp`.
#[cfg(oneiron_test_support)]
pub(crate) mod test_support {
    use super::*;

    /// How the scripted vault and the push answer.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Script {
        /// The selection is a paired slip.
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
    pub fn hand_off_commit(
        dir: &Path,
        within: Duration,
    ) -> Result<(String, Option<String>), String> {
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

        fn can_push(&self) -> bool {
            self.script.can_push
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

        fn start(
            &mut self,
            _: &ContinueOutsideWorkRequest,
        ) -> anyhow::Result<ContinueOutsideWorkView> {
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
}
