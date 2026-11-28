//! `oneiron jobs run` and `oneiron jobs follow` (FIX [ONEIRON-BOOKER-CLI]; FLEET-TOOL-PARITY,
//! owner 28 Nov: every booking the fleet tool makes moves into Oneiron): `fleet run` on the
//! vault's own machines, for the one booker agent (docs/ops/jobs-booker.md).
//!
//! `run` reads the machines the issuer holds a job grant for (`vault.machines.execution.get`)
//! and picks `--host` by its shown name and the template's digest from its node's answer; it
//! hashes the contract as the commit holds it, pins the workload for the booker's PROJECT
//! (`vault.jobs.workloads.pin`), orders it (`vault.jobs.order`: `--key` is the intent key,
//! `--host` the order's `limits.machines`), and follows the order and its logs
//! ([`follow`]) to its end. It exits with the job's own code, or the code `fleet run` gives the
//! same end ([`end`]). TERM or INT asks the issuer to cancel the order and follows it to its
//! end; HUP changes nothing. Every call is one facade row over `oneiron api`'s curl path,
//! under the booker's slip ([`transport`]). Nothing here opens a listener or a bind.

mod end;
mod follow;
mod request;
mod transport;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use oneiron::EntityId;
use oneiron::job_workload::{WorkloadChange, WorkloadVerb};
use oneiron::verbs::{MACHINES_EXECUTION_GET_VERB, MachineExecutionReply};
use oneiron::work_order::{ORDER_VERB, WorkOrderView};
use serde_json::{Value, json};

use self::end::{EXIT_KEY_HELD, EXIT_NO_ROOM, EXIT_REFUSED, OwnStop};
use self::follow::{Follow, Followed};
use self::transport::{CallError, CurlVerbCall, VerbCall};
use crate::cli::{JobsCommand, JobsFollowArgs, JobsRunArgs};

const NO_STOP: u8 = 0;
const STOP_TERMINATE: u8 = 1;
const STOP_INTERRUPT: u8 = 2;

/// Runs one `oneiron jobs` subcommand and exits with its code.
///
/// # Errors
///
/// A signal listener that does not install, or the blocking pool refusing the work.
pub async fn jobs(command: JobsCommand) -> anyhow::Result<()> {
    let stop = Arc::new(AtomicU8::new(NO_STOP));
    let listener = listen_for_stop(Arc::clone(&stop))?;
    let code = crate::logging::off_runtime("jobs", move || {
        let taken = move || match stop.load(Ordering::SeqCst) {
            STOP_TERMINATE => Some(OwnStop::Terminate),
            STOP_INTERRUPT => Some(OwnStop::Interrupt),
            _ => None,
        };
        let mut pause = std::thread::sleep;
        let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
        match command {
            JobsCommand::Run(args) => run(&args, &taken, &mut pause, &mut out, &mut err),
            JobsCommand::Follow(args) => follow_only(&args, &taken, &mut pause, &mut out, &mut err),
        }
    })
    .await?;
    listener.abort();
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// TERM and INT set `stop`; HUP is taken and changes nothing, so a closed terminal neither
/// cancels the order nor ends the follow.
#[cfg(unix)]
fn listen_for_stop(stop: Arc<AtomicU8>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(()) = terminate.recv() => stop.store(STOP_TERMINATE, Ordering::SeqCst),
                Some(()) = interrupt.recv() => stop.store(STOP_INTERRUPT, Ordering::SeqCst),
                Some(()) = hangup.recv() => {}
                else => break,
            }
        }
    }))
}

/// Ctrl-C sets `stop` where there are no Unix signals.
#[cfg(not(unix))]
fn listen_for_stop(stop: Arc<AtomicU8>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            stop.store(STOP_INTERRUPT, Ordering::SeqCst);
        }
    }))
}

/// `oneiron jobs run` on the host's curl and git.
fn run(
    args: &JobsRunArgs,
    stop: &dyn Fn() -> Option<OwnStop>,
    pause: &mut dyn FnMut(Duration),
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut call = match CurlVerbCall::new(&args.connect) {
        Ok(call) => call,
        Err(error) => return refused(err, &error.to_string()),
    };
    let repo = args.repo.clone().unwrap_or_else(|| PathBuf::from("."));
    let contract_at = args.contract_commit.as_deref().unwrap_or(&args.commit);
    let contract_sha256 = match request::contract_sha256(&repo, contract_at, &args.contract) {
        Ok(digest) => digest,
        Err(error) => return refused(err, &error.to_string()),
    };
    let mut booker = Booker {
        call: &mut call,
        out,
        err,
        stop,
        pause,
    };
    booker.run(args, &contract_sha256, &repo)
}

/// `oneiron jobs follow` on the host's curl.
fn follow_only(
    args: &JobsFollowArgs,
    stop: &dyn Fn() -> Option<OwnStop>,
    pause: &mut dyn FnMut(Duration),
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let Ok(order) = EntityId::from_hex(args.order.trim()) else {
        return refused(err, "an order is named by its id, 32 hex");
    };
    let mut call = match CurlVerbCall::new(&args.connect) {
        Ok(call) => call,
        Err(error) => return refused(err, &error.to_string()),
    };
    let mut booker = Booker {
        call: &mut call,
        out,
        err,
        stop,
        pause,
    };
    let names = booker.machine_names();
    booker.follow(order, &names)
}

/// One booking's calls and streams.
pub(super) struct Booker<'a> {
    pub(super) call: &'a mut dyn VerbCall,
    pub(super) out: &'a mut dyn Write,
    pub(super) err: &'a mut dyn Write,
    pub(super) stop: &'a dyn Fn() -> Option<OwnStop>,
    pub(super) pause: &'a mut dyn FnMut(Duration),
}

impl Booker<'_> {
    /// Pins and orders what `args` asks for, its contract hashing to `contract_sha256` in
    /// `repo`, then follows the order unless `--detach`.
    pub(super) fn run(&mut self, args: &JobsRunArgs, contract_sha256: &str, repo: &Path) -> i32 {
        let reply =
            match self.answer::<MachineExecutionReply>(MACHINES_EXECUTION_GET_VERB, &json!({})) {
                Ok(reply) => reply,
                Err(code) => return code,
            };
        let placement = match request::placement(&reply, &args.hosts, &args.template) {
            Ok(placement) => placement,
            Err(why) => return refused(self.err, &why),
        };
        let pin = match request::pin_request(args, &placement.template_digest, contract_sha256)
            .and_then(|pin| Ok(serde_json::to_value(pin)?))
        {
            Ok(pin) => pin,
            Err(error) => return refused(self.err, &error.to_string()),
        };
        let pinned = match self.answer::<WorkloadChange>(WorkloadVerb::Pin.name(), &pin) {
            Ok(pinned) => pinned,
            Err(code) => return code,
        };
        self.say(&format!(
            "[oneiron] workload {} pinned from {} ({:?})",
            pinned.workload.digest,
            repo.display(),
            pinned.workload.standing
        ));
        let order = match request::order_request(args, &pinned.workload.digest, &placement.machines)
            .and_then(|order| Ok(serde_json::to_value(order)?))
        {
            Ok(order) => order,
            Err(error) => return refused(self.err, &error.to_string()),
        };
        let view = match self.call.call(ORDER_VERB, &order) {
            Ok(value) => match serde_json::from_value::<WorkOrderView>(value) {
                Ok(view) => view,
                Err(error) => {
                    return refused(
                        self.err,
                        &format!("the order's answer did not read: {error}"),
                    );
                }
            },
            Err(error) => {
                let code = order_refusal_code(&error, args.key.is_some(), args.no_wait);
                self.say(error.text());
                return code;
            }
        };
        let id = view.order.id.to_hex();
        if view.replayed {
            self.say(&format!(
                "[oneiron] order {id}: the key {:?} made it before",
                args.key
            ));
        }
        if args.detach {
            let _ = writeln!(self.out, "order {id}");
            let _ = self.out.flush();
            return 0;
        }
        self.follow(view.order.id, &placement.names)
    }

    /// Follows `order` to its end and writes its end line.
    pub(super) fn follow(&mut self, order: EntityId, names: &BTreeMap<EntityId, String>) -> i32 {
        let Followed { code, line } = Follow {
            call: &mut *self.call,
            out: &mut *self.out,
            err: &mut *self.err,
            stop: self.stop,
            pause: &mut *self.pause,
            names,
        }
        .order(order);
        self.say(&line);
        code
    }

    /// The machines' shown names, for the end line; none when the read is refused.
    fn machine_names(&mut self) -> BTreeMap<EntityId, String> {
        self.call
            .call(MACHINES_EXECUTION_GET_VERB, &json!({}))
            .ok()
            .and_then(|value| serde_json::from_value::<MachineExecutionReply>(value).ok())
            .map(|reply| request::machine_names(&reply))
            .unwrap_or_default()
    }

    /// `verb`'s answer read as `T`, or the refusal's exit code with its body written out.
    fn answer<T: serde::de::DeserializeOwned>(
        &mut self,
        verb: &str,
        input: &Value,
    ) -> Result<T, i32> {
        match self.call.call(verb, input) {
            Ok(value) => serde_json::from_value(value).map_err(|error| {
                refused(self.err, &format!("{verb}'s answer did not read: {error}"))
            }),
            Err(error) => {
                self.say(error.text());
                Err(EXIT_REFUSED)
            }
        }
    }

    fn say(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
        let _ = self.err.flush();
    }
}

/// The exit of a refused order: the key held by another order, no room under `--no-wait`, or
/// refused.
fn order_refusal_code(error: &CallError, keyed: bool, no_wait: bool) -> i32 {
    let invalid_state = error.code().as_deref() == Some(oneiron::memory::MEMORY_CODE_INVALID_STATE);
    let blockers = error.reason_codes();
    // The order door's only refusal of the booker's own input with no reason code beside its
    // state is a key that made another order (`after` and `group` are never sent).
    if keyed && invalid_state && blockers.is_empty() {
        return EXIT_KEY_HELD;
    }
    if no_wait && !blockers.is_empty() {
        return EXIT_NO_ROOM;
    }
    EXIT_REFUSED
}

/// Writes `why` and answers the refusal's exit code.
fn refused(err: &mut dyn Write, why: &str) -> i32 {
    let _ = writeln!(err, "[oneiron] nothing was ordered: {why}");
    let _ = err.flush();
    EXIT_REFUSED
}
