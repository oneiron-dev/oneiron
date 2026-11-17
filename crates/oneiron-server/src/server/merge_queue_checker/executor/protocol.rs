//! The framed protocol both queue checker executors drive the trusted
//! helper over (FIX 6868): the header and the pinned tree in, then each
//! command's exit status, output and declared outputs, the input digests
//! and the terminal frame out. No terminal frame, an ended executor or the
//! host's stop holds the check; none is a failed test.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use oneiron::merge_queue::{
    QueueCheckExecution, QueueCheckHold, QueueCheckHoldReason, QueueCheckInputs,
    QueueCheckInvocation, QueueCheckRun, QueueCommandReceipt,
};
use serde::{Deserialize, Serialize};

use super::super::tree::{
    FRAME_DONE, FRAME_HEADER, FRAME_INPUTS, FRAME_OUTPUT, FRAME_RESULT, FRAME_STDERR, FRAME_STDOUT,
    Sent, read_frame, send_tree, write_frame,
};

/// Where the helper materializes its private scratch copy, in the guest
/// and for the host child alike; the plan's environment names paths under
/// it.
const CHECK_SCRATCH: &str = "/tmp/queue-check";

/// How often a waiting executor looks at the host's stop and its guest's
/// liveness. A poll, not a deadline: nothing ends a check for taking long.
const STOP_POLL: Duration = Duration::from_millis(500);

fn interrupted(detail: &str) -> QueueCheckExecution {
    QueueCheckExecution::Held(QueueCheckHold::new(
        QueueCheckHoldReason::Interrupted,
        detail,
    ))
}

/// The header the helper reads first.
#[derive(Serialize)]
struct Header<'h> {
    version: u8,
    scratch: &'h str,
    /// The pinned commit the guest's object store names as HEAD (FIX 7228).
    commit: &'h str,
    commands: Vec<HeaderCommand<'h>>,
    contract_outputs: Vec<HeaderCommand<'h>>,
}

#[derive(Serialize)]
struct HeaderCommand<'h> {
    name: Option<&'h str>,
    argv: &'h [String],
    env: &'h BTreeMap<String, String>,
    /// The output files the helper reads back after it runs (FIX 7235).
    declared_outputs: &'h [String],
}

/// One command result the helper reports.
#[derive(Deserialize)]
struct ResultFrame {
    kind: String,
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    name: Option<String>,
    status: Option<i32>,
    signal: Option<i32>,
    #[serde(default)]
    missing: Option<String>,
}

#[derive(Deserialize)]
struct InputsFrame {
    before: String,
    after: String,
}

/// Drives the helper over `reader` and `writer`: header and tree in, then
/// its frames until the terminal one, the host's stop, or its end. The
/// helper's input stays open until its terminal frame is read: the caller
/// closes `writer` after it reads what the session needs.
pub(super) fn drive(
    mut reader: Box<dyn Read + Send>,
    writer: &mut dyn Write,
    alive: &mut dyn FnMut() -> bool,
    invocation: &QueueCheckInvocation<'_>,
    inputs: &QueueCheckInputs,
    stop: &dyn Fn() -> bool,
) -> oneiron::Result<QueueCheckExecution> {
    let commit = invocation.target.commit();
    let header = Header {
        version: 1,
        scratch: CHECK_SCRATCH,
        commit,
        commands: inputs
            .commands
            .iter()
            .map(|command| HeaderCommand {
                name: None,
                argv: &command.argv,
                env: &command.env_allowlist,
                declared_outputs: &command.declared_outputs,
            })
            .collect(),
        contract_outputs: inputs
            .contract_outputs
            .iter()
            .map(|(name, command)| HeaderCommand {
                name: Some(name.as_str()),
                argv: &command.argv,
                env: &command.env_allowlist,
                declared_outputs: &command.declared_outputs,
            })
            .collect(),
    };
    let header = serde_json::to_vec(&header).map_err(io::Error::other)?;
    if write_frame(writer, FRAME_HEADER, &header).is_err() {
        return Ok(interrupted("the check helper closed before its header"));
    }
    let sent = match send_tree(writer, invocation.tree, commit)? {
        Sent::Tree(digest) => digest,
        Sent::Closed(error) => {
            return Ok(interrupted(&format!(
                "the check helper closed before the tree was in: {error}"
            )));
        }
    };
    let (frames, received) = mpsc::channel();
    crate::engine_thread("merge-check-reader".into())
        .spawn(move || {
            loop {
                match read_frame(reader.as_mut()) {
                    Ok(Some(frame)) => {
                        if frames.send(frame).is_err() {
                            return;
                        }
                    }
                    Ok(None) | Err(_) => return,
                }
            }
        })
        .expect("failed to spawn thread");
    let mut collected = Collected::default();
    let mut ended = false;
    loop {
        match received.recv_timeout(STOP_POLL) {
            Ok((kind, payload)) => {
                if kind == FRAME_DONE {
                    break;
                }
                if let Err(detail) = collected.take(kind, payload) {
                    return Ok(interrupted(&detail));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop() {
                    return Ok(interrupted("the host stopped during the check"));
                }
                // An ended executor's frames already read drain first; one
                // more quiet poll after its end holds the check.
                if ended {
                    return Ok(interrupted(
                        "the check executor ended before its terminal frame",
                    ));
                }
                ended = !alive();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(interrupted(
                    "the check helper ended before its terminal frame",
                ));
            }
        }
    }
    collected.finish(&sent, inputs)
}

/// The frames read so far.
#[derive(Default)]
struct Collected {
    pending: Option<(ResultFrame, Option<Vec<u8>>)>,
    commands: Vec<QueueCommandReceipt>,
    contract_outputs: BTreeMap<String, QueueCommandReceipt>,
    /// The contract command reported last, whose declared outputs follow;
    /// `None` after a phase command.
    last_contract: Option<String>,
    missing: Option<String>,
    inputs: Option<InputsFrame>,
}

impl Collected {
    fn take(&mut self, kind: u8, payload: Vec<u8>) -> Result<(), String> {
        match kind {
            FRAME_RESULT => {
                let result: ResultFrame = serde_json::from_slice(&payload)
                    .map_err(|_| "the check helper sent an unreadable result".to_owned())?;
                self.pending = Some((result, None));
            }
            FRAME_STDOUT => {
                let Some((_, stdout)) = self.pending.as_mut() else {
                    return Err("the check helper sent output out of order".to_owned());
                };
                if stdout.is_some() {
                    return Err("the check helper sent output out of order".to_owned());
                }
                *stdout = Some(payload);
            }
            FRAME_STDERR => {
                let Some((result, Some(stdout))) = self.pending.take() else {
                    return Err("the check helper sent output out of order".to_owned());
                };
                self.push(result, stdout, payload)?;
            }
            FRAME_OUTPUT => self.output(&payload)?,
            FRAME_INPUTS => {
                self.inputs = Some(
                    serde_json::from_slice(&payload)
                        .map_err(|_| "the check helper sent unreadable digests".to_owned())?,
                );
            }
            _ => return Err("the check helper sent an unknown frame".to_owned()),
        }
        Ok(())
    }

    /// One declared output file of the command reported last (FIX 7235).
    fn output(&mut self, payload: &[u8]) -> Result<(), String> {
        let malformed = || "the check helper sent an unreadable output".to_owned();
        let (length, rest) = payload.split_at_checked(4).ok_or_else(malformed)?;
        let length = u32::from_be_bytes(length.try_into().map_err(|_| malformed())?) as usize;
        let (path, bytes) = rest.split_at_checked(length).ok_or_else(malformed)?;
        let path = String::from_utf8(path.to_vec()).map_err(|_| malformed())?;
        let receipt = match &self.last_contract {
            Some(name) => self.contract_outputs.get_mut(name),
            None => self.commands.last_mut(),
        };
        let Some(receipt) = receipt.filter(|_| self.pending.is_none()) else {
            return Err("the check helper sent an output out of order".to_owned());
        };
        receipt.declared_outputs.insert(path, bytes.to_vec());
        Ok(())
    }

    fn push(
        &mut self,
        result: ResultFrame,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<(), String> {
        if let Some(missing) = &result.missing {
            self.missing.get_or_insert_with(|| missing.clone());
        }
        let receipt = |argv: Vec<String>| QueueCommandReceipt {
            argv,
            status: result.status,
            signal: result.signal,
            stdout,
            stderr,
            declared_outputs: BTreeMap::new(),
        };
        match (result.kind.as_str(), result.index, &result.name) {
            ("phase", Some(index), _) if index == self.commands.len() => {
                self.commands.push(receipt(Vec::new()));
                self.last_contract = None;
            }
            ("contract", _, Some(name)) => {
                self.contract_outputs
                    .insert(name.clone(), receipt(Vec::new()));
                self.last_contract = Some(name.clone());
            }
            _ => return Err("the check helper sent a result out of order".to_owned()),
        }
        Ok(())
    }

    fn finish(self, sent: &str, inputs: &QueueCheckInputs) -> oneiron::Result<QueueCheckExecution> {
        let Some(digests) = self.inputs else {
            return Ok(interrupted("the check helper sent no input digests"));
        };
        if digests.before != sent {
            return Ok(QueueCheckExecution::Held(QueueCheckHold::new(
                QueueCheckHoldReason::UnstableInputs,
                "the executor did not receive the pinned tree",
            )));
        }
        if let Some(missing) = self.missing {
            return Ok(QueueCheckExecution::Held(QueueCheckHold::new(
                QueueCheckHoldReason::MissingOfflineInput,
                missing,
            )));
        }
        let mut commands = self.commands;
        for (receipt, command) in commands.iter_mut().zip(&inputs.commands) {
            receipt.argv.clone_from(&command.argv);
        }
        let mut contract_outputs = self.contract_outputs;
        for (name, receipt) in &mut contract_outputs {
            if let Some(command) = inputs.contract_outputs.get(name) {
                receipt.argv.clone_from(&command.argv);
            }
        }
        Ok(QueueCheckExecution::Completed(QueueCheckRun {
            commands,
            contract_outputs,
            session: None,
            input_before: digests.before,
            input_after: digests.after,
        }))
    }
}
