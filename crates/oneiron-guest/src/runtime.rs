//! Canonical typed Component Model execution with six non-write imports and
//! the three that stream a proposed file to the host.

use crate::{
    Error, Result,
    filesystem::{Workspace, validate_files},
    protocol::{
        Input, MAX_CHUNK, MAX_COMPONENT, MAX_FILE, MAX_REQUESTS, MAX_SOURCE, MAX_TOTAL, Session,
        Snapshot,
    },
};
use oneiron_sandbox_contract::{ShapeError, WorkspacePath, WorkspaceShape};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};
use wasmtime::{
    Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder,
    component::{Component, Linker},
};

mod abi {
    wasmtime::component::bindgen!({ path: "../oneiron/wit", world: "guest" });
}

struct State<T> {
    session: Session<T>,
    workspace: Workspace,
    limits: StoreLimits,
    calls: usize,
    read_bytes: usize,
    poisoned: bool,
    proposed: Proposed,
}

/// The step's proposals so far, under the host's rules: one effect per path,
/// and the seeded tree with every accepted proposal applied.
struct Proposed {
    shape: WorkspaceShape,
    occupied: BTreeSet<String>,
    open: Option<OpenFile>,
    opened: u64,
}

/// The one proposed file streaming to the host. Its frames go out as they
/// come; the guest never holds the file.
struct OpenFile {
    id: u64,
    path: WorkspacePath,
    bytes: usize,
}

type Reply = std::result::Result<u64, String>;

impl<T> State<T> {
    fn count_call(&mut self) -> wasmtime::Result<()> {
        if self.poisoned || self.calls >= MAX_REQUESTS - 1 {
            return Err(wasmtime::Error::msg("guest host-call budget exhausted"));
        }
        self.calls += 1;
        Ok(())
    }

    fn count_bytes(&mut self, bytes: usize) -> wasmtime::Result<()> {
        if bytes > MAX_FILE || bytes > MAX_TOTAL - self.read_bytes {
            return Err(wasmtime::Error::msg("guest read-byte budget exhausted"));
        }
        self.read_bytes += bytes;
        Ok(())
    }
}

impl<T: Read + Write> State<T> {
    fn open_file(&mut self, path: String) -> wasmtime::Result<Reply> {
        self.count_call()?;
        if self.proposed.open.is_some() {
            return Ok(Err("a file proposal is already open".into()));
        }
        let Ok(checked) = WorkspacePath::parse(&path) else {
            return Ok(Err("file proposal path refused".into()));
        };
        if !self.proposed.occupied.insert(path.clone()) {
            return Ok(Err("duplicate file proposal".into()));
        }
        if let Err(error) = self.proposed.shape.replace_file(&checked, 0) {
            self.proposed.occupied.remove(&path);
            return Ok(Err(error.reason().into()));
        }
        if self.session.open_write(&path).is_err() {
            self.poisoned = true;
            return Ok(Err("file proposal transport failed".into()));
        }
        self.proposed.opened += 1;
        self.proposed.open = Some(OpenFile {
            id: self.proposed.opened,
            path: checked,
            bytes: 0,
        });
        Ok(Ok(self.proposed.opened))
    }

    fn file_chunk(&mut self, id: u64, frame: &[u8]) -> wasmtime::Result<Reply> {
        if self.poisoned {
            return Err(wasmtime::Error::msg("guest host transport failed"));
        }
        let Some(open) = self.proposed.open.as_mut().filter(|open| open.id == id) else {
            return Ok(Err("no such open file proposal".into()));
        };
        if frame.len() > MAX_CHUNK {
            return Ok(Err("file proposal frame exceeds one message".into()));
        }
        open.bytes = open
            .bytes
            .checked_add(frame.len())
            .ok_or_else(|| wasmtime::Error::msg("file proposal length overflow"))?;
        if self.session.write_chunk(frame).is_err() {
            self.poisoned = true;
            return Ok(Err("file proposal transport failed".into()));
        }
        Ok(Ok(frame.len() as u64))
    }

    fn close_file(&mut self, id: u64) -> wasmtime::Result<Reply> {
        self.count_call()?;
        let Some(open) = self.proposed.open.take_if(|open| open.id == id) else {
            return Ok(Err("no such open file proposal".into()));
        };
        if let Err(error) = self.proposed.shape.replace_file(&open.path, open.bytes) {
            return Ok(Err(error.reason().into()));
        }
        if self.session.close_write().is_err() {
            self.poisoned = true;
            return Ok(Err("file proposal transport failed".into()));
        }
        Ok(Ok(open.bytes as u64))
    }
}

pub(crate) fn execute<T: Read + Write + 'static>(
    session: Session<T>,
    input: Input,
    workspace: Workspace,
) -> (Session<T>, Result<()>) {
    let shape = match validate_files(&input.files) {
        Ok(shape) => shape,
        Err(error) => return (session, Err(error)),
    };
    // Compilation happens only after the PID-1 path has forked and dropped uid.
    let compiled = compile(&input.component);
    let (engine, component) = match compiled {
        Ok(value) => value,
        Err(error) => return (session, Err(error)),
    };
    let limits = StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024)
        .memories(1)
        .tables(8)
        .instances(32)
        .table_elements(10_000)
        .build();
    let mut store = Store::new(
        &engine,
        State {
            session,
            workspace,
            limits,
            calls: 0,
            read_bytes: 0,
            poisoned: false,
            proposed: Proposed {
                shape,
                occupied: BTreeSet::new(),
                open: None,
                opened: 0,
            },
        },
    );
    store.limiter(|state| &mut state.limits);
    let result = run(&engine, &component, &mut store, &input);
    (store.into_data().session, result)
}

fn compile(bytes: &[u8]) -> Result<(Engine, Component)> {
    if bytes.is_empty() || bytes.len() > MAX_COMPONENT {
        return Err(Error::Runtime("component size"));
    }
    let mut config = Config::new();
    config.wasm_component_model(true).consume_fuel(true);
    let engine = Engine::new(&config).map_err(|_| Error::Runtime("engine setup"))?;
    // Never deserialize a native compilation artifact from the host channel.
    let component =
        Component::new(&engine, bytes).map_err(|_| Error::Runtime("component compile"))?;
    Ok((engine, component))
}

fn run<T: Read + Write + 'static>(
    engine: &Engine,
    component: &Component,
    store: &mut Store<State<T>>,
    input: &Input,
) -> Result<()> {
    if input.source.len() > MAX_SOURCE || !(1..=4096).contains(&input.pids) {
        return Err(Error::Runtime("source size"));
    }
    // The pinned QuickJS component consumes over 12 million fuel just for its
    // first-party readiness probe; a 100-million ceiling lets the foreign
    // interpreter start. This lane keeps no streamed result, so it needs none
    // of the code-mode runtime's larger allowance for one.
    store
        .set_fuel(100_000_000)
        .map_err(|_| Error::Runtime("fuel setup"))?;
    let mut linker = Linker::new(engine);
    link_imports(&mut linker).map_err(|_| Error::Runtime("read import setup"))?;
    // Do not call the generated all-world add_to_linker: that would also link
    // first-party imports. Missing imports fail even when code never calls them.
    let instance = linker
        .instantiate(&mut *store, component)
        .map_err(|_| Error::Runtime("component imports or instantiation"))?;
    let run = instance
        .get_typed_func::<(String,), (std::result::Result<abi::StepResult, String>,)>(
            &mut *store,
            "run-step",
        )
        .map_err(|_| Error::Runtime("typed run-step ABI"))?;
    // Wasmtime performs canonical post-return inside call; either trap refuses proposals.
    let (output,) = run
        .call(&mut *store, (input.source.clone(),))
        .map_err(|error| {
            if matches!(
                error.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::OutOfFuel)
            ) {
                Error::Runtime("component fuel exhausted")
            } else {
                Error::Runtime("component trapped")
            }
        })?;
    if store.data().poisoned {
        return Err(Error::Protocol("host transport failed"));
    }
    let output = output.map_err(|_| Error::Runtime("component returned error"))?;
    // Every proposed file is already with the host, frame by frame; one
    // left open is refused with the step.
    if store.data().proposed.open.is_some() {
        return Err(Error::Runtime("unclosed file proposal"));
    }
    let result_json = output.result_json.clone();
    let proposals = proposals(output, &input.files, &mut store.data_mut().proposed)?;
    for proposal in proposals {
        match proposal {
            GuestProposal::Delete(path) => store.data_mut().session.delete(&path)?,
            GuestProposal::Rename(from, to) => store.data_mut().session.rename(&from, &to)?,
        }
    }
    store.data_mut().session.result(&result_json)?;
    Ok(())
}

enum GuestProposal {
    Delete(String),
    Rename(String, String),
}

fn proposals(
    output: abi::StepResult,
    base: &Snapshot,
    proposed: &mut Proposed,
) -> Result<Vec<GuestProposal>> {
    if output.result_json.len() > MAX_FILE {
        return Err(Error::Runtime("step result bounds"));
    }
    serde_json::from_str::<serde_json::Value>(&output.result_json)
        .map_err(|_| Error::Runtime("result-json is invalid JSON"))?;
    let mut proposals = Vec::new();
    let Proposed {
        shape, occupied, ..
    } = proposed;
    let shape_error = |error: ShapeError| Error::Runtime(error.reason());
    for proposal in output.proposals {
        match proposal {
            abi::ProposalDelta::FileDelete(delete) => {
                let path = workspace_path(&delete.path)?;
                if !base.contains_key(&delete.path) || !occupied.insert(delete.path.clone()) {
                    return Err(Error::Runtime("invalid delete proposal"));
                }
                shape.remove_file(&path).map_err(shape_error)?;
                proposals.push(GuestProposal::Delete(delete.path));
            }
            abi::ProposalDelta::FileRename(rename) => {
                let origin = workspace_path(&rename.origin)?;
                let destination = workspace_path(&rename.destination)?;
                if rename.origin == rename.destination
                    || !base.contains_key(&rename.origin)
                    || !occupied.insert(rename.origin.clone())
                    || !occupied.insert(rename.destination.clone())
                {
                    return Err(Error::Runtime("invalid rename proposal"));
                }
                shape
                    .rename_file(&origin, &destination)
                    .map_err(shape_error)?;
                proposals.push(GuestProposal::Rename(rename.origin, rename.destination));
            }
            abi::ProposalDelta::ClaimCandidate(_) => {
                return Err(Error::UnsupportedClaimCandidate);
            }
        }
    }
    Ok(proposals)
}

fn workspace_path(path: &str) -> Result<WorkspacePath> {
    WorkspacePath::parse(path).map_err(|error| Error::Filesystem(error.reason()))
}

fn link_imports<T: Read + Write + 'static>(linker: &mut Linker<State<T>>) -> wasmtime::Result<()> {
    linker.root().func_wrap(
        "read-file",
        |mut context: StoreContextMut<'_, State<T>>, (path,): (String,)| {
            let state = context.data_mut();
            state.count_call()?;
            let result = match state.workspace.read(&path) {
                Ok(bytes) => {
                    state.count_bytes(bytes.len())?;
                    Ok(bytes)
                }
                Err(_) => Err(String::from("workspace read refused")),
            };
            Ok((result,))
        },
    )?;
    linker.root().func_wrap(
        "credential-call",
        |mut context: StoreContextMut<'_, State<T>>, (input,): (abi::CredentialInput,)| {
            let state = context.data_mut();
            state.count_call()?;
            Ok((credential(state, input),))
        },
    )?;
    linker.root().func_wrap(
        "clock-now-unix-ms",
        |mut context: StoreContextMut<'_, State<T>>, (): ()| {
            context.data_mut().count_call()?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| wasmtime::Error::msg("clock unavailable"))?;
            let millis = u64::try_from(now.as_millis())
                .map_err(|_| wasmtime::Error::msg("clock overflow"))?;
            Ok((millis,))
        },
    )?;
    // A proposed file, streamed to the host as the component writes it.
    linker.root().func_wrap(
        "proposal-open",
        |mut context: StoreContextMut<'_, State<T>>, (path,): (String,)| {
            Ok((context.data_mut().open_file(path)?,))
        },
    )?;
    linker.root().func_wrap(
        "proposal-chunk",
        |mut context: StoreContextMut<'_, State<T>>, (id, frame): (u64, Vec<u8>)| {
            Ok((context.data_mut().file_chunk(id, &frame)?,))
        },
    )?;
    linker.root().func_wrap(
        "proposal-close",
        |mut context: StoreContextMut<'_, State<T>>, (id,): (u64,)| {
            Ok((context.data_mut().close_file(id)?,))
        },
    )?;
    // The step's streamed result. This lane keeps no step result, as it
    // keeps none of the returned one: frames are taken and dropped.
    linker.root().func_wrap(
        "output-text",
        |_: StoreContextMut<'_, State<T>>, (_, _, frame): (String, bool, String)| {
            Ok((Ok::<u64, String>(frame.len() as u64),))
        },
    )?;
    linker.root().func_wrap(
        "output-bytes",
        |_: StoreContextMut<'_, State<T>>, (_, frame): (String, Vec<u8>)| {
            Ok((Ok::<u64, String>(frame.len() as u64),))
        },
    )?;
    linker.root().func_wrap(
        "random-bytes",
        |mut context: StoreContextMut<'_, State<T>>, (length,): (u32,)| {
            let state = context.data_mut();
            state.count_call()?;
            state.count_bytes(length as usize)?;
            let mut bytes = vec![0; length as usize];
            let result = std::fs::File::open("/dev/urandom")
                .and_then(|mut file| file.read_exact(&mut bytes));
            Ok((result
                .map(|()| bytes)
                .map_err(|_| String::from("random unavailable")),))
        },
    )?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    scheme: String,
    host: String,
}

fn credential<T: Read + Write>(
    state: &mut State<T>,
    input: abi::CredentialInput,
) -> std::result::Result<String, String> {
    let refused = || String::from("credential call refused");
    if !token(&input.credential_handle, 256)
        || !token(&input.operation, 128)
        || input.args.len() > 4096
    {
        return Err(refused());
    }
    let destination: Destination = serde_json::from_str(&input.args).map_err(|_| refused())?;
    if destination.scheme != "https" || !dns_name(&destination.host) {
        return Err(refused());
    }
    // The entire forwarded shape is four allowlisted strings. No arbitrary
    // args, request body, URL, authorization header, or secret bytes cross here.
    // The host, not the component, owns destination and operation allowlists.
    match state.session.credential(
        &input.credential_handle,
        &input.operation,
        &destination.scheme,
        &destination.host,
    ) {
        Ok(true) => Ok(String::from("{\"accepted\":true}")),
        Ok(false) => Err(refused()),
        Err(_) => {
            state.poisoned = true;
            Err(refused())
        }
    }
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
