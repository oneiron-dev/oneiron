//! Canonical typed Component Model execution with four read-only imports.

use crate::{
    Error, Result,
    filesystem::{Workspace, validate_files},
    protocol::{
        Input, MAX_COMPONENT, MAX_FILE, MAX_FILES, MAX_REQUESTS, MAX_SOURCE, MAX_TOTAL, Session,
        Snapshot,
    },
};
use serde::Deserialize;
use std::{
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
}

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

pub(crate) fn execute<T: Read + Write + 'static>(
    session: Session<T>,
    input: Input,
    workspace: Workspace,
) -> (Session<T>, Result<()>) {
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
    // first-party readiness probe. Match the bounded code-mode runtime's
    // 100-million ceiling so the foreign interpreter can actually start.
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
        .map_err(|_| Error::Runtime("component trapped"))?;
    if store.data().poisoned {
        return Err(Error::Protocol("credential transport failed"));
    }
    let output = output.map_err(|_| Error::Runtime("component returned error"))?;
    let proposals = proposals(output)?;
    store.data().workspace.apply(&proposals)?;
    let changed = store.data().workspace.snapshot()?;
    if input.files.keys().any(|path| !changed.contains_key(path)) {
        return Err(Error::Filesystem("deletion is unsupported"));
    }
    for (path, bytes) in changed {
        if input.files.get(&path) != Some(&bytes) {
            store.data_mut().session.write(&path, &bytes)?;
        }
    }
    Ok(())
}

fn proposals(output: abi::StepResult) -> Result<Snapshot> {
    if output.result_json.len() > MAX_FILE || output.proposals.len() > MAX_FILES {
        return Err(Error::Runtime("step result bounds"));
    }
    serde_json::from_str::<serde_json::Value>(&output.result_json)
        .map_err(|_| Error::Runtime("result-json is invalid JSON"))?;
    let mut proposals = Snapshot::new();
    for proposal in output.proposals {
        match proposal {
            abi::ProposalDelta::FileWrite(file) => {
                if proposals.insert(file.path, file.bytes).is_some() {
                    return Err(Error::Runtime("duplicate file proposal"));
                }
            }
            abi::ProposalDelta::ClaimCandidate(_) => {
                return Err(Error::UnsupportedClaimCandidate);
            }
        }
    }
    validate_files(&proposals)?;
    Ok(proposals)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_claim_is_a_failure_not_a_dropped_proposal() {
        let output = abi::StepResult {
            result_json: "null".into(),
            proposals: vec![abi::ProposalDelta::ClaimCandidate(abi::ClaimInput {
                id: "id".into(),
                predicate: "p".into(),
                subject: "null".into(),
                value: "null".into(),
                confidence: None,
                occurred: None,
                learned_at: None,
            })],
        };
        assert!(matches!(
            proposals(output),
            Err(Error::UnsupportedClaimCandidate)
        ));
    }
}
