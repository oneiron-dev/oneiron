//! Canonical typed WIT imports over the bounded engine-host channel.

use super::{HostEvent, State, bindings::*, failure, wire};
use crate::Result;
use crate::code_sandbox::SandboxBoundaryContract;
use serde_json::{Value, json};
use std::sync::mpsc;
use wasmtime::StoreContextMut;
use wasmtime::component::Linker;

type Reply<T> = std::result::Result<T, String>;
const IMPORTS: &[(&str, &str)] = include!("../../../wit/generated/imports.rs");

impl State {
    fn begin_call(&mut self) -> wasmtime::Result<()> {
        if self.remaining_calls == 0 {
            return Err(wasmtime::Error::msg("host call budget exceeded"));
        }
        self.remaining_calls -= 1;
        Ok(())
    }

    fn call(&mut self, name: &'static str, input: Value) -> Reply<Value> {
        let input = input.to_string();
        if input.len() > self.message_bytes {
            return Err("host call budget exceeded".into());
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.events
            .send(HostEvent::Call { name, input, reply })
            .map_err(|_| "host bridge stopped")?;
        let output = response
            .recv()
            .map_err(|_| "host bridge stopped")?
            .map_err(|_| "host call refused")?;
        if output.len() > self.message_bytes {
            return Err("host response budget exceeded".into());
        }
        let value: Value = serde_json::from_str(&output).map_err(|_| "invalid host response")?;
        if value.get("denied").is_some() || value.get("failed").is_some() {
            return Err(output);
        }
        Ok(value)
    }
}

fn field<T: serde::de::DeserializeOwned>(value: &Value, name: &str) -> Reply<T> {
    serde_json::from_value(
        value
            .get(name)
            .cloned()
            .ok_or("missing host response field")?,
    )
    .map_err(|_| "invalid host response field".into())
}

fn claim(input: ClaimInput, limit: usize) -> Reply<Value> {
    let size = [&input.id, &input.predicate, &input.subject, &input.value]
        .into_iter()
        .try_fold(0usize, |total, value| total.checked_add(value.len()));
    if size.is_none_or(|size| size > limit) {
        return Err("claim arguments exceed message budget".into());
    }
    if input.confidence.is_some_and(|v| !v.is_finite()) {
        return Err("non-finite claim confidence".into());
    }
    // The SDK JSON-encodes a subject. The engine's current SelfCall contract
    // accepts an entity hex string, not caller-selected authority metadata.
    let subject: String = serde_json::from_str(&input.subject)
        .map_err(|_| "claim subject must be a JSON entity hex string")?;
    let value: Value =
        serde_json::from_str(&input.value).map_err(|_| "invalid claim value JSON")?;
    Ok(
        json!({"id":input.id,"predicate":input.predicate,"subject":subject,
        "value":value,"confidence":input.confidence,
        "occurred":input.occurred.map(|v| json!({"start":v.start,"end":v.end})),
        "learnedAt":input.learned_at}),
    )
}

pub(super) fn link_imports(
    linker: &mut Linker<State>,
    contract: SandboxBoundaryContract,
) -> Result<()> {
    let imports: Vec<_> = IMPORTS
        .iter()
        .copied()
        .filter(|(_, name)| {
            contract
                .linked_imports()
                .iter()
                .any(|item| item.name() == *name)
        })
        .collect();
    if imports.len() != contract.linked_imports().len()
        || contract.linked_imports().iter().any(|item| {
            !imports.iter().any(|(_, name)| *name == item.name())
                || (contract.tier().requires_zero_write_imports() && item.class().is_write())
        })
    {
        return Err(failure("canonical WIT capability inventory mismatch"));
    }
    let mut root = linker.root();
    for (wit, public) in imports {
        let result = match public {
            "sandbox.fs.read_file" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (path,): (String,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<Vec<u8>> = cx.data_mut().call("sandbox.fs.read_file", json!({"path":path}))
                        .and_then(|value| field(&value,"bytes"));
                    Ok((reply,))
                }),
            "sandbox.credential.call" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (CredentialInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<String> = (|| {
                        if input.args.len() > cx.data().message_bytes {
                            return Err("credential arguments exceed message budget".into());
                        }
                        let args: Value = serde_json::from_str(&input.args).map_err(|_| "invalid credential arguments")?;
                        cx.data_mut().call("sandbox.credential.call", json!({"operation":input.operation,
                            "credentialHandle":input.credential_handle,"args":args})).map(|value| value.to_string())
                    })();
                    Ok((reply,))
                }),
            "oneiron.clock.now_unix_ms" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (): ()| {
                    cx.data_mut().begin_call()?;
                    let value = cx.data_mut().call("oneiron.clock.now_unix_ms", json!({}))
                        .and_then(|value| field::<u64>(&value,"value"))
                        .map_err(wasmtime::Error::msg)?;
                    Ok((value,))
                }),
            "oneiron.random.bytes" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (length,): (u32,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<Vec<u8>> = cx.data_mut().call("oneiron.random.bytes", json!({"length":length}))
                        .and_then(|value| field(&value,"bytes"));
                    Ok((reply,))
                }),
            "self.memory.search" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (SearchInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<SearchOutput> = cx.data_mut().call("self.memory.search", json!({"query":input.query,"limit":input.limit}))
                        .and_then(|value| field::<Vec<Value>>(&value,"results"))
                        .map(|values| SearchOutput { results: values.into_iter().map(|value| value.to_string()).collect() });
                    Ok((reply,))
                }),
            "self.memory.put_claim" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (ClaimInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<ClaimOutput> = claim(input, cx.data().message_bytes)
                        .and_then(|input| cx.data_mut().call("self.memory.put_claim", input))
                        .and_then(|value| field(&value,"id")).map(|id| ClaimOutput { id });
                    Ok((reply,))
                }),
            "self.memory.supersede_claim" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (SupersedeInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<ClaimOutput> = cx.data_mut().call("self.memory.supersede_claim",
                        json!({"newId":input.new_id,"oldId":input.old_id,"now":input.now}))
                        .and_then(|value| field(&value,"id")).map(|id| ClaimOutput { id });
                    Ok((reply,))
                }),
            "self.memory.put_edge" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (EdgeInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<EdgeOutput> = (|| {
                        if input.weight.is_some_and(|v| !v.is_finite()) { return Err("non-finite edge weight".into()); }
                        wire::edge_kind(&input.kind).map_err(|_| "invalid edge kind")?;
                        let result = cx.data_mut().call("self.memory.put_edge",
                            json!({"src":input.src,"kind":input.kind,"tgt":input.tgt,"weight":input.weight}))?;
                        Ok(EdgeOutput { src: field(&result,"src")?, kind: input.kind, tgt: field(&result,"tgt")? })
                    })();
                    Ok((reply,))
                }),
            "self.report_blocked" => root.func_wrap(wit,
                |mut cx: StoreContextMut<'_, State>, (category, detail): (String, String)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<BlockedOutput> = cx.data_mut().call("self.report_blocked",
                        json!({"category":category,"detail":detail}))
                        .and_then(|value| field(&value,"receipt"))
                        .map(|receipt| BlockedOutput { receipt });
                    Ok((reply,))
                }),
            "self.ask_human" | "self.askHuman" => root.func_wrap(wit,
                move |mut cx: StoreContextMut<'_, State>, (input,): (PromptInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<WaitOutput> = cx.data_mut().call(public, json!({"prompt":input.prompt}))
                        .and_then(|value| field(&value,"waitId")).map(|wait_id| WaitOutput { wait_id });
                    Ok((reply,))
                }),
            "self.speak" | "self.think" | "self.express" => root.func_wrap(wit,
                move |mut cx: StoreContextMut<'_, State>, (input,): (TextInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<SpeechOutput> = cx.data_mut().call(public, json!({"text":input.text}))
                        .and_then(|value| Ok(SpeechOutput { order: field(&value,"order")?, is_visible:field(&value,"isVisible")? }));
                    Ok((reply,))
                }),
            _ => return Err(failure("canonical WIT import has no engine bridge")),
        };
        result.map_err(|_| failure("typed component import linking failed"))?;
    }
    Ok(())
}
