//! Canonical typed WIT imports over the bounded engine-host channel.

use super::{HostEvent, State, StreamTarget, bindings::*, failure};
use crate::Result;
use crate::code_sandbox::SandboxBoundaryContract;
use serde_json::{Value, json};
use std::sync::mpsc;
use wasmtime::StoreContextMut;
use wasmtime::component::Linker;

/// A typed import's answer. A refusal is a stable code the guest sees as the
/// thrown value, never prose; any wording for it belongs to the host or prompt
/// layer.
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
            return Err("host_call_over_budget".into());
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.events
            .send(HostEvent::Call { name, input, reply })
            .map_err(|_| "host_bridge_stopped")?;
        let output = response
            .recv()
            .map_err(|_| "host_bridge_stopped")?
            .map_err(|_| "host_call_refused")?;
        if output.len() > self.message_bytes {
            return Err("host_response_over_budget".into());
        }
        let value: Value = serde_json::from_str(&output).map_err(|_| "invalid_host_response")?;
        if value.get("denied").is_some() || value.get("failed").is_some() {
            return Err(output);
        }
        Ok(value)
    }

    /// Sends one frame of the step's streamed result to the host thread. A
    /// frame is not a host call: the step's fuel and deadline bound frames,
    /// never the call budget, so a result's size never ends its step. A
    /// refused frame traps the guest.
    fn output(&mut self, target: StreamTarget, frame: Vec<u8>) -> wasmtime::Result<Reply<u64>> {
        let (reply, response) = mpsc::sync_channel(1);
        self.events
            .send(HostEvent::Output {
                target,
                frame,
                reply,
            })
            .map_err(|_| wasmtime::Error::msg("host bridge stopped"))?;
        let len = response
            .recv()
            .map_err(|_| wasmtime::Error::msg("host bridge stopped"))?
            .map_err(|_| wasmtime::Error::msg("streamed output refused"))?;
        Ok(Ok(len))
    }
}

fn field<T: serde::de::DeserializeOwned>(value: &Value, name: &str) -> Reply<T> {
    serde_json::from_value(
        value
            .get(name)
            .cloned()
            .ok_or("missing_host_response_field")?,
    )
    .map_err(|_| "invalid_host_response_field".into())
}

/// A file reply's bytes: text arrives as a JSON string, other bytes as
/// base64. The guest receives the same bytes either way.
fn file_bytes(value: &Value) -> Reply<Vec<u8>> {
    match value.get("text") {
        Some(text) => text
            .as_str()
            .map(|text| text.as_bytes().to_vec())
            .ok_or_else(|| "invalid_host_response_field".into()),
        None => base64_bytes(value),
    }
}

/// Bytes a reply carries as base64, never as a number array.
fn base64_bytes(value: &Value) -> Reply<Vec<u8>> {
    use base64::Engine as _;
    let encoded = value
        .get("base64")
        .and_then(Value::as_str)
        .ok_or("missing_host_response_field")?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid_host_response_field".into())
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
            "sandbox.fs.read_file" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (path,): (String,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<Vec<u8>> = cx
                        .data_mut()
                        .call("sandbox.fs.read_file", json!({"path":path}))
                        .and_then(|value| file_bytes(&value));
                    Ok((reply,))
                },
            ),
            "sandbox.credential.call" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (CredentialInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<String> = (|| {
                        if input.args.len() > cx.data().message_bytes {
                            return Err("credential_arguments_over_budget".into());
                        }
                        let args: Value = serde_json::from_str(&input.args)
                            .map_err(|_| "invalid_credential_arguments")?;
                        cx.data_mut()
                            .call(
                                "sandbox.credential.call",
                                json!({"operation":input.operation,
                            "credentialHandle":input.credential_handle,"args":args}),
                            )
                            .map(|value| value.to_string())
                    })();
                    Ok((reply,))
                },
            ),
            // The verb table is the host's own generated catalog: no bridge row.
            "self.verbs.names" => {
                root.func_wrap(wit, |mut cx: StoreContextMut<'_, State>, (): ()| {
                    cx.data_mut().begin_call()?;
                    let names: Reply<Vec<String>> =
                        Ok(crate::task_verb::sdk::code_mode_verb_names()
                            .map(str::to_owned)
                            .collect());
                    Ok((names,))
                })
            }
            "self.verbs.call" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (verb, input): (String, String)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<String> = (|| {
                        if input.len() > cx.data().message_bytes {
                            return Err("verb_input_over_budget".into());
                        }
                        let input: Value =
                            serde_json::from_str(&input).map_err(|_| "invalid_verb_input")?;
                        cx.data_mut()
                            .call("self.verbs.call", json!({"verb":verb,"input":input}))
                            .and_then(|value| field::<Value>(&value, "output"))
                            .map(|output| output.to_string())
                    })();
                    Ok((reply,))
                },
            ),
            "oneiron.clock.now_unix_ms" => {
                root.func_wrap(wit, |mut cx: StoreContextMut<'_, State>, (): ()| {
                    cx.data_mut().begin_call()?;
                    let value = cx
                        .data_mut()
                        .call("oneiron.clock.now_unix_ms", json!({}))
                        .and_then(|value| field::<u64>(&value, "value"))
                        .map_err(wasmtime::Error::msg)?;
                    Ok((value,))
                })
            }
            "oneiron.output.text" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>,
                 (target, start, frame): (String, bool, String)| {
                    let target = match target.as_str() {
                        "console" => StreamTarget::Console,
                        "finish" => StreamTarget::Finish { start },
                        "store" => StreamTarget::Store { start },
                        _ => return Err(wasmtime::Error::msg("unknown streamed output target")),
                    };
                    Ok((cx.data_mut().output(target, frame.into_bytes())?,))
                },
            ),
            "oneiron.output.bytes" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (path, frame): (String, Vec<u8>)| {
                    Ok((cx.data_mut().output(StreamTarget::File(path), frame)?,))
                },
            ),
            "oneiron.random.bytes" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (length,): (u32,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<Vec<u8>> = cx
                        .data_mut()
                        .call("oneiron.random.bytes", json!({"length":length}))
                        .and_then(|value| base64_bytes(&value));
                    Ok((reply,))
                },
            ),
            "vault.agents.put" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (input,): (AgentPutInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<AgentPutOutput> = (|| {
                        if input.definition.len() > cx.data().message_bytes {
                            return Err("agent_definition_over_budget".into());
                        }
                        let definition: Value = serde_json::from_str(&input.definition)
                            .map_err(|_| "invalid_agent_definition")?;
                        let value = cx.data_mut().call(
                            "vault.agents.put",
                            json!({"id":input.id,"definition":definition}),
                        )?;
                        Ok(AgentPutOutput {
                            id: field(&value, "id")?,
                            disposition: field(&value, "disposition")?,
                        })
                    })();
                    Ok((reply,))
                },
            ),
            "self.json.validate" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (schema, value): (String, String)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<bool> = (|| {
                        let schema: Value =
                            serde_json::from_str(&schema).map_err(|_| "invalid_schema")?;
                        let value: Value =
                            serde_json::from_str(&value).map_err(|_| "invalid_value")?;
                        cx.data_mut()
                            .call("self.json.validate", json!({"schema":schema,"value":value}))
                            .and_then(|result| field(&result, "valid"))
                    })();
                    Ok((reply,))
                },
            ),
            "self.report_blocked" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, State>, (category, detail): (String, String)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<BlockedOutput> = cx
                        .data_mut()
                        .call(
                            "self.report_blocked",
                            json!({"category":category,"detail":detail}),
                        )
                        .and_then(|value| field(&value, "receipt"))
                        .map(|receipt| BlockedOutput { receipt });
                    Ok((reply,))
                },
            ),
            "ask" => root.func_wrap(
                wit,
                move |mut cx: StoreContextMut<'_, State>, (input,): (PromptInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<WaitOutput> = cx
                        .data_mut()
                        .call(public, json!({"prompt":input.prompt}))
                        .and_then(|value| field(&value, "waitId"))
                        .map(|wait_id| WaitOutput { wait_id });
                    Ok((reply,))
                },
            ),
            "self.speak" | "self.think" | "self.express" => root.func_wrap(
                wit,
                move |mut cx: StoreContextMut<'_, State>, (input,): (TextInput,)| {
                    cx.data_mut().begin_call()?;
                    let reply: Reply<SpeechOutput> = cx
                        .data_mut()
                        .call(public, json!({"text":input.text}))
                        .and_then(|value| {
                            Ok(SpeechOutput {
                                order: field(&value, "order")?,
                                is_visible: field(&value, "isVisible")?,
                            })
                        });
                    Ok((reply,))
                },
            ),
            _ => return Err(failure("canonical WIT import has no engine bridge")),
        };
        result.map_err(|_| failure("typed component import linking failed"))?;
    }
    Ok(())
}
