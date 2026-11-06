//! An organ's results onto the artifact family's one landing (ARCH-0078 "A
//! proposal landing"): each export file a call made waits beside its artifact
//! as a native output until a person keeps or discards it. Its made_by is the
//! call receipt: the organ and its version are the process, the args digest
//! the replay key, the vault versions it read the inputs.

use oneiron::edit_settle::{NativeOutput, PendingProposalView};
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use oneiron::{EntityId, Vault, WriteActor};
use oneiron_organ_protocol::{Value, to_value};

use crate::outcome::OrganOutcome;

impl OrganOutcome {
    /// The made_by envelope this call gives what it made: `actor` ran it,
    /// `trigger` is the task, ask, run or skill it answers.
    #[must_use]
    pub fn made_by(&self, actor: EntityId, trigger: Option<MadeByTrigger>, at: u64) -> MadeBy {
        let receipt = &self.receipt;
        MadeBy {
            inputs: receipt
                .inputs
                .iter()
                .filter(|input| !input.lent)
                .filter_map(|input| EntityId::from_hex(&input.artifact).ok())
                .map(|row| MadeByInput {
                    row,
                    role: MadeByInputRole::Input,
                })
                .collect(),
            process: MadeByProcess {
                actor,
                class: MadeByClass::Concluded,
                identity: format!("{}.{}", receipt.organ.name, receipt.verb),
                version: receipt.organ.version.clone(),
                params_hash: blake3::Hash::from_bytes(receipt.args_digest.0)
                    .to_hex()
                    .to_string(),
            },
            at,
            trigger,
        }
    }

    /// Each export file this call made, as a native output for its artifact.
    /// The organ's report and the host's call receipt travel with each; a
    /// call that made several files names them `<run_ref>/<n>`.
    ///
    /// A report the JSON writer cannot represent (a map key that is not a
    /// string, boolean, integer or finite float) keeps the baseline
    /// whole-report null, as the previous reader did when its conversion
    /// failed; only the depth of representable reports is fixed here
    /// (FIX 12431).
    #[must_use]
    pub fn native_outputs(&self, run_ref: &str, made_by: Option<&MadeBy>) -> Vec<NativeOutput> {
        let receipt = to_value(&self.receipt).unwrap_or_default();
        let both = Value::Map(vec![
            (Value::from("report"), self.report.clone()),
            (Value::from("receipt"), receipt),
        ]);
        let report = report_json_text(&both).unwrap_or_else(|| "null".to_owned());
        let several = self.outputs.len() > 1;
        self.outputs
            .iter()
            .enumerate()
            .map(|(n, output)| NativeOutput {
                run_ref: if several {
                    format!("{run_ref}/{n}")
                } else {
                    run_ref.to_owned()
                },
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                bytes: output.to_vec(),
                report: report.clone(),
                made_by: made_by.cloned(),
            })
            .collect()
    }
}

/// `value` as JSON text, written iteratively with a heap stack so a deep
/// report costs no thread stack (FIX 12431). Map entries keep insertion
/// order with the last value winning a repeated key, as the previous
/// reader did; a key that is not a string, boolean, integer or finite
/// float yields `None` so the caller keeps the baseline whole-report null.
/// Float values that are not finite become null leaves, as before.
fn report_json_text(report: &Value) -> Option<String> {
    fn key_text(key: &Value) -> Option<String> {
        match key {
            Value::String(text) => Some(text.clone()),
            Value::Boolean(flag) => Some(flag.to_string()),
            Value::Integer(n) => Some(n.to_string()),
            Value::F32(f) => NativeOutput::json_f32_text(*f),
            Value::F64(f) => NativeOutput::json_f64_text(*f),
            _ => None,
        }
    }

    fn push_escaped(out: &mut String, text: &str) {
        out.push('"');
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\x08' => out.push_str("\\b"),
                '\x0C' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let n = c as u32;
                    out.push_str("\\u00");
                    out.push(HEX[(n >> 4) as usize] as char);
                    out.push(HEX[(n & 0xF) as usize] as char);
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }

    fn push_byte_array(out: &mut String, bytes: &[u8]) {
        out.push('[');
        for (n, byte) in bytes.iter().enumerate() {
            if n > 0 {
                out.push(',');
            }
            out.push_str(&byte.to_string());
        }
        out.push(']');
    }

    fn push_flat(out: &mut String, value: &Value) {
        match value {
            Value::Nil => out.push_str("null"),
            Value::Boolean(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Value::Integer(n) => out.push_str(&n.to_string()),
            // A 32-bit float travels as the 64-bit value the JSON reader
            // holds it in; a float that is not finite is a null leaf.
            Value::F32(f) => out.push_str(
                &NativeOutput::json_f64_text(f64::from(*f)).unwrap_or_else(|| "null".to_owned()),
            ),
            Value::F64(f) => {
                out.push_str(&NativeOutput::json_f64_text(*f).unwrap_or_else(|| "null".to_owned()))
            }
            Value::String(text) => push_escaped(out, text),
            Value::Binary(bytes) => push_byte_array(out, bytes),
            Value::Ext(kind, bytes) => {
                out.push('[');
                out.push_str(&kind.to_string());
                out.push(',');
                push_byte_array(out, bytes);
                out.push(']');
            }
            Value::Array(_) | Value::Map(_) => {
                unreachable!("containers take the frame path")
            }
        }
    }

    fn ordered_entries<'a>(entries: &'a [(Value, Value)]) -> Option<Vec<(String, &'a Value)>> {
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut ordered: Vec<(String, &'a Value)> = Vec::new();
        for (key, value) in entries {
            let text = key_text(key)?;
            if let Some(&at) = index.get(&text) {
                ordered[at].1 = value;
            } else {
                index.insert(text.clone(), ordered.len());
                ordered.push((text, value));
            }
        }
        Some(ordered)
    }

    enum Frame<'a> {
        Array {
            items: &'a [Value],
            idx: usize,
        },
        Map {
            entries: Vec<(String, &'a Value)>,
            idx: usize,
        },
    }

    let mut out = String::new();
    let mut stack: Vec<Frame<'_>> = Vec::new();
    match report {
        Value::Array(items) => {
            out.push('[');
            stack.push(Frame::Array { items, idx: 0 });
        }
        Value::Map(entries) => {
            out.push('{');
            stack.push(Frame::Map {
                entries: ordered_entries(entries)?,
                idx: 0,
            });
        }
        leaf => {
            push_flat(&mut out, leaf);
            return Some(out);
        }
    }
    while let Some(frame) = stack.last_mut() {
        match frame {
            Frame::Array { items, idx } => {
                if *idx >= items.len() {
                    out.push(']');
                    stack.pop();
                    continue;
                }
                if *idx > 0 {
                    out.push(',');
                }
                let child = &items[*idx];
                *idx += 1;
                match child {
                    Value::Array(nested) => {
                        out.push('[');
                        stack.push(Frame::Array {
                            items: nested,
                            idx: 0,
                        });
                    }
                    Value::Map(nested) => {
                        out.push('{');
                        stack.push(Frame::Map {
                            entries: ordered_entries(nested)?,
                            idx: 0,
                        });
                    }
                    leaf => push_flat(&mut out, leaf),
                }
            }
            Frame::Map { entries, idx } => {
                if *idx >= entries.len() {
                    out.push('}');
                    stack.pop();
                    continue;
                }
                if *idx > 0 {
                    out.push(',');
                }
                let at = *idx;
                let (key, child) = {
                    let (key, value) = &entries[at];
                    (key.clone(), *value)
                };
                push_escaped(&mut out, &key);
                out.push(':');
                *idx += 1;
                match child {
                    Value::Array(nested) => {
                        out.push('[');
                        stack.push(Frame::Array {
                            items: nested,
                            idx: 0,
                        });
                    }
                    Value::Map(nested) => {
                        out.push('{');
                        stack.push(Frame::Map {
                            entries: ordered_entries(nested)?,
                            idx: 0,
                        });
                    }
                    leaf => push_flat(&mut out, leaf),
                }
            }
        }
    }
    Some(out)
}

/// Offers every export file of one organ call to `artifact`, each a proposal
/// waiting for Keep, with the call receipt as its made_by. A call a principal
/// submitted has its envelope's trigger and receipt inputs admitted through
/// that principal's own read as each proposal is retained (FIX 9310); a
/// host's own call, with no submitter, keeps the envelope as the host built
/// it ([`oneiron::edit_settle::MadeByReader::OrganReceipt`], FIX 1229).
///
/// # Errors
///
/// The vault's refusal of an output: another media type than the artifact's,
/// an empty file, a ref already settled or waiting, or a source the
/// submitter cannot read.
pub fn propose_organ_outputs(
    vault: &Vault,
    artifact: &EntityId,
    outcome: &OrganOutcome,
    run_ref: &str,
    trigger: Option<MadeByTrigger>,
    actor: WriteActor,
    submitter: Option<EntityId>,
) -> oneiron::Result<Vec<PendingProposalView>> {
    let now = vault.now_recorded_at();
    let made_by = outcome.made_by(actor.entity_ref(), trigger, now);
    outcome
        .native_outputs(run_ref, Some(&made_by))
        .iter()
        .map(|output| {
            let reader = vault.organ_landing_reader(submitter)?;
            vault.propose_native_output(artifact, output, Some(reader), actor, now)
        })
        .collect()
}
