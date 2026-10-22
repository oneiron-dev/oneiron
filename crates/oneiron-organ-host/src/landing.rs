//! An organ's results onto the artifact family's one landing (ARCH-0078 "A
//! proposal landing"): each export file a call made waits beside its artifact
//! as a native output until a person keeps or discards it. Its made_by is the
//! call receipt: the organ and its version are the process, the args digest
//! the replay key, the vault versions it read the inputs.

use oneiron::edit_settle::{MadeByReader, NativeOutput, PendingProposalView};
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
    #[must_use]
    pub fn native_outputs(&self, run_ref: &str, made_by: Option<&MadeBy>) -> Vec<NativeOutput> {
        let receipt = to_value(&self.receipt).unwrap_or_default();
        let both = Value::Map(vec![
            (Value::from("report"), self.report.clone()),
            (Value::from("receipt"), receipt),
        ]);
        let msgpack = rmpv_of(&both);
        let report = NativeOutput::report_from_msgpack(&msgpack);
        dismantle(msgpack);
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

/// `value` as the engine's report reader takes it, built bottom-up with a
/// stack of its own, so a deep report costs no thread stack here.
fn rmpv_of(value: &Value) -> rmpv::Value {
    enum Step<'a> {
        Enter(&'a Value),
        Array(usize),
        Map(usize),
    }
    let mut built: Vec<rmpv::Value> = Vec::new();
    let mut steps = vec![Step::Enter(value)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Enter(Value::Array(items)) => {
                steps.push(Step::Array(items.len()));
                steps.extend(items.iter().rev().map(Step::Enter));
            }
            Step::Enter(Value::Map(entries)) => {
                steps.push(Step::Map(entries.len()));
                for (key, item) in entries.iter().rev() {
                    steps.push(Step::Enter(item));
                    steps.push(Step::Enter(key));
                }
            }
            Step::Enter(leaf) => built.push(rmpv_leaf(leaf)),
            Step::Array(len) => {
                let items = built.split_off(built.len().saturating_sub(len));
                built.push(rmpv::Value::Array(items));
            }
            Step::Map(len) => {
                let flat = built.split_off(built.len().saturating_sub(len * 2));
                let mut flat = flat.into_iter();
                let mut entries = Vec::with_capacity(len);
                while let (Some(key), Some(item)) = (flat.next(), flat.next()) {
                    entries.push((key, item));
                }
                built.push(rmpv::Value::Map(entries));
            }
        }
    }
    built.pop().unwrap_or(rmpv::Value::Nil)
}

fn rmpv_leaf(value: &Value) -> rmpv::Value {
    match value {
        Value::Nil | Value::Array(_) | Value::Map(_) => rmpv::Value::Nil,
        Value::Boolean(flag) => rmpv::Value::Boolean(*flag),
        Value::Integer(integer) => match (integer.as_u64(), integer.as_i64()) {
            (Some(unsigned), _) => rmpv::Value::from(unsigned),
            (None, Some(signed)) => rmpv::Value::from(signed),
            (None, None) => rmpv::Value::Nil,
        },
        Value::F32(float) => rmpv::Value::F32(*float),
        Value::F64(float) => rmpv::Value::F64(*float),
        Value::String(text) => rmpv::Value::from(text.as_str()),
        Value::Binary(bytes) => rmpv::Value::Binary(bytes.clone()),
        Value::Ext(kind, bytes) => rmpv::Value::Ext(*kind, bytes.clone()),
    }
}

/// Drops an [`rmpv::Value`] child by child, as [`Value`] drops itself.
fn dismantle(value: rmpv::Value) {
    let mut stack = vec![value];
    while let Some(mut value) = stack.pop() {
        match &mut value {
            rmpv::Value::Array(items) => stack.append(items),
            rmpv::Value::Map(entries) => {
                for (key, item) in std::mem::take(entries) {
                    stack.push(key);
                    stack.push(item);
                }
            }
            _ => {}
        }
    }
}

/// Offers every export file of one organ call to `artifact`, each a proposal
/// waiting for Keep, with the call receipt as its made_by. No caller
/// credential reaches this rail, so the envelope waits as the host built it
/// ([`MadeByReader::OrganReceipt`], FIX 1229).
///
/// # Errors
///
/// The vault's refusal of an output: another media type than the artifact's,
/// an empty file, a ref already settled or waiting.
pub fn propose_organ_outputs(
    vault: &Vault,
    artifact: &EntityId,
    outcome: &OrganOutcome,
    run_ref: &str,
    trigger: Option<MadeByTrigger>,
    actor: WriteActor,
) -> oneiron::Result<Vec<PendingProposalView>> {
    let now = vault.now_recorded_at();
    let made_by = outcome.made_by(actor.entity_ref(), trigger, now);
    outcome
        .native_outputs(run_ref, Some(&made_by))
        .iter()
        .map(|output| {
            vault.propose_native_output(
                artifact,
                output,
                Some(MadeByReader::OrganReceipt),
                actor,
                now,
            )
        })
        .collect()
}
