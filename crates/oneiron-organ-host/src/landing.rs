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
        let receipt = rmpv::ext::to_value(&self.receipt).unwrap_or(rmpv::Value::Nil);
        let report = NativeOutput::report_from_msgpack(&rmpv::Value::Map(vec![
            (rmpv::Value::from("report"), self.report.clone()),
            (rmpv::Value::from("receipt"), receipt),
        ]));
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

/// Offers every export file of one organ call to `artifact`, each a proposal
/// waiting for Keep, with the call receipt as its made_by.
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
        .map(|output| vault.propose_native_output(artifact, output, actor, now))
        .collect()
}
