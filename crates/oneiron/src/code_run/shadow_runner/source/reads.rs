//! A captured step's read context as an arm reads it (FIX 6352). The bodies
//! of other runs that the context names (a reader child's delegated
//! sources, the settled findings a parent's lookups selected) are frozen
//! once with the rest of the step: each by the run that holds it and its
//! manifest in that run's committed record, with the taint its occurrence
//! reads under now and its bytes while it is clean. A manifest is reached
//! only through the binding or the finding that names it, never by a handle
//! alone, so it widens no range and authorizes no other handle.
//!
//! A read the arm makes of a result that is none of its own takes its answer
//! from what the live reads saw, in the live order: the child's delegated
//! input, then the parent's settled finding. Only a capture that proves no
//! binding answers `unknown_handle`. A context that is missing, or holds no
//! read of the kind the arm needs, is `SourceMissing`; a read whose bridge
//! position the reads kept do not establish is `CapturedOutcomeMissing`.

use super::context::ArmContext;
use super::{Admits, FrozenBody, Outcome, PreparedShadowStep, Reason, freeze_body, unavailable};
use crate::code_run::{
    CodeRunRawOutput, CodeRunReplayRecord, ReaderFoldReceipt, ReaderReadCapture,
};
use crate::engine_executor::JsResultRef;
use crate::{EntityId, Result, Vault};

/// A body of another run that the step's read context names, frozen for the
/// arm: the run that holds it, and its manifest, taint and clean bytes.
pub(crate) struct ForeignBody {
    pub(crate) owner: EntityId,
    pub(crate) body: FrozenBody,
}

/// A result of another run that a read of the arm names, as the step's live
/// read resolved it: its owner, its frozen body, the name the caller reads
/// it by, the range its parent delegated, and whether each read of it asks
/// again that the child's job is live.
pub(crate) struct ForeignRead<'s> {
    pub(crate) owner: EntityId,
    pub(crate) body: &'s FrozenBody,
    pub(crate) name: Option<String>,
    pub(crate) within: Option<(u64, u64)>,
    pub(crate) child_source: bool,
}

/// The bodies the step's read context names, each frozen once, by its run's
/// committed record, while `admits` says the reader still may read it. A
/// body its run's record no longer holds is `SourceMissing`.
pub(super) fn freeze_reader_bodies(
    vault: &Vault,
    context: &ArmContext,
    admits: Admits<'_>,
) -> Result<Outcome<Vec<ForeignBody>>> {
    let ArmContext::Captured { context, .. } = context else {
        return Ok(Ok(Vec::new()));
    };
    let reads = &context.reader_reads;
    let mut named: Vec<(EntityId, &str, &str)> = reads
        .child
        .iter()
        .flat_map(|child| child.sources())
        .map(|source| (source.owner, source.path.as_str(), source.handle.as_str()))
        .collect();
    named.extend(
        reads
            .findings
            .iter()
            .flat_map(|seen| &seen.answer.findings)
            .map(|held| {
                let finding = &held.finding;
                (
                    finding.owner,
                    finding.path.as_str(),
                    finding.handle.as_str(),
                )
            }),
    );
    named.sort_unstable();
    named.dedup();
    let mut record: Option<(EntityId, Option<CodeRunReplayRecord>)> = None;
    let mut foreign = Vec::with_capacity(named.len());
    let mut frozen_bytes = 0_u64;
    for (owner, path, handle) in named {
        if record.as_ref().is_none_or(|(held, _)| *held != owner) {
            if !admits()? {
                return Ok(Err(super::admitted::lapsed()));
            }
            record = Some((owner, vault.get_code_run_replay_record(&owner)?));
        }
        let output = record
            .as_ref()
            .and_then(|(_, record)| record.as_ref())
            .and_then(|record| {
                record
                    .outputs
                    .iter()
                    .find(|output| output.path == path && output.handle == handle)
            })
            .cloned();
        let Some(output) = output else {
            return Ok(Err(unavailable(Reason::SourceMissing, "reader_body")));
        };
        let body = match freeze_body(vault, owner, output, admits, "reader_body")? {
            Ok(body) => body,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        if let Some(bytes) = &body.bytes {
            frozen_bytes = frozen_bytes.saturating_add(bytes.len() as u64);
        }
        foreign.push(ForeignBody { owner, body });
    }
    tracing::debug!(
        bodies = foreign.len(),
        frozen_bytes,
        "a shadow step's reader bodies are frozen"
    );
    Ok(Ok(foreign))
}

impl PreparedShadowStep {
    /// What the step's result reads saw of reader state; `SourceMissing`
    /// with no replay context.
    fn reader_reads(&self) -> Outcome<&ReaderReadCapture> {
        match &self.context {
            ArmContext::Captured { context, .. } => Ok(&context.reader_reads),
            ArmContext::Missing => Err(unavailable(Reason::SourceMissing, "replay_context")),
        }
    }

    /// The frozen body run `owner` holds at `path` with `handle`.
    fn foreign_body(&self, owner: EntityId, path: &str, handle: &str) -> Outcome<&FrozenBody> {
        self.foreign
            .iter()
            .find(|held| {
                held.owner == owner
                    && held.body.output.path == path
                    && held.body.output.handle == handle
            })
            .map(|held| &held.body)
            .ok_or_else(|| unavailable(Reason::SourceMissing, "reader_body"))
    }

    /// The result of another run that `reference` names for a read of the
    /// arm at bridge position `cut`, as the step's live read resolved it: a
    /// reader child's delegated input (by its occurrence ref, then by its
    /// name or handle), else a settled finding of the run's children. `None`
    /// when the capture proves it names none: a reader child names only its
    /// inputs, a name names only the run's own results, and a handle names
    /// no finding the parent's lookups establish at `cut`.
    pub(crate) fn foreign_read(
        &self,
        reference: &JsResultRef,
        cut: u64,
    ) -> Outcome<Option<ForeignRead<'_>>> {
        let reads = self.reader_reads()?;
        if let Some(child) = &reads.child {
            let named = match reference {
                JsResultRef::Handle(handle) => handle
                    .strip_prefix("occurrence:")
                    .and_then(|wanted| child.delegated_occurrence(wanted))
                    .or_else(|| child.delegated(false, handle)),
                JsResultRef::Name(name) => child.delegated(true, name),
            };
            let Some((name, source)) = named else {
                return Ok(None);
            };
            return Ok(Some(ForeignRead {
                owner: source.owner,
                body: self.foreign_body(source.owner, &source.path, &source.handle)?,
                name: Some(name.to_owned()),
                within: Some(source.range),
                child_source: true,
            }));
        }
        let JsResultRef::Handle(handle) = reference else {
            return Ok(None);
        };
        if reads.findings.is_empty() {
            return Err(unavailable(Reason::SourceMissing, "reader_finding"));
        }
        let selected = reads
            .finding_at(handle, cut)
            .ok_or_else(|| unavailable(Reason::CapturedOutcomeMissing, "reader_finding"))?;
        let Some(selected) = selected else {
            return Ok(None);
        };
        let finding = &selected.finding;
        Ok(Some(ForeignRead {
            owner: finding.owner,
            body: self.foreign_body(finding.owner, &finding.path, &finding.handle)?,
            name: None,
            within: None,
            child_source: false,
        }))
    }

    /// Whether the reader child's job was live at bridge position `cut`, as
    /// the live reads of its source saw it.
    pub(crate) fn reader_job_live(&self, cut: u64) -> Outcome<bool> {
        let reads = self.reader_reads()?;
        if reads.job_live.is_empty() {
            return Err(unavailable(Reason::SourceMissing, "reader_job"));
        }
        reads
            .job_live_at(cut)
            .ok_or_else(|| unavailable(Reason::CapturedOutcomeMissing, "reader_job"))
    }

    /// The fold receipt the live card of the whole result `owner` holds as
    /// `output` carried: `None` for a card that carried none. A result whose
    /// card no live `describe` read is `SourceMissing`, never a result with
    /// no receipt; two live cards of it that disagree are
    /// `CapturedOutcomeMissing`.
    pub(crate) fn fold_receipt(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
    ) -> Outcome<Option<&ReaderFoldReceipt>> {
        let mut cards = self.reader_reads()?.fold_cards.iter().filter(|card| {
            card.folded.owner == owner
                && card.folded.path == output.path
                && card.folded.handle == output.handle
        });
        let Some(first) = cards.next() else {
            return Err(unavailable(Reason::SourceMissing, "fold_receipt"));
        };
        if cards.any(|card| card.receipt != first.receipt) {
            return Err(unavailable(Reason::CapturedOutcomeMissing, "fold_receipt"));
        }
        Ok(first.receipt.as_ref())
    }
}
