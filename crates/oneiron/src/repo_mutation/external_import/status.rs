//! `external_import_status` (FIX 6871): one import's progress as a pure
//! join over its own immutable facts and the door's receive records.
//!
//! Nothing here is stored, cached, matched, fetched, pushed, enqueued or
//! repaired. Precedence, highest first: the exact base to head update
//! received (whatever its candidate does next); a dispatched send's own
//! observed refusal; a dispatched send no receive record proves yet; then
//! the newest pre-send fact (a held base, a moved source, a refused fetch);
//! otherwise pending. A late failure never outranks an accepted receive,
//! and the receipt always names the frozen requested head.

use super::receive::{ImportReceive, ImportRefUpdate};
use super::source::{ImportOutcome, ImportStep, ObservationRecord};
use super::{ExternalImportPhase, ExternalImportReceipt};
use crate::error::Result;
use crate::git_wire::{GitOid, GitRefName};
use crate::{EntityId, Vault};

/// One import's derived state: its receipt, phase and reason code, and
/// the exact head receive once there is one.
#[derive(Debug, Clone)]
pub(crate) struct ExternalImportProjection {
    pub(crate) receipt: ExternalImportReceipt,
    pub(crate) phase: ExternalImportPhase,
    pub(crate) reason: Option<String>,
    pub(crate) head: Option<ImportReceive>,
}

/// What a projection reads beside the import's own facts.
#[derive(Debug, Clone, Copy)]
struct Evidence {
    seed_dispatched: bool,
    head_dispatched: bool,
    seed_received: bool,
    head_received: bool,
}

impl Vault {
    /// The import `import` of the served repository `repo` (object store
    /// `store`, CODE anchor `code_repo`), projected from its saved facts.
    /// `None` when no such import of this repository exists.
    ///
    /// # Errors
    /// A fact that does not decode, or a store failure.
    pub(crate) fn external_import_status(
        &self,
        store: &str,
        repo: &str,
        code_repo: EntityId,
        import: EntityId,
    ) -> Result<Option<ExternalImportProjection>> {
        let (source, seed, head, observations) = {
            let txn = self.store.env.read_txn()?;
            let Some(source) = self.external_import_source_in_txn(&txn, import, code_repo)? else {
                return Ok(None);
            };
            (
                source,
                self.external_import_dispatch_in_txn(&txn, import, ImportStep::Seed)?,
                self.external_import_dispatch_in_txn(&txn, import, ImportStep::Head)?,
                self.external_import_observations_in_txn(&txn, import)?,
            )
        };
        if source.object_store != store || source.repo != repo {
            return Ok(None);
        }
        let importer = source.importer();
        let name = GitRefName::parse_full(source.imported_ref.clone())?;
        let base = GitOid::parse_hex(source.base_commit.clone())?;
        let head_commit = GitOid::parse_hex(source.head_commit.clone())?;
        let seeded = self.received_import_update(
            store,
            &ImportRefUpdate {
                name: name.clone(),
                old: None,
                new: base.clone(),
            },
            importer,
        )?;
        let received = self.received_import_update(
            store,
            &ImportRefUpdate {
                name,
                old: Some(base),
                new: head_commit,
            },
            importer,
        )?;
        let (phase, reason) = project_phase(
            Evidence {
                seed_dispatched: seed.is_some(),
                head_dispatched: head.is_some(),
                seed_received: seeded.is_some(),
                head_received: received.is_some(),
            },
            &observations,
        );
        Ok(Some(ExternalImportProjection {
            receipt: ExternalImportReceipt {
                import,
                repo: source.repo.clone(),
                code_repo,
                source: source.source(),
                imported_ref: source.imported_ref.clone(),
                base_revision: EntityId::from_hex(&source.base_revision)?,
                importer,
                seed_publication: seeded.map(|found| found.publication),
                receive_provenance: received.map(|found| found.provenance),
                publication: received.map(|found| found.publication),
            },
            phase,
            reason,
            head: received,
        }))
    }
}

/// The phase and reason the facts and the receive evidence name.
fn project_phase(
    evidence: Evidence,
    observations: &[ObservationRecord],
) -> (ExternalImportPhase, Option<String>) {
    if evidence.head_received {
        return (ExternalImportPhase::Received, None);
    }
    for step in [ImportStep::Head, ImportStep::Seed] {
        if let Some(refused) = observations
            .iter()
            .rev()
            .find(|fact| fact.step == step && fact.outcome == ImportOutcome::Rejected)
        {
            return (ExternalImportPhase::DoorRefused, refused.reason.clone());
        }
    }
    if evidence.head_dispatched {
        return (
            ExternalImportPhase::TransportUnknown,
            Some("head_send_unproved".to_owned()),
        );
    }
    if evidence.seed_dispatched && !evidence.seed_received {
        return (
            ExternalImportPhase::TransportUnknown,
            Some("seed_send_unproved".to_owned()),
        );
    }
    let newest = observations
        .iter()
        .rev()
        .find(|fact| matches!(fact.step, ImportStep::Base | ImportStep::Fetch));
    match newest.map(|fact| (fact.outcome, fact.reason.clone())) {
        Some((ImportOutcome::Held, reason)) => (ExternalImportPhase::HeldBase, reason),
        Some((ImportOutcome::Moved, reason)) => (ExternalImportPhase::SourceMoved, reason),
        Some((ImportOutcome::Refused, reason)) => (ExternalImportPhase::FetchRefused, reason),
        _ => (ExternalImportPhase::Pending, None),
    }
}
