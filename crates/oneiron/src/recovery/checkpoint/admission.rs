//! The engine's half of a cold managed restore (LC FIX 5384/5385; the
//! contract is lanes/l14/t3/restore-contract.md): a historical signed
//! artifact the plan authorized, restored on a fresh node under the data key
//! its supervisor delivered, with its current custody through the admitted
//! head and log, as a fresh install.
//!
//! [`Vault::restore_checkpoint_admitted`] is
//! [`Vault::restore_checkpoint_recovering`] with the plan's checks and
//! facts: the artifact checked against the plan in the contract's order
//! before it opens (`source`), every refusal typed by its branch
//! (`reason`), the takeover fenced, then the fresh escrow wraps added and
//! the released recipients retired by a consumed-once capability, the page
//! custody read back, every keep, and last the caller's after-keep step
//! (the commit marker). It returns the verified facts beside the report
//! (`facts`). Every other restore path keeps its behaviour: none of these
//! checks runs there.

mod facts;
mod reason;
mod source;

use std::collections::BTreeSet;

pub use self::facts::{
    AddedRecipient, AdmittedRestore, AnchorDisposition, CustodyAdmissionFacts, CustodyPositionFact,
    CustodyRouteFact, EscrowRole, FreshRecipient, RecipientAdmissionFacts,
    RecipientRetirementDisposition, ReleasedRecipient, RestoreAdmission, RestoreCommitFacts,
    RestorePlan, RetiredBy, RetiredRecipient, SourceExpectation, VerifiedSource,
};
use self::reason::RestoreAdmissionReason as R;
pub(crate) use self::reason::{Rejected, because};
pub use self::reason::{
    RestoreAdmissionError, RestoreAdmissionReason, RestoreDestinationState, RestorePhase,
};
use super::{Custody, RestoreReason, RestoreReport, artifact, codec_error, image, write_budget};
use crate::store::custody_protocol::CustodyPosition;
use crate::store::{CustodyRoute, refuse_foreign_binding, route_custody};
use crate::world_keys::{RecipientCustody, RestoreAdmissionCapability, refused};
use crate::{Error, Vault};

/// The receipt's word for a retirement no custody head carries (Engine
/// 10-20 15:4x).
const NO_CUSTODY_HEAD: &str = "recipient_retirement: local_only (no custody head)";
/// The same where the image's custody is on this host or it binds none:
/// no takeover, so none is invented.
const NO_TAKEOVER: &str = "recipient_retirement: local_only (custody local, no takeover)";

fn position_fact(position: &CustodyPosition) -> CustodyPositionFact {
    CustodyPositionFact {
        vault: *position.vault.as_bytes(),
        namespace: *position.namespace.as_bytes(),
        epoch: position.epoch.get(),
        seq: position.seq,
        tip: position.tip,
    }
}

impl Vault {
    /// A cold managed restore (LC FIX 5384/5385):
    /// [`Vault::restore_checkpoint_recovering`] from the artifact the plan
    /// names, with the key [`CheckpointKey::from_delivered`] made for it.
    /// In order: the artifact read once and checked against the plan (its
    /// source vault, data key, kind, digest and snapshot, its commitment
    /// against the plan's signer pins alone), opened whole from that same
    /// file and checked (its checkpoint id, then a registry binding it
    /// carries); its custody routed and admitted as today, after its
    /// binding is checked to be the lineage its manifest requires; its rows
    /// landed; `finish` (the caller's pre-fence check, as today's); the
    /// takeover fence; the restored vault checked to be the source vault;
    /// the fresh escrow wraps added and the released recipients retired,
    /// journaled at the takeover writer epoch where a head was admitted, or
    /// the key header's alone where none was (`local_only`); the page
    /// custody read back; every keep; then `after_keep` with the commit
    /// facts. A refusal before the keeps removes everything the restore
    /// made, as any restore's does; `after_keep`'s leaves the destination
    /// and its custody committed (not serving, or uncertain as it says),
    /// never rolled back. Returns the verified facts beside the report.
    ///
    /// # Errors
    /// A [`RestoreAdmissionError`] naming its reason, phase and destination
    /// state, carrying the error today's paths return for the same branch.
    ///
    /// [`CheckpointKey::from_delivered`]: super::CheckpointKey::from_delivered
    pub fn restore_checkpoint_admitted(
        request: AdmittedRestore<'_>,
        finish: impl FnOnce(&Self) -> Result<(), RestoreAdmissionError>,
        after_keep: impl FnOnce(&Self, &RestoreCommitFacts) -> Result<(), RestoreAdmissionError>,
    ) -> Result<(Self, RestoreReport, RestoreAdmission), RestoreAdmissionError> {
        use RestorePhase as P;
        let AdmittedRestore {
            artifact: path,
            key,
            destination,
            config,
            restored_at,
            recovery,
            plan,
        } = request;
        let expected = key.expected().ok_or_else(|| {
            Rejected::new(
                R::SourceIdentityMismatch,
                refused("a cold managed restore opens with the key made for its plan"),
            )
            .at(P::SourceCheck)
        })?;
        let (file, evidence) = source::inspect(path, expected)?;
        let opened = artifact::open_artifact_file(file, key).map_err(|error| {
            let reason = match error {
                Error::Io(_) => R::StorageIo,
                _ => R::ArtifactIntegrityInvalid,
            };
            Rejected::new(reason, error).at(P::ArtifactOpen)
        })?;
        if opened.commitment_digest != evidence.commitment_digest
            || opened.image_id != expected.checkpoint_id
        {
            return Err(Rejected::new(
                R::ArtifactIdentityMismatch,
                refused("the checkpoint opened is not the one the plan names"),
            )
            .at(P::ArtifactOpen));
        }
        let checkpoint = opened.image_id;
        let (mut image, checkpoint_id, bodies, required) = image::decode_image(opened)
            .map_err(|error| because(R::CodecInvalid)(error).at(P::ArtifactOpen))?;
        let source = source::verified(
            &evidence,
            expected,
            checkpoint,
            source::registry(&evidence, expected)?,
        )?;
        image.drop_machine_identity();
        let rows = image
            .databases
            .get_mut("vault_meta")
            .ok_or_else(|| because(R::CodecInvalid)(codec_error()).at(P::ArtifactOpen))?;
        let at_custody = |rejected: Rejected| rejected.at(P::CustodyAdmission);
        refuse_foreign_binding(rows.as_slice(), required.as_ref()).map_err(at_custody)?;
        let image_position = required
            .as_ref()
            .and_then(|required| required.position().ok())
            .map(|position| position_fact(&position));
        let custody_source = recovery.source();
        let anchor = custody_source.anchor;
        let absolute = std::path::absolute(destination)
            .map_err(|error| because(R::StorageIo)(Error::from(error)).at(P::CustodyAdmission))?;
        let route = route_custody(
            rows,
            required.as_ref(),
            &absolute,
            key.custody_wrap(),
            Some(&custody_source),
        )
        .map_err(at_custody)?;
        let (custody, landing, route_fact) = match route {
            CustodyRoute::Local => (Custody::Keep, None, CustodyRouteFact::Local),
            CustodyRoute::Landed(landing) => {
                (Custody::Landed, Some(landing), CustodyRouteFact::Landed)
            }
            CustodyRoute::Absent => (Custody::NewHost, None, CustodyRouteFact::NoHead),
        };
        let (made, forked, mut vault, mut report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            custody,
            &BTreeSet::new(),
            &write_budget::Unfloored,
        )
        .map_err(|rejected| rejected.at(P::RowsLanding))?;
        finish(&vault)?;
        let landed = match &landing {
            Some(landing) => {
                landing
                    .fence(anchor)
                    .map_err(|rejected| rejected.at(P::TakeoverFence))?;
                report.custody_note = landing.note().map(str::to_owned);
                super::credential_custody::note_landed_access(
                    &mut report.credential_notes,
                    landing.owner_compartment_unopened(),
                );
                Some(
                    landing
                        .facts()
                        .map_err(|error| Rejected::from(error).at(P::TakeoverFence))?,
                )
            }
            None => None,
        };
        // The vault restored is the source the plan names, before any key
        // change and before it is kept.
        if vault.vault_key_vault_id() != expected.engine_vault_id {
            return Err(Rejected::new(
                R::SourceIdentityMismatch,
                refused("the restored vault is not the source vault the plan names"),
            )
            .at(P::Recipients));
        }
        let opened_key = key.opened().ok_or_else(|| {
            Rejected::new(
                R::DataKeyMismatch,
                refused("a cold managed restore holds the data key it was delivered"),
            )
            .at(P::Recipients)
        })?;
        let recipient_custody = match (&landed, route_fact) {
            (Some(facts), _) => RecipientCustody::Takeover(facts.takeover_epoch),
            (None, CustodyRouteFact::NoHead) => RecipientCustody::LocalOnly(NO_CUSTODY_HEAD),
            (None, _) => RecipientCustody::LocalOnly(NO_TAKEOVER),
        };
        let capability = RestoreAdmissionCapability::mint(
            expected.engine_vault_id,
            plan,
            recipient_custody,
            match &landing {
                Some(landing) => landing.retired_recipients(),
                None => Vec::new(),
            },
        );
        let recipients = vault
            .spend_restore_capability(capability, opened_key)
            .map_err(|rejected| rejected.at(P::Recipients))?;
        vault.check_page_custody().map_err(|error| {
            let reason = match error {
                Error::Io(_) | Error::Storage(_) => R::StorageIo,
                _ => R::PageCustodyInvalid,
            };
            Rejected::new(reason, error).at(P::PageCustody)
        })?;
        let publication = match vault.custody_status() {
            Ok(status) => Some(status),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a restore's custody status could not be read");
                None
            }
        };
        let anchor_disposition = match (&landed, anchor) {
            (None, _) => AnchorDisposition::NotApplicable,
            (Some(_), Some(_)) => AnchorDisposition::ConfiguredVerified,
            (Some(_), None) => AnchorDisposition::UnsetRollbackNotProven,
        };
        let custody_facts = CustodyAdmissionFacts {
            route: route_fact,
            image_position,
            head_position: landed.as_ref().map(|facts| position_fact(&facts.head)),
            admitted_position: landed.as_ref().map(|facts| position_fact(&facts.admitted)),
            anchor: anchor_disposition,
            anchor_read_digest: landed.as_ref().and_then(|facts| facts.anchor_read),
            anchor_advanced_digest: landed.as_ref().and_then(|facts| facts.anchor_advanced),
            takeover_epoch: landed.as_ref().map(|facts| facts.takeover_epoch),
            retired_ids: landed.as_ref().map_or(0, |facts| facts.retired_ids),
            dropped_gate_decisions: report.dropped_gate_decisions.clone(),
            publication,
            custody_note: report.custody_note.clone(),
            training_note: report.training_note.clone(),
            pad_notes: report.pad_notes.clone(),
            credential_notes: report.credential_notes.clone(),
        };
        forked.keep();
        made.keep(&mut vault);
        if let Some(landing) = landing {
            landing.keep();
        }
        let commit = RestoreCommitFacts {
            restore_id: plan.restore_id.clone(),
            plan_digest: plan.plan_digest,
            attempt_id: plan.attempt_id.clone(),
            generation: plan.generation,
            checkpoint_id: checkpoint,
            checkpoint_sequence: source.sequence,
            checkpoint_crypto_epoch: source.crypto_epoch,
            destination: vault.store.env.path().to_path_buf(),
        };
        after_keep(&vault, &commit).map_err(RestoreAdmissionError::committed)?;
        let admission = RestoreAdmission {
            expected: expected.clone(),
            source,
            custody: custody_facts,
            recipients,
        };
        Ok((vault, report, admission))
    }
}
