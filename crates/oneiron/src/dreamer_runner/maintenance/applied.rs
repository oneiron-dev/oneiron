//! Dreamer maintenance that applies at once (OF-023, owner ruling 10-18:
//! "autoapply + revert rather than holdout"). Each applied write commits its
//! effect, its finding at Auto, one typed inverse row and one Gate receipt
//! together; the owner reverts it through [`Vault::revert_dreamer_maintenance`].
//! The Coach's and the Healer's findings keep the run tray.
//!
//! A kind is one `MaintenanceInverse` variant carrying the before-state its
//! effect changed, one arm in `MaintenanceInverse::label` and one arm in
//! `MaintenanceInverse::revert_in_txn` calling the kind's own inverse.
use super::{curator, digest, invalid};
use crate::attempt_queue::AttemptId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{ClaimLifecycleStatus, EntityId, Error, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};

const APPLIED: SideTable<EntityId, AppliedRow, Named> =
    SideTable::new(&side_table::DREAMER_MAINTENANCE_APPLIED);
/// The Gate receipt one applied write leaves.
pub const MAINTENANCE_APPLY_KIND: &str = "dreamer_maintenance_apply";
/// The Gate receipt the owner's revert of one leaves.
pub const MAINTENANCE_REVERT_KIND: &str = "dreamer_maintenance_revert";
const APPLY_REASON: &str = "dreamer.maintenance.applied";
const REVERT_REASON: &str = "dreamer.maintenance.reverted";

/// What one applied write changed beyond its finding, and how to undo it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) enum MaintenanceInverse {
    /// A plain finding (a harness retune, an advisory mode): the revert
    /// retracts it and nothing else.
    Finding,
    /// One curator rung on its target.
    Curator(curator::CuratorInverse),
    /// The shared digest cadence and presentation rows.
    ProactivityPolicy(Box<digest::ProactivityPolicyInverse>),
}

impl MaintenanceInverse {
    /// The kind's name on the owner's list.
    fn label(&self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Curator(_) => "curator",
            Self::ProactivityPolicy(_) => "proactivity_policy",
        }
    }

    /// Undoes the effect, in the revert's transaction, as `owner`. Each kind
    /// leaves alone what a later write changed and lists it in `out`.
    fn revert_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        owner: WriteActor,
        now: u64,
        out: &mut MaintenanceRevert,
    ) -> Result<()> {
        match self {
            Self::Finding => Ok(()),
            Self::Curator(inverse) => curator::revert_in_txn(vault, txn, inverse, owner, now, out),
            Self::ProactivityPolicy(inverse) => {
                digest::revert_policy_in_txn(vault, txn, inverse, out)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedRow {
    inverse: MaintenanceInverse,
    attempt: AttemptId,
    facet: String,
    /// The BLAKE3 of the finding's body as it landed.
    finding_revision: [u8; 32],
    applied_at: u64,
    receipt: GateDecisionId,
    reverted: Option<MaintenanceRevert>,
}

/// One applied Dreamer maintenance write on the owner's list.
#[derive(Debug, Clone, PartialEq)]
pub struct AppliedMaintenance {
    pub finding: EntityId,
    /// `finding`, `curator` or `proactivity_policy`.
    pub kind: &'static str,
    pub facet: String,
    /// The attempt that wrote it, as 32 hex.
    pub attempt: String,
    pub applied_at: u64,
    pub receipt_ref: String,
    /// The owner's revert, once made.
    pub reverted: Option<MaintenanceRevert>,
}

/// What the owner's revert of one applied write did: the records standing
/// again in place, the Dreamer's fresh copies of its own signed records as
/// (record, copy), the outputs the write made that the revert closed, the
/// settings rows put back, and what a later write changed, left as it is (a
/// record's 32-hex id or a settings row's name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRevert {
    pub finding: EntityId,
    pub restored: Vec<EntityId>,
    pub copied: Vec<(EntityId, EntityId)>,
    pub closed: Vec<EntityId>,
    pub settings: Vec<String>,
    pub left_alone: Vec<String>,
    pub receipt_ref: String,
}

/// The BLAKE3 of a claim's body as it stands; `None` when it is gone.
pub(super) fn claim_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .filter(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN)
            .map(|raw| *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes()),
    )
}

/// Records one applied write in its own transaction: the inverse row and the
/// Dreamer's receipt naming the finding and the revision it landed at.
#[expect(
    clippy::too_many_arguments,
    reason = "one applied finding's attempt, facet, writer and inverse"
)]
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    finding: EntityId,
    attempt: AttemptId,
    facet: &str,
    actor: WriteActor,
    inverse: MaintenanceInverse,
    now: u64,
) -> Result<()> {
    if APPLIED.contains(&vault.store, &*txn, &finding)? {
        return Err(invalid());
    }
    let finding_revision = claim_revision_in_txn(vault, &*txn, &finding)?.ok_or_else(invalid)?;
    let receipt = decision(
        actor,
        MAINTENANCE_APPLY_KIND,
        APPLY_REASON,
        finding,
        finding_revision.to_vec(),
        now,
    );
    vault.store.append_gate_decision_in_txn(txn, &receipt)?;
    APPLIED.put(
        &vault.store,
        txn,
        &finding,
        &AppliedRow {
            inverse,
            attempt,
            facet: facet.to_owned(),
            finding_revision,
            applied_at: now,
            receipt: receipt.decision_id,
            reverted: None,
        },
    )
}

fn decision(
    actor: WriteActor,
    kind: &str,
    reason: &str,
    finding: EntityId,
    diff_handle: Vec<u8>,
    now: u64,
) -> GateDecisionRecord {
    GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: "approved".to_owned(),
        reason_codes: vec![reason.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: kind.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*finding.as_bytes()),
        grant_ref: None,
        diff_handle,
        read_frontier_hash: [0; 32],
        redacted_at: None,
    }
}

impl Vault {
    /// The Dreamer's applied maintenance writes, reverted ones too, newest
    /// first, at most `limit`. Owner tier: the list spans the whole vault.
    pub fn applied_dreamer_maintenance(
        &self,
        owner: &AuthenticatedOwner,
        limit: usize,
    ) -> Result<Vec<AppliedMaintenance>> {
        let txn = self.store.env.read_txn()?;
        super::validate_owner_in_txn(self, &txn, owner)?;
        let mut applied = Vec::new();
        for row in APPLIED.iter_from(&self.store, &txn, &[])? {
            let (finding, row) = row?;
            applied.push(AppliedMaintenance {
                finding,
                kind: row.inverse.label(),
                facet: row.facet,
                attempt: crate::entity_id::bytes_to_hex_lower(row.attempt.as_bytes()),
                applied_at: row.applied_at,
                receipt_ref: format!("gate:{}", row.receipt.to_hex()),
                reverted: row.reverted,
            });
        }
        applied.sort_by_key(|row| std::cmp::Reverse((row.applied_at, row.finding)));
        applied.truncate(limit);
        Ok(applied)
    }

    /// The owner's revert of the applied maintenance write `finding` names,
    /// in ONE transaction: the owner proof is rechecked, the kind's inverse
    /// undoes its effect where no later write changed it, the finding is
    /// retracted as the owner's, and the owner's receipt names it. The row
    /// keeps the revert, so a second revert returns the first one's result
    /// and the Dreamer never applies the same finding again.
    pub fn revert_dreamer_maintenance(
        &self,
        owner: &AuthenticatedOwner,
        finding: EntityId,
        now: u64,
    ) -> Result<MaintenanceRevert> {
        let reverted = self.with_write_txn_grouped(|txn| {
            let actor = super::validate_owner_in_txn(self, &*txn, owner)?;
            let mut row = APPLIED
                .get(&self.store, &*txn, &finding)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(done) = &row.reverted {
                return Ok(done.clone());
            }
            let owner_actor = WriteActor::new(actor, EdgeActorClass::Human);
            let mut out = MaintenanceRevert {
                finding,
                restored: Vec::new(),
                copied: Vec::new(),
                closed: Vec::new(),
                settings: Vec::new(),
                left_alone: Vec::new(),
                receipt_ref: String::new(),
            };
            row.inverse
                .revert_in_txn(self, txn, owner_actor, now, &mut out)?;
            if self
                .get_claim_in_txn(&*txn, &finding)?
                .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
            {
                self.retract_claim_in_txn_as(txn, &finding, now, Some(owner_actor))?;
            }
            let receipt = decision(
                owner_actor,
                MAINTENANCE_REVERT_KIND,
                REVERT_REASON,
                finding,
                row.receipt.as_bytes().to_vec(),
                now,
            );
            self.store.append_gate_decision_in_txn(txn, &receipt)?;
            out.receipt_ref = format!("gate:{}", receipt.decision_id.to_hex());
            row.reverted = Some(out.clone());
            APPLIED.put(&self.store, txn, &finding, &row)?;
            Ok(out)
        })?;
        self.store.notify_proactivity_changes();
        Ok(reverted)
    }
}
