//! Dreamer maintenance that applies at once (OF-023, owner ruling 10-18:
//! "autoapply + revert rather than holdout"). Each applied write commits its
//! effect, its finding at Auto, one typed inverse row and one Gate receipt
//! together; the owner reverts it through [`Vault::revert_dreamer_maintenance`].
//! A background identity abstention lands no finding: its row and receipt
//! name the identity ask it kept provisional. The Coach's and the Healer's
//! findings keep the run tray.
//!
//! A kind is one `MaintenanceInverse` variant carrying the before-state its
//! effect changed, one arm in `MaintenanceInverse::label` and one arm in
//! `MaintenanceInverse::revert_in_txn` calling the kind's own inverse.
use super::{curator, digest, identity, invalid, stewardship};
use crate::attempt_queue::AttemptId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{ClaimLifecycleStatus, EntityId, Error, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};

const APPLIED: SideTable<MaintenanceTarget, AppliedRow, Named> =
    SideTable::new(&side_table::DREAMER_MAINTENANCE_APPLIED);
/// The Gate receipt one applied write leaves.
pub const MAINTENANCE_APPLY_KIND: &str = "dreamer_maintenance_apply";
/// The Gate receipt a background identity abstention leaves when it keeps
/// the names separate for now.
pub const IDENTITY_PROVISIONAL_KIND: &str = "dreamer_identity_provisional";
/// The Gate receipt the owner's revert of one leaves.
pub const MAINTENANCE_REVERT_KIND: &str = "dreamer_maintenance_revert";
// The ledger takes only `gate.` reason codes.
const APPLY_REASON: &str = "gate.dreamer.maintenance_applied";
const REVERT_REASON: &str = "gate.dreamer.maintenance_reverted";

/// What one applied write is filed under: the finding it landed, or the
/// identity ask a background abstention kept provisional, which has no
/// finding claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceTarget {
    Finding(EntityId),
    /// The ask's key, the 64 hex `/v1/owner/identity/asks` lists.
    IdentityAsk([u8; 32]),
}

impl MaintenanceTarget {
    /// A finding's 32 hex, or an identity ask's 64 hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        match self {
            Self::Finding(id) => id.to_hex(),
            Self::IdentityAsk(key) => crate::entity_id::bytes_to_hex_lower(key),
        }
    }

    /// The identity ask a 64-hex key names.
    #[must_use]
    pub fn identity_ask(hex: &str) -> Option<Self> {
        identity::parse_key(hex).map(Self::IdentityAsk)
    }

    /// The finding claim, when the target is one.
    pub(super) const fn finding(&self) -> Option<EntityId> {
        match self {
            Self::Finding(id) => Some(*id),
            Self::IdentityAsk(_) => None,
        }
    }
}

/// A finding's 16 id bytes or an ask's 32 key bytes: the width tells them
/// apart.
impl SideKey for MaintenanceTarget {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Finding(id) => id.encode_into(out),
            Self::IdentityAsk(key) => key.encode_into(out),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            16 => EntityId::decode_key(bytes).map(Self::Finding),
            32 => <[u8; 32]>::decode_key(bytes).map(Self::IdentityAsk),
            _ => None,
        }
    }
}

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
    /// A stewardship reach-out: the revert also drops its draft marker and
    /// withdraws each follow-up plan drafted from it.
    ReachOut,
    /// A follow-up plan saved for the owner's send review: the revert
    /// retracts it, which stops any send of it not yet made.
    RepresentationPlan,
    /// A background identity abstention: the ask as it stood before.
    IdentityProvisional(Box<identity::ProvisionalInverse>),
}

impl MaintenanceInverse {
    /// The kind's name on the owner's list.
    fn label(&self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Curator(_) => "curator",
            Self::ProactivityPolicy(_) => "proactivity_policy",
            Self::ReachOut => "reach_out",
            Self::RepresentationPlan => "representation_plan",
            Self::IdentityProvisional(_) => "identity_provisional",
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
            Self::Finding | Self::RepresentationPlan => Ok(()),
            Self::Curator(inverse) => curator::revert_in_txn(vault, txn, inverse, owner, now, out),
            Self::ProactivityPolicy(inverse) => {
                digest::revert_policy_in_txn(vault, txn, inverse, out)
            }
            Self::ReachOut => stewardship::revert_reach_out_in_txn(vault, txn, owner, now, out),
            Self::IdentityProvisional(inverse) => {
                identity::revert_provisional_in_txn(vault, txn, inverse, now, out)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedRow {
    inverse: MaintenanceInverse,
    /// The attempt that wrote it; none for an identity abstention, which the
    /// host's decision loop records.
    attempt: Option<AttemptId>,
    facet: String,
    /// The BLAKE3 of the finding's body as it landed; none for an identity
    /// abstention, whose inverse holds the ask it left.
    finding_revision: Option<[u8; 32]>,
    applied_at: u64,
    receipt: GateDecisionId,
    reverted: Option<MaintenanceRevert>,
}

/// One applied Dreamer maintenance write on the owner's list.
#[derive(Debug, Clone, PartialEq)]
pub struct AppliedMaintenance {
    pub target: MaintenanceTarget,
    /// `finding`, `curator`, `proactivity_policy`, `reach_out`,
    /// `representation_plan` or `identity_provisional`.
    pub kind: &'static str,
    pub facet: String,
    /// The attempt that wrote it, as 32 hex; none for an identity abstention.
    pub attempt: Option<String>,
    pub applied_at: u64,
    pub receipt_ref: String,
    /// The owner's revert, once made.
    pub reverted: Option<MaintenanceRevert>,
}

/// What the owner's revert of one applied write did: the records standing
/// again in place, the Dreamer's fresh copies of its own signed records as
/// (record, copy), the outputs the write made that the revert closed, the
/// settings rows put back, the identity asks put to the owner (64 hex), and
/// what a later write changed, left as it is (a record's 32-hex id, an ask's
/// 64 hex or a settings row's name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRevert {
    pub target: MaintenanceTarget,
    pub restored: Vec<EntityId>,
    pub copied: Vec<(EntityId, EntityId)>,
    pub closed: Vec<EntityId>,
    pub settings: Vec<String>,
    pub asked: Vec<String>,
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

/// Whether `finding` is an applied write the owner has not reverted.
pub(super) fn standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    finding: EntityId,
) -> Result<bool> {
    Ok(APPLIED
        .get(&vault.store, txn, &MaintenanceTarget::Finding(finding))?
        .is_some_and(|row| row.reverted.is_none()))
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
    let target = MaintenanceTarget::Finding(finding);
    if APPLIED.contains(&vault.store, &*txn, &target)? {
        return Err(invalid());
    }
    let finding_revision = claim_revision_in_txn(vault, &*txn, &finding)?.ok_or_else(invalid)?;
    let mut receipt = decision(
        actor,
        MAINTENANCE_APPLY_KIND,
        APPLY_REASON,
        target,
        finding_revision.to_vec(),
        now,
    );
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    APPLIED.put(
        &vault.store,
        txn,
        &target,
        &AppliedRow {
            inverse,
            attempt: Some(attempt),
            facet: facet.to_owned(),
            finding_revision: Some(finding_revision),
            applied_at: now,
            receipt: receipt.decision_id,
            reverted: None,
        },
    )
}

/// Records one background identity abstention in its transaction: the
/// inverse row under the ask and the Dreamer's receipt naming the ask. A
/// later abstention on the same ask (its candidates changed and it was
/// decided again) takes the row over; the ledger keeps every receipt.
pub(super) fn record_disposition_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: [u8; 32],
    facet: &str,
    actor: WriteActor,
    inverse: MaintenanceInverse,
    now: u64,
) -> Result<()> {
    let target = MaintenanceTarget::IdentityAsk(ask);
    let mut receipt = decision(
        actor,
        IDENTITY_PROVISIONAL_KIND,
        APPLY_REASON,
        target,
        ask.to_vec(),
        now,
    );
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    APPLIED.put(
        &vault.store,
        txn,
        &target,
        &AppliedRow {
            inverse,
            attempt: None,
            facet: facet.to_owned(),
            finding_revision: None,
            applied_at: now,
            receipt: receipt.decision_id,
            reverted: None,
        },
    )
}

/// One approved Gate receipt by `actor`, naming `target`'s claim when it is
/// a finding; `diff_handle` is never empty.
pub(super) fn decision(
    actor: WriteActor,
    kind: &str,
    reason: &str,
    target: MaintenanceTarget,
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
        claim_id: target.finding().map(|id| *id.as_bytes()),
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
            let (target, row) = row?;
            applied.push(AppliedMaintenance {
                target,
                kind: row.inverse.label(),
                facet: row.facet,
                attempt: row
                    .attempt
                    .map(|attempt| crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())),
                applied_at: row.applied_at,
                receipt_ref: format!("gate:{}", row.receipt.to_hex()),
                reverted: row.reverted,
            });
        }
        applied.sort_by_key(|row| std::cmp::Reverse((row.applied_at, row.target)));
        applied.truncate(limit);
        Ok(applied)
    }

    /// The owner's revert of the applied maintenance write `target` names,
    /// in ONE transaction: the owner proof is rechecked, the kind's inverse
    /// undoes its effect where no later write changed it, a finding is
    /// retracted as the owner's, and the owner's receipt names it. The row
    /// keeps the revert, so a second revert returns the first one's result
    /// and the Dreamer never applies the same finding again.
    pub fn revert_dreamer_maintenance(
        &self,
        owner: &AuthenticatedOwner,
        target: MaintenanceTarget,
        now: u64,
    ) -> Result<MaintenanceRevert> {
        let reverted = self.with_write_txn_grouped(|txn| {
            let actor = super::validate_owner_in_txn(self, &*txn, owner)?;
            let mut row = APPLIED
                .get(&self.store, &*txn, &target)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(done) = &row.reverted {
                return Ok(done.clone());
            }
            let owner_actor = WriteActor::new(actor, EdgeActorClass::Human);
            let mut out = MaintenanceRevert {
                target,
                restored: Vec::new(),
                copied: Vec::new(),
                closed: Vec::new(),
                settings: Vec::new(),
                asked: Vec::new(),
                left_alone: Vec::new(),
                receipt_ref: String::new(),
            };
            row.inverse
                .revert_in_txn(self, txn, owner_actor, now, &mut out)?;
            if let Some(finding) = target.finding()
                && self
                    .get_claim_in_txn(&*txn, &finding)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
            {
                self.retract_claim_in_txn_as(txn, &finding, now, Some(owner_actor))?;
            }
            let mut receipt = decision(
                owner_actor,
                MAINTENANCE_REVERT_KIND,
                REVERT_REASON,
                target,
                row.receipt.as_bytes().to_vec(),
                now,
            );
            self.store
                .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
            out.receipt_ref = format!("gate:{}", receipt.decision_id.to_hex());
            row.reverted = Some(out.clone());
            APPLIED.put(&self.store, txn, &target, &row)?;
            Ok(out)
        })?;
        self.store.notify_proactivity_changes();
        Ok(reverted)
    }
}
