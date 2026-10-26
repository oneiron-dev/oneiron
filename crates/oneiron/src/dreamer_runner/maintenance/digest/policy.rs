//! The policy request for the digest's shared cadence and presentation rows
//! (FIX 8712, the ruled Grant). An agent's request and a Dreamer-born one
//! land Proposed and change nothing until the authenticated owner confirms
//! the exact revision. A Coach's request applies directly only in the field
//! the Coach's live digest-settings Grant covers, the digest's rhythm
//! (`cadence.period_secs`) on a vault with one owner, while the rows and the
//! records it was drafted from still stand in the settings writer: that
//! write keeps its typed inverse and a receipt naming the Coach and the
//! Grant, and the owner reverts it. Every field no Grant covers stays in the
//! Proposed request, which the revert of the applied field leaves pending.
use super::super::applied::{self, MaintenanceInverse, MaintenanceRevert};
use super::super::coach::COACH_WEAVE_DIGEST_SETTINGS_FACET;
use super::super::proposals::{self, Finding};
use super::super::{invalid, validate_owner_in_txn, validate_person_in_txn};
use super::{
    CADENCE, PRESENTATION, PROACTIVITY_POLICY_REQUEST_PREDICATE, ProactivityCadence,
    ProactivityPolicyProposal, ProactivityPolicyRequest, ProactivityPresentation, load_cadence,
    load_presentation,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_runner::authority::{BaseAgent, base_agent_for_facet};
use crate::side_table::{self, SideTable};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

const POLICY_CONFIRMED: SideTable<EntityId, [u8; 32], side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CONFIRMED);
/// The cadence row's name in a revert's settings list.
const CADENCE_ROW: &str = "cadence";
/// The presentation row's name in a revert's settings list.
const PRESENTATION_ROW: &str = "presentation";
/// The one field a Coach's live digest-settings Grant covers: the digest's
/// rhythm (CALL R5). Every other field of a Coach's request stays Proposed.
const COVERED: &str = "cadence.period_secs";

/// The shared rows as a Coach's policy request was drafted from them (`None`:
/// unset, so the defaults). The filing applies a covered field only while
/// both still read so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProactivityPolicyBasis {
    /// The cadence row the draft read.
    pub cadence: Option<ProactivityCadence>,
    /// The presentation row the draft read.
    pub presentation: Option<ProactivityPresentation>,
}

/// What filing a Coach's policy request did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProactivityPolicyFiling {
    /// The request's finding: Proposed in the owner's run tray, which he
    /// confirms whole by its exact revision.
    pub finding: EntityId,
    /// The fields applied under the Coach's live Grant, by name.
    pub applied: Vec<String>,
    /// The changed fields no Grant covered, which wait on the owner.
    pub proposed: Vec<String>,
}

impl Vault {
    /// Resolve an agent-authored, still-pending policy claim for exact owner
    /// review. An ordinary claim alone has no settings authority.
    pub fn proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
    ) -> Result<ProactivityPolicyProposal> {
        let txn = self.store.env.read_txn()?;
        let actor = validate_person_in_txn(self, &txn, owner)?;
        load_policy_proposal(self, &txn, actor, claim_ref)
    }

    /// Confirm the exact proposal the host showed the authenticated owner.
    /// Both policy rows and a replay marker commit together; an agent claim
    /// cannot edit either row directly, nor replay an old confirmation.
    pub fn confirm_proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
        expected_revision: [u8; 32],
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let actor = validate_owner_in_txn(self, txn, owner)?;
            if POLICY_CONFIRMED.contains(&self.store, &*txn, &claim_ref)? {
                return Err(invalid());
            }
            let proposal = load_policy_proposal(self, &*txn, actor, claim_ref)?;
            if proposal.revision != expected_revision {
                return Err(invalid());
            }
            proposal.request.presentation.measure(self);
            CADENCE.put(&self.store, txn, &(), &proposal.request.cadence)?;
            PRESENTATION.put(self, txn, &(), &proposal.request.presentation)?;
            POLICY_CONFIRMED.put(&self.store, txn, &claim_ref, &expected_revision)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Files a Dreamer-born policy request (FIX 8712): it lands Proposed in
    /// the owner's run tray, with its finding's notice, and changes nothing
    /// until the owner confirms its exact revision
    /// ([`Self::confirm_proactivity_policy_proposal`]), as an agent's
    /// request does. A Dreamer's stamp is no authority over the shared rows;
    /// only a Coach's live Grant is ([`Self::file_coach_proactivity_policy`]).
    /// The request is checked as the owner setters check it; `attempt` must
    /// be a verified Dreamer attempt, never the Coach's, and `evidence` the
    /// records it read. A replay returns the finding already landed.
    ///
    /// # Errors
    ///
    /// A request the owner setters refuse, an attempt that is not a verified
    /// Dreamer attempt, or storage errors.
    pub fn file_dreamer_proactivity_policy(
        &self,
        attempt: crate::attempt_queue::AttemptId,
        request: &ProactivityPolicyRequest,
        evidence: &[EntityId],
        now: u64,
    ) -> Result<EntityId> {
        request.claim_value()?;
        let stamp = self
            .dreamer_attempt_authority(attempt)?
            .ok_or_else(invalid)?;
        if base_agent_for_facet(&stamp.facet) != BaseAgent::Dreamer {
            return Err(invalid());
        }
        let subject = crate::vault::embedded_owner_actor_id()?;
        let value = serde_json::to_value(request).map_err(|_| invalid())?;
        let finding = proposals::emit(
            self,
            attempt,
            &stamp.facet,
            subject,
            PROACTIVITY_POLICY_REQUEST_PREDICATE,
            &value,
            evidence,
            now,
        )?;
        self.store.notify_proactivity_changes();
        Ok(finding)
    }

    /// The shared rows as they stand, for a Coach drafting a policy request
    /// to name as its basis.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn proactivity_policy_basis(&self) -> Result<ProactivityPolicyBasis> {
        let txn = self.store.env.read_txn()?;
        basis_in_txn(self, &txn)
    }

    /// Files a Coach's policy request (FIX 8712), drafted from the owner's
    /// own behaviour (`evidence`, the records it read) on the rows `basis`
    /// names, under a leased `coach.weave_digest_settings` attempt. The
    /// whole request lands Proposed in the owner's run tray, with its
    /// finding's notice, for him to confirm by its exact revision. In the
    /// same write, the field the Coach's live digest-settings Grant covers
    /// (the rhythm, `cadence.period_secs`) applies at once when it changed,
    /// the landing is fresh, the vault has one owner whose Grant names the
    /// Coach, the rows still read as `basis` and every record in `evidence`
    /// is a live claim the owner's own session wrote (FIX 9315); it keeps its
    /// typed inverse and a receipt naming the Coach and the Grant, and the
    /// owner reverts it. Every other changed
    /// field stays in the Proposed request, never dropped. Any error reading
    /// the Grant means a proposal, never an apply.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, a request the
    /// owner setters refuse, or storage errors.
    pub fn file_coach_proactivity_policy(
        &self,
        attempt: &DreamerAdmittedAttempt,
        request: &ProactivityPolicyRequest,
        basis: &ProactivityPolicyBasis,
        evidence: &[EntityId],
        now: u64,
    ) -> Result<ProactivityPolicyFiling> {
        self.require_coach_attempt(attempt, COACH_WEAVE_DIGEST_SETTINGS_FACET)?;
        request.claim_value()?;
        let attempt_id = attempt.status.attempt.id;
        let envelope =
            proposals::run_tray_envelope(self, COACH_WEAVE_DIGEST_SETTINGS_FACET, attempt_id)?;
        let value = serde_json::to_value(request).map_err(|_| invalid())?;
        let finding = Finding {
            subject: crate::vault::embedded_owner_actor_id()?,
            predicate: PROACTIVITY_POLICY_REQUEST_PREDICATE,
            value: &value,
            evidence,
        };
        let filing = self.with_write_txn_grouped(|txn| {
            let (id, fresh) = proposals::emit_fresh_in_txn(self, txn, &finding, &envelope, now)?;
            let cadence = load_cadence(self, &*txn)?;
            let presentation = load_presentation(self, &*txn)?;
            let mut proposed = changed_fields(&cadence, &presentation, request);
            let covered = proposed.iter().position(|field| field == COVERED);
            // A replay applies nothing again.
            let grant = match covered {
                Some(_) if fresh && basis_holds_in_txn(self, txn, basis, evidence)? => {
                    covering_grant_in_txn(self, txn)?
                }
                _ => None,
            };
            let mut granted = Vec::new();
            if let (Some(at), Some(grant)) = (covered, grant) {
                granted.push(proposed.remove(at));
                let rhythm = ProactivityCadence {
                    period_secs: request.cadence.period_secs,
                    ..cadence
                };
                CADENCE.put(&self.store, txn, &(), &rhythm)?;
                let inverse = ProactivityPolicyInverse {
                    prior_cadence: basis.cadence.clone(),
                    prior_presentation: basis.presentation.clone(),
                    cadence: rhythm,
                    presentation,
                    rows: Some(vec![CADENCE_ROW.to_owned()]),
                    pending: (!proposed.is_empty()).then(|| proposed.clone()),
                };
                let coach = self.coach_authority_in_txn(txn)?;
                applied::record_granted_in_txn(
                    self,
                    txn,
                    id,
                    attempt_id,
                    COACH_WEAVE_DIGEST_SETTINGS_FACET,
                    coach,
                    MaintenanceInverse::ProactivityPolicy(Box::new(inverse)),
                    grant,
                    now,
                )?;
            }
            Ok(ProactivityPolicyFiling {
                finding: id,
                applied: granted,
                proposed,
            })
        })?;
        self.store.notify_proactivity_changes();
        Ok(filing)
    }
}

/// The shared rows as stored, in `txn`.
fn basis_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityPolicyBasis> {
    Ok(ProactivityPolicyBasis {
        cadence: CADENCE.get(&vault.store, txn, &())?,
        presentation: PRESENTATION.get(&vault.store, txn, &())?,
    })
}

/// The own-behaviour basis rechecked in the settings writer: the rows still
/// read as `basis` drafted them, and the draft cites at least one record and
/// each one is the owner's own (FIX 9315): a live claim the session of the
/// vault's sole owner wrote. Anything else files the whole request as a
/// proposal for him to confirm, never an apply.
fn basis_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    basis: &ProactivityPolicyBasis,
    evidence: &[EntityId],
) -> Result<bool> {
    if evidence.is_empty() || basis_in_txn(vault, txn)? != *basis {
        return Ok(false);
    }
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let [owner] = owners.as_slice() else {
        return Ok(false);
    };
    for id in evidence {
        let crate::vault::LiveEntityRow::Live { entity_type, body } =
            crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?
        else {
            return Ok(false);
        };
        let own = entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && crate::claim::decode_claim_body(&body, true)
                .is_ok_and(|claim| crate::claim::session_claim_producer(&claim) == Some(*owner));
        if !own {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The Coach's live digest-settings Grant from the vault's one owner: the
/// cadence and presentation rows are the vault's own, so only a sole
/// owner's Grant covers them. Any error reading it is no Grant.
fn covering_grant_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<Option<EntityId>> {
    let owners = crate::policy_model::owners_in_txn(vault, &*txn)?;
    let [owner] = owners.as_slice() else {
        return Ok(None);
    };
    let coach = vault.coach_authority_in_txn(txn)?.entity_ref();
    Ok(
        match vault.coach_weave_digest_settings_grant_in_txn(&*txn, coach, *owner) {
            Ok(standing) => standing.ok(),
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "the Coach's digest settings Grant was not read"
                );
                None
            }
        },
    )
}

/// The fields `request` changes on the rows in force, by name.
fn changed_fields(
    cadence: &ProactivityCadence,
    presentation: &ProactivityPresentation,
    request: &ProactivityPolicyRequest,
) -> Vec<String> {
    let (to, shown) = (&request.cadence, &request.presentation);
    [
        (COVERED, cadence.period_secs != to.period_secs),
        (
            "cadence.group_by_facet",
            cadence.group_by_facet != to.group_by_facet,
        ),
        (
            "cadence.urgent_breakthrough",
            cadence.urgent_breakthrough != to.urgent_breakthrough,
        ),
        (
            "presentation.group_aliases",
            presentation.group_aliases != shown.group_aliases,
        ),
        (
            "presentation.group_template",
            presentation.group_template != shown.group_template,
        ),
        (
            "presentation.item_template",
            presentation.item_template != shown.item_template,
        ),
        (
            "presentation.voice_style",
            presentation.voice_style != shown.voice_style,
        ),
        (
            "presentation.urgent_groups",
            presentation.urgent_groups != shown.urgent_groups,
        ),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(field, _)| field.to_owned())
    .collect()
}

/// The shared rows one applied policy request replaced (OF-023, FIX 8712):
/// each row's prior value (`None`: unset, so the defaults) and the value
/// applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dreamer_runner::maintenance) struct ProactivityPolicyInverse {
    prior_cadence: Option<ProactivityCadence>,
    prior_presentation: Option<ProactivityPresentation>,
    cadence: ProactivityCadence,
    presentation: ProactivityPresentation,
    /// The rows the write applied, by name; `None`: both, as a Dreamer-born
    /// request applied them.
    rows: Option<Vec<String>>,
    /// The changed fields no Grant covered, still Proposed in the finding:
    /// the owner's revert of the applied rows leaves them pending.
    pending: Option<Vec<String>>,
}

impl ProactivityPolicyInverse {
    /// Whether the owner's revert leaves the finding standing, its
    /// uncovered fields still waiting on him.
    pub(in crate::dreamer_runner::maintenance) fn keeps_finding(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| !pending.is_empty())
    }
}

/// Puts back each row the request applied that still holds what it applied;
/// a row a later write changed is left as it is and listed. The caller
/// signals the change after commit.
pub(in crate::dreamer_runner::maintenance) fn revert_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inverse: &ProactivityPolicyInverse,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let applied = |row: &str| {
        inverse
            .rows
            .as_ref()
            .is_none_or(|rows| rows.iter().any(|applied| applied == row))
    };
    if applied(CADENCE_ROW) {
        if CADENCE.get(&vault.store, &*txn, &())?.as_ref() == Some(&inverse.cadence) {
            match &inverse.prior_cadence {
                Some(row) => CADENCE.put(&vault.store, txn, &(), row)?,
                None => {
                    CADENCE.delete(&vault.store, txn, &())?;
                }
            }
            out.settings.push(CADENCE_ROW.to_owned());
        } else {
            out.left_alone.push(CADENCE_ROW.to_owned());
        }
    }
    if applied(PRESENTATION_ROW) {
        if PRESENTATION.get(&vault.store, &*txn, &())?.as_ref() == Some(&inverse.presentation) {
            match &inverse.prior_presentation {
                Some(row) => PRESENTATION.put(vault, txn, &(), row)?,
                None => {
                    PRESENTATION.delete(&vault.store, txn, &())?;
                }
            }
            out.settings.push(PRESENTATION_ROW.to_owned());
        } else {
            out.left_alone.push(PRESENTATION_ROW.to_owned());
        }
    }
    Ok(())
}

fn load_policy_proposal(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    claim_ref: EntityId,
) -> Result<ProactivityPolicyProposal> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &claim_ref)?
        .ok_or_else(invalid)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PROACTIVITY_POLICY_REQUEST_PREDICATE
        || body.subject != crate::ClaimSubject::Entity(owner)
        || body.source != Some(ClaimSource::Generated)
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || crate::claim::session_claim_producer(&body).is_none()
    {
        return Err(invalid());
    }
    let value = body.value.as_str().ok_or_else(invalid)?;
    let request: ProactivityPolicyRequest = serde_json::from_str(value).map_err(|_| invalid())?;
    request.claim_value()?;
    Ok(ProactivityPolicyProposal {
        request,
        revision: *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
    })
}
