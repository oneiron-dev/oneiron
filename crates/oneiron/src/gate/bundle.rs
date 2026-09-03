use std::collections::BTreeSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::batch::{
    BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_session_bundle_claim_puts,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, SessionClaimBundle,
    SessionClaimBundleClaim, decode_claim_body, encode_claim_body,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::run_tree::{
    GATE_CONSENT_BUNDLE_DOMAIN, GATE_CONSENT_BUNDLE_SCHEMA_VERSION, GateConsentBundle,
    GateConsentBundleAction, GateConsentBundleMember, GateConsentBundleReceipt, RunTreeAdapter,
};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

use super::constants::POLICY_SCHEMA_VERSION;
use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::doors::{
    ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision,
    check_claim_policy_for_write_with_record, claim_consent_binding_parts, claim_gate_input,
    edge_actor_class_str, enforce_gate_decision,
};
use super::input::{GateActor, GateContentKind, GateProvenanceHandles};
use super::resolution::{
    PolicyManifestResolution, check_claim_source_trust, resolve_policy_manifest,
};

/// Gate `content_kind` of the ONE durable receipt a bundle resolution appends.
pub const GATE_BUNDLE_CONTENT_KIND: &str = "consent_bundle";

/// Ledger outcome of an approved bundle.
pub const GATE_BUNDLE_OUTCOME_APPROVED: &str = "bundle_approved";

/// Ledger outcome of a declined bundle.
pub const GATE_BUNDLE_OUTCOME_DECLINED: &str = "bundle_declined";

/// Reason code stamped on the approved-bundle receipt.
pub const GATE_BUNDLE_REASON_APPROVED: &str = "gate.bundle.approved";

/// Reason code stamped on the declined-bundle receipt.
pub const GATE_BUNDLE_REASON_DECLINED: &str = "gate.bundle.declined";

/// Per-member resolution outcomes, in the pending-consent tray's existing
/// vocabulary — the bundle adds a unit receipt, not a second claim history.
const GATE_BUNDLE_MEMBER_OUTCOME_APPROVED: &str = "approved";
const GATE_BUNDLE_MEMBER_OUTCOME_REJECTED: &str = "rejected";

/// `grant_ref` prefix binding each per-member receipt to its bundle.
const GATE_BUNDLE_REF_PREFIX: &str = "bundle:";

/// Provenance stamped on the envelope every member replay rides.
const GATE_BUNDLE_PROVENANCE: &str = "gate-consent-bundle-resolve";

/// Bound on the pending-consent rows one bundle projection reads. Membership
/// is deterministic under it: the scan is ordered, so review and resolve
/// select the same rows and a truncated group binds the same digest.
const GATE_BUNDLE_PENDING_SCAN_LIMIT: usize = 10_000;

impl Vault {
    pub fn review_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let rtxn = self.store.env.read_txn()?;
        self.validate_session_bundle_actor_in_txn(&rtxn, actor)?;
        let members =
            self.session_claim_bundle_members_in_txn(&rtxn, expected_producer, session_tag)?;
        let policy = resolve_policy_manifest(&self.store, &rtxn)?;
        for member in &members {
            let mut approved = member.body.clone();
            approved.approval = ClaimApprovalStatus::Approved;
            check_session_bundle_actor_policy(&self.store, &rtxn, actor, &approved, &policy)?;
        }
        Ok(session_claim_bundle(session_tag, members))
    }

    /// Replays every active proposed claim in a session bundle through the
    /// ordinary gate and commits all resulting approvals atomically.
    ///
    /// Any gate denial or stale pending-consent binding aborts the enclosing
    /// write transaction, leaving every member of the producer-bound session
    /// bundle unchanged.
    pub fn merge_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let (bundle, recorded_decisions) = self.with_write_txn(|wtxn| {
            self.validate_session_bundle_actor_in_txn(&*wtxn, actor)?;
            let members =
                self.session_claim_bundle_members_in_txn(&*wtxn, expected_producer, session_tag)?;
            if members.is_empty() {
                return Ok((
                    session_claim_bundle(session_tag, members),
                    Vec::<RecordedClaimGateDecision>::new(),
                ));
            }

            let policy = resolve_policy_manifest(&self.store, &*wtxn)?;
            let mut merged = Vec::with_capacity(members.len());
            let mut ops = Vec::with_capacity(members.len());
            let mut recorded_decisions = Vec::with_capacity(members.len());
            for member in members {
                let mut body = member.body;
                body.approval = ClaimApprovalStatus::Approved;
                let source = body.source.ok_or(Error::InvalidClaimBody(
                    "session bundle member missing claim source",
                ))?;
                let envelope = WriteEnvelope::new(
                    *actor,
                    source,
                    WriteProvenance::new(Value::from("session-claim-bundle-merge"))?,
                    ClaimApprovalStatus::Approved,
                );
                let mut recorded_decision = None;
                let gate_result = check_claim_policy_for_write_with_record(
                    &self.store,
                    wtxn,
                    &member.id,
                    ClaimGateWrite {
                        body: &body,
                        envelope: Some(&envelope),
                        defer_metrics_until_commit: true,
                    },
                    &policy,
                    GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: true,
                        can_resolve_pending_consent: false,
                        include_source_in_gate_input: true,
                    },
                    &mut recorded_decision,
                );
                if let Some(recorded_decision) = recorded_decision {
                    recorded_decisions.push(recorded_decision);
                }
                gate_result?;
                let data = encode_claim_body(&body)?;
                merged.push(SessionClaimBundleClaim {
                    id: member.id,
                    body,
                });
                ops.push(BatchOp::Put {
                    id: member.id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: member.occurred,
                    learned_at: member.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                });
            }

            apply_session_bundle_claim_puts(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
            )?;

            Ok((
                SessionClaimBundle {
                    session_tag: session_tag.to_owned(),
                    claims: merged,
                },
                recorded_decisions,
            ))
        })?;
        for decision in recorded_decisions {
            decision.record_metrics();
        }
        Ok(bundle)
    }

    /// Projects every still-pending consent row stamped with `dreamer_run_id`
    /// into one deterministic, content-bound [`GateConsentBundle`].
    ///
    /// This is a READ, and it is deliberately NOT owner-only: an agent may
    /// review the run it proposed into, while only
    /// [`Vault::resolve_gate_consent_bundle`] — which takes an
    /// [`AuthenticatedOwner`] — can act on it. `actor` is validated against
    /// store truth exactly as the session-bundle review door validates its
    /// caller.
    ///
    /// It reaches proposed claims that ordinary retrieval
    /// hides and mutates none of them. The returned `bundle_id` binds the
    /// sorted members' decision ids, claim ids, diff handles, policy-frontier
    /// hashes and LIVE claim-body bytes, so any added or removed member, any
    /// edited body, and any policy-frontier move all yield a different id and
    /// make this review stale.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] when `dreamer_run_id` is empty or a member
    /// row names a non-claim entity, [`Error::EntityNotFound`] when the run has
    /// no open pending rows or one names a claim the store no longer holds, and
    /// [`Error::CorruptedIndex`] when the pending rows repeat a decision or
    /// claim id.
    pub fn review_gate_consent_bundle(
        &self,
        actor: &WriteActor,
        dreamer_run_id: &str,
    ) -> Result<GateConsentBundle> {
        require_gate_consent_bundle_run_id(dreamer_run_id)?;
        let (bundle_id, members) = {
            let rtxn = self.store.env.read_txn()?;
            self.validate_session_bundle_actor_in_txn(&rtxn, actor)?;
            let members = gate_consent_bundle_members_in_txn(&self.store, &rtxn, dreamer_run_id)?;
            if members.is_empty() {
                return Err(Error::EntityNotFound);
            }
            let bundle_id = gate_consent_bundle_id(dreamer_run_id, &members);
            let members: Vec<GateConsentBundleMember> =
                members.into_iter().map(|entry| entry.member).collect();
            (bundle_id, members)
        };
        // The name is resolved after the projection transaction closes: the
        // run-tree adapter opens its own read transaction, and naming is
        // presentation metadata over an identity the digest already fixed.
        let (name, agent_label) =
            RunTreeAdapter::new(self).consent_bundle_label(dreamer_run_id, &bundle_id)?;
        Ok(GateConsentBundle {
            schema_version: GATE_CONSENT_BUNDLE_SCHEMA_VERSION,
            bundle_id,
            name,
            dreamer_run_id: dreamer_run_id.to_owned(),
            agent_label,
            members,
        })
    }

    /// Resolves one run's consent bundle as a unit, in ONE write transaction.
    ///
    /// The live group is re-read and re-hashed inside that transaction before
    /// any claim changes: a bundle whose membership, claim bodies, or policy
    /// frontier moved since `expected_bundle_id` was reviewed is refused, so
    /// an approval can never land on content the owner did not see.
    ///
    /// [`GateConsentBundleAction::Approve`] replays every member through the
    /// ordinary live claim gate and its pending-consent binding and lands each
    /// body as [`ClaimApprovalStatus::Approved`].
    /// [`GateConsentBundleAction::Decline`] replays the same gate and closes
    /// each member as [`ClaimApprovalStatus::Rejected`] +
    /// [`ClaimLifecycleStatus::Retracted`] with `valid_to` set. Either way
    /// every member's pending row is closed with its own resolution receipt,
    /// and exactly ONE further [`GateDecisionRecord`] — `claim_id: None`,
    /// `content_kind` [`GATE_BUNDLE_CONTENT_KIND`], `diff_handle` the bundle
    /// id — represents the unit in the ordinary gate decision ledger.
    ///
    /// Only an authenticated owner reaches this door: [`AuthenticatedOwner`]
    /// has no constructor other than [`Vault::authenticate_owner`], so an
    /// agent that produced the proposals cannot resolve its own bundle.
    ///
    /// # Errors
    ///
    /// Any missing member, stale digest or consent binding, gate rejection,
    /// malformed claim, or storage failure aborts the whole operation and
    /// leaves every member exactly as it was:
    /// [`Error::InvalidClaimBody`] for an empty run id or an unusable member
    /// body, [`Error::EntityNotFound`] for an empty live group,
    /// [`Error::GateConsentStale`] for digest or binding drift,
    /// [`Error::GateWriteRejected`] for a member the live gate refuses, and
    /// [`Error::CorruptedIndex`] for an unreadable pending row.
    pub fn resolve_gate_consent_bundle(
        &self,
        owner: &AuthenticatedOwner,
        expected_bundle_id: [u8; 32],
        dreamer_run_id: &str,
        action: GateConsentBundleAction,
        now: u64,
    ) -> Result<GateConsentBundleReceipt> {
        require_gate_consent_bundle_run_id(dreamer_run_id)?;
        let (receipt, recorded_decisions) = self.with_write_txn(|wtxn| {
            let members = gate_consent_bundle_members_in_txn(&self.store, &*wtxn, dreamer_run_id)?;
            if members.is_empty() {
                return Err(Error::EntityNotFound);
            }
            let bundle_id = gate_consent_bundle_id(dreamer_run_id, &members);
            if bundle_id != expected_bundle_id {
                // Reported against the lowest-sorted live member: the drift is
                // the group's, and the group is never empty here.
                return Err(Error::GateConsentStale {
                    claim_id: members[0].member.claim_id,
                });
            }

            let policy = resolve_policy_manifest(&self.store, &*wtxn)?;
            let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
            let bundle_ref = gate_consent_bundle_ref(&bundle_id);
            let (member_outcome, member_reason) = match action {
                GateConsentBundleAction::Approve => (
                    GATE_BUNDLE_MEMBER_OUTCOME_APPROVED,
                    GATE_BUNDLE_REASON_APPROVED,
                ),
                GateConsentBundleAction::Decline => (
                    GATE_BUNDLE_MEMBER_OUTCOME_REJECTED,
                    GATE_BUNDLE_REASON_DECLINED,
                ),
            };

            let mut ops = Vec::with_capacity(members.len());
            let mut member_claim_ids = Vec::with_capacity(members.len());
            let mut recorded_decisions = Vec::with_capacity(members.len());
            let mut frontier = Sha256::new();
            frontier.update(GATE_CONSENT_BUNDLE_DOMAIN);
            for entry in &members {
                let id = entry.member.claim_id;
                let (body, header) = live_claim_parts_in_txn(&self.store, &*wtxn, &id)?;
                // The digest already bound this body; the consent binding is
                // checked too, so the member is redeemed against the same
                // content-addressed handle the pending row was parked on.
                let (diff_handle, read_frontier_hash) =
                    claim_consent_binding_parts(&self.store, &*wtxn, &body)?;
                if diff_handle != entry.member.diff_handle
                    || read_frontier_hash != entry.member.read_frontier_hash
                {
                    return Err(Error::GateConsentStale { claim_id: id });
                }

                let mut resolved = body.clone();
                let occurred = match action {
                    GateConsentBundleAction::Approve => {
                        resolved.approval = ClaimApprovalStatus::Approved;
                        TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        }
                    }
                    GateConsentBundleAction::Decline => {
                        resolved.approval = ClaimApprovalStatus::Rejected;
                        resolved.lifecycle = ClaimLifecycleStatus::Retracted;
                        resolved.valid_to = Some(now);
                        // Body ↔ envelope mirror: a closed claim's occurred
                        // window ends when it closed.
                        TimeRange {
                            start: header.occurred_start,
                            end: now.max(header.occurred_start),
                        }
                    }
                };
                // `replayed` is the body the live gate answers for. Approval
                // REDEEMS the parked consent, so the door must see the
                // Approved body and its pending binding. Decline CLOSES the
                // claim, and a terminal Rejected/Retracted body is not a write
                // the door has a verdict for — the REVIEWED body is replayed
                // instead, so a denial or a fail-closed manifest still aborts
                // the decline without asking the gate to rule on a closure.
                let replayed = match action {
                    GateConsentBundleAction::Approve => &resolved,
                    GateConsentBundleAction::Decline => &body,
                };
                replay_gate_consent_bundle_member(
                    self,
                    wtxn,
                    &id,
                    replayed,
                    &policy,
                    actor,
                    &mut recorded_decisions,
                )?;
                let data = encode_claim_body(&resolved)?;

                // Closed AFTER the gate replay and BEFORE the materialization,
                // so every member leaves an explicit resolution receipt in the
                // same transaction that changes it.
                if self
                    .store
                    .close_pending_gate_consent_in_txn(
                        wtxn,
                        &id,
                        now,
                        member_outcome,
                        vec![member_reason.to_owned()],
                        Some(bundle_ref.clone()),
                    )?
                    .is_none()
                {
                    return Err(Error::CorruptedIndex("gate consent bundle member"));
                }

                frontier.update(entry.member.read_frontier_hash);
                member_claim_ids.push(id);
                ops.push(BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred,
                    learned_at: header.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                });
            }

            apply_session_bundle_claim_puts(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
            )?;

            let record = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::now(),
                created_at: now,
                outcome: match action {
                    GateConsentBundleAction::Approve => GATE_BUNDLE_OUTCOME_APPROVED,
                    GateConsentBundleAction::Decline => GATE_BUNDLE_OUTCOME_DECLINED,
                }
                .to_owned(),
                reason_codes: vec![member_reason.to_owned()],
                // `valid_gate_receipt_reason` admits only the counterparty /
                // connector-key / effector-budget / charter families, so the
                // bundle id, run id and member count ride the typed receipt
                // and the content-bound `diff_handle` instead.
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: edge_actor_class_str(EdgeActorClass::Human).to_owned(),
                actor_ref: Some(owner.actor().to_hex()),
                content_kind: GATE_BUNDLE_CONTENT_KIND.to_owned(),
                policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: None,
                diff_handle: bundle_id.to_vec(),
                read_frontier_hash: frontier.finalize().into(),
                redacted_at: None,
            };
            self.store.append_gate_decision_in_txn(wtxn, &record)?;

            Ok((
                GateConsentBundleReceipt {
                    schema_version: GATE_CONSENT_BUNDLE_SCHEMA_VERSION,
                    receipt_id: record.decision_id,
                    bundle_id,
                    dreamer_run_id: dreamer_run_id.to_owned(),
                    action,
                    member_claim_ids,
                    created_at: now,
                },
                recorded_decisions,
            ))
        })?;
        for decision in recorded_decisions {
            decision.record_metrics();
        }
        Ok(receipt)
    }

    fn validate_session_bundle_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        actor: &WriteActor,
    ) -> Result<()> {
        let actor_raw = self
            .store
            .entities
            .get(rtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
    }
}

/// Read-only authorization check for the proposed bodies exposed by review.
/// It uses the same actor, source, sensitivity, and live agent-definition
/// ceiling as merge, but does not persist a decision or consume consent.
fn check_session_bundle_actor_policy(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    actor: &WriteActor,
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, rtxn, *actor);
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                actor_ref: Some(actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            GateContentKind::Claim,
            GateProvenanceHandles {
                actor_entity_ref: Some(actor.entity_ref()),
                ..GateProvenanceHandles::default()
            },
            true,
            agent_definition_ceiling,
            // Read-only review door over proposed claims; no effect facts to
            // classify, so no consent context is composed (pre-DEC-0006 path).
            None,
        );
        enforce_gate_decision(policy.evaluate_gate(&input))?;
    }
    let actor_ref = actor.entity_ref().to_hex();
    check_claim_source_trust(body, Some(actor_ref.as_str()), policy)
}

/// One bundle member paired with the hash of the LIVE claim body the digest
/// commits to.
///
/// The body hash is not a surfaced member field: `diff_handle` and the policy
/// frontier can both stay stable across a body edit, so the bytes themselves
/// are hashed into the bundle id and recomputed on every read.
struct BundleDigestMember {
    member: GateConsentBundleMember,
    body_hash: [u8; 32],
}

/// A nonempty run id is the bundle's only key; there is no default lane.
fn require_gate_consent_bundle_run_id(dreamer_run_id: &str) -> Result<()> {
    if dreamer_run_id.is_empty() {
        return Err(Error::InvalidClaimBody(
            "gate consent bundle requires a dreamer run id",
        ));
    }
    Ok(())
}

/// The bundle reference carried by every per-member resolution receipt.
fn gate_consent_bundle_ref(bundle_id: &[u8; 32]) -> String {
    format!(
        "{GATE_BUNDLE_REF_PREFIX}{}",
        crate::entity_id::bytes_to_hex_lower(bundle_id)
    )
}

/// Every still-pending consent row stamped with exactly `dreamer_run_id`,
/// paired with its live claim body hash and sorted into digest order.
///
/// Membership comes from the authoritative pending rows themselves; the bundle
/// owns no membership table that could drift from them.
fn gate_consent_bundle_members_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    dreamer_run_id: &str,
) -> Result<Vec<BundleDigestMember>> {
    let mut members = Vec::new();
    let mut seen_decisions = BTreeSet::new();
    let mut seen_claims = BTreeSet::new();
    for record in store.pending_gate_consents_in_txn(txn, GATE_BUNDLE_PENDING_SCAN_LIMIT)? {
        if record.dreamer_run_id.as_deref() != Some(dreamer_run_id) {
            continue;
        }
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("gate consent bundle member"))?;
        if !seen_decisions.insert(record.decision_id.as_bytes())
            || !seen_claims.insert(record.claim_id)
        {
            return Err(Error::CorruptedIndex("gate consent bundle member"));
        }
        let (body, _) = live_claim_parts_in_txn(store, txn, &claim_id)?;
        members.push(BundleDigestMember {
            body_hash: claim_body_hash(&body)?,
            member: GateConsentBundleMember {
                decision_id: record.decision_id,
                claim_id,
                created_at: record.created_at,
                diff_handle: record.diff_handle,
                read_frontier_hash: record.read_frontier_hash,
                reason_codes: record.reason_codes,
            },
        });
    }
    members.sort_by(|left, right| {
        left.member
            .decision_id
            .as_bytes()
            .cmp(&right.member.decision_id.as_bytes())
            .then_with(|| {
                left.member
                    .claim_id
                    .as_bytes()
                    .cmp(right.member.claim_id.as_bytes())
            })
    });
    Ok(members)
}

/// The bundle digest over `members`, which MUST already be in digest order
/// (member `decision_id` bytes, then `claim_id` bytes).
fn gate_consent_bundle_id(dreamer_run_id: &str, members: &[BundleDigestMember]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GATE_CONSENT_BUNDLE_DOMAIN);
    hasher.update(be_len(dreamer_run_id.len()));
    hasher.update(dreamer_run_id.as_bytes());
    for entry in members {
        hasher.update(entry.member.decision_id.as_bytes());
        hasher.update(entry.member.claim_id.as_bytes());
        hasher.update(be_len(entry.member.diff_handle.len()));
        hasher.update(&entry.member.diff_handle);
        hasher.update(entry.member.read_frontier_hash);
        hasher.update(entry.body_hash);
    }
    hasher.finalize().into()
}

/// Length prefix that keeps the variable-width digest fields unambiguous. A
/// length no `u32` can hold saturates rather than wrapping onto a shorter one.
fn be_len(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

/// SHA-256 over one claim body's canonical encoding.
fn claim_body_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(encode_claim_body(body)?);
    Ok(hasher.finalize().into())
}

/// The live CLAIM body and envelope header behind one bundle member.
fn live_claim_parts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(ClaimBody, EntityMetadataHeader)> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok((body, header))
}

/// Replays one member through the ordinary live claim gate and its
/// pending-consent binding, WITHOUT consuming the tray row.
///
/// `resolve_pending` is deliberately off: the bundle closes every member row
/// itself, in the same transaction, so each resolution leaves its own receipt
/// instead of being silently swallowed by the door. A denial, a fail-closed
/// manifest, or a drifted binding returns here and aborts the whole unit.
fn replay_gate_consent_bundle_member(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
    actor: WriteActor,
    recorded_decisions: &mut Vec<RecordedClaimGateDecision>,
) -> Result<()> {
    let source = body.source.ok_or(Error::InvalidClaimBody(
        "gate consent bundle member missing claim source",
    ))?;
    let envelope = WriteEnvelope::new(
        actor,
        source,
        WriteProvenance::new(Value::from(GATE_BUNDLE_PROVENANCE))?,
        body.approval,
    );
    let mut recorded_decision = None;
    let gate_result = check_claim_policy_for_write_with_record(
        &vault.store,
        wtxn,
        id,
        ClaimGateWrite {
            body,
            envelope: Some(&envelope),
            defer_metrics_until_commit: true,
        },
        policy,
        GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: true,
            include_source_in_gate_input: true,
        },
        &mut recorded_decision,
    );
    if let Some(recorded_decision) = recorded_decision {
        recorded_decisions.push(recorded_decision);
    }
    gate_result
}

fn session_claim_bundle(
    session_tag: &str,
    members: Vec<crate::claim::SessionClaimBundleMember>,
) -> SessionClaimBundle {
    SessionClaimBundle {
        session_tag: session_tag.to_owned(),
        claims: members
            .into_iter()
            .map(|member| SessionClaimBundleClaim {
                id: member.id,
                body: member.body,
            })
            .collect(),
    }
}
