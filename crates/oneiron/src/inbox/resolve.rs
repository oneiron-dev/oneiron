//! Write-side inbox bulk bundle consent, approve-with-edit, and bundle-reopen doors.

use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::edit_distance::delta::{
    AmendmentDelta, DeltaCaptureContext, OUTCOME_APPROVED_AMENDED, attach_amendment_deltas,
    capture_delta_best, put_amendment_delta_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::gate_decision_receipt;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::temporal::TimeRange;

use super::model::{
    INBOX_BUNDLE_ACTOR_CLASS, INBOX_BUNDLE_CONTENT_KIND, INBOX_BUNDLE_REF_PREFIX,
    INBOX_GROUP_DOOR_PREFIX, INBOX_REASON_AMEND_ACCEPT, INBOX_REASON_AMEND_DELTA_UNCAPTURED,
    INBOX_REASON_BUNDLE_ACCEPT, INBOX_REASON_BUNDLE_REJECT, INBOX_REVIEW_DIAL_KEY,
    InboxAmendedApproval, InboxBulkVerb, InboxBundleResolution, InboxGroupReopen, InboxReviewDial,
};
use super::projection::explicit_inbox_group;
use crate::error::GateError;

impl Vault {
    /// Reads the persisted inbox review dial (default: exceptions-only).
    pub fn inbox_review_dial(&self) -> Result<InboxReviewDial> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, INBOX_REVIEW_DIAL_KEY)? else {
            return Ok(InboxReviewDial::default());
        };
        let token =
            std::str::from_utf8(&raw).map_err(|_| Error::CorruptedIndex("inbox review dial"))?;
        InboxReviewDial::parse(token).ok_or(Error::CorruptedIndex("inbox review dial"))
    }

    /// Persists the inbox review dial position.
    pub fn set_inbox_review_dial(&self, dial: InboxReviewDial) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, INBOX_REVIEW_DIAL_KEY, dial.as_str().as_bytes())?;
            Ok(())
        })
    }

    /// Applies one bulk verb to a group at the current time, covering every
    /// verb class. See [`Vault::resolve_inbox_group_at`] for post-commit VAD
    /// failure and retry semantics.
    pub fn resolve_inbox_group(
        &self,
        group_key: &str,
        verb: InboxBulkVerb,
    ) -> Result<InboxBundleResolution> {
        self.resolve_inbox_group_at(group_key, verb, None, crate::unix_seconds_now())
    }

    /// Applies one bulk verb to a group: B2 RS6 bundle consent at
    /// run × verb-class. Accept/reject resolve every targeted member — and
    /// the cross-run duplicates collapsed onto it, each verified against its
    /// own consent binding — with per-item receipts plus ONE bundle receipt
    /// carrying the run id; review-each expands the members without mutating
    /// them. `verb_class` narrows the bundle to `new_claim` / `update` /
    /// `conflict` rows.
    ///
    /// AcceptAll consolidates VAD for accepted Dreamer members after commit.
    /// A VAD error is returned with all approvals and receipts still committed;
    /// earlier members may be populated and later members not yet attempted.
    /// Retry canonical [`Vault::consolidate_claim_vad`] on the accepted ids, not
    /// this door: a retry with no remaining targets returns
    /// [`Error::EntityNotFound`]. Other verb classes can remain open after a
    /// narrowed accept. Neither RejectAll nor ReviewEach runs consolidation.
    pub fn resolve_inbox_group_at(
        &self,
        group_key: &str,
        verb: InboxBulkVerb,
        verb_class: Option<&str>,
        now: u64,
    ) -> Result<InboxBundleResolution> {
        let group = explicit_inbox_group(self, group_key, now)?.ok_or(Error::EntityNotFound)?;

        let mut targets = Vec::new();
        for member in &group.members {
            if let Some(verb_class) = verb_class
                && member.verb_class != verb_class
            {
                continue;
            }
            targets.push(member.claim_id.clone());
            targets.extend(member.duplicate_claim_ids.iter().cloned());
        }
        if targets.is_empty() {
            return Err(Error::EntityNotFound);
        }

        let bundle_ref = bundle_ref_for_group(&group.group_key);
        let (bundle_record, item_records, vad_claim_ids) = self.with_write_txn(|wtxn| {
            let mut item_records = Vec::new();
            let mut vad_claim_ids = Vec::new();
            let mut basis: Vec<GateDecisionRecord> = Vec::new();
            for claim_id in &targets {
                let id = EntityId::from_hex(claim_id)
                    .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
                match verb {
                    InboxBulkVerb::AcceptAll => {
                        if let Some(accepted) =
                            accept_member_in_txn(self, wtxn, &id, &bundle_ref, now)?
                        {
                            vad_claim_ids.extend(accepted.vad_claim_id);
                            item_records.push(accepted.record);
                        }
                    }
                    InboxBulkVerb::RejectAll => {
                        if let Some(record) = self.store.close_pending_gate_consent_in_txn(
                            wtxn,
                            &id,
                            now,
                            "rejected",
                            vec![INBOX_REASON_BUNDLE_REJECT.to_owned()],
                            Some(bundle_ref.clone()),
                        )? {
                            item_records.push(record);
                        }
                    }
                    InboxBulkVerb::ReviewEach => {
                        // No mutation: the bundle receipt still needs the
                        // policy floor the members were gated under.
                        if let Some(pending) = self.store.pending_gate_consent_in_txn(wtxn, &id)?
                            && let Some(original) =
                                self.store.gate_decision_in_txn(wtxn, pending.decision_id)?
                        {
                            basis.push(original);
                        }
                    }
                }
            }
            let bundle_basis = if item_records.is_empty() {
                &basis
            } else {
                &item_records
            };
            let bundle_record = append_bundle_decision_in_txn(
                self,
                wtxn,
                &bundle_ref,
                verb,
                verb_class,
                bundle_basis,
                now,
            )?;
            Ok((bundle_record, item_records, vad_claim_ids))
        })?;
        // Consent is committed before the consolidator opens its own writer.
        // Do not hide a VAD failure: Approved and its receipts remain durable.
        for claim_id in vad_claim_ids {
            self.consolidate_claim_vad_now(&claim_id, now)?;
        }

        let review_items = if verb == InboxBulkVerb::ReviewEach {
            targets
        } else {
            Vec::new()
        };
        Ok(InboxBundleResolution {
            group_key: group.group_key,
            verb,
            bundle_ref,
            bundle_receipt: gate_decision_receipt(&bundle_record),
            item_receipts: item_records.iter().map(gate_decision_receipt).collect(),
            review_items,
        })
    }

    /// Approves ONE pending member with the decider's edit (ED-01,
    /// ONE-1757): the AMENDED body is what lands, and the receipt records
    /// both that fact (`approved_amended`) and the ARCH-0056 Δ between what
    /// was proposed and what was approved.
    ///
    /// Without this door an approve-with-edit surface has nowhere to put the
    /// edit — the bulk verbs re-encode the EXISTING body, so every amendment
    /// was silently discarded and no edit ever reached a receipt.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] when the claim has no open pending row,
    /// [`GateError::GateConsentStale`](crate::error::GateError::GateConsentStale) when the reviewed content or policy floor
    /// drifted, and [`Error::InvalidClaimBody`] when the amendment does not
    /// decode or leaves the reviewed claim's predicate/subject.
    ///
    /// Dreamer members also run canonical VAD consolidation after commit. Its
    /// errors are returned without rolling back Approved, the edit, or receipts.
    /// Retry VAD through [`Vault::consolidate_claim_vad`] on the approved id;
    /// unchanged evidence is idempotent. The pending row is already closed, so
    /// retrying this approval door returns [`Error::EntityNotFound`]. Annotation
    /// and reappraisal predicates retain their canonical consolidation errors.
    pub fn approve_inbox_member_with_edit(
        &self,
        claim_id: &EntityId,
        amended_body: &[u8],
    ) -> Result<InboxAmendedApproval> {
        self.approve_inbox_member_with_edit_at(claim_id, amended_body, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::approve_inbox_member_with_edit`] with an
    /// explicit event time.
    ///
    /// # Errors
    ///
    /// As [`Vault::approve_inbox_member_with_edit`].
    pub fn approve_inbox_member_with_edit_at(
        &self,
        claim_id: &EntityId,
        amended_body: &[u8],
        now: u64,
    ) -> Result<InboxAmendedApproval> {
        let (approval, vad_claim_id) = self.with_write_txn(|wtxn| {
            let accepted = accept_member_with_amendment_in_txn(
                self,
                wtxn,
                claim_id,
                None,
                now,
                Some(amended_body),
            )?
            .ok_or(Error::EntityNotFound)?;
            let mut receipt = gate_decision_receipt(&accepted.record);
            // The Δ rides the same attach pass every receipt query uses, so
            // the door's own return and a later query cannot disagree about
            // it — and it rides it INSIDE the write txn, which is what keeps
            // the returned Result honest. Enriching after the commit meant a
            // read failure reported Err on a consent decision that had
            // already landed; here the same failure rolls it back.
            attach_amendment_deltas(self, wtxn, std::slice::from_mut(&mut receipt))?;
            Ok((
                InboxAmendedApproval {
                    claim_id: claim_id.to_hex(),
                    receipt,
                    delta: accepted.delta,
                },
                accepted.vad_claim_id,
            ))
        })?;
        if let Some(claim_id) = vad_claim_id {
            self.consolidate_claim_vad_now(&claim_id, now)?;
        }
        Ok(approval)
    }

    /// RS3 door: reopens the group behind a bundle receipt reference
    /// (`bundle:dreamer_run:<key>` or `dreamer_run:<key>`), returning the
    /// still-open remainder plus every receipt its bundles emitted.
    pub fn reopen_inbox_group(&self, door_ref: &str) -> Result<InboxGroupReopen> {
        self.reopen_inbox_group_at(door_ref, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::reopen_inbox_group`] with an explicit
    /// event time.
    pub fn reopen_inbox_group_at(&self, door_ref: &str, now: u64) -> Result<InboxGroupReopen> {
        let inner = door_ref
            .strip_prefix(INBOX_BUNDLE_REF_PREFIX)
            .unwrap_or(door_ref);
        let group_key = inner.strip_prefix(INBOX_GROUP_DOOR_PREFIX).ok_or_else(|| {
            Error::InvalidConfig("inbox door ref must reference a dreamer run".into())
        })?;
        let bundle_ref = bundle_ref_for_group(group_key);

        let open_group = explicit_inbox_group(self, group_key, now)?;

        let resolution_receipts = self
            .store
            .gate_decisions_for_grant_ref(&bundle_ref)?
            .iter()
            .map(gate_decision_receipt)
            .collect();

        Ok(InboxGroupReopen {
            group_key: group_key.to_owned(),
            open_group,
            resolution_receipts,
        })
    }
}

fn bundle_ref_for_group(group_key: &str) -> String {
    format!("{INBOX_BUNDLE_REF_PREFIX}{INBOX_GROUP_DOOR_PREFIX}{group_key}")
}

/// Redeems bundle consent on one member with no amendment.
fn accept_member_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    bundle_ref: &str,
    now: u64,
) -> Result<Option<AcceptedMember>> {
    accept_member_with_amendment_in_txn(vault, wtxn, id, Some(bundle_ref), now, None)
}

/// One accepted member: the resolution decision plus the Δ its amendment
/// measured (`None` on the untouched path, which has nothing to measure).
struct AcceptedMember {
    record: GateDecisionRecord,
    delta: Option<AmendmentDelta>,
    vad_claim_id: Option<EntityId>,
}

/// Redeems consent on one member: verifies the content-addressed binding
/// (stale on content or policy-floor drift), persists the approved body
/// through the one claim door (`apply_ops`), and emits the resolution
/// receipt.
///
/// `amended_body` is the approve-with-EDIT arm (ED-01, ONE-1757). The binding
/// is checked against the body the decider REVIEWED — consent was given on
/// that content, and the edit is the decider's own — after which the amended
/// body replaces it. Amendment lives entirely on the receipt
/// (`approved_amended` + the ARCH-0056 Δ): [`ClaimApprovalStatus`] gains no
/// `Amended` variant, so the claim's four-status enum and every reader of it
/// stay exactly as they were.
fn accept_member_with_amendment_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    bundle_ref: Option<&str>,
    now: u64,
    amended_body: Option<&[u8]>,
) -> Result<Option<AcceptedMember>> {
    let Some(pending) = vault.store.pending_gate_consent_in_txn(wtxn, id)? else {
        return Ok(None);
    };
    let Some(original) = vault
        .store
        .gate_decision_in_txn(wtxn, pending.decision_id)?
    else {
        return Err(Error::CorruptedIndex("pending gate consent"));
    };
    let Some(raw) = vault.store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::CorruptedIndex("pending gate consent"));
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let reviewed = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;

    let (diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(&vault.store, wtxn, &reviewed)?;
    if diff_handle != pending.diff_handle || read_frontier_hash != pending.read_frontier_hash {
        return Err(Error::Gate(GateError::GateConsentStale { claim_id: *id }));
    }

    let amended = amended_body
        .map(|body| amended_claim_body(&reviewed, body))
        .transpose()?;
    let amended_approval = amended.is_some();
    // Both sides are normalized to Approved before the Δ is measured, so it
    // reports the DECIDER's edit and not the approval flip this door performs
    // on every accept.
    let approved = approved_body(amended.as_ref().unwrap_or(&reviewed))?;
    let (delta, receipt_reasons) = if amended_approval {
        captured_amendment_delta(&approved_body(&reviewed)?, &approved)
    } else {
        (None, Vec::new())
    };

    if amended_approval || reviewed.approval != ClaimApprovalStatus::Approved {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                learned_at: header.learned_at,
                data: approved,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
    }

    // The gated rewrite may already have redeemed and removed the tray row;
    // the delete is idempotent either way.
    vault.store.delete_pending_gate_consent_in_txn(wtxn, id)?;
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: if amended_approval {
            OUTCOME_APPROVED_AMENDED.to_owned()
        } else {
            "approved".to_owned()
        },
        reason_codes: vec![
            if amended_approval {
                INBOX_REASON_AMEND_ACCEPT
            } else {
                INBOX_REASON_BUNDLE_ACCEPT
            }
            .to_owned(),
        ],
        receipt_reasons,
        system_notices: Vec::new(),
        actor_class: original.actor_class,
        actor_ref: original.actor_ref,
        content_kind: original.content_kind,
        policy_manifest_version: original.policy_manifest_version,
        claim_id: Some(pending.claim_id),
        grant_ref: bundle_ref.map(str::to_owned),
        diff_handle: pending.diff_handle,
        read_frontier_hash: pending.read_frontier_hash,
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(wtxn, &record)?;

    if let Some(delta) = delta.as_ref() {
        put_amendment_delta_in_txn(
            vault,
            wtxn,
            &gate_decision_receipt(&record).receipt_id,
            delta,
        )?;
    }
    Ok(Some(AcceptedMember {
        record,
        delta,
        vad_claim_id: pending.dreamer_run_id.is_some().then_some(*id),
    }))
}

/// Measures the amendment Δ, returning the receipt reasons that record a
/// capture failure.
///
/// Δ capture is TELEMETRY hanging off an approval that has already happened,
/// so a measurement failure is stamped on the receipt and the decision
/// stands. Blocking here would let a telemetry bug refuse a decision the
/// decider already made — and a receipt that says its Δ is missing is worth
/// more than one that silently has none.
pub(super) fn captured_amendment_delta(
    proposed: &[u8],
    approved: &[u8],
) -> (Option<AmendmentDelta>, Vec<String>) {
    match capture_delta_best(&DeltaCaptureContext::from_bodies(proposed, approved)) {
        Ok(delta) => (Some(delta), Vec::new()),
        Err(_) => (None, vec![INBOX_REASON_AMEND_DELTA_UNCAPTURED.to_owned()]),
    }
}

/// The claim body as the door will persist it. Approval is the ENGINE's to
/// set: a submitted body asserting its own approval decides nothing.
fn approved_body(body: &ClaimBody) -> Result<Vec<u8>> {
    let mut approved = body.clone();
    approved.approval = ClaimApprovalStatus::Approved;
    crate::claim::encode_claim_body(&approved)
}

/// Validates a decider's edit against the proposal it amends.
///
/// The body rides the SAME strict claim-body decode the original rode, and
/// must keep the proposal's IDENTITY — same predicate, same subject. That
/// pair is not decoration: `classify_member` derives the exception classes
/// from it (manifest-critical, supersedes-user_stated) and
/// `claim_consent_binding_parts` binds consent to it. An amendment that moved
/// either one would land a claim under a classification that never described
/// it, which is a substitution wearing an edit's clothes. Everything else —
/// value, confidence, validity, scope — is exactly what an edit is for.
fn amended_claim_body(reviewed: &ClaimBody, amended_body: &[u8]) -> Result<ClaimBody> {
    let amended = crate::claim::decode_claim_body(amended_body, true)?;
    if amended.predicate != reviewed.predicate {
        return Err(Error::InvalidClaimBody(
            "amendment changes the reviewed claim's predicate",
        ));
    }
    if amended.subject != reviewed.subject {
        return Err(Error::InvalidClaimBody(
            "amendment changes the reviewed claim's subject",
        ));
    }
    Ok(amended)
}

fn append_bundle_decision_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    bundle_ref: &str,
    verb: InboxBulkVerb,
    verb_class: Option<&str>,
    basis: &[GateDecisionRecord],
    now: u64,
) -> Result<GateDecisionRecord> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.inbox.bundle.v0");
    hasher.update(bundle_ref.as_bytes());
    hasher.update(verb.as_str().as_bytes());
    for record in basis {
        if let Some(claim_id) = record.claim_id {
            hasher.update(claim_id);
        }
    }

    // The decision ledger pins reason codes to the `gate.` namespace.
    let mut reason_codes = vec![format!("gate.consent.bundle.{}", verb.as_str())];
    if let Some(verb_class) = verb_class {
        reason_codes.push(format!("gate.consent.bundle.verb_class.{verb_class}"));
    }

    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: verb.bundle_outcome().to_owned(),
        reason_codes,
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: INBOX_BUNDLE_ACTOR_CLASS.to_owned(),
        actor_ref: None,
        content_kind: INBOX_BUNDLE_CONTENT_KIND.to_owned(),
        policy_manifest_version: basis.first().map_or_else(
            || "unversioned".to_owned(),
            |record| record.policy_manifest_version.clone(),
        ),
        claim_id: None,
        grant_ref: Some(bundle_ref.to_owned()),
        diff_handle: hasher.finalize().to_vec(),
        read_frontier_hash: basis
            .first()
            .map_or([0; 32], |record| record.read_frontier_hash),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(wtxn, &record)?;
    Ok(record)
}
