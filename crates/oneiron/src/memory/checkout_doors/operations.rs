use super::*;
use crate::batch::{EntityMetadataHeader, ENTITY_METADATA_HEADER_LEN};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::codebase::RepoRef;
use crate::checkout::lease::transactions as transition;
use crate::checkout::lease::teardown::{TeardownStep, teardown_through, prepare_teardown_in_txn};
use crate::task_verb::CheckoutTaskAccess;

impl Memory<'_> {
    fn checkout_readable_in(&self, txn: &heed::RoTxn<'_>, lane: &ScopedRead<'_>, ids: &[EntityId]) -> MemoryResult<()> {
        self.produced_from(ids.iter().copied());
        if lane.entities_readable_in_txn(txn, ids)?.into_iter().any(|readable| !readable) {
            return Err(MemoryError::not_found("checkout record is absent or withheld"));
        }
        Ok(())
    }

    fn checkout_act_in(&self, txn: &heed::RoTxn<'_>, id: CheckoutId) -> MemoryResult<CheckoutLeaseAct> {
        crate::checkout::lease::load_act_in_txn(self.vault(), txn, id)
            .map_err(refusal)?.ok_or_else(|| MemoryError::not_found("checkout not found"))
    }

    fn checkout_repo_in(&self, txn: &heed::RoTxn<'_>, lane: &ScopedRead<'_>, id: EntityId) -> MemoryResult<RepoRef> {
        self.checkout_readable_in(txn, lane, &[id])?;
        let raw = self.vault().get_raw_in(txn, &id)?.ok_or_else(|| MemoryError::not_found("code artifact not found"))?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(crate::Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
            return Err(MemoryError::bad_request("repo must be a CODE_ARTIFACT"));
        }
        let body = crate::code_artifact::decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let repo = RepoRef::parse(&body.repo_ref)?;
        if !matches!(repo, RepoRef::LocalFolder { .. }) {
            return Err(MemoryError::bad_request("a checkout needs a stored local repository pointer"));
        }
        Ok(repo)
    }

    fn checkout_check_in(&self, txn: &heed::RoTxn<'_>, lane: &ScopedRead<'_>, act: &CheckoutLeaseAct, access: CheckoutTaskAccess) -> MemoryResult<()> {
        if self.keeps_no_record() {
            return Err(MemoryError::new(crate::memory::MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
                "checkout custody keeps synced facts and cannot run off-record", &[]));
        }
        self.checkout_readable_in(txn, lane, &[act.task_ref])?;
        self.checkout_task_in(txn, act.task_ref, access)
    }

    pub fn checkout_claim_through<L: CheckoutLiveness>(&self, input: CheckoutClaimInput, live: &mut L) -> MemoryResult<CheckoutLeaseView> {
        positive_ttl(input.ttl_seconds)?;
        let id = checkout_id(&input.checkout)?;
        let task_class = class(input.task_class);
        if task_class.allows_ttl_reclaim() && !input.declared_idempotent {
            return Err(MemoryError::bad_request("build/verify TTL reclaim requires declared_idempotent"));
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (act, now, receipt) = self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().instant_in_write_txn(txn)?.secs();
            let repo = self.checkout_repo_in(txn, &lane, input.repo)?;
            self.checkout_readable_in(txn, &lane, &[input.task])?;
            self.checkout_task_in(txn, input.task, CheckoutTaskAccess::Claim)?;
            if self.keeps_no_record() { return Err(MemoryError::bad_request("checkout custody cannot run off-record")); }
            let act = transition::claim_in_txn(self.vault(), txn, CheckoutClaimRequest {
                checkout_id: id, task_ref: input.task, repo_ref: repo,
                holder_ref: self.actor().to_hex(), task_class,
                ttl_secs: Some(input.ttl_seconds), now,
            }).map_err(refusal)?;
            self.checkout_started_in(txn, &act, now)?;
            let receipt = self.checkout_receipt_in(txn, &act, "checkout.grant", &[], now)?;
            Ok((act, now, receipt))
        })?;
        self.vault().store.notify_task_updates([act.task_ref]);
        pulse(&act, live, now)?;
        view(act, now, Some(receipt))
    }

    pub fn checkout_get(&self, input: CheckoutGetInput) -> MemoryResult<CheckoutLeaseView> {
        let id = checkout_id(&input.checkout)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self.vault().store.env.read_txn().map_err(crate::Error::from)?;
        let act = self.checkout_act_in(&txn, id)?;
        self.checkout_check_in(&txn, &lane, &act, CheckoutTaskAccess::Read)?;
        let now = self.vault().instant_in_txn(&txn)?.secs();
        let receipt = self.checkout_receipt_exists_in(&txn, &act, "checkout.grant", &[])?;
        view(act, now, receipt)
    }

    pub fn checkout_renew_through<L: CheckoutLiveness>(&self, input: CheckoutRenewInput, live: &mut L) -> MemoryResult<CheckoutLeaseView> {
        positive_ttl(input.ttl_seconds)?;
        let f = fence(self, &input.checkout, input.epoch)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (act, now, receipt) = self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().instant_in_write_txn(txn)?.secs();
            let current = self.checkout_act_in(txn, f.checkout_id)?;
            self.checkout_check_in(txn, &lane, &current, CheckoutTaskAccess::Holder)?;
            let act = transition::renew_in_txn(self.vault(), txn, &f, input.ttl_seconds, now).map_err(refusal)?;
            let receipt = self.checkout_receipt_in(txn, &act, "checkout.renew", &now.to_le_bytes(), now)?;
            Ok((act, now, receipt))
        })?;
        pulse(&act, live, now)?;
        view(act, now, Some(receipt))
    }

    pub fn checkout_reclaim_through<L: CheckoutLiveness>(&self, input: CheckoutReclaimInput, live: &mut L) -> MemoryResult<CheckoutLeaseView> {
        self.checkout_take_through(&input.checkout, input.expired_epoch, false, live)
    }

    /// Explicit task-owner takeover, including effect tasks. Expiry never grants this act.
    pub fn checkout_takeover_through<L: CheckoutLiveness>(&self, input: CheckoutTakeoverInput, live: &mut L) -> MemoryResult<CheckoutLeaseView> {
        self.checkout_take_through(&input.checkout, input.expected_epoch, true, live)
    }

    fn checkout_take_through<L: CheckoutLiveness>(&self, checkout: &str, epoch: u64, manual: bool, live: &mut L) -> MemoryResult<CheckoutLeaseView> {
        let f = fence(self, checkout, epoch)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (act, now, receipt) = self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().instant_in_write_txn(txn)?.secs();
            let current = self.checkout_act_in(txn, f.checkout_id)?;
            self.checkout_check_in(txn, &lane, &current,
                if manual { CheckoutTaskAccess::Takeover } else { CheckoutTaskAccess::Reclaim })?;
            let (act, changed) = if current.holder_ref == f.holder_ref
                && epoch.checked_add(1) == Some(current.epoch)
            {
                transition::require_live(&current, now).map_err(refusal)?;
                (current, false)
            } else {
                transition::reclaim_in_txn(self.vault(), txn, f.checkout_id,
                    f.holder_ref.clone(), now, Some(epoch), manual).map_err(refusal)?
            };
            if changed { self.checkout_started_in(txn, &act, now)?; }
            let receipt = self.checkout_receipt_in(txn, &act, "checkout.grant", &[], now)?;
            Ok((act, now, receipt))
        })?;
        self.vault().store.notify_task_updates([act.task_ref]);
        pulse(&act, live, now)?;
        view(act, now, Some(receipt))
    }

    /// Publishes a candidate result identity, not a Git head or an approval.
    pub fn checkout_publish(&self, input: CheckoutPublishInput) -> MemoryResult<CheckoutPublished> {
        let f = fence(self, &input.checkout, input.epoch)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().instant_in_write_txn(txn)?.secs();
            let act = transition::fenced_in_txn(self.vault(), txn, &f).map_err(refusal)?;
            self.checkout_check_in(txn, &lane, &act, CheckoutTaskAccess::Holder)?;
            self.checkout_readable_in(txn, &lane, &[input.candidate])?;
            let identity = checkout_result_identity(f.checkout_id, f.epoch, &input.observed_ref, &input.candidate.to_hex());
            let receipt = match self.checkout_receipt_exists_in(txn, &act, "checkout.publish", &identity)? {
                Some(receipt) => receipt,
                None => {
                    transition::publish_in_txn(self.vault(), txn, &f, &input.observed_ref,
                        &input.candidate.to_hex(), now).map_err(refusal)?;
                    self.checkout_receipt_in(txn, &act, "checkout.publish", &identity, now)?
                },
            };
            Ok(CheckoutPublished { checkout: input.checkout.clone(), epoch: act.epoch,
                observed_ref: input.observed_ref.clone(), candidate: input.candidate,
                result_identity: hex(&identity), receipt })
        })
    }

    pub fn checkout_settle(&self, input: CheckoutSettleInput) -> MemoryResult<CheckoutSettled> {
        let f = fence(self, &input.checkout, input.epoch)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (answer, task, new) = self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().instant_in_write_txn(txn)?.secs();
            let act = transition::fenced_in_txn(self.vault(), txn, &f).map_err(refusal)?;
            self.checkout_check_in(txn, &lane, &act, CheckoutTaskAccess::Holder)?;
            self.checkout_readable_in(txn, &lane, &[input.candidate])?;
            let identity = checkout_result_identity(f.checkout_id, f.epoch, &input.observed_ref, &input.candidate.to_hex());
            if self.checkout_receipt_exists_in(txn, &act, "checkout.publish", &identity)?.is_none() {
                return Err(MemoryError::bad_request("publish the candidate under this epoch before settling it"));
            }
            let (act, receipt, new) = transition::settle_in_txn(self.vault(), txn, &CheckoutSettlementRequest {
                fence: f.clone(), disposition: action(input.action), observed_ref: input.observed_ref.clone(),
                result_ref: input.candidate.to_hex(), now,
            }).map_err(refusal)?;
            if new { self.checkout_settled_fact_in(txn, &act, receipt.disposition, input.candidate, now)?; }
            let answer = CheckoutSettled { checkout: input.checkout.clone(), epoch: receipt.epoch,
                observed_ref: receipt.observed_ref, candidate: input.candidate, action: input.action,
                result_identity: hex(&receipt.result_identity), receipt: hex(&receipt.receipt_id), settled_at: receipt.settled_at };
            Ok((answer, act.task_ref, new))
        })?;
        if new {
            self.vault().store.notify_task_updates([task]);
            if !matches!(input.action, CheckoutAction::Release) {
                self.checkout_signal_settled(task, answer.settled_at)?;
            }
        }
        Ok(answer)
    }

    pub fn checkout_teardown_through<L: CheckoutLiveness>(&self, input: CheckoutTeardownInput, live: &mut L) -> MemoryResult<CheckoutTornDown> {
        let f = fence(self, &input.checkout, input.epoch)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let initial = self.with_verified_actor_write_txn(|txn| {
            let act = transition::fenced_in_txn(self.vault(), txn, &f).map_err(refusal)?;
            self.checkout_check_in(txn, &lane, &act, CheckoutTaskAccess::Holder)?;
            Ok(act)
        })?;
        let wire = crate::git_wire::GitWire::new(self.vault())?;
        let RepoRef::LocalFolder { path, .. } = &initial.repo_ref else {
            return Err(MemoryError::bad_request("checkout is not a local repository"));
        };
        let identity = wire.repository_identity(std::path::Path::new(path))?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&identity.as_hex())?;
        let pushed = self.with_verified_actor_write_txn(|txn| {
            let act = transition::fenced_in_txn(self.vault(), txn, &f).map_err(refusal)?;
            self.checkout_check_in(txn, &lane, &act, CheckoutTaskAccess::Holder)?;
            self.checkout_pushed_receipt_in(txn, &act, repo_id, input.pushed_head_receipt)
        })?;
        let outcome = teardown_through(&f, &wire, live, |step, liveness| {
            self.with_verified_actor_write_txn(|txn| {
                let act = transition::fenced_in_txn(self.vault(), txn, &f).map_err(refusal)?;
                self.checkout_check_in(txn, &lane, &act, CheckoutTaskAccess::Holder)?;
                self.checkout_pushed_receipt_in(txn, &act, repo_id, input.pushed_head_receipt)?;
                let now = self.vault().instant_in_write_txn(txn)?.secs();
                match step {
                    TeardownStep::Prepare => prepare_teardown_in_txn(
                        self.vault(), txn, &f, pushed.as_ref(), &wire, liveness, now,
                    ).map_err(refusal),
                    TeardownStep::Finish => {
                        let act = transition::finish_teardown_in_txn(self.vault(), txn, &f, now).map_err(refusal)?;
                        self.checkout_released_fact_in(txn, act.task_ref, now)?;
                        Ok((act, None))
                    },
                }
            })
        })?;
        self.vault().store.notify_task_updates([initial.task_ref]);
        Ok(match outcome {
            CheckoutTeardownOutcome::Collected { checkout_id, epoch } => CheckoutTornDown::Collected { checkout: checkout_id.to_string(), epoch },
            CheckoutTeardownOutcome::Retained { checkout_id, epoch, reason } => CheckoutTornDown::Retained {
                checkout: checkout_id.to_string(), epoch, reason: match reason {
                    CheckoutRetainReason::MissingPushedHeadReceipt => CheckoutRetention::MissingPushedHeadReceipt,
                    CheckoutRetainReason::ReceiptMismatch => CheckoutRetention::ReceiptMismatch,
                    CheckoutRetainReason::LiveOccupant => CheckoutRetention::LiveOccupant,
                    CheckoutRetainReason::DirtyOrUncertain => CheckoutRetention::DirtyOrUncertain,
                },
            },
        })
    }

    fn checkout_pushed_receipt_in(&self, txn: &heed::RoTxn<'_>, act: &CheckoutLeaseAct, repo_id: EntityId, receipt: Option<EntityId>) -> MemoryResult<Option<PushedHeadReceipt>> {
        let Some(id) = receipt else { return Ok(None); };
        let row = self.vault().origin_publication_in_txn(txn, id)?
            .ok_or_else(|| MemoryError::not_found("pushed-head publication receipt not found"))?;
        if row.status != crate::origin::publication::OriginPublicationStatus::Published
            || row.repo_id != repo_id || row.actor_id.id() != Some(self.actor())
            || row.finished_at.is_none_or(|at| at < act.claimed_at)
        {
            return Err(MemoryError::bad_request("pushed-head receipt does not bind this holder, repository and lease"));
        }
        Ok(Some(PushedHeadReceipt { receipt_ref: id.to_hex(), observed_ref: row.ref_name.as_str().to_owned(),
            pushed_head: row.new_oid.as_str().to_owned(), checkout_id: act.checkout_id, epoch: act.epoch }))
    }
}

fn positive_ttl(ttl: u64) -> MemoryResult<()> {
    if ttl == 0 { return Err(MemoryError::bad_request("ttl_seconds must be positive")); }
    Ok(())
}
