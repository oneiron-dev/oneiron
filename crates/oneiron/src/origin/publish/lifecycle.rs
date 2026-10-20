//! Reading, approving and cancelling an exact publish request (FIX 6866).
//!
//! Every verb first admits its caller to the repo, then reads the request,
//! then admits the act over the request's whole review in its own snapshot:
//! a Grant holder who may not read every reviewed path may not read, approve
//! or cancel the request either. An approval names the review digest it was
//! given and binds the approver's owner or Grant; no second human yes is
//! asked. A request has no default expiry: only its caller's, a cancel or a
//! refusal at dispatch ends it unspent (CALLS "FIX 6866 request lifetime").

use super::PublishScope;
use super::authority::{OriginPublishCaller, PublishAnswer, PublishMember, PublishTarget};
use super::inputs::{
    OriginPublishApproveRequest, OriginPublishIdRequest, OriginPublishReviewRequest,
    OriginPublishReviewView,
};
use super::types::{OriginPublishAct, OriginPublishRequestView, OriginPublishState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// A caller admitted to one request: the repo, how, and the request.
type Admitted<'v> = (PublishScope<'v>, PublishMember, OriginPublishRequestView);

const OPEN: [OriginPublishState; 2] = [OriginPublishState::Pending, OriginPublishState::Approved];

impl Vault {
    /// One request, as it stands.
    pub fn origin_publish_get(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishIdRequest,
    ) -> Result<PublishAnswer<OriginPublishRequestView>> {
        let admitted =
            self.admitted_publish_request(caller, &input.repo, input.request_id, input.code_repo)?;
        Ok(admitted.map(|(_, _, view)| view))
    }

    /// One page of a request's review.
    pub fn origin_publish_review(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishReviewRequest,
    ) -> Result<PublishAnswer<OriginPublishReviewView>> {
        let (_, _, view) = match self.admitted_publish_request(
            caller,
            &input.repo,
            input.request_id,
            input.code_repo,
        )? {
            Ok(admitted) => admitted,
            Err(denial) => return Ok(Err(denial)),
        };
        let items = if view.review.pages == 0 && input.page == 0 {
            Vec::new()
        } else if input.page < view.review.pages {
            let txn = self.store.env.read_txn()?;
            self.publish_review_page_in_txn(&txn, &view, input.page)?
                .ok_or(Error::CorruptedIndex("origin publish review page"))?
                .items
        } else {
            return Err(Error::InvalidConfig(format!(
                "the review has {} pages; page {} is past its last",
                view.review.pages, input.page
            )));
        };
        Ok(Ok(OriginPublishReviewView {
            request_id: view.request_id,
            digest: view.review.digest,
            page: input.page,
            pages: view.review.pages,
            items,
        }))
    }

    /// Approves a pending request's reviewed tuple: the digest named must be
    /// the request's. An approved request answers as it stands.
    pub fn origin_publish_approve(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishApproveRequest,
    ) -> Result<PublishAnswer<OriginPublishRequestView>> {
        let (_, member, view) = match self.admitted_publish_request(
            caller,
            &input.repo,
            input.request_id,
            input.code_repo,
        )? {
            Ok(admitted) => admitted,
            Err(denial) => return Ok(Err(denial)),
        };
        match view.state {
            OriginPublishState::Pending => {}
            OriginPublishState::Approved => return Ok(Ok(view)),
            other => {
                return Err(Error::Refused(format!(
                    "the request is {other:?}; only a pending request is approved"
                )));
            }
        }
        if input.review_digest != view.review.digest {
            return Err(Error::Refused(
                "review_changed: that digest is not this request's review; read its review \
                 again and approve the digest it names"
                    .to_owned(),
            ));
        }
        if super::expired(&view, self.now_recorded_at()) {
            let expired = self.settle_publish(&view, &OPEN, OriginPublishState::Expired, None)?;
            return Ok(Ok(expired));
        }
        let mut txn = self.store.env.write_txn()?;
        let authority = match self.admit_publish_act_in_txn(
            &txn,
            caller,
            &member,
            PublishTarget::of(&view),
            || self.publish_review_paths_in_txn(&txn, &view),
        )? {
            Ok(authority) => authority,
            Err(denial) => return Ok(Err(denial)),
        };
        let act = OriginPublishAct {
            actor: Some(caller.actor),
            class: caller.class.into(),
            authority,
            at: self.now_recorded_at(),
        };
        let (approved, _) = self.transition_publish_in_txn(
            &mut txn,
            &view,
            &[OriginPublishState::Pending],
            OriginPublishState::Approved,
            |row| row.approved = Some(act),
        )?;
        txn.commit()?;
        Ok(Ok(approved))
    }

    /// Cancels a pending or approved request. A settled request answers as
    /// it stands; one whose push is in flight is refused.
    pub fn origin_publish_cancel(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishIdRequest,
    ) -> Result<PublishAnswer<OriginPublishRequestView>> {
        let (_, _, view) = match self.admitted_publish_request(
            caller,
            &input.repo,
            input.request_id,
            input.code_repo,
        )? {
            Ok(admitted) => admitted,
            Err(denial) => return Ok(Err(denial)),
        };
        if view.state == OriginPublishState::Dispatching {
            return Err(Error::Refused(
                "the request's one push is in flight; it settles from what the mirror holds"
                    .to_owned(),
            ));
        }
        if view.state.is_terminal() {
            return Ok(Ok(view));
        }
        let cancelled = self.settle_publish(&view, &OPEN, OriginPublishState::Cancelled, None)?;
        Ok(Ok(cancelled))
    }

    /// Admits `caller` to the repo, reads the request, then admits the act
    /// over the request's whole review in one snapshot. A Grant holder's
    /// request of another repo handle is not found, as a missing one is.
    pub(super) fn admitted_publish_request(
        &self,
        caller: &OriginPublishCaller<'_>,
        repo: &str,
        request_id: EntityId,
        code_repo: Option<EntityId>,
    ) -> Result<PublishAnswer<Admitted<'_>>> {
        let scope = self.publish_scope(repo)?;
        let member = match self.admit_publish_member(&scope, caller, code_repo)? {
            Ok(member) => member,
            Err(denial) => return Ok(Err(denial)),
        };
        let view = self
            .publish_request(scope.repo_id, request_id)?
            .ok_or(Error::EntityNotFound)?;
        if matches!(member, PublishMember::Grant { .. }) && view.code_repo != code_repo {
            return Err(Error::EntityNotFound);
        }
        let txn = self.store.env.read_txn()?;
        let admitted =
            self.admit_publish_act_in_txn(&txn, caller, &member, PublishTarget::of(&view), || {
                self.publish_review_paths_in_txn(&txn, &view)
            })?;
        drop(txn);
        Ok(admitted.map(|_| (scope, member, view)))
    }
}
