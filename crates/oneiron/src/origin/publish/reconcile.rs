//! An exact publish's outbound IO and its settlement (FIX 6866; CALLS "FIX
//! 6866 retry" and "FIX 6866 unknown remote tip").
//!
//! The mirror's token leaves custody only through the custody door, bound to
//! the mirror push effector, and reaches git only as one child's header.
//! Each request is pushed at most once. A push that did not prove its own
//! outcome is settled from an authenticated read of the branch, never by a
//! second send: the commit there is `observed_published`; the leased tip
//! there is `rejected` after the mirror's own refusal, else
//! `outcome_unknown`; anything else is `remote_moved`. A branch that cannot
//! be read leaves the request dispatching until a later call reads it. A
//! claimed request is settled by another call only once the mirror's push
//! hold, which its push's child inherits, is free (FIX 7045).

use std::path::Path;

use base64::Engine as _;

use super::PublishScope;
use super::types::{
    OriginPublishDestination, OriginPublishRefusal, OriginPublishRefusalReason,
    OriginPublishRemote, OriginPublishRequestView, OriginPublishState,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitPublishPushOutcome, GitRefName, GitRemoteTip, GitWire, GitWireRepo,
    try_lock_repository,
};
use crate::origin::mirror::ORIGIN_MIRROR_PUSH_EFFECTOR;
use crate::origin::mirror_run::mirror_hold_dir;
use crate::origin::publication::OriginKeepRefKind;

/// The longest redacted cause a refusal carries.
const MAX_DETAIL_BYTES: usize = 256;

impl Vault {
    /// Reads `name` at the request's mirror with the mirror's credential.
    pub(super) fn read_publish_remote(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        destination: &OriginPublishDestination,
        name: &GitRefName,
    ) -> Result<GitRemoteTip> {
        let mut answer = Err(Error::InvariantViolation("publish remote read never ran"));
        self.with_publish_credential(destination, &mut |header| {
            answer = wire.read_remote_branch(handle, &destination.url, name, header);
        })?;
        answer
    }

    /// The request's one push: exactly `commit` to `name`, leased on
    /// `expected`, in a child that inherits the mirror's push hold `hold`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one exact push binds its repository, mirror, branch, commit, lease and hold"
    )]
    pub(super) fn push_publish_once(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        destination: &OriginPublishDestination,
        name: &GitRefName,
        commit: &GitOid,
        expected: Option<&GitOid>,
        hold: &Path,
    ) -> Result<GitPublishPushOutcome> {
        let mut answer = Err(Error::InvariantViolation("publish push never ran"));
        self.with_publish_credential(destination, &mut |header| {
            answer = wire.push_publish(
                handle,
                &destination.url,
                name,
                commit,
                expected,
                hold,
                header,
            );
        })?;
        answer
    }

    /// Runs `apply` with the mirror's basic-auth header, inside the door.
    pub(super) fn with_publish_credential(
        &self,
        destination: &OriginPublishDestination,
        apply: &mut dyn FnMut(&str),
    ) -> Result<()> {
        let user = destination.user.clone();
        self.inject_secret_at_door(
            &destination.secret_ref,
            ORIGIN_MIRROR_PUSH_EFFECTOR,
            &mut |token: &[u8]| {
                let mut credential =
                    zeroize::Zeroizing::new(Vec::with_capacity(user.len() + 1 + token.len()));
                credential.extend_from_slice(user.as_bytes());
                credential.push(b':');
                credential.extend_from_slice(token);
                let header = zeroize::Zeroizing::new(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credential.as_slice())
                ));
                apply(&header);
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Settles a claimed request from its one push's outcome.
    pub(super) fn settle_publish_push(
        &self,
        scope: &PublishScope<'_>,
        handle: &GitWireRepo,
        view: &OriginPublishRequestView,
        outcome: Result<GitPublishPushOutcome>,
    ) -> Result<OriginPublishRequestView> {
        let (rejected, detail) = match outcome {
            Ok(GitPublishPushOutcome::Applied) => {
                return self.settle_publish(
                    view,
                    &[OriginPublishState::Dispatching],
                    OriginPublishState::Published,
                    None,
                );
            }
            Ok(GitPublishPushOutcome::Rejected(detail)) => (true, detail),
            Ok(GitPublishPushOutcome::Unknown(detail)) => (false, detail),
            Err(error) => (false, error.to_string()),
        };
        self.settle_from_mirror(scope, handle, view, rejected, Some(detail))
    }

    /// A dispatching request settled from the mirror once its push has
    /// ended: the mirror's push hold is free. The dispatch held it from its
    /// claim to its push's end and the push's child inherited it, so a free
    /// hold proves no push of it still runs, a child orphaned by its host's
    /// death included. While another holds it, the request is answered as
    /// it stands; none is sent again.
    pub(super) fn settle_stale_dispatch(
        &self,
        scope: &PublishScope<'_>,
        view: OriginPublishRequestView,
    ) -> Result<OriginPublishRequestView> {
        let Ok(handle) = scope.handle_at(&GitOid::parse_hex(view.commit.clone())?) else {
            return Ok(view);
        };
        let Some(_held) = try_lock_repository(&mirror_hold_dir(&handle)?)? else {
            return Ok(view);
        };
        self.settle_from_mirror(scope, &handle, &view, false, None)
    }

    /// Reads the branch and settles the claimed request from what it holds.
    fn settle_from_mirror(
        &self,
        scope: &PublishScope<'_>,
        handle: &GitWireRepo,
        view: &OriginPublishRequestView,
        rejected: bool,
        detail: Option<String>,
    ) -> Result<OriginPublishRequestView> {
        let name = GitRefName::parse_full(view.ref_name.clone())?;
        let Ok(observed) = self.read_publish_remote(&scope.wire, handle, &view.destination, &name)
        else {
            return Ok(view.clone());
        };
        let expected = expected_oid(&view.expected_remote)?;
        let from = [OriginPublishState::Dispatching];
        if observed.oid().map(GitOid::as_str) == Some(view.commit.as_str()) {
            return self.settle_publish(view, &from, OriginPublishState::ObservedPublished, None);
        }
        let reason = if observed.oid() != expected.as_ref() {
            OriginPublishRefusalReason::RemoteMoved
        } else if rejected {
            OriginPublishRefusalReason::Rejected
        } else {
            OriginPublishRefusalReason::OutcomeUnknown
        };
        let refusal = refusal(reason, Some(&observed), Vec::new(), detail);
        self.settle_publish(view, &from, OriginPublishState::Refused, Some(refusal))
    }

    /// Pins the request's commit behind its own keep-ref owner, before the
    /// request is recorded (the physical-first pin protocol).
    pub(super) fn pin_publish_commit(
        &self,
        scope: &PublishScope<'_>,
        handle: &GitWireRepo,
        request_id: crate::entity_id::EntityId,
        commit: &GitOid,
    ) -> Result<()> {
        self.pin_origin_object(
            &scope.wire,
            handle,
            OriginKeepRefKind::PublishRequest,
            &request_id.to_hex(),
            commit,
            self.now_recorded_at(),
        )
        .map(drop)
    }

    /// Releases a settled request's pin. A release that cannot run leaves a
    /// keep-ref behind, never a missing object, so it only warns.
    pub(super) fn release_publish_pin(&self, view: &OriginPublishRequestView) {
        let released = (|| {
            let scope = self.publish_scope(&view.repo)?;
            let commit = GitOid::parse_hex(view.commit.clone())?;
            let handle = scope.handle_at(&commit)?;
            self.unpin_origin_object(
                &scope.wire,
                &handle,
                OriginKeepRefKind::PublishRequest,
                &view.request_id.to_hex(),
                &commit,
                self.now_recorded_at(),
            )
        })();
        if let Err(error) = released {
            tracing::warn!(kind = ?error.kind(), "publish request pin was not released");
        }
    }
}

/// The commit a request's lease expects at the branch; `None`: absent.
pub(super) fn expected_oid(remote: &OriginPublishRemote) -> Result<Option<GitOid>> {
    match remote {
        OriginPublishRemote::Absent => Ok(None),
        OriginPublishRemote::At { commit } => Ok(Some(GitOid::parse_hex(commit.clone())?)),
    }
}

/// The wire form of what a read saw.
pub(super) fn remote_of(tip: &GitRemoteTip) -> OriginPublishRemote {
    match tip {
        GitRemoteTip::Absent => OriginPublishRemote::Absent,
        GitRemoteTip::At(oid) => OriginPublishRemote::At {
            commit: oid.as_str().to_owned(),
        },
    }
}

/// A typed refusal with a bounded, redacted cause.
pub(super) fn refusal(
    reason: OriginPublishRefusalReason,
    observed: Option<&GitRemoteTip>,
    changed_fields: Vec<String>,
    detail: Option<String>,
) -> OriginPublishRefusal {
    OriginPublishRefusal {
        reason,
        observed: observed.map(remote_of),
        changed_fields,
        detail: detail.map(|mut text| {
            let mut cut = text.len().min(MAX_DETAIL_BYTES);
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text
        }),
    }
}
