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

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::publish_push::GitPublishPushOutcome;
use crate::git_wire::publish_push::GitRemoteTip;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::try_lock_repository;
use crate::origin::mirror::ORIGIN_MIRROR_PUSH_EFFECTOR;
use crate::origin::mirror_run::mirror_hold_dir;
use crate::origin::publication::publication_types::OriginKeepRefKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The longest redacted cause a refusal carries.
pub const MAX_DETAIL_BYTES: usize = 256;
