//! The remote half of an automatic mirror push plan (FIX 6866 part 2): the
//! authenticated read of what the mirror holds at a plan's refs, and the
//! push of some of a plan's refs exactly as frozen. Both go through the
//! custody door bound to `origin:mirror-push`, whose token reaches git only
//! as the one child's header, and both ride the mirror push's fixed
//! outbound profile (`git_wire::mirror_plan_push`).

use std::collections::BTreeMap;

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::mirror_plan_push::GitPlanPushReport;
use crate::git_wire::mirror_plan_push::GitPlanRef;
use crate::origin::publish::mirror_plan_types::MirrorObservedTip;
use crate::origin::publish::secret_hold::MirrorPlanSend;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The longest redacted cause a plan keeps.
pub const MIRROR_PLAN_MAX_DETAIL_BYTES: usize = 256;

/// A cause cut to [`MIRROR_PLAN_MAX_DETAIL_BYTES`] on a character boundary.
pub fn bounded(mut text: String) -> String {
    let mut cut = text.len().min(MIRROR_PLAN_MAX_DETAIL_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}
