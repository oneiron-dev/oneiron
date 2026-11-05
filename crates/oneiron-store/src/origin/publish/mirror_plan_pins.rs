//! The pins of automatic mirror push plans (FIX 7173): each open plan keeps
//! the objects it still sends behind its own keep owner
//! (`OriginKeepRefKind::MirrorWork`, the plan id), so a gc never takes one
//! that a same-plan resend needs.
//!
//! A plan pins before it is written (the physical-first pin protocol) and
//! releases once it settles; both run under the mirror's push hold, under
//! which alone a plan is frozen or settled. A plan forgotten, rebuilt away or
//! cleared, and one a crash left pinned before its row, is released by the
//! census, which sweeps only when it can take that hold at once. Only an
//! update whose object the mirror's ref did not hold when the plan read it
//! is pinned: a ref already there needs nothing kept. A pin or release that
//! fails only warns: a missing pin is the plan as it was before plans were
//! pinned, and a pin left behind keeps an object, never loses one.

use std::collections::BTreeSet;

use crate::git_wire::ids::GitOid;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::try_lock_repository;
use crate::origin::mirror_run::mirror_hold_dir;
use crate::origin::publication::publication_types::OriginKeepRefKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const KIND: OriginKeepRefKind = OriginKeepRefKind::MirrorWork;
