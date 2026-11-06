//! The review section of one whole ref an automatic mirror plan pushes (FIX
//! 6866 part 2; CALLS "FIX 6866 automatic review record").
//!
//! A commit tip's section is an exact publish's full-ancestry review
//! (`review`): `Reach(new) - Reach(the tip the plan read)`, with every merge
//! parent and each path, mode and object each commit introduces against each
//! parent; the tip is subtracted only when this store holds it as a commit,
//! else the section covers the whole closure. A plan reviews its refs in
//! order, and a later ref leaves out what an earlier ref's section already
//! names, so the plan's pages hold the union once while each ref keeps its
//! own section. A tag tip names each annotated tag on its way first, its raw
//! bytes (message included) in the digest, or for a tag too large to read
//! whole its oid and size; a tree tip names every path it
//! holds; a blob tip names itself. Every section passes the one history
//! policy hook an exact publish's review passes.

use std::collections::BTreeSet;

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::publish::mirror_plan_types::MirrorObservedTip;
use oneiron_base::error::Result;

/// A section digest's BLAKE3 derive-key context.
pub const ORIGIN_MIRROR_REVIEW_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-review:v1";
