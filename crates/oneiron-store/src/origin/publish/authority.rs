//! Who acts on an exact publish request (FIX 6866; CALLS "FIX 6866
//! approval" and "FIX 6866 grant destination").
//!
//! The vault's live owner, from any linked surface, acts on every request.
//! Anyone else acts only under ONE live agent Grant, judged in the snapshot
//! the act commits in by [`Vault::admit_origin_publish_grant_in_txn`]: G1's
//! read admission (FIX 6867), over the same live candidate Grants
//! (`admit_repo_read_passing_in_txn`), must admit the request's branch over
//! EVERY path its review names under that Grant's repo bounds, and the same
//! Grant's Scope must list `publish` (`publish_rewrite` too, for a rewrite).
//! The first Grant meeting both stands, so a read-only Grant never masks a
//! publishing one. The destination is the repository's one
//! owner-configured mirror; the repo bounds gain no field. Grants are never
//! combined, the outer `Result` is a store error and never "no membership",
//! and the Grant's id is bound on the act and checked again at dispatch. A
//! caller is admitted to the repo handle before anything it names is read.
//! Mirror setup and strategy stay the owner's alone.

use std::collections::BTreeSet;
use std::path::Path;

use crate::code_snapshot::repo_ref::RepoRef;
use oneiron_authority::federation::{RepoAccessRefusal, RepoTarget, ScopeAxis};
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The verb class a Grant's Scope lists to publish within its repo bounds.
pub const ORIGIN_PUBLISH_GRANT_VERB: &str = "publish";

/// The verb class a Grant's Scope lists, beside `publish`, to rewrite a
/// mirror branch's history.
pub const ORIGIN_PUBLISH_REWRITE_GRANT_VERB: &str = "publish_rewrite";

/// A caller refused before its act: the stable code and a plain message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPublishDenial {
    pub code: &'static str,
    pub message: String,
}

/// A publish verb's answer, or its caller's denial. The outer `Result` of
/// each publish entry point is a store or input error.
pub type PublishAnswer<T> = std::result::Result<T, OriginPublishDenial>;

/// What a caller's admission to the repo found.
pub enum PublishMember {
    Owner,
    /// One Grant admits the caller to the repo handle whose anchor serves
    /// this repository.
    Grant {
        anchor: RepoRef,
    },
}

/// The one Grant an act stands on, and the anchor's repo it read.
pub struct OriginPublishGrant {
    pub grant: EntityId,
    pub repo_ref: RepoRef,
}

pub fn denial(code: &'static str, message: impl Into<String>) -> OriginPublishDenial {
    OriginPublishDenial {
        code,
        message: message.into(),
    }
}

pub fn repo_denial(refused: RepoAccessRefusal) -> OriginPublishDenial {
    denial(refused.public_code(), refused.message())
}
