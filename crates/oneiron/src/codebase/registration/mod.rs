//! FIX 4299 (CODE-CUSTODY-01): a registered repository with a stable
//! identity and an enforced editable whitelist.
//!
//! The owner registers a repository through `vault.repo.anchor.bind`. A
//! registration is one stable CODE_ARTIFACT record with a `belongs_to` edge
//! to a live PROJECT. It is minted once and returned; a later config update
//! names that id. Its body retains the source and the editable whitelist
//! ([`CodeRepoRegistration`]). Its portable id ([`RepoPortableId`]) is
//! minted in the same checked writer, so a registration that succeeds
//! names both. A served repo registers on the anchor its served bind made
//! ([`crate::Vault::bind_served_repo_anchor_with`]); an external local Git
//! repository gets a fresh CODE id ([`local`]).
//!
//! - A capture of a registered repository names its anchor, and its scope
//!   derives from that anchor, never from the commit ([`capture`]). The
//!   importer reads the registered source in its final writer, never a
//!   caller's whitelist. An unregistered capture names no anchor and
//!   confers no edit authority.
//! - The whitelist is an edit ceiling, not a read filter. Every changed path
//!   must be on it, beside the current Grant's editable globs, at each final
//!   write admission ([`ceiling`]). The ceiling judges by folder, so a
//!   capture that names no anchor does not escape it.
//! - Registration grants nobody membership: a Grant still admits a member.

mod capture;
mod ceiling;
mod local;

pub(crate) use self::capture::CaptureRepository;
pub(crate) use self::ceiling::proposed_file_paths;

use crate::entity_id::EntityId;
use crate::origin::RepoPortableId;
use crate::store::code_repo_registration::CodeRepoRegistration;

/// What a registration writer leaves standing (FIX 4299).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredRepository {
    /// The stable CODE anchor.
    pub(crate) repo: EntityId,
    /// The live PROJECT it belongs to.
    pub(crate) project: EntityId,
    /// Its portable id, minted in the same writer.
    pub(crate) portable: RepoPortableId,
    /// Its retained configuration; `None` for a served anchor bound with
    /// none, which keeps no edit ceiling.
    pub(crate) registration: Option<CodeRepoRegistration>,
    /// Whether this call changed the anchor, its edge, its configuration or
    /// its portable id.
    pub(crate) changed: bool,
}
