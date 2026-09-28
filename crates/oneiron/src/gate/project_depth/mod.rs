//! Immutable project-scoped policy-manifest contributions.
//! The mutable PROJECT body is membership; it never chooses a spawn ceiling.
mod codec;
mod fold;
mod write;

#[cfg(all(test, feature = "sync"))]
pub(crate) use codec::seeded_default_carrier;
pub(crate) use codec::{
    ProjectDepthContribution, canonical_birth, decode_contribution, is_project_depth_contribution,
    is_project_depth_id, validate_contribution_put,
};
#[cfg(all(test, feature = "sync"))]
pub(crate) use fold::resolve_creation_default;
pub(crate) use fold::{
    birth_for_project, implicit_birth_applies, resolve_project_depth, unsigned_birth_trusted,
};
pub(crate) use write::{put_edit_in_txn, put_local_birth_in_txn, put_signed_birth_in_txn};

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "sync"))]
pub(crate) use tests::contributions_for_test;
