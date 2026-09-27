//! Immutable project-scoped policy-manifest contributions.
//! The mutable PROJECT body is membership; it never chooses a spawn ceiling.
mod codec;
mod fold;
mod write;

pub(crate) use codec::{
    ProjectDepthContribution, decode_contribution, is_project_depth_contribution,
    is_project_depth_id, locally_seeded_birth, seeded_default_carrier, validate_contribution_put,
};
pub(crate) use fold::{
    ProjectDepthDisposition, birth_for_project, resolve_creation_default, resolve_project_depth,
};
pub(crate) use write::{put_birth_in_txn, put_edit_in_txn, put_signed_birth_in_txn};

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "sync"))]
pub(crate) use tests::contributions_for_test;
