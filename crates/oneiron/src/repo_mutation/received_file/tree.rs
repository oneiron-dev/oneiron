//! The old paths of the bundle tree helpers, which moved to
//! `repo_mutation/bundle/tree.rs` under bundle names (FIX 10928).

#[allow(unused_imports)]
pub(crate) use super::super::bundle::tree::{
    BundleTreeEdit as ReceivedTreeEdit, bundle_tree_edits as received_tree_edits,
    stage_bundle_tree_edits as stage_received_tree_edits,
};
#[allow(unused_imports)]
pub(in crate::repo_mutation) use super::super::bundle::tree::{
    apply_prepared_bundle_files as apply_prepared_received_files,
    bundle_post_snapshot as received_post_snapshot,
    prepare_bundle_files_commit as prepare_received_files_commit,
};
