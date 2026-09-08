//! Equivocation and fork detection, ranking, quarantine, and restore markers.
//!
//! MUST BE READ TOGETHER WITH [`super::entry_transition`]. The two files are
//! mutually recursive by direct call — [`resolve_equivocation_group`] calls
//! [`super::entry_transition::fold_entry_state`], which calls back into the
//! quarantine and global-fork-resolution helpers here. Any fork, quorum, or
//! equivocation correctness change has to be reasoned about across both files;
//! the file boundary is a readability split, not a decoupling.

mod ancestry_bypass;
mod equivocation_core;
mod quarantine_gate;
mod restore_rank;

pub(super) use self::ancestry_bypass::{
    entry_folds_on_available_ancestry, entry_waits_on_unresolved_equivocation,
    revocation_bypass_states,
};
pub(super) use self::equivocation_core::{
    EntryFold, EquivocationResolution, build_fork_alarms, reconcile_reported_authority_forks,
    resolve_equivocation_group,
};
pub(super) use self::quarantine_gate::{
    key_is_quarantined_for_entry, resolve_global_forks_for_recovery_reboot,
    resolve_global_forks_for_revoke,
};
pub(super) use self::restore_rank::{entry_ancestor_index, restore_prefix_divergence};
