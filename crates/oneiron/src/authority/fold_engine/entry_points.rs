//! The fold's entry points: the reference, seen-time, posture, peer and
//! local-observation variants over `fold_authority_log_inner`.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Folds a set of authority entries into a deterministic roster.
///
/// No local seen-times, so the stale-roster window never expires an approval;
/// callers with local seen-time data should use
/// [`fold_authority_log_with_seen_times`].
pub fn fold_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        &peer_consent_roots,
        folded_device_can_authority_consent,
        FoldLocalInputs::VAULT_DOOR,
    )
}

// Historical signed-history reference for unit tests of pre-handoff ancestry.
// Never used by Vault, peers, cache, replay admission, or public authorization.
#[cfg(test)]
pub(in crate::authority) fn fold_legacy_authority_log(
    entries: &[AuthorityLogEntry],
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs::default(),
    )
}

#[cfg(test)]
pub(in crate::authority) fn fold_legacy_authority_log_with_seen_times(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs::default(),
    )
}

#[cfg(test)]
pub(in crate::authority) fn fold_legacy_peer_authority_log(
    entries: &[AuthorityLogEntry],
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_peer_device_is_consent_root,
        FoldLocalInputs::default(),
    )
}

/// Folds authority entries using local first-seen timestamps for the
/// stale-roster approval window.
///
/// `first_seen_at_secs` is keyed by authority entry hash and must be sourced
/// from the local device's monotonic first-observation time. An entry missing a
/// timestamp never starts a stale-roster window. No entry waits on its
/// timestamp: every op lands the moment its ancestry folds.
pub fn fold_authority_log_with_seen_times(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
) -> AuthorityFold {
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_with_peer_consent_roots(
        entries,
        first_seen_at_secs,
        now_secs,
        &peer_consent_roots,
    )
}

/// [`fold_authority_log_with_seen_times`] with the consent roots of every
/// admitted peer roster in scope for FED-01 gesture acceptance.
///
/// The local fold is otherwise IDENTICAL — same consent arm, same roster, same
/// vault id. `peer_consent_roots` only widens which peer signature a lifecycle
/// gesture may carry, and only for the peer vault the gesture already names.
pub(crate) fn fold_authority_log_with_peer_consent_roots(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        peer_consent_roots,
        folded_device_can_authority_consent,
        FoldLocalInputs::VAULT_DOOR,
    )
}

/// [`fold_authority_log`] under this vault's hosting posture: the fold a door of the
/// vault's own log uses when it has no seen-times. A Hosted root is cloud-stamped, and
/// the self-host arm would refuse that genesis.
pub(crate) fn fold_own_authority_log(
    entries: &[AuthorityLogEntry],
    posture: crate::HostingPrivacyPosture,
) -> AuthorityFold {
    let consent = if posture == crate::HostingPrivacyPosture::Hosted {
        folded_host_device_can_consent
    } else {
        folded_device_can_authority_consent
    };
    fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        consent,
        FoldLocalInputs {
            hosted: posture == crate::HostingPrivacyPosture::Hosted,
            ..FoldLocalInputs::VAULT_DOOR
        },
    )
}

/// Folds under the vault's explicit hosting posture. Relay and self-host retain
/// owner-device consent; only managed hosts may treat a cloud key as root.
pub fn fold_authority_log_for_posture(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    posture: crate::HostingPrivacyPosture,
) -> AuthorityFold {
    let consent = if posture == crate::HostingPrivacyPosture::Hosted {
        folded_host_device_can_consent
    } else {
        folded_device_can_authority_consent
    };
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        peer_consent_roots,
        consent,
        FoldLocalInputs {
            hosted: posture == crate::HostingPrivacyPosture::Hosted,
            ..FoldLocalInputs::VAULT_DOOR
        },
    )
}

/// Peer-side roster fold: same fold machinery, same transcript domain, two
/// swaps.
///
/// The consent arm becomes the unfiltered host-root predicate
/// (`folded_peer_device_is_consent_root`), and there are no seen-times: peer
/// entries carry no local first-observation time, so no local stale-roster
/// window applies, and they stay inside the peer fold's own epoch semantics.
///
/// The output is evidence, not authority: it never enters the local roster.
#[must_use]
pub fn fold_peer_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        &peer_consent_roots,
        folded_peer_device_is_consent_root,
        FoldLocalInputs::VAULT_DOOR,
    )
}

/// The reference fold under the vault's local observations (sequence floors
/// and observation policy) and hosting posture.
pub(in crate::authority) fn fold_authority_log_with_local_observations_and_posture(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    observations: &AuthorityLocalObservations,
    posture: crate::HostingPrivacyPosture,
) -> AuthorityFold {
    let consent = if posture == crate::HostingPrivacyPosture::Hosted {
        folded_host_device_can_consent
    } else {
        folded_device_can_authority_consent
    };
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        peer_consent_roots,
        consent,
        FoldLocalInputs {
            observations: Some(observations),
            hosted: posture == crate::HostingPrivacyPosture::Hosted,
            ..FoldLocalInputs::VAULT_DOOR
        },
    )
}
