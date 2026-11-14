//! Single-vault selector grant scope shared by handler and livequery (FIX 9251),
//! and the scope each socket checks its selectors under (MEMBER-SYNC D2).

use std::sync::Arc;

use oneiron::sync::SyncSelector;

/// The grant scope this single-vault selector server path checks: the one an
/// owner's own-device grant is minted under (FIX 3134). Distinct from the
/// lease ABI's internal vault id. A socket asks its [`SelectorLane`] instead;
/// this stays the scope of paths no socket carries (LFS over HTTP) and of
/// owner-machine calls a member lane never reaches.
pub(crate) fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::federation::own_device_residence_scope()
}

/// The lane a sync socket checks every selector it is sent on (MEMBER-SYNC
/// D2, D3), fixed at its upgrade: an owner's own device under the own-device
/// scope as before, or a shared-vault member's selector-only lane under the
/// scope its home derived from its own shared-vault creation.
#[derive(Clone, Debug, Default)]
pub(crate) enum SelectorLane {
    /// The owner's own device (or the dev mode acting as him): the
    /// own-device scope, and no pin beyond each site's own principal check.
    #[default]
    OwnDevice,
    /// A member lane: its home-proved grant, holder and scope.
    Member(Arc<super::member_lane::MemberLane>),
}

impl SelectorLane {
    /// The member lane this socket carries, if it is one.
    pub(crate) fn member(&self) -> Option<&super::member_lane::MemberLane> {
        match self {
            Self::OwnDevice => None,
            Self::Member(lane) => Some(lane),
        }
    }

    /// The grant scope a selector this socket already holds is checked under:
    /// one it stored after [`Self::scope_for`] pinned it (an admitted window,
    /// a promoted window, a subscribed document).
    pub(crate) fn grant_scope(&self) -> oneiron::FederationGrantScope {
        match self {
            Self::OwnDevice => selector_grant_scope(),
            Self::Member(lane) => lane.standing().scope,
        }
    }

    /// The grant scope `selector` is checked under on this socket, handed out
    /// only for a selector this lane may send (MEMBER-SYNC D3): on a member
    /// lane it must name the lane's own grant and holder, so a second grant of
    /// the same holder, or another holder's, is refused before any read; it
    /// may still narrow that grant, which the engine's check judges. An owner
    /// socket's scope is the own-device scope, unchanged.
    pub(crate) fn scope_for(
        &self,
        selector: &SyncSelector,
    ) -> oneiron::Result<oneiron::FederationGrantScope> {
        match self {
            Self::OwnDevice => Ok(selector_grant_scope()),
            Self::Member(lane) => {
                let standing = lane.standing();
                if selector.grant_id != standing.grant || selector.member_ref != standing.holder {
                    return Err(oneiron::Error::sync_protocol(
                        oneiron::error::SyncProtocolValidation::Selector {
                            reason: oneiron::error::SyncSelectorValidation::MemberNotGranted,
                        },
                    ));
                }
                Ok(standing.scope)
            }
        }
    }
}
