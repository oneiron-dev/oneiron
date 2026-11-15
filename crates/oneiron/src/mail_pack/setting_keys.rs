//! The mail pack's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: a room's stretch searches no mail.
fn searched_nowhere_shared() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Allow mail search in this room (results visible to everyone here). Off by default: a
    /// search inside a room's off-record stretch is refused before the provider is asked, and
    /// nothing is fetched or kept. On for a room, a search in its stretch keeps its hits in the
    /// room's overlay, as a search alone does: every member of the room reads them until the
    /// stretch closes, and none reaches base (UNBUILT-01-ROOM-READERS, owner 16 Nov 00:44). A
    /// room's row sits at its conversation's thread scope; a vault row opens every room, and a
    /// room's own row wins over it. On is the looser value, so only the owner turns it on; an
    /// agent's change waits on the owner's answer.
    pub(crate) MAIL_SEARCH_IN_ROOM: bool = "mail.search.in_room" {
        kind: Kind::new(searched_nowhere_shared)
            .strictest(searched_nowhere_shared)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Thread],
    };
}
