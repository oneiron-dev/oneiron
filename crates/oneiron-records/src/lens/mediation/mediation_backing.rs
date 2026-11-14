//! Moved from `crates/oneiron/src/lens/mediation/mediation_backing.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::lens::LensAtomId;
use oneiron_verb_wire::lens::LensHandleName;
use oneiron_verb_wire::lens::LensRenderId;
pub use oneiron_verb_wire::lens::mediation::mediation_backing::LensBackingTargetKind;
pub use oneiron_verb_wire::lens::mediation::mediation_backing::LensReadReach;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Client-authored atom selection. It names *what was pointed at* and nothing else:
/// no entity id, body text, screenshot, write token, authority, or query string is
/// expressible here. The engine looks the node up in the exact render it emitted and
/// takes the target from its own backing table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensAtomSelectionRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
}

/// A client names only scalar offsets into the host-bound entity document.
/// Neither a document id nor a cursor/version may be supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSpanSelectionRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
    pub start: usize,
    pub end: usize,
}
