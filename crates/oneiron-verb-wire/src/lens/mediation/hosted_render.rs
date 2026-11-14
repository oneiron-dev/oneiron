//! Moved from `crates/oneiron/src/lens/mediation/hosted_render.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_lens_wire::lens::generated_ui::GeneratedLens;
use oneiron_lens_wire::lens::generated_ui::GeneratedUiRender;
use oneiron_lens_wire::lens::wire_ids::LensRenderId;
use serde::Deserialize;
use serde::Serialize;

/// What a hosted lens render answers: the card's id, the exact render its
/// host lowered (and, on a server, holds the frame of), and the lens tree.
/// It carries no frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensFrameCard {
    /// The card an event names, and the path a server takes its events at
    /// (`POST /v1/core/lens-frames/{card_id}/events`).
    pub card_id: LensRenderId,
    /// The surface-lowered render: its nodes, action manifest, `$state` and
    /// lifecycle, exactly as its host holds it.
    pub render: GeneratedUiRender,
    /// The authored lens tree.
    pub lens: GeneratedLens,
}
