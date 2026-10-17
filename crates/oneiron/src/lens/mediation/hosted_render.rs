//! Host custody of one generated-lens render (OF-181): the frame that minted
//! a card's backing refs, beside the card it rendered.
//!
//! A [`HostedLensRender`] never crosses the wire. Its host lowers the card
//! once for the surface it answers ([`HostedLensRender::lower`]) and keeps
//! the frame beside exactly that render; the caller is handed only the
//! [`LensFrameCard`]. An event on the card names only what was touched, and
//! [`Memory::lens_frame_event`] checks it against the held frame, render and
//! current `$state` under the caller's own read. Backing refs are never
//! rebuilt from a returned tree.

use serde::{Deserialize, Serialize};

use super::{GeneratedUiValidatedAction, LensRenderFrame};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::error::Result;
use crate::lens::LensDefaultRequest;
use crate::lens::generated_ui::{
    GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiCard,
    GeneratedUiRender, GeneratedUiStateSnapshot, GeneratedUiSurfaceCapabilities,
};
use crate::lens::wire_ids::LensRenderId;
use crate::memory::{Memory, MemoryResult};

/// One host-rendered lens: the frame its reads minted backing refs on, and
/// the card it rendered, whose id is the frame's render id. Host-only: a
/// caller is handed the [`LensFrameCard`] [`Self::lower`] makes.
#[derive(Debug)]
pub struct HostedLensRender {
    pub frame: LensRenderFrame,
    pub card: GeneratedUiCard,
}

/// What a hosted lens render answers: the card's id, the exact render its
/// host lowered (and, on a server, holds the frame of), and the lens tree.
/// It carries no frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl HostedLensRender {
    /// A read-only card of `tree`, with no actions and no `$state`.
    pub fn new(frame: LensRenderFrame, tree: GeneratedLens) -> Result<Self> {
        let card = GeneratedUiCard::new(frame.render_id().clone(), tree)?;
        Ok(Self { frame, card })
    }

    /// An interactive card of `tree`, its engine-authored action manifest
    /// and initial `$state` proved against the tree.
    pub fn interactive(
        frame: LensRenderFrame,
        tree: GeneratedLens,
        actions: Vec<GeneratedUiActionDeclaration>,
        state: GeneratedUiStateSnapshot,
    ) -> Result<Self> {
        let card = GeneratedUiCard::interactive(frame.render_id().clone(), tree, actions, state)?;
        Ok(Self { frame, card })
    }

    /// Lowers the card for `surface`, once: the render handed out is the one
    /// a host keeps beside the frame, so a control the surface degrades
    /// loses its declaration in both. The frame, and the wire card.
    pub fn lower(
        self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<(LensRenderFrame, LensFrameCard)> {
        let render = self.card.render_for_surface(surface)?;
        Ok((
            self.frame,
            LensFrameCard {
                card_id: self.card.card_id,
                render,
                lens: self.card.tree,
            },
        ))
    }
}

impl Memory<'_> {
    /// `vault.lenses.default` where no host keeps the frame: the same card,
    /// lowered for the whole atom kit. Its events need a server, which holds
    /// the frame of each card it answers.
    pub fn lenses_default(
        &self,
        input: LensDefaultRequest,
    ) -> MemoryResult<ScopedReadResult<LensFrameCard>> {
        let ScopedReadResult { value, receipt } = self.lenses_default_framed(input)?;
        let (_, card) = value.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
        Ok(ScopedReadResult {
            value: card,
            receipt,
        })
    }

    /// One client event on a card whose frame this host holds, checked
    /// against that frame, the exact `render` it handed out and the card's
    /// current `state`, under this handle's own read: its key, the emitter,
    /// the card, the declared action and its tier, the patch, and each
    /// backing ref's reach now. Nothing runs here.
    pub fn lens_frame_event(
        &self,
        frame: &LensRenderFrame,
        render: &GeneratedUiRender,
        state: &GeneratedUiStateSnapshot,
        event: &GeneratedUiActionEvent,
    ) -> MemoryResult<GeneratedUiValidatedAction> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(frame.validate_action_event(&read, frame.principal(), render, state, event)?)
    }
}
