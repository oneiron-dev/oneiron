//! A caller's sources, admitted for each offer a call actually goes to (FIX
//! 8714): an opt-in hook on the ladder's walk
//! ([`OfferLadder::generate_admitted`]). Before a rung is admitted, the
//! caller builds the request that rung's own destination may receive, from
//! only the sources it may receive, and keeps that destination-bound read
//! before any byte goes; right before the rung is sent, once its admission
//! and any wait are behind it, the caller says whether that read still
//! holds. A destination that may receive too little to work from passes
//! the rung over, held as the world hold holds one, and the call goes on
//! down the ladder. Every rung is judged so, the first and a picked one included,
//! and the owner's fallback too; a caller that does not opt in walks the
//! ladder exactly as before.
//!
//! [`OfferLadder::generate_admitted`]: super::OfferLadder::generate_admitted

use oneiron::LlmRequest;
use oneiron::settings::ReadDestination;

use super::offer::ServedOffer;

/// What a caller's sources come to for one offer's destination.
pub(crate) enum SourceOffer {
    /// The request that destination may receive: built from only the
    /// sources it may receive.
    Send(LlmRequest),
    /// The destination may receive too little to work from: the rung is
    /// passed over, for this content-free reason.
    Held(&'static str),
}

/// A caller whose request carries sources each destination must be admitted
/// to (FIX 8714).
pub(crate) trait SourceAdmission: Sync {
    /// `request` as `destination`, the offer's own, may receive it. The
    /// caller keeps its read bound to that destination, receipt included,
    /// before it returns the request to send.
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer;

    /// Why what [`Self::offer`] last admitted for `destination` no longer
    /// holds, read again right before the rung is sent; `None` while it
    /// holds.
    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str>;
}

/// The request the rung of `offer` is sent with `sources`: `Ok(None)` with no
/// hook (the call's own request goes), else the one its destination may
/// receive, or why the rung is passed over.
pub(super) fn offered(
    sources: Option<&dyn SourceAdmission>,
    request: &LlmRequest,
    offer: &ServedOffer,
) -> Result<Option<LlmRequest>, &'static str> {
    let Some(sources) = sources else {
        return Ok(None);
    };
    match sources.offer(request, &offer.destination()) {
        SourceOffer::Send(request) => Ok(Some(request)),
        SourceOffer::Held(reason) => Err(reason),
    }
}

/// Why the rung of `offer` is held right before it is sent: what `sources`
/// admitted for its destination no longer holds. `None` while it does, and
/// with no hook.
pub(super) fn lapsed(
    sources: Option<&dyn SourceAdmission>,
    offer: &ServedOffer,
) -> Option<&'static str> {
    sources.and_then(|sources| sources.recheck(&offer.destination()))
}
