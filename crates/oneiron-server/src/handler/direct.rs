//! The socket's existing direct queue, with native promotion evidence attached.

use oneiron::sync::window::PreparedPromotionClaimCopies;
use tokio::sync::mpsc::{self, error::SendError};

pub(super) struct DirectFrame {
    pub(super) data: Vec<u8>,
    pub(super) promotion: Option<PromotionFrame>,
}

/// Uses the same queue for ordinary bytes and optional native promotion custody.
#[derive(Clone)]
pub(crate) struct DirectSender(mpsc::UnboundedSender<DirectFrame>);

impl DirectSender {
    pub(super) fn channel() -> (Self, mpsc::UnboundedReceiver<DirectFrame>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self(sender), receiver)
    }

    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.send_with_promotion(data, None)
    }

    pub(crate) fn send_with_promotion(
        &self,
        data: Vec<u8>,
        promotion: Option<PromotionFrame>,
    ) -> Result<(), SendError<Vec<u8>>> {
        self.0
            .send(DirectFrame { data, promotion })
            .map_err(|error| SendError(error.0.data))
    }
}

/// The pre-encoded optional choice, not a queued release certificate.
pub(crate) struct PromotionFrame {
    required: Vec<u8>,
    extended: Vec<u8>,
    copies: PreparedPromotionClaimCopies,
}

impl PromotionFrame {
    pub(crate) fn new(
        required: Vec<u8>,
        extended: Vec<u8>,
        copies: PreparedPromotionClaimCopies,
    ) -> Self {
        Self {
            required,
            extended,
            copies,
        }
    }

    /// A release that changed the required reply also discards its optional data.
    pub(super) fn for_required(
        self,
        required: &[u8],
    ) -> Option<(Vec<u8>, PreparedPromotionClaimCopies)> {
        (self.required == required).then_some((self.extended, self.copies))
    }
}
