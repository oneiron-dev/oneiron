//! The client lane's registration for relayed ask intents (FIX 7494): after
//! a frame that imports window rows, the intents it landed for asks this
//! node admitted go to their consumer ([`crate::sync::ask_forward`]).

use super::base::SyncClient;
use crate::sync::transport::{TAG_BULK_TRANSFER_DONE, TAG_WINDOW_SYNC};

impl SyncClient {
    /// Consumes the relayed ask intents the frame tagged `tag` landed, when
    /// it is a window update or the end of a bulk transfer.
    pub(super) fn consume_landed_ask_intents(&self, tag: u8) {
        if matches!(tag, TAG_WINDOW_SYNC | TAG_BULK_TRANSFER_DONE) {
            crate::sync::ask_forward::consume_landed_intents(&self.vault);
        }
    }
}
