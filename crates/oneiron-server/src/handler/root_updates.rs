//! Root exports leave as one immutable image. The guarded transport checks
//! revocation and stopping again for every physical frame of a large image.

use super::socket_stop::StoppingTransport;
use oneiron::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TAG_SYNC_UPDATE, root_update_frames};

pub(super) async fn send_root_frame(transport: &mut StoppingTransport, frame: Vec<u8>) -> bool {
    if frame.first() != Some(&TAG_SYNC_UPDATE)
        || frame.len().saturating_sub(1) <= MAX_DECODED_PAYLOAD_BYTES
    {
        return transport.send_binary(frame).await;
    }
    for part in root_update_frames(&frame[1..]) {
        if !transport.send_binary(part).await {
            return false;
        }
    }
    true
}
