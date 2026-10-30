//! The server's close frame, read by its code (FIX 5927), never only
//! formatted into a message.
//!
//! - A server fault (1011: an export or an admission read the server could
//!   not make, FIX 5570, 5849, 5850) and a frame the server asks to have sent
//!   again (1013) take the retry path: nothing this device sent was refused,
//!   its queue and buffered edits stand, and the next connect sends them
//!   again, as after any outage. Each is reported as the server's fault.
//! - A refusal (4002: a frame that did not decode or import, 4003: an
//!   unknown tag, 4004: a frame past the size limit) is the server's
//!   judgment of a frame this device sent, and is reported as one.
//! - Any other close, or a close with no frame, ends the socket as before.

use tokio_tungstenite::tungstenite::protocol::CloseFrame;

/// RFC 6455 "Internal Error": the server met a fault of its own.
const INTERNAL_ERROR: u16 = 1011;
/// RFC 6455 "Try Again Later": nothing was applied; the frame may come again.
const TRY_AGAIN_LATER: u16 = 1013;
/// The codes the server closes with when it refuses a frame this device sent
/// (ARCH-023 section 3.5): decode, unknown tag, frame too large.
const REFUSED_FRAME_CODES: [u16; 3] = [4002, 4003, 4004];

/// How the server closed a socket, by its close code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ServerClose {
    /// The server's own fault, or its ask to send again later: the retry path.
    Fault { code: u16, reason: String },
    /// The server refused a frame this device sent: the refusal path.
    Refused { code: u16, reason: String },
    /// Any other close, with its code if the frame carried one.
    Other { code: Option<u16>, reason: String },
}

impl ServerClose {
    /// Reads `frame`, the close the server sent, if it sent one.
    pub(super) fn read(frame: Option<&CloseFrame>) -> Self {
        let Some(frame) = frame else {
            return Self::Other {
                code: None,
                reason: String::new(),
            };
        };
        let code = u16::from(frame.code);
        let reason = frame.reason.as_str().to_owned();
        if code == INTERNAL_ERROR || code == TRY_AGAIN_LATER {
            Self::Fault { code, reason }
        } else if REFUSED_FRAME_CODES.contains(&code) {
            Self::Refused { code, reason }
        } else {
            Self::Other {
                code: Some(code),
                reason,
            }
        }
    }
}

impl std::fmt::Display for ServerClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault { code, reason } => write!(
                f,
                "server fault (close {code}: {reason}); nothing this device sent was refused, \
                 and it is sent again on reconnect"
            ),
            Self::Refused { code, reason } => {
                write!(
                    f,
                    "server refused a frame this device sent (close {code}: {reason})"
                )
            }
            Self::Other {
                code: Some(code),
                reason,
            } => write!(f, "server closed the connection (close {code}: {reason})"),
            Self::Other { code: None, .. } => f.write_str("server closed the connection"),
        }
    }
}
