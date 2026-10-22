//! Opaque continuation cursors for Context Board pages.
//!
//! A cursor carries the read fence its first page took, the last key the
//! previous page emitted, and a binding digest over the page kind plus the
//! caller and filter it was minted for. A cursor presented under any other
//! binding, or one that does not decode, is refused rather than
//! reinterpreted.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Wire version of the cursor bytes.
const PAGE_CURSOR_VERSION: u8 = 1;

/// Domain separator for every board page binding digest.
const PAGE_BINDING_DOMAIN: &[u8] = b"oneiron.context_board.page.v1\0";

/// One decoded page cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoardPageCursor {
    /// The fence the first page read through, for page kinds that take one.
    pub(crate) fence: Option<u64>,
    /// The last key bytes the previous page emitted.
    pub(crate) after: Vec<u8>,
}

/// Binds a cursor to one page kind and its caller and filter parts.
/// Each part is length-prefixed, so two part lists never share a digest.
pub(crate) fn page_binding(kind: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAGE_BINDING_DOMAIN);
    for part in std::iter::once(kind.as_bytes()).chain(parts.iter().copied()) {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Encodes `cursor` under `binding` as one opaque URL-safe token.
pub(crate) fn encode_page_cursor(binding: &[u8; 32], cursor: &BoardPageCursor) -> String {
    let mut bytes = Vec::with_capacity(1 + binding.len() + 9 + cursor.after.len());
    bytes.push(PAGE_CURSOR_VERSION);
    bytes.extend_from_slice(binding);
    match cursor.fence {
        Some(fence) => {
            bytes.push(1);
            bytes.extend_from_slice(&fence.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&cursor.after);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes a token minted by [`encode_page_cursor`] under the same binding.
/// `None` for a token that does not decode or was minted under another
/// binding.
pub(crate) fn decode_page_cursor(binding: &[u8; 32], token: &str) -> Option<BoardPageCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(token.trim()).ok()?;
    let (&version, rest) = bytes.split_first()?;
    if version != PAGE_CURSOR_VERSION {
        return None;
    }
    let (bound, rest) = rest.split_at_checked(binding.len())?;
    if bound != binding.as_slice() {
        return None;
    }
    let (&tag, rest) = rest.split_first()?;
    let (fence, after) = match tag {
        0 => (None, rest),
        1 => {
            let (fence, after) = rest.split_at_checked(8)?;
            (Some(u64::from_be_bytes(fence.try_into().ok()?)), after)
        }
        _ => return None,
    };
    Some(BoardPageCursor {
        fence,
        after: after.to_vec(),
    })
}
