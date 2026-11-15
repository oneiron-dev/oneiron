//! The executor's declarations, kept out of a stored request (FIX row
//! [AGENT-RUN-START-LATENCY-4S]). A code-mode step's system prompt ends with
//! every declaration text the build carries (the host verbs, the code-mode
//! catalog, the runtime types), about 1.1 MB of a 1.1 MB request, all of it
//! compiled in. A capsule stores its request with that block swapped for a
//! reference that names its digest. The side-row wall, the request's parses
//! and its pieces then read only the rest, in the writer that puts the
//! capsule, and every write that waits on that writer waits less. The
//! request hash stays the hash of the request as sent.
//!
//! The capsule's one reader ([`super::capsule_request`]) puts the block back
//! where a reference names this build's block, and reads none where one
//! names another build's: a request is never rebuilt from declarations it
//! was not sent with. The stored hash of a request that names the block is
//! the hash of the request with the block put back
//! ([`stored_request_hash`]), so a request the wall placed nothing in still
//! reads as the request as sent (`StepReplayCapsule::as_sent`, FIX 6144).

use std::borrow::Cow;
use std::sync::OnceLock;

use crate::llm::{ContentPart, LlmMessageRole, LlmRequest};
use crate::{Error, Result};

/// What a reference to a declarations block starts with. The digest's 64
/// hex digits and a closing bracket follow.
const REFERENCE_OPENER: &str = "[executor declarations blake3:";

/// This build's declarations block and the reference that names it.
struct Declarations {
    block: &'static str,
    reference: String,
}

fn declarations() -> &'static Declarations {
    static DECLARATIONS: OnceLock<Declarations> = OnceLock::new();
    DECLARATIONS.get_or_init(|| {
        let block = crate::engine_executor::executor_declarations_block();
        Declarations {
            block,
            reference: format!("{REFERENCE_OPENER}{}]", blake3::hash(block.as_bytes())),
        }
    })
}

/// `request` as a capsule stores it: each system text that ends with this
/// build's declarations block ends with the block's reference instead.
/// Borrowed when no system text does.
pub(crate) fn request_as_stored(request: &LlmRequest) -> Cow<'_, LlmRequest> {
    let declarations = declarations();
    if !system_texts(request).any(|text| text.ends_with(declarations.block)) {
        return Cow::Borrowed(request);
    }
    let mut stored = request.clone();
    for text in system_texts_mut(&mut stored) {
        if let Some(head) = text.strip_suffix(declarations.block) {
            let kept = head.len();
            text.truncate(kept);
            text.push_str(&declarations.reference);
        }
    }
    Cow::Owned(stored)
}

/// `stored`, a request as a capsule stores it, with each reference to this
/// build's declarations block replaced by the block: the request as sent.
/// `None` when a system text ends with a reference to any other block.
fn request_as_sent(mut stored: LlmRequest) -> Option<LlmRequest> {
    let declarations = declarations();
    for text in system_texts_mut(&mut stored) {
        let Some(at) = reference_start(text) else {
            continue;
        };
        if text.get(at..) != Some(declarations.reference.as_str()) {
            return None;
        }
        text.truncate(at);
        text.push_str(declarations.block);
    }
    Some(stored)
}

/// The hash a capsule keeps of `stored`, its request as the wall admitted
/// it, whose canonical bytes are `bytes`: the hash of those bytes, or, for a
/// request that names this build's declarations, the hash of the request
/// with them put back.
///
/// # Errors
///
/// A request that does not encode.
pub(crate) fn stored_request_hash(stored: &LlmRequest, bytes: &[u8]) -> Result<[u8; 32]> {
    if !names_declarations(stored) {
        return Ok(*blake3::hash(bytes).as_bytes());
    }
    match request_as_sent(stored.clone()) {
        Some(sent) => sent
            .canonical_hash()
            .map_err(|error| Error::InvalidConfig(format!("capsule request: {error}"))),
        // Another build's declarations: no read puts them back.
        None => Ok(*blake3::hash(bytes).as_bytes()),
    }
}

/// `bytes`, a capsule's stored request, read back as the request as sent
/// when they hash to `stored_hash` as [`stored_request_hash`] says. `None`
/// for bytes that are no request, a hash that differs, and a request that
/// names another build's declarations.
pub(crate) fn read_stored_request(bytes: &[u8], stored_hash: &[u8; 32]) -> Option<LlmRequest> {
    let stored: LlmRequest = serde_json::from_slice(bytes).ok()?;
    if !names_declarations(&stored) {
        return (blake3::hash(bytes).as_bytes() == stored_hash).then_some(stored);
    }
    let sent = request_as_sent(stored)?;
    let hash = sent.canonical_hash().ok()?;
    (&hash == stored_hash).then_some(sent)
}

/// Whether a system text of `request` ends with a reference to a
/// declarations block, this build's or another's.
fn names_declarations(request: &LlmRequest) -> bool {
    system_texts(request).any(|text| reference_start(text).is_some())
}

/// Where the reference `text` ends with starts: the opener, a digest of 64
/// hex digits and the closing bracket. `None` when it ends with none.
fn reference_start(text: &str) -> Option<usize> {
    let open = text.strip_suffix(']')?;
    let at = open.rfind(REFERENCE_OPENER)?;
    let digest = open.get(at + REFERENCE_OPENER.len()..)?;
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(at)
}

/// Each text part of `request`'s system messages.
fn system_texts(request: &LlmRequest) -> impl Iterator<Item = &str> {
    request
        .messages
        .iter()
        .filter(|message| matches!(message.role, LlmMessageRole::System))
        .flat_map(|message| message.content.iter())
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
}

/// [`system_texts`], each to change in place.
fn system_texts_mut(request: &mut LlmRequest) -> impl Iterator<Item = &mut String> {
    request
        .messages
        .iter_mut()
        .filter(|message| matches!(message.role, LlmMessageRole::System))
        .flat_map(|message| message.content.iter_mut())
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text),
            _ => None,
        })
}
