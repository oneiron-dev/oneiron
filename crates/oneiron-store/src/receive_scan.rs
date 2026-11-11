//! Pushed-blob scan inputs, value-free hits, and the receive-pack effector name.

/// The receive-pack door's effector — the scope every door-issued lease and
/// door injection is bound to by default.
pub const DOOR_RECEIVE_PACK_EFFECTOR: &str = "door:receive-pack";

/// One pushed blob as the transport hands it to the door. A data seam: the
/// quarantine extraction that fills it belongs to the transport owner.
///
/// `Debug` redacts `content` — those bytes are exactly the ones that may be
/// secret-shaped, and a diagnostic print is not a place for them.
#[derive(Clone, PartialEq, Eq)]
pub struct PushedBlob {
    /// Repository-relative label of the blob, C-quoted for some Git tip paths.
    pub path: String,
    /// Exact path bytes for a Git tip diff; absent for history or non-tip input.
    pub tip_raw_path: Option<Vec<u8>>,
    /// The blob's object id (hex).
    pub oid: String,
    /// The blob's whole content as raw bytes: what the push makes durable.
    pub content: Vec<u8>,
}

impl PushedBlob {
    /// Exact Git tip path bytes, or the original label for other input.
    pub fn path_bytes(&self) -> &[u8] {
        self.tip_raw_path.as_deref().unwrap_or(self.path.as_bytes())
    }

    /// The content as lines, split on `\n` with no line reshaped: a trailing
    /// newline ends the last line rather than adding an empty one, an empty
    /// blob has no line, and CR, NUL and every other byte survive untouched.
    /// Each line borrows the content, so a blob costs the door its own bytes
    /// and nothing per line.
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        let content = (!self.content.is_empty()).then_some(self.content.as_slice());
        content.into_iter().flat_map(|content| {
            content
                .strip_suffix(b"\n")
                .unwrap_or(content)
                .split(|byte| *byte == b'\n')
        })
    }
}

impl std::fmt::Debug for PushedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedBlob")
            .field("path", &self.path)
            .field("oid", &self.oid)
            .field(
                "content",
                &format_args!("<redacted {} bytes>", self.content.len()),
            )
            .finish()
    }
}

/// How the door read one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveBlobKind {
    /// Valid UTF-8 with no NUL byte: read line by line, as before.
    Text,
    /// Any other bytes: the custody automaton, then the release reader.
    Binary,
}

/// One detector hit on one pushed blob: where it is and which rule named
/// it. It carries no byte of the blob, so its `Debug` and every error made
/// from it are safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveScanHit {
    /// The blob's repository-relative path.
    pub path: String,
    /// The blob's object id (hex).
    pub oid: String,
    /// The detector's reason code.
    pub reason: &'static str,
    /// How the blob was read.
    pub content_kind: ReceiveBlobKind,
}
