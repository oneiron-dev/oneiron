use super::*;

// ---------------------------------------------------------------------------
// The closed decode door for the public six-field result
// ---------------------------------------------------------------------------

impl FetchResult {
    /// Returns the exact Markdown bytes covered by [`Self::content_hash`].
    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.markdown
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the validated, normalized, credential-free HTTP(S) identity.
    #[must_use]
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    #[must_use]
    pub const fn fetched_at(&self) -> u64 {
        self.fetched_at
    }

    /// Returns the domain-separated BLAKE3 identity of [`Self::markdown`].
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    #[must_use]
    pub const fn renderer(&self) -> RendererKind {
        self.renderer
    }
}

/// How many lowercase hex characters a BLAKE3 content identity is written in.
const CONTENT_HASH_HEX_CHARS: usize = 64;

/// Whether a decoded `content_hash` has the only shape this door accepts:
/// exactly [`CONTENT_HASH_HEX_CHARS`] lowercase ASCII hex characters. Uppercase
/// is refused rather than folded, because the writer emits one spelling and two
/// spellings of one identity is how a later dedup seam starts missing matches.
fn is_content_hash_shaped(hex: &str) -> bool {
    let is_lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    hex.len() == CONTENT_HASH_HEX_CHARS && hex.bytes().all(is_lower_hex)
}

/// The decode-side form of [`FetchResult`]: the same six fields, the same names,
/// and the same closure, plus the one check a derived door cannot make.
///
/// [`FetchResult`] documents `content_hash` as the identity of the `markdown`
/// beside it, and [`WebFetcher::try_rung`] always writes exactly that. A payload
/// arriving from anywhere else only asserts it, so this door re-derives the
/// identity through the one private [`content_hash`] over the exact markdown
/// bytes and refuses any pair that disagrees.
///
/// The re-derived value never replaces the supplied one. A door that quietly
/// substituted would turn a stale or forged pair into a well-formed-looking one,
/// which is the opposite of what a rematerialization door is for.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchResultWire {
    markdown: String,
    title: String,
    canonical_url: String,
    fetched_at: u64,
    content_hash: String,
    renderer: RendererKind,
}

impl TryFrom<FetchResultWire> for FetchResult {
    /// A decode-door diagnostic, not a typed engine error: serde renders it
    /// through `de::Error::custom`, and no caller branches on it.
    type Error = String;

    fn try_from(wire: FetchResultWire) -> std::result::Result<Self, Self::Error> {
        // Shape first, so a malformed, short, long, or uppercase value is
        // refused as what it is rather than reported as a stale identity.
        if !is_content_hash_shaped(&wire.content_hash) {
            return Err(format!(
                "content_hash must be {CONTENT_HASH_HEX_CHARS} lowercase hex characters"
            ));
        }
        if wire.content_hash != content_hash(&wire.markdown) {
            return Err("content_hash does not match the markdown it arrived with".to_string());
        }
        let canonical_url = validated_web_url(&wire.canonical_url).ok_or_else(|| {
            "canonical_url must be a credential-free absolute http(s) URL".to_string()
        })?;
        Ok(Self {
            markdown: wire.markdown,
            title: wire.title,
            canonical_url: canonical_url.to_string(),
            fetched_at: wire.fetched_at,
            content_hash: wire.content_hash,
            renderer: wire.renderer,
        })
    }
}
