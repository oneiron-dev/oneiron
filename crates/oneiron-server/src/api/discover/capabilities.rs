//! The capabilities discovery and health advertise, sorted (FIX 6692).
//!
//! Nothing is cut: authenticated discovery carries every token, grouped by
//! family, each group sorted and deduped with its count. Health carries only
//! the counts per family. Both carry one digest of the whole set, so a client
//! that kept the set asks discovery again only when the digest moves.

use super::{MCP_ENDPOINT_CAPABILITY_PREFIX, MCP_SURFACE_UNAVAILABLE_CAPABILITY_PREFIX};
use crate::api::MCP_TOOL_CAPABILITY_PREFIX;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use utoipa::ToSchema;

/// The domain the capabilities digest is hashed under.
const CAPABILITY_DIGEST_DOMAIN: &[u8] = b"oneiron.capabilities.v1";

/// Prefixes whose family is the prefix and the next segment: an MCP tool's
/// namespace, an endpoint's mode, an unavailable surface's mode.
const SEGMENTED_FAMILY_PREFIXES: [&str; 3] = [
    MCP_TOOL_CAPABILITY_PREFIX,
    MCP_ENDPOINT_CAPABILITY_PREFIX,
    MCP_SURFACE_UNAVAILABLE_CAPABILITY_PREFIX,
];

/// Capability flags advertised by authenticated discovery: every capability
/// this server serves, by family.
#[derive(Serialize, ToSchema)]
pub(crate) struct FeatureFlags {
    /// How many capabilities the groups hold together.
    #[schema(example = 2228)]
    total: usize,
    /// Digest of the whole set, the same one health carries: `blake3:` and
    /// the hex of BLAKE3 over the tokens in byte order. It does not depend on
    /// the grouping.
    #[schema(example = "blake3:5f0c8a1d2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5")]
    digest: String,
    /// The capabilities by family, families in byte order. A family is a
    /// token's first segment (`core`, `search`, `booking`, `self`, ...), or,
    /// under `mcp.tool.`, `mcp.endpoint.` and `mcp.surface_unavailable.`, that
    /// prefix and its next segment: an MCP tool's namespace (`mcp.tool.vault`,
    /// or `mcp.tool` for a name with none) or an endpoint's mode
    /// (`mcp.endpoint.tool_first`). Every `mcp.tool.<name>` token is a tool
    /// some registered endpoint accepts, and every
    /// `mcp.endpoint.<mode>.<name>` token says which endpoint.
    groups: BTreeMap<String, CapabilityGroup>,
    /// Model or runtime effort modes advertised by the API.
    #[schema(value_type = Vec<String>, example = json!(["flash", "thinking", "pro", "ultra"]))]
    modes: Vec<&'static str>,
}

/// One family's capabilities.
#[derive(Default, Serialize, ToSchema)]
pub(crate) struct CapabilityGroup {
    /// How many capabilities the family holds.
    #[schema(example = 3)]
    count: usize,
    /// The family's tokens, in byte order, each once.
    #[schema(example = json!(["search.semantic", "search.text", "search.vector"]))]
    capabilities: Vec<String>,
}

/// What health says of the capabilities: how many each family holds, and the
/// digest of the full set authenticated discovery carries.
#[derive(Serialize, ToSchema)]
pub(crate) struct CapabilitySummary {
    /// How many capabilities this server serves.
    #[schema(example = 2228)]
    total: usize,
    /// The digest [`FeatureFlags`] carries for the same set.
    #[schema(example = "blake3:5f0c8a1d2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5")]
    digest: String,
    /// How many capabilities each family holds, families in byte order.
    #[schema(example = json!({"core": 14, "mcp.endpoint.primary": 2, "mcp.tool.vault": 920, "search": 3}))]
    counts: BTreeMap<String, usize>,
}

impl FeatureFlags {
    /// `tokens` deduped and grouped by family, each group in byte order, with
    /// `modes` beside them.
    pub(crate) fn of(tokens: impl IntoIterator<Item = String>, modes: Vec<&'static str>) -> Self {
        let tokens = tokens.into_iter().collect::<BTreeSet<_>>();
        let total = tokens.len();
        let digest = capability_digest(&tokens);
        let mut groups = BTreeMap::<String, CapabilityGroup>::new();
        for token in tokens {
            let group = groups.entry(capability_family(&token)).or_default();
            group.count += 1;
            group.capabilities.push(token);
        }
        Self {
            total,
            digest,
            groups,
            modes,
        }
    }

    /// What health carries of these flags: the counts per family and the
    /// digest.
    pub(crate) fn summary(&self) -> CapabilitySummary {
        CapabilitySummary {
            total: self.total,
            digest: self.digest.clone(),
            counts: self
                .groups
                .iter()
                .map(|(family, group)| (family.clone(), group.count))
                .collect(),
        }
    }
}

/// The family `token` is grouped under (see [`FeatureFlags::groups`]).
fn capability_family(token: &str) -> String {
    for prefix in SEGMENTED_FAMILY_PREFIXES {
        if let Some(rest) = token.strip_prefix(prefix) {
            return match rest.split_once('.') {
                Some((segment, _)) => format!("{prefix}{segment}"),
                None => prefix.trim_end_matches('.').to_owned(),
            };
        }
    }
    token
        .split_once('.')
        .map_or(token, |(root, _)| root)
        .to_owned()
}

/// `blake3:` and the hex of BLAKE3 over `tokens` in byte order, under
/// [`CAPABILITY_DIGEST_DOMAIN`], the count and each token framed by its
/// length.
fn capability_digest(tokens: &BTreeSet<String>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_DIGEST_DOMAIN);
    hasher.update(&(tokens.len() as u64).to_be_bytes());
    for token in tokens {
        hasher.update(&(token.len() as u64).to_be_bytes());
        hasher.update(token.as_bytes());
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}
