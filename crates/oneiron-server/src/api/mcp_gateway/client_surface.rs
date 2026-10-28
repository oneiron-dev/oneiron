//! The generated-UI surface profile a caller declares over MCP (FIX 7969;
//! ARCH-0048 G3). A client declares it as an `experimental` capability, under
//! [`MCP_GENERATED_UI_CAPABILITY`], in `initialize`'s `capabilities` and in
//! each `tools/call`'s `_meta.clientCapabilities`. This endpoint holds no
//! session, so it reads the profile on every call; a session transport (the
//! `oneiron mcp` bridge) keeps its initialize selection and names it on each
//! call it relays. A profile chooses how a card is lowered. It authenticates
//! no one and grants nothing, and a caller that declares none gets the whole
//! atom kit.

use oneiron::lens::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiCatalogDescriptor, GeneratedUiStreamProfile,
    GeneratedUiSurfaceCapabilities,
};
use serde_json::{Value, json};

use super::{McpGatewayError, McpToolCallParams};

/// The `_meta` key a `tools/call` names its client's MCP capabilities under.
pub(crate) const MCP_CLIENT_CAPABILITIES_META: &str = "clientCapabilities";

/// The `experimental` capability that holds a generated-UI surface profile,
/// in a client's capabilities and in this server's `initialize` answer.
pub(crate) const MCP_GENERATED_UI_CAPABILITY: &str = "oneiron/generatedUi";

/// The profile an MCP `capabilities` object declares; `None` when it
/// declares none. A declaration that is no profile is refused with `kind`,
/// naming `field`.
pub(super) fn declared_surface(
    capabilities: Option<&Value>,
    field: &str,
    kind: &'static str,
) -> Result<Option<GeneratedUiSurfaceCapabilities>, McpGatewayError> {
    let Some(profile) = capabilities
        .and_then(|capabilities| capabilities.get("experimental"))
        .and_then(|experimental| experimental.get(MCP_GENERATED_UI_CAPABILITY))
    else {
        return Ok(None);
    };
    serde_json::from_value(profile.clone())
        .map(Some)
        .map_err(|error| {
            McpGatewayError::new(
                -32602,
                kind,
                format!(
                    "{field}.experimental.{MCP_GENERATED_UI_CAPABILITY} is not a generated-ui surface profile: {error}"
                ),
            )
            .with_field(field)
        })
}

impl McpToolCallParams {
    /// The profile the call's `_meta.clientCapabilities` declares, if any.
    pub(super) fn client_surface(
        &self,
    ) -> Result<Option<GeneratedUiSurfaceCapabilities>, McpGatewayError> {
        declared_surface(
            self.meta
                .as_ref()
                .and_then(|meta| meta.get(MCP_CLIENT_CAPABILITIES_META)),
            "_meta.clientCapabilities",
            "tool_args_invalid",
        )
    }
}

/// What `initialize` answers of generated UI: the protocol version, the
/// catalog descriptors the engine supplies (the built-in kit), the stream
/// profiles it sends, and the profile this caller declared (`null` lowers
/// for the whole atom kit).
pub(super) fn initialize_capability(declared: Option<&GeneratedUiSurfaceCapabilities>) -> Value {
    json!({
        "protocolVersion": GENERATED_UI_WIRE_VERSION,
        "catalogs": [GeneratedUiCatalogDescriptor::lens_atom_kit()],
        "streamProfiles": [GeneratedUiStreamProfile::FullModel, GeneratedUiStreamProfile::Patch],
        "negotiated": declared,
    })
}
