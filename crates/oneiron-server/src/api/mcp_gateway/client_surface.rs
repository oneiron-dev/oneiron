//! The generated-UI surface profile a caller declares over MCP (FIX 7969;
//! ARCH-0048 G3). A client declares it as an `experimental` capability, under
//! [`MCP_GENERATED_UI_CAPABILITY`], in `initialize`'s `capabilities` and in
//! each `tools/call`'s `_meta.clientCapabilities`. This endpoint holds no
//! session, so it reads the profile on every call; a session transport (the
//! `oneiron mcp` bridge) keeps its initialize selection and names it on each
//! call it relays. A profile chooses how a card is lowered. It authenticates
//! no one and grants nothing. A caller that declares none, or declares one
//! this build cannot read, gets the whole atom kit: the declaration is
//! optional metadata and never refuses the call it rides.

use oneiron::lens::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiCatalogDescriptor, GeneratedUiStreamProfile,
    GeneratedUiSurfaceCapabilities,
};
use serde_json::{Value, json};

use super::McpToolCallParams;

/// The `_meta` key a `tools/call` names its client's MCP capabilities under.
pub(crate) const MCP_CLIENT_CAPABILITIES_META: &str = "clientCapabilities";

/// The `experimental` capability that holds a generated-UI surface profile,
/// in a client's capabilities and in this server's `initialize` answer.
pub(crate) const MCP_GENERATED_UI_CAPABILITY: &str = "oneiron/generatedUi";

/// The `_meta` key a 2026-07-28 request declares its client's capabilities
/// under, on each request (L1-03). An earlier request's declaration does not
/// count for this one (ARCH-0028 `#mcp-tasks`).
pub(crate) const MCP_SPEC_CLIENT_CAPABILITIES_META: &str =
    "io.modelcontextprotocol/clientCapabilities";

/// The MCP Tasks extension: this server advertises it, and a request
/// declares it under its client capabilities' `extensions`.
pub(crate) const MCP_TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Whether a request's `_meta` declares the Tasks extension: its client
/// capabilities name `extensions["io.modelcontextprotocol/tasks"]` as an
/// object. `initialize`'s capabilities are never read for it.
pub(super) fn declares_tasks(meta: Option<&Value>) -> bool {
    meta.and_then(|meta| meta.get(MCP_SPEC_CLIENT_CAPABILITIES_META))
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(|extensions| extensions.get(MCP_TASKS_EXTENSION))
        .is_some_and(Value::is_object)
}

/// Whether a request's `_meta` declares form elicitation (L1-03 PR 3): its
/// client capabilities name `elicitation` with `form`, or with neither `form`
/// nor `url`, as a bare `elicitation: {}` means form. Only such a request is
/// shown a task's questions as a form.
pub(super) fn declares_form_elicitation(meta: Option<&Value>) -> bool {
    meta.and_then(|meta| meta.get(MCP_SPEC_CLIENT_CAPABILITIES_META))
        .and_then(|capabilities| capabilities.get("elicitation"))
        .and_then(Value::as_object)
        .is_some_and(|elicitation| {
            elicitation.contains_key("form") || !elicitation.contains_key("url")
        })
}

/// The profile an MCP `capabilities` object declares; `None` when it
/// declares none or one that is no profile, which lowers for the whole atom
/// kit as an undeclared one does.
pub(super) fn declared_surface(
    capabilities: Option<&Value>,
) -> Option<GeneratedUiSurfaceCapabilities> {
    let profile = capabilities?
        .get("experimental")?
        .get(MCP_GENERATED_UI_CAPABILITY)?;
    serde_json::from_value(profile.clone()).ok()
}

impl McpToolCallParams {
    /// The profile the call's `_meta.clientCapabilities` declares, if any.
    pub(super) fn client_surface(&self) -> Option<GeneratedUiSurfaceCapabilities> {
        declared_surface(
            self.meta
                .as_ref()
                .and_then(|meta| meta.get(MCP_CLIENT_CAPABILITIES_META)),
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
