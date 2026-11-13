//! MCP tool annotations (census L1-11; Engine ruling 2026-11-13 22:39 = A).
//! Every tool `tools/list` lists carries the standard MCP hints of its verb
//! row's act class (`readOnlyHint`, `destructiveHint`, `openWorldHint`;
//! `src/mcp/annotations.rs` holds the table), a tool whose class is unstated
//! carries none, and the listing stays the same bytes for every caller.
//!
//! The first four tests read the registered surfaces on public paths and
//! restate the ruled table apart from the server's own mapping. The last
//! runs `tools/list` over the gateway under two credentials, and needs the
//! test-support build: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_tool_annotations`.

use oneiron::check_in::{ActClass, VerbActClass, verb_act_class};
use oneiron_server::mcp::{
    MCP_EXECUTE_CODE_TOOL, MCP_INVOKE_ACTION_TOOL, MCP_READ_RESULT_TOOL, MCP_SETUP_TOOL,
    McpSurfaceMode, registered_surface, try_registered_surface_with_execution,
};
use serde_json::{Value, json};

#[cfg(oneiron_test_support)]
#[path = "support/engine_stack.rs"]
mod engine_stack;

/// Every registered listing: both endpoints, with and without a verified
/// code host (which adds `execute_code` and `read_result`).
fn listings() -> Vec<(String, &'static Value)> {
    let mut all = Vec::new();
    for mode in McpSurfaceMode::ALL {
        for code_host in [false, true] {
            let surface = try_registered_surface_with_execution(mode, code_host)
                .expect("the surface registers");
            all.push((
                format!("{mode:?}, code host {code_host}"),
                surface.listing(),
            ));
        }
    }
    all
}

fn entries(listing: &Value) -> &[Value] {
    listing.as_array().expect("the listing is a list")
}

fn name_of(entry: &Value) -> &str {
    entry["name"].as_str().expect("each tool has a name")
}

fn entry<'a>(listing: &'a Value, name: &str) -> &'a Value {
    entries(listing)
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("the listing names {name}"))
}

/// The hints the ruled table gives a verb whose row states `class`.
fn ruled_hints(class: Option<VerbActClass>) -> Option<Value> {
    match class? {
        VerbActClass::Read => Some(json!({ "readOnlyHint": true })),
        VerbActClass::Unstated => None,
        VerbActClass::Act(ActClass::ReversibleWork) => {
            Some(json!({ "readOnlyHint": false, "destructiveHint": false }))
        }
        VerbActClass::Act(
            ActClass::Delete | ActClass::Erase | ActClass::VaultDelete | ActClass::MemberRemove,
        ) => Some(json!({ "readOnlyHint": false, "destructiveHint": true })),
        VerbActClass::Act(ActClass::OutboundSend | ActClass::LegalSend) => {
            Some(json!({ "readOnlyHint": false, "openWorldHint": true }))
        }
        VerbActClass::Act(_) => Some(json!({ "readOnlyHint": false })),
    }
}

/// The hints the ruled table gives the tool listed as `name`.
fn ruled_hints_for_tool(name: &str) -> Option<Value> {
    match name {
        MCP_SETUP_TOOL | MCP_READ_RESULT_TOOL => Some(json!({ "readOnlyHint": true })),
        MCP_EXECUTE_CODE_TOOL | MCP_INVOKE_ACTION_TOOL => None,
        verb => ruled_hints(verb_act_class(verb)),
    }
}

#[test]
fn a_read_verb_tool_says_it_only_reads() {
    let listing = registered_surface(McpSurfaceMode::ToolFirst).listing();
    assert_eq!(verb_act_class("vault.recall"), Some(VerbActClass::Read));
    assert_eq!(
        entry(listing, "vault.recall")["annotations"],
        json!({ "readOnlyHint": true })
    );
    let mut reads = 0_usize;
    for tool in entries(listing) {
        let name = name_of(tool);
        if verb_act_class(name) == Some(VerbActClass::Read) {
            reads += 1;
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{name}");
        }
    }
    assert!(
        reads > 1,
        "the tool-first endpoint lists {reads} read verbs"
    );
}

#[test]
fn a_delete_verb_tool_says_it_destroys() {
    let listing = registered_surface(McpSurfaceMode::ToolFirst).listing();
    assert_eq!(
        verb_act_class("vault.delete"),
        Some(VerbActClass::Act(ActClass::Delete))
    );
    assert_eq!(
        entry(listing, "vault.delete")["annotations"],
        json!({ "readOnlyHint": false, "destructiveHint": true })
    );
    let mut destructive = 0_usize;
    for tool in entries(listing) {
        let name = name_of(tool);
        if let Some(VerbActClass::Act(
            ActClass::Delete | ActClass::Erase | ActClass::VaultDelete | ActClass::MemberRemove,
        )) = verb_act_class(name)
        {
            destructive += 1;
            assert_eq!(tool["annotations"]["destructiveHint"], true, "{name}");
            assert_eq!(tool["annotations"]["readOnlyHint"], false, "{name}");
        }
    }
    assert!(
        destructive > 1,
        "the tool-first endpoint lists {destructive} destructive verbs"
    );
}

#[test]
fn every_listed_tool_carries_the_hints_of_its_act_class() {
    let mut annotated = 0_usize;
    for (label, listing) in listings() {
        for tool in entries(listing) {
            let name = name_of(tool);
            let ruled = ruled_hints_for_tool(name);
            annotated += usize::from(ruled.is_some());
            assert_eq!(tool.get("annotations").cloned(), ruled, "{label}: {name}");
        }
    }
    assert!(annotated > 0);
    // The rarer classes are listed too, so the table's rows are each seen.
    let listing = registered_surface(McpSurfaceMode::ToolFirst).listing();
    for (name, class) in [
        ("connector.call", ActClass::OutboundSend),
        ("vault.esign.send_for_signature", ActClass::LegalSend),
    ] {
        assert_eq!(
            verb_act_class(name),
            Some(VerbActClass::Act(class)),
            "{name}"
        );
        assert_eq!(
            entry(listing, name)["annotations"],
            json!({ "readOnlyHint": false, "openWorldHint": true }),
            "{name}"
        );
    }
}

#[test]
fn an_unstated_verb_and_the_code_doors_carry_no_hints() {
    let mut unstated = 0_usize;
    for (label, listing) in listings() {
        for tool in entries(listing) {
            let name = name_of(tool);
            let no_class = matches!(verb_act_class(name), None | Some(VerbActClass::Unstated))
                && name != MCP_SETUP_TOOL
                && name != MCP_READ_RESULT_TOOL;
            if no_class {
                unstated += 1;
                assert!(
                    tool.get("annotations").is_none(),
                    "{label}: {name} carries hints: {tool}"
                );
            }
        }
        for door in [MCP_EXECUTE_CODE_TOOL, MCP_INVOKE_ACTION_TOOL] {
            if let Some(tool) = entries(listing).iter().find(|tool| tool["name"] == door) {
                assert!(tool.get("annotations").is_none(), "{label}: {door}");
            }
        }
    }
    assert!(unstated > 0);
}

/// `tools/list` over the gateway, as two credentials call it.
#[cfg(oneiron_test_support)]
mod served {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use ed25519_dalek::{Signer, SigningKey};
    use oneiron::authority::{
        CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
    };
    use oneiron::claim::base_world_id;
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    use oneiron::test_doors::label_writers::embedded_owner;
    use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
    use oneiron_server::mcp::{McpSurfaceMode, registered_surface};
    use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::engine_stack::on_engine_stack;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const MCP_PATH: &str = "/mcp/tool-first";
    const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

    /// A slip and the key its holder proves it with.
    struct Holder {
        slip: CapabilitySlip,
        key: SigningKey,
    }

    /// A served vault with no code host, as mcp_caveated_reader.rs builds it.
    struct Fixture {
        app: Router,
        vault: Arc<Vault>,
        issuer: HostSlipIssuer,
        root: CapabilitySlip,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let dir = tempfile::tempdir()?;
            let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
            vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
            let issuer = oneiron::test_support::provision_engine_machines(&vault);
            vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
            // The vault's embedded owner, as a served install has one.
            let _owner = embedded_owner(&vault)?;
            let root = vault.ensure_host_root_slip(&issuer)?;
            let server = Arc::new(SyncServer::new(
                vault.clone(),
                SyncServerConfig {
                    auth_secret: Some("mcp-tool-annotations".into()),
                    ..Default::default()
                },
            )?);
            Ok(Self {
                app: build_app(server),
                vault,
                issuer,
                root,
                _dir: dir,
            })
        }

        /// A distinct person's `core:read` slip, minted under the vault's
        /// logged issuer as pairing mints one.
        fn mint_reader(&self) -> TestResult<Holder> {
            let person = EntityId::now();
            self.vault.put_entity(
                &person,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a reader listing the tools",
            )?;
            let key = SigningKey::from_bytes(&[0x71; 32]);
            let mut claims = self.root.claims.clone();
            claims.parent_id = None;
            claims.slip_id = [0x71; 32];
            claims.holder_ref = person.to_hex();
            claims.binding_key = key.verifying_key().to_bytes();
            claims.actor_class = Some("human".to_owned());
            claims.scope = Scope::top();
            claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
            let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
            Ok(Holder { slip, key })
        }

        /// `holder`'s slip narrowed by its own holder to the base world: a
        /// second credential, with a narrower scope, on the same key.
        fn narrowed_to_base_world(holder: &Holder) -> TestResult<Holder> {
            let mut slip = holder.slip.clone();
            let mut ceiling = Scope::top();
            ceiling.worlds = ScopeAxis::Some([ScopeId(base_world_id())].into_iter().collect());
            slip.attenuate(
                SlipCaveat {
                    scope: Some(ceiling),
                    ..Default::default()
                },
                &holder.key,
            )?;
            Ok(Holder {
                slip,
                key: holder.key.clone(),
            })
        }

        /// One JSON-RPC request to the tool-first endpoint under `holder`'s
        /// slip and a fresh holder proof: the HTTP status and the body.
        async fn rpc(
            &self,
            holder: &Holder,
            id: u64,
            method: &str,
            params: Value,
        ) -> TestResult<(u16, Vec<u8>)> {
            let timestamp = self.vault.now_recorded_at();
            let nonce = EntityId::now().to_hex();
            let challenge = holder_proof_challenge(timestamp, &nonce);
            let signature = holder
                .key
                .sign(&holder.slip.binding_transcript(&challenge)?)
                .to_bytes();
            let binding = json!({
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": hex(&signature),
            });
            let request = Request::post(MCP_PATH)
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("Bearer {}", holder.slip.to_token()?),
                )
                .header("x-oneiron-binding", binding.to_string())
                .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                        .to_string(),
                ))?;
            let response = self.app.clone().oneshot(request).await?;
            let status = response.status().as_u16();
            let bytes = to_bytes(response.into_body(), usize::MAX).await?;
            Ok((status, bytes.to_vec()))
        }

        /// `initialize`, then `tools/list`: the listed tools, as bytes.
        async fn listed_tools(&self, holder: &Holder, id: u64) -> TestResult<Vec<u8>> {
            let (status, body) = self
                .rpc(
                    holder,
                    id,
                    "initialize",
                    json!({
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": { "name": "mcp-tool-annotations", "version": "1" },
                    }),
                )
                .await?;
            let reply: Value = serde_json::from_slice(&body)?;
            assert_eq!(status, 200, "{reply}");
            assert!(reply.get("error").is_none(), "{reply}");
            let (status, body) = self.rpc(holder, id + 1, "tools/list", json!({})).await?;
            let reply: Value = serde_json::from_slice(&body)?;
            assert_eq!(status, 200, "{reply}");
            Ok(serde_json::to_vec(&reply["result"]["tools"])?)
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn two_credentials_list_the_same_annotated_tools() -> TestResult {
        on_engine_stack(list_tools_under_two_credentials)
    }

    async fn list_tools_under_two_credentials() -> TestResult {
        let fixture = Fixture::new()?;
        let reader = fixture.mint_reader()?;
        let narrowed = Fixture::narrowed_to_base_world(&reader)?;
        assert_ne!(reader.slip.to_token()?, narrowed.slip.to_token()?);

        let first = fixture.listed_tools(&reader, 1).await?;
        let second = fixture.listed_tools(&narrowed, 3).await?;
        // The same bytes for both credentials, and the frozen registration's.
        assert!(first == second, "two credentials got different listings");
        let registered =
            serde_json::to_vec(registered_surface(McpSurfaceMode::ToolFirst).listing())?;
        assert!(
            first == registered,
            "the served listing is not the registration"
        );

        // The hints reach the wire.
        let tools: Value = serde_json::from_slice(&first)?;
        let recall = tools
            .as_array()
            .ok_or("tools/list lists tools")?
            .iter()
            .find(|tool| tool["name"] == "vault.recall")
            .ok_or("the tool-first endpoint lists vault.recall")?;
        assert_eq!(
            recall["annotations"],
            json!({ "readOnlyHint": true }),
            "{recall}"
        );
        Ok(())
    }
}
