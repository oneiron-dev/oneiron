use std::fs;
use std::path::Path;

const PACK: &str = include_str!("../../oneiron.skills.md");
const SKILL_PACK_LAYER_BOUNDARY: &str =
    "skills = how to think about memory; MCP tools = what to call";

const EXPECTED_REGISTERED_ROUTES: &[&str] = &[
    "/a/{artifact}",
    "/a/{artifact}/",
    "/a/{artifact}/{*path}",
    "/api/openapi.json",
    "/api/skills/oneiron.skills.md",
    "/api/health",
    "/mcp",
    "/api/core/discover",
    "/api/search/vector",
    "/api/search/text",
    "/api/entity/{id}",
    "/api/edges/{id}",
    "/api/companion/resume",
    "/v1/companion/register/records/{record_id}/end-relationship",
    "/api/lease/revoke",
    "/v1/core/outbound/capabilities",
    "/v1/core/outbound/capabilities/{connector}",
    "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
    "/v1/core/run-tree",
    "/v1/core/run-tree/observe",
    "/v1/core/run-tree/intervene",
    "/v1/core/turns/annotate",
    "/v1/consumer/usage",
    "/v1/consumer/usage/details",
    "/v1/consumer/top-up",
    "/v1/usage/events",
    "/v1/usage/tenants/{tenant_id}/rollup",
];

#[test]
fn crate_local_pack_matches_root_artifact() {
    let root_pack_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("oneiron.skills.md");
    if root_pack_path.exists() {
        let root_pack =
            fs::read_to_string(root_pack_path).expect("root oneiron.skills.md must be readable");
        assert_eq!(
            PACK, root_pack,
            "crate-local oneiron.skills.md must match the root artifact"
        );
    }
}

#[test]
fn frontmatter_has_required_skill_keys() {
    let frontmatter = frontmatter(PACK);

    for key in ["name", "description"] {
        let value = frontmatter_scalar(frontmatter, key)
            .unwrap_or_else(|| panic!("frontmatter missing scalar key {key}"));
        assert!(!value.trim().is_empty(), "frontmatter key {key} is empty");
    }

    assert!(
        frontmatter_list(frontmatter, "trigger_phrases").len() >= 3,
        "frontmatter trigger_phrases must contain discovery phrases"
    );
    assert!(
        !frontmatter_list(frontmatter, "when_to_use").is_empty(),
        "frontmatter when_to_use must describe activation"
    );
}

#[test]
fn tier_headings_exist_in_progressive_order() {
    let tier1 = PACK.find("## Tier-1").expect("missing Tier-1 heading");
    let tier2 = PACK.find("## Tier-2").expect("missing Tier-2 heading");
    let tier3 = PACK.find("## Tier-3").expect("missing Tier-3 heading");

    assert!(tier1 < tier2, "Tier-1 must appear before Tier-2");
    assert!(tier2 < tier3, "Tier-2 must appear before Tier-3");
}

#[test]
fn tier1_endpoint_blocks_have_when_to_use_and_triggers() {
    let tier1 = section_between(PACK, "## Tier-1", "## Tier-2");

    for route in EXPECTED_REGISTERED_ROUTES {
        let block = tier1_endpoint_block(tier1, route);
        assert!(
            block.contains("- when-to-use:"),
            "Tier-1 block for {route} is missing when-to-use"
        );

        let trigger_line = block
            .find("- trigger phrases:")
            .unwrap_or_else(|| panic!("Tier-1 block for {route} is missing trigger phrases"));
        let trigger_count = block[trigger_line..]
            .lines()
            .skip(1)
            .take_while(|line| line.starts_with("  - "))
            .count();
        assert!(
            trigger_count > 0,
            "Tier-1 block for {route} needs at least one trigger phrase"
        );
    }
}

#[test]
fn tier3_error_catalog_uses_structured_recovery_fields() {
    let tier3 = section_after(PACK, "## Tier-3");

    for field in ["error_code", "human_message", "recovery_suggestions[]"] {
        assert!(
            tier3.contains(field),
            "Tier-3 error catalog missing field literal {field}"
        );
    }

    let unauthorized = section_after(tier3, "\"error_code\": \"UNAUTHORIZED\"");
    assert!(
        unauthorized.contains("\"human_message\": \"request is not authorized\""),
        "UNAUTHORIZED catalog entry must include a human_message"
    );
    assert!(
        unauthorized.contains("\"recovery_suggestions\": [")
            && unauthorized.contains("Send Authorization: Bearer credentials and retry."),
        "UNAUTHORIZED catalog entry must include a non-empty recovery_suggestions array"
    );
}

#[test]
fn mcp_discovery_advertisement_matches_committed_pack() {
    assert!(
        PACK.contains("- Skills are how to think about memory:"),
        "pack must keep the static skill-layer statement"
    );
    assert!(
        PACK.contains("- MCP tools are what to call:"),
        "pack must keep the callable MCP-layer statement"
    );
    assert!(
        PACK.contains("`skill_pack`: static agentskills.io pack advertisement"),
        "pack must document the discovery advertisement field"
    );
    assert!(
        PACK.contains("`endpoint` (`/api/skills/oneiron.skills.md`)"),
        "pack must document the HTTP endpoint advertised by discovery"
    );
    assert!(
        PACK.contains("same Oneiron HTTP origin"),
        "pack must tell agents how to resolve the endpoint without a local checkout"
    );
    assert!(
        !PACK.contains(&["`", "path", "` (`oneiron.skills.md`)"].concat())
            && !PACK.contains(&["`repo_", "path` (`oneiron.skills.md`)"].concat()),
        "pack must not document a bare relative skill-pack path"
    );
    assert!(
        PACK.contains(SKILL_PACK_LAYER_BOUNDARY),
        "pack must preserve the exact dual-layer boundary literal"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// ONE-1705 — the choose-your-own-lane onramp.
//
// The lanes are packaging, not semantics: one API, one credential, one error
// envelope, four carriers. These rows pin the routing surface an agent reads
// FIRST, because a lane heading that drifted, doubled, or lost its link would
// route an agent into a carrier it cannot run.
// ─────────────────────────────────────────────────────────────────────────

const LANE_HEADINGS: [&str; 4] = [
    "## Lane: code-mode-repl",
    "## Lane: thin-client",
    "## Lane: curl-cli",
    "## Lane: tool-first-mcp",
];

/// The onramp's own budget. It is the first screen: an agent must be able to
/// choose a carrier without ingesting the endpoint catalog first, so this
/// section stays small enough to read whole.
const ONRAMP_BYTE_BUDGET: usize = 6_144;

#[test]
fn onramp_offers_exactly_four_lanes_each_named_once() {
    assert_eq!(
        PACK.matches("\n## Lane: ").count(),
        LANE_HEADINGS.len(),
        "the pack must carry exactly the four pinned lane headings"
    );

    for heading in LANE_HEADINGS {
        assert_eq!(
            PACK.matches(heading).count(),
            1,
            "lane heading {heading} must appear exactly once"
        );
    }
}

#[test]
fn onramp_decision_tree_links_every_lane() {
    let tree = section_between(PACK, "## Agent Onramp", LANE_HEADINGS[0]);

    for anchor in [
        "#lane-code-mode-repl",
        "#lane-thin-client",
        "#lane-curl-cli",
        "#lane-tool-first-mcp",
    ] {
        assert!(
            tree.contains(anchor),
            "the decision tree must link {anchor} so an agent can jump to its lane"
        );
    }
}

/// The first screen comes before the catalog and stays bounded. Progressive
/// disclosure is the contract: the detailed route reference stays in the pack,
/// below the choice it informs.
#[test]
fn onramp_precedes_the_endpoint_catalog_and_stays_bounded() {
    let onramp = PACK
        .find("## Agent Onramp")
        .expect("missing onramp section");
    let auth = PACK
        .find("## Authentication")
        .expect("missing shared authentication section");
    let tier1 = PACK.find("## Tier-1").expect("missing Tier-1 heading");

    assert!(
        onramp < auth,
        "the onramp must open before shared reference"
    );
    assert!(
        auth < tier1,
        "shared reference precedes the endpoint catalog"
    );
    for heading in LANE_HEADINGS {
        let lane = PACK.find(heading).expect("missing lane heading");
        assert!(lane < tier1, "{heading} must precede the endpoint catalog");
    }

    assert!(
        auth - onramp <= ONRAMP_BYTE_BUDGET,
        "the onramp is {} bytes, over its {ONRAMP_BYTE_BUDGET}-byte first-screen budget",
        auth - onramp
    );
}

/// Lane 1 is the host dispatcher, not an HTTP import. Code mode shares the
/// wire with the other lanes; it does not share the HTTP client artifact.
#[test]
fn code_mode_lane_routes_to_the_host_dispatcher() {
    let lane = section_between(PACK, LANE_HEADINGS[0], LANE_HEADINGS[1]);

    assert!(
        lane.contains("setup_oneiron"),
        "the code-mode lane must open with the setup call"
    );
    assert!(
        lane.contains("host dispatcher") && lane.contains("self.oneiron"),
        "the code-mode lane must name the host dispatcher surface"
    );
    assert!(
        lane.contains("execute_code"),
        "the code-mode lane must say what drives the verb grammar"
    );
    assert!(
        !lane.contains("@oneiron/client"),
        "code mode must not be told to install the HTTP client"
    );
}

/// Lane 2 installs one package; lane 3 is bash-only. Each carries its own
/// first call and neither restates the catalog.
#[test]
fn thin_client_and_curl_lanes_each_carry_one_first_call() {
    let thin_client = section_between(PACK, LANE_HEADINGS[1], LANE_HEADINGS[2]);
    assert!(
        thin_client.contains("npm install @oneiron/client"),
        "the thin-client lane must show the one install"
    );
    assert!(
        thin_client.contains("HttpBaseClient") && thin_client.contains("Response"),
        "the thin-client lane must show the raw-response client"
    );

    let curl_cli = section_between(PACK, LANE_HEADINGS[2], LANE_HEADINGS[3]);
    assert!(
        curl_cli.contains("oneiron api discover") && curl_cli.contains("curl"),
        "the curl lane must show both the binary and the plain curl form"
    );
    assert!(
        curl_cli.contains("ONEIRON_SECRET"),
        "the curl lane must read the credential from the environment"
    );

    for lane in [thin_client, curl_cli] {
        assert!(
            !lane.contains("- when-to-use:"),
            "a lane must link the shared catalog, never repeat an endpoint block"
        );
    }
}

/// Lane 4 is a HOST registration choice. The skill must tell the agent to ask
/// its operator for the distinct tool-first endpoint, never to select or
/// switch a connector mode by itself.
#[test]
fn tool_first_lane_is_an_operator_registration_not_a_self_switch() {
    let lane = section_between(PACK, LANE_HEADINGS[3], "## Authentication");

    assert!(
        lane.contains("operator") || lane.contains("OPERATOR"),
        "lane 4 must address the operator"
    );
    assert!(
        lane.contains("register or provide"),
        "lane 4 must ask the operator to register or provide the endpoint"
    );
    assert!(
        lane.contains("/mcp/tool-first"),
        "lane 4 must name the distinct tool-first endpoint"
    );
    assert!(
        lane.contains("never self-selects") && lane.contains("never switches"),
        "lane 4 must forbid the agent selecting or switching its own connector mode"
    );
}

/// `openapi.rs` and `discover.rs` publish this identifier; the onramp edit
/// must not have moved it.
#[test]
fn frontmatter_name_stays_the_published_identifier() {
    assert!(
        PACK.starts_with("---\nname: oneiron-http-memory-api\n"),
        "the pack must keep its published skill identifier"
    );
}

fn frontmatter(markdown: &str) -> &str {
    let rest = markdown
        .strip_prefix("---\n")
        .expect("skill pack must start with YAML frontmatter");
    let end = rest
        .find("\n---\n")
        .expect("skill pack frontmatter must be closed");
    &rest[..end]
}

fn frontmatter_scalar<'a>(frontmatter: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    frontmatter.lines().find_map(|line| {
        let value = line.strip_prefix(&prefix)?;
        Some(value.trim().trim_matches('"'))
    })
}

fn frontmatter_list(frontmatter: &str, key: &str) -> Vec<String> {
    let header = format!("{key}:");
    let mut items = Vec::new();
    let mut in_list = false;

    for line in frontmatter.lines() {
        if line == header {
            in_list = true;
            continue;
        }
        if in_list {
            if let Some(item) = line.strip_prefix("  - ") {
                items.push(item.trim().trim_matches('"').to_owned());
            } else if !line.starts_with(' ') {
                break;
            }
        }
    }

    items
}

fn section_between<'a>(text: &'a str, start_heading: &str, end_heading: &str) -> &'a str {
    let start = text
        .find(start_heading)
        .unwrap_or_else(|| panic!("missing section start {start_heading}"));
    let end = text[start..].find(end_heading).map_or_else(
        || panic!("missing section end {end_heading}"),
        |offset| start + offset,
    );
    &text[start..end]
}

fn section_after<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("missing section marker {heading}"));
    &text[start..]
}

fn tier1_endpoint_block<'a>(tier1: &'a str, route: &str) -> &'a str {
    let route_pos = tier1
        .find(route)
        .unwrap_or_else(|| panic!("Tier-1 missing route literal {route}"));
    let block_start = tier1[..route_pos]
        .rfind("\n#### ")
        .unwrap_or_else(|| panic!("Tier-1 route {route} is not inside an endpoint block"));
    let block_tail = &tier1[route_pos..];
    let block_end = block_tail
        .find("\n#### ")
        .map_or(tier1.len(), |offset| route_pos + offset);

    &tier1[block_start..block_end]
}
