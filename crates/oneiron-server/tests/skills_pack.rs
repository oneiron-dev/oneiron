use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const PACK: &str = include_str!("../oneiron.skills.md");
const API_RS: &str = include_str!("../src/api.rs");
const SKILL_PACK_PATH: &str = "oneiron.skills.md";
const SKILL_PACK_LAYER_BOUNDARY: &str =
    "skills = how to think about memory; MCP tools = what to call";

const EXPECTED_REGISTERED_ROUTES: &[&str] = &[
    "/api/openapi.json",
    "/api/skills/oneiron.skills.md",
    "/api/health",
    "/api/core/discover",
    "/api/search/vector",
    "/api/search/text",
    "/api/entity/{id}",
    "/api/edges/{id}",
    "/api/context-pack",
    "/api/companion/resume",
    "/api/lease/revoke",
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
fn documented_route_set_matches_api_routes_exactly() {
    let registered = route_set(registered_routes_from_api_source(API_RS));
    let expected = route_set(EXPECTED_REGISTERED_ROUTES.iter().copied());
    assert_eq!(
        registered, expected,
        "api.rs route table changed; update oneiron.skills.md and this contract test together"
    );

    let documented_counts = documented_api_literal_counts(PACK);
    let documented = documented_counts.keys().copied().collect::<BTreeSet<_>>();
    assert_eq!(documented, expected, "documented route literals drifted");

    for route in EXPECTED_REGISTERED_ROUTES {
        assert_eq!(
            documented_counts.get(route).copied(),
            Some(1),
            "route literal {route} must appear exactly once in the skill pack"
        );
    }
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
            && unauthorized.contains("Send the configured x-oneiron-secret header and retry."),
        "UNAUTHORIZED catalog entry must include a non-empty recovery_suggestions array"
    );
}

#[test]
fn mcp_discovery_advertisement_matches_committed_pack() {
    assert_eq!(
        rust_string_const(API_RS, "SKILL_PACK_PATH"),
        SKILL_PACK_PATH
    );
    assert_eq!(
        rust_string_const(API_RS, "SKILL_PACK_LAYER_BOUNDARY"),
        SKILL_PACK_LAYER_BOUNDARY
    );

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
        PACK.contains("`path` (`oneiron.skills.md`)"),
        "pack must document the committed path advertised by discovery"
    );
    assert!(
        PACK.contains(SKILL_PACK_LAYER_BOUNDARY),
        "pack must preserve the exact dual-layer boundary literal"
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

fn rust_string_const<'a>(source: &'a str, name: &str) -> &'a str {
    let prefix = format!("const {name}: &str =");
    let start = source
        .find(&prefix)
        .unwrap_or_else(|| panic!("missing Rust string const {name}"));
    let rest = source[start + prefix.len()..].trim_start();
    let value = rest
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("Rust const {name} must be a string literal"));
    let end = value
        .find('"')
        .unwrap_or_else(|| panic!("Rust const {name} string literal must close"));
    &value[..end]
}

fn registered_routes_from_api_source(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter_map(|line| {
        let start = line.find(".route(\"")? + ".route(\"".len();
        let rest = &line[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    })
}

fn route_set<'a>(routes: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    routes.into_iter().collect()
}

fn documented_api_literal_counts(markdown: &str) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    let mut cursor = markdown;

    while let Some(start) = cursor.find("/api/") {
        let route_start = &cursor[start..];
        let route_len = route_start
            .char_indices()
            .take_while(|(_, ch)| {
                ch.is_ascii_alphanumeric() || matches!(ch, '/' | '-' | '_' | '.' | '{' | '}')
            })
            .last()
            .map_or(0, |(index, ch)| index + ch.len_utf8());

        let route = &route_start[..route_len];
        *counts.entry(route).or_insert(0) += 1;
        cursor = &route_start[route_len..];
    }

    counts
}

fn section_between<'a>(text: &'a str, start_heading: &str, end_heading: &str) -> &'a str {
    let start = text
        .find(start_heading)
        .unwrap_or_else(|| panic!("missing section start {start_heading}"));
    let end = text[start..]
        .find(end_heading)
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing section end {end_heading}"));
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
