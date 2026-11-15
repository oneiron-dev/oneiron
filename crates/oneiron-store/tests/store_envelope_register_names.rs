//! The names of 6 name lists in `oneiron-store`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-store/src/settings/web_connector/mod.rs`
//! - `crates/oneiron-store/src/settings/web_connector/provider.rs`
//! - `crates/oneiron-store/src/write_envelope/coping_outcome.rs`
//! - `crates/oneiron-store/src/write_envelope/skill_source/hub_record.rs`

use oneiron_store::settings::web_connector::WebTool;
use oneiron_store::settings::web_connector::provider::WebProvider;
use oneiron_store::write_envelope::coping_outcome::CopingStrategy;
use oneiron_store::write_envelope::skill_source::hub_record::HubSyncPolicy;
use oneiron_store::write_envelope::skill_source::hub_record::SkillHubKind;
use oneiron_store::write_envelope::skill_source::hub_record::SkillHubTrustTier;
use serde_json::Value;

/// Every row of `WebTool`, as its hand table spelled it.
const WEB_TOOL_ROWS: [(WebTool, &str); 2] =
    [(WebTool::Search, "search"), (WebTool::Fetch, "fetch")];

#[test]
fn every_web_tool_keeps_its_name() {
    assert_eq!(WebTool::Search.as_str(), "search");
    assert_eq!(WebTool::Fetch.as_str(), "fetch");
}

#[test]
fn every_web_tool_name_is_its_serde_name() {
    for (row, name) in WEB_TOOL_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: WebTool =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn web_tool_parse_reads_each_name_back() {
    for (row, name) in WEB_TOOL_ROWS {
        assert_eq!(WebTool::parse(name), Some(row), "{name}");
    }
    assert_eq!(WebTool::parse("not.a.row"), None);
}

/// Every row of `WebProvider`, as its hand table spelled it.
const WEB_PROVIDER_ROWS: [(WebProvider, &str); 6] = [
    (WebProvider::Tavily, "tavily"),
    (WebProvider::Exa, "exa"),
    (WebProvider::Brave, "brave"),
    (WebProvider::Tinyfish, "tinyfish"),
    (WebProvider::ContextDev, "context_dev"),
    (WebProvider::Octen, "octen"),
];

#[test]
fn every_web_provider_keeps_its_name() {
    assert_eq!(WebProvider::Tavily.as_str(), "tavily");
    assert_eq!(WebProvider::Exa.as_str(), "exa");
    assert_eq!(WebProvider::Brave.as_str(), "brave");
    assert_eq!(WebProvider::Tinyfish.as_str(), "tinyfish");
    assert_eq!(WebProvider::ContextDev.as_str(), "context_dev");
    assert_eq!(WebProvider::Octen.as_str(), "octen");
}

#[test]
fn every_web_provider_name_is_its_serde_name() {
    for (row, name) in WEB_PROVIDER_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: WebProvider =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `CopingStrategy`, as its hand table spelled it.
const COPING_STRATEGY_ROWS: [(CopingStrategy, &str); 6] = [
    (CopingStrategy::SitSel, "SitSel"),
    (CopingStrategy::SitMod, "SitMod"),
    (CopingStrategy::AttDep, "AttDep"),
    (CopingStrategy::CogChg, "CogChg"),
    (CopingStrategy::ResMod, "ResMod"),
    (CopingStrategy::ERFlex, "ERFlex"),
];

#[test]
fn every_coping_strategy_keeps_its_name() {
    assert_eq!(CopingStrategy::SitSel.as_str(), "SitSel");
    assert_eq!(CopingStrategy::SitMod.as_str(), "SitMod");
    assert_eq!(CopingStrategy::AttDep.as_str(), "AttDep");
    assert_eq!(CopingStrategy::CogChg.as_str(), "CogChg");
    assert_eq!(CopingStrategy::ResMod.as_str(), "ResMod");
    assert_eq!(CopingStrategy::ERFlex.as_str(), "ERFlex");
}

#[test]
fn every_coping_strategy_name_is_its_serde_name() {
    for (row, name) in COPING_STRATEGY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CopingStrategy =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn coping_strategy_parse_reads_each_name_back() {
    for (row, name) in COPING_STRATEGY_ROWS {
        assert_eq!(CopingStrategy::parse(name), Some(row), "{name}");
    }
    assert_eq!(CopingStrategy::parse("not.a.row"), None);
}

/// Every row of `SkillHubKind`, as its hand table spelled it.
const SKILL_HUB_KIND_ROWS: [(SkillHubKind, &str); 3] = [
    (SkillHubKind::Git, "git"),
    (SkillHubKind::HttpIndex, "http-index"),
    (SkillHubKind::LocalDir, "local-dir"),
];

#[test]
fn every_skill_hub_kind_keeps_its_name() {
    assert_eq!(SkillHubKind::Git.as_str(), "git");
    assert_eq!(SkillHubKind::HttpIndex.as_str(), "http-index");
    assert_eq!(SkillHubKind::LocalDir.as_str(), "local-dir");
}

#[test]
fn every_skill_hub_kind_name_is_its_serde_name() {
    for (row, name) in SKILL_HUB_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: SkillHubKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `SkillHubTrustTier`, as its hand table spelled it.
const SKILL_HUB_TRUST_TIER_ROWS: [(SkillHubTrustTier, &str); 3] = [
    (SkillHubTrustTier::Untrusted, "untrusted"),
    (SkillHubTrustTier::Community, "community"),
    (SkillHubTrustTier::Verified, "verified"),
];

#[test]
fn every_skill_hub_trust_tier_keeps_its_name() {
    assert_eq!(SkillHubTrustTier::Untrusted.as_str(), "untrusted");
    assert_eq!(SkillHubTrustTier::Community.as_str(), "community");
    assert_eq!(SkillHubTrustTier::Verified.as_str(), "verified");
}

#[test]
fn every_skill_hub_trust_tier_name_is_its_serde_name() {
    for (row, name) in SKILL_HUB_TRUST_TIER_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: SkillHubTrustTier =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `HubSyncPolicy`, as its hand table spelled it.
const HUB_SYNC_POLICY_ROWS: [(HubSyncPolicy, &str); 4] = [
    (HubSyncPolicy::PinnedRef, "pinned-ref"),
    (HubSyncPolicy::PinnedCommit, "pinned-commit"),
    (HubSyncPolicy::ContentHashFrozen, "content-hash-frozen"),
    (HubSyncPolicy::MirrorOfHub, "mirror-of-hub"),
];

#[test]
fn every_hub_sync_policy_keeps_its_name() {
    assert_eq!(HubSyncPolicy::PinnedRef.as_str(), "pinned-ref");
    assert_eq!(HubSyncPolicy::PinnedCommit.as_str(), "pinned-commit");
    assert_eq!(
        HubSyncPolicy::ContentHashFrozen.as_str(),
        "content-hash-frozen"
    );
    assert_eq!(HubSyncPolicy::MirrorOfHub.as_str(), "mirror-of-hub");
}

#[test]
fn every_hub_sync_policy_name_is_its_serde_name() {
    for (row, name) in HUB_SYNC_POLICY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: HubSyncPolicy =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn hub_sync_policy_parse_reads_each_name_back() {
    for (row, name) in HUB_SYNC_POLICY_ROWS {
        assert_eq!(HubSyncPolicy::parse(name), Some(row), "{name}");
    }
    assert_eq!(HubSyncPolicy::parse("not.a.row"), None);
}
