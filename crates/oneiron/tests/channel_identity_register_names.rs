//! The channel identity names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron/src/channel_identity/binding.rs`
//! - `crates/oneiron/src/channel_identity/custody.rs`
//! - `crates/oneiron/src/channel_identity/lifecycle.rs`
//! - `crates/oneiron/src/channel_identity_provider/inbound_types.rs`
//! - `crates/oneiron/src/channel_identity_provider/line_adapter.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron::channel_identity::{
    ChannelIdentityFulfillment, ChannelIdentityState, DelegatedGrantScope,
};
use oneiron::channel_identity_provider::{LineChatKind, LineOfficialAccountPlanTier};
use serde_json::Value;

/// Every `ChannelIdentityFulfillment` row, as the hand `as_str` table spelled it.
const CHANNEL_IDENTITY_FULFILLMENT_ROWS: [(ChannelIdentityFulfillment, &str); 3] = [
    (ChannelIdentityFulfillment::Api, "api"),
    (ChannelIdentityFulfillment::Manual, "manual"),
    (ChannelIdentityFulfillment::Review, "review"),
];

#[test]
fn every_channel_identity_fulfillment_keeps_its_name() {
    assert_eq!(ChannelIdentityFulfillment::Api.as_str(), "api");
    assert_eq!(ChannelIdentityFulfillment::Manual.as_str(), "manual");
    assert_eq!(ChannelIdentityFulfillment::Review.as_str(), "review");
}

#[test]
fn every_channel_identity_fulfillment_name_is_its_serde_name() {
    for (row, name) in CHANNEL_IDENTITY_FULFILLMENT_ROWS {
        let written = serde_json::to_value(row).expect("a channel identity fulfillment serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ChannelIdentityFulfillment =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_channel_identity_fulfillment_name_reads_back() {
    for (row, name) in CHANNEL_IDENTITY_FULFILLMENT_ROWS {
        assert_eq!(ChannelIdentityFulfillment::parse(name), Some(row), "{name}");
    }
    assert_eq!(ChannelIdentityFulfillment::parse("not-a-name"), None);
    assert_eq!(ChannelIdentityFulfillment::parse(""), None);
}

/// Every `DelegatedGrantScope` row, as the hand `as_str` table spelled it.
const DELEGATED_GRANT_SCOPE_ROWS: [(DelegatedGrantScope, &str); 3] = [
    (DelegatedGrantScope::MailRead, "mail.read"),
    (DelegatedGrantScope::MailMetadata, "mail.metadata"),
    (DelegatedGrantScope::MailSend, "mail.send"),
];

#[test]
fn every_delegated_grant_scope_keeps_its_name() {
    assert_eq!(DelegatedGrantScope::MailRead.as_str(), "mail.read");
    assert_eq!(DelegatedGrantScope::MailMetadata.as_str(), "mail.metadata");
    assert_eq!(DelegatedGrantScope::MailSend.as_str(), "mail.send");
}

#[test]
fn every_delegated_grant_scope_name_is_its_serde_name() {
    for (row, name) in DELEGATED_GRANT_SCOPE_ROWS {
        let written = serde_json::to_value(row).expect("a delegated grant scope serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: DelegatedGrantScope =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_delegated_grant_scope_name_reads_back() {
    for (row, name) in DELEGATED_GRANT_SCOPE_ROWS {
        assert_eq!(DelegatedGrantScope::parse(name), Some(row), "{name}");
    }
    assert_eq!(DelegatedGrantScope::parse("not-a-name"), None);
    assert_eq!(DelegatedGrantScope::parse(""), None);
}

/// Every `ChannelIdentityState` row, as the hand `as_str` table spelled it.
const CHANNEL_IDENTITY_STATE_ROWS: [(ChannelIdentityState, &str); 7] = [
    (ChannelIdentityState::Requested, "requested"),
    (
        ChannelIdentityState::PendingFulfillment,
        "pending_fulfillment",
    ),
    (ChannelIdentityState::Active, "active"),
    (ChannelIdentityState::Rotating, "rotating"),
    (ChannelIdentityState::Released, "released"),
    (ChannelIdentityState::Quarantine, "quarantine"),
    (ChannelIdentityState::Tombstone, "tombstone"),
];

#[test]
fn every_channel_identity_state_keeps_its_name() {
    assert_eq!(ChannelIdentityState::Requested.as_str(), "requested");
    assert_eq!(
        ChannelIdentityState::PendingFulfillment.as_str(),
        "pending_fulfillment"
    );
    assert_eq!(ChannelIdentityState::Active.as_str(), "active");
    assert_eq!(ChannelIdentityState::Rotating.as_str(), "rotating");
    assert_eq!(ChannelIdentityState::Released.as_str(), "released");
    assert_eq!(ChannelIdentityState::Quarantine.as_str(), "quarantine");
    assert_eq!(ChannelIdentityState::Tombstone.as_str(), "tombstone");
}

#[test]
fn every_channel_identity_state_name_is_its_serde_name() {
    for (row, name) in CHANNEL_IDENTITY_STATE_ROWS {
        let written = serde_json::to_value(row).expect("a channel identity state serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ChannelIdentityState =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_channel_identity_state_name_reads_back() {
    for (row, name) in CHANNEL_IDENTITY_STATE_ROWS {
        assert_eq!(ChannelIdentityState::parse(name), Some(row), "{name}");
    }
    assert_eq!(ChannelIdentityState::parse("not-a-name"), None);
    assert_eq!(ChannelIdentityState::parse(""), None);
}

/// Every `LineChatKind` row, as the hand `as_str` table spelled it.
const LINE_CHAT_KIND_ROWS: [(LineChatKind, &str); 2] =
    [(LineChatKind::Group, "group"), (LineChatKind::Room, "room")];

#[test]
fn every_line_chat_kind_keeps_its_name() {
    assert_eq!(LineChatKind::Group.as_str(), "group");
    assert_eq!(LineChatKind::Room.as_str(), "room");
}

#[test]
fn every_line_chat_kind_name_is_its_serde_name() {
    for (row, name) in LINE_CHAT_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a line chat kind serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: LineChatKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_line_chat_kind_name_reads_back() {
    for (row, name) in LINE_CHAT_KIND_ROWS {
        assert_eq!(LineChatKind::parse(name), Some(row), "{name}");
    }
    assert_eq!(LineChatKind::parse("not-a-name"), None);
    assert_eq!(LineChatKind::parse(""), None);
}

/// Every `LineOfficialAccountPlanTier` row, as the hand `as_str` table spelled it.
const LINE_OFFICIAL_ACCOUNT_PLAN_TIER_ROWS: [(LineOfficialAccountPlanTier, &str); 3] = [
    (LineOfficialAccountPlanTier::Free, "free"),
    (LineOfficialAccountPlanTier::Paid, "paid"),
    (LineOfficialAccountPlanTier::Enterprise, "enterprise"),
];

#[test]
fn every_line_official_account_plan_tier_keeps_its_name() {
    assert_eq!(LineOfficialAccountPlanTier::Free.as_str(), "free");
    assert_eq!(LineOfficialAccountPlanTier::Paid.as_str(), "paid");
    assert_eq!(
        LineOfficialAccountPlanTier::Enterprise.as_str(),
        "enterprise"
    );
}

#[test]
fn every_line_official_account_plan_tier_name_is_its_serde_name() {
    for (row, name) in LINE_OFFICIAL_ACCOUNT_PLAN_TIER_ROWS {
        let written =
            serde_json::to_value(row).expect("a line official account plan tier serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: LineOfficialAccountPlanTier =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
