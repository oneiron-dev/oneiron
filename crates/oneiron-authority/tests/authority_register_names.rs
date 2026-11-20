//! The names of 5 name lists in `oneiron-authority`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-authority/src/authority/comm_reach.rs`
//! - `crates/oneiron-authority/src/authority/membership_execution.rs`
//! - `crates/oneiron-authority/src/authority/owner_work/result.rs`
//! - `crates/oneiron-authority/src/authority/support_delegation.rs`

use oneiron_authority::authority::CommReach;
use oneiron_authority::authority::CustodyUncheckedReason;
use oneiron_authority::authority::MembershipExecutionCause;
use oneiron_authority::authority::OwnerWorkRefusal;
use oneiron_authority::authority::SupportRepair;
use serde_json::Value;

/// Every row of `CommReach`, as its hand table spelled it.
const COMM_REACH_ROWS: [(CommReach, &str); 4] = [
    (CommReach::Parent, "parent"),
    (CommReach::Subtree, "subtree"),
    (CommReach::Project, "project"),
    (CommReach::Vault, "vault"),
];

#[test]
fn every_comm_reach_keeps_its_name() {
    assert_eq!(CommReach::Parent.as_str(), "parent");
    assert_eq!(CommReach::Subtree.as_str(), "subtree");
    assert_eq!(CommReach::Project.as_str(), "project");
    assert_eq!(CommReach::Vault.as_str(), "vault");
}

#[test]
fn every_comm_reach_name_is_its_serde_name() {
    for (row, name) in COMM_REACH_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CommReach =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn comm_reach_parse_reads_each_name_back() {
    for (row, name) in COMM_REACH_ROWS {
        assert_eq!(CommReach::parse(name), Some(row), "{name}");
    }
    assert_eq!(CommReach::parse("not.a.row"), None);
}

/// Every row of `MembershipExecutionCause`, as its hand table spelled it.
const MEMBERSHIP_EXECUTION_CAUSE_ROWS: [(MembershipExecutionCause, &str); 5] = [
    (MembershipExecutionCause::AssignRole, "assign_role"),
    (MembershipExecutionCause::RemoveMember, "remove_member"),
    (MembershipExecutionCause::Leave, "leave"),
    (
        MembershipExecutionCause::TransferOwnership,
        "transfer_ownership",
    ),
    (MembershipExecutionCause::RemoveOwner, "remove_owner"),
];

#[test]
fn every_membership_execution_cause_keeps_its_name() {
    assert_eq!(MembershipExecutionCause::AssignRole.wire(), "assign_role");
    assert_eq!(
        MembershipExecutionCause::RemoveMember.wire(),
        "remove_member"
    );
    assert_eq!(MembershipExecutionCause::Leave.wire(), "leave");
    assert_eq!(
        MembershipExecutionCause::TransferOwnership.wire(),
        "transfer_ownership"
    );
    assert_eq!(MembershipExecutionCause::RemoveOwner.wire(), "remove_owner");
}

#[test]
fn every_membership_execution_cause_name_is_its_serde_name() {
    for (row, name) in MEMBERSHIP_EXECUTION_CAUSE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: MembershipExecutionCause =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn membership_execution_cause_parse_reads_each_name_back() {
    for (row, name) in MEMBERSHIP_EXECUTION_CAUSE_ROWS {
        assert_eq!(MembershipExecutionCause::parse(name), Some(row), "{name}");
    }
    assert_eq!(MembershipExecutionCause::parse("not.a.row"), None);
}

/// Every row of `OwnerWorkRefusal`, as its hand table spelled it.
const OWNER_WORK_REFUSAL_ROWS: [(OwnerWorkRefusal, &str); 12] = [
    (OwnerWorkRefusal::StaleRevision, "stale_revision"),
    (OwnerWorkRefusal::OwnerNotLive, "owner_not_live"),
    (OwnerWorkRefusal::WorldNotLive, "world_not_live"),
    (OwnerWorkRefusal::ExecutorNotReader, "executor_not_reader"),
    (OwnerWorkRefusal::HomeNotLinked, "home_not_linked"),
    (OwnerWorkRefusal::SecretNotPortable, "secret_not_portable"),
    (OwnerWorkRefusal::SecretNotActive, "secret_not_active"),
    (OwnerWorkRefusal::RecipientChanged, "recipient_changed"),
    (OwnerWorkRefusal::InvalidInput, "invalid_input"),
    (OwnerWorkRefusal::CustodyConflict, "custody_conflict"),
    (OwnerWorkRefusal::WiderThanFloor, "wider_than_floor"),
    (
        OwnerWorkRefusal::RootRevisionMismatch,
        "root_revision_mismatch",
    ),
];

#[test]
fn every_owner_work_refusal_keeps_its_name() {
    assert_eq!(OwnerWorkRefusal::StaleRevision.as_str(), "stale_revision");
    assert_eq!(OwnerWorkRefusal::OwnerNotLive.as_str(), "owner_not_live");
    assert_eq!(OwnerWorkRefusal::WorldNotLive.as_str(), "world_not_live");
    assert_eq!(
        OwnerWorkRefusal::ExecutorNotReader.as_str(),
        "executor_not_reader"
    );
    assert_eq!(OwnerWorkRefusal::HomeNotLinked.as_str(), "home_not_linked");
    assert_eq!(
        OwnerWorkRefusal::SecretNotPortable.as_str(),
        "secret_not_portable"
    );
    assert_eq!(
        OwnerWorkRefusal::SecretNotActive.as_str(),
        "secret_not_active"
    );
    assert_eq!(
        OwnerWorkRefusal::RecipientChanged.as_str(),
        "recipient_changed"
    );
    assert_eq!(OwnerWorkRefusal::InvalidInput.as_str(), "invalid_input");
    assert_eq!(
        OwnerWorkRefusal::CustodyConflict.as_str(),
        "custody_conflict"
    );
    assert_eq!(
        OwnerWorkRefusal::WiderThanFloor.as_str(),
        "wider_than_floor"
    );
    assert_eq!(
        OwnerWorkRefusal::RootRevisionMismatch.as_str(),
        "root_revision_mismatch"
    );
}

#[test]
fn every_owner_work_refusal_name_is_its_serde_name() {
    for (row, name) in OWNER_WORK_REFUSAL_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: OwnerWorkRefusal =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn owner_work_refusal_from_name_reads_each_name_back() {
    for (row, name) in OWNER_WORK_REFUSAL_ROWS {
        assert_eq!(OwnerWorkRefusal::from_name(name), Some(row), "{name}");
    }
    assert_eq!(OwnerWorkRefusal::from_name("not.a.row"), None);
}

/// Every row of `CustodyUncheckedReason`, as its hand table spelled it.
const CUSTODY_UNCHECKED_REASON_ROWS: [(CustodyUncheckedReason, &str); 5] = [
    (CustodyUncheckedReason::NoneNamed, "none_named"),
    (CustodyUncheckedReason::NonePublished, "none_published"),
    (CustodyUncheckedReason::Unread, "unread"),
    (CustodyUncheckedReason::OtherManifest, "other_manifest"),
    (CustodyUncheckedReason::Disagrees, "disagrees"),
];

#[test]
fn every_custody_unchecked_reason_keeps_its_name() {
    assert_eq!(CustodyUncheckedReason::NoneNamed.as_str(), "none_named");
    assert_eq!(
        CustodyUncheckedReason::NonePublished.as_str(),
        "none_published"
    );
    assert_eq!(CustodyUncheckedReason::Unread.as_str(), "unread");
    assert_eq!(
        CustodyUncheckedReason::OtherManifest.as_str(),
        "other_manifest"
    );
    assert_eq!(CustodyUncheckedReason::Disagrees.as_str(), "disagrees");
}

#[test]
fn every_custody_unchecked_reason_name_is_its_serde_name() {
    for (row, name) in CUSTODY_UNCHECKED_REASON_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CustodyUncheckedReason =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn custody_unchecked_reason_from_name_reads_each_name_back() {
    for (row, name) in CUSTODY_UNCHECKED_REASON_ROWS {
        assert_eq!(CustodyUncheckedReason::from_name(name), Some(row), "{name}");
    }
    assert_eq!(CustodyUncheckedReason::from_name("not.a.row"), None);
}

/// Every row of `SupportRepair`, as its hand table spelled it.
const SUPPORT_REPAIR_ROWS: [(SupportRepair, &str); 7] = [
    (
        SupportRepair::CriticalConfirmExpiry,
        "critical_confirm_expiry",
    ),
    (SupportRepair::SymbolLeaseExpiry, "symbol_lease_expiry"),
    (SupportRepair::EsignExpiry, "esign_expiry"),
    (SupportRepair::EsignSealBackstop, "esign_seal_backstop"),
    (SupportRepair::CommitmentLapse, "commitment_lapse"),
    (SupportRepair::PprCacheEviction, "ppr_cache_eviction"),
    (SupportRepair::SharedActMaturity, "shared_act_maturity"),
];

#[test]
fn every_support_repair_keeps_its_name() {
    assert_eq!(
        SupportRepair::CriticalConfirmExpiry.as_str(),
        "critical_confirm_expiry"
    );
    assert_eq!(
        SupportRepair::SymbolLeaseExpiry.as_str(),
        "symbol_lease_expiry"
    );
    assert_eq!(SupportRepair::EsignExpiry.as_str(), "esign_expiry");
    assert_eq!(
        SupportRepair::EsignSealBackstop.as_str(),
        "esign_seal_backstop"
    );
    assert_eq!(SupportRepair::CommitmentLapse.as_str(), "commitment_lapse");
    assert_eq!(
        SupportRepair::PprCacheEviction.as_str(),
        "ppr_cache_eviction"
    );
    assert_eq!(
        SupportRepair::SharedActMaturity.as_str(),
        "shared_act_maturity"
    );
}

#[test]
fn every_support_repair_name_is_its_serde_name() {
    for (row, name) in SUPPORT_REPAIR_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: SupportRepair =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
