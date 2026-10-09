//! Census cases for what a campaign send reads about its recipient.
use super::Case;
use crate::campaign::claims::{PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_JURISDICTION};
use crate::campaign::compliance::PREDICATE_CRM_COMPLIANCE_EVIDENCE;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::comm::CommError;
use crate::edge::EdgeKind;
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

fn comm(error: CommError) -> Error {
    match error {
        CommError::Engine(error) => error,
        other => Error::InvalidConfig(format!("{other:?}")),
    }
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

/// An active claim of `predicate` about `subject`, made at `at`.
fn claim(
    vault: &Vault,
    id: EntityId,
    predicate: &str,
    subject: EntityId,
    value: Value,
    at: u64,
) -> Result<()> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    if predicate == PREDICATE_COMM_JURISDICTION {
        body.evidence = Some(Value::from("connector:profile-region"));
    }
    vault.put_claim(&id, &body, TimeRange { start: at, end: at }, at)
}

/// A `comm.jurisdiction` observation of `jurisdiction` at `observed_at`.
fn observed(jurisdiction: &str, observed_at: u64) -> Value {
    map(vec![
        ("jurisdiction", Value::from(jurisdiction)),
        ("observed_at", Value::from(observed_at)),
    ])
}

/// A recipient's dispatch evidence reaches it through its `claim_of` edge.
/// UK law exempts a business recipient from consent only on a known legal
/// form, so evidence taken off the recipient since the backup, its body
/// unchanged, leaves every campaign send to it failing that rule; a restore
/// would put the evidence back. A newer observation of the same jurisdiction
/// binds the same rules.
pub(super) fn campaign_compliance() -> Result<Case> {
    let (dir, vault) = open_vault();
    let sora =
        crate::comm::resolve_or_create_comm_party(&vault, "sora@example.com").map_err(comm)?;
    let reference = |seed| Value::from(entity(seed).to_hex());
    claim(
        &vault,
        entity(0xC0),
        PREDICATE_CAMPAIGN_MEMBER,
        sora,
        map(vec![
            ("campaign", reference(0xD0)),
            ("state", map(vec![("kind", Value::from("enrolled"))])),
            (
                "channels",
                Value::Array(vec![map(vec![
                    ("channel", Value::from("email")),
                    ("basis_evidence", reference(0xD1)),
                    ("sender_ref", reference(0xD2)),
                ])]),
            ),
        ]),
        5,
    )?;
    claim(
        &vault,
        entity(0xC1),
        PREDICATE_COMM_JURISDICTION,
        sora,
        observed("UK", 10),
        10,
    )?;
    let evidence = entity(0xC2);
    claim(
        &vault,
        evidence,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        sora,
        map(vec![("legal_form", Value::from("corporate"))]),
        10,
    )?;
    Case::after_backup(
        "campaign compliance rules",
        (dir, vault),
        move |vault| {
            claim(
                vault,
                entity(0xC3),
                PREDICATE_COMM_JURISDICTION,
                sora,
                observed("uk", 20),
                20,
            )
        },
        move |vault| {
            vault
                .delete_edge(&evidence, EdgeKind::ClaimOf, &sora)
                .map(drop)
        },
    )
}
