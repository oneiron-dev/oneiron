//! Agent-run batch consent: see what a run is waiting on, then approve or
//! decline the whole run in one act (OF-211).
//!
//! A run's pending proposals are one content-bound bundle. Review returns its
//! id with the bodies read in the same transaction; resolve must present that
//! id, and the engine re-hashes the live bundle inside the resolving
//! transaction, so an approval never lands on proposals the owner did not see.
//! Review shows each value through the release redaction, as every serve
//! path does; the id stays bound to the stored body. A run id is free text
//! its proposer chose, so it is shown redacted too, beside a `run_ref` that
//! review and resolve accept in its place, in a field of its own: a run id
//! may be any text, a `run_ref` among it, so one read as the other would let
//! one run's id select another.

use oneiron::claim::ClaimBody;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::run_tree::{GateConsentBundle, GateConsentBundleAction};
use oneiron::write_envelope::WriteActor;
use oneiron::{ClaimSubject, EntityId, Vault};
use serde::Serialize;

use super::{OwnerError, OwnerResult};

/// Pending rows read when listing runs; a run past this is still resolvable.
const PENDING_SCAN_LIMIT: usize = 10_000;

/// A run with proposals waiting for the owner.
#[derive(Debug, Serialize)]
pub(crate) struct PendingRun {
    /// The run id through the release redaction.
    pub(crate) run_id: String,
    /// Names the run to review and resolve, whatever its id holds.
    pub(crate) run_ref: String,
    pub(crate) pending: usize,
}

/// One run's waiting proposals as the owner reviews them.
#[derive(Debug, Serialize)]
pub(crate) struct RunReview {
    /// Send this back to approve or decline exactly what was reviewed.
    pub(crate) bundle_id: String,
    pub(crate) name: String,
    pub(crate) run_id: String,
    pub(crate) run_ref: String,
    pub(crate) agent_label: Option<String>,
    pub(crate) proposals: Vec<RunProposal>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunProposal {
    pub(crate) claim_id: String,
    pub(crate) predicate: String,
    pub(crate) subject: String,
    /// The proposed value with credentials and sensitive fields redacted.
    pub(crate) value: serde_json::Value,
    pub(crate) reason_codes: Vec<String>,
    pub(crate) created_at: u64,
}

/// The run's one receipt.
#[derive(Debug, Serialize)]
pub(crate) struct RunResolved {
    pub(crate) run_id: String,
    pub(crate) run_ref: String,
    pub(crate) bundle_id: String,
    pub(crate) action: &'static str,
    pub(crate) receipt_id: String,
    pub(crate) claim_ids: Vec<String>,
}

/// Runs with proposals waiting, most proposals first.
pub(crate) fn pending(vault: &Vault) -> OwnerResult<Vec<PendingRun>> {
    let mut runs: Vec<(String, usize)> = vault
        .pending_gate_consent_groups(PENDING_SCAN_LIMIT)?
        .into_iter()
        .filter_map(|group| {
            group
                .dreamer_run_id
                .map(|run_id| (run_id, group.records.len()))
        })
        .collect();
    runs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(runs
        .into_iter()
        .map(|(run_id, pending)| PendingRun {
            run_ref: run_ref(&run_id),
            run_id: redacted(run_id),
            pending,
        })
        .collect())
}

/// A run's handle for review and resolve, derived from its id and never
/// carrying it.
fn run_ref(run_id: &str) -> String {
    hex(&blake3::derive_key(
        "oneiron owner run ref v1",
        run_id.as_bytes(),
    ))
}

/// How the owner names a run: by its id, or by the `run_ref` the listing
/// printed for it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RunName<'a> {
    Id(&'a str),
    Ref(&'a str),
}

impl<'a> RunName<'a> {
    /// The run a request names in exactly one of its two fields.
    pub(crate) fn from_fields(
        run_id: Option<&'a str>,
        run_ref: Option<&'a str>,
    ) -> OwnerResult<Self> {
        match (run_id, run_ref) {
            (Some(run_id), None) => Ok(Self::Id(run_id)),
            (None, Some(run_ref)) => Ok(Self::Ref(run_ref)),
            _ => Err(OwnerError::Invalid(
                "name the run by exactly one of run_id or run_ref".into(),
            )),
        }
    }
}

/// The id of the run `run` names: the id itself, or the waiting run whose
/// `run_ref` it is.
fn run_named(vault: &Vault, run: RunName<'_>) -> OwnerResult<String> {
    match run {
        RunName::Id(run_id) => Ok(run_id.to_owned()),
        RunName::Ref(reference) => vault
            .pending_gate_consent_groups(PENDING_SCAN_LIMIT)?
            .into_iter()
            .filter_map(|group| group.dreamer_run_id)
            .find(|run_id| run_ref(run_id) == reference)
            .ok_or_else(|| oneiron::Error::EntityNotFound.into()),
    }
}

/// What one run is waiting on.
pub(crate) fn review(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    run: RunName<'_>,
) -> OwnerResult<RunReview> {
    let run_id = run_named(vault, run)?;
    let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
    let (bundle, bodies) = vault.review_gate_consent_bundle_with_bodies(&actor, &run_id)?;
    Ok(review_of(bundle, bodies))
}

fn review_of(bundle: GateConsentBundle, bodies: Vec<ClaimBody>) -> RunReview {
    let proposals = bundle
        .members
        .into_iter()
        .zip(bodies)
        .map(|(member, body)| {
            // Redact a copy of the stored MessagePack before projecting it:
            // a value stored while the ingest scan was off is still never
            // served, and binary is checked before it becomes hex.
            let mut value = body.value;
            oneiron::batch::export::redact_messagepack_credentials(&mut value);
            RunProposal {
                claim_id: member.claim_id.to_hex(),
                predicate: redacted(body.predicate),
                subject: match &body.subject {
                    ClaimSubject::Entity(id) => id.to_hex(),
                    ClaimSubject::Edge { source, target, .. } => {
                        format!("{}->{}", source.to_hex(), target.to_hex())
                    }
                },
                value: crate::commands::msgpack_value_json(&value),
                reason_codes: member.reason_codes,
                created_at: member.created_at,
            }
        })
        .collect();
    RunReview {
        bundle_id: hex(&bundle.bundle_id),
        name: redacted(bundle.name),
        run_ref: run_ref(&bundle.dreamer_run_id),
        run_id: redacted(bundle.dreamer_run_id),
        agent_label: bundle.agent_label.map(redacted),
        proposals,
    }
}

/// A stored string as the release redaction serves it: a predicate, a run id
/// or a label is free text a proposer chose, so it is checked like the value.
fn redacted(text: String) -> String {
    let mut value = rmpv::Value::from(text);
    oneiron::batch::export::redact_messagepack_credentials(&mut value);
    value.as_str().unwrap_or_default().to_owned()
}

/// Approves or declines the whole reviewed run in one engine transaction.
pub(crate) fn resolve(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    run: RunName<'_>,
    bundle_id: &str,
    action: GateConsentBundleAction,
) -> OwnerResult<RunResolved> {
    let expected = parse_bundle_id(bundle_id)?;
    let run_id = run_named(vault, run)?;
    let receipt = vault
        .resolve_gate_consent_bundle(owner, expected, &run_id, action, vault.now_recorded_at())
        .map_err(|error| match error.kind() {
            oneiron::ErrorKind::GateConsentStale => OwnerError::Changed(
                "this run's proposals changed since they were reviewed; review it again".into(),
            ),
            _ => OwnerError::from(error),
        })?;
    Ok(RunResolved {
        run_ref: run_ref(&receipt.dreamer_run_id),
        run_id: redacted(receipt.dreamer_run_id),
        bundle_id: hex(&receipt.bundle_id),
        action: receipt.action.as_str(),
        receipt_id: receipt.receipt_id.to_hex(),
        claim_ids: receipt
            .member_claim_ids
            .iter()
            .map(EntityId::to_hex)
            .collect(),
    })
}

fn parse_bundle_id(value: &str) -> OwnerResult<[u8; 32]> {
    let invalid = || OwnerError::Invalid("bundle_id must be 64 lowercase hex characters".into());
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut id = [0_u8; 32];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `oneiron runs show`: the local owner's review redacts what the ingest
    /// scan let through while it was off.
    #[test]
    fn runs_show_redacts_stored_credentials_with_the_scan_off() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open_owned(dir.path(), oneiron::VaultConfig::default()).unwrap();
        let owner = super::super::local_owner(&vault).unwrap();
        vault
            .set_secret_scan_mode(
                &owner,
                oneiron::policy_model::SecretScanMode::Off,
                vault.now_recorded_at(),
            )
            .unwrap();
        let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
        let agent = EntityId::now();
        for value in [
            rmpv::Value::from(format!("my token is {token}")),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("api_key"),
                rmpv::Value::from("sk-not-for-display-0123456789"),
            )]),
            rmpv::Value::Binary(token.as_bytes().to_vec()),
        ] {
            vault
                .park_run_proposal_for_test("cli-run", agent, EntityId::now(), value)
                .unwrap();
        }
        let reviewed = review(&vault, &owner, RunName::Id("cli-run")).unwrap();
        let shown = serde_json::to_string(&reviewed).unwrap();
        let hex: String = token.bytes().map(|byte| format!("{byte:02x}")).collect();
        assert!(!shown.contains(token), "{shown}");
        assert!(!shown.contains(&hex), "{shown}");
        assert!(!shown.contains("sk-not-for-display"), "{shown}");
    }
}
