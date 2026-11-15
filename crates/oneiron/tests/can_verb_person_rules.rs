//! `can({verb})` reads a host door's proof rule (FIX-LIST
//! TAKES-PERSON-PROOF-MISSES-THREE-KINDS; UC-01 PR 0a). Three rows ask a
//! person's proof under a kind the catalogue did not read:
//! `vault.trusted_contacts.name` (`trusted_contact_person`: the owner's proof,
//! else a live person's own), `vault.check_in.answer` (`check_in_holder`) and
//! `vault.workflows.dispatch_bound` (`workflow_member`), both a live person
//! bound on their own slip. The dispatch refuses an agent's call to each before
//! its door runs, so the gate answers `person` for an agent, with the one
//! reason, as it already does for `vault.members.remove` (`shared_person`).
//! A person's own gate stays `unchecked`: none of the four has a preview.
//!
//! On main the three rows answer `unchecked` for an agent (the catalogue's
//! `takes_person_proof` names only `owner` and `shared_person`); with the
//! proof table the catalogue reads the row's rule, so they answer `person`.
//!
//! UC-01 PR 0b (FIX-LIST HOST-DOOR-UNNAMED-OWNER-HOOKS-FIRE): 37 rows whose
//! door proves the vault owner first named `"proof": "in_door"`, so an
//! agent's gate on each answered `unchecked` though the door refuses every
//! agent. They name rule `owner` now and answer `person` for an agent.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test can_verb_person_rules`.

use oneiron::memory::{CanAnswer, CanVerbAnswer, CanVerbGate, Memory};
use oneiron::verbs::CanRequest;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The three rows whose proof is a person's under a kind the catalogue missed.
const MISSED: [&str; 3] = [
    "vault.trusted_contacts.name",
    "vault.check_in.answer",
    "vault.workflows.dispatch_bound",
];
/// A row the catalogue already reads as a person's proof (`shared_person`).
const READ_BEFORE: &str = "vault.members.remove";
/// The rows whose door admits exactly the callers the owner's proof admits
/// (rule `owner` since UC-01 PR 0b).
const OWNER_DOOR_ROWS: [&str; 37] = [
    "ai.streams.release",
    "vault.budgets.resident_shares",
    "vault.budgets.resident_shares.set",
    "vault.code.snapshots.capture",
    "vault.code.symbols.neighbors",
    "vault.commitments.ledger",
    "vault.connectors.read_grants.grant",
    "vault.connectors.read_grants.revoke",
    "vault.connectors.replies.retry_failed",
    "vault.connectors.web.usage",
    "vault.decisions.asks.confirm_grant",
    "vault.dreamer.follower.keyframe",
    "vault.files.sources.exclude",
    "vault.inbox.groups.resolve",
    "vault.model_pack.revert",
    "vault.models.trials.resend_arm",
    "vault.outbox.diverged.answer",
    "vault.outbox.diverged.list",
    "vault.proactivity.digest.get",
    "vault.roots.requests.cancel",
    "vault.secrets.lift_history",
    "vault.settings.model_pack",
    "vault.settings.model_pack.replace",
    "vault.settings.snapshot_read.replace",
    "vault.settings.web_connector",
    "vault.settings.web_connector.replace",
    "vault.shape.groups",
    "vault.shape.groups.resolve",
    "vault.skill_hubs.clawhub.import",
    "vault.skill_hubs.clawhub.search",
    "vault.skills.optimize.tradeoff_asks.resolve",
    "vault.skills.proposal.settle",
    "vault.step_up.totp.reset",
    "vault.sync.documents.copy_edit.review",
    "vault.sync.documents.copy_edit.settle",
    "vault.sync.repo_manifests.conflict.discard",
    "vault.sync.repo_manifests.conflict.review",
];

/// The rows both tests judge: the three the catalogue missed, the one it
/// already read and the owner door rows.
fn person_rule_rows() -> impl Iterator<Item = &'static str> {
    MISSED
        .into_iter()
        .chain([READ_BEFORE])
        .chain(OWNER_DOOR_ROWS)
}

/// `memory`'s own `can({verb: {name: verb, params: {}}})`, as the wire
/// carries it.
fn own_gate(memory: &Memory<'_>, verb: &str) -> TestResult<CanVerbAnswer> {
    let request: CanRequest =
        serde_json::from_value(json!({ "verb": { "name": verb, "params": {} } }))?;
    match memory.can(&request)? {
        CanAnswer::Verb(answer) => Ok(answer),
        other => Err(format!("{verb}: not a verb gate: {other:?}").into()),
    }
}

/// A vault with its embedded owner and one registered agent: the vault, the
/// agent, and the tempdir it lives in.
fn open_vault() -> TestResult<(Vault, EntityId, EntityId, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let agent = vault.ensure_agent_principal("person-rules-agent")?;
    Ok((vault, owner, agent, directory))
}

/// An agent's own gate on each row whose rule asks a person's proof is
/// `person`, with the one reason, naming the agent: the three rows the
/// catalogue missed, the one it already read and the owner door rows.
#[test]
fn an_agent_gate_on_a_person_rule_row_is_person() -> TestResult {
    let (vault, _owner, agent, _directory) = open_vault()?;
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    for verb in person_rule_rows() {
        let answer = own_gate(&memory, verb)?;
        assert_eq!(
            (answer.gate, answer.reasons.len()),
            (CanVerbGate::Person, 1),
            "{verb}: an agent's gate on a person-proof row: {answer:?}"
        );
        assert_eq!(answer.actor_ref, agent, "{verb}: {answer:?}");
        assert_eq!(
            answer.actor_kind,
            EdgeActorClass::Agent,
            "{verb}: {answer:?}"
        );
    }
    Ok(())
}

/// A person's own gate on the same rows is `unchecked`: the person rule does
/// not refuse a person, and none of the rows has a preview.
#[test]
fn a_person_gate_on_a_person_rule_row_is_unchecked() -> TestResult {
    let (vault, owner, _agent, _directory) = open_vault()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for verb in person_rule_rows() {
        let answer = own_gate(&memory, verb)?;
        assert_eq!(
            (answer.gate, answer.reasons.len()),
            (CanVerbGate::Unchecked, 0),
            "{verb}: the owner's own gate: {answer:?}"
        );
    }
    Ok(())
}
