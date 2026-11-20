//! A FOREIGN fact-hook pack's receipt, read by the owner's credential (HOOKS-05, leg B61).
//!
//! Pins the nightly E2E HOOKS-05 §6b question at lib level with ONE fact hook:
//! a foreign pack installed from a local git hub (pinned commit), qualified,
//! owner-bound (every binding's author is `foreign_actor`), given the §4 owner
//! policy rows (an Agent Auto ceiling plus a scoped `core:read` grant on the
//! publisher actor) and the witness TASK, plus the §5 per-binding `HookGrant`,
//! then a landed safe fact and one `FactHookRunner::run_pass` on the fake
//! `NothingRuntime` (as #9535's test (c)). The owner's full owner-grade
//! credential then pages kinds `["hook"]`. Unknown: whether the run happens at
//! all, and if it does, which row the owner's credential cannot read.
//!
//! Public paths only: `Vault::configure_skill_hub`,
//! `Vault::admit_skill_publisher`, `Vault::install_pack_from_hub`,
//! `Vault::qualify_pack_hooks`, `Vault::bind_pack_hooks`,
//! `policy_manifest_doors::{policy_manifests_as_owner,
//! put_policy_manifest_as_owner}`, `Memory::tasks_create`,
//! `Vault::set_hook_grant`, `Vault::put_entity`/`Vault::put_claim`,
//! `FactHookRunner::run_pass`, `Vault::receipts` and the credential-bound
//! `Memory::receipts_page`/`Memory::get_entity`. No new test door, so no
//! `RUSTFLAGS="--cfg oneiron_test_support"`.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test foreign_fact_hook_receipt_owner_credential -- --nocapture`
//!
//! - `foreign_fact_hook_receipt_reaches_the_owner_credential`: red today at
//!   (a), predicted: the E2E-faithful §5 grant (`worlds: [base]`) withholds
//!   the base-world fact (`HookGrant::admits` needs `claim.world.is_some()`
//!   for a non-empty `worlds`, and a base-world claim decodes to `world:
//!   None`), so the run never happens and no unscreened receipt stands. That
//!   absence is the finding the leg asks for. If (a) passes instead, (c) is
//!   the E2E behaviour assert and may fail on the receipt screening.
//! - `owner_put_fact_hook_receipt_reaches_the_owner_credential` (control):
//!   green today (the #9535 test (c) shape: the owner's broad credential keeps
//!   the local fact-hook receipt).
//! - `stranger_credential_reads_no_foreign_fact_hook_receipt`: green today (a
//!   credential that does not read the trigger keeps 0 of the foreign
//!   receipts); it must stay green after any fix.
//!
//! E2E differences, all named in REPORT.md: one fact hook, not seven hooks;
//! the HOOK.md declares no `actors` (the proven #9535 test (c) shape); the
//! lib claims carry the test (c) value shape; the control reuses the test (c)
//! pack bytes inline rather than the E2E fixture files.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{
    FactHookRunner, HookBodyRun, HookBodyRuntime, HookGrant, HookReplayResult, HookRunContext,
};
use oneiron::skill_hub::pack_catalog::{
    FOREIGN_SKILL_PUBLISHER, HookActorClass, HookAuthor, HookOutcomeKind, HookPhase,
    PackInstallDisposition, PackInstallStatus,
};
use oneiron::skill_hub::{
    HubFile, HubPin, HubSyncPolicy, SkillHubKind, SkillHubRecord, SkillHubTrustTier,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;

/// The foreign pack's author-scoped name (HOOKS-05 installs `hooksandbox.probe`).
const FOREIGN_PACK: &str = "foreign.factprobe";
/// The foreign pack's one fact hook.
const FOREIGN_HOOK: &str = "fact-note";
/// The foreign fact hook's input predicate.
const FOREIGN_PREDICATE: &str = "foreign.factprobe.input";
/// The foreign receipt's `hook` field, as `pack/hook`.
const FOREIGN_HOOK_REF: &str = "foreign.factprobe/fact-note";
/// The foreign publisher's identity (HOOKS-05's `independent-hook-publisher`).
const PUBLISHER: &str = "independent-hook-publisher";
/// The fact-hook pack the owner puts (the #9535 test (c) control).
const FACT_PACK: &str = "example.factscreen";
/// The control fact hook's input predicate.
const FACT_PREDICATE: &str = "example.factscreen.input";
/// The control receipt's `hook` field, as `pack/hook`.
const FACT_HOOK_REF: &str = "example.factscreen/fact-note";
/// The challenge the credential proofs sign, as a transport challenge does.
const CHALLENGE: &[u8] = b"oneiron-request:foreign-fact-hook-receipt";
/// A page large enough to hold every Hook receipt the fixture records.
const PAGE_LIMIT: usize = 100;

const FOREIGN_PACK_MD: &str = "---
name: foreign.factprobe
description: One foreign fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook a hub install carries.
";

const FOREIGN_HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:foreign.factprobe.input\"]
phase: fact
outcomes: [\"nothing\"]
---
Watches foreign.factprobe.input claims and does nothing.
";

const FACT_PACK_MD: &str = "---
name: example.factscreen
description: One fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner's put binds.
";

const FACT_HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.factscreen.input\"]
phase: fact
outcomes: [\"nothing\"]
---
Watches example.factscreen.input claims and does nothing.
";

const NOTHING_BODY_JS: &str = "return { kind: \"nothing\" };\n";

/// A hook sandbox that answers every fact body with Nothing, reading nothing.
struct NothingRuntime;

impl HookBodyRuntime for NothingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"nothing"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault with its install signing, embedded owner and host root. No
    /// verb runtime is installed: the packs hold fact hooks only, and the
    /// fake `NothingRuntime` is passed explicitly to qualification and the
    /// runner.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("FIXTURE: vault dir");
        let vault =
            Vault::open(directory.path(), VaultConfig::device()).expect("FIXTURE: open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("FIXTURE: load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("FIXTURE: owner");
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-foreign-fact-hook-receipt")
            .expect("FIXTURE: host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: host root slip");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        Self {
            vault,
            issuer,
            owner,
            owner_proof,
            _directory: directory,
        }
    }
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The live `human` credential this host mints `holder`, held to `records`
/// (empty: no records narrowing), verified as a transport verifies it.
fn credential(fixture: &Fixture, holder: EntityId, records: BTreeSet<String>) -> VerifiedSlip {
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("FIXTURE: host root slip");
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("FIXTURE: mint the credential slip");
    let binding = fixture
        .issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("FIXTURE: sign the credential proof");
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("FIXTURE: verify the credential as a transport does")
}

/// One landed `user_stated` claim with `predicate` about a fresh person;
/// answers the claim id.
fn land_fact_claim(vault: &Vault, predicate: &str) -> EntityId {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"hook subject",
        )
        .expect("FIXTURE: put the claim subject");
    let claim_id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fixture input"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: build the claim body");
    body.source = Some(ClaimSource::UserStated);
    vault
        .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("FIXTURE: land the fact claim");
    claim_id
}

/// The unscreened Hook receipts whose trigger is `trigger_hex`, newest first.
fn unscreened_hook_receipts(vault: &Vault, trigger_hex: &str) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Hook))
        .expect("FIXTURE: hook receipts read")
        .into_iter()
        .filter(|receipt| receipt.trigger_ref.as_deref() == Some(trigger_hex))
        .collect()
}

/// One DIAG line per row `receipt` names (its trigger, `binding` and `code`
/// fields), judged through the credential-bound `reader`'s public point read,
/// plus the receipt's field map.
fn diag_named_rows(reader: &oneiron::Memory<'_>, receipt: &ReceiptRecord) {
    eprintln!("DIAG fields={:?}", receipt.fields);
    let trigger = receipt.trigger_ref.clone().unwrap_or_default();
    let binding = receipt.fields.get("binding").cloned().unwrap_or_default();
    let code = receipt.fields.get("code").cloned().unwrap_or_default();
    for (label, id) in [("trigger", trigger), ("binding", binding), ("code", code)] {
        let hex = id.rsplit(':').next().unwrap_or("");
        let reads_body = reader
            .get_entity(hex)
            .map(|read| read.value.is_some())
            .unwrap_or(false);
        eprintln!("DIAG row={label} id={hex} credential_reads_body={reads_body}");
    }
}

/// `git args` in `dir`; answers the trimmed standard output.
fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("FIXTURE: git runs");
    assert!(
        output.status.success(),
        "FIXTURE: git {args:?} succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("FIXTURE: git speaks UTF-8")
        .trim()
        .to_owned()
}

/// `content` as the hub working tree's `rel` file, making its parents.
fn write_pack_file(dir: &std::path::Path, rel: &str, content: &str) {
    let dest = dir.join(rel);
    std::fs::create_dir_all(dest.parent().expect("FIXTURE: pack file parent"))
        .expect("FIXTURE: hub dir");
    std::fs::write(dest, content).expect("FIXTURE: hub file");
}

/// The owner's put of the one control fact hook; answers its binding id.
fn put_fact_pack(fixture: &Fixture) -> EntityId {
    let files = vec![
        HubFile::new("PACK.md", FACT_PACK_MD),
        HubFile::new("hooks/fact-note/HOOK.md", FACT_HOOK_MD),
        HubFile::new("hooks/fact-note/body.js", NOTHING_BODY_JS),
    ];
    match fixture
        .vault
        .put_pack(&fixture.owner_proof, files)
        .expect("FIXTURE: the owner's put installs the fact pack")
    {
        PackInstallDisposition::Installed(receipt) => {
            assert_eq!(
                receipt.pack_name, FACT_PACK,
                "FIXTURE: the owner's put installs the fact pack"
            );
        }
        other => {
            panic!("FIXTURE: the owner's put installs the fact pack and binds its hook: {other:?}")
        }
    }
    let bindings = fixture
        .vault
        .pack_hook_bindings()
        .expect("FIXTURE: live bindings read")
        .into_iter()
        .filter(|(_, binding)| binding.pack == FACT_PACK)
        .collect::<Vec<_>>();
    assert_eq!(
        bindings.len(),
        1,
        "FIXTURE: the put binds the fact hook live: {bindings:?}"
    );
    bindings[0].0
}

/// The HOOKS-05 §§1-5 setup at lib level: the foreign pack from a local git
/// hub, qualified, owner-bound, with the §4 policy rows and witness TASK and
/// the §5 `HookGrant`. The caller lands the live fact and runs the pass.
struct ForeignSetup {
    fixture: Fixture,
    binding: EntityId,
    publisher: EntityId,
    // Dropped after the install that read it.
    _hub_dir: tempfile::TempDir,
}

fn install_foreign_hook() -> ForeignSetup {
    let fixture = Fixture::new();
    // ---- §1. Real LOCAL git hub, explicit admit, pinned Candidate install. ----
    let hub_dir = tempfile::tempdir().expect("FIXTURE: hub dir");
    write_pack_file(hub_dir.path(), "PACK.md", FOREIGN_PACK_MD);
    write_pack_file(hub_dir.path(), "hooks/fact-note/HOOK.md", FOREIGN_HOOK_MD);
    write_pack_file(hub_dir.path(), "hooks/fact-note/body.js", NOTHING_BODY_JS);
    git(hub_dir.path(), &["init"]);
    git(hub_dir.path(), &["add", "-A"]);
    git(
        hub_dir.path(),
        &[
            "-c",
            "user.name=hooks05",
            "-c",
            "user.email=hooks05@local",
            "commit",
            "-m",
            "hooks05 foreign fixture",
        ],
    );
    let commit_oid = git(hub_dir.path(), &["rev-parse", "HEAD"]).to_lowercase();
    assert!(
        (commit_oid.len() == 40 || commit_oid.len() == 64)
            && commit_oid.chars().all(|c| c.is_ascii_hexdigit()),
        "FIXTURE: the hub pins a full commit id: {commit_oid}"
    );
    let hub_id = EntityId::now();
    let record = SkillHubRecord::new(
        SkillHubKind::Git,
        hub_dir.path().to_str().expect("FIXTURE: hub path is UTF-8"),
        SkillHubTrustTier::Untrusted,
        HubSyncPolicy::PinnedCommit,
    )
    .expect("FIXTURE: the hub record builds");
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .configure_skill_hub(
            &fixture.owner_proof,
            &hub_id,
            &record,
            TimeRange { start: at, end: at },
            at,
        )
        .expect("FIXTURE: the owner configures the git hub");
    let admission = fixture
        .vault
        .admit_skill_publisher(&fixture.owner_proof, PUBLISHER, hub_id)
        .expect("FIXTURE: the owner admits the publisher");
    assert_eq!(
        admission.identity(),
        PUBLISHER,
        "FIXTURE: the admission names the publisher"
    );
    assert!(
        !admission.grant_ref().is_empty()
            && admission.grant_ref().chars().all(|c| c.is_ascii_hexdigit()),
        "FIXTURE: the admission mints a grant ref: {}",
        admission.grant_ref()
    );
    let source_hex = match fixture
        .vault
        .install_pack_from_hub(
            &fixture.owner_proof,
            hub_id,
            ".",
            HubPin::Commit(commit_oid.clone()),
            PUBLISHER,
        )
        .expect("FIXTURE: the owner installs the pinned pack")
    {
        PackInstallDisposition::Candidate(receipt) => {
            assert_eq!(
                receipt.pack_name, FOREIGN_PACK,
                "FIXTURE: the Candidate install names the foreign pack"
            );
            assert_eq!(
                receipt.status,
                PackInstallStatus::Candidate,
                "FIXTURE: the hook pack waits as a Candidate: {receipt:?}"
            );
            assert_eq!(
                receipt.publisher, PUBLISHER,
                "FIXTURE: the Candidate names the publisher: {receipt:?}"
            );
            assert_eq!(
                receipt.hub_id,
                hub_id.to_hex(),
                "FIXTURE: the Candidate names the hub: {receipt:?}"
            );
            assert_eq!(
                receipt.pin_type, "commit",
                "FIXTURE: the Candidate pins a commit: {receipt:?}"
            );
            assert_eq!(
                receipt.pin_value, commit_oid,
                "FIXTURE: the Candidate pins this commit: {receipt:?}"
            );
            receipt.source_id.clone()
        }
        other => panic!("FIXTURE: the hub install lands the hook pack Candidate: {other:?}"),
    };
    let source_id =
        EntityId::from_hex(&source_hex).expect("FIXTURE: the Candidate names its source");
    // ---- §2. One safe seed fact plus the qualify replay. ----
    land_fact_claim(&fixture.vault, FOREIGN_PREDICATE);
    let qualification = fixture
        .vault
        .qualify_pack_hooks(&fixture.owner_proof, &NothingRuntime, source_id)
        .expect("FIXTURE: the hook pack qualifies");
    match &qualification.disposition {
        PackInstallDisposition::Installed(receipt) => {
            assert_eq!(
                receipt.pack_name, FOREIGN_PACK,
                "FIXTURE: qualification installs the foreign pack"
            );
            assert_eq!(
                receipt.status,
                PackInstallStatus::Active,
                "FIXTURE: qualification activates the foreign pack: {receipt:?}"
            );
        }
        other => panic!("FIXTURE: the safe seed qualifies the hook pack: {other:?}"),
    }
    assert_eq!(
        qualification.replays.len(),
        1,
        "FIXTURE: qualification replays the one fact hook: {:?}",
        qualification.replays
    );
    let replay = &qualification.replays[0];
    assert_eq!(
        replay.hook, FOREIGN_HOOK,
        "FIXTURE: the replay names the fact hook: {replay:?}"
    );
    assert!(
        !replay.unreplayed,
        "FIXTURE: the safe seed runs, it is not unreplayed: {replay:?}"
    );
    assert_eq!(
        replay.entries.len(),
        1,
        "FIXTURE: the safe seed replays once: {replay:?}"
    );
    assert!(
        matches!(
            &replay.entries[0].result,
            HookReplayResult::Ran { outcome, .. } if outcome.as_str() == "nothing"
        ),
        "FIXTURE: the safe seed replays to Nothing: {:?}",
        replay.entries[0].result
    );
    // ---- §3. Owner bind; the foreign-author identity. ----
    let bound = fixture
        .vault
        .bind_pack_hooks(&fixture.owner_proof, FOREIGN_PACK)
        .expect("FIXTURE: the owner binds the foreign pack");
    assert_eq!(
        bound.len(),
        1,
        "FIXTURE: the bind answers one hook: {bound:?}"
    );
    let bindings = fixture
        .vault
        .pack_hook_bindings()
        .expect("FIXTURE: live bindings read")
        .into_iter()
        .filter(|(_, binding)| binding.pack == FOREIGN_PACK)
        .collect::<Vec<_>>();
    assert_eq!(
        bindings.len(),
        1,
        "FIXTURE: the foreign pack binds one hook live: {bindings:?}"
    );
    let (binding_id, binding) = &bindings[0];
    assert_eq!(
        binding.owner, fixture.owner,
        "FIXTURE: the binding's owner is the owner: {binding:?}"
    );
    let publisher = binding.author_id();
    match &binding.author {
        HookAuthor::ForeignActor {
            actor_kind,
            identity,
            hub,
            grant,
            actor,
        } => {
            assert_eq!(
                actor_kind.as_str(),
                FOREIGN_SKILL_PUBLISHER,
                "FIXTURE: the foreign author is a skill publisher: {binding:?}"
            );
            assert_eq!(
                identity.as_str(),
                PUBLISHER,
                "FIXTURE: the foreign author names the publisher: {binding:?}"
            );
            assert_eq!(
                *hub, hub_id,
                "FIXTURE: the foreign author names the hub: {binding:?}"
            );
            assert_eq!(
                grant.as_str(),
                admission.grant_ref(),
                "FIXTURE: the foreign author carries the admission grant: {binding:?}"
            );
            assert_eq!(
                *actor, publisher,
                "FIXTURE: the foreign author stamps the publisher actor: {binding:?}"
            );
        }
        other => panic!("FIXTURE: the foreign pack binds with a foreign author: {other:?}"),
    }
    assert_ne!(
        publisher, fixture.owner,
        "FIXTURE: the publisher actor is not the owner"
    );
    assert!(
        binding.body_hash.len() == 64 && binding.body_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "FIXTURE: the binding hashes its body: {binding:?}"
    );
    assert!(
        binding.enabled,
        "FIXTURE: the binding is enabled: {binding:?}"
    );
    assert_eq!(
        binding.selector.verbs,
        vec![format!("claim.landed:{FOREIGN_PREDICATE}")],
        "FIXTURE: the fact hook watches its own predicate: {binding:?}"
    );
    assert_eq!(
        binding.selector.phase,
        HookPhase::Fact,
        "FIXTURE: the hook is a fact hook: {binding:?}"
    );
    assert!(
        binding
            .selector
            .outcomes
            .contains(&HookOutcomeKind::Nothing),
        "FIXTURE: the fact hook allows Nothing: {binding:?}"
    );
    eprintln!("DIAG selector_actors={:?}", binding.selector.actors);
    let publisher_hex = publisher.to_hex();
    // ---- §4. Same-actor owner READ grant plus ONE Child witness TASK. ----
    let view = policy_manifests_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("FIXTURE: the owner reads the policy manifests");
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .expect("FIXTURE: the default policy manifest");
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".to_owned(),
        actor_ref: Some(publisher_hex.clone()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["propose".to_owned(), "read".to_owned()]));
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(publisher_hex.clone()),
        effector: "core:read".to_owned(),
        scope,
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    let put = put_policy_manifest_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )
    .expect("FIXTURE: the owner grants the publisher reads");
    assert!(
        !put.receipt_ref.is_empty(),
        "FIXTURE: the policy put answers a receipt: {put:?}"
    );
    let again = policy_manifests_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("FIXTURE: the owner re-reads the policy manifests");
    let default_again = again
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == again.default_manifest_ref)
        .expect("FIXTURE: the default policy manifest after the put");
    assert!(
        default_again
            .manifest
            .actor_ceilings
            .iter()
            .any(|row| row.actor_class == "agent"
                && row.actor_ref.as_deref() == Some(publisher_hex.as_str())
                && row.ceiling == PolicyCeiling::Auto),
        "FIXTURE: the Agent Auto ceiling stands: {:?}",
        default_again.manifest.actor_ceilings
    );
    assert!(
        default_again
            .manifest
            .scoped_grants
            .clone()
            .unwrap_or_default()
            .iter()
            .any(
                |row| row.actor_ref.as_deref() == Some(publisher_hex.as_str())
                    && row.effector == "core:read"
            ),
        "FIXTURE: the scoped core:read grant stands: {:?}",
        default_again.manifest.scoped_grants
    );
    let witness = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::from("HOOKS-05 foreign witness"),
                Some("hooks05-witness".to_owned()),
                None,
                None,
            )
            .with_assignee(TaskAssignee::Child {
                actor_ref: publisher,
            }),
        )
        .expect("FIXTURE: the owner creates the witness TASK");
    assert!(
        witness.task_ref.is_some(),
        "FIXTURE: the witness TASK lands: {witness:?}"
    );
    assert!(
        witness.proposal_ref.is_none(),
        "FIXTURE: the witness TASK proposes nothing: {witness:?}"
    );
    assert_eq!(
        witness.approval,
        ClaimApprovalStatus::Auto,
        "FIXTURE: the witness TASK is Auto: {witness:?}"
    );
    assert!(
        witness.effected,
        "FIXTURE: the witness TASK takes effect: {witness:?}"
    );
    assert_eq!(
        witness.route,
        Some(TaskRouteOutcome::ChildAddressed {
            actor_ref: publisher,
        }),
        "FIXTURE: the witness TASK addresses the publisher child: {witness:?}"
    );
    // ---- §5. The manual per-binding HookGrant (the E2E's own shape). ----
    let grant = HookGrant {
        reader: publisher,
        reader_class: HookActorClass::Agent,
        predicates: vec![FOREIGN_PREDICATE.to_owned()],
        worlds: vec![base_world_id()],
    };
    fixture
        .vault
        .set_hook_grant(&fixture.owner_proof, *binding_id, grant.clone())
        .expect("FIXTURE: the owner sets the hook grant");
    assert_eq!(
        fixture
            .vault
            .hook_grant(*binding_id)
            .expect("FIXTURE: the hook grant reads back"),
        Some(grant),
        "FIXTURE: the hook grant roundtrips"
    );
    ForeignSetup {
        fixture,
        binding: *binding_id,
        publisher,
        _hub_dir: hub_dir,
    }
}

#[test]
fn foreign_fact_hook_receipt_reaches_the_owner_credential() {
    let setup = install_foreign_hook();
    let fixture = &setup.fixture;
    let claim_id = land_fact_claim(&fixture.vault, FOREIGN_PREDICATE);
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &NothingRuntime, 256)
        .expect("FIXTURE: the runner takes the fact");
    eprintln!(
        "DIAG pass runs={} skipped={} entries_read={} failed={} refused={}",
        pass.runs, pass.skipped, pass.entries_read, pass.failed, pass.refused
    );
    let want = claim_id.to_hex();
    let publisher_hex = setup.publisher.to_hex();
    let binding_hex = setup.binding.to_hex();
    // The publisher's own unbound read of the trigger: when it holds, a
    // skipped fact was withheld by the §5 grant, not by the read lane.
    let lane_reads_trigger = fixture
        .vault
        .memory(setup.publisher, EdgeActorClass::Agent)
        .get_entity(&want)
        .map(|read| read.value.is_some())
        .unwrap_or(false);
    eprintln!("DIAG publisher_lane_reads_trigger={lane_reads_trigger}");
    // (a) The unscreened owner read must list the fact-hook receipt.
    let kept = unscreened_hook_receipts(&fixture.vault, &want);
    assert_eq!(
        kept.len(),
        1,
        "FIXTURE: the foreign fact run records one Hook receipt on its trigger; if absent, the run never happened: {kept:?} (pass={pass:?})"
    );
    assert!(
        !kept[0].fields.contains_key("verb"),
        "FIXTURE: a fact-hook receipt carries no verb field: {:?}",
        kept[0]
    );
    assert_eq!(
        kept[0].fields.get("binding").map(String::as_str),
        Some(binding_hex.as_str()),
        "FIXTURE: the fact-hook receipt names its binding: {:?}",
        kept[0]
    );
    // (b) One DIAG line per named row through the owner's credential.
    let owner_credential = credential(fixture, fixture.owner, BTreeSet::new());
    let owner_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&owner_credential);
    diag_named_rows(&owner_reader, &kept[0]);
    // (c) The E2E expectation: the owner's credential keeps that receipt.
    let page = owner_reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the owner's kinds [hook] page reads");
    let got: Vec<_> = page
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("trigger_ref").map(String::as_str) == Some(want.as_str())
        })
        .collect();
    assert_eq!(
        got.len(),
        1,
        "MISSING: the owner's credential-bound kinds [hook] read keeps the foreign fact-hook receipt it triggers on, got {}: {got:?}",
        got.len()
    );
    assert_eq!(
        got[0].fields.get("hook").map(String::as_str),
        Some(FOREIGN_HOOK_REF),
        "MISSING: the kept receipt is the foreign fact hook's: {:?}",
        got[0]
    );
    assert_eq!(
        got[0].outcome, "nothing",
        "MISSING: the kept receipt answers Nothing: {:?}",
        got[0]
    );
    assert_eq!(
        got[0].actor_ref.as_deref(),
        Some(publisher_hex.as_str()),
        "MISSING: the kept receipt is stamped on the publisher: {:?}",
        got[0]
    );
}

#[test]
fn owner_put_fact_hook_receipt_reaches_the_owner_credential() {
    let fixture = Fixture::new();
    let binding = put_fact_pack(&fixture);
    let claim_id = land_fact_claim(&fixture.vault, FACT_PREDICATE);
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &NothingRuntime, 256)
        .expect("FIXTURE: the runner takes the fact");
    assert_eq!(
        pass.runs, 1,
        "FIXTURE: the fact hook runs once on the landed claim: {pass:?}"
    );
    let want = claim_id.to_hex();
    let binding_hex = binding.to_hex();
    let kept = unscreened_hook_receipts(&fixture.vault, &want);
    assert_eq!(
        kept.len(),
        1,
        "FIXTURE: the fact run records one Hook receipt on its trigger: {kept:?}"
    );
    assert!(
        !kept[0].fields.contains_key("verb"),
        "FIXTURE: a fact-hook receipt carries no verb field: {:?}",
        kept[0]
    );
    assert_eq!(
        kept[0].fields.get("binding").map(String::as_str),
        Some(binding_hex.as_str()),
        "FIXTURE: the fact-hook receipt names its binding: {:?}",
        kept[0]
    );
    let owner_credential = credential(&fixture, fixture.owner, BTreeSet::new());
    let owner_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&owner_credential);
    diag_named_rows(&owner_reader, &kept[0]);
    let page = owner_reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the owner's kinds [hook] page reads");
    let got: Vec<_> = page
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("trigger_ref").map(String::as_str) == Some(want.as_str())
        })
        .collect();
    assert_eq!(
        got.len(),
        1,
        "MISSING: the owner's credential-bound kinds [hook] read keeps the fact-hook receipt it triggers on, got {}: {got:?}",
        got.len()
    );
    assert_eq!(
        got[0].fields.get("hook").map(String::as_str),
        Some(FACT_HOOK_REF),
        "MISSING: the kept receipt is the fact hook's: {:?}",
        got[0]
    );
    assert_eq!(
        got[0].outcome, "nothing",
        "MISSING: the kept receipt answers Nothing: {:?}",
        got[0]
    );
}

#[test]
fn stranger_credential_reads_no_foreign_fact_hook_receipt() {
    let setup = install_foreign_hook();
    let fixture = &setup.fixture;
    let claim_id = land_fact_claim(&fixture.vault, FOREIGN_PREDICATE);
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &NothingRuntime, 256)
        .expect("FIXTURE: the runner takes the fact");
    eprintln!(
        "DIAG pass runs={} skipped={} entries_read={}",
        pass.runs, pass.skipped, pass.entries_read
    );
    let want = claim_id.to_hex();
    eprintln!(
        "DIAG unscreened_foreign_receipts={}",
        unscreened_hook_receipts(&fixture.vault, &want).len()
    );
    // A person with no grant, held by a records caveat to its own row: it
    // reads no trigger row, so it keeps none of the foreign receipts.
    let stranger = EntityId::now();
    fixture
        .vault
        .put_entity(
            &stranger,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person with no grant",
        )
        .expect("FIXTURE: put the stranger person");
    let stranger_proof = credential(fixture, stranger, BTreeSet::from([stranger.to_hex()]));
    let stranger_reader = fixture
        .vault
        .memory(stranger, EdgeActorClass::Human)
        .with_read_proof(&stranger_proof);
    let stranger_page = stranger_reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the stranger's kinds [hook] page reads");
    let stranger_got: Vec<_> = stranger_page
        .receipts
        .iter()
        .filter(|receipt| receipt.fields.get("hook").map(String::as_str) == Some(FOREIGN_HOOK_REF))
        .collect();
    assert!(
        stranger_got.is_empty(),
        "LEAK: a credential that cannot read the fact trigger keeps no foreign fact-hook receipt, got {stranger_got:?}"
    );
}
