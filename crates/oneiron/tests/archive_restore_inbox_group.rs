//! The owner approves the claims of one whole-vault restore in one receipted
//! act (RULING 02:26 13 Nov, NOTE ARCHIVE-RESTORE-APPROVE-DESIGN R1-R6).
//!
//! The owner door (`import_whole_vault_archive_from_as_owner`) brings every
//! claim back Imported and Proposed, out of recall. Each restore is one group
//! of the owner's inbox (`vault.inbox.groups`, kind `restore`, keyed by the
//! restore receipt), over the claims it inserted as Proposed, stamped or not;
//! `vault.inbox.groups.resolve` answers it: accept-all and reject-all settle
//! each member on the `vault.claims.settle` path in one write under one
//! bundle receipt, and `vault.runs.revert` takes the settlement back. Accept-all
//! leaves waiting a member whose approval would supersede a live head.
//!
//! * `an_owner_restore_is_one_inbox_group_and_accept_all_lands_every_member`:
//!   an owner-written claim, a raw-evidence claim and a Dreamer-landed claim
//!   restored into a fresh vault are one restore group; accept-all lands each
//!   as approved with its own Settlement receipt under one bundle receipt,
//!   each is then recalled, and the group is gone.
//! * `reject_all_retracts_the_members_and_keeps_their_records`.
//! * `accept_all_leaves_waiting_a_member_that_would_replace_a_live_head`: the
//!   owner's newer claim on the same conflict set stands; that member waits,
//!   names the head, and the owner then settles it alone.
//! * `the_runs_revert_handle_takes_the_whole_settlement_back`.
//! * `the_actor_door_and_the_actorless_door_list_no_restore_group`: a guard,
//!   green on the base as well.
//! * `a_restore_of_2000_claims_about_one_person_times_its_page_read` (R6):
//!   prints the page read and accept-all times; asserts only the counts.
//!
//! The group and the answer are read and built as JSON, so the file compiles
//! on the base, where the page lists no restore group and `restore` is no kind.
//! Public doors and the Dreamer's test door; neutral fixtures (`owen`); vaults
//! in tempdirs; each destination opens at least one wall-clock second after
//! its source (sleep 1100 ms), as in `whole_vault_restore_seeds.rs`. The
//! destination of each owner restore is rooted under a host first, which binds
//! its owner under the root, as a served vault is: the run review doors that
//! answer and revert the group act only for the root owner (`verify_owner`),
//! as in `owner_approval_criticality_floor.rs`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test archive_restore_inbox_group -- --nocapture`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;
use std::time::Instant;

use oneiron::agent_inbox_lens::InboxRunGroupsRequest;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::inbox::InboxGroupResolveRequest;
use oneiron::memory::run_review::RevertRunRequest;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, Effort, RecallScope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Memory, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

/// A `profile.` predicate: the shipped default policy labels that prefix
/// Normal, so the owner's settle is not parked at the criticality floor.
const NICKNAME: &str = "profile.nickname";

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault, id: &EntityId, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode person body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("put person");
}

/// A claim through the raw door: no envelope, so its evidence names no actor.
fn put_raw_claim(vault: &Vault, subject: EntityId, predicate: &str, value: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_claim(
            &id,
            &ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("claim body"),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put raw claim");
    id
}

/// The owner writes `value` under `predicate` about `subject`.
fn owner_claim(vault: &Vault, subject: EntityId, predicate: &str, value: &str) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let id = EntityId::now();
    let written = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("the owner writes a claim");
    assert_ne!(written.approval, "proposed", "the owner's own write lands");
    id
}

/// The source: a Dreamer vault whose Dreamer landed one MACHINE-signed claim
/// about the person it met, `owen`, beside an owner-written claim and a
/// raw-evidence claim about `owen`.
struct Source {
    _dir: tempfile::TempDir,
    owen: EntityId,
    owner_written: EntityId,
    raw: EntityId,
    dreamer: EntityId,
    archive: Vec<u8>,
}

fn source() -> Source {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("the Dreamer's vault");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [dreamer] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    // The person the Dreamer met, so each claim is about one recalled person.
    let ClaimSubject::Entity(owen) = vault
        .get_claim(dreamer)
        .expect("read the landed claim")
        .expect("the landed claim")
        .subject
    else {
        panic!("the Dreamer's claim is about a person");
    };
    let owner_written = owner_claim(&vault, owen, NICKNAME, "Owen");
    let raw = put_raw_claim(&vault, owen, "profile.note", "Owen drinks tea");
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Source {
        _dir: dir,
        owen,
        owner_written,
        raw,
        dreamer: *dreamer,
        archive,
    }
}

/// A fresh destination, opened at least one wall-clock second after its
/// source, with no embedding model (lexical recall only).
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// `vault` rooted under a host, which binds its embedded owner under the
/// root (H149), with this install's signing keys loaded.
fn root_under_a_host(vault: &Vault) {
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    vault
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"archive-restore-inbox-group").expect("fixture host issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root binds the owner");
}

/// The archive restored as the destination's bound owner, into a destination
/// rooted under a host: the vault, its owner, the owner's proof and the
/// restore receipt's ref.
fn restore_as_owner(
    archive: &[u8],
) -> (
    tempfile::TempDir,
    Vault,
    EntityId,
    AuthenticatedOwner,
    String,
) {
    let (dir, dest) = open_later_vault();
    root_under_a_host(&dest);
    let owner = owner_proof(&dest);
    let dest_owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let receipt = match dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner)
    {
        Ok(receipt) => receipt,
        Err(error) => panic!("the owner's whole archive must restore: {error:?}"),
    };
    let receipt_ref = receipt
        .owner_restore_receipt_ref
        .expect("the owner door names its restore receipt");
    (dir, dest, dest_owner, owner, receipt_ref)
}

/// The restore groups of the owner's inbox page, as JSON.
fn restore_groups(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> Vec<serde_json::Value> {
    let page = memory
        .inbox_groups_page(
            owner,
            &InboxRunGroupsRequest {
                limit: Some(200),
                after: None,
            },
        )
        .expect("the owner's inbox page");
    let page = serde_json::to_value(page).expect("the page as JSON");
    page["groups"]
        .as_array()
        .expect("the page's groups")
        .iter()
        .filter(|group| group["kind"] == "restore")
        .map(|group| group["group"].clone())
        .collect()
}

/// The one restore group of the page, keyed by the restore receipt.
fn the_restore_group(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    receipt_ref: &str,
) -> serde_json::Value {
    let groups = restore_groups(memory, owner);
    let [group] = groups.as_slice() else {
        panic!(
            "the owner's restore is one group of the inbox page, found {}: {groups:?}",
            groups.len()
        );
    };
    assert_eq!(
        group["receipt_ref"], receipt_ref,
        "the group is keyed by the restore receipt"
    );
    group.clone()
}

/// The owner's answer `verb` to the restore group `group_key`, as JSON.
fn resolve(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    group_key: &str,
    verb: &str,
) -> serde_json::Value {
    let request: InboxGroupResolveRequest = serde_json::from_value(json!({
        "kind": "restore",
        "group_key": group_key,
        "verb": verb,
    }))
    .expect("restore is an inbox group kind");
    let resolution = match memory.resolve_inbox_group_of_kind(owner, None, &request) {
        Ok(resolution) => resolution,
        Err(error) => panic!("the owner answers the restore group with {verb}: {error:?}"),
    };
    let resolution = serde_json::to_value(resolution).expect("the resolution as JSON");
    assert_eq!(resolution["kind"], "restore");
    resolution["resolution"].clone()
}

/// The member of `resolution` that names `claim`.
fn member<'r>(resolution: &'r serde_json::Value, claim: &EntityId) -> &'r serde_json::Value {
    resolution["members"]
        .as_array()
        .expect("the members")
        .iter()
        .find(|member| member["claim_ref"] == claim.to_hex())
        .unwrap_or_else(|| panic!("{} is a member: {resolution:#}", claim.to_hex()))
}

/// Whether the owner's lexical recall of "owen" serves `claim`.
fn recalled(memory: &Memory<'_>, claim: &EntityId) -> bool {
    let hex = claim.to_hex();
    memory
        .recall(
            "owen",
            Effort::Light,
            &RecallScope::default(),
            50,
            None,
            None,
        )
        .expect("the owner's recall")
        .items
        .iter()
        .any(|item| {
            item.record
                .as_ref()
                .is_some_and(|record| record.id == hex && record.kind == "CLAIM")
        })
}

fn claim(vault: &Vault, id: &EntityId) -> ClaimBody {
    vault
        .get_claim(id)
        .expect("read the claim")
        .expect("the restore keeps the claim's id")
}

#[test]
fn an_owner_restore_is_one_inbox_group_and_accept_all_lands_every_member() {
    let source = source();
    let (_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&source.archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let ours = [source.owner_written, source.raw, source.dreamer];
    for id in &ours {
        let restored = claim(&dest, id);
        assert_eq!(restored.source, Some(ClaimSource::Imported));
        assert_eq!(restored.approval, ClaimApprovalStatus::Proposed);
        assert!(
            !recalled(&memory, id),
            "a proposed restored claim stays out of recall"
        );
    }
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    let open = group["open_members"].as_u64().expect("open_members");
    assert!(open >= 3, "the group counts the three claims: {group:#}");
    assert_eq!(
        group["replaces_live_head"], 0,
        "a fresh vault has no live head"
    );
    let group_key = group["group_key"].as_str().expect("group_key").to_owned();

    let resolution = resolve(&memory, &owner, &group_key, "accept_all");
    assert_eq!(
        resolution["members"].as_array().map(Vec::len),
        Some(usize::try_from(open).expect("count")),
        "the answer reads every open member: {resolution:#}"
    );
    let bundle = resolution["receipt_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("one bundle receipt: {resolution:#}"));
    let mut receipts = std::collections::BTreeSet::new();
    for id in &ours {
        let member = member(&resolution, id);
        assert_eq!(member["verdict"], "landed", "{member:#}");
        let receipt = member["receipt_ref"].as_str().expect("its own receipt");
        assert_ne!(receipt, bundle);
        receipts.insert(receipt.to_owned());
        let settled = claim(&dest, id);
        assert_eq!(settled.approval, ClaimApprovalStatus::Approved);
        assert_eq!(settled.lifecycle, ClaimLifecycleStatus::Active);
        assert!(
            recalled(&memory, id),
            "the approved restored claim is recalled"
        );
    }
    assert_eq!(receipts.len(), 3, "one Settlement receipt per member");
    assert!(
        resolution["members"]
            .as_array()
            .expect("members")
            .iter()
            .all(|member| member["verdict"] == "landed"),
        "no member waits in a fresh vault: {resolution:#}"
    );
    assert_eq!(
        resolution["revert_handle"],
        format!("run:restore:{group_key}")
    );
    assert!(
        restore_groups(&memory, &owner).is_empty(),
        "an answered restore leaves the inbox"
    );
}

#[test]
fn reject_all_retracts_the_members_and_keeps_their_records() {
    let source = source();
    let (_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&source.archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    let group_key = group["group_key"].as_str().expect("group_key").to_owned();

    let resolution = resolve(&memory, &owner, &group_key, "reject_all");
    assert!(resolution["receipt_ref"].is_string(), "{resolution:#}");
    for id in [source.owner_written, source.raw, source.dreamer] {
        assert_eq!(member(&resolution, &id)["verdict"], "rejected");
        let rejected = claim(&dest, &id);
        assert_eq!(rejected.approval, ClaimApprovalStatus::Rejected);
        assert_ne!(rejected.lifecycle, ClaimLifecycleStatus::Active);
        assert!(!recalled(&memory, &id), "a rejected claim is not recalled");
    }
    assert!(restore_groups(&memory, &owner).is_empty());
}

#[test]
fn accept_all_leaves_waiting_a_member_that_would_replace_a_live_head() {
    let source = source();
    let (_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&source.archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    // The vault is in use: the owner's newer nickname for owen stands.
    let newer = owner_claim(&dest, source.owen, NICKNAME, "Ow");
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    assert_eq!(group["replaces_live_head"], 1, "{group:#}");
    let group_key = group["group_key"].as_str().expect("group_key").to_owned();
    // Review-each reads the heads as the page does; it names the same head
    // the settle's own review binds below.
    let review_each = resolve(&memory, &owner, &group_key, "review_each");
    assert_eq!(
        member(&review_each, &source.owner_written)["replaces_ref"],
        newer.to_hex(),
        "{review_each:#}"
    );

    let resolution = resolve(&memory, &owner, &group_key, "accept_all");
    let waiting = member(&resolution, &source.owner_written);
    assert_eq!(waiting["verdict"], "waiting", "{resolution:#}");
    assert_eq!(waiting["waiting"], "replaces_live_head");
    assert_eq!(waiting["replaces_ref"], newer.to_hex());
    assert_eq!(
        claim(&dest, &source.owner_written).approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(claim(&dest, &newer).lifecycle, ClaimLifecycleStatus::Active);
    for id in [source.raw, source.dreamer] {
        assert_eq!(member(&resolution, &id)["verdict"], "landed");
    }
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    assert_eq!(
        group["open_members"], 1,
        "the waiting member keeps the group"
    );

    // The owner settles it alone, and its approval supersedes the head.
    let review = memory
        .claim_review_as_owner(
            &owner,
            &ClaimProposalReviewRequest {
                claim_ref: source.owner_written.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the waiting member");
    let settled = memory
        .claim_settle_as_owner(
            &owner,
            &ClaimSettleRequest {
                claim_ref: source.owner_written.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect("the owner settles the waiting member alone");
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_ne!(claim(&dest, &newer).lifecycle, ClaimLifecycleStatus::Active);
    assert!(restore_groups(&memory, &owner).is_empty());
}

#[test]
fn the_runs_revert_handle_takes_the_whole_settlement_back() {
    let source = source();
    let (_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&source.archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    let group_key = group["group_key"].as_str().expect("group_key").to_owned();
    let resolution = resolve(&memory, &owner, &group_key, "accept_all");
    let handle = resolution["revert_handle"]
        .as_str()
        .expect("the revert handle")
        .to_owned();

    let reverted = memory
        .revert_run_as_owner(
            &owner,
            &RevertRunRequest {
                run_id: handle,
                changes: None,
            },
        )
        .expect("the owner reverts the restore's settlement");
    for id in [source.owner_written, source.raw, source.dreamer] {
        assert!(
            reverted
                .compensated
                .iter()
                .any(|compensated| compensated.change == id.to_hex()),
            "{} is compensated: {reverted:?}",
            id.to_hex()
        );
        assert_ne!(claim(&dest, &id).lifecycle, ClaimLifecycleStatus::Active);
        assert!(!recalled(&memory, &id), "a reverted claim is not recalled");
    }
}

#[test]
fn the_actor_door_and_the_actorless_door_list_no_restore_group() {
    let source = source();
    // Either door may import the archive or refuse it; neither lists a group.
    let (_actorless_dir, actorless) = open_later_vault();
    if let Err(error) = actorless.import_whole_vault_archive_from(Cursor::new(&source.archive)) {
        println!("the actorless door refused the archive: {error:?}");
    }
    let (_actor_dir, actor_dest) = open_later_vault();
    let actor = actor_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    if let Err(error) = actor_dest.import_whole_vault_archive_from_with_actor(
        Cursor::new(&source.archive),
        &WriteActor::new(actor, EdgeActorClass::Human),
    ) {
        println!("the actor door refused the archive: {error:?}");
    }
    for dest in [&actorless, &actor_dest] {
        let owner = owner_proof(dest);
        let person = dest.ensure_embedded_owner_actor().expect("owner");
        let memory = dest.memory(person, EdgeActorClass::Human);
        assert!(
            restore_groups(&memory, &owner).is_empty(),
            "only the owner's restore is an inbox group"
        );
    }
}

#[test]
fn a_restore_of_2000_claims_about_one_person_times_its_page_read() {
    const CLAIMS: usize = 2000;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owen = EntityId::now();
    put_person(&vault, &owen, "owen");
    for index in 0..CLAIMS {
        put_raw_claim(&vault, owen, &format!("profile.fact_{index:04}"), "a fact");
    }
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let (_dest_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);

    let started = Instant::now();
    let group = the_restore_group(&memory, &owner, &receipt_ref);
    let page_read = started.elapsed();
    // Printed before the answer, so a refused answer still reports the read.
    println!(
        "## R6-PAGE-READ claims={CLAIMS} page_read_ms={}",
        page_read.as_millis()
    );
    assert!(
        group["open_members"].as_u64().expect("open_members") >= CLAIMS as u64,
        "{group:#}"
    );
    let group_key = group["group_key"].as_str().expect("group_key").to_owned();
    let started = Instant::now();
    let resolution = resolve(&memory, &owner, &group_key, "accept_all");
    let accept_all = started.elapsed();
    let landed = resolution["members"]
        .as_array()
        .expect("members")
        .iter()
        .filter(|member| member["verdict"] == "landed")
        .count();
    let started = Instant::now();
    let after = restore_groups(&memory, &owner);
    let page_after = started.elapsed();
    println!(
        "## R6-TIMING claims={CLAIMS} page_read_ms={} accept_all_ms={} landed={landed} page_after_ms={} groups_after={}",
        page_read.as_millis(),
        accept_all.as_millis(),
        page_after.as_millis(),
        after.len()
    );
    assert!(landed >= CLAIMS, "{landed} of {CLAIMS} landed");
}
