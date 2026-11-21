//! A lens's regeneration reruns the intent its author stored (canon
//! `oneiron/agents/oneiron-arch-0062-booking-loop-v1.md:314`: "the widget
//! lens is a CODE artifact with intent-senior regeneration").
//! `tests/vault_lenses_doors.rs` pins the door half: a proposal is a
//! `CODE_ARTIFACT` row and its authored intent is kept beside it. This file
//! pins the regeneration half, which has no verb: the upgrade decision
//! (`Vault::regenerate_lens_on_upgrade`) and its enactment through the
//! propose and activate doors (`Memory::lenses_enact_regeneration`, here
//! through its embedded-owner wrappers).
//!
//! - A lens body at a stamp behind the live pair reruns the lens's stored
//!   intent prompt against the live pair; a lens with no stored intent rolls
//!   back to its last-good body and nothing reruns; a lens at the live
//!   stamps is left alone.
//! - Enacting a decision: an auto-adopted candidate is proposed with the
//!   decided lens's intent and takes the slot; a candidate that needs the
//!   owner's stamp is only proposed (with the same intent) and the old lens
//!   stays selected; a slot the owner moved since the decision keeps the
//!   owner's newer selection (FIX 9897).
//!
//! A proposal at a stale stamp is refused at the door, so no stale body can
//! be stored on this build: the decision tests pass a stale last-good body
//! to the decision, as a host does after an atom-kit bump, and the
//! enactment tests hand-build each decision over the stored body.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test lens_regeneration_reruns_stored_intent`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;

use oneiron::lens::{
    GeneratedLens, LensBehaviorDiff, LensBehaviorFingerprint, LensEvaluatedRevision,
    LensRegenDecision, LensRegenEnactment, LensRegenFailure, LensRegenFailurePhase,
    LensRegenOutcome, LensRegenRequest, LensRegenerator, LensSlot, LensVersionStamp,
    enact_lens_regeneration_embedded, regenerate_and_enact_lens_embedded,
};
use oneiron::memory::{Memory, MemoryError};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// A 32-hex id nothing is stored under.
const SOME_ID: &str = "019a7218240070008000000000000001";

/// A seeded vault this process owns (the writer lease), opened as
/// `tests/vault_lenses_doors.rs` opens it. Its open installs the engine's
/// weave lens pack Active.
fn owned_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned open");
    let _issuer = oneiron::test_support::provision_engine_machines(&vault);
    (dir, vault)
}

#[track_caller]
fn answered(result: Result<Value, MemoryError>, what: &str) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what} was refused: {error:?}"),
    }
}

/// The weave pack's slot as the owner reads its install: the pack name, its
/// one skill and the content hash it is Active at.
struct Slot {
    pack: String,
    skill: String,
    content: String,
}

impl Slot {
    fn lens_slot(&self) -> LensSlot {
        LensSlot {
            pack_name: self.pack.clone(),
            skill_id: self.skill.clone(),
        }
    }
}

fn weave_slot(owner: &Memory<'_>) -> Slot {
    let install = answered(
        door::invoke(owner, "vault.packs.get", json!({"name": "oneiron.weave"})),
        "packs.get oneiron.weave",
    );
    assert_eq!(
        install["status"],
        json!("active"),
        "the weave pack is Active: {install}"
    );
    Slot {
        pack: install["pack_name"].as_str().expect("pack_name").to_owned(),
        skill: install["skills"][0].as_str().expect("one skill").to_owned(),
        content: install["content_hash"]
            .as_str()
            .expect("content_hash")
            .to_owned(),
    }
}

/// One closed `throbber` atom labelled `label`, stamped atom kit `kit` and
/// apps contract 1. Kit 3 is this build's live pair; kit 2 is the oldest
/// stamp a body decodes at and holds a throbber.
fn throbber_tree(kit: u16, label: &str) -> Value {
    json!({
        "kit_version": kit,
        "apps_contract_version": 1,
        "root": {
            "id": "root",
            "atom": {"kind": "throbber", "props": {"label": label}},
            "fallbackText": label
        }
    })
}

fn throbber(kit: u16, label: &str) -> GeneratedLens {
    serde_json::from_value(throbber_tree(kit, label)).expect("a throbber lens decodes")
}

/// `lens` with the behavior it renders over a one-fixture golden corpus.
fn evaluated(lens: GeneratedLens) -> LensEvaluatedRevision {
    let behavior =
        LensBehaviorFingerprint::from_golden_renders([("golden", &lens)]).expect("a fingerprint");
    LensEvaluatedRevision::new(lens, behavior)
}

/// A proposed lens as its receipt names it.
struct Proposed {
    lens_ref: String,
    compiled_hash: String,
}

impl Proposed {
    fn id(&self) -> EntityId {
        EntityId::from_hex(&self.lens_ref).expect("a lens id")
    }
}

fn propose(owner: &Memory<'_>, slot: &Slot, label: &str, intent: &str) -> Proposed {
    let receipt = answered(
        door::invoke(
            owner,
            "vault.lenses.propose",
            json!({
                "slot": {"pack_name": slot.pack, "skill_id": slot.skill},
                "pack_content_hash": slot.content,
                "compiled": throbber_tree(3, label),
                "intent_prompt": intent
            }),
        ),
        "propose",
    );
    Proposed {
        lens_ref: receipt["lens_ref"].as_str().expect("lens_ref").to_owned(),
        compiled_hash: receipt["compiled_hash"]
            .as_str()
            .expect("compiled_hash")
            .to_owned(),
    }
}

/// The owner selects `lens` for its slot, which holds `expected` now.
fn activate(owner: &Memory<'_>, lens: &Proposed, expected: Option<&Proposed>) {
    let mut body = json!({"lens_ref": lens.lens_ref, "compiled_hash": lens.compiled_hash});
    if let Some(expected) = expected {
        body["expected_active_ref"] = json!(expected.lens_ref);
    }
    let receipt = answered(
        door::invoke(owner, "vault.lenses.activate", body),
        "activate",
    );
    assert_eq!(receipt["decision"], json!("activated"), "{receipt}");
}

fn list_row(owner: &Memory<'_>, lens_ref: &str) -> Value {
    let page = answered(
        door::invoke(owner, "vault.lenses.list", json!({"with_compiled": true})),
        "lenses.list",
    );
    page["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["lens_ref"] == json!(lens_ref))
        .cloned()
        .unwrap_or_else(|| panic!("list names {lens_ref}: {page}"))
}

#[track_caller]
fn assert_mounted(owner: &Memory<'_>, lens_ref: &str, mounted: bool) {
    let row = list_row(owner, lens_ref);
    assert_eq!(row["mounted"], json!(mounted), "{lens_ref}: {row}");
    if mounted {
        assert_eq!(row["state"], json!("active"), "{lens_ref}: {row}");
    }
}

fn stored_intent(vault: &Vault, lens_ref: &str) -> String {
    let id = EntityId::from_hex(lens_ref).expect("a lens id");
    vault
        .get_lens_intent(&id)
        .expect("the intent reads")
        .unwrap_or_else(|| panic!("{lens_ref} has a stored intent"))
        .prompt()
        .to_owned()
}

/// A regenerator that answers `candidate` and keeps every request it gets.
struct RecordingRegenerator {
    candidate: LensEvaluatedRevision,
    requests: RefCell<Vec<LensRegenRequest>>,
}

impl RecordingRegenerator {
    fn answering(candidate: LensEvaluatedRevision) -> Self {
        Self {
            candidate,
            requests: RefCell::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<LensRegenRequest> {
        self.requests.borrow().clone()
    }
}

impl LensRegenerator for RecordingRegenerator {
    fn regenerate(
        &self,
        request: &LensRegenRequest,
    ) -> Result<LensEvaluatedRevision, LensRegenFailure> {
        self.requests.borrow_mut().push(request.clone());
        Ok(self.candidate.clone())
    }
}

fn behavior_diff(
    before: &LensEvaluatedRevision,
    after: &LensEvaluatedRevision,
) -> LensBehaviorDiff {
    LensBehaviorDiff::between(before.behavior(), after.behavior()).expect("a behavior diff")
}

/// An upgrade reruns the prompt the lens's author stored, against the live
/// pair, once. The candidate reads what the last-good body read, so the
/// decision auto-adopts it, against the lens it names.
/// Red proof: `lens/intent.rs` the request carries the lens id in place of
/// the stored prompt (`-red1`).
#[test]
fn an_upgrade_reruns_the_lens_stored_intent_prompt() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let intent = "Draw a loading card for the weave.";
    let lens = propose(&owner, &slot, "loading", intent);

    let stale = evaluated(throbber(2, "loading"));
    assert_ne!(
        stale.lens().version_stamp(),
        LensVersionStamp::current(),
        "kit 2 is behind the live pair"
    );
    let regenerator = RecordingRegenerator::answering(evaluated(throbber(3, "loading")));

    let decision = vault
        .regenerate_lens_on_upgrade(&lens.id(), &regenerator, stale.clone())
        .expect("a lens behind the live pair is regenerated");
    assert_eq!(
        decision.active_ref,
        lens.id(),
        "the decision names the lens"
    );
    assert_eq!(
        regenerator.requests(),
        vec![LensRegenRequest::new(LensVersionStamp::current(), intent)],
        "the stored prompt reruns against the live pair, once"
    );
    match decision.outcome {
        LensRegenOutcome::AutoAdopt {
            last_good,
            candidate,
            diff,
        } => {
            assert_eq!(last_good, stale, "decided against the body it was given");
            assert_eq!(candidate, regenerator.candidate);
            assert!(!diff.has_data_read_change(), "the same reads");
        }
        other => panic!("a candidate with the same reads auto-adopts: {other:?}"),
    }
}

/// A lens with no stored intent never reruns a made-up prompt: the decision
/// rolls back to the last-good body, and enacting it stores nothing.
/// Red proof: `lens/intent.rs` the missing-intent arm reruns a fixed prompt
/// (`-red1`).
#[test]
fn a_lens_with_no_stored_intent_rolls_back_without_a_rerun() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let unknown = EntityId::from_hex(SOME_ID).expect("an id");

    let stale = evaluated(throbber(2, "loading"));
    let regenerator = RecordingRegenerator::answering(evaluated(throbber(3, "loading")));
    let decision = vault
        .regenerate_lens_on_upgrade(&unknown, &regenerator, stale.clone())
        .expect("a lens behind the live pair gets a decision");
    assert!(
        regenerator.requests().is_empty(),
        "no stored prompt, no rerun: {:?}",
        regenerator.requests()
    );
    assert_eq!(decision.active_ref, unknown);
    match &decision.outcome {
        LensRegenOutcome::RolledBack { last_good, failure } => {
            assert_eq!(*last_good, stale, "the last-good body stays");
            assert_eq!(failure.phase(), LensRegenFailurePhase::SummaryPromptRerun);
            assert_eq!(failure.message(), "lens intent record is missing");
        }
        other => panic!("a missing intent rolls back: {other:?}"),
    }

    let enactment =
        enact_lens_regeneration_embedded(&owner, slot.lens_slot(), slot.content.clone(), decision)
            .expect("a roll-back is enacted");
    assert_eq!(
        enactment,
        LensRegenEnactment::RolledBack {
            active_ref: None,
            phase: LensRegenFailurePhase::SummaryPromptRerun,
            message: "lens intent record is missing".to_owned(),
        }
    );
    let page = answered(door::invoke(&owner, "vault.lenses.list", json!({})), "list");
    assert_eq!(page["rows"], json!([]), "nothing was stored: {page}");
}

/// A lens at the live stamps needs no work: no decision, no rerun, and the
/// combined enactment answers that the slot is current.
/// Red proof: `lens/intent.rs` the live-stamp check is skipped (`-red1`).
#[test]
fn a_lens_at_the_live_stamps_is_not_regenerated() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let lens = propose(&owner, &slot, "loading", "Draw a loading card.");
    activate(&owner, &lens, None);

    let current = evaluated(throbber(3, "loading"));
    assert_eq!(current.lens().version_stamp(), LensVersionStamp::current());
    let regenerator = RecordingRegenerator::answering(evaluated(throbber(3, "ready")));
    assert!(
        vault
            .regenerate_lens_on_upgrade(&lens.id(), &regenerator, current.clone())
            .is_none(),
        "a current body is not regenerated"
    );

    let enactment = regenerate_and_enact_lens_embedded(
        &owner,
        slot.lens_slot(),
        slot.content.clone(),
        &regenerator,
        current,
    )
    .expect("the upgrade check runs");
    assert_eq!(
        enactment,
        LensRegenEnactment::Current {
            active_ref: lens.lens_ref.clone()
        }
    );
    assert!(
        regenerator.requests().is_empty(),
        "nothing reran: {:?}",
        regenerator.requests()
    );
    assert_mounted(&owner, &lens.lens_ref, true);
}

/// An auto-adopted candidate is proposed with the intent of the lens it was
/// regenerated from, so the next upgrade reruns the same prompt, and the
/// owner's slot now mounts it.
/// Red proof: `lens/regen.rs` the candidate's proposal carries an altered
/// intent (`-red2`).
#[test]
fn an_adopted_candidate_carries_the_intent_and_takes_the_slot() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let intent = "Draw a loading card for the weave.";
    let lens = propose(&owner, &slot, "loading", intent);
    activate(&owner, &lens, None);

    let last_good = evaluated(throbber(3, "loading"));
    let candidate = evaluated(throbber(3, "ready"));
    let diff = behavior_diff(&last_good, &candidate);
    assert!(!diff.has_data_read_change(), "the same reads");
    let decision = LensRegenDecision {
        active_ref: lens.id(),
        outcome: LensRegenOutcome::AutoAdopt {
            last_good,
            candidate,
            diff,
        },
    };

    let enactment =
        enact_lens_regeneration_embedded(&owner, slot.lens_slot(), slot.content.clone(), decision)
            .expect("an auto-adopt is enacted");
    let LensRegenEnactment::AutoAdopted {
        proposal,
        activation,
    } = &enactment
    else {
        panic!("the candidate takes the slot: {enactment:?}");
    };
    assert_ne!(proposal.lens_ref, lens.lens_ref, "a new revision");
    assert_eq!(activation.lens_ref, proposal.lens_ref);
    assert_eq!(
        activation.previous_ref.as_deref(),
        Some(lens.lens_ref.as_str())
    );
    assert_eq!(enactment.mounted_ref(), Some(proposal.lens_ref.as_str()));

    let row = list_row(&owner, &proposal.lens_ref);
    assert_eq!(
        row["compiled"]["root"]["atom"]["props"]["label"],
        json!("ready"),
        "the candidate's tree is stored: {row}"
    );
    assert_mounted(&owner, &proposal.lens_ref, true);
    assert_mounted(&owner, &lens.lens_ref, false);
    assert_eq!(
        stored_intent(&vault, &proposal.lens_ref),
        intent,
        "the recipe carries to the candidate"
    );
}

/// A candidate whose reads changed waits for the owner's stamp: it is
/// proposed with the decided lens's intent, and the old lens stays selected.
/// `lenses_enact_regeneration` reads only the outcome's kind, so the
/// decision is built over two throbber bodies.
/// Red proof: `lens/regen.rs` the candidate's proposal carries an altered
/// intent (`-red2`).
#[test]
fn a_candidate_that_needs_a_stamp_is_only_proposed() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let intent = "Draw a loading card for the weave.";
    let lens = propose(&owner, &slot, "loading", intent);
    activate(&owner, &lens, None);

    let last_good = evaluated(throbber(3, "loading"));
    let candidate = evaluated(throbber(3, "ready"));
    let diff = behavior_diff(&last_good, &candidate);
    let decision = LensRegenDecision {
        active_ref: lens.id(),
        outcome: LensRegenOutcome::NeedsHumanStamp {
            last_good,
            candidate: Box::new(candidate),
            diff,
        },
    };

    let enactment =
        enact_lens_regeneration_embedded(&owner, slot.lens_slot(), slot.content.clone(), decision)
            .expect("a stamp wait is enacted");
    let LensRegenEnactment::ProposedForStamp {
        proposal,
        active_ref,
    } = &enactment
    else {
        panic!("the candidate waits for the owner: {enactment:?}");
    };
    assert_eq!(active_ref.as_deref(), Some(lens.lens_ref.as_str()));
    assert_eq!(enactment.mounted_ref(), Some(lens.lens_ref.as_str()));
    assert_mounted(&owner, &lens.lens_ref, true);
    assert_mounted(&owner, &proposal.lens_ref, false);
    assert_eq!(
        list_row(&owner, &proposal.lens_ref)["state"],
        json!("proposed")
    );
    assert_eq!(
        stored_intent(&vault, &proposal.lens_ref),
        intent,
        "the recipe carries to the candidate"
    );
}

/// The owner selected another lens after the decision was made: the
/// auto-adopt candidate stays a proposal and the owner's newer selection
/// stays mounted (FIX 9897).
/// Red proof: `lens/regen.rs` the moved-slot check is off and the
/// activation is compared against the slot's selection now (`-red2`).
#[test]
fn a_slot_the_owner_moved_keeps_the_newer_selection() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let slot = weave_slot(&owner);
    let first = propose(
        &owner,
        &slot,
        "loading",
        "Draw a loading card for the weave.",
    );
    activate(&owner, &first, None);
    let decided = LensRegenDecision {
        active_ref: first.id(),
        outcome: {
            let last_good = evaluated(throbber(3, "loading"));
            let candidate = evaluated(throbber(3, "ready"));
            let diff = behavior_diff(&last_good, &candidate);
            LensRegenOutcome::AutoAdopt {
                last_good,
                candidate,
                diff,
            }
        },
    };
    let newer = propose(&owner, &slot, "waiting", "The owner's newer pick.");
    activate(&owner, &newer, Some(&first));

    let enactment =
        enact_lens_regeneration_embedded(&owner, slot.lens_slot(), slot.content.clone(), decided)
            .expect("a stale decision is enacted");
    let LensRegenEnactment::ProposedForStamp {
        proposal,
        active_ref,
    } = &enactment
    else {
        panic!("the owner's newer selection stays: {enactment:?}");
    };
    assert_eq!(active_ref.as_deref(), Some(newer.lens_ref.as_str()));
    assert_mounted(&owner, &newer.lens_ref, true);
    assert_mounted(&owner, &proposal.lens_ref, false);
    assert_mounted(&owner, &first.lens_ref, false);
}
