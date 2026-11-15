//! The check a host-door row's door runs before the row's pre hooks
//! (`row_door_admits`, FIX 1763) admits the same callers under every proof
//! kind, before and after the proof table (UC-01 PR 0a): a guard, green on
//! main and on every later UC-01 PR.
//!
//! One row per proof kind the rows name today, plus one row per check of
//! the old hand list of verb names, which 0a moves into the rows. That is
//! one row or more per rule of the table, so a kind folded into a shared
//! rule keeps who it admits. Each row is judged for the three callers of
//! `support/door_rule_fixture.rs`: `owner` (this install's host root),
//! `agent` (a registered agent on its own slip, holding no Grant) and
//! `unbound` (a slip naming a principal the vault does not know).
//!
//! The table below is what main admits. A mismatch lists every row's
//! observed answers at once. An IN is only this pre-hook check: the room
//! save, booking, grants-answer, foreign-code and saved-query handlers
//! check the save grant, owner act, request, actor or query after it.
//! `vault.coach.training_offers.run` (`engine_controller`) is left out: its
//! kind is `substrate_reader`'s own fn, and Setting stage 2 deletes its 14
//! rows.
//!
//! Deterministic: in-process vault and server, no HTTP, no models.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test door_rule_admission`.
#![cfg(oneiron_test_support)]

#[path = "support/door_rule_fixture.rs"]
mod door_rule_fixture;

use door_rule_fixture::{TestResult, admits, setup};

/// Admitted before the row's hooks.
const IN: bool = true;
/// Refused before the row's hooks.
const OUT: bool = false;

/// `(kind or hand-list check, row, owner, agent, unbound)`, as main admits.
const ROWS: &[(&str, &str, bool, bool, bool)] = &[
    // The owner's proof.
    ("owner", "ai.reply", IN, OUT, OUT),
    // A person: the owner, or a live person on their own human slip.
    ("shared_person", "vault.code.waits.receipt", IN, OUT, OUT),
    (
        "trusted_contact_person",
        "vault.trusted_contacts.concern.asks",
        IN,
        OUT,
        OUT,
    ),
    // A member: as a person, bound as one.
    (
        "workflow_member",
        "vault.workflows.dispatch_bound",
        IN,
        OUT,
        OUT,
    ),
    ("check_in_holder", "vault.check_in.answer", IN, OUT, OUT),
    // The owner, else a person or agent on its own verified slip.
    ("substrate_reader", "vault.imports.get", IN, IN, OUT),
    ("run_reader", "vault.budgets.lease", IN, IN, OUT),
    ("skill_reader", "vault.skills.get", IN, IN, OUT),
    ("import_canceller", "vault.imports.cancel", IN, IN, OUT),
    ("skill_forker", "vault.skills.fork", IN, IN, OUT),
    // The owner, else the credential's own actor.
    ("claim_settler", "vault.claims.review", IN, IN, OUT),
    ("consent_revoker", "vault.consent.revoke", IN, IN, OUT),
    (
        "model_binding_proposer",
        "vault.models.bindings.propose",
        IN,
        IN,
        OUT,
    ),
    // The credential's own actor.
    (
        "origin_publish",
        "vault.code.origin.publish.approve",
        IN,
        IN,
        OUT,
    ),
    ("diary_reader", "self.memory.diary.pinned", IN, IN, OUT),
    ("facade_actor", "crawl", IN, IN, OUT),
    ("artifact_asker", "vault.artifacts.admit", IN, IN, OUT),
    ("code_import", "vault.code.imports.create", IN, IN, OUT),
    (
        "slide_reviewer",
        "vault.artifacts.review_slides",
        IN,
        IN,
        OUT,
    ),
    ("image_editor", "vault.artifacts.image.edit", IN, IN, OUT),
    (
        "hand list: share_doors::principal",
        "vault.shares.view",
        IN,
        IN,
        OUT,
    ),
    (
        "hand list: weave_doors::own_caller",
        "vault.weave.lens",
        IN,
        IN,
        OUT,
    ),
    // The credential's own actor, on a credential that is not channel-bound.
    (
        "code_export_preview",
        "vault.code.export.preview",
        IN,
        IN,
        OUT,
    ),
    (
        "review_policy",
        "vault.code.merge_queue.review_policy.get",
        IN,
        IN,
        OUT,
    ),
    ("view_editor", "vault.code.views.edit", IN, IN, OUT),
    (
        "checkout_holder",
        "vault.code.checkout.holder.bind",
        IN,
        IN,
        OUT,
    ),
    // An owner-grade credential.
    ("media_owner_grade", "ai.embed", IN, OUT, OUT),
    ("video_job_owner_grade", "ai.video.cancel", IN, OUT, OUT),
    // The caller, then the usage-repair writer's admission for the verb.
    (
        "usage_repair_list",
        "vault.usage.events.undecodable",
        IN,
        OUT,
        OUT,
    ),
    (
        "usage_repair_remove",
        "vault.usage.events.remove_undecodable",
        IN,
        OUT,
        OUT,
    ),
    (
        "usage_repair_receipts",
        "vault.usage.repair.receipts",
        IN,
        OUT,
        OUT,
    ),
    // The rules that stay one kind each.
    ("off_record", "self.off_record.execute", IN, IN, OUT),
    (
        "off_record_room",
        "vault.off_record.rooms.confirm_save",
        OUT,
        IN,
        OUT,
    ),
    ("voice_bank", "vault.voices.inspect", IN, IN, OUT),
    (
        "booking_owner_act",
        "vault.booking.availability",
        IN,
        IN,
        IN,
    ),
    ("packs_setup", "vault.packs.put", IN, IN, OUT),
    ("decision_holder", "self.decisions.asks", OUT, IN, OUT),
    ("hyde_caller", "vault.retrieval.hyde.complete", IN, IN, OUT),
    (
        "guest_document_reader",
        "vault.guests.export_envelope",
        OUT,
        OUT,
        OUT,
    ),
    (
        "tradeoff_picker",
        "vault.skills.optimize.tradeoff_asks",
        IN,
        IN,
        OUT,
    ),
    ("artifact_publisher", "vault.artifacts.publish", IN, IN, OUT),
    ("model_step_caller", "ai.steps.receipt", IN, IN, OUT),
    ("policy_putter", "vault.gate.policy.put", IN, OUT, OUT),
    (
        "ramp_demoter",
        "vault.consent.graduation.demote",
        IN,
        OUT,
        OUT,
    ),
    ("grants_answer", "self.grants.answer", IN, IN, OUT),
    ("credential_holder", "self.credential.attenuate", IN, IN, IN),
    ("foreign_code", "execute_code", IN, IN, IN),
    ("verdict_asker", "ai.verdict", IN, IN, IN),
    (
        "hand list: graph_ask_doors::asker",
        "vault.graph.ask",
        IN,
        IN,
        IN,
    ),
    (
        "eval_authoring",
        "vault.evals.authoring.execute",
        IN,
        OUT,
        OUT,
    ),
    ("saved_query", "self.saved_query.evaluate", IN, IN, OUT),
    // A person who also binds an actor (the old hand list's weave labels).
    (
        "hand list: weave_doors::person_lens",
        "vault.weave.link.wrong",
        IN,
        OUT,
        OUT,
    ),
];

/// Every row admits before its hooks exactly the callers main admits. A
/// mismatch names every row's observed answers.
#[test]
fn each_proof_kind_admits_the_callers_main_admits() -> TestResult {
    let fixture = setup()?;
    let mut observed = Vec::new();
    let mut mismatched = 0;
    for &(kind, verb, owner, agent, unbound) in ROWS {
        let mut answers = Vec::new();
        for (who, credential, expected) in [
            ("owner", &fixture.owner, owner),
            ("agent", &fixture.agent, agent),
            ("unbound", &fixture.unbound, unbound),
        ] {
            let answer = admits(&fixture, credential, verb)?;
            if answer.is_ok() != expected {
                mismatched += 1;
            }
            let shown = match &answer {
                Ok(()) => "IN".to_owned(),
                Err(refusal) => format!("OUT ({refusal})"),
            };
            let mark = if answer.is_ok() == expected {
                ""
            } else {
                " <- expected otherwise"
            };
            answers.push(format!("    {who}: {shown}{mark}"));
        }
        observed.push(format!("  {kind} ({verb}):\n{}", answers.join("\n")));
    }
    assert!(
        mismatched == 0,
        "{mismatched} answers differ from main's table:\n{}",
        observed.join("\n")
    );
    Ok(())
}

/// A credential's refusal is the row check's own: each caller is
/// authenticated, so no answer above is a credential refusal.
#[test]
fn every_caller_is_authenticated() -> TestResult {
    let fixture = setup()?;
    for (who, credential) in [
        ("owner", &fixture.owner),
        ("agent", &fixture.agent),
        ("unbound", &fixture.unbound),
    ] {
        for &(_, verb, ..) in ROWS {
            if let Err(refusal) = admits(&fixture, credential, verb)? {
                assert!(
                    !refusal.starts_with("credential:"),
                    "{who} on {verb}: {refusal}"
                );
            }
        }
    }
    Ok(())
}
