//! The `/v1/owner` routes [`super`] serves, one row per method and path:
//! the router and the OpenAPI document read this one table (FIX 8931).

use axum::routing::{get, post};

use super::super::{OwnerRoute, OwnerTable, RestShape};
use super::schema::{
    action_mode_policy_schema, answer_identity_ask_body_schema, approve_representation_body_schema,
    decline_representation_body_schema, digest_assembled_schema, identity_settled_schema,
    label_finding_body_schema, representation_approved_schema, representation_declined_schema,
    reviewed_finding_schema, set_action_mode_body_schema, set_stewardship_body_schema,
    stewardship_rules_schema,
};
use super::{
    action_mode, answer_identity_ask, answer_training_offer, approve_representation,
    assemble_digest, code_fixes, decline_representation, fund_judge_asks, identity_asks,
    judge_ask_minutes, label_self_heal_finding, pick_judge_ask, read_digest, regrade_judge_label,
    review_representation, self_heal_findings, self_heal_minted, set_action_mode, set_stewardship,
    stewardship, training_offers, training_runs, undo_training_offer_switch,
};

pub(in super::super) fn owner_table() -> OwnerTable {
    let mut table = vec![
        (
            OwnerRoute {
                method: "get",
                path: "/proactivity/digest",
                summary: "One delivered digest, verified against its id.",
                row: None,
                shape: None,
            },
            get(read_digest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/proactivity/digest/assemble",
                summary: "The caller's own digest, assembled now: what a due regular digest carries, and once a cadence period the judge calibration asks their funded minutes buy, which no other digest delivers.",
                row: None,
                shape: Some(RestShape::no_body(digest_assembled_schema)),
            },
            post(assemble_digest),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/proactivity/action-mode",
                summary: "The owner's action-mode policy.",
                row: None,
                shape: None,
            },
            get(action_mode),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/proactivity/action-mode",
                summary: "Replaces the whole policy.",
                row: None,
                shape: Some(RestShape::json(
                    set_action_mode_body_schema,
                    action_mode_policy_schema,
                )),
            },
            post(set_action_mode),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/stewardship",
                summary: "The owner's keep-in-touch rules.",
                row: None,
                shape: None,
            },
            get(stewardship),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/stewardship",
                summary: "Replaces the whole rule set.",
                row: None,
                shape: Some(RestShape::json(
                    set_stewardship_body_schema,
                    stewardship_rules_schema,
                )),
            },
            post(set_stewardship),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/representation",
                summary: "One drafted follow-up, as approval would send it.",
                row: None,
                shape: None,
            },
            get(review_representation),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/representation/approve",
                summary: "Approves the draft and schedules it.",
                row: None,
                shape: Some(RestShape::json(
                    approve_representation_body_schema,
                    representation_approved_schema,
                )),
            },
            post(approve_representation),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/representation/decline",
                summary: "Declines the draft for good.",
                row: None,
                shape: Some(RestShape::json(
                    decline_representation_body_schema,
                    representation_declined_schema,
                )),
            },
            post(decline_representation),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/coach/training-offers",
                summary: "The offers awaiting the owner.",
                row: None,
                shape: None,
            },
            get(training_offers),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-offers/answer",
                summary: "The owner's answer to the exact offer they saw.",
                row: None,
                shape: None,
            },
            post(answer_training_offer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-offers/undo",
                summary: "The owner's undo of the stock switch an approved offer bound.",
                row: None,
                shape: None,
            },
            post(undo_training_offer_switch),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/coach/code-fixes",
                summary: "The Coach's code-fix work, newest first (at most 256).",
                row: None,
                shape: None,
            },
            get(code_fixes),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/coach/judge-asks/minutes",
                summary: "The caller's remaining judge-ask minutes; zero until they fund some.",
                row: None,
                shape: None,
            },
            get(judge_ask_minutes),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/judge-asks/minutes",
                summary: "Sets the caller's balance.",
                row: None,
                shape: None,
            },
            post(fund_judge_asks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/judge-asks/pick",
                summary: "The caller's pick on an ask their digest delivered, a final label in the judged skill's anchor.",
                row: None,
                shape: None,
            },
            post(pick_judge_ask),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/judge-asks/regrade",
                summary: "The caller's re-grade of a pick a judge rubric edit left waiting: kept, or its case asked again.",
                row: None,
                shape: None,
            },
            post(regrade_judge_label),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/identity/asks",
                summary: "Every open identity ask, each with its one-tap choice card.",
                row: None,
                shape: None,
            },
            get(identity_asks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/identity/asks/answer",
                summary: "The owner's choice on one ask.",
                row: None,
                shape: Some(RestShape::json(
                    answer_identity_ask_body_schema,
                    identity_settled_schema,
                )),
            },
            post(answer_identity_ask),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/self-heal/findings",
                summary: "One detector's raised T3 findings, newest first, each with the owner's label.",
                row: None,
                shape: None,
            },
            get(self_heal_findings),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/self-heal/findings/label",
                summary: "The owner's one label on a raised T3 finding.",
                row: None,
                shape: Some(RestShape::json(
                    label_finding_body_schema,
                    reviewed_finding_schema,
                )),
            },
            post(label_self_heal_finding),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/self-heal/minted",
                summary: "Each family's registered T2, by family.",
                row: None,
                shape: None,
            },
            get(self_heal_minted),
        ),
    ];
    table.extend(training_runs::owner_table());
    table
}
