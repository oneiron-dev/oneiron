//! Threshold fixtures of the project scans for `no_engine_scan_refuses_for_its_row_count`
//! (FIX LIBTEST-SCAN-CHECK-TABLE-UNSEEDED-SCANS).

use super::*;

// Project family entity seeds: 0x90 and up (0x80 + 8 * 2).

/// A project body over `id`: parentless, leader and claims scope at fixed
/// seeds. Validates in a fresh vault; the depth row resolves implicitly.
fn project_body(id: EntityId) -> crate::workspace_roster::ProjectRecord {
    crate::workspace_roster::ProjectRecord::new(id, None, id(0x90, 1), id(0x90, 2))
        .expect("project body")
}

/// Roots the vault under `seed` for `writer`'s person (id 0x91/0): the
/// `gate::project_depth::tests` owner recipe. Returns the bound writer.
fn rooted_writer(vault: &Vault, seed: u8) -> crate::write_envelope::WriteActor {
    let person = id(0x91, 0);
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("owner person");
    let writer = crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(vault, writer, seed).expect("root");
    crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human)
}

/// One owner-signed creation-default edit at `depth`, signed with `seed`'s key.
fn default_edit(
    vault: &Vault,
    writer: &crate::write_envelope::WriteActor,
    depth: u64,
    now: u64,
    seed: u8,
) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    vault
        .set_project_creation_depth_default(depth, writer, now, key, |message| {
            Ok(ed25519_dalek::Signer::sign(&signing, message)
                .to_bytes()
                .to_vec())
        })
        .expect("default edit");
}

/// The owner, authenticated, and the root project, after narrowing every
/// goal-intake limit to `ROW` in the installed policy manifest.
fn goal_setup(vault: &Vault) -> (crate::consent::AuthenticatedOwner, EntityId) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("auth");
    let limits = crate::policy_model::goal_limits::GoalLimits {
        precedence: crate::policy_model::goal_limits::GoalLimitsPrecedence::NestedNarrowing,
        goal_bytes: ROW,
        why_bytes: ROW,
        axis_name_bytes: ROW,
        axis_detail_bytes: ROW,
        axes: ROW,
        preferences: ROW,
        scoped: Vec::new(),
    };
    let bytes = crate::gate::default_policy_manifest().expect("manifest");
    let mut value = rmpv::decode::read_value(&mut bytes.as_slice()).expect("decode");
    if let rmpv::Value::Map(ref mut entries) = value {
        entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("goal_limits"))
            .expect("goal limits row")
            .1 = limits.encode();
    } else {
        panic!("manifest map");
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &value).expect("encode");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &data,
    )
    .expect("put manifest");
    (auth, vault.root_project().expect("root"))
}

/// A minimal valid intake: three axes, no preferences, one-letter texts.
fn goal_base() -> crate::workspace_roster::GoalRecord {
    let axis = |name: &str| crate::workspace_roster::GoalAxis {
        name: name.into(),
        measure: "m".into(),
        bound: "b".into(),
    };
    crate::workspace_roster::GoalRecord {
        goal: "g".into(),
        why: "w".into(),
        primary_axes: vec![axis("a1")],
        floor_axes: vec![axis("a2")],
        cost_axes: vec![axis("human_minutes")],
        preferences: Vec::new(),
        exploration_budget: crate::workspace_roster::GoalExplorationBudget {
            max_spend: 1000,
            exploration_slice: 100,
            unit: crate::run_budget::LeaseUnit::tokens(),
            human_minutes: 20,
        },
    }
}

/// A minimal valid proposal card: `axes` goal axes, one board human, no skills.
fn proposal_card(card_id: &str, axes: Vec<String>) -> crate::genui::ProjectProposalCard {
    crate::genui::ProjectProposalCard::new(
        card_id,
        "p",
        "m",
        crate::genui::ProjectGoalDraft {
            goal: "g".into(),
            why: "w".into(),
            axes,
        },
        crate::genui::ProjectProposalPicks {
            leader_agent_def_ref: "l".into(),
            board_human_refs: vec!["h".into()],
            budget_share_bps: 0,
            starting_skill_refs: Vec::new(),
        },
    )
    .expect("card")
}

const O_CARDS: crate::side_table::SideTable<
    [u8; 32],
    crate::workspace_roster::ProjectCardRecord,
    crate::side_table::Named,
> = crate::side_table::SideTable::new(&crate::side_table::PROJECT_PROPOSAL_CARD);
const O_CONV: crate::side_table::SideTable<(EntityId, [u8; 32]), EntityId, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::PROJECT_PROPOSAL_CONVERSATION);
const O_VERDICTS: crate::side_table::SideTable<
    EntityId,
    crate::workspace_roster::project::ProjectDetectionVerdict,
    crate::side_table::Named,
> = crate::side_table::SideTable::new(&crate::side_table::PROJECT_PROPOSAL_VERDICT);

fn card_key(card_id: &str) -> [u8; 32] {
    *blake3::hash(card_id.as_bytes()).as_bytes()
}

/// A kept yes on `message` for the drafter `house`: the receipt's shape is
/// never judged by the propose door, only the answer and the house.
fn yes_verdict(
    conversation: EntityId,
    turn: EntityId,
    message: EntityId,
    author: EntityId,
    house: EntityId,
) -> crate::workspace_roster::project::ProjectDetectionVerdict {
    crate::workspace_roster::project::ProjectDetectionVerdict {
        source: crate::workspace_roster::project::ProjectDetectionSource {
            conversation,
            turn,
            message,
            author,
            thread: None,
            at: 2,
        },
        answer: crate::workspace_roster::project::ProjectDetectionAnswer::Yes,
        receipt: crate::llm::decision::DecisionReceipt {
            question: message,
            question_version: 1,
            principal: author,
            providers: Vec::new(),
            band: crate::model_decision::DecisionBand {
                low: 0.35,
                high: 0.65,
            },
            band_version: 0,
            evidence_versions: Vec::new(),
            cost_per_thousand: None,
            paired: Vec::new(),
            person: Vec::new(),
            time: None,
            images: Vec::new(),
            think_row: None,
            person_row: None,
            rule: None,
            asked: None,
            state_cut: None,
        },
        house: Some(house),
    }
}

/// Two live cards and three kept yeses in one conversation; returns the
/// drafter and the third card's request.
fn outstanding_seed(vault: &Vault) -> (EntityId, crate::workspace_roster::ProjectProposalRequest) {
    let conversation = id(0x93, 0);
    let turn = id(0x93, 1);
    let author = id(0x93, 2);
    let drafter = id(0x93, 3);
    vault
        .put_entity(
            &drafter,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .expect("drafter");
    let messages = [id(0x93, 4), id(0x93, 5), id(0x93, 6)];
    vault
        .with_write_txn(|wtxn| {
            for message in &messages {
                O_VERDICTS.put(
                    &vault.store,
                    wtxn,
                    message,
                    &yes_verdict(conversation, turn, *message, author, drafter),
                )?;
            }
            for (slot, message) in ["card-1", "card-2"].into_iter().zip(&messages[..2]) {
                let card = proposal_card(slot, vec!["a".into()]);
                O_CARDS.put(
                    &vault.store,
                    wtxn,
                    &card_key(slot),
                    &crate::workspace_roster::ProjectCardRecord {
                        card,
                        conversation,
                        detection: *message,
                        drafted_by: crate::workspace_roster::RosterActor::Actor(drafter),
                        state: crate::workspace_roster::project::ProjectCardState::Proposed,
                        at: 2,
                        history: false,
                    },
                )?;
                O_CONV.put(&vault.store, wtxn, &(conversation, card_key(slot)), message)?;
            }
            Ok(())
        })
        .expect("seed");
    let request = crate::workspace_roster::ProjectProposalRequest {
        card_id: "card-3".into(),
        source_message_ref: messages[2].to_hex(),
        goal: crate::genui::ProjectGoalDraft {
            goal: "g".into(),
            why: "w".into(),
            axes: vec!["a".into()],
        },
        picks: crate::genui::ProjectProposalPicks {
            leader_agent_def_ref: "l".into(),
            board_human_refs: vec!["h".into()],
            budget_share_bps: 0,
            starting_skill_refs: Vec::new(),
        },
    };
    (drafter, request)
}

/// The owner and a three-axis resident binding over a witnessed home room.
fn resident_binding(
    vault: &Vault,
) -> (
    crate::consent::AuthenticatedOwner,
    crate::agent_dispatch::ResidentAgentSpec,
) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (lead, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("defs")
        .expect("lead");
    let inbox = id(0x94, 0);
    vault
        .create_own_app_channel_identity(&inbox, lead, 1)
        .expect("inbox");
    let goal = id(0x94, 1);
    vault
        .put_entity(
            &goal,
            crate::registry::ENTITY_TYPE_TURN,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            &[0x80],
        )
        .expect("goal turn");
    let room = id(0x94, 2);
    let node = id(0x94, 3);
    vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 2,
            messages: vec![crate::memory::WitnessMessage {
                id: Some(node.to_hex()),
                author: crate::memory::WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "room".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("witness");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("auth");
    let axis = crate::task_verb::ConsultPayloadRef::Turn(goal);
    let spec = crate::agent_dispatch::ResidentAgentSpec {
        agent_def_ref: lead,
        inbox_identity_ref: inbox,
        home_conversation_ref: room,
        home_message_ref: node,
        goal: crate::agent_dispatch::ResidentGoalRecord {
            goal: axis,
            why: axis,
            axes: vec![axis, axis, axis],
        },
        wake: crate::agent_dispatch::ResidentWakeMode::HumanMessages,
        wake_hold_secs: 0,
        digest_delay_secs: crate::agent_dispatch::RESIDENT_DIGEST_DELAY_DEFAULT_SECS,
    };
    (auth, spec)
}

pub(super) fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    match scan {
        EngineScan::ProjectTaskRows => {
            // Three TASK rows, no asks: one count under the project.
            let id = id(0x90, 10);
            let mut body = project_body(id);
            body.tasks = (20..20 + PAST)
                .map(|index| id(0x90, index).to_hex())
                .collect();
            let bytes = rmp_serde::to_vec_named(&body).expect("encode");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::workspace_roster::normalize_project_body(
                        &vault.store,
                        &txn,
                        id,
                        &bytes,
                        vault.privacy_posture(),
                    )?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectDepthDefaultRows => {
            // Three owner-signed creation-default edits, chained; the fold
            // serves the last one's depth.
            let writer = rooted_writer(vault, 0xB0);
            default_edit(vault, &writer, 9, 2, 0xB0);
            default_edit(vault, &writer, 8, 3, 0xB0);
            default_edit(vault, &writer, 7, 4, 0xB0);
            Some((
                7,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let resolved = crate::gate::project_depth::resolve_creation_default(
                        &vault.store,
                        &txn,
                        vault.privacy_posture(),
                    )?;
                    Ok(resolved.depth as usize)
                }),
            ))
        }
        EngineScan::ProjectDepthPolicyRows => {
            // A project with three owner-signed depth edits over its
            // implicit birth; the fold serves the last one's depth.
            let root = vault.root_project().expect("root");
            let project = id(0x91, 1);
            let record =
                crate::workspace_roster::ProjectRecord::new(project, Some(root), root, id(0x91, 0))
                    .expect("record");
            vault.put_project(project, &record, 1).expect("project");
            let writer = rooted_writer(vault, 0xB0);
            crate::workspace_roster::set_project_depth_signed_for_test(
                vault, project, 2, &writer, 2, 0xB0,
            )
            .expect("edit");
            crate::workspace_roster::set_project_depth_signed_for_test(
                vault, project, 5, &writer, 3, 0xB0,
            )
            .expect("edit");
            crate::workspace_roster::set_project_depth_signed_for_test(
                vault, project, 7, &writer, 4, 0xB0,
            )
            .expect("edit");
            Some((
                7,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let resolved = crate::gate::project_depth::resolve_project_depth(
                        &vault.store,
                        &txn,
                        vault.privacy_posture(),
                        project,
                    )?;
                    Ok(resolved.depth as usize)
                }),
            ))
        }
        EngineScan::ProjectDepthSourceAncestors => {
            // Three chained default edits, then a signed birth pinned on
            // the last: resolving the depth walks four ancestors.
            let writer = rooted_writer(vault, 0xB0);
            default_edit(vault, &writer, 9, 2, 0xB0);
            default_edit(vault, &writer, 8, 3, 0xB0);
            default_edit(vault, &writer, 7, 4, 0xB0);
            let project = id(0x91, 2);
            let signing = ed25519_dalek::SigningKey::from_bytes(&[0xB0; 32]);
            let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
            vault
                .with_write_txn(|wtxn| {
                    crate::gate::project_depth::put_signed_birth_in_txn(
                        vault,
                        wtxn,
                        project,
                        &writer,
                        5,
                        key,
                        |message| {
                            Ok(ed25519_dalek::Signer::sign(&signing, message)
                                .to_bytes()
                                .to_vec())
                        },
                    )?;
                    Ok(())
                })
                .expect("birth");
            Some((
                7,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let resolved = crate::gate::project_depth::resolve_project_depth(
                        &vault.store,
                        &txn,
                        vault.privacy_posture(),
                        project,
                    )?;
                    Ok(resolved.depth as usize)
                }),
            ))
        }
        // NO-FIXTURE: the owner doors build on one head, so no reachable
        // write carries three predecessors; signing one by hand needs the
        // private contribution transcript.
        EngineScan::ProjectDepthPredecessors => None,
        EngineScan::ProjectDepthContributionBytes => {
            // A rooted vault with no birth yet: the read stores the local
            // birth, whose bytes dwarf the row; the second read is a no-op.
            rooted_writer(vault, 0xB0);
            let project = id(0x91, 3);
            Some((
                1,
                Box::new(move || {
                    vault.with_write_txn(|wtxn| {
                        crate::gate::project_depth::put_local_birth_in_txn(
                            vault, wtxn, project, 2,
                        )?;
                        Ok(1)
                    })
                }),
            ))
        }
        EngineScan::ProjectGoalAxes => {
            // Three axes against the narrowed limit; the intake writes twice.
            let (auth, project) = goal_setup(vault);
            let record = goal_base();
            Some((
                PAST,
                Box::new(move || {
                    vault.write_project_goal_from_intake(&auth, project, &record, 2)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectGoalPreferences => {
            // Three preferences against the narrowed limit.
            let (auth, project) = goal_setup(vault);
            let mut record = goal_base();
            record.preferences = ["a", "b", "c"]
                .map(|tag| crate::workspace_roster::GoalPreference {
                    prefer: format!("cheap-{tag}"),
                    over: format!("fast-{tag}"),
                    reason: format!("chose-{tag}"),
                })
                .to_vec();
            Some((
                PAST,
                Box::new(move || {
                    vault.write_project_goal_from_intake(&auth, project, &record, 2)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectGoalTextBytes => {
            // A three-byte goal against the narrowed limit; the why stays
            // at the row so only the goal's scope crosses.
            let (auth, project) = goal_setup(vault);
            let mut record = goal_base();
            record.goal = "abc".into();
            record.why = "ok".into();
            Some((
                PAST,
                Box::new(move || {
                    vault.write_project_goal_from_intake(&auth, project, &record, 2)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectGoalAxisNameBytes => {
            // Three three-byte axis names under one scope.
            let (auth, project) = goal_setup(vault);
            let mut record = goal_base();
            record.primary_axes[0].name = "aaa".into();
            record.floor_axes[0].name = "bbb".into();
            record.cost_axes[0].name = "ccc".into();
            record.cost_axes.push(crate::workspace_roster::GoalAxis {
                name: "human_minutes".into(),
                measure: "m".into(),
                bound: "b".into(),
            });
            Some((
                PAST,
                Box::new(move || {
                    vault.write_project_goal_from_intake(&auth, project, &record, 2)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectGoalDetailBytes => {
            // Three-byte measures against the narrowed limit; bounds stay
            // at the row and no preferences are named, so only the
            // measure's scope crosses.
            let (auth, project) = goal_setup(vault);
            let mut record = goal_base();
            for axis in record
                .primary_axes
                .iter_mut()
                .chain(record.floor_axes.iter_mut())
                .chain(record.cost_axes.iter_mut())
            {
                axis.measure = "mmm".into();
                axis.bound = "ok".into();
            }
            Some((
                PAST,
                Box::new(move || {
                    vault.write_project_goal_from_intake(&auth, project, &record, 2)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectSideListEntries => {
            // A three-entry board; every other side list stays at its row.
            let id = id(0x90, 11);
            let mut body = project_body(id);
            body.board = (30..30 + PAST)
                .map(|index| id(0x90, index).to_hex())
                .collect();
            let bytes = rmp_serde::to_vec_named(&body).expect("encode");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::workspace_roster::normalize_project_body(
                        &vault.store,
                        &txn,
                        id,
                        &bytes,
                        vault.privacy_posture(),
                    )?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectBodyGoalAxes => {
            // A goal record with three axes.
            let id = id(0x90, 12);
            let mut body = project_body(id);
            body.goal_record = Some(crate::workspace_roster::ProjectGoalRecord {
                project_id: id.to_hex(),
                goal: "g".into(),
                why: "w".into(),
                axes: vec!["a".into(), "b".into(), "c".into()],
            });
            body.why = Some("w".into());
            let bytes = rmp_serde::to_vec_named(&body).expect("encode");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::workspace_roster::normalize_project_body(
                        &vault.store,
                        &txn,
                        id,
                        &bytes,
                        vault.privacy_posture(),
                    )?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectAncestryRows => {
            // Three direct parents, counted under the project and the list.
            let id = id(0x90, 13);
            let mut body = project_body(id);
            body.parents = (40..40 + PAST)
                .map(|index| id(0x90, index).to_hex())
                .collect();
            let bytes = rmp_serde::to_vec_named(&body).expect("encode");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::workspace_roster::normalize_project_body(
                        &vault.store,
                        &txn,
                        id,
                        &bytes,
                        vault.privacy_posture(),
                    )?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectOutstandingCards => {
            // Two live cards shown, three kept yeses: the read drafts the
            // third card past the row; its retry is the idempotent same.
            let (drafter, request) = outstanding_seed(vault);
            Some((
                1,
                Box::new(move || {
                    vault
                        .memory(drafter, crate::edge::EdgeActorClass::Agent)
                        .projects_propose(&request)
                        .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
                    Ok(1)
                }),
            ))
        }
        // NO-FIXTURE: deciding a parent cycle needs several signed projects
        // whose parents name each other; the signing doors behind that are
        // private test helpers, far past forty lines from here.
        EngineScan::ProjectCycleWorlds => None,
        // NO-FIXTURE: deciding a parent cycle needs several signed projects
        // whose parents name each other; the signing doors behind that are
        // private test helpers, far past forty lines from here.
        EngineScan::ProjectCycleAssignments => None,
        // NO-FIXTURE: deciding a parent cycle needs several signed projects
        // whose parents name each other; the signing doors behind that are
        // private test helpers, far past forty lines from here.
        EngineScan::ProjectJointWork => None,
        EngineScan::ProjectProposalEntries => {
            // Three goal axes; the board holds one human and no skill is
            // named, so only the axes' scope crosses.
            let card = proposal_card("card-9", vec!["a".into(), "b".into(), "c".into()]);
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    card.observe_sizes(&vault.store, &txn)?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::ProjectProposalTextBytes => {
            // Every field one letter: only the joined fallback text, tens
            // of bytes, crosses the row.
            let card = proposal_card("c", vec!["a".into()]);
            let served = card.fallback_text().len();
            Some((
                served,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    card.observe_sizes(&vault.store, &txn)?;
                    Ok(card.fallback_text().len())
                }),
            ))
        }
        EngineScan::ResidentGoalAxes => {
            // A resident binding with three goal axes; binding twice
            // validates twice under one scope.
            let (auth, spec) = resident_binding(vault);
            Some((
                PAST,
                Box::new(move || {
                    vault.bind_resident_agent(&auth, &spec, 3)?;
                    Ok(PAST)
                }),
            ))
        }
        // NO-FIXTURE: a three-deep anchor lineage needs three verified
        // signed revisions; the slip-signing doors behind those are
        // private test helpers, far past forty lines from here.
        EngineScan::ProjectAnchorDepth => None,
        // NO-FIXTURE: a three-deep revision lineage needs three signed
        // revisions over one another; capturing those needs the same
        // private signing doors, far past forty lines from here.
        EngineScan::ProjectFoldDepth => None,
        other => unreachable!("{} is seeded in another module", other.code()),
    }
}
