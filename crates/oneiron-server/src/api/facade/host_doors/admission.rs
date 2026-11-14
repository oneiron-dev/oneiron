//! The owner preflight every host door's verb meets before its door runs. `door_admits` is its call
//! surface. Each door's own facade module defines the proof it admits on; this match only routes to
//! it. Every host door that checks first names its proof in its verb row (`host_door_proof`, the
//! generated `HostDoorRow::proof`): the generator refuses a checked row without one, and a new proof
//! kind fails to compile until it has its arm here (FIX 1763; VERB-METADATA). Checked verbs that
//! project no host row keep main's owner-proof check in the fallback below.

use oneiron::memory::MemoryResult;

use super::super::host_door_rows::{HostDoorProof as Proof, HostDoorRow as Row};
use super::support::{
    MEDIA_OWNERS, VIDEO_JOB_OWNERS, artifact_asker, asking, diary_reader, owner_grade, owner_proof,
    slide_reviewer,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The authority check host-door row `verb`'s own door runs first: the owner's proof, a person's
/// proof, a bound principal or an owner-grade credential. The facade runs it before the row's pre
/// chain, so a hook never fires on a call the door refuses; the door runs it again for the proof it
/// acts under. A host door whose table row says `"host_door_precheck": false` has no such check and
/// passes, as does any row that is no host door.
pub(in crate::api::facade) fn door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    // Every other host door names its check below (FIX 1763).
    let Some(row) = Row::from_verb(verb) else {
        // Verbs main's match checks that project no host row (all under
        // the owner's proof there) keep that check here instead of passing.
        return match verb {
            "vault.artifacts.live_preview.revoke_invite"
            | "vault.artifacts.live_preview.revoke_share"
            | "vault.authority.handoff_alarms.acknowledge"
            | "vault.coach.training_offers.candidates.prepare"
            | "vault.coach.training_offers.pilots.complete"
            | "vault.coach.training_offers.pilots.prepare"
            | "vault.federation.connect.world_privacy.export"
            | "vault.federation.connect.world_privacy.receive"
            | "vault.federation.coreference.share_consent"
            | "vault.skills.attribution.evidence.record"
            | "vault.skills.attribution.positive.retire" => {
                owner_proof(auth, server, verb).map(drop)
            }
            // Doors with no host row whose own door refuses its caller up
            // front run that same check here (FIX 1817), so a hook never
            // fires on a call the door refuses.
            "vault.shares.view" | "vault.shares.revoke" | "vault.notes.follow_citation" => {
                super::super::share_doors::principal(server, auth, verb).map(drop)
            }
            "vault.weave.link.wrong" => {
                super::super::weave_doors::person_lens(server, auth, verb, "labels a link")
                    .map(drop)
            }
            "vault.weave.item.wrong" => {
                super::super::weave_doors::person_lens(server, auth, verb, "labels an item")
                    .map(drop)
            }
            "vault.weave.lens" => super::super::weave_doors::own_caller(
                server,
                auth,
                verb,
                "renders the credential's own lens",
            )
            .map(drop),
            "vault.weave.digest" => super::super::weave_doors::own_caller(
                server,
                auth,
                verb,
                "reads the credential's own digest",
            )
            .map(drop),
            "vault.graph.ask"
            | "vault.graph.admit"
            | "vault.questions.create"
            | "vault.questions.edit"
            | "vault.questions.pause"
            | "vault.questions.backfill"
            | "vault.questions.read"
            | "vault.questions.refresh"
            | "vault.questions.schedule" => {
                super::super::graph_ask_doors::asker(auth, server, verb).map(drop)
            }
            _ => Ok(()),
        };
    };
    match row.proof() {
        Proof::BookingOwnerAct => {
            crate::api::facade::owner_binding::host_preflight(server, auth)?;
            crate::api::host_action::require_host_owner_act(server, auth)
                .map(drop)
                .map_err(|error| {
                    crate::api::facade::FacadeApiError::from(error).into_memory_error()
                })
        }
        Proof::Owner => owner_proof(auth, server, verb).map(drop),
        // `vault.consent.revoke` (FIX 23149): the owner's proof, or a credential bound to an actor,
        // which the door then admits only on a Grant that actor holds. A caller with neither keeps
        // the owner refusal.
        Proof::ConsentRevoker => owner_proof(auth, server, verb)
            .map(drop)
            .or_else(|refusal| {
                crate::api::facade::owner_binding::facade_caller_or(server, auth, || refusal)
                    .map(drop)
            }),
        // The step rows (slice 6.5c): the owner, or an agent on its own
        // verified credential; the door holds the live run the agent names.
        Proof::ModelStepCaller => {
            crate::api::facade::model_step_doors::step_caller_admits(server, auth, verb)
        }
        // A substrate read (untangle 6.6c): the owner under its proof, or a person or agent on its own slip,
        // whose Steward grant the engine reader checks at the read.
        Proof::SubstrateReader => {
            crate::api::facade::substrate_read_doors::substrate_reader(server, auth, verb).map(drop)
        }
        // `vault.imports.cancel` (ARCH-0027 #hosted-import): the owner under its proof, or a person
        // or agent on its own slip, whose Steward `delete` grant the cancel's writer checks.
        Proof::ImportCanceller => {
            crate::api::facade::hosted_import_doors::import_canceller(server, auth, verb).map(drop)
        }
        // An engine-control knob (untangle 6.6d): the owner under its proof, or a person or agent on
        // its own slip, whose engine.controls grant the knob's writer checks in the write.
        Proof::EngineController => {
            crate::api::facade::engine_control_doors::engine_controller(server, auth, verb)
                .map(drop)
        }
        Proof::ClaimSettler => {
            crate::api::facade::claim_settle_doors::settler_admits(server, auth, verb)
        }
        // The owner's proof, or an actor-bound credential whose own live Grant the proposal
        // writer checks. A caller bound to no actor keeps the owner refusal.
        Proof::ModelBindingProposer => {
            owner_proof(auth, server, verb)
                .map(drop)
                .or_else(|refusal| {
                    crate::api::facade::owner_binding::facade_caller_or(server, auth, || refusal)
                        .map(drop)
                })
        }
        Proof::SharedPerson => {
            crate::api::facade::shared_act_doors::person(server, auth, verb).map(drop)
        }
        // The voice bank's rows (FIX 4393): a live person on their own proof,
        // owner or not, or a designed voice's creator on its own credential;
        // the bank binds each act to the voice's subject or creator.
        Proof::VoiceBank => {
            crate::api::facade::voice_bank_doors::voice_bank_admits(server, auth, verb)
        }
        // The exact publish rows (FIX 6866): the owner, or a bound principal
        // whose one Grant the engine door admits in its own snapshot.
        Proof::OriginPublish => {
            crate::api::facade::origin_publish_doors::publish_admits(server, auth, verb)
        }
        // The outside import rows (FIX 6871): a bound principal; the engine
        // door admits the owner or the push's own standing.
        Proof::CodeImport => {
            crate::api::facade::code_import_doors::imports_admit(server, auth, verb)
        }
        // The exact export preview rows (FIX 6869, G4 PR3): a live Owner, or a
        // bound principal whose one Grant the engine door admits.
        Proof::CodeExportPreview => {
            crate::api::facade::origin_doors::preview_admits(server, auth, verb)
        }
        Proof::CheckoutHolder => {
            crate::api::facade::origin_doors::checkout_holder_admits(server, auth)
        }
        // The working view edit door (row 6 WORKING-VIEW-EDIT): a live
        // Owner, or a bound caller whose view-bound Grant the engine judges.
        Proof::ViewEditor => {
            crate::api::facade::code_view_doors::view_editor_admits(server, auth, verb)
        }
        // The vault's review policy rows (FIX 8268): a live Owner, or a bound
        // principal whose one Grant the engine door admits.
        Proof::ReviewPolicy => {
            crate::api::facade::merge_queue_checker_doors::review_policy_admits(server, auth, verb)
        }
        // A member's own TASK-bound workflow run (FIX 5316): a live person on
        // their own slip, bound to it, as the door acts under.
        Proof::WorkflowMember => {
            crate::api::facade::agent_definition_doors::member_proof(server, auth, verb).map(drop)
        }
        // The off-record session rows admit their session's manager: the
        // owner, or a person or agent who starts and keeps their own
        // (WILL-PLAN L13 row 03). Each door binds the stretch for them again.
        Proof::OffRecord => {
            crate::api::facade::off_record_doors::off_record_admits(server, auth, verb)
        }
        Proof::OffRecordRoom => {
            crate::api::facade::off_record_room_doors::off_record_room_admits(auth, verb)
        }
        Proof::GuestDocumentReader => {
            crate::api::facade::guest_document_doors::guest_document_reader(server, auth).map(drop)
        }
        Proof::ForeignCode => {
            crate::api::facade::foreign_code_doors::foreign_code_admits(server, auth)
        }
        Proof::SavedQuery => crate::api::facade::saved_query_doors::admits(server, auth),
        // The access request answer (FIX 1379): the owner, or the person or
        // agent a request asks, on their own proof.
        Proof::GrantsAnswer => crate::api::facade::grants_doors::answer_admits(server, auth, verb),
        Proof::CredentialHolder => crate::api::facade::credential_doors::holder(auth).map(drop),
        Proof::SlideReviewer => slide_reviewer(server, auth).map(drop),
        Proof::ArtifactAsker => artifact_asker(server, auth).map(drop),
        // An image edit (L4-15): the owner, or a person or agent on its own slip, whose lane the
        // engine reads the artifact through.
        Proof::ImageEditor => {
            crate::api::facade::image_edit_doors::image_editor(server, auth).map(drop)
        }
        Proof::DiaryReader => diary_reader(server, auth, verb).map(drop),
        Proof::DecisionHolder => {
            crate::api::facade::decision_ask_doors::holder(auth, verb).map(drop)
        }
        Proof::HydeCaller => crate::api::facade::hyde_doors::hyde_caller(server, auth).map(drop),
        Proof::FacadeActor => crate::api::facade::facade_actor(server, auth)
            .map(drop)
            .map_err(crate::api::facade::FacadeApiError::into_memory_error),
        Proof::VerdictAsker => asking(auth, server).map(drop),
        // The pack setup doors (OF-378) and the pack put: the owner's proof,
        // or an agent acting for the owner (an agent puts `local` alone).
        Proof::PacksSetup => super::packs::setup_admits(server, auth, verb),
        Proof::MediaOwnerGrade => owner_grade(auth, MEDIA_OWNERS),
        Proof::VideoJobOwnerGrade => owner_grade(auth, VIDEO_JOB_OWNERS),
        // A person's own trusted-contact acts (FIX 8169): the live person whose own slip the engine door
        // revalidates.
        Proof::TrustedContactPerson => {
            crate::api::facade::trusted_contact_doors::own_person(server, auth, verb).map(drop)
        }
        // The responsible role's own tradeoff asks (FIX 8178): the person or agent the credential binds, as
        // REST admits them.
        Proof::TradeoffPicker => {
            crate::api::facade::goal_optimize_doors::picker(server, auth, verb).map(drop)
        }
        // A fork as the caller itself (FIX 8167): a person or agent on its own slip, whose write Grant the
        // fork's writer checks.
        Proof::SkillForker => crate::api::facade::skill_doors::forker(server, auth, verb).map(drop),
        // A skill library read as the caller itself (slice 6.4d): the owner under its proof, or a person or
        // agent on its own slip, whose read the engine reader checks row by row.
        Proof::SkillReader => {
            crate::api::facade::skill_doors::skill_reader(server, auth, verb).map(drop)
        }
        // A committed-run read as the run's own actor (slice 6.4c): the owner under its proof, or a
        // person or agent on its own slip, whose run the engine reader checks.
        Proof::RunReader => {
            crate::api::facade::run_read_doors::run_reader(server, auth, verb).map(drop)
        }
        // A policy put by a person holding the policy power (FIX 8177), which the manifest writer checks.
        Proof::PolicyPutter => {
            crate::api::facade::gate_policy_doors::policy_putter(server, auth, verb).map(drop)
        }
        // A publish or repoint as the caller on its own slip (FIX 8161), which the outbound Gate judges.
        Proof::ArtifactPublisher => {
            crate::api::facade::artifact_hosting_doors::publisher(server, auth, verb).map(drop)
        }
        // The usage repair rows (FIX 7039): the owner's own proof or an agent's own Grant naming the verb,
        // as their writer admits it.
        Proof::UsageRepairList => crate::api::facade::usage_repair_doors::repair_admits(
            server,
            auth,
            oneiron::memory::usage_repair::UsageRepairVerb::List,
        ),
        Proof::UsageRepairRemove => crate::api::facade::usage_repair_doors::repair_admits(
            server,
            auth,
            oneiron::memory::usage_repair::UsageRepairVerb::Remove,
        ),
        Proof::UsageRepairReceipts => crate::api::facade::usage_repair_doors::repair_admits(
            server,
            auth,
            oneiron::memory::usage_repair::UsageRepairVerb::Receipts,
        ),
        // A requested eval-authoring pass (LEARNING-06): the owner's own proof or an agent's own Grant
        // naming the verb, as the writer that admits the Coach attempt checks it.
        Proof::EvalAuthoring => crate::api::facade::eval_doors::execute_admits(server, auth),
    }
}
