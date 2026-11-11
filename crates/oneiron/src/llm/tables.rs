//! The side tables `llm` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Native host allocation selection, balances and original holds. Key: ().
    BUDGET_HOST_ACCOUNT: VaultMeta b"budget.host.account.v1\0" Named Engine
        [restore: live] [family: not_imaged] [tier: canonical]
        => crate::llm::run_admission::allocation::erase_actor_in_txn;
    /// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
    BUDGET_RSI_LINE: VaultMeta b"budget.rsi.line.v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// A case where a person changed the decision ladder's answer, kept until the Coach's
    /// person-threshold run reads it. Key: id16 of the source the host bound the answer to.
    COACH_PERSON_CHANGED: VaultMeta b"coach:person_changed:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::dreamer_runner::maintenance::coach::erase_person_changed_principal_in_txn;
    /// One typed-decision ask the ladder queued for the vault owner role, and its answer once
    /// given. Key: u64be(sequence).
    DECISION_ASK: VaultMeta b"decision:ask:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::llm::decision::erase_ask_actor_in_txn;
    /// Private binding proving an SDK-facing detached step (no engine-owned run) belongs to its
    /// actor/subject/step hash. Key: id16(attempt).
    DREAMER_DETACHED_STEP: VaultMeta b"dreamer.detached_step.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::llm::erase_detached_step_actor_in_txn;
    /// Private step-only wait binding for one (task, trap) pair. Key: id16(task ref) + id16(trap
    /// ref).
    DREAMER_PEER_WAIT: VaultMeta b"dreamer:peer_wait:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Reverse pointer from a peer-wait trap anchor claim to its bound task ref. Key: id16(trap
    /// anchor claim).
    DREAMER_PEER_WAIT_TRAP: VaultMeta b"dreamer:peer_wait_trap:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Dreamer step index rows, plus the 'i:' sub-index. Key: bytes.
    DREAMER_STEP_INDEX: VaultMeta b"dreamer:step_index:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The exact response versions a terminal step claim holds (FIX 6225). Key: id16(claim).
    DREAMER_STEP_RESPONSE_PIN: VaultMeta b"dreamer:step_response_pin:v1:" Named Engine
        [restore: content] [family: structure] [tier: canonical];
    /// Private binding of a Budget/Consent trap anchor claim to its owning step. Key: id16(anchor
    /// claim).
    DREAMER_TRAP_BINDING: VaultMeta b"dreamer:trap_binding:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Device-local presence index of trap anchors whose head is Sent. Key: id16(anchor claim).
    DREAMER_TRAP_SENT: VaultMeta b"dreamer:trap_sent:v1:" Named Engine
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The vault's pinned model-role manifest (role bindings, tier/route defaults). Key: ().
    /// Owner-reviewed role binding offers with their retained trial evidence. Key: id16.
    LLM_BINDING_PROPOSAL: VaultMeta b"llm:binding_proposal:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The current immutable catalog revision. Key: ().
    LLM_CATALOG_HEAD: VaultMeta b"llm:catalog_head:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Pinned catalog prices, scores and refresh diffs. Key: revision string.
    LLM_CATALOG_REVISION: VaultMeta b"llm:catalog_revision:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::llm::catalog_doors::erase_catalog_source_rows_in_txn;
    /// Measured description scores keyed inside one singleton map. Key: ().
    LLM_DESCRIPTION_MEASUREMENTS: VaultMeta b"llm:description_measurements:v1" LegacyJson Authored [accepts: crate::store::model_description_rows::llm_description_measurements_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Vault-owned description policy. Key: ().
    LLM_DESCRIPTION_POLICY: VaultMeta b"llm:description_policy:v1" LegacyJson Authored [accepts: crate::store::model_description_rows::llm_description_policy_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable re-ask keyed by 64-character hex identity.
    LLM_DESCRIPTION_REASK: VaultMeta b"llm:description_reask:v1:" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Training provenance and checkpoint pin for the installed distilled encoder. Key: ().
    LLM_ENCODER_EXPORT: VaultMeta b"llm:encoder_export:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The passing extraction-teacher probe approval behind the pinned teacher. Key: ().
    LLM_EXTRACTION_TEACHER_PROBE: VaultMeta b"llm:extraction_teacher_probe:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    LLM_MANIFEST: VaultMeta b"llm:manifest:v2" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Revision-pinned description of one registered model, read by seat routing. Key:
    /// string(model id).
    LLM_MODEL_DESCRIPTION: VaultMeta b"llm:model_description:v1:" LegacyJson Authored [accepts: crate::store::seat_model_description::llm_model_description_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// The model pack the vault followed at its last pack change and the one it followed
    /// before, each as its install receipt named it: what a way back returns to (FIX 5367,
    /// FIX 5369). Key: ().
    LLM_MODEL_PACK_ACTIVE: VaultMeta b"llm:model_pack_active:v1" Named
        // Restore class: FIX 5367: the followed-pack record travels with the install receipts it
        // names; the owner's follow-or-pin preference stands as the live vault holds it.
        [restore: content] [family: unclassified] [tier: canonical];
    /// The owner's model pack preference: follow the latest pack, pin a season or pin one pack
    /// (FIX 5367, FIX 5369). Key: ().
    LLM_MODEL_PACK_PREFERENCE: VaultMeta b"llm:model_pack_preference:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Each model pack retirement notice sent to the vault's owners, and when, so a restart or a
    /// second pass sends none twice (FIX 5368). Key: u64be(retirement epoch day) + u64be(mark,
    /// days before it) + string(`pack:<pack id>` or `model:<model id>`).
    LLM_MODEL_PACK_RETIREMENT_NOTICE: VaultMeta b"llm:model_pack_retirement_notice:v1:" Named Engine
        // Restore class: FIX 5368: a retirement notice the owners were sent stays sent; a restore
        // never sends it again.
        [restore: live] [family: unclassified] [tier: canonical];
    /// Held-out model trial, billed evidence and switch offer. Key: question id16 + trial id16.
    LLM_MODEL_TRIAL: VaultMeta b"llm:model_trial:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The loaded native Oneironer bundle's receipt at its bind: stack and
    /// checkpoint, label count and per-artifact hashes. Key: string (slot).
    LLM_ONEIRONER_BUNDLE_RECEIPT: VaultMeta b"llm:oneironer_bundle_receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A non-holder's inert inference-defaults replacement (FIX 8211). Key: id16(proposal).
    LLM_PURPOSE_DEFAULT_PROPOSAL: VaultMeta b"llm:purpose_default_proposal:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Vault-local per-purpose and voice-lane inference defaults table. Key: ().
    LLM_PURPOSE_DEFAULTS: VaultMeta b"llm:purpose_defaults:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Priced model-catalog row: wire format, cost, and cached benchmark scores. Key: string(model
    /// id).
    LLM_REGISTRY_ROW: VaultMeta b"llm:registry:v1:" LegacyJson Authored
        [accepts: crate::llm::registry::llm_registry_row_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::llm::registry::erase_registry_source_in_txn;
    /// FIX 4546: when the owner marked a model's registry row stale, kept through re-puts and
    /// pack refreshes until the owner clears it. Key: string(model id).
    LLM_REGISTRY_STALE_MARK: VaultMeta b"llm:registry_stale:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Per-vault narrow-only resident route overrides: those the new manifest
    /// still admits stay, the others clear in the manifest txn. Key: ().
    LLM_RESIDENT_ROUTES: VaultMeta b"llm:resident_routes:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// One routed seat selected and pinned by caller-chosen bounded seat id.
    LLM_ROUTED_SEAT: VaultMeta b"llm:routed_seat:v1:" LegacyJson Authored [accepts: crate::llm::llm_routed_seat_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// A run's immutable model-seat pin and choice receipt, committed before its first provider
    /// call. Key: id16 (run).
    LLM_RUN_SEAT: VaultMeta b"llm:run_seat:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Rolling window (max 64) of recent benchmark score-change diffs for one model. Key:
    /// string(model id) "\x00".
    LLM_SCORE_DIFFS: VaultMeta b"llm:scores:v1:" LegacyJson Authored [accepts: crate::store::model_score_diff::llm_score_diffs_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// The catalog revision pinned when a held-out trial was nominated. Key: id16.
    LLM_TRIAL_CATALOG: VaultMeta b"llm:trial_catalog:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-submitted shared model streams: the frozen request and its one durable terminal.
    /// Key: id16(stream).
    MODEL_STREAM: VaultMeta b"model_stream:terminal:v1:" Named Authored [accepts: crate::store::model_stream_row::model_stream_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Installed knowledge-pack receipt, keyed by pack name. Key: string.
    SKILL_HUB_PACK_INSTALL: VaultMeta b"pack.install.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-trap ask-void proof committed before a peer-result signal: u64 BE generation. Key: id16.
    TASK_ASK_PEER_VOID_TRAP: VaultMeta b"tasks.ask.peer_void_trap.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A standing artifact question's last ask of one artifact: the head versions it read and
    /// the proposal its answers wait under. Key: id16(question) + id16(artifact).
    TYPED_QUESTION_ARTIFACT_ASKED: VaultMeta b"typed_question:artifact_asked:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A question's asks in commit order (FIX 2337): each graph answer by its claim, and
    /// each artifact ask with the pins it read and its proposal, a failed one too. Its
    /// high-water mark is a `TYPED_QUESTION` row. Key: id16(question) + u64be(sequence).
    TYPED_QUESTION_ASK_HISTORY: VaultMeta b"typed_question:ask_history:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::llm::decision::questions::erase_ask_history_actor_in_txn;
    /// Typed question versions, heads, answers and labels. Key: id16(question) ":version:" u32be.
    /// Pending refresh for a question/unit pair. Key: id16(question) + id16(unit).
    TYPED_QUESTION_PENDING: VaultMeta b"typed_question:pending:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The sources a unit's latest standing answer rests on, so the next answer replaces their
    /// watchers. Key: id16(question) + id16(unit).
    TYPED_QUESTION_ROOT_SOURCES: VaultMeta b"typed_question:root_sources:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 11231: one graph unit's person ask, kept while it waits and once its holder's
    /// answer landed on the unit: the question, principal and unit it decides, the declined
    /// decision it went up from, and the answer claim that landed. Key: u64be(ask sequence).
    TYPED_QUESTION_UNIT_ASK: VaultMeta b"typed_question:unit_ask:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    TYPED_QUESTION: VaultMeta b"typed_question:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::llm::decision::questions::erase_questions_for_actor_in_txn;
    /// Reverse watch index from an outcome predicate to the questions learning from it. Key:
    /// string(predicate) "\x00" id16(question).
    TYPED_QUESTION_WATCH: VaultMeta b"typed_question:watch:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
