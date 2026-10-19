// Declared `vault_meta` tables whose prefix starts with `d` or `e`, in prefix order.

side_tables! {
    VAULT_META_D_E;
    /// One typed-decision ask the ladder queued for the vault owner role, and its answer once
    /// given. Key: u64be(sequence).
    DECISION_ASK: VaultMeta b"decision:ask:v1:" Named
        => crate::llm::decision::erase_ask_actor_in_txn;
    /// One revision of a host rule row: the owner's reason on an answered decision ask, the
    /// answer it gives that question about that evidence, and whether it was revoked. Key:
    /// id16 (rule) + u64be(revision).
    DECISION_HOST_RULE: VaultMeta b"decision:host_rule:v1:" Named
        => crate::llm::decision::erase_rule_actor_in_txn;
    /// The creation record of one deck made from a kept outline: born-from, template, slides,
    /// write set and fit. Key: id16 (artifact).
    DECK_CREATION: VaultMeta b"deck:creation:v1:" Named;
    /// The design directions compiled from one kept outline. Key: id16 (outline note).
    DECK_DESIGN_SPEC: VaultMeta b"deck:design_spec:v1:" Named;
    /// A person's keep of one outline brief: frontier, exact bytes and hash. Key: id16 (note).
    DECK_OUTLINE_KEEP: VaultMeta b"deck:outline_keep:v1:" Named;
    /// Marker that the one-time row-deletion-fence backfill from applied soft-delete markers has
    /// run. Key: ().
    DELETION_ROW_FENCE_BACKFILLED: VaultMeta b"deletion.row_fence.v1.backfilled" Raw;
    /// Immutable account/organization owner binding used to scope hosted derivation caches for this
    /// vault. Key: ().
    DERIVATION_OWNER: VaultMeta b"derivation:owner:v1" Raw;
    /// OF-490: one read of an agent's diary: reader, stated reason, entries and Grants (the agent
    /// sees it). Key: id16 (agent) + id16 (read).
    DIARY_READ_LOG: VaultMeta b"diary:read_log:v1:" Named;
    /// OF-490: a reader's reason waiting on, or answered by, the agent's Y/N review. Key: id16
    /// (agent) + id16 (request).
    DIARY_READ_REQUEST: VaultMeta b"diary:read_request:v1:" Named;
    /// OF-490: an agent reviews each read of its diary before it is read (on for Eiri; absent
    /// means off). Value: one byte, 1 on, 0 off. Key: id16 (agent).
    DIARY_READ_REVIEW: VaultMeta b"diary:read_review:v1:" Raw;
    /// Owner's model-channel band ceiling, optionally specialized by data class.
    /// Key: connection "/" class (or "*").
    DISCLOSURE_MODEL_CEILING: VaultMeta b"disclosure.model_ceiling.v1:" Named;
    /// Enforcement-truth per-counterparty-contact disclosure scope row (rmpv-encoded), dual-written
    /// with an owner-visible claim. Key: id16.
    DISCLOSURE_SCOPE: VaultMeta b"disclosure.scope.v1:" Raw;
    /// Owner Tier-A mark row for an entity (value = marked_at u64 LE), dual-written with an owner-
    /// visible claim. Key: id16.
    DISCLOSURE_TIER_A: VaultMeta b"disclosure.tier_a.v1:" Raw;
    /// Passive outbound dispatch audit observation for one attempt/try. Key: id16 + u32be.
    DISPATCH_OBSERVATION: VaultMeta b"dispatch_observation:v1/" Raw Authored;
    /// Classifier-derived annotation (derivation envelope + annotation body) for one imported docs
    /// page/asset. Key: hex32 ":" hex32.
    INGEST_DOCS_ANNOTATION: VaultMeta b"docs-annotation:v1:" LegacyJson Admitted;
    /// Approved docs source ceiling (source hash, owner, approval), keyed by the asset's hex32 id.
    INGEST_DOCS_DEEP_CEILING: VaultMeta b"docs-deep-ceiling:v1:" LegacyJson;
    /// Last deep-ingest receipt for one docs asset, keyed by its hex32 id.
    INGEST_DOCS_DEEP_RECEIPT: VaultMeta b"docs-deep-receipt:v1:" LegacyJson;
    /// Stable-ref index from a deterministic docs-extraction id (corpus/page/segment) to the minted
    /// entity id. Key: string.
    INGEST_DOCS_EXTRACTION: VaultMeta b"docs-extraction:v1:" Raw;
    /// Set of chunk/summary member content-refs recorded for one imported docs asset. Key: hex32.
    INGEST_DOCS_MEMBERSHIP: VaultMeta b"docs-membership:v1:" LegacyJson;
    /// Private binding proving an SDK-facing detached step (no engine-owned run) belongs to its
    /// actor/subject/step hash. Key: id16(attempt).
    DREAMER_DETACHED_STEP: VaultMeta b"dreamer.detached_step.v1/" Raw;
    /// Marker that the one-time durable-milestone-index backfill pass has run. Key: ().
    DREAMER_MILESTONE_INDEX_BACKFILLED: VaultMeta b"dreamer.milestone_index.v1.backfilled" Raw;
    /// Durable milestone-index candidate row (empty-value marker) for an attempt, ordered by (at,
    /// learned_at, claim_id); only indexed once the milestone claim is bound to its attempt. Key:
    /// id16 + u64be + u64be + id16.
    DREAMER_MILESTONE_INDEX_CANDIDATE: VaultMeta b"dreamer.milestone_index.v1.c:" Raw;
    /// Pointer from a milestone claim id back to its DREAMER_MILESTONE_INDEX_CANDIDATE row key. Key:
    /// id16.
    DREAMER_MILESTONE_INDEX_CLAIM: VaultMeta b"dreamer.milestone_index.v1.i:" Raw;
    /// Pointer to the single vault-owned Dreamer principal actor entity id. Key: ().
    DREAMER_AUTHORITY_ACTOR: VaultMeta b"dreamer:authority:v1:actor" Raw;
    /// Stamp binding one attempt id to the Dreamer principal, facet, and gate-decision receipt that
    /// admitted it. Key: id16.
    DREAMER_AUTHORITY_ATTEMPT: VaultMeta b"dreamer:authority:v1:attempt:" LegacyJson;
    /// Named token-budget counter row (total/remaining/reserved units) keyed by budget id. Key:
    /// string.
    DREAMER_BUDGET: VaultMeta b"dreamer:budget:" Raw;
    /// Reservation of budget units against one child attempt, keyed by (budget id, attempt id). Key:
    /// u16be + string + id16.
    DREAMER_BUDGET_RESERVATION: VaultMeta b"dreamer:budget_reservation:" Raw;
    /// Paid-step receipt keyed by attempt id16 + step hash32. Value: one-byte marker.
    DREAMER_BUDGET_STEP_CHARGE: VaultMeta b"dreamer:budget_step_charge:" Raw;
    /// Operator-set predicate key rules governing which claim keys the consolidator may fold;
    /// defaults from key_defaults.json when absent. Key: ().
    /// Resident-owned v1 failure rules, stored as the validated JSON payload with its author.
    /// Key: ().
    DREAMER_FAILURE_RULES: VaultMeta b"dreamer:consolidation:failure_rules:v1" Raw;
    DREAMER_CONSOLIDATION_KEY_RULES: VaultMeta b"dreamer:consolidation:keys:v1" LegacyJson;
    /// Owner-root reference pins and immutable child evidence accounting. Key: id16(root).
    DREAMER_CONSOLIDATION_ROOT: VaultMeta b"dreamer:consolidation:root:v1:" Named
        => crate::dreamer_consolidation::root_evidence::erase_actor_in_txn;
    /// Operator-set consolidation candidate-selection config (strength weights, caps). Key: ().
    DREAMER_CONSOLIDATION_SELECTION: VaultMeta b"dreamer:consolidation:selection:v1" LegacyJson;
    /// Parent-verified promotion evidence observations. Key: id16(claim).
    DREAMER_CONSOLIDATION_STRENGTH: VaultMeta b"dreamer:consolidation:strength:v1:" Named;
    /// Pre-archive claim revision and strength policy. Key: id16(claim) + u64be(at_ms).
    DREAMER_CONSOLIDATION_STRENGTH_ARCHIVE: VaultMeta b"dreamer:consolidation:strength_archive:v1:" Named;
    /// Operator-set archive-only strength lifecycle. Key: ().
    DREAMER_CONSOLIDATION_STRENGTH_POLICY: VaultMeta b"dreamer:consolidation:strength_policy:v1" Named;
    /// Private run-tree-scoped critique artifact for one branch attempt, keyed by attempt id and
    /// artifact id; written independently by both the generic critic reviewer and the Dreamer
    /// tournament with the identical prefix and key layout (see WHERE) - worth a second look for
    /// accidental collision if the same (attempt, artifact_id) pair is ever used from both callers.
    /// Key: id16 + u16be + string.
    CRITIC_ARTIFACT: VaultMeta b"dreamer:critic:v1:" Named Authored;
    /// Per-scope, per-partition consolidation cursor row. Key: u8 + hash32.
    DREAMER_CURSOR: VaultMeta b"dreamer:cursor:v1:" Raw;
    /// Branch-scoped reflection-gap queue namespaced by partition hash and the branch's
    /// relationship/project scope axes. Key: hex64 ":" hex32-or-"none" ":" hex32-or-"none" ":"
    /// hash32.
    DREAMER_GAP_BRANCH: VaultMeta b"dreamer:gap-branch:v1:" Raw;
    /// Global reflection-gap queue row keyed by a hash of (kind, subject). Key: hash32.
    DREAMER_GAP: VaultMeta b"dreamer:gap:v1:" Raw;
    /// Prior tuning-harness evaluation baseline for a config artifact, used to reject
    /// stale/regressive re-evaluation. Key: id16.
    DREAMER_HARNESS_EVAL_BASELINE: VaultMeta b"dreamer:harness:eval-baseline:v1:" LegacyJson;
    /// The host's last MACRO home-node candidate set, as it supplied it, which an owner's home
    /// pick re-elects over (DOOR-101 PR2a). Node-local; a restore never takes it from an image.
    /// Key: ().
    DREAMER_HOME_CANDIDATES: VaultMeta b"dreamer:home_candidates:v1" Named;
    /// Elected MACRO-scope home-node designation (node_id, class, elected_at). Key: ().
    DREAMER_HOME_NODE: VaultMeta b"dreamer:home_node_macro:v1" Raw;
    /// One open identity ask: a saved mention the Dreamer could not settle, or one an agent must
    /// act on now (OF-123). Key: hash32(turn, message, span).
    DREAMER_IDENTITY_ASK: VaultMeta b"dreamer:identity:v1:ask:" Named;
    /// The identity re-check's page cursor: the last TURN a nightly pass read. Key: ().
    DREAMER_IDENTITY_CURSOR: VaultMeta b"dreamer:identity:v1:cursor" Named;
    /// A settled identity's context hint: a name, the words around it and the entity it named.
    /// Key: u8(kind) + hash32(name) + id16(entity).
    DREAMER_IDENTITY_HINT: VaultMeta b"dreamer:identity:v1:hint:" Named;
    /// The original mention and its resolving evidence, written with the link.
    /// Key: id16(turn) + hash32(message, span).
    DREAMER_IDENTITY_RESOLUTION: VaultMeta b"dreamer:identity:v1:resolution:" Named;
    /// OF-023: one Dreamer maintenance write applied at once: its kind, attempt, the finding's
    /// revision, the before-state its effect changed, its receipt and, once the owner reverts
    /// it, the revert. Key: id16 (finding).
    DREAMER_MAINTENANCE_APPLIED: VaultMeta b"dreamer:maintenance:applied:v1:" Named;
    /// The entity and claim ids one Dreamer attempt's extraction listed for its model, so a replay
    /// lists the same ones. Ids only, never their text. Key: id16.
    DREAMER_NEIGHBOURHOOD: VaultMeta b"dreamer:neighbourhood:v1:" LegacyJson;
    /// Atomic merge/narrative outputs for one nightly fan-in receipt. Key: id16.
    DREAMER_NIGHTLY_MERGED: VaultMeta b"dreamer:nightly:merged:v1:" Named;
    /// Promoted/attached proposal ids returned by one nightly child. Key: id16.
    DREAMER_NIGHTLY_OUTPUT: VaultMeta b"dreamer:nightly:output:v1:" Named;
    /// The NOTE review's page cursor: the last NOTE id a review finished. Key: ().
    DREAMER_NOTE_REVIEW_CURSOR: VaultMeta b"dreamer:note-review:cursor:v1" Named;
    /// What a NOTE review last read and decided for one NOTE: the BLAKE3 of the markdown, so an
    /// unchanged NOTE is not read again, its verdict and importance, and a sealed pad's missed
    /// keep lines with the re-asks spent on them (FIX 2240). Key: id16.
    DREAMER_NOTE_REVIEW_SEEN: VaultMeta b"dreamer:note-review:seen:v1:" Named;
    /// Parked (paused) attempt row (reason, park_owner, parked_at) keyed by attempt id. Key: id16.
    DREAMER_PARKED: VaultMeta b"dreamer:parked:" Raw Authored;
    /// Private step-only wait binding for one (task, trap) pair. Key: id16(task ref) + id16(trap
    /// ref).
    DREAMER_PEER_WAIT: VaultMeta b"dreamer:peer_wait:v1:" Raw;
    /// Reverse pointer from a peer-wait trap anchor claim to its bound task ref. Key: id16(trap
    /// anchor claim).
    DREAMER_PEER_WAIT_TRAP: VaultMeta b"dreamer:peer_wait_trap:v1:" Raw;
    /// Dreamer prefilter screening policy. Key: ().
    PREFILTER_CONFIG: VaultMeta b"dreamer:prefilter:config:v1" Named;
    /// Turn to screening round index. Key: string ":" id16.
    PREFILTER_MEMBER: VaultMeta b"dreamer:prefilter:member:v1:" Raw;
    /// Prefilter round rollup. Key: bytes32.
    PREFILTER_ROUND: VaultMeta b"dreamer:prefilter:round:v1:" Named;
    /// Prefilter skip receipt. Key: bytes32 + id16.
    PREFILTER_SKIP: VaultMeta b"dreamer:prefilter:skip:v1:" Named;
    /// One emitted proactivity digest, keyed by its content-derived id. Key: hash32.
    DREAMER_PROACTIVITY_DIGEST: VaultMeta b"dreamer:proactivity:digest:v1:" LegacyJson Authored;
    /// Time (u64 BE) of the last digest that delivered judge asks to one recipient. Key: id16.
    DREAMER_PROACTIVITY_JUDGE_ASKS: VaultMeta b"dreamer:proactivity:judge_asks:v1:" Raw;
    /// Rolling proactivity-digest emission state (last_emitted timestamp). Key: ().
    DREAMER_PROACTIVITY_STATE: VaultMeta b"dreamer:proactivity:state:v1" LegacyJson;
    /// The projector rounds one TURN gave words to, for erasure. Key: id16(turn).
    DREAMER_PROJECTION_GIVEN: VaultMeta b"dreamer:projection:given:v1:" Named;
    /// The latest TURN the projector queued, vault-wide, its round, and whether it holds. Key: ().
    DREAMER_PROJECTION_LATEST: VaultMeta b"dreamer:projection:latest:v1" Named;
    /// A TURN consumed as a repeat of the held TURN: the round it rode and the TURN it repeated.
    /// Key: u64be + id16.
    DREAMER_PROJECTION_RIDER: VaultMeta b"dreamer:projection:rider:v1:" Named;
    /// A rider by the TURN it repeated. Key: id16(repeated) + u64be + id16(rider).
    DREAMER_PROJECTION_RIDER_OF: VaultMeta b"dreamer:projection:rider_of:v1:" Raw;
    /// The temporal key one riding TURN rides under. Key: id16(turn).
    DREAMER_PROJECTION_RIDES: VaultMeta b"dreamer:projection:rides:v1:" Named;
    /// One projector round: its turns and riders, and whether it applied. Key: hash32(round).
    DREAMER_PROJECTION_ROUND: VaultMeta b"dreamer:projection:round:v1:" Named;
    /// The refusal dial an agent last woke under (OF-533), so its next wake notes a change in its
    /// own diary. Key: id16(agent).
    DREAMER_REFUSAL_DIAL_SEEN: VaultMeta b"dreamer:refusal-dial:seen:v1:" Named;
    /// Owner approval/decline record for a representation proposal review. Key: id16.
    DREAMER_REPRESENTATION_APPROVAL: VaultMeta b"dreamer:representation:v1:approval:" LegacyJson
        => crate::dreamer_runner::maintenance::representation::erase_approval_actor_in_txn;
    /// Evidence-citing user-voice representation proposal record, keyed by proposal claim id. Key:
    /// id16.
    DREAMER_REPRESENTATION_PROPOSAL: VaultMeta b"dreamer:representation:v1:proposal:" LegacyJson;
    /// OF-490: the resident one dreaming attempt runs as, its own stamp, and the Gate receipt that
    /// admitted it. Key: id16 (attempt).
    DREAMER_RESIDENT_ATTEMPT: VaultMeta b"dreamer:resident:attempt:v1:" Named;
    /// OF-490: the diary entry one resident dreaming attempt landed, so a replay writes none.
    /// Key: id16 (attempt).
    DREAMER_RESIDENT_LANDED: VaultMeta b"dreamer:resident:landed:v1:" Named;
    /// OF-490: a sealed scratchpad a resident's dreaming already read. Value: one byte. Key:
    /// id16 (resident) + id16 (pad).
    DREAMER_RESIDENT_PADS: VaultMeta b"dreamer:resident:pads:v1:" Raw;
    /// OF-490: what a resident's dreaming has read so far: newest receipt and INBOX times, last
    /// dreaming, entries written. Key: id16 (resident).
    DREAMER_RESIDENT_PROGRESS: VaultMeta b"dreamer:resident:progress:v1:" Named;
    /// Parent/child attempt-tree edge row (parent_attempt, created_at) keyed by attempt id. Key:
    /// id16.
    DREAMER_RUN_TREE: VaultMeta b"dreamer:run_tree:" Raw;
    /// Pinned effective scope attenuation bound to one Dreamer attempt, inherited by retry
    /// successors. Key: id16.
    DREAMER_SELECTION_SCOPE: VaultMeta b"dreamer:selection_scope:v1:" LegacyJson;
    /// Sample audit grade per durable rung attempt. Key: id16.
    DREAMER_SIEVE_AUDIT: VaultMeta b"dreamer:sieve:audit:v1:" Named;
    /// One span the nightly spending consumed, by the attempt that spent it.
    /// Key: id16(attempt) + hash32(span).
    DREAMER_SIEVE_CONSUMED: VaultMeta b"dreamer:sieve:consumed:v1:" Named;
    /// A TURN whose sieve read the pass's text bound stopped, with the chunks it reads on in.
    /// Key: id16(turn).
    DREAMER_SIEVE_CONTINUE: VaultMeta b"dreamer:sieve:continue:v1:" Named;
    /// Where the continuous sieve stands on the TURN timeline. Key: ().
    DREAMER_SIEVE_CURSOR: VaultMeta b"dreamer:sieve:cursor:v1" Named;
    /// Retained original cheap span readings, for sampled expensive-path audits. Key: turn id16 + span hash32.
    DREAMER_SIEVE_HISTORY: VaultMeta b"dreamer:sieve:history:v1:" Named;
    /// A TURN owed a new sieve read (new, changed words or saved tags). Key: id16(turn).
    DREAMER_SIEVE_OWED: VaultMeta b"dreamer:sieve:owed:v1:" Raw;
    /// The sieve's interest queue, one span per row. Key: u32be(inverted score) + hash32(span).
    DREAMER_SIEVE_QUEUE: VaultMeta b"dreamer:sieve:queue:v1:" Named;
    /// The sieve's grant epoch and its sweep over the withheld turns. Key: ().
    DREAMER_SIEVE_RETRY: VaultMeta b"dreamer:sieve:retry:v1" Named;
    /// One queued span of a TURN. Key: id16(turn) + u32be(inverted score) + hash32(span).
    DREAMER_SIEVE_SPANS: VaultMeta b"dreamer:sieve:spans:v1:" Raw;
    /// What the sieve last read of one TURN. Key: id16(turn).
    DREAMER_SIEVE_TURN: VaultMeta b"dreamer:sieve:turn:v1:" Named;
    /// A TURN the sieve read with a MESSAGE the Dreamer may not read, and the grant epoch it was
    /// read at (u64be). Key: id16(turn).
    DREAMER_SIEVE_WITHHELD: VaultMeta b"dreamer:sieve:withheld:v1:" Raw;
    /// Dreamer step index rows, plus the 'i:' sub-index. Key: bytes.
    DREAMER_STEP_INDEX: VaultMeta b"dreamer:step_index:v1:" Raw;
    /// Device-local step progression state (Started/ResponseReceived/Logged); never synced. Key:
    /// id16(attempt) + hash32(step).
    DREAMER_STEP_STATE: VaultMeta b"dreamer:step_state:v1:" Raw Authored;
    /// When a host draft was scheduled for one stewardship reach-out. Key: id16(reach-out claim),
    /// value: u64be.
    DREAMER_STEWARDSHIP_DRAFTED: VaultMeta b"dreamer:stewardship:v1:drafted:" Raw;
    /// Per-round branch tournament evidence row (verdict, synthesis/critique/veto artifact ids) for
    /// one candidate. Key: u16be+string(run_id) + id16 + u16be + u8 + u16be+string(candidate_ref).
    DREAMER_TOURNAMENT_EVIDENCE: VaultMeta b"dreamer:tournament:v1:" Named;
    /// Private binding of a Budget/Consent trap anchor claim to its owning step. Key: id16(anchor
    /// claim).
    DREAMER_TRAP_BINDING: VaultMeta b"dreamer:trap_binding:v1:" Raw;
    /// Latest consolidation carrier of a TURN re-dirtied without moving its row: second, a
    /// store-minted order id, the row learned_at it was taken against and the scopes that consumed
    /// it. Key: id16(turn).
    DREAMER_TURN_REDIRTY: VaultMeta b"dreamer:turn-redirty:v1:" Named;
    /// DOOR-141: one turn program admission: the sealed wake, its Gate receipt, and the attempt it
    /// queued or why it was refused. Key: hash32(actor, registration, revision, turn).
    DREAMER_TURN_PROGRAM_ADMISSION: VaultMeta b"dreamer:turn_program:admission:v1:" Named;
    /// DOOR-141: one armed turn program: its actor, the conversation its turns wake it from, and its
    /// pinned callable SKILL entry with its revision. Key: id16(actor) + id16(registration).
    DREAMER_TURN_PROGRAM_ARM: VaultMeta b"dreamer:turn_program:arm:v1:" Named
        => crate::dreamer_runner::erase_turn_program_actor_in_txn;
    /// DOOR-141: the waking actor one turn program attempt runs as, never a base-agent stamp, and
    /// the admission that bound it. Key: id16(attempt).
    DREAMER_TURN_PROGRAM_ATTEMPT: VaultMeta b"dreamer:turn_program:attempt:v1:" Named;
    /// DOOR-141: a wake a landed turn owes an armed program, recorded in that turn's own commit and
    /// consumed by its admission. Key: id16(turn) + id16(registration).
    DREAMER_TURN_PROGRAM_WAKE: VaultMeta b"dreamer:turn_program:wake:v1:" Named;
    /// Coalesced recipe input for one wake recipe. Key: u8(recipe).
    DREAMER_WAKE_RECIPE_INPUT: VaultMeta b"dreamer:wake-policy:recipe-input:v1:" LegacyJson;
    /// Wake cursor and pending state. Key: ().
    DREAMER_WAKE_STATE: VaultMeta b"dreamer:wake-policy:state:v1" LegacyJson;
    /// Node-local wake-pass observation (DOOR-144): a pass's header, admitted generations, calls
    /// and Checkpoint cuts. Key: u8(row kind) + ids (`dreamer_wake::observation`).
    DREAMER_WAKE_OBSERVATION: VaultMeta b"dreamer:wake:observation:v1:" Named;
    /// Digest (32 bytes) of the last queued wake projector image. Key: ().
    DREAMER_WAKE_PROJECTION: VaultMeta b"dreamer:wake:projection:v1" Raw;
    /// Owner-authored wake recipe budgets and rung instructions. Key: ().
    DREAMER_WAKE_RECIPE_POLICY: VaultMeta b"dreamer:wake:recipe_policy:v1" LegacyJson;
    /// Per-scope (micro/meso/macro) consolidation watermark: last learned_at/turn_id progress. Key:
    /// u8.
    DREAMER_WATERMARK: VaultMeta b"dreamer:watermark:v1:" Raw;
    /// Committed weave-recipe result bound to its pin, evidence and claim. Key: id16(attempt).
    DREAMER_WEAVE_RECIPE_RESULT: VaultMeta b"dreamer:weave:result:v1:" LegacyJson;
    /// One compiled acting revision (a charter or brief revision compiled from one principal's
    /// approved preferences) and its answer. Key: string (revision id, 64 hex).
    EDIT_DISTANCE_ACTING_REVISION: VaultMeta b"edit_distance/acting_revision/v1\0" Named;
    /// Write-once Δ side-ledger row for one receipt: a captured edit-distance measurement (canonical
    /// JSON), or the literal marker "uncaptured" when capture was attempted and failed. Key: string.
    EDIT_DISTANCE_AMENDMENT_DELTA: VaultMeta b"edit_distance/amendment_delta/v1\0" Raw;
    /// Recorded routing/attribution evidence for one amendment receipt. Key: string.
    EDIT_DISTANCE_AMENDMENT_EVIDENCE: VaultMeta b"edit_distance/amendment_evidence/v1\0" Raw;
    /// Judge-routed classification of one amendment's edit distance/preference class. Key: string.
    EDIT_DISTANCE_AMENDMENT_JUDGMENT: VaultMeta b"edit_distance/amendment_judgment/v1\0" Raw;
    /// Live edit-cost head for a (predicate, subject, scope) tuple; the retraction ledger for re-
    /// judged receipts. Key: string "\x00" hex32 "\x00" string.
    EDIT_DISTANCE_EDIT_COST_TARGET: VaultMeta b"edit_distance/edit_cost_target/v1\0" Raw;
    /// Dial: agreeing-ruling count needed to auto-propose a standing escalation policy. Key: ().
    EDIT_DISTANCE_ESCALATION_STANDING_N: VaultMeta b"edit_distance/escalation/standing_n/dial/v1" Raw;
    /// Append-only ruled-escalation ledger row, scope-major (scope digest then UUIDv7 row id) so one
    /// scope's history is a contiguous range. Key: id16 + id16.
    EDIT_DISTANCE_ESCALATION: VaultMeta b"edit_distance/escalation/v1\0" Raw;
    /// Standing escalation policy for one (scope, trigger) pair, keyed by what the row governs. Key:
    /// id16 + u8.
    EDIT_DISTANCE_ESCALATION_POLICY: VaultMeta b"edit_distance/escalation_policy/v1\0" Raw;
    /// Publisher digest-interview session state, keyed by the digest artifact id. Key: id16.
    EDIT_DISTANCE_INTERVIEW_SESSION: VaultMeta b"edit_distance/interview_session/v1\0" Raw;
    /// Stored publisher issue-signature (category, artifact, version, model, counts, content hash).
    /// Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE: VaultMeta b"edit_distance/issue_signature/v1\0" Raw;
    /// Send-state token (pending/sent/etc) for a publisher issue signature. Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE_SEND: VaultMeta b"edit_distance/issue_signature_send/v1\0" Raw;
    /// Persisted amendment-judge audit report (total/passed/abstained), ordered oldest-first by (at,
    /// sequence). Key: u64be + u64be.
    EDIT_DISTANCE_JUDGE_AUDIT: VaultMeta b"edit_distance/judge_audit/v1\0" Raw;
    /// Monotonic counter behind EDIT_DISTANCE_JUDGE_AUDIT's sequence half. Key: ().
    EDIT_DISTANCE_JUDGE_AUDIT_SEQUENCE: VaultMeta b"edit_distance/judge_audit_sequence/v1" Raw;
    /// Mint-mark preventing a re-mint of the same substitution cluster, keyed by cluster handle. Key:
    /// hash32.
    EDIT_DISTANCE_MINER_MINT_MARK: VaultMeta b"edit_distance/miner_mint_mark/v1\0" Raw;
    /// Mined skill-edit proposal awaiting owner decision, keyed by proposal id. Key: id16.
    EDIT_DISTANCE_MINER_SKILL_EDIT: VaultMeta b"edit_distance/miner_skill_edit/v1\0" Raw;
    /// Global work-gate watermark for the substitution-miner pass. Key: ().
    EDIT_DISTANCE_MINER_WATERMARK: VaultMeta b"edit_distance/miner_watermark/v1" Raw;
    /// Minted phrasing/preference proposal born from a judged amendment. Key: string.
    EDIT_DISTANCE_PREFERENCE_PROPOSAL: VaultMeta b"edit_distance/preference_proposal/v1\0" Raw;
    /// Immutable owner-bound decision on an inbox/amendment intake item, keyed by receipt id. Key:
    /// string.
    EDIT_DISTANCE_PRINCIPAL_DECISION: VaultMeta b"edit_distance/principal_decision/v1\0" Raw;
    /// Finalized proposal-text artifact (span attributions, actor/class per span), write-once keyed
    /// by artifact ref. Key: id16.
    EDIT_DISTANCE_PROPOSAL_ARTIFACT: VaultMeta b"edit_distance/proposal_artifact/v1\0" Raw Authored;
    /// Rebuildable training-reservoir candidate index row, keyed by the proposal artifact's entity
    /// id. Key: id16.
    EDIT_DISTANCE_RESERVOIR_CANDIDATE: VaultMeta b"edit_distance/reservoir_candidate/v1\0" Raw;
    /// Training-reservoir export-receipt ledger row. Key: id16.
    EDIT_DISTANCE_RESERVOIR_EXPORT: VaultMeta b"edit_distance/reservoir_export/v1\0" Raw;
    /// Per-(task class, model version) routing score aggregate. Key: string "\x00" string.
    EDIT_DISTANCE_ROUTING_AGGREGATE: VaultMeta b"edit_distance/routing_aggregate/v1\0" Raw;
    /// Run-to-generation membership binding, keyed by receipt id. Key: string.
    EDIT_DISTANCE_ROUTING_MEMBER: VaultMeta b"edit_distance/routing_member/v1\0" Raw;
    /// Per-task-class rollout rung state. Key: string.
    EDIT_DISTANCE_ROUTING_RUNG: VaultMeta b"edit_distance/routing_rung/v1\0" Raw;
    /// Model-version stamp new routing folds are recorded against. Key: ().
    EDIT_DISTANCE_ROUTING_SERVING_MODEL: VaultMeta b"edit_distance/routing_serving_model/v1" Raw;
    /// An organ call held until one of the owner's nodes can run it (OF-575 MESH): the call's
    /// bytes, why it waits, and its tries. Key: id16 + hash32 (blake3 of the run ref).
    EDIT_SETTLE_ORGAN_WAIT: VaultMeta b"edit_settle:organ_wait:v1:" Named;
    /// A proposal retained beside its artifact until Keep or Discard: an edit proposal or a native
    /// organ output. Key: id16 + hash32 (blake3 of the proposal ref).
    EDIT_SETTLE_PENDING_PROPOSAL: VaultMeta b"edit_settle:pending:v1:" Named;
    /// Stranded edit proposal. Key: id16 + hash32.
    EDIT_SETTLE_STRANDED_PROPOSAL: VaultMeta b"edit_settle:stranded:v1:" Named;
    /// The once-only undo of one kept proposal: the version it restored. Key: id16 + hash32.
    EDIT_SETTLE_UNDO: VaultMeta b"edit_settle:undo:v1:" Named;
    /// The answers of one held answer proposal whose units changed under it (ARCH-0075 §4): each
    /// with the revision it was judged against, and its proposer's wake. Key: id16 + hash32.
    EDIT_SETTLE_UNIT_WITHDRAWAL: VaultMeta b"edit_settle:withdrawal:v1:" Named;
    /// The device family and runtime that computed the current embedding vector, outside the space
    /// identity (ARCH-0036). Key: id16.
    EMBEDDING_DEVICE: VaultMeta b"embedding/device/" Named;
    /// Where the current reconciled embedding vector was filled (on-device/owner-server/third-party).
    /// Key: id16.
    EMBEDDING_LOCALITY: VaultMeta b"embedding/locality/" Raw;
    /// A document a declared space's model refused by its content, with the BLAKE3 of the bytes
    /// it refused; the media backfill skips it until they change (OF-370). Key: space key16 +
    /// id16.
    EMBEDDING_MEDIA_REFUSED: VaultMeta b"embedding/media_refused/" Named;
    /// One media vector per declared space and entity: its input-kind byte, then the v1 vector
    /// row (OF-370). Key: space key16 + id16.
    EMBEDDING_MEDIA_VECTOR: VaultMeta b"embedding/media_vector/" Raw;
    /// A kind slot version move, open or concluded, with its last paired probe check (OF-370).
    /// Key: candidate space id string.
    EMBEDDING_MOVE: VaultMeta b"embedding/move/" Named;
    /// A retrieval probe a space version move runs on both spaces (OF-370). Key: probe id16.
    EMBEDDING_PROBE: VaultMeta b"embedding/probe/" Named;
    /// Media kind slot to declared space id (OF-370). Key: one input-kind byte.
    EMBEDDING_SLOT: VaultMeta b"embedding/slot/" Named;
    /// Declared embedding space: id, width, accepted inputs, query towers (OF-370). Key: string.
    EMBEDDING_SPACE: VaultMeta b"embedding/space/" Named;
    /// Pointer from an entity to its owning document, plus generation/pending-update counters. Key:
    /// hex32.
    ENTITY_DOC_HEAD: VaultMeta b"entity_doc:v1:head:" Named;
    /// Retained revision history document. Key: id16.
    ENTITY_REVISION_DOC: VaultMeta b"entity_revision:doc:" Raw;
    /// Pinned revision frontier. Key: id16 + rev16.
    ENTITY_REVISION_FRONTIER: VaultMeta b"entity_revision:frontier:" Raw;
    /// Revision hash to owning entity. Key: rev16.
    ENTITY_REVISION_IDENTITY: VaultMeta b"entity_revision:identity:" Raw;
    /// Staged text/vector index inputs. Key: id16.
    ENTITY_REVISION_PENDING_INDEX_INPUTS: VaultMeta b"entity_revision:index_inputs:" Named;
    /// Staged phonetic codes. Key: id16.
    ENTITY_REVISION_PENDING_PHONETIC: VaultMeta b"entity_revision:phonetic:" Named;
    /// Live vs indexed revision pointers. Key: id16.
    ENTITY_REVISION_STATE: VaultMeta b"entity_revision:state:" Named;
    /// A published revision whose vector an embedding-space swap dropped, to be embedded again at
    /// idle. Key: id16.
    ENTITY_REVISION_VECTOR_REFILL: VaultMeta b"entity_revision:vector_refill:" Raw;
    /// Esign machine actor id. Key: ().
    ESIGN_ARTIFACT_ACTOR: VaultMeta b"esign.artifact_actor.v1" Raw;
    /// Esign document audit event. Key: id16 + u64be.
    ESIGN_AUDIT: VaultMeta b"esign.audit.v1/" LegacyJson;
    /// Signing capability row. Key: bytes32.
    ESIGN_CAPABILITY_TOKEN: VaultMeta b"esign.capability.v1/" LegacyJson;
    /// Esign outbound dispatch marker. Key: bytes32.
    ESIGN_DISPATCH_MARKER: VaultMeta b"esign.dispatch.v1/" Raw;
    /// Held automated sign act, one per recipient. Key: hex32/string.
    ESIGN_HELD_SIGNING: VaultMeta b"esign.held_signing.v1/" Named;
    /// Signature image byte budget. Key: id16.
    ESIGN_IMAGE_BYTES_BUDGET: VaultMeta b"esign.image_bytes.v1/" Raw;
    /// Signing principal set owner stamp. Key: ().
    ESIGN_PRINCIPAL_OWNER_STAMP: VaultMeta b"esign.principal.owner_stamp.v1" Raw;
    /// Signing principal. Key: hex32.
    ESIGN_PRINCIPAL: VaultMeta b"esign.principal.v1/" LegacyJson;
    /// Advisory burst observation for one document/recipient/window. Key: hex32/string/u64be.
    ESIGN_PUBLIC_CHECK: VaultMeta b"esign.public_check.v1/" Named;
    /// Public ceremony rate counter. Key: hex32 [/ string].
    ESIGN_PUBLIC_RATE: VaultMeta b"esign.public_rate.v1/" Raw;
    /// Recipient live capability index. Key: id16 + string.
    /// Advisory rate count; key: document hex32/string, value window u64be + count u64be.
    ESIGN_PUBLIC_RATE_V2: VaultMeta b"esign.public_rate.v2/" Raw;
    ESIGN_RECIPIENT_CAPABILITY_INDEX: VaultMeta b"esign.recipient_capability.v1/" Raw;
    /// Completed seal attempt result. Key: id16.
    ESIGN_SEAL_RESULT: VaultMeta b"esign.seal_result.v1/" LegacyJson;
    /// Sealed document manifest. Key: id16.
    ESIGN_SEALED_DOCUMENT: VaultMeta b"esign.sealed.v1/" LegacyJson;
    /// Signature image ownership marker. Key: id16 + string + string.
    ESIGN_SIGNATURE_IMAGE_BINDING: VaultMeta b"esign.signature_image.v1/" Raw;
    /// One whole-vault export receipt: when, which format, how many bytes and their digest, by
    /// whom; never the exported bytes. Key: u64be(sequence).
    EXPORT_RECEIPT: VaultMeta b"export:receipt:v1:" Named;
    /// Binding proof tying a restored foreign expression-preference claim to the exact local row it
    /// reconstructed. Key: id16.
    EXPRESSION_ARCHIVE_BINDING: VaultMeta b"expression/archive-binding/v1\0" Raw;
}
