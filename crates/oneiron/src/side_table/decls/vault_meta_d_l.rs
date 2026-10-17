// Declared `vault_meta` tables whose prefix starts with `d` to `l`, in prefix order.

side_tables! {
    VAULT_META_D_L;
    /// One typed-decision ask the ladder queued for the vault owner role, and its answer once
    /// given. Key: u64be(sequence).
    DECISION_ASK: VaultMeta b"decision:ask:v1:" Named;
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
    /// Enforcement-truth per-counterparty-contact disclosure scope row (rmpv-encoded), dual-written
    /// with an owner-visible claim. Key: id16.
    DISCLOSURE_SCOPE: VaultMeta b"disclosure.scope.v1:" Raw;
    /// Owner Tier-A mark row for an entity (value = marked_at u64 LE), dual-written with an owner-
    /// visible claim. Key: id16.
    DISCLOSURE_TIER_A: VaultMeta b"disclosure.tier_a.v1:" Raw;
    /// Passive outbound dispatch audit observation for one attempt/try. Key: id16 + u32be.
    DISPATCH_OBSERVATION: VaultMeta b"dispatch_observation:v1/" Raw;
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
    /// Operator-set consolidation candidate-selection config (strength weights, caps). Key: ().
    DREAMER_CONSOLIDATION_SELECTION: VaultMeta b"dreamer:consolidation:selection:v1" LegacyJson;
    /// Private run-tree-scoped critique artifact for one branch attempt, keyed by attempt id and
    /// artifact id; written independently by both the generic critic reviewer and the Dreamer
    /// tournament with the identical prefix and key layout (see WHERE) - worth a second look for
    /// accidental collision if the same (attempt, artifact_id) pair is ever used from both callers.
    /// Key: id16 + u16be + string.
    CRITIC_ARTIFACT: VaultMeta b"dreamer:critic:v1:" Named;
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
    /// The entity and claim ids one Dreamer attempt's extraction listed for its model, so a replay
    /// lists the same ones. Ids only, never their text. Key: id16.
    DREAMER_NEIGHBOURHOOD: VaultMeta b"dreamer:neighbourhood:v1:" LegacyJson;
    /// Atomic merge/narrative outputs for one nightly fan-in receipt. Key: id16.
    DREAMER_NIGHTLY_MERGED: VaultMeta b"dreamer:nightly:merged:v1:" Named;
    /// Promoted/attached proposal ids returned by one nightly child. Key: id16.
    DREAMER_NIGHTLY_OUTPUT: VaultMeta b"dreamer:nightly:output:v1:" Named;
    /// The NOTE review's page cursor: the last NOTE id a review finished. Key: ().
    DREAMER_NOTE_REVIEW_CURSOR: VaultMeta b"dreamer:note-review:cursor:v1" Named;
    /// BLAKE3 of the markdown a NOTE review last read for one NOTE, so an unchanged NOTE is not
    /// read again. Key: id16.
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
    DREAMER_PROACTIVITY_DIGEST: VaultMeta b"dreamer:proactivity:digest:v1:" LegacyJson;
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
    DREAMER_REPRESENTATION_APPROVAL: VaultMeta b"dreamer:representation:v1:approval:" LegacyJson;
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
    /// Coalesced recipe input for one wake recipe. Key: u8(recipe).
    DREAMER_WAKE_RECIPE_INPUT: VaultMeta b"dreamer:wake-policy:recipe-input:v1:" LegacyJson;
    /// Wake cursor and pending state. Key: ().
    DREAMER_WAKE_STATE: VaultMeta b"dreamer:wake-policy:state:v1" LegacyJson;
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
    EDIT_DISTANCE_PROPOSAL_ARTIFACT: VaultMeta b"edit_distance/proposal_artifact/v1\0" Raw;
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
    /// One sealed FIX6 code-fix export (an invented example or a candidate fix's result) waiting
    /// for the host to drain it, with the worlds it touched; never real chat text. Key: id16.
    FAILURE_SIGNALS_CODE_FIX: VaultMeta b"failure_signals:code_fix:v1:" Named;
    /// The Coach's code-fix work on one failure case and its local verdicts: the invented
    /// example's and the candidate fix's, kept after the export queue drains. Never real chat
    /// text. Key: id16(case key).
    FAILURE_SIGNALS_CODE_FIX_WORK: VaultMeta b"failure_signals:code_fix_work:v1:" Named;
    /// The actor bound to the active content write transaction, deleted before commit. Key: ().
    FEDERATION_ACTOR_CONTENT_INFLIGHT: VaultMeta b"federation:actor-content:inflight:v1" Raw;
    /// An ask guest's FEDERATION_GRANT the owner withdrew: the guest it conferred on and when, so
    /// a repeat revoke reports the first (OF-232). Key: id16 (grant).
    FEDERATION_GUEST_REVOKE: VaultMeta b"federation:guest_revoke:v1:" Named;
    /// The owner's confidence scale for claims one federation peer sends, this device's local
    /// truth (OF-149). Key: id16(peer principal).
    FEDERATION_PEER_CONFIDENCE: VaultMeta b"federation:peer_confidence:v1:" Named;
    /// One note the open feedback inbox took, kept for the triage sweep. Key: u64be(sequence).
    FEEDBACK_INBOX: VaultMeta b"feedback:inbox:v1:" Named;
    /// Open feedback-review-item queue row awaiting triage. Key: id16.
    FEEDBACK_QUEUE: VaultMeta b"feedback:queue:v1:" Named;
    /// Dedup index from a feedback bundle's content digest to the review item id that first recorded
    /// it. Key: hex64.
    FEEDBACK_RECEIVED_DIGEST: VaultMeta b"feedback:received:v1:" Raw;
    /// Universal report arrivals; review lives on the ISSUE entity. Key: u64be + id16.
    FEEDBACK_REPORT_ARRIVAL: VaultMeta b"feedback:report-arrival:v1:" Named;
    /// T2 report membership and vectors, keyed by the first ISSUE id.
    FEEDBACK_REPORT_CLUSTER: VaultMeta b"feedback:report-cluster:v1:" Named;
    /// Owner disclosure preference, keyed by the resolved publisher reference.
    FEEDBACK_REPORT_DISCLOSURE: VaultMeta b"feedback:report-disclosure:v1:" Named;
    /// Host-stamped subject provenance or owner routing policy. Key: subject reference.
    FEEDBACK_REPORT_ROUTE: VaultMeta b"feedback:report-route:v1:" Named;
    /// A folder the owner attached as a standing source of notes (OF-554): the folder, its
    /// include patterns, default kind, source and trust tier, and its last rescan. Key: hex16
    /// (hash of the folder).
    FOLDER_SOURCE: VaultMeta b"folder-source:attached:v1:" Named;
    /// What an attached folder's rescans know of one file: its note, the hash of its text and of
    /// what the vault took from it, and whether it landed, waits as a fork or was retracted.
    /// Key: string (`folder hash:path`, a long path by its hash).
    FOLDER_SOURCE_FILE: VaultMeta b"folder-source:file:v1:" Named;
    /// Per-actor foreign-introduction ceiling and widen state for an owner-bound agent introduction.
    /// Key: id16.
    GATE_FOREIGN_AGENT_INTRODUCTION: VaultMeta b"gate.foreign-agent.v1:" Named;
    /// Cached configuration window (seconds) for the receipt-derived auto-checker signal; no engine
    /// write path found in this repo, likely operator-provisioned. Key: ().
    GATE_AUTO_SIGNALS_WINDOW: VaultMeta b"gate:auto_signals:window:v1" LegacyJson;
    /// Per-claim critical confirm invalidation. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also checks the version
    /// byte and rejects an all-zero claim id, business validation `Named`'s
    /// generic strict-msgpack decode does not run; `RawValue` delegates to
    /// the module's own `encode_critical_confirm_invalidation`/
    /// `decode_critical_confirm_invalidation`.
    CRITICAL_CONFIRM_INVALIDATION: VaultMeta b"gate_critical_invalidation:v0:" Raw;
    /// Latest verified claim-write retention ancestry, inherited by later decisions on the claim;
    /// the retention-scope module's own layout. Key: id16 (claim).
    GATE_DECISION_CLAIM_CONTEXT: VaultMeta b"gate_decision:claim_context:v1:" Raw;
    /// Grant-reference index over the gate decision ledger. Key: u64be len + string + id16.
    /// Exterior-key root binding of encrypted claim-bound gate decisions. Key: ().
    GATE_DECISION_CUSTODY_ROOT: VaultMeta b"gate_decision:custody_root:v1" Raw;
    GATE_DECISION_GRANT_REF_INDEX: VaultMeta b"gate_decision:grant_ref_index:v1:" Raw;
    /// A committed erase whose claim-partition key retirement is still pending; the value is
    /// the single byte 1. No hold defers that retirement or lands while it stands. Key: id16
    /// (claim).
    GATE_DECISION_PARTITION_ERASE_PENDING: VaultMeta b"gate_decision:partition_erase_pending:v1:" Raw;
    /// Latest retain-until stamp (u64be seconds) of a held gate decision partition. Key: 0
    /// (claim-free partition) or 1 + id16 (claim).
    GATE_DECISION_PARTITION_RETAIN_UNTIL: VaultMeta b"gate_decision:partition_retain_until:v1:" Raw;
    /// Committed intent to retire one claim partition's exterior key, holding the newest key
    /// generation (u64be) an erase or the sweep removed rows under. Key: id16 (claim).
    GATE_DECISION_PARTITION_RETIRE_PENDING: VaultMeta b"gate_decision:partition_retire_pending:v1:" Raw;
    /// Append-time retention ancestry of one gate decision; the retention-scope module's own
    /// layout. Key: id16 (decision).
    GATE_DECISION_RETENTION_CONTEXT: VaultMeta b"gate_decision:retention_context:v1:" Raw;
    /// Gate decision ledger row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_gate_decision_record` (version, notice, receipt-reason and
    /// redaction-shape checks), business validation `Named`'s generic
    /// strict-msgpack decode does not run; `RawValue` delegates to the
    /// module's own `encode_gate_decision`/`decode_gate_decision`.
    GATE_DECISION_LEDGER: VaultMeta b"gate_decision:v0:" Raw Ciphertext;
    /// Claim-keyed gate decision index. Key: id16 + id16.
    GATE_DECISION_CLAIM_INDEX: VaultMeta b"gate_decision_by_claim:v0:" Raw;
    /// Claim-index backfill flag. Key: ().
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE: VaultMeta b"gate_decision_by_claim_backfill_complete" Raw;
    /// Per-constituent index over bundle decisions' claim refs; empty value. Key: id16 (claim) +
    /// id16 (decision).
    GATE_DECISION_CLAIM_REF_INDEX: VaultMeta b"gate_decision_by_claim_ref:v0:" Raw;
    /// A bundle decision's complete constituent claim ids (ascending, distinct). Key: id16.
    GATE_DECISION_CLAIM_REFS: VaultMeta b"gate_decision_claim_refs:v0:" LegacyCompact;
    /// Batch preflight decision whose op has not applied yet; never survives a commit. Key: id16.
    GATE_DECISION_UNAPPLIED_PREFLIGHT: VaultMeta b"gate_decision_unapplied_preflight:v0:" Raw;
    /// Staged deletion authority decision sidecar. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_deletion_gate_decision_record`, a business check
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own `encode_pending_deletion_gate_decision`/
    /// `decode_pending_deletion_gate_decision`.
    GATE_DELETE_PENDING_SIDECAR: VaultMeta b"gate_delete_pending:v0:" Raw;
    /// Local deletion tombstone needs an authority sidecar. Key: id16.
    GATE_DELETE_REQUIRED_MARKER: VaultMeta b"gate_delete_required:v0:" Raw;
    /// Critical-write confirm id to pending claim. Key: bytes32.
    CRITICAL_CONFIRM_INDEX: VaultMeta b"gate_pending:critical_confirm_by_id:v1:" Raw;
    /// Critical confirm expiry sweep state. Key: ().
    CRITICAL_CONFIRM_EXPIRY_CURSOR: VaultMeta b"gate_pending:critical_confirm_expiry_cursor:v1" Raw;
    /// Critical confirm list sweep state. Key: ().
    CRITICAL_CONFIRM_LIST_CURSOR: VaultMeta b"gate_pending:critical_confirm_list_cursor:v1" Raw;
    /// Pending consents grouped by root-group alias. Key: u64be len + string + id16.
    PENDING_GATE_CONSENT_GROUP_INDEX: VaultMeta b"gate_pending:group_index:v1:" Raw;
    /// Semantic duplicate index of pending consents. Key: bytes32 + id16.
    PENDING_GATE_CONSENT_HASH_INDEX: VaultMeta b"gate_pending:hash_index:v1:" Raw;
    /// Index keys created for a pending consent. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces the
    /// version byte and non-empty run/group keys, business validation
    /// `Named`'s generic strict-msgpack decode does not run; `RawValue`
    /// delegates to the module's own
    /// `encode_pending_gate_consent_index_state`/
    /// `decode_pending_gate_consent_index_state`.
    PENDING_GATE_CONSENT_INDEX_STATE: VaultMeta b"gate_pending:index_state:v1:" Raw;
    /// Pending consents grouped by run. Key: u64be len + string + id16.
    PENDING_GATE_CONSENT_RUN_INDEX: VaultMeta b"gate_pending:run_index:v1:" Raw;
    /// Pending consent insertion sequence. Key: id16.
    PENDING_GATE_CONSENT_SEQUENCE: VaultMeta b"gate_pending:sequence:v1:" Raw;
    /// Pending-consent sequence high-water mark. Key: ().
    PENDING_GATE_CONSENT_SEQUENCE_COUNTER: VaultMeta b"gate_pending:sequence_counter:v1" Raw;
    /// Pending consents ordered by sequence. Key: u64be.
    PENDING_GATE_CONSENT_SEQUENCE_INDEX: VaultMeta b"gate_pending:sequence_index:v1:" Raw;
    /// Pending gate-consent tray row. Key: id16.
    ///
    /// Codec fixed to `Raw` (T47 store slice): decode also enforces
    /// `vet_pending_gate_consent_record` (version, diff-handle, reason-code
    /// shape checks), business validation `Named`'s generic strict-msgpack
    /// decode does not run; `RawValue` delegates to the module's own
    /// `encode_pending_gate_consent`/`decode_pending_gate_consent`.
    PENDING_GATE_CONSENT: VaultMeta b"gate_pending:v0:" Raw;
    /// Durable journal record of one prepared/applied/failed git ref, stage, or worktree effect. Key:
    /// hex64(repo identity) ":" hex64(record key).
    /// Owner-confirmed voice disclosure grant offer. Key: hex64 nonce.
    GENUI_VOICE_GRANT_OFFER: VaultMeta b"genui.voice_grant_offer.v1:" LegacyJson;
    GIT_WIRE_RECORD: VaultMeta b"git_wire:record:v2:" Named;
    /// Node-local Gmail page cursor keyed by lower-case hex identity id. Key: hex32.
    GMAIL_MAILBOX_CURSOR: VaultMeta b"gmail:mailbox_cursor:v1:" LegacyJson;
    /// Append-only offer-answer log for consent-graduation ramps, scope-major then UUIDv7 row id.
    /// Key: id16 + id16.
    EDIT_DISTANCE_GRADUATION_ANSWER: VaultMeta b"graduation_answer:v1:" Raw;
    /// Runtime consent-graduation threshold override for one ramp pattern, keyed by a digest of the
    /// pattern text. Key: id16.
    EDIT_DISTANCE_GRADUATION_THRESHOLD: VaultMeta b"graduation_threshold:v1:" Raw;
    /// Proposed/reviewed/escalated timestamps for one healer case, feeding oversight coverage counts.
    /// Key: hex32 (case_ref).
    HEALER_ACTIVITY: VaultMeta b"healer:activity:v1:" Named;
    /// Durable failure-ladder case authenticating one healer admission, bound to its lease-fenced
    /// failed attempt. Key: hex32 (case_ref).
    HEALER_CASE: VaultMeta b"healer:case:v1:" Named;
    /// Per-actor healer-submission counter and burst-check flag. Key: id16 (actor).
    SELF_HEAL_HEALER_COUNT: VaultMeta b"healer:count:" Named;
    /// Latest signed per-vault-device oversight receipt (coverage, review latency, or escalation
    /// rate). Key: u8 (OversightKind tag: 0/1/2).
    HEALER_OVERSIGHT_RECEIPT: VaultMeta b"healer:oversight:v1:" Named;
    /// An external healer's repair proposal record and its review state. Key: id16.
    SELF_HEAL_HEALER_PROPOSAL: VaultMeta b"healer:proposal:" Named;
    /// A human-ratified patch pull-request record for a released healer proposal. Key: id16.
    SELF_HEAL_HEALER_RELEASE: VaultMeta b"healer:release:" Named;
    /// Per-actor per-run healer receipt: submitted proposals and reversal state. Key: id16 + bytes32
    /// (actor then blake3 hash of run name).
    SELF_HEAL_HEALER_RUN: VaultMeta b"healer:run:" Named;
    /// The history import ledger: one row per imported source message (the conversation it landed
    /// in, its MESSAGE and TURN ids, the hash of what was imported, its revision). Key: string
    /// (`source:native message id`).
    INGEST_HISTORY_LEDGER: VaultMeta b"history-import:v1:" Named;
    /// A hook block: the rows one AddBlock pins for a recipient's board deliveries, its lifetime
    /// and its consumption. Key: id16 (block).
    HOOKS_BLOCK: VaultMeta b"hooks:block:v1:" Named Authored;
    /// An owner check a hook's causal chain raised (a cycle or a deep chain). Key: hash32 (run key).
    HOOKS_CHECK: VaultMeta b"hooks:check:v1:" Named;
    /// A fact hook's cursor in one source. Key: id16 (binding) + u8 (source).
    HOOKS_CURSOR: VaultMeta b"hooks:cursor:v1:" Named;
    /// The vault's `hooks.enabled` switch; absent is on. Key: ().
    HOOKS_ENABLED: VaultMeta b"hooks:enabled:v1" Named;
    /// The owner's grant on one hook binding. Key: id16 (binding).
    HOOKS_GRANT: VaultMeta b"hooks:grant:v1:" Named;
    /// Queued work a hook run saved before its cursor moved, and whether it landed. Key: hash32
    /// (run key).
    HOOKS_INTENT: VaultMeta b"hooks:intent:v1:" Named Authored;
    /// The hook chain behind a row a hook landed. Key: id16 (row).
    HOOKS_LINEAGE: VaultMeta b"hooks:lineage:v1:" Named;
    /// A hook run's saved result and pinned input. Key: hash32 (run key).
    HOOKS_MEMO: VaultMeta b"hooks:memo:v1:" Named Authored;
    /// A hook run's Hook receipt. Key: hash32 (run key).
    HOOKS_RECEIPT: VaultMeta b"hooks:receipt:v1:" Named Authored;
    /// A hook's regen record: the contract its last good body passed under, its intent, and a
    /// regen decision waiting to be enacted. Key: id16 (binding).
    HOOKS_REGEN: VaultMeta b"hooks:regen:v1:" Named Authored;
    /// The settlement feed fact hooks follow: one row per settled proposal. Key: u64be (sequence).
    HOOKS_SETTLED: VaultMeta b"hooks:settled:v1:" Named;
    /// The last settlement sequence handed out. Key: ().
    HOOKS_SETTLED_NEXT: VaultMeta b"hooks:settled_next:v1" Named;
    /// A call a verb hook's ask stopped: the call, its re-validated args, the hook's place in the
    /// chain and the ask handle, Open until a retry resumes it once. Key: id16 (invocation).
    HOOKS_VERB_ASK: VaultMeta b"hooks:verb_ask:v1:" Named;
    /// One engine housekeeping sweep's schedule: when it is next due, when its last run finished,
    /// and whether a run is in flight. Key: string (the sweep's code).
    HOUSEKEEPING_SCHEDULE: VaultMeta b"housekeeping:v1:" Named;
    /// A retirement deadline a door started (a secret lease's expiry, a voice print's retention
    /// deadline, a critical confirm's window), kept for a vault that is not running to know when to
    /// wake. Key: the sweep's tag byte, the deadline (u64 BE), then an id16 per note, so a sweep's
    /// earliest deadline is its first row and two notes of one deadline are two rows. Value: empty.
    HOUSEKEEPING_WAKE: VaultMeta b"housekeeping:wake:v1:" Raw;
    /// Follow-up reminder/escalation cursor state for one human task. Key: id16.
    HUMAN_TASK_FOLLOWUP: VaultMeta b"human_task.followup.v1\0" Raw;
    /// The TASK whose follow-up cursor the due sweep read last: the next wake pass resumes after
    /// it. Key: ().
    HUMAN_TASK_FOLLOWUP_SWEEP: VaultMeta b"human_task.followup_sweep.v1" Raw;
    /// Idempotency marker recording which signal/surface-event a wait's response already produced.
    /// Key: id16.
    HUMAN_TASK_WAIT_SIGNAL: VaultMeta b"human_task.wait.signal.v1\0" Raw;
    /// Active binding from a human task to the trap claim awaiting its response. Key: id16.
    HUMAN_TASK_WAIT_BINDING: VaultMeta b"human_task.wait.v1\0" Raw;
    /// Empty-marker index from a normalized identity hint (name/alias/handle) hashed per entity-kind
    /// to the entity id it names, for lookup-before-mint resolution. Key: u8 + hash32 + id16.
    INGEST_IDENTITY_HINT: VaultMeta b"identity-hint:v1:" Raw;
    /// Caller-supplied phonetic codes retained to recompute an entity's phonetic postings on
    /// reindex/delete. Key: id16.
    BATCH_PHONETIC_INDEX_SOURCE: VaultMeta b"index_source:phonetic:v1:" Named;
    /// Canonical caller-supplied text fields backing one document's bm25 index, used to rebuild
    /// postings. Key: id16.
    INDEX_SOURCE_TEXT: VaultMeta b"index_source:text:v1:" Named;
    /// Blob birth fingerprint tree used for perceptual/exact duplicate detection on ingest. Key:
    /// id16.
    INGEST_FINGERPRINT: VaultMeta b"ingest-fingerprint:v1:" LegacyJson;
    /// Run id to queued attempt ids. Key: u64be len + string + id16.
    ATTEMPT_RUN_INDEX: VaultMeta b"job:run_index:v1:" Raw;
    /// The next tagging marker's sequence number, a part of its derived id, so no marker id is
    /// ever drawn twice, even once a settled marker has left the job ledger. Key: (). Value: u64be.
    TAGGING_MARKER_SEQUENCE: VaultMeta b"job:tagging_marker_seq:v1" Raw;
    /// A turn's recorded tagging traces, oldest first: job state, never synced. Key: turn id16
    /// (sixteen zero bytes for a marker whose payload named no turn) + u64be sequence.
    TAGGING_TRACE: VaultMeta b"job:tagging_trace:v1:" Named;
    /// Empty-marker age index over the tagging traces. Key: u64be recorded-at + turn id16 + u64be
    /// sequence.
    TAGGING_TRACE_AGE: VaultMeta b"job:tagging_trace_age:v1:" Raw;
    /// Vault-scoped structural-kind registration. Key: u8.
    STRUCTURAL_KIND_REGISTRY: VaultMeta b"kind_reg:" Raw;
    /// A `learning.*` cell's key, estimate form and what counted. Key: cell digest (32 bytes).
    LEARNING_CELL: VaultMeta b"learning:cell:v1:" Named;
    /// Subject index over `learning.*` cells (value: the member). Key: subject id16 + cell digest.
    LEARNING_CELL_SUBJECT: VaultMeta b"learning:cell_subject:v1:" Named;
    /// A team's derived coordination cost (wait by reason, reuse delay, duplicate work): a
    /// diagnostic, never a score. Key: string (team reference).
    LEARNING_COORDINATION: VaultMeta b"learning:coordination:v1:" Named;
    /// An audit's label that two pieces of one team's work duplicated each other. Key: string
    /// (team reference "\0" first "\0" second).
    LEARNING_DUPLICATE_LABEL: VaultMeta b"learning:duplicate_label:v1:" Named;
    /// One admitted anchored outcome for a `learning.*` cell. Key: cell digest + receipt string.
    LEARNING_EVIDENCE: VaultMeta b"learning:evidence:v1:" Named;
    /// A judge swap's fitted score map, applied as a projection. Key: string (old judge revision).
    LEARNING_JUDGE_CONVERSION: VaultMeta b"learning:judge_conversion:v1:" Named;
    /// A `learning.*` cell's engine-written prior (origin, value, weight in runs). Key: cell digest.
    LEARNING_PRIOR: VaultMeta b"learning:prior:v1:" Named;
    /// Owner seed or pin over one learned-setting catalog row (value, weight in runs, setter, why).
    /// Key: string (setting key "\0" mode).
    LEARNING_SETTING: VaultMeta b"learning:setting:v1:" Raw;
    /// The vault-scope `learning.setting` fit, cached beside its claim for hot readers. Key: string
    /// (setting key).
    LEARNING_SETTING_FIT: VaultMeta b"learning:setting_fit:v1:" Named;
    /// The customer holds an owner's lift-and-erase confirm lifted from one record, until its
    /// deletion receipt completes (OF-470 C4). Key: id16 (record).
    LEGAL_HOLD_ERASE_LINK: VaultMeta b"legal_hold:erase_link:v1:" Named;
    /// The owner-visible legal-hold log: ids, times and reason codes only (OF-470 C3). Key: id16
    /// (hold) + u64be (sequence).
    LEGAL_HOLD_EVENT: VaultMeta b"legal_hold:event:v1:" Named;
    /// The host orders an owner's confirmed erase met (OF-470 C4). Host-only and runtime-tier:
    /// no checkpoint image carries it. Key: id16 (record).
    LEGAL_HOLD_HOST_ERASE_LINK: VaultMeta b"legal_hold:host:erase_link:v1:" Named;
    /// The host-only legal-hold log (OF-470 C2). Runtime-tier: no checkpoint image carries it.
    /// Key: id16 (hold) + u64be (sequence).
    LEGAL_HOLD_HOST_EVENT: VaultMeta b"legal_hold:host:event:v1:" Named;
    /// A host-order legal hold Oneiron placed on an authority order (OF-470 C1). Runtime-tier: no
    /// checkpoint image carries it. Key: id16 (hold).
    LEGAL_HOLD_HOST_ROW: VaultMeta b"legal_hold:host:row:v1:" Named;
    /// What a standing host-order hold holds; the value is empty. Key: held key (1 + id16, or 17
    /// zero bytes for the claim-free gate partition) + id16 (hold).
    LEGAL_HOLD_HOST_TARGET: VaultMeta b"legal_hold:host:target:v1:" Raw;
    /// An owner-confirmed erase a host order keeps waiting; it names no hold. Key: id16 (record).
    LEGAL_HOLD_PENDING_ERASE: VaultMeta b"legal_hold:pending_erase:v1:" Named;
    /// A customer legal hold naming records or gate-decision partitions (OF-470). Key: id16
    /// (hold).
    LEGAL_HOLD_ROW: VaultMeta b"legal_hold:row:v1:" Named;
    /// What a standing customer hold holds; the value is empty. Key: held key (1 + id16, or 17
    /// zero bytes for the claim-free gate partition) + id16 (hold).
    LEGAL_HOLD_TARGET: VaultMeta b"legal_hold:target:v1:" Raw;
    /// A record kept after a refused privacy erasure, serving only that legal reason (OF-470 C6).
    /// Key: id16 (record).
    LEGAL_HOLD_USE_LIMIT: VaultMeta b"legal_hold:use_limit:v1:" Named;
    /// Vault-scoped authored lens prompt keyed by the lens entity id16.
    LENS_INTENT: VaultMeta b"lens/intent/v1\0" Named;
    /// One proposed pack lens: its frozen compiled tree, the pack/skill slot and pack content
    /// hash it is bound to, and who proposed it. It mounts only once the owner selects it. Key:
    /// id16 (lens).
    LENS_PROPOSAL: VaultMeta b"lens/proposal/v1\0" Named;
    /// The owner's consented selection of one proposed lens revision for a pack/skill slot.
    /// Key: string (pack name "\0" skill id hex).
    LENS_SLOT: VaultMeta b"lens/slot/v1\0" Named;
    /// Tracker issue id to task id. Key: string.
    LINEAR_ISSUE_REVERSE: VaultMeta b"linear.issue.v1/" Raw;
    /// Tracker pull-page cursor. Key: ().
    LINEAR_PULL_CURSOR: VaultMeta b"linear.pull_cursor.v1" Raw;
    /// Tracker-mirror outbox marker. Key: id16.
    LINEAR_TASK_DIRTY: VaultMeta b"linear.task_dirty.v1/" Raw Engine;
    /// Tracker-mirror revision counter of a task. Key: id16.
    LINEAR_TASK_REVISION: VaultMeta b"linear.task_revision.v1/" Raw Engine;
    /// Verified typed writer of a task at its current revision (u64be revision, id16 actor, class
    /// byte). Key: id16.
    LINEAR_TASK_WRITER: VaultMeta b"linear.task_writer.v1/" Raw;
    /// Digest of the Linear effect request an operation id was first authorized for. Key: 32-byte
    /// operation id.
    LINEAR_EFFECT_AUTHORIZED: VaultMeta b"linear:effect_authorized:v1/" Raw;
    /// Task to tracker issue link state. Key: id16.
    LINEAR_SYNC_LINK: VaultMeta b"linear_sync:link:v4:" LegacyJson;
    /// The vault's pinned model-role manifest (role bindings, tier/route defaults). Key: ().
    /// Measured description scores keyed inside one singleton map. Key: ().
    LLM_DESCRIPTION_MEASUREMENTS: VaultMeta b"llm:description_measurements:v1" LegacyJson;
    /// Vault-owned description policy. Key: ().
    LLM_DESCRIPTION_POLICY: VaultMeta b"llm:description_policy:v1" LegacyJson;
    /// Durable re-ask keyed by 64-character hex identity.
    LLM_DESCRIPTION_REASK: VaultMeta b"llm:description_reask:v1:" LegacyJson;
    /// Training provenance and checkpoint pin for the installed distilled encoder. Key: ().
    LLM_ENCODER_EXPORT: VaultMeta b"llm:encoder_export:v1" Named;
    /// The passing extraction-teacher probe approval behind the pinned teacher. Key: ().
    LLM_EXTRACTION_TEACHER_PROBE: VaultMeta b"llm:extraction_teacher_probe:v1" LegacyJson;
    LLM_MANIFEST: VaultMeta b"llm:manifest:v2" LegacyJson;
    /// Revision-pinned description of one registered model, read by seat routing. Key:
    /// string(model id).
    LLM_MODEL_DESCRIPTION: VaultMeta b"llm:model_description:v1:" LegacyJson;
    /// Held-out model trial, billed evidence and switch offer. Key: question id16 + trial id16.
    LLM_MODEL_TRIAL: VaultMeta b"llm:model_trial:v1:" Named;
    /// Vault-local per-purpose and voice-lane inference defaults table. Key: ().
    LLM_PURPOSE_DEFAULTS: VaultMeta b"llm:purpose_defaults:v1" LegacyJson;
    /// Priced model-catalog row: wire format, cost, and cached benchmark scores. Key: string(model
    /// id).
    LLM_REGISTRY_ROW: VaultMeta b"llm:registry:v1:" LegacyJson;
    /// Per-vault narrow-only resident route overrides, cleared when the manifest is replaced. Key:
    /// ().
    LLM_RESIDENT_ROUTES: VaultMeta b"llm:resident_routes:v1" LegacyJson;
    /// One routed seat selected and pinned by caller-chosen bounded seat id.
    LLM_ROUTED_SEAT: VaultMeta b"llm:routed_seat:v1:" LegacyJson;
    /// A run's immutable model-seat pin and choice receipt, committed before its first provider
    /// call. Key: id16 (run).
    LLM_RUN_SEAT: VaultMeta b"llm:run_seat:v1:" LegacyJson;
    /// Rolling window (max 64) of recent benchmark score-change diffs for one model. Key:
    /// string(model id) "\x00".
    LLM_SCORE_DIFFS: VaultMeta b"llm:scores:v1:" LegacyJson;
}
