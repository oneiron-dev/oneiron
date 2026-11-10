//! The side tables `workspace_roster` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One bind or unbind of a house mind's org link (HOUSE-BIND = A): binder, house, org, role,
    /// workspace and grant. Key: id16 (house) + id16 (receipt).
    HOUSE_LINK_RECEIPT: VaultMeta b"house_link.receipt.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_house_link_actor_in_txn;
    /// Where one project ask went: its project, placing TASK and ask (content, not authority).
    /// Key: id16 (ask).
    PROJECT_ASK: VaultMeta b"project.ask.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An owner question about a parent cycle past its world bound (OF-520), local. Key: id16
    /// (the cycle's first project).
    PROJECT_CYCLE_QUESTION: VaultMeta b"project.cycle_question.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The last verified frontier of one project's signed history, LIVE. Key: id16 (project).
    PROJECT_FRONTIER: VaultMeta b"project.frontier.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A descendant of an over-budget project's frozen head applied as a meet. Key: id16
    /// (project) + hash32 (revision).
    PROJECT_FROZEN_APPLIED: VaultMeta b"project.frozen_applied.v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A frozen descendant whose verdict waits on a parent project. Key: id16 (parent project) +
    /// id16 (project) + hash32 (revision).
    PROJECT_FROZEN_WAIT_PROJECT: VaultMeta b"project.frozen_wait_project.v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Local admission marker of one goal claim: `[1]` + body hash32 (sealed), `[2]` + project id16
    /// + payload hash32 (armed birth), or `[3]` + prior hash32 + allowed hash32 (supersession).
    /// Key: id16 (goal claim).
    PROJECT_GOAL_INTAKE_ADMISSION: VaultMeta b"project.goal_intake.admission/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Goal claim a single-use interview confirmation committed. Key: id16 (confirmation turn).
    PROJECT_GOAL_INTAKE_CONFIRMATION: VaultMeta b"project.goal_intake.confirmation/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A project's goal generation (u64be). Key: id16 (project).
    PROJECT_GOAL_INTAKE_GENERATION: VaultMeta b"project.goal_intake.generation/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permit for one goal-pointer change: old goal id16, new goal id16 (zeros for none), project
    /// body hash32. Key: id16 (project).
    PROJECT_GOAL_INTAKE_POINTER_WRITE: VaultMeta b"project.goal_intake.pointer_write/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's per-project history budget, set by the owner. Key: ().
    PROJECT_HISTORY_POLICY: VaultMeta b"project.history_policy.v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable owner tap of one project card: (tap digest, mint receipt). Key: blake3 hash32 of
    /// the card id.
    PROJECT_MINT_TAP: VaultMeta b"project.mint.tap.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A host-held project card (OF-501): the card, its conversation, the agent that drafted it
    /// and its state. Key: blake3 hash32 of the card id.
    PROJECT_PROPOSAL_CARD: VaultMeta b"project.proposal.card.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_card_actor_in_txn;
    /// The source message of each card shown in one conversation. Key: id16 (conversation) +
    /// blake3 hash32 of the card id.
    PROJECT_PROPOSAL_CONVERSATION: VaultMeta b"project.proposal.conversation.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A conversation's latest person turn awaiting the project question. Key: id16
    /// (conversation).
    PROJECT_PROPOSAL_PENDING: VaultMeta b"project.proposal.pending.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_pending_actor_in_txn;
    /// The project question's yes, or its ask of a person, on one source message, with its
    /// decision receipt. Key: id16 (source message).
    PROJECT_PROPOSAL_VERDICT: VaultMeta b"project.proposal.verdict.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_project_verdict_actor_in_txn;
    /// A held revision waiting for its slip's mint. Key: slip id32 + id16 (project) + hash32
    /// (revision).
    PROJECT_REVISION_AWAITING_MINT: VaultMeta b"project.revision_awaiting_mint.v1/" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Version (u64be) of the one-time revision capture a writable open ran. Key: ().
    PROJECT_REVISION_BACKFILL: VaultMeta b"project.revision_backfill.v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A held project revision companion and its origin. Key: id16 (project) + hash32 (revision).
    PROJECT_REVISIONS: VaultMeta b"project.revisions.v1/" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Change-log event recording a project's home-room membership transition. Key: id16 (project) +
    /// id16 (change event id).
    PROJECT_ROOM_CHANGES: VaultMeta b"project.room_changes.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index from a project's derived home room back to the project that owns it. Key: id16 (derived
    /// home-room id).
    PROJECT_ROOM_OWNER: VaultMeta b"project.room_owner.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The root project's entity id, seeded once at first boot. Key: ().
    PROJECT_ROOT: VaultMeta b"project.root.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A signed project row that replay replaced with an unsigned one, held
    /// in quarantine until a signed row lands again. Key: id16 (project id).
    PROJECT_STRIPPED_PROOF: VaultMeta b"project.stripped_proof.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Claim-before-speaking receipt naming which actor may respond to one addressed turn. Key: id16
    /// (turn id).
    ROOMS_CLAIM: VaultMeta b"rooms.claim.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Chronological index of non-branch (thread-root) turns, walked in reverse for the canonical
    /// room head. Key: id16 (room) + u64be (at) + id16 (turn).
    ROOMS_HEADS: VaultMeta b"rooms.heads.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Chronological index of every turn in a room, walked for paged message history. Key: id16
    /// (room) + u64be (at) + id16 (turn).
    ROOMS_HISTORY: VaultMeta b"rooms.history.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A room's stored host (OF-528): the latest pin, by someone the room's grant allows, or
    /// handoff, by the host it replaced. Latest write wins; it grants no scope, role or admission.
    /// Key: id16 (room).
    ROOMS_HOST_PIN: VaultMeta b"rooms.host_pin.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_host_pin_actor_in_txn;
    /// One room-join intent's receipt (OF-531): the request, each party's recorded answer, the three
    /// consents as last decided, and the participation a Ready decision committed. Key: string (hex64
    /// join ref).
    ROOMS_JOIN: VaultMeta b"rooms.join.v1/" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_join_actor_in_txn;
    /// The latest Ready join receipt for one subject in one room or thread. Key: string (room hex "/"
    /// subject hex "/" branch hex or "-").
    ROOMS_JOIN_READY: VaultMeta b"rooms.join_ready.v1/" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// One offer card (OF-530): who asks, what, the cost, the join it files and its state, with the
    /// host's answer that settled it. Key: string (hex64 offer id).
    ROOMS_OFFER: VaultMeta b"rooms.offer.v1/" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_offer_actor_in_txn;
    /// The offer card current for one agent in one room or thread. Key: string (room hex "/" branch
    /// hex or "-" "/" agent hex).
    ROOMS_OFFER_CURRENT: VaultMeta b"rooms.offer_current.v1/" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// One participation fact (OF-529): who took part in a room or one of its threads, how and since
    /// when, written once and never rewritten. Key: id16 (room) + 16 bytes (thread, all zero for the
    /// room itself) + u8 (subject kind) + id16 (subject) + u8 (cause kind) + 16 bytes (the cause's turn
    /// or task id, or an offer id's digest).
    ROOMS_PARTICIPATION: VaultMeta b"rooms.participation.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_participation_actor_in_txn;
    /// Maps a host-configured platform handle to the one present actor it addresses within a room.
    /// Key: id16 (room id) + bytes (platform handle).
    ROOMS_HANDLE: VaultMeta b"rooms.platform_handle.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Single-response-per-claim guard: which turn already answered one claimed parent turn. Key:
    /// id16 (parent turn id).
    ROOMS_RESPONSE: VaultMeta b"rooms.response.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Inverse of a room turn's TASK bindings, read to place one TASK in its private threads. Key:
    /// id16 (task) + id16 (binding turn).
    ROOMS_TASK_TURN: VaultMeta b"rooms.task_turn.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Parent-to-child index of a room's thread replies, scanned for one message's threads. Key:
    /// id16 (room) + id16 (parent turn) + id16 (child turn).
    ROOMS_THREAD_CHILDREN: VaultMeta b"rooms.thread_children.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One addressed room turn (actor, addressed agents, message ids, reply/thread links). Key: id16
    /// (turn id).
    ROOMS_TURN: VaultMeta b"rooms.turn.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_turn_actor_in_txn;
    /// Guards a companion PERSON against being claimed by a second principal's onboarding. Key: id16
    /// (companion person id).
    WORKSPACE_ROSTER_COMPANION_PRINCIPAL: VaultMeta b"workspace_roster:companion_principal:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_companion_principal_actor_in_txn;
    /// One onboarded member's roster row (actor, optional companion person/actor/facet, identity).
    /// Key: string (workspace_ref) "\x00" hex32 (person id).
    WORKSPACE_ROSTER_MEMBER: VaultMeta b"workspace_roster:member:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_member_actor_in_txn;
    /// Guards one member's workspace-onboarding slot against a second onboarding with different
    /// inputs. Key: string (workspace_ref) "\x00" id16 (person id).
    WORKSPACE_ROSTER_MEMBER_INTENT: VaultMeta b"workspace_roster:member_intent:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_member_intent_actor_in_txn;
    /// Idempotency journal tracking one member-onboarding request's progress through the pinned step
    /// ladder. Key: string (caller-supplied onboarding_id).
    WORKSPACE_ONBOARDING: VaultMeta b"workspace_roster:onboarding:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-workspace roster preset (org, venture name, house actor/identity, house display name).
    /// Key: string (workspace_ref).
    WORKSPACE_ROSTER_PRESET: VaultMeta b"workspace_roster:preset:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
