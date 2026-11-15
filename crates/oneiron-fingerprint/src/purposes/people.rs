//! Purposes of people (`crates/oneiron/src/context_board/people`, `memory::people_verbs`,
//! `consent::contact_clearance`).

purposes! {
    /// The model PERSON an agent definition is born with (`context_board::people`). Parts:
    /// agent.
    AGENT_PERSON = "oneiron.people.agent-person.v1";

    /// A seeded agent's `person.substrate` claim (FIX 12098; `context_board::people`). Parts:
    /// agent.
    SEEDED_SUBSTRATE = "oneiron.people.seeded-substrate.v1";

    /// A seeded agent's `actor.subject_ref` claim (FIX 12098; `context_board::people`).
    /// Parts: agent.
    SEEDED_ANCHOR = "oneiron.people.seeded-anchor.v1";

    /// The one Direct room two persons share (`memory::people_verbs`). Parts: the pair, in
    /// order.
    DIRECT_ROOM = "oneiron.people.direct-room.v1";

    /// A leader message's room: one per leadership tenure, so a new leader gets a new room
    /// (FIX 1380; CALLS C6; `memory::people_verbs`). Parts: each project and its leader.
    LEADER_ROOM = "oneiron.people.leader-room.v1";

    /// The id the engine files its own contact-disclosure offers under
    /// (`consent::contact_clearance::engine_offer`). No parts.
    CONTACT_DISCLOSURE_ENGINE_FILER = "oneiron:contact-disclosure-engine-filer:v1";
}

legacy_purposes! {}
