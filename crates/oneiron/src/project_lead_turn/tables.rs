//! The side tables `project_lead_turn` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One project's lead turns as the owner set them (FIX NEON-LEAD-TURN-TRIGGER): the lead,
    /// its model, the plain-job starters, the settings, the hold, the owed turn and the timer's
    /// next due time. Key: id16 (project).
    PROJECT_LEAD_TURN_REGISTRATION: VaultMeta b"project_lead_turn_registration:v1:" Named
        // Restore class: An owner's setting is live: a restore never names a lead again or
        // lifts a hold the owner placed.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::project_lead_turn::erase_lead_turn_entity_in_txn;
    /// One line per turn of a project's lead: its causes, claim, end, outcome and kept files.
    /// Key: id16 (project) + u64be (turn number).
    PROJECT_LEAD_TURN: VaultMeta b"project_lead_turn:v1:" Named
        // Restore class: A turn line is history the comparison reads: a restore keeps the lines
        // it holds and never invents one.
        [restore: live] [family: unclassified] [tier: canonical];
    /// One file a turn kept under its name (ANSWER NEON-TURN-FILES = A): tenant data, read only
    /// by the owner or a Grant that reaches the project. Key: id16 (project) + u64be (turn
    /// number) + the name.
    PROJECT_LEAD_TURN_FILE: VaultMeta b"project_lead_turn_file:v1:" Named
        // Restore class: A kept file is the turn's own record: a restore keeps what it holds.
        [restore: live] [family: unclassified] [tier: canonical];
    /// The project whose lead-turn registration lists an actor as a plain-job starter, so a
    /// plain job's end finds its company by one read. Key: id16 (actor).
    PROJECT_LEAD_TURN_STARTER: VaultMeta b"project_lead_turn_starter:v1:" Named
        // Restore class: An index of the owner's setting, live as the setting is.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::project_lead_turn::erase_lead_turn_entity_in_txn;
}
