//! Purposes of bookings.
//!
//! An emergency reschedule hashes seven things, each the BLAKE3 of a value's JSON
//! (`oneiron_records::booking::emergency_reschedule::content_hash`): the owner's request,
//! stored in the instruction row and compared before any plan or effect; three row keys;
//! the intent reference its outbound effects are frozen under; and the plan's and the
//! pick's content hashes, stored and compared on every read. So each keeps its bytes (K,
//! PLAN-UC-04 6.2). None writes a tag: the names below are registry names only.

purposes! {}

legacy_purposes! {
    /// The request hash (`canonical_emergency_request_hash`) of the window, the reason and
    /// the action policy, stored as `OwnerInstructionRecord.request_hash`.
    EMERGENCY_REQUEST_HASH = (Blake3, NotHashed, "oneiron.booking.emergency_request_hash.v1");

    /// The instruction row key's suffix (`instruction_key`): the owner (hex), the request's
    /// fields and the time the instruction was recorded, written as lowercase hex.
    EMERGENCY_INSTRUCTION_KEY = (Blake3, NotHashed, "oneiron.booking.emergency_instruction_key.v1");

    /// The request-to-plan index key's hash (`request_plan_hash`) of the instruction's row key.
    EMERGENCY_REQUEST_PLAN_INDEX_KEY =
        (Blake3, NotHashed, "oneiron.booking.emergency_request_plan_index_key.v1");

    /// The item and plan row keys' suffix (`item_key`): the instruction's row key and the
    /// event (hex), written as lowercase hex.
    EMERGENCY_ITEM_KEY = (Blake3, NotHashed, "oneiron.booking.emergency_item_key.v1");

    /// The intent reference of an outbound effect (`effect_ref`): the item's row key and the
    /// content hash the effect carries, written as lowercase hex.
    EMERGENCY_EFFECT_REF = (Blake3, NotHashed, "oneiron.booking.emergency_effect_ref.v1");

    /// A plan's content hash (`EmergencyPlan::hash`), stored in the plan and compared on
    /// every read.
    EMERGENCY_PLAN_CONTENT_HASH =
        (Blake3, NotHashed, "oneiron.booking.emergency_plan_content_hash.v1");

    /// A pick's content hash (`EmergencyPick::hash`), stored in the pick checkpoint and
    /// compared on every read.
    EMERGENCY_PICK_CONTENT_HASH =
        (Blake3, NotHashed, "oneiron.booking.emergency_pick_content_hash.v1");
}
