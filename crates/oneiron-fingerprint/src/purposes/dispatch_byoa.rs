//! Purposes of BYOA dispatch (`crates/oneiron/src/dispatch_byoa`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The one exhaust artifact every capture of an attempt appends to
    /// (`dispatch_byoa::exhaust::byoa_exhaust_artifact_id`). Parts: the attempt.
    EXHAUST_ARTIFACT = (Blake3, HashedFirst, "oneiron:byoa-exhaust-artifact:v1");

    /// The host runtime's Agent PERSON, which authors exhaust artifact writes
    /// (`dispatch_byoa::exhaust::byoa_runtime_actor`). No parts; the tag's bytes are also the
    /// PERSON's canonical body.
    RUNTIME_ACTOR = (Blake3, HashedFirst, "oneiron:byoa-runtime-actor:v1");

    /// The Agent PERSON that holds every seat run's T1 grants (`dispatch_byoa::seat_secrets`).
    /// No parts; the tag's bytes are also the PERSON's canonical body.
    SEAT_SECRET_HOLDER = (Blake3, HashedFirst, "oneiron:byoa-seat-secret-holder:v1");

    /// The per-claim Agent PERSON a seat child's slip holds for (FIX 10624 step 2;
    /// `dispatch_byoa::seat_secrets::seat_child_holder`). No parts: the claim's attempt, its
    /// lease generation (u32 big-endian) and its lease owner follow the tag unframed, as a tag
    /// suffix (`EntityId::derive_legacy_material_with_tag_suffix`), and the tag with its suffix
    /// is the PERSON's canonical body.
    SEAT_CHILD_HOLDER = (Blake3, HashedFirst, "oneiron:byoa-seat-child-holder:v1:");

    /// An official seat's model-seat id (`dispatch_byoa::official_seats::official_seat_id`).
    /// Parts: the route, the account, the machine and the login store labels (empty for none).
    OFFICIAL_SEAT = (Blake3, HashedFirst, "oneiron:official-seat:v1");

    /// A configured Sign in with ChatGPT offer's model-seat id
    /// (`dispatch_byoa::official_seats::siwc_offer_seat_id`). Parts: the credential file's path.
    SIWC_OFFER_SEAT = (Blake3, HashedFirst, "oneiron:siwc-offer-seat:v1");

    /// A runner seat's quota record (`dispatch_byoa::seat_quota::seat_quota_id`). Parts: the
    /// runner, the auth kind, then each credential handle.
    RUNNER_SEAT_QUOTA = (Blake3, HashedFirst, "oneiron:byoa-runner-seat-quota:v1");

    /// A staged job's artifact (`dispatch_byoa::staged_input::staged_input_artifact_id`; its
    /// erase derives it again). Parts: the job's digest.
    STAGED_INPUT_ARTIFACT = (Blake3, HashedFirst, "oneiron:byoa-staged-input-artifact:v1");

    /// The binding a parent makes for one of its steps (`dispatch_byoa::work_binding`). Parts:
    /// the parent, the step key.
    RUNNER_WORK_BINDING = (Blake3, HashedFirst, "oneiron:byoa-runner-work-binding:v1");
}
