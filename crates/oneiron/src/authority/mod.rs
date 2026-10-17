//! AUTHORITY_LOG record substrate.
//!
//! Type 122 is a fold-verified maintenance log. Replay doors validate the
//! record shape and embedded origin signature only; authority semantics stay in
//! [`fold_authority_log`], where the roster is derived from peer-signed log
//! entries rather than from a server-issued registry.
//!
//! Concern map (see each file's header for its contract):
//!
//! | file | concern |
//! |------|---------|
//! | `constants` | pinned schema version, domains, role bits, wire keys, limits |
//! | `crypto` | key material, signature envelope, transcript verification |
//! | `confirm` | owner-confirm and critical-write-confirm types |
//! | `federation_pact` | federation lifecycle/pact types, transcript, digests |
//! | `device` | device authority material and consent-role predicates |
//! | `log_entry_op` | op vocabulary, signed entry envelope, hashing, ids |
//! | `fold_state` | folded-state data model and the two-state merge |
//! | `first_seen_clock` | first-seen sidecar keys and the per-vault clock |
//! | `fold_engine` | top-level fold orchestration |
//! | `fold_schedule` | the per-entry scheduler: the next entry that does not wait |
//! | `ancestor_index` / `ancestry_bypass` | fold ancestry and revocation bypass |
//! | `log_budget` | pinned fold-work bounds, the slip issuer, and the store doors' per-signer bound |
//! | `import_order` | the order an import or a sync pass hands the store doors several rows in |
//! | `entry_transition` | per-entry transition and consent/quorum predicates |
//! | `anchor_fold` | owner roots and an anchor's machine marks, before the roster |
//! | `machine_profile` | per-admitter machine chains and the trusted projection |
//! | `pinned_root` / `owner_roots` | this install's pin, and the stored roots it reads |
//! | `op_apply` | applies one op to a fold state |
//! | `wire_encode` / `wire_decode` | the `rmpv` codec, edited in lockstep |
//! | `vault_api` | `impl Vault` read/write doors |

pub use crate::gate::manifest_authenticity::ManifestContribution;

mod ancestor_index;
mod ancestry_evaluator;
mod anchor_fold;
mod anchor_marks;
mod causal_write;
mod checkpoint;
mod checkpoint_adopt;
mod checkpoint_attest;
mod checkpoint_image;
mod checkpoint_policy;
mod claim_write;
mod engine_machine;
mod entry_transition;
mod first_seen_clock;
mod fold_engine;
mod fold_project;
mod fold_resume;
mod fold_schedule;
mod fold_state;
mod guest_revoke;
mod handoff_equivocation;
mod history_coverage;
mod history_fetch;
mod history_repair;
mod history_transfer;
mod host_actor;
mod host_re_root;
mod import_order;
mod ingest_observation;
mod install_fold;
mod invitee_slip;
mod invocation_slip;
mod left_notices;
mod log_budget;
mod log_structure;
mod machine_claims;
mod machine_enroll;
mod machine_identity;
mod machine_profile;
mod machine_standing;
mod machine_write;
mod mesh_machine;
mod observation_policy;
mod op_apply;
mod owner_project_slip;
mod owner_roots;
mod pinned_root;
mod readonly_fold;
mod recover_many;
mod retired_signers;
mod revoke_proof;
mod sequence_ancestry;
mod sequence_observation;
mod slip;
mod slip_pairing;
mod slip_replay;
mod slip_state;
mod slip_vault;
mod stale_roster;
mod task_actor;
mod vault_api;
mod world_key_fold;
mod world_key_support;
mod world_privacy;
mod world_privacy_door;
mod world_refold;
mod world_strength;
mod write_authorization;

#[cfg(test)]
mod tests;

// The wire layer (constants, key material and signatures, the op vocabulary and entry
// envelope, the codec, device/confirm/pact types, slip payloads) is defined in
// `oneiron-authority`. Its public items keep their public path here; the helpers that were
// private to this module are re-exported crate-internally only, so the fold and the doors
// below call them as before without widening `oneiron::authority`.
pub(crate) use oneiron_authority::authority::*;
pub use oneiron_authority::authority::{
    AUTHORITY_HASH_LEN, AUTHORITY_LOG_SCHEMA_VERSION, AUTHORITY_TRANSCRIPT_DOMAIN,
    AuthorityAttestation, AuthorityConfirmAction, AuthorityConfirmKind, AuthorityEntryHash,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthoritySignatureSuite,
    AuthorityTier, AuthorityVaultId, CRITICAL_WRITE_CONFIRM_DOMAIN,
    CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION, CriticalWriteConfirmAction,
    CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod, CriticalWriteConfirmState,
    DeviceAuthority, FEDERATION_PACT_DOMAIN, FEDERATION_SCOPE_COMMIT_DOMAIN,
    FederationGrantActivation, FederationLifecycleAction, FederationLifecycleKind,
    FederationLifecycleRejection, FederationPactGesture, FederationPactState, FederationPactStatus,
    FoldedDevice, GENESIS_FRAGILE_FLAG, GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MACHINE_SEEN_WORLD_EDITS_MAX, MAX_PACT_SCOPE_BYTES,
    MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole, ModelOrder,
    OWNER_HANDOVER_REF_MAX, OwnerHandover, OwnerHandoverCause, OwnerRootRecord, ROLE_ADMIN,
    ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER, ROLE_RECOVERY, ReadLocation, RecoveryRootId, SealedCopies,
    SlipClaims, SlipMintAction, WORLD_MODEL_ROUTE_MAX_BYTES, WORLD_MODEL_ROUTES_MAX,
    WorldKeyWrapsRecord, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash,
    authority_log_entity_id, authority_log_entity_id_from_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body, federation_pact_transcript,
    federation_scope_digest, genesis_vault_id, machine_profile_proof_transcript,
    sign_federation_pact_gesture, validate_authority_log_entry_body_bytes,
    verify_authority_signature,
};
mod federation_activation;
pub use federation_activation::federation_grant_activation;

// Re-exports reproduce the pre-split `crate::authority::` surface exactly: each
// glob carries every item of its file at that item's own visibility, so `pub`
// stays `pub` at this path and `pub(crate)` stays `pub(crate)`, with no
// hand-maintained name list to drift out of date. The globs are also the
// module's internal wiring — sibling files and `tests` share one scope through
// `use super::*`, so the file boundaries below do not change name resolution.
pub use causal_write::CausalWriteDisposition;
pub use checkpoint_adopt::VerifiedAuthorityCheckpoint;
pub use checkpoint_attest::*;
pub use checkpoint_image::*;
pub use checkpoint_policy::*;
pub use fold_engine::*;
pub use fold_state::*;
pub use handoff_equivocation::{
    AuthorityHandoffAlarm, AuthorityHandoffAlarmAck, AuthorityHandoffEquivocation,
};
pub use history_coverage::{AuthorityHistoryCoverage, AuthorityHistoryRequest};
pub use history_fetch::{
    AUTHORITY_HISTORY_PAGE_MAX, AuthorityHistoryFetch, AuthorityHistoryPage,
    AuthorityHistoryVerificationCoverage,
};
pub use history_repair::AuthorityRepairOutcome;
pub use history_transfer::{VaultRecoveryRequest, recover_vaults_independently};
pub use host_re_root::{HostReRoot, RetiredSlip};
pub use ingest_observation::*;
pub use invocation_slip::InvocationSlipBinding;
pub use log_budget::{AuthorityLogCheck, MAX_AUTHORITY_ROWS_PER_SIGNER};
pub use machine_identity::{
    LocalMachine, MACHINE_PROOF_HEADER, MachineEnrolmentRequest, PeerMachine, RequestCode,
    machine_connection_transcript, machine_proof_header_value,
};
pub use machine_profile::{
    FoldedMachine, MachineAdmitter, MachineRevision, PinnedRoot, SignerClass, TrustedMachine,
};
pub use machine_write::machine_claim_transcript;
pub use mesh_machine::{MeshMachineAddress, MeshMachineAddressEnvelope};
pub use observation_policy::*;
pub(crate) use owner_roots::anchor_signed_entry;
pub use owner_roots::{AwaitedRoot, OwnerRootView};
pub use recover_many::{
    VaultRecovered, VaultRecoveryOutcome, VaultRecoveryProof, VaultRecoveryStep, recover_vaults,
};
pub use slip::*;
pub use slip_pairing::{
    PairingDescriptor, PairingLink, PairingPinRef, PairingPrincipal, PairingRedeemed,
    format_pairing_link, format_pinned_pairing_link, pairing_binding_transcript,
    pairing_binding_transcript_pinned, parse_pairing_link, parse_pinned_pairing_link,
};
pub(crate) use slip_replay::refuse_moved_proof_freshness;
pub use slip_replay::{ProofClockAhead, ProofClockRecovery, holder_proof, holder_proof_challenge};
pub use slip_state::{FoldedSlip, SlipAuthorityState};
pub use slip_vault::HostSlipIssuer;
pub use task_actor::AdmittedTaskGrant;
pub(crate) use task_actor::{RunnerLease, TaskActorProof, TaskActorVerb};

// Crate-internal doors (first-seen sidecars and the observation clock) consumed by
// `batch`, `batch::export`, `facade`, `store` and `federation`.
pub(crate) use claim_write::{
    check_materialized_claim_causality, claim_causal_admitted, row_causal_admitted,
};
pub(crate) use first_seen_clock::*;
pub(crate) use handoff_equivocation::{HandoffEquivocations, door_refuses_retired_standing};
#[cfg(any(test, feature = "sync"))]
pub(crate) use import_order::authority_stage_order;
#[cfg(test)]
pub(crate) use log_budget::with_authority_doors_open_for_test;
pub(crate) use log_budget::{
    AuthorityDoor, AuthorityDoorView, authority_door, authority_signer_label, signer_has_standing,
};
pub(crate) use pinned_root::{drop_pinned_root_in_txn, is_pinned_root_row};
pub(crate) use pinned_root::{
    read_pin_and_earlier_in_txn, read_pin_row_in_txn, write_awaited_root_in_txn,
    write_pinned_root_in_txn,
};
pub(crate) use readonly_fold::AuthorityView;
use readonly_fold::authority_log_rows_in_txn;
use readonly_fold::authority_view_readonly_for_store_in_txn;
pub(crate) use readonly_fold::{
    AuthorityCachedFold, advance_authority_cache_generation,
    authority_fold_readonly_for_store_in_txn,
};
pub(crate) use retired_signers::{authority_row_resident, stored_authority_row};
pub(crate) use sequence_observation::record_authority_sequence_observation_in_txn;

// Module-internal only: nothing here leaves `authority`.
use ancestor_index::*;
pub(crate) use anchor_marks::anchor_mark_stands;
use entry_transition::*;
use machine_profile::{
    KeyClaim, MachineChain, apply_anchor_profile, apply_machine_profile, merge_machine_maps,
};
pub(crate) use machine_write::{
    evidence_without_machine_signature, machine_claim_needs_history, machine_claim_read_admitted,
    machine_history_authority_descends, machine_history_host_context, verify_machine_claim_in_txn,
};
use observation_policy::authority_observation_policy_in_txn;
use op_apply::*;
use sequence_observation::{AuthorityLocalObservations, authority_local_observations_in_txn};
use stale_roster::{apply_stale_roster_window, next_stale_roster_deadline};
pub use world_key_fold::{FoldedWorldKey, WORLD_KEY_WRAPS_PER_RECIPIENT, WrappedKey};
pub(crate) use world_key_support::{
    next_sequence, own_world_key_records_in_txn, owner_root_record_in_txn,
    owner_root_records_in_txn, scope_head, sign_side_entry, standing_rows,
};
pub use world_privacy::{
    Destination, EffectiveModelOrder, EffectiveRead, EffectiveWorldPrivacy, FoldedWorld,
    WorldEditStanding,
};
pub use world_privacy_door::{EditOrigin, WorldPrivacyView, world_readable_on_machine_in};
use world_strength::{WorldFrontier, apply_world_privacy, merge_world_frontiers};
