use super::*;
use crate::entity_id::EntityId;
use crate::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, ScopeId, SelectorRange,
    base_world_axis, encode_federation_pact_scope,
};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::temporal::TimeRange;
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::time::{Duration, Instant};

mod actor_binding;
mod basic_fold;
mod cooperative_deletion;
mod critical_confirm;
mod federation_confirm;
mod federation_lifecycle;
mod federation_merge;
mod fork_ancestry;
mod fork_quarantine;
mod fork_resolution;
mod fork_scoping;
mod foundations;
mod hosted_consent;
mod observation_safety;
mod peer_roster;
mod readonly_fold;
mod revoke_freeze_bypass;
mod support;
mod tier_floor;
mod widen_veto;

mod causal_claim;
mod checkpoint;
mod history_transfer;
mod recovery_ceremony;
mod retired_ceiling;
