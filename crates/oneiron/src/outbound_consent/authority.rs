//! Frozen payload, keyed binding authority, and grant-scope digest.

use std::fmt;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::ScopedCapabilityProvenance;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentLedgerError, OutboundAuthorizationBinding, derive_intent_id,
};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;

use super::scope::{
    ScopedMcpCallContext, ScopedMcpConsentDecision, ScopedMcpEscalationReason,
    evaluate_scoped_mcp_call,
};

#[cfg(test)]
std::thread_local! {
    static FROZEN_MCP_PAYLOAD_FREEZE_EVENTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Once-serialized payload consumed by the durable outbound pipeline.
pub struct FrozenMcpPayload {
    pub(super) bytes: Vec<u8>,
    #[cfg(test)]
    pub(super) freeze_event_baseline: usize,
}

impl FrozenMcpPayload {
    /// Freezes caller-serialized bytes. No later stage has a serialization
    /// API; the buffer is moved into the ledger request unchanged.
    #[must_use]
    pub fn new(serialized: Vec<u8>) -> Self {
        #[cfg(test)]
        let freeze_event_baseline = FROZEN_MCP_PAYLOAD_FREEZE_EVENTS.with(|counter| {
            let baseline = counter.get();
            counter.set(baseline.wrapping_add(1));
            baseline
        });
        Self {
            bytes: serialized,
            #[cfg(test)]
            freeze_event_baseline,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[cfg(test)]
    pub(crate) const fn freeze_event_baseline(&self) -> usize {
        self.freeze_event_baseline
    }

    #[cfg(test)]
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for FrozenMcpPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenMcpPayload")
            .field(
                "bytes",
                &format_args!("[{} bytes redacted]", self.bytes.len()),
            )
            .finish()
    }
}

/// Keyed authority that mints and verifies opaque ledger bindings.
pub struct OutboundBindingAuthority {
    key: [u8; 32],
}

impl OutboundBindingAuthority {
    /// Derives a device-local binding key from the vault's durable signing
    /// secret. The intent ledger is device-local, so recovery sees the same
    /// authority after restart without syncing secret material.
    pub fn for_vault(vault: &Vault) -> Result<Self> {
        let mut seed = None;
        vault.with_write_txn(|wtxn| {
            let identity = crate::identity::ensure_device_identity_in_txn(vault, wtxn)?;
            seed = Some(identity.signing_key.to_bytes());
            Ok(())
        })?;
        Ok(Self::from_secret(seed.expect("identity closure ran on Ok")))
    }

    /// Builds a session-scoped authority from 32 bytes of caller-managed
    /// cryptographic secret material.
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            key: blake3::derive_key("oneiron.outbound.authorization_binding.v2", &secret),
        }
    }

    /// Mints only after the persisted live grant passes every scoped-consent
    /// axis. The caller's grant copy is never an authorization authority.
    #[expect(clippy::too_many_arguments)]
    pub fn authorize_request(
        &self,
        vault: &Vault,
        grant_id: EntityId,
        _caller_grant: &StandingOutboundGrant,
        principal_ref: &str,
        attempt_id: AttemptId,
        call_seq: u64,
        call: &ScopedMcpCallContext,
        payload: &[u8],
    ) -> std::result::Result<ScopedMcpAuthorization, IntentLedgerError> {
        let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
            return Ok(ScopedMcpAuthorization {
                decision: ScopedMcpConsentDecision::Escalate(
                    ScopedMcpEscalationReason::InvalidGrant,
                ),
                binding: None,
            });
        };
        if grant.principal_ref != principal_ref {
            return Ok(ScopedMcpAuthorization {
                decision: ScopedMcpConsentDecision::Escalate(
                    ScopedMcpEscalationReason::WrongPrincipal,
                ),
                binding: None,
            });
        }
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let current_policy_floor =
            crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?;
        let decision = if grant.is_active_under_policy(&current_policy_floor) {
            grant.scope.scoped_mcp_grant().map_or(
                ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant),
                |scope| evaluate_scoped_mcp_call(scope, call.as_call()),
            )
        } else {
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
        };
        if decision != ScopedMcpConsentDecision::AutoFire {
            return Ok(ScopedMcpAuthorization {
                decision,
                binding: None,
            });
        }

        let payload_hash = *blake3::hash(payload).as_bytes();
        let intent_id = derive_intent_id(
            attempt_id,
            call_seq,
            &call.server,
            &call.tool,
            &payload_hash,
        )?;
        let binding = self.binding_for_identity(
            grant_id,
            &grant,
            &intent_id,
            &call.server,
            &call.tool,
            &payload_hash,
            Some(&call.resolved_endpoint),
        );
        Ok(ScopedMcpAuthorization {
            decision,
            binding: Some(binding),
        })
    }

    /// Mints the v2 binding AND the typed scoped capability provenance from the
    /// same serialized write snapshot that admitted and accounted the new
    /// effect.
    ///
    /// The provenance is created only here, and only after the live grant, the
    /// principal, the policy floor, the scoped scope, the scoped call, and the
    /// safe canonical server have all been admitted on this txn — it is the one
    /// value that later carries capability authority into the durable ledger
    /// and recovery (ONE-1885).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn mint_scoped_binding_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        grant_id: EntityId,
        principal_ref: &str,
        intent_id: &[u8; 32],
        call: &ScopedMcpCallContext,
        payload_hash: &[u8; 32],
    ) -> std::result::Result<
        Option<(OutboundAuthorizationBinding, ScopedCapabilityProvenance)>,
        IntentLedgerError,
    > {
        let Some(grant) =
            crate::outbound_grant::standing_outbound_grant_in_txn(&vault.store, txn, &grant_id)?
        else {
            return Ok(None);
        };
        if grant.principal_ref != principal_ref {
            return Ok(None);
        }
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        if !grant.is_active_under_policy(&policy.read_frontier_hash()?) {
            return Ok(None);
        }
        let Some(scope) = grant.scope.scoped_mcp_grant() else {
            return Ok(None);
        };
        if evaluate_scoped_mcp_call(scope, call.as_call()) != ScopedMcpConsentDecision::AutoFire {
            return Ok(None);
        }
        // The admitted call's server is safe and canonical (the scoped-consent
        // axes just proved it), so this is the real engine-produced per-grant
        // key identity — not a spelling anyone asserted.
        let Some(capability) = ScopedCapabilityProvenance::mint(&call.server, &grant_id) else {
            return Ok(None);
        };
        Ok(Some((
            self.binding_for_identity(
                grant_id,
                &grant,
                intent_id,
                &call.server,
                &call.tool,
                payload_hash,
                Some(&call.resolved_endpoint),
            ),
            capability,
        )))
    }

    /// Re-validates authenticity and current grant liveness immediately
    /// before a send, including recovery sends from persisted frozen bytes.
    pub fn validate_frozen_call(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<OutboundBindingValidation> {
        Ok(match self.validate_frozen_call_grant(vault, call)? {
            FrozenCallValidation::Valid => OutboundBindingValidation::Valid,
            FrozenCallValidation::Rejected(validation) => validation,
        })
    }

    fn validate_frozen_call_grant(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<FrozenCallValidation> {
        self.validate_frozen_call_grant_with_liveness(vault, call, true)
    }

    pub(crate) fn validate_frozen_call_grant_for_recovery(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
    ) -> Result<FrozenCallValidation> {
        self.validate_frozen_call_grant_with_liveness(vault, call, false)
    }

    fn validate_frozen_call_grant_with_liveness(
        &self,
        vault: &Vault,
        call: &FrozenOutboundCall,
        require_live_grant: bool,
    ) -> Result<FrozenCallValidation> {
        if call.binding_version() != crate::outbound_intent_ledger::OUTBOUND_BINDING_VERSION {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Invalid,
            ));
        }
        let Some(binding) = call.authorization_binding() else {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Missing,
            ));
        };
        let Some(intent_id) = call.intent_id() else {
            return Ok(FrozenCallValidation::Rejected(
                OutboundBindingValidation::Invalid,
            ));
        };
        let current_policy_floor = if require_live_grant {
            let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
            Some(crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?)
        } else {
            None
        };
        // A frozen call that carries typed capability provenance names its own
        // grant: check exactly that grant rather than searching for whichever
        // grant reproduces the binding (ONE-1885). Ordinary calls keep the scan.
        let candidates = match call.capability_provenance() {
            Some(capability) => vec![capability.grant_id()],
            None => vault.entities_by_type(ENTITY_TYPE_OUTBOUND_GRANT)?,
        };
        for grant_id in candidates {
            let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
                if call.capability_provenance().is_some() {
                    return Ok(FrozenCallValidation::Rejected(
                        OutboundBindingValidation::Invalid,
                    ));
                }
                return Err(Error::CorruptedIndex("outbound grant type index row"));
            };
            let expected = self.binding_for_identity(
                grant_id,
                &grant,
                intent_id,
                call.server(),
                call.tool(),
                call.payload_hash(),
                call.resolved_endpoint(),
            );
            if !constant_time_eq(binding.as_bytes(), expected.as_bytes()) {
                continue;
            }
            if current_policy_floor
                .as_ref()
                .is_some_and(|floor| !grant.is_active_under_policy(floor))
            {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::GrantNotLive,
                ));
            }
            let Some(scope) = grant.scope.scoped_mcp_grant() else {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            };
            if scope.server != call.server() || scope.tool != call.tool() {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            }
            if call.resolved_endpoint().is_none_or(|endpoint| {
                !scope
                    .endpoint_allowlist
                    .iter()
                    .any(|allowed| allowed == endpoint)
            }) {
                return Ok(FrozenCallValidation::Rejected(
                    OutboundBindingValidation::Invalid,
                ));
            }
            return Ok(FrozenCallValidation::Valid);
        }
        Ok(FrozenCallValidation::Rejected(
            OutboundBindingValidation::Invalid,
        ))
    }

    /// Commits the granting scope digest and the selected per-call endpoint.
    #[expect(clippy::too_many_arguments)]
    fn binding_for_identity(
        &self,
        grant_id: EntityId,
        grant: &StandingOutboundGrant,
        intent_id: &[u8; 32],
        server: &str,
        tool: &str,
        payload_hash: &[u8; 32],
        resolved_endpoint: Option<&str>,
    ) -> OutboundAuthorizationBinding {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        binding_hash_bytes(&mut hasher, b"oneiron.outbound.authorization_binding.v2");
        binding_hash_bytes(&mut hasher, grant_id.as_bytes());
        binding_hash_bytes(&mut hasher, intent_id);
        binding_hash_str(&mut hasher, server);
        binding_hash_str(&mut hasher, tool);
        binding_hash_bytes(&mut hasher, payload_hash);
        match resolved_endpoint {
            Some(endpoint) => {
                hasher.update(&[1]);
                binding_hash_str(&mut hasher, endpoint);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        binding_hash_bytes(&mut hasher, &grant_scope_binding_digest(grant));
        OutboundAuthorizationBinding::new(*hasher.finalize().as_bytes())
    }
}

impl fmt::Debug for OutboundBindingAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundBindingAuthority")
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Result of the authenticated per-call consent step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedMcpAuthorization {
    pub decision: ScopedMcpConsentDecision,
    pub binding: Option<OutboundAuthorizationBinding>,
}

/// Binding status checked at the final transport boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundBindingValidation {
    Valid,
    Missing,
    Invalid,
    GrantNotLive,
}

pub(crate) enum FrozenCallValidation {
    Valid,
    Rejected(OutboundBindingValidation),
}

fn grant_scope_binding_digest(grant: &StandingOutboundGrant) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    binding_hash_bytes(
        &mut hasher,
        b"oneiron.outbound.authorization_grant_scope.v1",
    );
    binding_hash_bytes(&mut hasher, &grant.binding_diff_handle);
    binding_hash_bytes(&mut hasher, &grant.read_frontier_hash);
    match &grant.scope {
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            binding_hash_str(&mut hasher, "scoped_mcp");
            binding_hash_str(&mut hasher, server);
            binding_hash_str(&mut hasher, tool);
            binding_hash_str(&mut hasher, data_class_ceiling.as_str());
            for endpoint in endpoint_allowlist {
                binding_hash_str(&mut hasher, endpoint);
            }
        }
        _ => binding_hash_str(&mut hasher, "not_scoped_mcp"),
    }
    *hasher.finalize().as_bytes()
}

fn binding_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    binding_hash_bytes(hasher, value.as_bytes());
}

fn binding_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
pub(crate) fn observed_freeze_events_since(baseline: usize) -> usize {
    FROZEN_MCP_PAYLOAD_FREEZE_EVENTS.with(|counter| counter.get().wrapping_sub(baseline))
}

#[cfg(not(test))]
#[allow(dead_code)]
pub(super) const fn observed_freeze_events_since(_baseline: ()) -> usize {
    0
}
