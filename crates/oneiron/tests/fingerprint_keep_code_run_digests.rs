//! K-proof for code-run legacy digests at cc184ff09aea: existing stored, keyed
//! and compared identities keep main's bytes through the fingerprint K door.
//!
//! A replay generation carries its pending step's digest, and a guarded write
//! compares it. A chat breakpoint stores its rung's offer digest. A code consent
//! binding seals its run origin's digest and stores the request digest its wait
//! id is derived from. An executed fork stores its execution pin. The emission
//! record and the team review claim are named by derived ids. A leader spawn
//! signs a slip id into the authority log. A turn program step stores its write's
//! call and answer digests. A repo provenance claim stores its request params
//! hash. A live-run binding keeps its credential digest, and an action runs under
//! its derived key. A step replay capsule stores its messages digest.
//!
//! The base modules copy exact main lines. Inline hash lines have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: a verb
//! call's verb and input, a receipt's bridge rows, a request's params, a
//! credential's and an attachment's fields, a fork pin's fields, the claims
//! field a leader sets, and the fresh id `EntityId::now()` answers there.
//! `live_fork_offer_digest` and `ForkExecutionPin::digest` are public, so the
//! test calls them directly.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_code_run_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::attempt_queue::AttemptId;
use oneiron::code_run::consent::CodeSourceTrust;
use oneiron::code_run::shadow_runner::ShadowDeterminism;
use oneiron::code_run::{
    CodeConsentRunEndpoint, CodeConsentRunOrigin, CodeConsentRunPeer, ForkExecutionPin,
    live_fork_offer_digest,
};
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::llm::run_admission::{KeyCustody, OfferBinding, OfferRoute, Payer};
use oneiron::llm::{ModelId, ModelLocality};
use oneiron::runtime_hooks::verb::{
    VerbAskCredentialRef, VerbAskCredentialSource, VerbAskDoor, VerbAskInstrument,
    VerbAskMcpCeiling,
};
use oneiron::test_doors::fingerprint_keep_code_run_digests as door;
use oneiron::{ContentPart, EdgeActorClass, EntityId, LlmMessage, LlmMessageRole};
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

/// The path main's `live_fork_offer_digest` names its hex writer by.
mod entity_id {
    pub(crate) use oneiron_contracts::entity_id::bytes_to_hex_lower;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_pending_step {
    // main cc184ff09aea: crates/oneiron/src/code_run/codec/pending_step.rs:49-49
    const PENDING_STEP_DIGEST_DOMAIN: &[u8] = b"oneiron:code-run-pending-step:v1";
    pub(crate) fn digest(bytes: Vec<u8>) -> Result<[u8; 32], ()> {
        // main cc184ff09aea: crates/oneiron/src/code_run/codec/pending_step.rs:210-213
            let mut hasher = blake3::Hasher::new();
            hasher.update(PENDING_STEP_DIGEST_DOMAIN);
            hasher.update(&bytes);
            Ok(*hasher.finalize().as_bytes())
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_live_fork {
    use oneiron::llm::run_admission::OfferBinding;
    // main cc184ff09aea: crates/oneiron/src/code_run/compaction_fork.rs:154-159
    pub fn live_fork_offer_digest(offer: &OfferBinding) -> Option<String> {
        let bytes = serde_json::to_vec(offer).ok()?;
        Some(crate::entity_id::bytes_to_hex_lower(
            blake3::hash(&bytes).as_bytes(),
        ))
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_origin {
    use oneiron::EntityId;
    use oneiron::code_run::CodeConsentRunOrigin;
    use oneiron::runtime_hooks::verb::{VerbAskCredentialSource, VerbAskDoor};
    // main cc184ff09aea: crates/oneiron/src/code_run/consent_wait/resume.rs:47-48
    /// The hash domain of an origin's digest inside a binding digest.
    const CODE_CONSENT_RUN_ORIGIN_DOMAIN: &[u8] = b"oneiron:code-consent-run-origin:v1";
    // main cc184ff09aea: crates/oneiron/src/code_run/consent_wait/resume.rs:55-118
    /// BLAKE3 over every field, for the binding digest the wait is sealed
    /// with (FIX 4606).
    pub(super) fn code_consent_run_origin_digest(
        code_consent_run_origin: &CodeConsentRunOrigin,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        let optional = |id: Option<EntityId>| id.map_or([0; 17], |id| present(id.as_bytes()));
        field(CODE_CONSENT_RUN_ORIGIN_DOMAIN);
        field(code_consent_run_origin.handle.as_bytes());
        let instrument = &code_consent_run_origin.credential.instrument;
        field(&instrument.vault);
        match &instrument.source {
            VerbAskCredentialSource::Slip { slip, fingerprint } => {
                field(b"slip");
                field(slip);
                field(fingerprint);
            }
            VerbAskCredentialSource::AttestedOwner { holder } => {
                field(b"attested_owner");
                field(holder.as_bytes());
            }
        }
        field(&instrument.ceiling);
        match &code_consent_run_origin.credential.door {
            VerbAskDoor::Facade { room } => {
                field(b"facade");
                field(&optional(*room));
            }
            VerbAskDoor::Mcp {
                connection,
                ceiling,
            } => {
                field(b"mcp");
                field(connection.as_bytes());
                // The saved registration ceiling is a typed record on main
                // (#6407), sealed by its named encoding as binding.rs seals
                // a hook snapshot.
                field(&rmp_serde::to_vec_named(ceiling).unwrap_or_default());
            }
            VerbAskDoor::McpOwner { connection } => {
                field(b"mcp_owner");
                field(connection.as_bytes());
            }
        }
        field(&[u8::from(code_consent_run_origin.credential.on_device)]);
        field(code_consent_run_origin.endpoint.as_str().as_bytes());
        field(&optional(
            code_consent_run_origin.peer.map(|peer| peer.machine),
        ));
        field(
            code_consent_run_origin
                .peer
                .as_ref()
                .map_or(&[][..], |peer| &peer.key[..]),
        );
        field(&optional(code_consent_run_origin.session));
        field(&optional(code_consent_run_origin.room_turn));
        field(&[u8::from(code_consent_run_origin.forwarded_caller)]);
        *hasher.finalize().as_bytes()
    }
    // main cc184ff09aea: crates/oneiron/src/code_run/consent_wait/resume.rs:144-148
    fn present(bytes: &[u8; 16]) -> [u8; 17] {
        let mut out = [1; 17];
        out[1..].copy_from_slice(bytes);
        out
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_fork_pin {
    use oneiron::code_sandbox::SANDBOX_WIT_WORLD_NAME;
    use oneiron::dreamer_runner::shadow_values::SHADOW_PROTOCOL_VERSION;
    // Stand-ins: the pin's fields main's lines read.
    pub(crate) struct Determinism {
        pub(crate) frozen_unix_ms: u64,
        pub(crate) rng_seed: [u8; 32],
    }
    pub(crate) struct ForkExecutionPin {
        pub(crate) start: [u8; 32],
        pub(crate) bridge_start: u64,
        pub(crate) bridge_end: u64,
        pub(crate) context: Option<[u8; 32]>,
        pub(crate) determinism: Determinism,
        pub(crate) runtime: [u8; 32],
    }
    impl ForkExecutionPin {
        // main cc184ff09aea: crates/oneiron/src/code_run/contribution/execution.rs:118-137
            /// Its digest, bound to the executor's sandbox contract as well: the WIT
            /// world and the shadow protocol the programs run under.
            #[must_use]
            pub fn digest(&self) -> [u8; 32] {
                let mut hasher = blake3::Hasher::new_derive_key("oneiron contribution fork execution pin");
                hasher.update(SANDBOX_WIT_WORLD_NAME.as_bytes());
                hasher.update(&[0]);
                hasher.update(&SHADOW_PROTOCOL_VERSION.to_be_bytes());
                hasher.update(&self.start);
                hasher.update(&self.bridge_start.to_be_bytes());
                hasher.update(&self.bridge_end.to_be_bytes());
                hasher.update(&[u8::from(self.context.is_some())]);
                if let Some(context) = &self.context {
                    hasher.update(context);
                }
                hasher.update(&self.determinism.frozen_unix_ms.to_be_bytes());
                hasher.update(&self.determinism.rng_seed);
                hasher.update(&self.runtime);
                *hasher.finalize().as_bytes()
            }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_consent_request {
    // Stand-ins: a verb call's verb and input; the identity main's call_identity
    // returns, here the verb's UTF-8, NUL, then the input bytes.
    pub(crate) struct Verb(pub(crate) &'static str);
    impl Verb {
        pub(crate) fn as_str(&self) -> &'static str {
            self.0
        }
    }
    pub(crate) struct Call {
        pub(crate) verb: Verb,
        pub(crate) input: Vec<u8>,
    }
    pub(crate) fn call_identity(verb: &str, input: &[u8]) -> Vec<u8> {
        [verb.as_bytes(), &[0], input].concat()
    }
    pub(crate) fn request_digest(call: &Call) -> [u8; 32] {
        // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/agent_verb/consent.rs:33-34
                let request_digest =
                    *blake3::hash(&call_identity(call.verb.as_str(), &call.input)).as_bytes();
        request_digest
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_emission {
    use oneiron::code_run::consent::CodeSourceTrust;
    use oneiron::code_sandbox::SandboxGuestTier;
    use oneiron::{EntityId, Error, Result};
    use sha2::{Digest, Sha256};
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/emission.rs:22-22
    const CODE_EMISSION_RECORD_ID_DOMAIN: &[u8] = b"oneiron:self-code-emission-record:v1";
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/emission.rs:186-217
    fn code_emission_record_id(
        tier: SandboxGuestTier,
        source_trust: CodeSourceTrust,
        dreamer_run_id: &str,
        run_ref: &str,
    ) -> Result<EntityId> {
        for salt in 0..=u8::MAX {
            let mut hasher = Sha256::new();
            hasher.update(CODE_EMISSION_RECORD_ID_DOMAIN);
            hasher.update([salt]);
            for part in [
                tier.as_str().as_bytes(),
                source_trust.as_str().as_bytes(),
                dreamer_run_id.as_bytes(),
                run_ref.as_bytes(),
            ] {
                let len = u64::try_from(part.len())
                    .map_err(|_| Error::ArithmeticOverflow("code emission record id material"))?;
                hasher.update(len.to_le_bytes());
                hasher.update(part);
            }
            let digest = hasher.finalize();
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            if let Ok(id) = EntityId::from_bytes(bytes) {
                return Ok(id);
            }
        }
        Err(Error::InvariantViolation(
            "code emission record id derivation failed",
        ))
    }
    pub(crate) fn id(
        tier: SandboxGuestTier,
        source_trust: CodeSourceTrust,
        dreamer_run_id: &str,
        run_ref: &str,
    ) -> Result<EntityId> {
        code_emission_record_id(tier, source_trust, dreamer_run_id, run_ref)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_leader {
    use std::cell::Cell;
    // Stand-ins: the claims field main's line sets; `EntityId::now()` answers the
    // fresh id the case names.
    thread_local! {
        static FRESH: Cell<[u8; 16]> = const { Cell::new([0; 16]) };
    }
    pub(crate) struct EntityId;
    impl EntityId {
        pub(crate) fn now() -> oneiron::EntityId {
            oneiron::EntityId::from_bytes_unchecked(FRESH.with(Cell::get))
        }
    }
    pub(crate) struct Claims {
        pub(crate) slip_id: [u8; 32],
    }
    pub(crate) fn slip_id(child: oneiron::EntityId, fresh: [u8; 16]) -> [u8; 32] {
        FRESH.with(|cell| cell.set(fresh));
        let mut claims = Claims { slip_id: [0; 32] };
        // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/leader.rs:586-590
                claims.slip_id = *blake3::Hasher::new()
                    .update(child.as_bytes())
                    .update(EntityId::now().as_bytes())
                    .finalize()
                    .as_bytes();
        claims.slip_id
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_program {
    use oneiron::{Error, Result};
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/program_step.rs:56-56
    const PROGRAM_CALL_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-write-call:v1";
    // Stand-ins: a verb call's verb and JSON input.
    pub(crate) struct Verb(pub(crate) &'static str);
    impl Verb {
        pub(crate) fn as_str(&self) -> &'static str {
            self.0
        }
    }
    pub(crate) struct Call {
        pub(crate) verb: Verb,
        pub(crate) input: serde_json::Value,
    }
    pub(crate) fn call_digest(call: &Call) -> Result<[u8; 32]> {
        // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/program_step.rs:234-241
                let input = serde_json::to_vec(&call.input)
                    .map_err(|_| Error::InvalidClaimBody("a program write's call does not encode"))?;
                let call_digest = *blake3::Hasher::new()
                    .update(PROGRAM_CALL_DOMAIN)
                    .update(call.verb.as_str().as_bytes())
                    .update(&input)
                    .finalize()
                    .as_bytes();
        Ok(call_digest)
    }
    // Stand-ins: a receipt's bridge rows, each with its outcome.
    pub(crate) struct Row {
        pub(crate) outcome: rmpv::Value,
    }
    pub(crate) struct CodeRunReplayRecord {
        pub(crate) bridge_calls: Vec<Row>,
    }
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/program_step.rs:391-403
    /// The digest of the answer a receipt keeps as its first row.
    fn answer_digest(receipt: &CodeRunReplayRecord) -> Option<[u8; 32]> {
        let row = receipt.bridge_calls.first()?;
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &row.outcome).ok()?;
        Some(
            *blake3::Hasher::new()
                .update(PROGRAM_CALL_DOMAIN)
                .update(&bytes)
                .finalize()
                .as_bytes(),
        )
    }
    pub(crate) fn answer(receipt: &CodeRunReplayRecord) -> Option<[u8; 32]> {
        answer_digest(receipt)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_repo {
    // Stand-ins: a request's sampling params and provider options; the witness
    // field main's line writes.
    pub(crate) struct Request {
        pub(crate) params: serde_json::Value,
        pub(crate) provider_options: serde_json::Value,
    }
    pub(crate) struct Witness {
        pub(crate) params_hash: String,
    }
    pub(crate) fn params_hash(request: &Request) -> Option<String> {
        // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/repo_sources.rs:56-56
                let params = serde_json::to_vec(&(&request.params, &request.provider_options)).ok()?;
        Some(Witness {
            // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/repo_sources.rs:60-60
                        params_hash: blake3::hash(&params).to_hex().to_string(),
        }
        .params_hash)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_team {
    use oneiron::attempt_queue::AttemptId;
    use oneiron::{EntityId, Error, Result};
    use sha2::{Digest, Sha256};
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/team_submit.rs:42-42
    const TEAM_SUBMIT_REVIEW_ID_DOMAIN: &[u8] = b"oneiron:self-team-submit-review:v1";
    // main cc184ff09aea: crates/oneiron/src/code_run/dispatcher/team_submit.rs:269-297
    /// The review claim's id: a domain-separated, length-prefixed digest of the
    /// leader, the team and the output. A digest that lands on a reserved
    /// sentinel is re-salted rather than truncated into one.
    fn review_claim_id(leader: AttemptId, team: &str, output_revision: &str) -> Result<EntityId> {
        for salt in 0..=u8::MAX {
            let mut hasher = Sha256::new();
            hasher.update(TEAM_SUBMIT_REVIEW_ID_DOMAIN);
            hasher.update([salt]);
            for part in [
                leader.as_bytes().as_slice(),
                team.as_bytes(),
                output_revision.as_bytes(),
            ] {
                let len = u64::try_from(part.len())
                    .map_err(|_| Error::ArithmeticOverflow("team submit review id material"))?;
                hasher.update(len.to_le_bytes());
                hasher.update(part);
            }
            let digest = hasher.finalize();
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            if let Ok(id) = EntityId::from_bytes(bytes) {
                return Ok(id);
            }
        }
        Err(Error::InvariantViolation(
            "team submit review id derivation failed",
        ))
    }
    pub(crate) fn id(leader: AttemptId, team: &str, output_revision: &str) -> Result<EntityId> {
        review_claim_id(leader, team, output_revision)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_live_credential {
    // Stand-ins: the credential's fields; the caller's locality is not hashed.
    pub(crate) type CallerLocality = u8;
    pub(crate) struct LiveRunCredential {
        pub(crate) digest: [u8; 32],
        pub(crate) locality: CallerLocality,
    }
    // main cc184ff09aea: crates/oneiron/src/code_run/live_run.rs:60-72
    impl LiveRunCredential {
        /// The credential whose idempotency identity is `principal`, on a
        /// connection at `locality`.
        #[must_use]
        pub fn of(principal: &str, locality: CallerLocality) -> Self {
            let mut hasher = blake3::Hasher::new_derive_key("oneiron live-run credential v1");
            hasher.update(principal.as_bytes());
            Self {
                digest: *hasher.finalize().as_bytes(),
                locality,
            }
        }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_live_action {
    use oneiron::{Error, Result};
    // main cc184ff09aea: crates/oneiron/src/code_run/live_run.rs:48-49
    /// The most bytes a caller's own idempotency key holds, as an action's.
    const CLIENT_KEY_MAX_BYTES: usize = 256;
    // Stand-ins: the attachment's issued handle and credential digest.
    pub(crate) struct Credential {
        pub(crate) digest: [u8; 32],
    }
    pub(crate) struct Binding {
        pub(crate) issued: [u8; 16],
        pub(crate) credential: Credential,
    }
    impl Binding {
        // main cc184ff09aea: crates/oneiron/src/code_run/live_run.rs:117-143
            /// The idempotency key an action sent through this attachment runs
            /// under: the caller's `key`, hashed into the namespace of the issued
            /// handle and the attached credential, so no other attachment or
            /// credential replays its answer. The action keeps its run's own
            /// attempt and generation partition besides.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidConfig`] for a blank key or one past 256 bytes, as an
            /// action's own key.
            pub fn action_key(&self, key: &str) -> Result<String> {
                if key.trim().is_empty() || key.len() > CLIENT_KEY_MAX_BYTES {
                    return Err(Error::InvalidConfig(
                        "action arguments do not match declared schema".to_owned(),
                    ));
                }
                let mut hasher = blake3::Hasher::new_derive_key("oneiron live-run action key v1");
                for part in [
                    self.issued.as_slice(),
                    self.credential.digest.as_slice(),
                    key.as_bytes(),
                ] {
                    hasher.update(&(part.len() as u64).to_be_bytes());
                    hasher.update(part);
                }
                Ok(format!("live-run:{}", hasher.finalize().to_hex()))
            }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_capsule {
    use oneiron::LlmMessage;
    // main cc184ff09aea: crates/oneiron/src/code_run/replay_capsule.rs:211-217
    /// The hash a captured request and the call a ladder sends for it share:
    /// their messages, which admission and a rung's binding leave as they are
    /// (the route prompt is a new first message, never a change to these).
    fn messages_digest(messages: &[LlmMessage]) -> Option<[u8; 32]> {
        let bytes = serde_json::to_vec(messages).ok()?;
        Some(*blake3::hash(&bytes).as_bytes())
    }
    pub(crate) fn digest(messages: &[LlmMessage]) -> Option<[u8; 32]> {
        messages_digest(messages)
    }
}

fn id(n: u8) -> EntityId {
    EntityId::from_bytes([n; 16]).expect("a test id is no sentinel")
}

fn texts() -> Vec<String> {
    vec![
        "a".to_owned(),
        "run-ref:01JC0D3RUN".to_owned(),
        "connector.call".to_owned(),
        "ünïcödé ✓".to_owned(),
        "nul\0inside".to_owned(),
        "x".repeat(300),
    ]
}

/// Distinct byte strings: empty, one byte, every byte value, a MessagePack map,
/// a long run, and each text's bytes.
fn byte_inputs() -> Vec<Vec<u8>> {
    let mut map = Vec::new();
    rmpv::encode::write_value(
        &mut map,
        &rmpv::Value::Map(vec![(rmpv::Value::from("step"), rmpv::Value::from(7))]),
    )
    .expect("MessagePack map");
    let mut inputs = vec![
        Vec::new(),
        vec![0],
        (0..=255).collect(),
        map,
        vec![0xA5; 4096],
    ];
    inputs.extend(texts().into_iter().map(String::into_bytes));
    inputs
}

fn offers() -> Vec<OfferBinding> {
    let base = OfferBinding {
        offer: "model-a@model.test".to_owned(),
        model: ModelId::new("vendor/model-a").expect("model id"),
        route: OfferRoute::new("fake", "https://model.test:443").expect("route"),
        locality: ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    };
    let mut offers = vec![base.clone()];
    let mut other = base.clone();
    other.offer = "model-a@other.test".to_owned();
    offers.push(other);
    let mut other = base.clone();
    other.model = ModelId::new("vendor/model-b").expect("model id");
    offers.push(other);
    let mut other = base.clone();
    other.locality = ModelLocality::OnDevice;
    offers.push(other);
    let mut other = base.clone();
    other.payer = Payer::Local;
    offers.push(other);
    let mut other = base.clone();
    other.credential_binding = None;
    offers.push(other);
    let mut other = base.clone();
    other.catalog_revision = None;
    offers.push(other);
    let mut other = base;
    other.custody = KeyCustody::Keyless;
    offers.push(other);
    offers
}

fn origins() -> Vec<CodeConsentRunOrigin> {
    let ceiling = VerbAskMcpCeiling {
        actor_ref: id(0x71),
        actor_class: EdgeActorClass::Agent,
        world: Some(id(0x72)),
        facets: ScopeAxis::All,
        write_facet: None,
        bound_verbs: Some(BTreeSet::from(["note.write".to_owned()])),
    };
    let base = CodeConsentRunOrigin {
        handle: "run-ref-1".to_owned(),
        credential: VerbAskCredentialRef {
            instrument: VerbAskInstrument {
                source: VerbAskCredentialSource::Slip {
                    slip: [0x51; 32],
                    fingerprint: [0x52; 32],
                },
                vault: [0x31; 32],
                ceiling: [0x32; 32],
            },
            door: VerbAskDoor::Facade { room: None },
            on_device: false,
            session_workspace: None,
        },
        endpoint: CodeConsentRunEndpoint::Primary,
        peer: None,
        session: None,
        room_turn: None,
        forwarded_caller: false,
    };
    let doors = [
        VerbAskDoor::Facade {
            room: Some(id(0x81)),
        },
        VerbAskDoor::Mcp {
            connection: "conn-1".to_owned(),
            ceiling: ceiling.clone(),
        },
        VerbAskDoor::Mcp {
            connection: "conn-1".to_owned(),
            ceiling: VerbAskMcpCeiling {
                facets: ScopeAxis::Some(BTreeSet::from([ScopeId(id(0x73))])),
                ..ceiling
            },
        },
        VerbAskDoor::McpOwner {
            connection: "conn-2".to_owned(),
        },
    ];
    let mut origins = vec![base.clone()];
    for door in doors {
        let mut other = base.clone();
        other.credential.door = door;
        origins.push(other);
    }
    let mut other = base.clone();
    other.credential.instrument.source =
        VerbAskCredentialSource::AttestedOwner { holder: id(0x61) };
    origins.push(other);
    let mut other = base.clone();
    other.credential.instrument.vault = [0x33; 32];
    origins.push(other);
    let mut other = base.clone();
    other.credential.instrument.ceiling = [0x34; 32];
    origins.push(other);
    let mut other = base.clone();
    other.credential.on_device = true;
    origins.push(other);
    let mut other = base.clone();
    other.handle = "run-ref-2".to_owned();
    origins.push(other);
    let mut other = base.clone();
    other.endpoint = CodeConsentRunEndpoint::ToolFirst;
    origins.push(other);
    let mut other = base.clone();
    other.peer = Some(CodeConsentRunPeer {
        machine: id(0x91),
        key: [0x92; 32],
    });
    origins.push(other);
    let mut other = base.clone();
    other.session = Some(id(0xA1));
    origins.push(other);
    let mut other = base.clone();
    other.room_turn = Some(id(0xA1));
    origins.push(other);
    let mut other = base;
    other.forwarded_caller = true;
    origins.push(other);
    origins
}

fn json_values() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!(null),
        serde_json::json!({}),
        serde_json::json!({"a": 1, "b": [true, "x"]}),
        serde_json::json!({"a": 2}),
        serde_json::json!([1, 2, 3]),
        serde_json::json!("text"),
    ]
}

fn message(role: LlmMessageRole, text: &str, signature: Option<&str>) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text: text.to_owned(),
            signature: signature.map(str::to_owned),
        }],
    }
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // emission.rs:22, pending_step.rs:49, program_step.rs:56 and team_submit.rs:42
    // name their tags in constants; contribution/execution.rs:122 and
    // live_run.rs:65/:133 inline them; their bytes are written out here.
    let recipes: [(LegacyPurpose, LegacyHash, TagMode, &[u8]); 13] = [
        (
            purposes::code_run::CAPSULE_MESSAGES,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.capsule_messages.v1",
        ),
        (
            purposes::code_run::CONSENT_REQUEST,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.consent_request.v1",
        ),
        (
            purposes::code_run::CONSENT_RUN_ORIGIN,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.consent_run_origin.v1",
        ),
        (
            purposes::code_run::EMISSION_RECORD,
            LegacyHash::Sha256,
            TagMode::HashedFirst,
            b"oneiron:self-code-emission-record:v1",
        ),
        (
            purposes::code_run::FORK_EXECUTION_PIN,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            b"oneiron contribution fork execution pin",
        ),
        (
            purposes::code_run::LEADER_SPAWN_SLIP,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.leader_spawn_slip.v1",
        ),
        (
            purposes::code_run::LIVE_FORK_OFFER,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.live_fork_offer.v1",
        ),
        (
            purposes::code_run::LIVE_RUN_ACTION_KEY,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            b"oneiron live-run action key v1",
        ),
        (
            purposes::code_run::LIVE_RUN_CREDENTIAL,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            b"oneiron live-run credential v1",
        ),
        (
            purposes::code_run::PENDING_STEP,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron:code-run-pending-step:v1",
        ),
        (
            purposes::code_run::PROGRAM_CALL,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron:dreamer:turn-program-write-call:v1",
        ),
        (
            purposes::code_run::REPO_REQUEST_PARAMS,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.code_run.repo_request_params.v1",
        ),
        (
            purposes::code_run::TEAM_SUBMIT_REVIEW,
            LegacyHash::Sha256,
            TagMode::HashedFirst,
            b"oneiron:self-team-submit-review:v1",
        ),
    ];
    for (purpose, hash, mode, tag) in recipes {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), hash);
        assert_eq!(purpose.tag_mode(), mode);
    }
}

#[test]
fn pending_step_digests_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for bytes in byte_inputs() {
        let head = door::pending_step_digest(&bytes);
        assert_eq!(Ok(head), base_pending_step::digest(bytes));
        digests.insert(head);
    }
    assert_eq!(digests.len(), byte_inputs().len());
}

#[test]
fn live_fork_offer_digests_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for offer in offers() {
        let head = live_fork_offer_digest(&offer).expect("an offer encodes");
        assert_eq!(
            Some(head.clone()),
            base_live_fork::live_fork_offer_digest(&offer)
        );
        assert_eq!(head.len(), 64);
        digests.insert(head);
    }
    assert_eq!(digests.len(), offers().len());
}

#[test]
fn consent_run_origin_digests_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for origin in origins() {
        let head = door::consent_run_origin_digest(&origin);
        assert_eq!(head, base_origin::code_consent_run_origin_digest(&origin));
        digests.insert(head);
    }
    assert_eq!(digests.len(), origins().len());
}

#[test]
fn fork_execution_pins_keep_main_s_bytes() {
    // (start, bridge window, context, frozen clock, seed, runtime) per case.
    let cases: [(
        [u8; 32],
        (u64, u64),
        Option<[u8; 32]>,
        u64,
        [u8; 32],
        [u8; 32],
    ); 8] = [
        ([0x01; 32], (0, 0), None, 0, [0x02; 32], [0x03; 32]),
        ([0x11; 32], (0, 0), None, 0, [0x02; 32], [0x03; 32]),
        ([0x01; 32], (3, 9), None, 0, [0x02; 32], [0x03; 32]),
        (
            [0x01; 32],
            (0, 0),
            Some([0x04; 32]),
            0,
            [0x02; 32],
            [0x03; 32],
        ),
        (
            [0x01; 32],
            (0, 0),
            Some([0x00; 32]),
            0,
            [0x02; 32],
            [0x03; 32],
        ),
        (
            [0x01; 32],
            (0, 0),
            None,
            1_700_000_000_000,
            [0x02; 32],
            [0x03; 32],
        ),
        ([0x01; 32], (0, 0), None, 0, [0x12; 32], [0x03; 32]),
        (
            [0x01; 32],
            (u64::MAX, u64::MAX),
            None,
            u64::MAX,
            [0x02; 32],
            [0x13; 32],
        ),
    ];
    let mut digests = BTreeSet::new();
    for (start, (bridge_start, bridge_end), context, frozen_unix_ms, rng_seed, runtime) in cases {
        let head = ForkExecutionPin {
            start,
            bridge_start,
            bridge_end,
            context,
            determinism: ShadowDeterminism {
                frozen_unix_ms,
                rng_seed,
            },
            runtime,
        }
        .digest();
        let base = base_fork_pin::ForkExecutionPin {
            start,
            bridge_start,
            bridge_end,
            context,
            determinism: base_fork_pin::Determinism {
                frozen_unix_ms,
                rng_seed,
            },
            runtime,
        };
        assert_eq!(head, base.digest());
        digests.insert(head);
    }
    assert_eq!(digests.len(), cases.len());
}

#[test]
fn consent_request_digests_keep_main_s_bytes() {
    let verbs = ["connector.call", "browser.act", "note.write"];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for verb in verbs {
        for input in byte_inputs() {
            let identity = base_consent_request::call_identity(verb, &input);
            let head = door::consent_request_digest(&identity);
            let call = base_consent_request::Call {
                verb: base_consent_request::Verb(verb),
                input,
            };
            assert_eq!(head, base_consent_request::request_digest(&call));
            digests.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, digests.len()), (33, 33));
}

#[test]
fn emission_record_ids_keep_main_s_ids() {
    let tiers = [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ];
    let trusts = [CodeSourceTrust::Trusted, CodeSourceTrust::Untrusted];
    let mut ids = BTreeSet::new();
    let mut rows = 0;
    for tier in tiers {
        for trust in trusts {
            for run in ["", "dreamer-run-1"] {
                for run_ref in texts() {
                    let head =
                        door::emission_record_id(tier, trust, run, &run_ref).expect("head id");
                    let base = base_emission::id(tier, trust, run, &run_ref).expect("main id");
                    assert_eq!(head, base);
                    ids.insert(head);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!((rows, ids.len()), (72, 72));
}

#[test]
fn leader_spawn_slip_ids_keep_main_s_bytes() {
    let mut slips = BTreeSet::new();
    let mut rows = 0;
    for child in [0x01, 0x02, 0x7F] {
        for fresh in [0x10, 0x20, 0xFE] {
            let head = door::leader_spawn_slip_id(id(child), id(fresh));
            assert_eq!(head, base_leader::slip_id(id(child), [fresh; 16]));
            slips.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, slips.len()), (9, 9));
}

#[test]
fn program_call_digests_keep_main_s_bytes() {
    let verbs = ["note.write", "task.create", "connector.call"];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for verb in verbs {
        for input in json_values() {
            let bytes = serde_json::to_vec(&input).expect("JSON");
            let head = door::program_call_digest(verb, &bytes);
            let call = base_program::Call {
                verb: base_program::Verb(verb),
                input,
            };
            assert_eq!(head, base_program::call_digest(&call).expect("main digest"));
            digests.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, digests.len()), (18, 18));
}

#[test]
fn program_answer_digests_keep_main_s_bytes() {
    let outcomes = vec![
        rmpv::Value::Nil,
        rmpv::Value::from(true),
        rmpv::Value::from(42),
        rmpv::Value::from("answer"),
        rmpv::Value::Binary(vec![0, 1, 2]),
        rmpv::Value::Array(vec![rmpv::Value::from(1), rmpv::Value::Nil]),
        rmpv::Value::Map(vec![(rmpv::Value::from("ok"), rmpv::Value::from(1))]),
    ];
    let mut digests = BTreeSet::new();
    for outcome in &outcomes {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, outcome).expect("MessagePack");
        let head = door::program_answer_digest(&bytes);
        let receipt = base_program::CodeRunReplayRecord {
            bridge_calls: vec![
                base_program::Row {
                    outcome: outcome.clone(),
                },
                base_program::Row {
                    outcome: rmpv::Value::from("a later row"),
                },
            ],
        };
        assert_eq!(Some(head), base_program::answer(&receipt));
        digests.insert(head);
    }
    assert_eq!(digests.len(), outcomes.len());
    let empty = base_program::CodeRunReplayRecord {
        bridge_calls: Vec::new(),
    };
    assert_eq!(base_program::answer(&empty), None);
}

#[test]
fn repo_params_hashes_keep_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for params in json_values() {
        for provider_options in [serde_json::json!(null), serde_json::json!({"cache": true})] {
            let bytes = serde_json::to_vec(&(&params, &provider_options)).expect("JSON");
            let head = door::repo_params_hash(&bytes);
            let request = base_repo::Request {
                params: params.clone(),
                provider_options,
            };
            assert_eq!(Some(head.clone()), base_repo::params_hash(&request));
            hashes.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, hashes.len()), (12, 12));
}

#[test]
fn team_review_claim_ids_keep_main_s_ids() {
    let mut ids = BTreeSet::new();
    let mut rows = 0;
    for leader in [0x01, 0x02] {
        let leader = AttemptId::from_bytes(&[leader; 16]).expect("attempt id");
        for team in ["", "team-a", "team-b"] {
            for output in texts() {
                let head = door::team_review_claim_id(leader, team, &output).expect("head id");
                let base = base_team::id(leader, team, &output).expect("main id");
                assert_eq!(head, base);
                ids.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, ids.len()), (36, 36));
}

#[test]
fn live_run_credential_digests_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    let mut principals = texts();
    principals.push(String::new());
    for principal in &principals {
        let head = door::live_run_credential_digest(principal);
        let base = base_live_credential::LiveRunCredential::of(principal, 7);
        assert_eq!((head, 7), (base.digest, base.locality));
        digests.insert(head);
    }
    assert_eq!(digests.len(), principals.len());
}

#[test]
fn live_run_action_keys_keep_main_s_bytes() {
    let mut keys = BTreeSet::new();
    let mut rows = 0;
    for issued in [[0x01; 16], [0x02; 16]] {
        for credential in [[0x11; 32], [0x12; 32]] {
            // main refuses a key past 256 bytes before it hashes.
            for key in texts().into_iter().filter(|key| key.len() <= 256) {
                let head = door::live_run_action_key(&issued, &credential, &key);
                let binding = base_live_action::Binding {
                    issued,
                    credential: base_live_action::Credential { digest: credential },
                };
                assert_eq!(head, binding.action_key(&key).expect("main key"));
                assert!(head.starts_with("live-run:"));
                keys.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, keys.len()), (20, 20));
}

#[test]
fn capsule_messages_digests_keep_main_s_bytes() {
    let lists = vec![
        Vec::new(),
        vec![message(LlmMessageRole::User, "hello", None)],
        vec![message(LlmMessageRole::User, "hello", Some("sig"))],
        vec![
            message(LlmMessageRole::System, "be brief", None),
            message(LlmMessageRole::User, "hello", None),
        ],
        vec![message(LlmMessageRole::Assistant, "hi", None)],
        vec![message(LlmMessageRole::Tool, "{\"ok\":true}", None)],
    ];
    let mut digests = BTreeSet::new();
    for messages in &lists {
        let head = door::capsule_messages_digest(messages).expect("messages encode");
        assert_eq!(Some(head), base_capsule::digest(messages));
        digests.insert(head);
    }
    assert_eq!(digests.len(), lists.len());
}
