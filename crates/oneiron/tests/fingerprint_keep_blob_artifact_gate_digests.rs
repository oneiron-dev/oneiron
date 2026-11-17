//! K-proof for blob-artifact and Gate legacy digests at 26f4e0c559a: existing
//! keyed, compared and bound identities keep main's bytes through the
//! fingerprint K door.
//!
//! An e-sign act called with no key sends a key derived from its invocation,
//! and a retry naming the same invocation derives it again. A seal stores its
//! output's SHA-256, and every read of the sealed PDF compares the bytes with
//! it. A QR capability's digest keys its token row. A signature image's id
//! names its stored artifact and binding row. A standing outbound grant and a
//! witnessed MESSAGE write are bound by their digests.
//!
//! The base modules copy exact main lines. Inline hash lines have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: a
//! capability's raw text, a seal's stored hash, an upload capability's
//! recipient, a policy's frontier hash and main's refusal of an image id.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_blob_artifact_gate_digests`.
#![cfg(oneiron_test_support)]

use oneiron::blob_artifact::esign::{EsignOutboundVerb, EsignQrCapability};
use oneiron::booking::DisclosureRung;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::store::verb_invocation::InvocationId;
use oneiron::test_doors::fingerprint_keep_blob_artifact_gate_digests as door;
use oneiron::write_envelope::WriteActor;
use oneiron::{EdgeActorClass, EntityId};
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

/// The path main's `invocation_key` names its hex writer by.
mod entity_id {
    pub(crate) use oneiron_contracts::entity_id::bytes_to_hex_lower;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_dispatch_key {
    use oneiron::blob_artifact::esign::EsignOutboundVerb;
    use oneiron::store::verb_invocation::InvocationId;
    use oneiron::EntityId;
    // main 26f4e0c559a: crates/oneiron-store/src/blob_artifact/esign/dispatch_key.rs:20-24
    /// The BLAKE3 domain of a no-key act's key derived from its invocation.
    pub const NO_KEY_CALL_DOMAIN: &[u8] = b"oneiron.esign.dispatch.no_key.call.v1";
    /// How many bytes of that digest the key keeps, as lower hex: a fresh
    /// nonce's length.
    pub const NO_KEY_CALL_KEY_BYTES: usize = 16;
    // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/dispatch_key.rs:48-80
    /// The key a no-key call named `invocation` derives: BLAKE3 over the domain,
    /// the actor, the act, the document and the invocation, each length-framed
    /// (u64 little-endian), and the principal tagged present (1) or absent (0).
    fn invocation_key(
        verb: EsignOutboundVerb,
        document: EntityId,
        actor: EntityId,
        on_behalf_of: Option<&str>,
        invocation: InvocationId,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NO_KEY_CALL_DOMAIN);
        for part in [
            actor.to_hex().as_str(),
            verb.as_str(),
            document.to_hex().as_str(),
            invocation.to_hex().as_str(),
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        match on_behalf_of {
            Some(principal) => {
                hasher.update(&[1]);
                hasher.update(&(principal.len() as u64).to_le_bytes());
                hasher.update(principal.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        crate::entity_id::bytes_to_hex_lower(&hasher.finalize().as_bytes()[..NO_KEY_CALL_KEY_BYTES])
    }
    pub(crate) fn key(
        verb: EsignOutboundVerb,
        document: EntityId,
        actor: EntityId,
        on_behalf_of: Option<&str>,
        invocation: InvocationId,
    ) -> String {
        invocation_key(verb, document, actor, on_behalf_of, invocation)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_sealed_pdf {
    use sha2::{Digest, Sha256};
    /// A seal's stored output hash, as the QR download reads it.
    pub(crate) struct Sealed {
        pub(crate) sha256: [u8; 32],
    }
    /// The signing-link read's check of a pinned PDF version.
    pub(crate) fn read_differs(pair: &(Vec<u8>, ()), sha256: [u8; 32]) -> bool {
        true
        // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/public_read.rs:210-210
                    && <[u8; 32]>::from(Sha256::digest(&pair.0)) != sha256
    }
    /// The signing-link read's check of a pinned PDF's bytes.
    pub(crate) fn bytes_differ(bytes: &[u8], sha256: [u8; 32]) -> bool {
        true
        // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/public_read.rs:288-288
                    && <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256
    }
    /// The QR download's check of a sealed PDF.
    pub(crate) fn qr_download_differs(bytes: &[u8], sealed: &Sealed) -> bool {
        // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/qr_capability.rs:409-409
                if <[u8; 32]>::from(Sha256::digest(&bytes)) != sealed.sha256 {
            return true;
        }
        false
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_qr_capability {
    use sha2::{Digest, Sha256};
    /// A capability's raw 64 lowercase hex characters.
    pub(crate) struct Capability(pub(crate) String);
    impl Capability {
        // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/qr_capability.rs:149-151
            fn digest(&self) -> [u8; 32] {
                Sha256::digest(self.0.as_bytes()).into()
            }
    }
    pub(crate) fn digest(raw: &str) -> [u8; 32] {
        Capability(raw.to_owned()).digest()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_signature_image {
    use oneiron::EntityId;
    /// An upload capability's recipient.
    pub(crate) struct Capability {
        pub(crate) recipient: String,
    }
    /// Main's refusal of an image id (`esign::model::invalid`).
    fn invalid(reason: &'static str) -> oneiron::Error {
        oneiron::Error::InvalidConfig(reason.to_owned())
    }
    pub(crate) fn image_id(
        id: EntityId,
        cap: &Capability,
        canonical: Vec<u8>,
    ) -> Result<EntityId, oneiron::Error> {
        // main 26f4e0c559a: crates/oneiron/src/blob_artifact/esign/signature_image.rs:212-221
                    let mut hash = blake3::Hasher::new();
                    hash.update(b"esign.signature_image.v1");
                    hash.update(id.as_bytes());
                    hash.update(cap.recipient.as_bytes());
                    hash.update(&canonical);
                    let image = EntityId::from_bytes(
                        hash.finalize().as_bytes()[..16]
                            .try_into()
                            .map_err(|_| invalid("image id"))?,
                    )?;
        Ok(image)
    }
}

/// Main's Gate lines name their helpers `pub(in crate::gate)`.
#[allow(unreachable_pub)]
mod gate {
    use oneiron::EdgeActorClass;
    #[rustfmt::skip]
    // main 26f4e0c559a: crates/oneiron/src/gate/doors/peripheral.rs:124-126
    pub(in crate::gate) const fn edge_actor_class_str(actor_class: EdgeActorClass) -> &'static str {
        actor_class.gate_actor_class()
    }

    #[rustfmt::skip]
    pub(crate) mod base_frontier_hash {
        use sha2::{Digest, Sha256};
        // main 26f4e0c559a: crates/oneiron/src/gate/resolution/frontier_hash.rs:884-891
        pub(in crate::gate) fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
            let Some(value) = value else {
                hash_bool(hasher, false);
                return;
            };
            hash_bool(hasher, true);
            hash_str(hasher, value);
        }

        // main 26f4e0c559a: crates/oneiron/src/gate/resolution/frontier_hash.rs:911-926
        pub(crate) fn hash_str(hasher: &mut Sha256, value: &str) {
            hash_bytes(hasher, value.as_bytes());
        }

        pub(crate) fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
            hash_len(hasher, bytes.len());
            hasher.update(bytes);
        }

        pub(in crate::gate) fn hash_bool(hasher: &mut Sha256, value: bool) {
            hasher.update([u8::from(value)]);
        }

        fn hash_len(hasher: &mut Sha256, value: usize) {
            hasher.update((value as u64).to_le_bytes());
        }
    }

    #[rustfmt::skip]
    pub(crate) mod base_standing_grant {
        use super::base_frontier_hash::{hash_bytes, hash_opt_str, hash_str};
        use oneiron::error::{Error, RecordError, Result};
        use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
        use sha2::{Digest, Sha256};
        /// A policy's read frontier hash, the binding's second half.
        pub(crate) struct PolicyManifestResolution;
        impl PolicyManifestResolution {
            pub(crate) fn read_frontier_hash(&self) -> Result<[u8; 32]> {
                Ok([7; 32])
            }
        }
        // main 26f4e0c559a: crates/oneiron/src/gate/doors/peripheral.rs:232-285
        pub(crate) fn standing_outbound_grant_binding_parts(
            intent: &GrantMintIntent,
            policy: &PolicyManifestResolution,
        ) -> Result<(Vec<u8>, [u8; 32])> {
            let mut hasher = Sha256::new();
            hash_bytes(&mut hasher, b"oneiron.gate.standing_outbound_grant.v0");
            hash_str(&mut hasher, intent.principal_ref.trim());
            hash_str(&mut hasher, intent.origin_component_id.trim());
            hash_str(&mut hasher, intent.origin_action_id.trim());
            hash_opt_str(&mut hasher, intent.origin_receipt_ref.as_deref());
            match &intent.scope {
                GrantMintIntentScope::JustOnce { .. } => {
                    return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                        "non-standing grant scope is not supported",
                    )));
                }
                GrantMintIntentScope::Contact { contact_ref } => {
                    hash_str(&mut hasher, "contact");
                    hash_str(&mut hasher, contact_ref.trim());
                }
                GrantMintIntentScope::VerbClass { verb_class } => {
                    hash_str(&mut hasher, "verb_class");
                    hash_str(&mut hasher, verb_class.trim());
                }
                GrantMintIntentScope::Channel { channel } => {
                    hash_str(&mut hasher, "channel");
                    hash_str(&mut hasher, channel.trim());
                }
                GrantMintIntentScope::BundleExactSends { .. } => {
                    return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                        "non-standing grant scope is not supported",
                    )));
                }
                GrantMintIntentScope::BriefVerbClass {
                    brief_ref,
                    verb_class,
                } => {
                    hash_str(&mut hasher, "brief_verb_class");
                    hash_str(&mut hasher, brief_ref.trim());
                    hash_str(&mut hasher, verb_class.trim());
                }
                GrantMintIntentScope::ArtifactPublish { artifact } => {
                    hash_str(&mut hasher, "artifact_publish");
                    hash_str(&mut hasher, artifact.trim());
                }
                GrantMintIntentScope::Calendar { .. } => {
                    return Err(Error::Record(RecordError::InvalidOutboundGrantBody(
                        "calendar disclosure scope is a read grant, not an outbound grant scope",
                    )));
                }
            }
            Ok((hasher.finalize().to_vec(), policy.read_frontier_hash()?))
        }

    }

    #[rustfmt::skip]
    pub(crate) mod base_witness_message {
        use super::edge_actor_class_str;
        use oneiron::write_envelope::WriteActor;
        use oneiron::EntityId;
        use sha2::{Digest, Sha256};
        // main 26f4e0c559a: crates/oneiron/src/gate/witness_message/binding.rs:5-21
        /// The domain tag for the witness-message binding hash. Bump the suffix if the
        /// hashed tuple below ever changes; the value is an ABI.
        const WITNESS_MESSAGE_BINDING_DOMAIN: &[u8] = b"oneiron.gate.witness_message.v1";

        /// The content-addressed binding for one authorized MESSAGE write: the actor
        /// that presented it and the canonical body bytes that carry every envelope
        /// axis. Deterministic across processes and stable as an ABI.
        pub(super) fn witness_message_binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
            let entity_ref: EntityId = actor.entity_ref();
            let mut hasher = Sha256::new();
            hasher.update(WITNESS_MESSAGE_BINDING_DOMAIN);
            hasher.update(edge_actor_class_str(actor.actor_class()).as_bytes());
            hasher.update(entity_ref.as_bytes());
            hasher.update((body.len() as u64).to_le_bytes());
            hasher.update(body);
            hasher.finalize().into()
        }
        pub(crate) const DOMAIN: &[u8] = WITNESS_MESSAGE_BINDING_DOMAIN;
        pub(crate) fn binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
            witness_message_binding(actor, body)
        }
    }
}

fn id(n: u8) -> EntityId {
    EntityId::from_bytes_unchecked([n; 16])
}

fn ids() -> Vec<EntityId> {
    vec![
        id(0),
        id(1),
        id(0x7f),
        id(0xff),
        EntityId::from_bytes_unchecked(*b"0123456789abcdef"),
    ]
}

fn texts() -> Vec<String> {
    vec![
        String::new(),
        "a".to_owned(),
        "owner".to_owned(),
        " padded \t".to_owned(),
        "contact:42".to_owned(),
        "\u{fc}-\u{f1}-\u{1f600}".to_owned(),
        "nul\0byte".to_owned(),
        "x".repeat(300),
    ]
}

fn byte_inputs() -> Vec<Vec<u8>> {
    let mut seed: u64 = 0x5eed_0f_b10b;
    let noise: Vec<u8> = (0..10_000)
        .map(|_| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 56) as u8
        })
        .collect();
    vec![
        Vec::new(),
        vec![0],
        b"%PDF-1.7\n%%EOF\n".to_vec(),
        (0..=255).collect(),
        vec![0xff; 4096],
        noise,
    ]
}

fn verbs() -> Vec<EsignOutboundVerb> {
    vec![
        EsignOutboundVerb::SendForSignature,
        EsignOutboundVerb::Remind,
        EsignOutboundVerb::Void,
        EsignOutboundVerb::Extend { expires_at: 0 },
        EsignOutboundVerb::Extend {
            expires_at: 1_800_000_000,
        },
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    use purposes::blob_artifact;
    let recipes = [
        (
            blob_artifact::ESIGN_NO_KEY_CALL,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            "oneiron.esign.dispatch.no_key.call.v1",
        ),
        (
            blob_artifact::ESIGN_QR_CAPABILITY,
            LegacyHash::Sha256,
            TagMode::NotHashed,
            "oneiron.blob_artifact.esign_qr_capability.v1",
        ),
        (
            blob_artifact::ESIGN_SIGNATURE_IMAGE,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            "esign.signature_image.v1",
        ),
        (
            blob_artifact::SEALED_PDF_SHA256,
            LegacyHash::Sha256,
            TagMode::NotHashed,
            "oneiron.blob_artifact.sealed_pdf_sha256.v1",
        ),
        (
            purposes::gate::STANDING_OUTBOUND_GRANT,
            LegacyHash::Sha256,
            TagMode::NotHashed,
            "oneiron.gate.standing_outbound_grant_binding.v1",
        ),
        (
            purposes::gate::WITNESS_MESSAGE,
            LegacyHash::Sha256,
            TagMode::HashedFirst,
            "oneiron.gate.witness_message.v1",
        ),
    ];
    for (purpose, hash, tag_mode, tag) in recipes {
        assert_eq!(
            (purpose.hash(), purpose.tag_mode(), purpose.tag()),
            (hash, tag_mode, tag)
        );
    }
    assert_eq!(
        blob_artifact::ESIGN_NO_KEY_CALL.tag().as_bytes(),
        base_dispatch_key::NO_KEY_CALL_DOMAIN
    );
    assert_eq!(
        purposes::gate::WITNESS_MESSAGE.tag().as_bytes(),
        gate::base_witness_message::DOMAIN
    );
}

#[test]
fn no_key_call_keys_keep_main_s_bytes() {
    let principals: Vec<Option<String>> = std::iter::once(None)
        .chain(texts().into_iter().map(Some))
        .collect();
    let mut rows = 0;
    for verb in verbs() {
        for document in ids() {
            for actor in [id(2), id(0xa5)] {
                for principal in &principals {
                    for invocation in [
                        InvocationId([0; 16]),
                        InvocationId([9; 16]),
                        InvocationId(*b"fedcba9876543210"),
                    ] {
                        let main = base_dispatch_key::key(
                            verb,
                            document,
                            actor,
                            principal.as_deref(),
                            invocation,
                        );
                        let head = door::esign_no_key_call_key(
                            verb,
                            document,
                            actor,
                            principal.as_deref(),
                            invocation,
                        );
                        assert_eq!(
                            head, main,
                            "{verb:?} {document:?} {actor:?} {principal:?} {invocation:?}"
                        );
                        assert_eq!(head.len(), 32);
                        rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!(rows, 5 * 5 * 2 * 9 * 3);
}

#[test]
fn sealed_pdf_sha256s_keep_main_s_bytes() {
    for bytes in byte_inputs() {
        let head = door::sealed_pdf_sha256(&bytes);
        let sealed = base_sealed_pdf::Sealed { sha256: head };
        assert!(
            !base_sealed_pdf::read_differs(&(bytes.clone(), ()), head),
            "{} bytes",
            bytes.len()
        );
        assert!(
            !base_sealed_pdf::bytes_differ(&bytes, head),
            "{} bytes",
            bytes.len()
        );
        assert!(
            !base_sealed_pdf::qr_download_differs(&bytes, &sealed),
            "{} bytes",
            bytes.len()
        );
        let mut other = head;
        other[31] ^= 1;
        assert!(base_sealed_pdf::read_differs(&(bytes.clone(), ()), other));
        assert!(base_sealed_pdf::bytes_differ(&bytes, other));
        assert!(base_sealed_pdf::qr_download_differs(
            &bytes,
            &base_sealed_pdf::Sealed { sha256: other }
        ));
    }
}

#[test]
fn qr_capability_digests_keep_main_s_bytes() {
    let mut raws: Vec<String> = ["0", "9", "a", "f"].iter().map(|c| c.repeat(64)).collect();
    raws.push("0123456789abcdef".repeat(4));
    raws.push("fedcba9876543210".repeat(4));
    for raw in raws {
        let token =
            EsignQrCapability::parse(&raw).expect("a 64-character lowercase hex capability parses");
        assert_eq!(
            door::esign_qr_capability_digest(&token),
            base_qr_capability::digest(&raw),
            "{raw}"
        );
    }
}

#[test]
fn signature_image_ids_keep_main_s_ids() {
    let mut rows = 0;
    for document in ids() {
        for recipient in texts() {
            for canonical in byte_inputs() {
                let main = base_signature_image::image_id(
                    document,
                    &base_signature_image::Capability {
                        recipient: recipient.clone(),
                    },
                    canonical.clone(),
                );
                let head = door::esign_signature_image_id(document, &recipient, &canonical);
                assert_eq!(
                    head.as_ref().ok(),
                    main.as_ref().ok(),
                    "{document:?} {recipient:?} {}",
                    canonical.len()
                );
                assert_eq!(head.is_err(), main.is_err());
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 5 * 8 * 6);
}

fn intents() -> Vec<GrantMintIntent> {
    let mut scopes = vec![
        GrantMintIntentScope::JustOnce { effect_ref: None },
        GrantMintIntentScope::JustOnce {
            effect_ref: Some("effect:1".to_owned()),
        },
        GrantMintIntentScope::BundleExactSends {
            send_refs: vec!["send:1".to_owned()],
        },
        GrantMintIntentScope::Calendar {
            calendar_ref: "cal:1".to_owned(),
            rung: DisclosureRung::Busy,
        },
    ];
    for text in texts() {
        scopes.push(GrantMintIntentScope::Contact {
            contact_ref: text.clone(),
        });
        scopes.push(GrantMintIntentScope::VerbClass {
            verb_class: text.clone(),
        });
        scopes.push(GrantMintIntentScope::Channel {
            channel: text.clone(),
        });
        scopes.push(GrantMintIntentScope::BriefVerbClass {
            brief_ref: text.clone(),
            verb_class: "outbound.send".to_owned(),
        });
        scopes.push(GrantMintIntentScope::BriefVerbClass {
            brief_ref: "brief:7".to_owned(),
            verb_class: text.clone(),
        });
        scopes.push(GrantMintIntentScope::ArtifactPublish { artifact: text });
    }
    let mut intents = Vec::new();
    for (n, scope) in scopes.into_iter().enumerate() {
        let texts = texts();
        let pick = |k: usize| texts[(n + k) % texts.len()].clone();
        intents.push(GrantMintIntent {
            principal_ref: pick(0),
            origin_component_id: pick(1),
            origin_action_id: pick(2),
            origin_receipt_ref: (n % 3 != 0).then(|| pick(3)),
            scope,
        });
    }
    intents
}

#[test]
fn standing_outbound_grant_bindings_keep_main_s_bytes() {
    let policy = gate::base_standing_grant::PolicyManifestResolution;
    let (mut bound, mut refused) = (0, 0);
    for intent in intents() {
        let main =
            gate::base_standing_grant::standing_outbound_grant_binding_parts(&intent, &policy);
        let head = door::standing_outbound_grant_binding(&intent);
        match (head, main) {
            (Ok(head), Ok((main, frontier))) => {
                assert_eq!(head.to_vec(), main, "{intent:?}");
                assert_eq!(frontier, [7; 32]);
                bound += 1;
            }
            (Err(_), Err(_)) => refused += 1,
            (head, main) => panic!("{intent:?}: head {head:?}, main {main:?}"),
        }
    }
    assert_eq!((bound, refused), (6 * 8, 4));
}

#[test]
fn witness_message_bindings_keep_main_s_bytes() {
    let mut rows = 0;
    for class in [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ] {
        for entity in ids() {
            let actor = WriteActor::new(entity, class);
            for body in byte_inputs() {
                assert_eq!(
                    door::witness_message_binding(actor, &body),
                    gate::base_witness_message::binding(actor, &body),
                    "{class:?} {entity:?} {}",
                    body.len()
                );
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 3 * 5 * 6);
}
