// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! FIX-LIST [ASK-FORWARD-INTENT-TOKEN-MASKED]: a person's relayed ask word
//! (FIX 7494) stores, and the ask's admitting node admits it, while the
//! vault's write-door secret scan is on, as it is by default. The stored
//! intent once kept the holder's slip under the wire name `token`, a
//! credential name to the door's mask, which swapped the slip for a custody
//! handle before the put's guard read it: the guard refused the put as
//! "invalid TASK body: tasks.ask.fact", for every caller. The intent now
//! keeps it under `slip`, and a `v2.slip.` value under that key is no
//! secret shape to the scan either.
//!
//! The holder is the vault's owner, on their own slip of this host's mint,
//! bound to a key they keep. The ask is admitted here, so the word is
//! consumed in the same call: the admitting node reads the stored slip back
//! and verifies the holder's signature over the intent's challenge.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test ask_forward_intent_secret_scan`

use ed25519_dalek::{Signer, SigningKey};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{
    AskForwardAct, AskForwardHolderProof, AskForwardReceipt, ConsultPayloadRef, TaskAskDefault,
    TaskAskQuestion, TaskAskSpec, TaskAskTarget, TaskAskWord, TaskAssignee,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange};
use oneiron_testkit::dreamer::{attach_test_host, test_host_issuer};

fn turn_body(role: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("role"), rmpv::Value::from(role))]),
    )
    .unwrap();
    body
}

/// The member `key` of the map `value`, if it is a map that holds one.
fn member<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(name, member)| (name.as_str() == Some(key)).then_some(member))
}

#[test]
fn relayed_ask_word_stores_and_admits_with_secret_scan_on() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    attach_test_host(&vault).unwrap();
    assert_eq!(
        vault.secret_scan_mode().unwrap(),
        SecretScanMode::On,
        "the write-door secret scan is on, its default"
    );

    // The holder's own slip, of this host's mint, bound to the key they keep.
    let issuer = test_host_issuer().unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let holder_key = SigningKey::from_bytes(blake3::hash(b"ask-forward-holder-key").as_bytes());
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"ask-forward-holder-slip").as_bytes();
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key.verifying_key().to_bytes();
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let token = slip.to_token().unwrap();

    // The ask, admitted here; its owner is its responder.
    let question = EntityId::now();
    vault
        .put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &turn_body("question"),
        )
        .unwrap();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory
        .tasks_ask(&TaskAskSpec {
            intent_key: "ask-forward-scan-on".into(),
            ..TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Human {
                    actor_ref: owner,
                })),
                TaskAskQuestion::new(
                    ConsultPayloadRef::parse(&vault, &format!("tn_{}", question.to_hex())).unwrap(),
                ),
                Some(u64::MAX),
                TaskAskDefault::AskMe,
            )
        })
        .unwrap();

    // The word's result row is here, so nothing the intent names is pending.
    let result_row = EntityId::now();
    vault
        .put_entity(
            &result_row,
            ENTITY_TYPE_TURN,
            TimeRange { start: 3, end: 3 },
            3,
            &turn_body("answer"),
        )
        .unwrap();

    // The holder signs their slip's binding transcript of the challenge.
    let intent_key = "ask-forward-scan-on-intent";
    let act = AskForwardAct::Word(TaskAskWord::new(result_row));
    let challenge = memory
        .tasks_answer_forward_challenge(&ask.handle, intent_key, &act)
        .unwrap();
    let signature = holder_key
        .sign(&slip.binding_transcript(&challenge).unwrap())
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let receipt = memory
        .tasks_answer_forward(
            &ask.handle,
            intent_key,
            &act,
            &AskForwardHolderProof {
                token: token.clone(),
                signature,
            },
        )
        .unwrap_or_else(|error| {
            panic!("the relayed word stores with the secret scan on: {error:?}")
        });
    let intent_ref = match receipt {
        AskForwardReceipt::Answered { intent_ref, .. } => intent_ref,
        other => {
            panic!("the admitting node reads the stored slip back and admits the word: {other:?}")
        }
    };

    // The stored intent keeps the slip as the holder gave it, under `slip`.
    let body = vault
        .get(&intent_ref)
        .unwrap()
        .expect("the intent is stored");
    let stored = rmpv::decode::read_value(&mut body.as_slice()).unwrap();
    let proof = member(&stored, "proof").expect("the intent stores its holder proof");
    assert_eq!(
        member(proof, "slip").and_then(rmpv::Value::as_str),
        Some(token.as_str()),
        "the stored slip is the holder's own, unmasked"
    );
    assert!(
        member(proof, "token").is_none(),
        "no stored proof key is a credential name"
    );
}
