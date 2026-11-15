//! K-proof (oracle) for PLAN-UC-04 stage 6.3e: an IMAP folder's digest, a live goal-axis
//! plan's digest and the encoder input hash keep their bytes.
//!
//! Each starts through the fingerprint crate's K door (`purposes::mail_pack::
//! IMAP_FOLDER_DIGEST`, `purposes::skill_optimize::LIVE_AXIS_PLAN`, `purposes::memory::
//! ENCODER_INPUT`). Provider ids and page cursors carry a folder's digest, a resumed listing
//! compares it and the UID map is keyed by it; a live goal-axis row stores its plan's digest
//! and binds a report only while it is equal; shadow and tagging traces stamp the encoder
//! input hash and a parity check compares it with a golden's. So each must give main's bytes
//! for every input.
//!
//! The `base_*` modules hold main's lines at 72fd8019a3d5, copied by range (each range is named
//! above its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are the
//! imports main's lines name and wrappers for main's private items. The encoder copy keeps
//! main's two files as two modules, so its `super::register::fold_register` call resolves.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_imap_plan_encoder_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderRegister, EncoderTurn, RegisterReach, SpeakerRole,
};
use oneiron::skill_optimize::GoalAxisPlan;
use oneiron::test_doors::fingerprint_keep_imap_plan_encoder_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_imap {
    // main 72fd8019a3d5: crates/oneiron/src/mail_pack/imap.rs:524-526
    fn digest_of(label: &str) -> String {
        blake3::hash(label.as_bytes()).to_hex()[..16].to_owned()
    }

    /// Main's folder digest, which is private there.
    pub(crate) fn main_folder_digest(label: &str) -> String {
        digest_of(label)
    }
}

#[rustfmt::skip]
mod base_live {
    use oneiron::skill_optimize::GoalAxisPlan;
    use oneiron_contracts::entity_id::bytes_to_hex_lower;
    use sha2::{Digest, Sha256};

    // main 72fd8019a3d5: crates/oneiron/src/skill_optimize/gate/live.rs:24-24
    const PLAN_DOMAIN: &[u8] = b"skill_optimize:live_axis_plan:v1\0";

    // main 72fd8019a3d5: crates/oneiron/src/skill_optimize/gate/live.rs:130-145
    fn plan_digest(plan: &GoalAxisPlan) -> String {
        let mut hash = Sha256::new();
        hash.update(PLAN_DOMAIN);
        for (side, axes) in [
            (&b"offline"[..], &plan.offline),
            (&b"online"[..], &plan.online),
        ] {
            hash.update(side);
            hash.update(b"\0");
            for axis in axes {
                hash.update(axis.as_bytes());
                hash.update(b"\0");
            }
        }
        bytes_to_hex_lower(&hash.finalize())
    }

    /// Main's plan digest tag, which is private there.
    pub(crate) const MAIN_PLAN_DOMAIN: &[u8] = PLAN_DOMAIN;

    /// Main's plan digest, which is private there.
    pub(crate) fn main_plan_digest(plan: &GoalAxisPlan) -> String {
        plan_digest(plan)
    }
}

#[rustfmt::skip]
mod base_extraction {
    pub(crate) mod shadow {
        use oneiron::memory::extraction::{EncoderInput, EncoderMessage, SpeakerRole};
        use sha2::{Digest, Sha256};

        // main 72fd8019a3d5: crates/oneiron/src/memory/extraction/shadow.rs:165-206
        pub(crate) fn hash_input(input: &EncoderInput) -> String {
            let mut hash = Sha256::new();
            hash.update(input.turn.as_bytes());
            let message = |hash: &mut Sha256, message: &EncoderMessage| {
                hash.update(message.id.as_bytes());
                hash.update((message.text.len() as u64).to_le_bytes());
                hash.update(message.text.as_bytes());
            };
            for each in &input.messages {
                message(&mut hash, each);
            }
            if !input.context.is_empty() {
                hash.update(b"\0context");
                hash.update((input.context.len() as u64).to_le_bytes());
                for turn in &input.context {
                    hash.update(turn.turn.as_bytes());
                    hash.update((turn.messages.len() as u64).to_le_bytes());
                    for each in &turn.messages {
                        message(&mut hash, each);
                    }
                }
            }
            if let Some(language) = &input.language {
                hash.update(b"\0language");
                hash.update((language.len() as u64).to_le_bytes());
                hash.update(language.as_bytes());
            }
            let roles = std::iter::once(input.speaker).chain(input.context.iter().map(|turn| turn.speaker));
            if roles.clone().any(|role| role.is_some()) {
                // The current turn's role, then each context turn's in order.
                hash.update(b"\0speaker");
                for role in roles {
                    hash.update(match role {
                        None => b"-",
                        Some(SpeakerRole::User) => b"A",
                        Some(SpeakerRole::Companion) => b"B",
                    });
                }
            }
            super::register::fold_register(&mut hash, input, message);
            format!("{:x}", hash.finalize())
        }
    }

    pub(crate) mod register {
        use oneiron::memory::extraction::{EncoderInput, EncoderMessage, EncoderRegister, SpeakerRole};
        use sha2::{Digest, Sha256};

        // main 72fd8019a3d5: crates/oneiron/src/memory/extraction/register.rs:24-57
        pub(super) fn fold_register(
            hash: &mut Sha256,
            input: &EncoderInput,
            message: impl Fn(&mut Sha256, &EncoderMessage),
        ) {
            if input.register.is_live() {
                return;
            }
            hash.update(b"\0register");
            hash.update((input.following.len() as u64).to_le_bytes());
            for turn in &input.following {
                hash.update(turn.turn.as_bytes());
                hash.update((turn.messages.len() as u64).to_le_bytes());
                for each in &turn.messages {
                    message(hash, each);
                }
            }
            hash.update(b"\0following-speaker");
            for turn in &input.following {
                hash.update(match turn.speaker {
                    None => b"-",
                    Some(SpeakerRole::User) => b"A",
                    Some(SpeakerRole::Companion) => b"B",
                });
            }
            // Where the register stops short (FIX 10705); one read whole folds
            // nothing more, so it digests as it did before the record existed.
            if let EncoderRegister::Conversation(reach) = input.register
                && !reach.is_whole()
            {
                hash.update(b"\0reach");
                hash.update([u8::from(reach.earlier_cut), u8::from(reach.later_cut)]);
            }
        }
    }
}

#[test]
fn the_k_purposes_keep_main_s_recipes() {
    let folder = purposes::mail_pack::IMAP_FOLDER_DIGEST;
    assert_eq!(folder.hash(), LegacyHash::Blake3);
    assert_eq!(folder.tag_mode(), TagMode::NotHashed);

    let plan = purposes::skill_optimize::LIVE_AXIS_PLAN;
    assert_eq!(plan.tag(), "skill_optimize:live_axis_plan:v1\0");
    assert_eq!(plan.tag().as_bytes(), base_live::MAIN_PLAN_DOMAIN);
    assert_eq!(plan.hash(), LegacyHash::Sha256);
    assert_eq!(plan.tag_mode(), TagMode::HashedFirst);

    let input = purposes::memory::ENCODER_INPUT;
    assert_eq!(input.hash(), LegacyHash::Sha256);
    assert_eq!(input.tag_mode(), TagMode::NotHashed);
}

#[test]
fn the_imap_folder_digest_keeps_its_bytes() {
    let long = "x".repeat(5000);
    let labels = [
        "INBOX",
        "",
        "inbox",
        " INBOX ",
        "[Gmail]/All Mail",
        "[Gmail]/Sent Mail",
        "[Gmail]/Trash",
        "Archive/2026/Nov",
        // An IMAP modified UTF-7 name, as a server lists it.
        "&AOk-t&AOk-",
        "Été/Привет/日本語",
        "a\0b",
        long.as_str(),
    ];
    let mut seen = BTreeSet::new();
    for label in labels {
        let digest = door::imap_folder_digest(label);
        assert_eq!(digest, base_imap::main_folder_digest(label), "{label:?}");
        assert_eq!(digest.len(), 16);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        seen.insert(digest);
    }
    assert_eq!(seen.len(), 12);
}

#[test]
fn the_live_axis_plan_digest_keeps_its_bytes() {
    let long = "x".repeat(300);
    let sides: [(&[&str], &[&str]); 12] = [
        (&[], &[]),
        (&["accuracy"], &[]),
        (&[], &["accuracy"]),
        (&["accuracy", "honesty"], &["human_minutes"]),
        (&["honesty", "accuracy"], &["human_minutes"]),
        (&["ab"], &["c"]),
        (&["a", "b"], &["c"]),
        (&["a"], &["b", "c"]),
        (&["Genauigkeit", "正確さ"], &["réponse"]),
        (&[long.as_str()], &[""]),
        (&[""], &[]),
        (&["offline"], &["online"]),
    ];
    let mut seen = BTreeSet::new();
    let mut cases = 0;
    for (offline, online) in sides {
        // The pull cap is not hashed: each cap gives the same digest.
        for pulls_per_axis in [0, 7, u32::MAX] {
            let plan = GoalAxisPlan {
                offline: offline.iter().map(|axis| (*axis).to_owned()).collect(),
                online: online.iter().map(|axis| (*axis).to_owned()).collect(),
                pulls_per_axis,
            };
            let digest = door::live_axis_plan_digest(&plan);
            assert_eq!(digest, base_live::main_plan_digest(&plan), "{plan:?}");
            assert_eq!(digest.len(), 64);
            seen.insert(digest);
            cases += 1;
        }
    }
    assert_eq!(cases, 36);
    assert_eq!(seen.len(), 12);
}

#[test]
fn the_encoder_input_hash_keeps_its_bytes() {
    let turns = [hex_id(0x32), hex_id(0xab)];
    let message_sets = [
        vec![],
        vec![message(0x33, "Alice. She agreed.")],
        vec![message(0x34, "hi"), message(0x35, "")],
    ];
    let context_sets = [
        vec![],
        vec![turn(0x41, vec![message(0x36, "earlier")], None)],
        vec![
            turn(
                0x41,
                vec![message(0x36, "earlier")],
                Some(SpeakerRole::User),
            ),
            turn(0x42, vec![], Some(SpeakerRole::Companion)),
        ],
    ];
    let later = vec![turn(
        0x51,
        vec![message(0x38, "later")],
        Some(SpeakerRole::Companion),
    )];
    let mut last = later.clone();
    last.push(turn(
        0x52,
        vec![message(0x3a, "last"), message(0x3b, "")],
        None,
    ));
    let reach = |earlier_cut, later_cut| {
        EncoderRegister::Conversation(RegisterReach {
            earlier_cut,
            later_cut,
        })
    };
    let registers = [
        (EncoderRegister::Live, vec![]),
        // A live input folds no later turn, even when it carries one.
        (EncoderRegister::Live, later.clone()),
        (reach(false, false), vec![]),
        (reach(false, false), later.clone()),
        (reach(true, false), later),
        (reach(true, true), last),
    ];
    let languages = [None, Some("en"), Some("")];
    let speakers = [None, Some(SpeakerRole::User), Some(SpeakerRole::Companion)];
    let mut seen = BTreeSet::new();
    let mut cases = 0;
    for turn_id in &turns {
        for messages in &message_sets {
            for context in &context_sets {
                for (register, following) in &registers {
                    for language in languages {
                        for speaker in speakers {
                            let input = EncoderInput {
                                turn: turn_id.clone(),
                                messages: messages.clone(),
                                context: context.clone(),
                                following: following.clone(),
                                register: *register,
                                language: language.map(str::to_owned),
                                speaker,
                            };
                            let hash = door::encoder_input_hash(&input);
                            assert_eq!(
                                hash,
                                base_extraction::shadow::hash_input(&input),
                                "{input:?}"
                            );
                            assert_eq!(hash.len(), 64);
                            seen.insert(hash);
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 972);
    // A live input with later turns hashes as one without them: 162 inputs repeat.
    assert_eq!(seen.len(), 810);
}

#[test]
fn the_encoder_input_hash_keeps_the_pinned_golden() {
    // The input `memory::extraction`'s shadow test witnesses: one user message.
    let input = EncoderInput {
        turn: hex_id(0x32),
        messages: vec![message(0x33, "Alice. She agreed.")],
        context: vec![],
        following: vec![],
        register: EncoderRegister::Live,
        language: None,
        speaker: Some(SpeakerRole::User),
    };
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("../src/data/encoder_shadow.v1.json"))
            .expect("the golden decodes");
    let pinned = golden["input_hash"]
        .as_str()
        .expect("the golden pins an input hash");
    assert_eq!(
        pinned,
        "4b733282d61cc297d2bb62c0172bb6464a72d9c89614e0520060f96919e88fb7"
    );
    assert_eq!(base_extraction::shadow::hash_input(&input), pinned);
    assert_eq!(door::encoder_input_hash(&input), pinned);
}

/// A 32-digit hex id of one repeated byte, as a resolved ref prints.
fn hex_id(byte: u8) -> String {
    oneiron_hex::encode(&[byte; 16])
}

fn message(id: u8, text: &str) -> EncoderMessage {
    EncoderMessage {
        id: hex_id(id),
        text: text.to_owned(),
    }
}

fn turn(id: u8, messages: Vec<EncoderMessage>, speaker: Option<SpeakerRole>) -> EncoderTurn {
    EncoderTurn {
        turn: hex_id(id),
        messages,
        speaker,
    }
}
