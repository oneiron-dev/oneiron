//! A room's export takes only the slip this vault minted, as it shows
//! itself (ARCH-0052 #d5-proof-open; Engine ruling L6-17-PROVENANCE = C,
//! 14 Nov). An export copies the talk out of the room under the slip's
//! authority, as a save writes it into the vault, so it runs the save's
//! `minted_as_shown` check. A slip narrowed or handed on since its mint gets
//! the refusal an outsider gets (`OffRecordNotInRoom`, the room routes' 404),
//! and the room hears nothing. The exact minted slip still exports.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test
//! room_export_slip_provenance`.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole, SlipCaveat, VerifiedSlip,
};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::off_record::{OffRecordBackendClass, OffRecordNoticeAct, OffRecordSession};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, ErrorKind, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// The challenge a holder signs to prove a slip in these tests.
const CHALLENGE: &[u8] = b"room-export-provenance";

/// The stretch every test exports.
const SESSION_REF: &str = "yuki-garden";

/// A vault rooted under its own host, its engine machines and install
/// profile provisioned and its owner bound (as
/// tests/gate_pins_authority_custody_grants.rs g188 opens one), with a room
/// whose roster is the owner and yuki, a PERSON of this vault, and an
/// off-record stretch the owner started in it.
struct Room {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    yuki: EntityId,
    room: EntityId,
}

fn room() -> TestResult<Room> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).map_err(at("open"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer =
        HostSlipIssuer::from_seed(&[0x52; HOST_ISSUER_SEED_BYTES]).map_err(at("host issuer"))?;
    let root = vault
        .ensure_host_root_slip(&issuer)
        .map_err(at("host root"))?;
    vault
        .provision_engine_machine_identities(&issuer)
        .map_err(at("engine machines"))?;
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(at("install profile"))?;
    let yuki = EntityId::now();
    vault
        .put_entity(
            &yuki,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"yuki",
        )
        .map_err(at("put yuki's PERSON"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).map_err(at("bind owner"))?;
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owner, yuki],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )
        .map_err(at("create the room"))?;
    vault
        .off_record_session_vault()
        .enter_in_room_as(SESSION_REF, OffRecordBackendClass::Local, room, &proof)
        .map_err(at("enter the room off record"))?;
    Ok(Room {
        _dir: dir,
        vault,
        issuer,
        root,
        yuki,
        room,
    })
}

impl Room {
    /// The owner's stretch, bound for yuki as the room routes bind it.
    fn session(&self) -> TestResult<OffRecordSession<'_>> {
        self.vault
            .off_record_session_vault()
            .bind_in_room(SESSION_REF, self.room, self.yuki)
            .map_err(at("bind the room's stretch for yuki"))
    }

    /// yuki's own human slip, cut from the host root as this vault mints it.
    fn minted(&self) -> TestResult<CapabilitySlip> {
        let mut claims = self.root.claims.clone();
        claims.slip_id = slip_id();
        claims.holder_ref = self.yuki.to_hex();
        claims.actor_class = Some("human".to_owned());
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .map_err(at("mint yuki's slip"))
    }

    /// `slip` as this vault verifies it for the host key that binds it.
    fn verified_by_host(&self, slip: &CapabilitySlip) -> TestResult<VerifiedSlip> {
        let binding = self
            .issuer
            .binding_proof(slip, CHALLENGE)
            .map_err(at("binding proof"))?;
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), slip, CHALLENGE, &binding)
            .map_err(at("verify the slip"))
    }

    /// How many `exported` notices by yuki the room holds, as yuki reads it.
    fn exports_by_yuki(&self, session: &OffRecordSession<'_>) -> TestResult<usize> {
        let record = session
            .record_for(self.yuki)
            .map_err(at("read the stretch's record"))?;
        Ok(record
            .notices
            .iter()
            .filter(|notice| {
                matches!(notice.act, OffRecordNoticeAct::Exported)
                    && notice.by == *self.yuki.as_bytes()
            })
            .count())
    }

    /// Asserts `slip` is refused at export with the outsider's refusal, and
    /// that the room hears nothing of it.
    fn assert_export_refused(&self, slip: &VerifiedSlip, what: &str) -> TestResult {
        let session = self.session()?;
        let refused = session.export_talk_by(self.yuki, slip);
        let Err(error) = refused else {
            return Err(format!("{what} exported the talk").into());
        };
        assert!(
            matches!(error.kind(), ErrorKind::OffRecordNotInRoom),
            "{what} was refused, but not with the outsider's refusal: {error:?}"
        );
        assert_eq!(
            self.exports_by_yuki(&session)?,
            0,
            "the room heard an export on {what}"
        );
        Ok(())
    }
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

#[test]
fn an_exact_minted_slip_exports_the_talk() -> TestResult {
    let room = room()?;
    let exact = room.verified_by_host(&room.minted()?)?;
    let session = room.session()?;
    let talk = session
        .export_talk_by(room.yuki, &exact)
        .map_err(at("export on the exact minted slip"))?;
    assert_eq!(talk.room, Some(*room.room.as_bytes()));
    assert_eq!(
        room.exports_by_yuki(&session)?,
        1,
        "the room did not hear yuki's export"
    );
    Ok(())
}

#[test]
fn a_narrowed_slip_is_refused_at_export_as_an_outsider() -> TestResult {
    let room = room()?;
    let minted = room.minted()?;
    let exact = room.verified_by_host(&minted)?;
    let mut narrowed = minted;
    let mut reads = Scope::top();
    reads.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned(), "read".to_owned()]));
    room.issuer
        .attenuate(
            &mut narrowed,
            SlipCaveat {
                scope: Some(reads),
                ..Default::default()
            },
        )
        .map_err(at("narrow yuki's slip"))?;
    let narrowed = room.verified_by_host(&narrowed)?;
    assert_ne!(
        narrowed.scope(),
        exact.scope(),
        "fixture: the caveat did not narrow the slip"
    );
    assert_eq!(narrowed.claims().holder_ref, room.yuki.to_hex());
    room.assert_export_refused(&narrowed, "a narrowed slip")
}

#[test]
fn a_handed_on_slip_is_refused_at_export_as_an_outsider() -> TestResult {
    let room = room()?;
    let mut handed = room.minted()?;
    let next = SigningKey::from_bytes(&[0x47; 32]);
    room.issuer
        .attenuate_to(
            &mut handed,
            SlipCaveat::default(),
            next.verifying_key().to_bytes(),
        )
        .map_err(at("hand yuki's slip on"))?;
    let transcript = handed
        .binding_transcript(CHALLENGE)
        .map_err(at("binding transcript"))?;
    let binding = next.sign(&transcript).to_bytes();
    let handed = room
        .vault
        .verify_capability_slip(&room.issuer.public_key(), &handed, CHALLENGE, &binding)
        .map_err(at("verify the handed-on slip"))?;
    assert!(
        handed.is_transferred(),
        "fixture: the slip was not handed on"
    );
    // It still names yuki: only the key that proves it moved.
    assert_eq!(handed.claims().holder_ref, room.yuki.to_hex());
    room.assert_export_refused(&handed, "a handed-on slip")
}
