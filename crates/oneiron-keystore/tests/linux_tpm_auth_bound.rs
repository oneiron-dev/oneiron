//! Row OCS-OWNER-PIN, the TPM tier: the device PIN key rests in the chip
//! under an auth value. The right value opens it, a wrong one is counted by
//! the chip, and a chip in lockout takes none and says how long.
//!
//! Three chips answer here:
//! - a scripted one in this file, which every run uses. It reads the bytes
//!   the tier sends, so these tests state the commands on their own: the
//!   object made for the device PIN key is counted and carries the auth
//!   value, a slot's object is neither, and each unseal gives its password.
//! - a software TPM (`swtpm`), in a test that is ignored unless asked for:
//!   `cargo test -p oneiron-keystore --all-features --test
//!   linux_tpm_auth_bound -- --ignored a_software_tpm`. It needs `swtpm` on
//!   the path.
//! - this machine's own chip, in a test that is ignored unless asked for:
//!   `... -- --ignored this_machines_tpm`. It spends one of the chip's wrong
//!   tries, which the chip forgets after its recovery interval.
#![cfg(target_os = "linux")]
// The software TPM is a subprocess of a test.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use oneiron_keystore::{
    AUTH_VALUE_MAX, AuthBoundError, AuthBoundSecretStore, DEVICE_PIN_WAIT_SECS, DeviceKeystore,
    KeystoreError, KeystoreSlot, LinuxTpmKeystore, LocalFileKeystore, MemoryKeystore,
    SealedBytesName, SlotKind,
};
use zeroize::Zeroizing;

const AUTH: [u8; 32] = [0xa5; 32];
const OTHER_AUTH: [u8; 32] = [0x3c; 32];
const SECRET: [u8; 32] = [0x5a; 32];
const OTHER_SECRET: [u8; 32] = [0x77; 32];

const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_CREATE: u32 = 0x153;
const CC_LOAD: u32 = 0x157;
const CC_UNSEAL: u32 = 0x15e;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_GET_CAPABILITY: u32 = 0x17a;

/// `TPM_RC_AUTH_FAIL` and `TPM_RC_BAD_AUTH` as the first session's.
const RC_AUTH_FAIL_SESSION_1: u32 = 0x98e;
const RC_BAD_AUTH_SESSION_1: u32 = 0x9a2;
const RC_LOCKOUT: u32 = 0x921;
/// `TPM_RC_INTEGRITY` as the first parameter's.
const RC_INTEGRITY_PARAMETER_1: u32 = 0x1df;
/// `TPM_RC_RETRY`: a warning the keystore has no word for.
const RC_RETRY: u32 = 0x922;
const RC_COMMAND_CODE: u32 = 0x143;
const RC_HANDLE_1: u32 = 0x18b;

/// `TPMA_OBJECT.noDA`.
const NO_DA: u32 = 1 << 10;
/// `fixedTPM`, `fixedParent` and `userWithAuth`: what every sealed object of
/// the tier has.
const SEALED_OBJECT_BITS: u32 = (1 << 1) | (1 << 4) | (1 << 6);

/// The owner signing slot of the vault whose id is all `vault`.
fn owner_slot(vault: u8) -> KeystoreSlot {
    KeystoreSlot {
        vault_id: [vault; 32],
        install: [3; 16],
        kind: SlotKind::OwnerSigning,
    }
}

/// A secret as a keystore hands it out.
fn held(bytes: [u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(bytes)
}

/// What every auth-bound secret does, whatever counts behind it. It spends
/// two wrong tries.
fn the_right_auth_value_opens_and_a_wrong_one_does_not(store: &dyn AuthBoundSecretStore) {
    assert_eq!(store.holds_auth_bound(), Ok(false));
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Ok(None),
        "an empty store opened"
    );

    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed under the auth value");
    assert_eq!(store.holds_auth_bound(), Ok(true));
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
    assert_eq!(
        store.open_auth_bound(&OTHER_AUTH),
        Err(AuthBoundError::WrongAuth),
        "another auth value opened the secret"
    );
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Ok(Some(held(SECRET))),
        "one wrong try closed the secret to the right auth value"
    );

    // A new auth value is a put of the same secret: the old value opens
    // nothing afterwards.
    store
        .put_auth_bound(&OTHER_AUTH, &SECRET)
        .expect("the secret is sealed under the new auth value");
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::WrongAuth),
        "the old auth value still opened the secret"
    );
    assert_eq!(store.open_auth_bound(&OTHER_AUTH), Ok(Some(held(SECRET))));

    // A put replaces the secret too.
    store
        .put_auth_bound(&AUTH, &OTHER_SECRET)
        .expect("another secret takes the place");
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(OTHER_SECRET))));

    store.delete_auth_bound().expect("the secret is removed");
    store
        .delete_auth_bound()
        .expect("removing none is not an error");
    assert_eq!(store.holds_auth_bound(), Ok(false));
    assert_eq!(store.open_auth_bound(&AUTH), Ok(None));
}

/// An auth value no hardware holds as given is refused, and what was sealed
/// before stays.
fn an_auth_value_out_of_bounds_is_refused(store: &dyn AuthBoundSecretStore) {
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");
    let too_long = [0x11; AUTH_VALUE_MAX + 1];
    for refused in [&[][..], &too_long[..], &[0; 32][..], &[0][..]] {
        assert!(
            matches!(
                store.put_auth_bound(refused, &OTHER_SECRET),
                Err(KeystoreError::Unsupported(_))
            ),
            "an auth value of {} bytes sealed a secret",
            refused.len()
        );
        assert!(
            matches!(
                store.open_auth_bound(refused),
                Err(AuthBoundError::Keystore(KeystoreError::Unsupported(_)))
            ),
            "an auth value of {} bytes was tried",
            refused.len()
        );
    }
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Ok(Some(held(SECRET))),
        "a refused auth value changed the secret, or was counted"
    );
    // One byte is an auth value, and so is one that ends in zeros.
    store
        .put_auth_bound(&[9], &SECRET)
        .expect("a one-byte auth value seals");
    assert_eq!(store.open_auth_bound(&[9]), Ok(Some(held(SECRET))));
    store.delete_auth_bound().expect("the secret is removed");
}

#[test]
fn the_memory_tier_counts_wrong_auth_values_as_a_chip_does() {
    let keys = MemoryKeystore::with_counted_auth_bound(3, 600);
    let store = keys
        .auth_bound_secret()
        .expect("a memory keystore made with a counter has an auth-bound secret");
    the_right_auth_value_opens_and_a_wrong_one_does_not(store);
    keys.forget_wrong_auth_tries();
    an_auth_value_out_of_bounds_is_refused(store);

    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");
    for _ in 0..3 {
        assert_eq!(
            store.open_auth_bound(&OTHER_AUTH),
            Err(AuthBoundError::WrongAuth)
        );
    }
    // The fourth try is not compared: a right value is refused too.
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::LockedOut { wait_secs: 600 })
    );
    assert_eq!(
        store.holds_auth_bound(),
        Ok(true),
        "a lockout removed the secret"
    );
    keys.forget_wrong_auth_tries();
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
}

#[test]
fn a_tier_whose_hardware_counts_nothing_holds_no_auth_bound_secret() {
    assert!(MemoryKeystore::new().auth_bound_secret().is_none());
    let root = tempfile::tempdir().expect("a temporary directory");
    let files =
        LocalFileKeystore::open(&root.path().join("keys"), &[]).expect("the key directory opens");
    assert!(files.auth_bound_secret().is_none());
}

/// Big-endian fields of a command, front to back. A short command is a bug
/// of the tier under test, so it panics.
struct Fields<'b>(&'b [u8]);

impl<'b> Fields<'b> {
    fn take(&mut self, len: usize) -> &'b [u8] {
        assert!(
            self.0.len() >= len,
            "the command ends before a field of {len} bytes"
        );
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        head
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().expect("two bytes"))
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().expect("four bytes"))
    }

    /// A `TPM2B`'s body.
    fn sized(&mut self) -> &'b [u8] {
        let len = usize::from(self.u16());
        self.take(len)
    }

    /// The authorization area of one password session: its password.
    fn password(&mut self) -> &'b [u8] {
        let mut area = Fields(self.sized_by_u32());
        assert_eq!(area.u32(), 0x4000_0009, "not a password session");
        assert!(area.sized().is_empty(), "a password session has no nonce");
        assert_eq!(area.take(1), [1], "the session is not continued");
        let password = area.sized();
        assert!(area.0.is_empty(), "bytes follow the one session");
        password
    }

    fn sized_by_u32(&mut self) -> &'b [u8] {
        let len = usize::try_from(self.u32()).expect("a size");
        self.take(len)
    }
}

fn push_sized(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&u16::try_from(value.len()).expect("a size").to_be_bytes());
    bytes.extend_from_slice(value);
}

/// A response: its header with the size filled in, then `body`.
fn response(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(10 + body.len());
    bytes.extend_from_slice(&tag.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(10 + body.len())
            .expect("a size")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn refusal(code: u32) -> Vec<u8> {
    response(0x8001, code, &[])
}

/// What the scripted chip knows of one sealed object.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChipObject {
    /// `TPMA_OBJECT`, as the template gave it.
    attributes: u32,
    auth: Vec<u8>,
    data: Vec<u8>,
}

impl ChipObject {
    /// The private area this chip hands out: a mark, then the object in the
    /// clear. A real chip encrypts it; this one only has to know its own.
    fn private(&self) -> Vec<u8> {
        let mut bytes = b"chip".to_vec();
        bytes.extend_from_slice(&self.attributes.to_be_bytes());
        push_sized(&mut bytes, &self.auth);
        push_sized(&mut bytes, &self.data);
        bytes
    }

    /// The object of a private area this chip handed out, when the public
    /// area beside it is the one it was made with.
    fn of_private(private: &[u8], public: &[u8]) -> Option<Self> {
        let rest = private.strip_prefix(b"chip")?;
        let mut fields = Fields(rest);
        let attributes = fields.u32();
        let auth = fields.sized().to_vec();
        let data = fields.sized().to_vec();
        (template_attributes(public) == attributes).then_some(Self {
            attributes,
            auth,
            data,
        })
    }

    fn counted(&self) -> bool {
        self.attributes & NO_DA == 0
    }
}

/// The `TPMA_OBJECT` word of a `TPMT_PUBLIC`: after its type and its name
/// algorithm.
fn template_attributes(public: &[u8]) -> u32 {
    let mut fields = Fields(public);
    assert_eq!(fields.u16(), 0x0008, "not a keyed-hash object");
    assert_eq!(fields.u16(), 0x000b, "the name algorithm is not SHA-256");
    fields.u32()
}

/// As a TPM compares an auth value: without its trailing zero bytes.
fn trimmed(auth: &[u8]) -> &[u8] {
    let len = auth
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    &auth[..len]
}

#[derive(Default)]
struct ChipState {
    /// What is loaded, by handle. `None` is the storage key.
    loaded: HashMap<u32, Option<ChipObject>>,
    handles_given: u32,
    wrong_tries: u32,
    max_wrong_tries: u32,
    /// The recovery interval the chip reports. `None`: it answers no
    /// capability.
    interval_secs: Option<u32>,
    /// Each command's code, in order.
    commands: Vec<u32>,
    /// Each object made, in order.
    created: Vec<ChipObject>,
    /// Each password given to an unseal, in order.
    unseal_passwords: Vec<Vec<u8>>,
    /// The code the next unseal answers, once.
    next_unseal_code: Option<u32>,
}

impl ChipState {
    fn load(&mut self, object: Option<ChipObject>) -> Vec<u8> {
        let handle = 0x8000_0000 + self.handles_given;
        self.handles_given += 1;
        self.loaded.insert(handle, object);
        // The handle, then an empty parameter area.
        let mut body = handle.to_be_bytes().to_vec();
        body.extend_from_slice(&0u32.to_be_bytes());
        response(0x8002, 0, &body)
    }

    fn create(&mut self, mut fields: Fields<'_>) -> Vec<u8> {
        let parent = fields.u32();
        assert_eq!(
            self.loaded.get(&parent),
            Some(&None),
            "an object is made under something other than the storage key"
        );
        assert!(
            fields.password().is_empty(),
            "the storage key has the empty password"
        );
        let mut sensitive = Fields(fields.sized());
        let public = fields.sized();
        let object = ChipObject {
            attributes: template_attributes(public),
            auth: sensitive.sized().to_vec(),
            data: sensitive.sized().to_vec(),
        };
        assert!(sensitive.0.is_empty(), "bytes follow the sensitive area");
        // The parameter size (not read), the private area, the public area.
        let mut body = 0u32.to_be_bytes().to_vec();
        push_sized(&mut body, &object.private());
        push_sized(&mut body, public);
        self.created.push(object);
        response(0x8002, 0, &body)
    }

    fn load_object(&mut self, mut fields: Fields<'_>) -> Vec<u8> {
        let parent = fields.u32();
        assert_eq!(self.loaded.get(&parent), Some(&None));
        assert!(fields.password().is_empty());
        let private = fields.sized();
        let public = fields.sized();
        match ChipObject::of_private(private, public) {
            Some(object) => self.load(Some(object)),
            None => refusal(RC_INTEGRITY_PARAMETER_1),
        }
    }

    fn unseal(&mut self, mut fields: Fields<'_>) -> Vec<u8> {
        let handle = fields.u32();
        let password = fields.password();
        self.unseal_passwords.push(password.to_vec());
        if let Some(code) = self.next_unseal_code.take() {
            return refusal(code);
        }
        let Some(Some(object)) = self.loaded.get(&handle) else {
            return refusal(RC_HANDLE_1);
        };
        if object.counted() && self.wrong_tries >= self.max_wrong_tries {
            return refusal(RC_LOCKOUT);
        }
        if trimmed(password) != trimmed(&object.auth) {
            if !object.counted() {
                return refusal(RC_BAD_AUTH_SESSION_1);
            }
            self.wrong_tries += 1;
            return refusal(RC_AUTH_FAIL_SESSION_1);
        }
        // The parameter size (not read), then the data.
        let mut body = 0u32.to_be_bytes().to_vec();
        push_sized(&mut body, &object.data);
        response(0x8002, 0, &body)
    }

    fn capability(&self, mut fields: Fields<'_>) -> Vec<u8> {
        let capability = fields.u32();
        let property = fields.u32();
        assert_eq!(
            (capability, property, fields.u32()),
            (6, 0x210, 1),
            "not the one lockout-interval property"
        );
        let Some(interval) = self.interval_secs else {
            return refusal(RC_COMMAND_CODE);
        };
        // moreData, the capability, one property and its value.
        let mut body = vec![0];
        for field in [capability, 1, property, interval] {
            body.extend_from_slice(&field.to_be_bytes());
        }
        response(0x8001, 0, &body)
    }

    fn answer(&mut self, code: u32, body: &[u8]) -> Vec<u8> {
        self.commands.push(code);
        let mut fields = Fields(body);
        match code {
            CC_CREATE_PRIMARY => {
                assert_eq!(fields.u32(), 0x4000_0001, "not the owner hierarchy");
                assert!(fields.password().is_empty());
                self.load(None)
            }
            CC_CREATE => self.create(fields),
            CC_LOAD => self.load_object(fields),
            CC_UNSEAL => self.unseal(fields),
            CC_FLUSH_CONTEXT => {
                self.loaded.remove(&fields.u32());
                response(0x8001, 0, &[])
            }
            CC_GET_CAPABILITY => self.capability(fields),
            _ => refusal(RC_COMMAND_CODE),
        }
    }
}

/// A chip that answers the tier's commands on a Unix socket from a script:
/// it keeps what was loaded, counts wrong auth values for counted objects,
/// and records what it was sent.
struct ScriptedChip {
    state: Arc<Mutex<ChipState>>,
    root: tempfile::TempDir,
}

impl ScriptedChip {
    /// A chip that locks out after `max_wrong_tries` wrong auth values and
    /// reports `interval_secs` as its recovery interval.
    fn start(max_wrong_tries: u32, interval_secs: Option<u32>) -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let listener = UnixListener::bind(root.path().join("chip.sock")).expect("the chip listens");
        let state = Arc::new(Mutex::new(ChipState {
            max_wrong_tries,
            interval_secs,
            ..ChipState::default()
        }));
        let served = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                serve(stream, &served);
            }
        });
        Self { state, root }
    }

    fn socket(&self) -> PathBuf {
        self.root.path().join("chip.sock")
    }

    fn key_dir(&self) -> PathBuf {
        self.root.path().join("keys")
    }

    fn keystore(&self) -> LinuxTpmKeystore {
        LinuxTpmKeystore::open_on_socket(&self.key_dir(), &[], &self.socket())
            .expect("the tier opens on the scripted chip")
    }

    fn state(&self) -> MutexGuard<'_, ChipState> {
        self.state.lock().expect("the chip's state")
    }

    /// The codes of the commands sent since `mark`, without the flushes.
    fn commands_since(&self, mark: usize) -> Vec<u32> {
        self.state().commands[mark..]
            .iter()
            .copied()
            .filter(|code| *code != CC_FLUSH_CONTEXT)
            .collect()
    }

    fn command_count(&self) -> usize {
        self.state().commands.len()
    }

    fn nothing_stays_loaded(&self) {
        assert!(
            self.state().loaded.is_empty(),
            "the tier left an object loaded in the chip"
        );
    }
}

/// Answers one connection's commands until it closes. Each response goes out
/// in two parts, as a socket may deliver it.
fn serve(mut stream: UnixStream, state: &Mutex<ChipState>) {
    loop {
        let mut header = [0u8; 10];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut fields = Fields(&header);
        let _tag = fields.u16();
        let size = usize::try_from(fields.u32()).expect("a size");
        let code = fields.u32();
        let mut body = vec![0u8; size - header.len()];
        stream.read_exact(&mut body).expect("the command's body");
        let answer = state.lock().expect("the chip's state").answer(code, &body);
        let (first, rest) = answer.split_at(3);
        stream.write_all(first).expect("the response's first part");
        stream.flush().expect("the first part is sent");
        std::thread::sleep(Duration::from_millis(2));
        stream.write_all(rest).expect("the response's second part");
    }
}

fn device_pin_key_file(dir: &Path) -> PathBuf {
    dir.join("device-pin-key.tpm2")
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("the key directory lists")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn the_chip_opens_the_device_pin_key_for_its_auth_value_and_counts_a_wrong_one() {
    let chip = ScriptedChip::start(8, Some(600));
    let keys = chip.keystore();
    let store = keys
        .auth_bound_secret()
        .expect("the TPM tier has an auth-bound secret");

    the_right_auth_value_opens_and_a_wrong_one_does_not(store);
    chip.nothing_stays_loaded();
    assert_eq!(
        chip.state().wrong_tries,
        2,
        "the chip did not count each wrong auth value once"
    );
    {
        let state = chip.state();
        // Every object made was the device PIN key's: counted, with the
        // auth value given, holding the secret given.
        let counted = |auth: &[u8; 32], data: &[u8; 32]| ChipObject {
            attributes: SEALED_OBJECT_BITS,
            auth: auth.to_vec(),
            data: data.to_vec(),
        };
        assert_eq!(
            state.created,
            [
                counted(&AUTH, &SECRET),
                counted(&OTHER_AUTH, &SECRET),
                counted(&AUTH, &OTHER_SECRET)
            ]
        );
        // Each unseal gave the auth value it was asked with as its password.
        assert_eq!(
            state.unseal_passwords,
            [
                AUTH.to_vec(),
                OTHER_AUTH.to_vec(),
                AUTH.to_vec(),
                AUTH.to_vec(),
                OTHER_AUTH.to_vec(),
                AUTH.to_vec()
            ]
        );
    }

    // What rests on disk: one private file, and no temporary one.
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");
    let file = device_pin_key_file(&chip.key_dir());
    let mode = fs::metadata(&file)
        .expect("the device PIN key's file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        file_names(&chip.key_dir()),
        ["CACHEDIR.TAG", "device-pin-key.tpm2"]
    );

    // The questions that need no chip ask it nothing.
    let mark = chip.command_count();
    assert_eq!(store.holds_auth_bound(), Ok(true));
    store.delete_auth_bound().expect("the secret is removed");
    assert_eq!(store.open_auth_bound(&AUTH), Ok(None));
    assert!(
        chip.commands_since(mark).is_empty(),
        "a question that needs no chip asked it"
    );

    let mark = chip.command_count();
    an_auth_value_out_of_bounds_is_refused(store);
    // One put and one open of the secret kept, then the one-byte put and
    // open: no refused auth value reached the chip.
    assert_eq!(
        chip.commands_since(mark),
        [
            CC_CREATE_PRIMARY,
            CC_CREATE,
            CC_CREATE_PRIMARY,
            CC_LOAD,
            CC_UNSEAL,
            CC_CREATE_PRIMARY,
            CC_CREATE,
            CC_CREATE_PRIMARY,
            CC_LOAD,
            CC_UNSEAL
        ]
    );
    chip.nothing_stays_loaded();
}

#[test]
fn a_chip_in_lockout_takes_no_auth_value_and_says_how_long() {
    let chip = ScriptedChip::start(3, Some(7200));
    let keys = chip.keystore();
    let store = keys.auth_bound_secret().expect("an auth-bound secret");
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");

    for _ in 0..3 {
        assert_eq!(
            store.open_auth_bound(&OTHER_AUTH),
            Err(AuthBoundError::WrongAuth)
        );
    }
    // The chip is in lockout: a right auth value is refused too, with the
    // chip's own recovery interval as the wait.
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::LockedOut { wait_secs: 7200 })
    );
    assert_eq!(chip.state().wrong_tries, 3, "a try in lockout was counted");
    chip.nothing_stays_loaded();
    assert_eq!(
        store.holds_auth_bound(),
        Ok(true),
        "a lockout removed the secret"
    );

    // The slots are not counted, so they still open in lockout.
    let slot = owner_slot(7);
    keys.create(&slot, &SECRET)
        .expect("a slot fills in lockout");
    assert_eq!(keys.get(&slot), Ok(Some(held(SECRET))));
    chip.nothing_stays_loaded();

    // The recovery interval passes: the chip forgets, and the secret opens.
    chip.state().wrong_tries = 0;
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
}

#[test]
fn a_chip_that_gives_no_interval_answers_the_gates_wait() {
    for interval in [None, Some(0)] {
        let chip = ScriptedChip::start(1, interval);
        let keys = chip.keystore();
        let store = keys.auth_bound_secret().expect("an auth-bound secret");
        store
            .put_auth_bound(&AUTH, &SECRET)
            .expect("the secret is sealed");
        assert_eq!(
            store.open_auth_bound(&OTHER_AUTH),
            Err(AuthBoundError::WrongAuth)
        );
        assert_eq!(
            store.open_auth_bound(&AUTH),
            Err(AuthBoundError::LockedOut {
                wait_secs: DEVICE_PIN_WAIT_SECS
            }),
            "interval {interval:?}"
        );
        chip.nothing_stays_loaded();
    }
}

#[test]
fn a_slot_stays_uncounted_and_neither_file_is_read_as_the_other() {
    let chip = ScriptedChip::start(1, Some(600));
    let keys = chip.keystore();
    let store = keys.auth_bound_secret().expect("an auth-bound secret");
    let slot = owner_slot(7);
    keys.create(&slot, &SECRET).expect("the slot fills");
    assert_eq!(keys.get(&slot), Ok(Some(held(SECRET))));
    {
        let state = chip.state();
        assert_eq!(
            state.created,
            [ChipObject {
                attributes: SEALED_OBJECT_BITS | NO_DA,
                auth: Vec::new(),
                data: SECRET.to_vec(),
            }],
            "a slot's object changed"
        );
        assert_eq!(state.unseal_passwords, [Vec::<u8>::new()]);
    }

    // A slot's file under the device PIN key's name is refused before the
    // chip is asked, and so is the device PIN key's file under a slot's.
    let dir = chip.key_dir();
    let slot_file = dir.join(format!("{}.tpm2", slot.name()));
    fs::copy(&slot_file, device_pin_key_file(&dir)).expect("the slot's file is copied");
    let mark = chip.command_count();
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::Keystore(KeystoreError::Corrupt(
            "the sealed device PIN key does not parse"
        )))
    );
    store
        .put_auth_bound(&AUTH, &OTHER_SECRET)
        .expect("a put replaces the file that does not parse");
    fs::copy(device_pin_key_file(&dir), &slot_file).expect("the key's file is copied");
    let before_get = chip.command_count();
    assert_eq!(
        keys.get(&slot),
        Err(KeystoreError::Corrupt("the sealed slot does not parse"))
    );
    assert_eq!(chip.command_count(), before_get, "the chip was asked");
    assert_eq!(chip.commands_since(mark), [CC_CREATE_PRIMARY, CC_CREATE]);

    // A device PIN key the chip does not know as its own (another chip's,
    // or altered) does not load, and is not a wrong auth value: no try is
    // spent on it.
    let file = device_pin_key_file(&dir);
    let mut altered = fs::read(&file).expect("the key's file reads");
    // The tag, the public area with its size, the private area's size.
    altered[8 + 16 + 2] ^= 0xff;
    fs::write(&file, altered).expect("the key's file is altered");
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::Keystore(KeystoreError::Corrupt(
            "the sealed device PIN key does not load in this machine's TPM"
        )))
    );
    assert_eq!(chip.state().wrong_tries, 0);
    chip.nothing_stays_loaded();

    // A file that others can read is refused.
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("the mode changes");
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::Keystore(KeystoreError::Corrupt(
            "the device PIN key file is open to others"
        )))
    );
}

#[test]
fn only_the_unseal_answers_a_wrong_auth_value() {
    let chip = ScriptedChip::start(8, Some(600));
    let keys = chip.keystore();
    let store = keys.auth_bound_secret().expect("an auth-bound secret");
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");

    // A refusal the chip did not count is a wrong auth value too.
    chip.state().next_unseal_code = Some(RC_BAD_AUTH_SESSION_1);
    assert_eq!(store.open_auth_bound(&AUTH), Err(AuthBoundError::WrongAuth));
    // Another code is the chip's failure by command and code.
    chip.state().next_unseal_code = Some(RC_RETRY);
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Err(AuthBoundError::Keystore(KeystoreError::Platform(
            "tpm2 unseal",
            i64::from(RC_RETRY)
        )))
    );
    chip.nothing_stays_loaded();
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));

    // To a slot a refused unseal stays `Denied`, as before this row.
    let slot = owner_slot(7);
    keys.create(&slot, &SECRET).expect("the slot fills");
    for code in [RC_BAD_AUTH_SESSION_1, RC_AUTH_FAIL_SESSION_1, RC_LOCKOUT] {
        chip.state().next_unseal_code = Some(code);
        assert_eq!(
            keys.get(&slot),
            Err(KeystoreError::Denied),
            "code {code:#x}"
        );
    }
    chip.nothing_stays_loaded();
}

#[test]
fn the_tpm_tier_keeps_caller_sealed_bytes_beside_its_slots_and_asks_the_chip_nothing() {
    let chip = ScriptedChip::start(8, Some(600));
    let keys = chip.keystore();
    let home = keys
        .sealed_bytes()
        .expect("the TPM tier has a home for sealed bytes");
    let mark = chip.command_count();
    let device = SealedBytesName::DevicePinKey;
    let seed = SealedBytesName::Slot(owner_slot(7));
    assert_eq!(home.get_sealed(&seed), Ok(None));
    home.put_sealed(&seed, b"owner seed, sealed by the engine")
        .expect("the sealed seed is kept");
    home.put_sealed(&device, b"sealed by the engine")
        .expect("a sealed value under the device PIN key's name is kept");
    assert_eq!(
        home.get_sealed(&seed),
        Ok(Some(b"owner seed, sealed by the engine".to_vec()))
    );
    assert!(
        chip.commands_since(mark).is_empty(),
        "the sealed-bytes home asked the chip"
    );

    // The sealed bytes, the chip's device PIN key and a slot of the same
    // names are three files, and none reads another.
    let store = keys.auth_bound_secret().expect("an auth-bound secret");
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the secret is sealed");
    keys.create(&owner_slot(7), &OTHER_SECRET)
        .expect("the slot fills");
    assert_eq!(
        home.get_sealed(&device),
        Ok(Some(b"sealed by the engine".to_vec()))
    );
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
    assert_eq!(keys.get(&owner_slot(7)), Ok(Some(held(OTHER_SECRET))));
    let slot_name = owner_slot(7).name();
    assert_eq!(
        file_names(&chip.key_dir()),
        [
            format!("{slot_name}.sealed"),
            format!("{slot_name}.tpm2"),
            "CACHEDIR.TAG".to_owned(),
            "device-pin-key.sealed".to_owned(),
            "device-pin-key.tpm2".to_owned(),
        ]
    );
    home.delete_sealed(&device)
        .expect("the sealed value is removed");
    assert_eq!(
        store.holds_auth_bound(),
        Ok(true),
        "removing sealed bytes removed the chip's device PIN key"
    );
}

/// A software TPM (`swtpm`) on a socket of its own, with fresh state. It is
/// stopped when this drops.
struct SoftwareTpm {
    child: std::process::Child,
    root: tempfile::TempDir,
}

impl SoftwareTpm {
    fn start() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let state = root.path().join("state");
        fs::create_dir(&state).expect("the state directory");
        let socket = root.path().join("tpm.sock");
        let child = std::process::Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", state.display()))
            .arg("--server")
            .arg(format!("type=unixio,path={}", socket.display()))
            .arg("--ctrl")
            .arg(format!(
                "type=unixio,path={}",
                root.path().join("ctrl.sock").display()
            ))
            .arg("--flags")
            .arg("startup-clear")
            .spawn()
            .expect("swtpm starts: it must be on the path");
        let started = Instant::now();
        while !socket.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "swtpm made no socket in 20 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The socket's name appears before swtpm listens on it.
        std::thread::sleep(Duration::from_millis(500));
        Self { child, root }
    }

    fn keystore(&self) -> LinuxTpmKeystore {
        LinuxTpmKeystore::open_on_socket(
            &self.root.path().join("keys"),
            &[],
            &self.root.path().join("tpm.sock"),
        )
        .expect("the tier opens on the software TPM")
    }
}

impl Drop for SoftwareTpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The same tier against a TPM this file did not write. It asserts what any
/// TPM 2.0 must do and prints what this one's settings are: how many wrong
/// auth values it counts before its lockout, and its recovery interval.
#[test]
#[ignore = "needs swtpm on the path: run with -- --ignored a_software_tpm"]
fn a_software_tpm_opens_for_the_right_auth_value_counts_wrong_ones_and_locks_out() {
    let tpm = SoftwareTpm::start();
    let keys = tpm.keystore();
    let store = keys
        .auth_bound_secret()
        .expect("the TPM tier has an auth-bound secret");
    let slot = owner_slot(7);

    // A slot, as before this row: sealed and opened with the empty password.
    keys.create(&slot, &OTHER_SECRET).expect("the slot fills");
    assert_eq!(keys.get(&slot), Ok(Some(held(OTHER_SECRET))));

    assert_eq!(store.open_auth_bound(&AUTH), Ok(None));
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the TPM seals the secret under the auth value");
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
    // An auth value that ends in zeros is the same value to the TPM.
    let mut ends_in_zeros = [0x42; 32];
    ends_in_zeros[31] = 0;
    store
        .put_auth_bound(&ends_in_zeros, &SECRET)
        .expect("the TPM seals under an auth value that ends in a zero");
    assert_eq!(
        store.open_auth_bound(&ends_in_zeros),
        Ok(Some(held(SECRET)))
    );
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the TPM seals the secret again");

    // Wrong auth values, until the TPM's own limit. Each one before it is a
    // wrong auth value; none opens the secret.
    let mut wrong_tries = 0;
    let wait_secs = loop {
        match store.open_auth_bound(&OTHER_AUTH) {
            Err(AuthBoundError::WrongAuth) => wrong_tries += 1,
            Err(AuthBoundError::LockedOut { wait_secs }) => break wait_secs,
            other => panic!("a wrong auth value answered {other:?}"),
        }
        assert!(wrong_tries <= 64, "the TPM never locked out");
    };
    assert!(
        wrong_tries >= 1,
        "the TPM was in lockout before one wrong auth value"
    );
    println!(
        "## SWTPM-LOCKOUT wrong auth values counted before the lockout: {wrong_tries}; recovery interval reported: {wait_secs} s"
    );
    assert!(wait_secs > 0);
    assert_ne!(
        wait_secs, DEVICE_PIN_WAIT_SECS,
        "the wait is the gate's, not the TPM's own interval"
    );

    // In lockout the right auth value is refused too, and stays refused.
    for _ in 0..2 {
        assert_eq!(
            store.open_auth_bound(&AUTH),
            Err(AuthBoundError::LockedOut { wait_secs })
        );
    }
    // The slots are not counted: they open, fill and empty in lockout.
    assert_eq!(keys.get(&slot), Ok(Some(held(OTHER_SECRET))));
    let second = owner_slot(8);
    keys.create(&second, &SECRET)
        .expect("a slot fills in lockout");
    assert_eq!(keys.get(&second), Ok(Some(held(SECRET))));
    // A new object is made in lockout (its parent is not counted), and it
    // does not open until the TPM forgets.
    store
        .put_auth_bound(&OTHER_AUTH, &OTHER_SECRET)
        .expect("a new auth value seals in lockout");
    assert_eq!(
        store.open_auth_bound(&OTHER_AUTH),
        Err(AuthBoundError::LockedOut { wait_secs })
    );
    store.delete_auth_bound().expect("the secret is removed");
    assert_eq!(store.open_auth_bound(&AUTH), Ok(None));
}

/// This machine's own TPM, through the kernel's resource manager. It spends
/// one of the chip's wrong tries and leaves nothing behind.
#[test]
#[ignore = "needs this machine's TPM 2.0 and spends one of its wrong tries: run with -- --ignored this_machines_tpm"]
fn this_machines_tpm_opens_for_the_right_auth_value_and_counts_one_wrong_one() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let keys = LinuxTpmKeystore::open(&root.path().join("keys"), &[])
        .expect("this machine's TPM answers (its device needs the tss group)");
    let store = keys
        .auth_bound_secret()
        .expect("the TPM tier has an auth-bound secret");
    store
        .put_auth_bound(&AUTH, &SECRET)
        .expect("the TPM seals the secret under the auth value");
    assert_eq!(store.open_auth_bound(&AUTH), Ok(Some(held(SECRET))));
    assert_eq!(
        store.open_auth_bound(&OTHER_AUTH),
        Err(AuthBoundError::WrongAuth)
    );
    assert_eq!(
        store.open_auth_bound(&AUTH),
        Ok(Some(held(SECRET))),
        "one wrong try put this TPM in lockout: its count was near its limit"
    );
    store.delete_auth_bound().expect("the secret is removed");
}
