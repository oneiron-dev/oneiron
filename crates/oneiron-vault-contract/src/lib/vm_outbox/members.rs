//! Each outbox kind's member names, as the carrier takes them: the owning
//! protocol's own file names, relative to the kind's root, never a path
//! outside it. A name is one to five plain parts joined by `/`, each letters,
//! digits, `.`, `_` and `-`, none hidden: a producer's temporaries and locks
//! (a leading `.`) are never members.

use super::{VmOutboxKind, VmOutboxSide};
use crate::backup_handoff::backup_stage_ack_file_name;
use crate::conversation_training::{
    CONTROLS_DIR, INTAKE_RECEIPT_KEY_FILE, INTAKE_RECIPIENT_FILE, OFFERS_DIR, RECEIPTS_DIR,
    SCOPES_DIR, TrainingFileName, parse_training_file_name,
};
use crate::escrow::escrow_report_file_name;
use crate::esign_delivery::ESIGN_DELIVERY_FILE_PREFIX;

/// The most parts a member name has (a custody log frame's).
const MAX_PARTS: usize = 5;
/// The longest part: a filesystem name's own bound.
const MAX_PART_BYTES: usize = 255;
/// The escrow recipients' files, as a node stages them.
const RECIPIENT_FILES: [&str; 2] = ["managed.pub", "break-glass.pub"];
/// The custody batch files the engine stages, and the one it writes last.
const CUSTODY_STAGED: [&str; 3] = ["meta.json", "head", "frames.jsonl"];
const CUSTODY_READY: &str = "READY";
/// The control plane's answers the node writes into a custody batch.
const CUSTODY_ANSWERS: [&str; 2] = ["ack.json", "pending.json"];
/// A sealed backup's suffix (`owner::backup`).
const BACKUP_SUFFIX: &str = ".oneiron-backup";
/// The suffix of a sealed backup's checkpoint fact beside it,
/// `<artifact>.cpfact` (`owner::backup::checkpoint_fact`, FIX 7327).
const CHECKPOINT_FACT_SUFFIX: &str = ".cpfact";

/// How the carrier treats one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmOutboxMember {
    /// The one side that puts it.
    pub origin: VmOutboxSide,
    /// Whether the other side's removal of it retires it at the origin too,
    /// as removing the one shared copy does on a node.
    pub peer_retires: bool,
    /// The guest keeps it root-owned, readable by the vault's group only
    /// (root:UID 0640), in a root-owned directory: a public key the engine
    /// must never replace.
    pub protected: bool,
    /// The set it is published with: the members a sender sends together and
    /// a receiver publishes all at once or not at all.
    pub set: String,
    /// Its place in its set when put, lowest first.
    pub put_rank: u8,
    /// Its place in its set when removed, lowest first.
    pub remove_rank: u8,
}

impl VmOutboxMember {
    fn single(origin: VmOutboxSide, member: &str) -> Self {
        Self {
            origin,
            peer_retires: true,
            protected: false,
            set: member.to_owned(),
            put_rank: 0,
            remove_rank: 0,
        }
    }

    fn in_set(origin: VmOutboxSide, set: String, put_rank: u8, remove_rank: u8) -> Self {
        Self {
            origin,
            peer_retires: true,
            protected: false,
            set,
            put_rank,
            remove_rank,
        }
    }
}

/// The class of `kind`'s member `member`, or `None` for a name that is not
/// one of that kind's protocol members.
#[must_use]
pub fn vm_outbox_member(kind: VmOutboxKind, member: &str) -> Option<VmOutboxMember> {
    let parts = plain_parts(member)?;
    match (kind, parts.as_slice()) {
        (VmOutboxKind::Escrow, [name]) => escrow(name, member),
        (VmOutboxKind::Custody, parts) => custody(parts),
        (VmOutboxKind::Esign, [name]) => esign(name),
        (VmOutboxKind::Training, parts) => training(parts, member),
        (VmOutboxKind::Recipients, [name]) if RECIPIENT_FILES.contains(name) => {
            Some(VmOutboxMember {
                protected: true,
                ..VmOutboxMember::in_set(VmOutboxSide::Host, "recipients".to_owned(), 0, 0)
            })
        }
        (VmOutboxKind::Backup, [name]) => backup(name),
        (VmOutboxKind::BackupStageAck, [_label, ack]) => {
            let digest = ack.strip_prefix("stage-ack-")?.strip_suffix(".json")?;
            (backup_stage_ack_file_name(digest).as_deref() == Some(*ack))
                .then(|| VmOutboxMember::single(VmOutboxSide::Host, member))
        }
        _ => None,
    }
}

/// `member`'s parts, when each is plain and there are at most
/// [`MAX_PARTS`].
fn plain_parts(member: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = member.split('/').collect();
    let plain = |part: &&str| {
        !part.is_empty()
            && part.len() <= MAX_PART_BYTES
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    (parts.len() <= MAX_PARTS && parts.iter().all(plain)).then_some(parts)
}

/// A sealed backup, `<label>-<...>.oneiron-backup`, and its checkpoint fact,
/// `<that name>.cpfact`, in one set the artifact names: the fact put before
/// the artifact and retired after it, as the engine writes and prunes them.
/// Only the engine's prune retires either. An artifact with no fact (one
/// taken before facts, or whose fact did not land) is a set of one.
fn backup(name: &str) -> Option<VmOutboxMember> {
    let (artifact, put_rank, remove_rank) = match name.strip_suffix(CHECKPOINT_FACT_SUFFIX) {
        Some(artifact) => (artifact, 0, 1),
        None => (name, 1, 0),
    };
    let stem = artifact.strip_suffix(BACKUP_SUFFIX)?;
    stem.contains('-').then(|| VmOutboxMember {
        peer_retires: false,
        ..VmOutboxMember::in_set(
            VmOutboxSide::Guest,
            artifact.to_owned(),
            put_rank,
            remove_rank,
        )
    })
}

fn escrow(name: &str, member: &str) -> Option<VmOutboxMember> {
    let label = name
        .strip_prefix("vault-key-escrow-")?
        .strip_suffix(".json")?;
    (escrow_report_file_name(label).as_deref() == Some(name))
        .then(|| VmOutboxMember::single(VmOutboxSide::Guest, member))
}

/// `<slot>/<target>/b.<operation>.r<revision>/<file>`, or a log frame
/// `.../log/f<16 hex>`: the engine's batch, READY put last and removed first,
/// and the node's answers in it.
fn custody(parts: &[&str]) -> Option<VmOutboxMember> {
    let (batch, rest) = match parts {
        [slot, target, batch, rest @ ..] if batch.starts_with("b.") && !rest.is_empty() => {
            (format!("{slot}/{target}/{batch}"), rest)
        }
        _ => return None,
    };
    match rest {
        [file] if CUSTODY_STAGED.contains(file) => {
            Some(VmOutboxMember::in_set(VmOutboxSide::Guest, batch, 0, 1))
        }
        [file] if *file == CUSTODY_READY => {
            Some(VmOutboxMember::in_set(VmOutboxSide::Guest, batch, 1, 0))
        }
        [file] if CUSTODY_ANSWERS.contains(file) => {
            Some(VmOutboxMember::in_set(VmOutboxSide::Host, batch, 0, 1))
        }
        ["log", frame] => {
            let seq = frame.strip_prefix('f')?;
            (seq.len() == 16 && seq.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                .then(|| VmOutboxMember::in_set(VmOutboxSide::Guest, batch, 0, 1))
        }
        _ => None,
    }
}

/// `esign-delivery-<key>.json`, `.done.json` and `.ack.json`, one set per
/// key: the engine's envelope removal, then its receipt, then its removal of
/// the sender's ack, in that order (H1); the sender retires the receipt last.
fn esign(name: &str) -> Option<VmOutboxMember> {
    let rest = name.strip_prefix(ESIGN_DELIVERY_FILE_PREFIX)?;
    let (key, origin, put_rank, remove_rank) = if let Some(key) = rest.strip_suffix(".ack.json") {
        (key, VmOutboxSide::Host, 0, 2)
    } else if let Some(key) = rest.strip_suffix(".done.json") {
        (key, VmOutboxSide::Guest, 1, 3)
    } else {
        (rest.strip_suffix(".json")?, VmOutboxSide::Guest, 0, 0)
    };
    super::is_digest(key).then(|| {
        VmOutboxMember::in_set(
            origin,
            format!("esign-delivery-{key}"),
            put_rank,
            remove_rank,
        )
    })
}

/// The training outbox's protocol files under their own directories, and the
/// intake's key pair at its root, published as one protected set.
fn training(parts: &[&str], member: &str) -> Option<VmOutboxMember> {
    match parts {
        [key] if *key == INTAKE_RECIPIENT_FILE || *key == INTAKE_RECEIPT_KEY_FILE => {
            Some(VmOutboxMember {
                protected: true,
                ..VmOutboxMember::in_set(VmOutboxSide::Host, "intake-keys".to_owned(), 0, 0)
            })
        }
        [dir, name] => match (*dir, parse_training_file_name(name)?) {
            (OFFERS_DIR, TrainingFileName::OfferManifest { submission }) => Some(
                VmOutboxMember::in_set(VmOutboxSide::Guest, format!("offers/{submission}"), 1, 0),
            ),
            (OFFERS_DIR, TrainingFileName::OfferChunk { submission, .. }) => Some(
                VmOutboxMember::in_set(VmOutboxSide::Guest, format!("offers/{submission}"), 0, 1),
            ),
            (CONTROLS_DIR, TrainingFileName::Control { .. })
            | (SCOPES_DIR, TrainingFileName::Scopes) => {
                Some(VmOutboxMember::single(VmOutboxSide::Guest, member))
            }
            (RECEIPTS_DIR, TrainingFileName::Receipt { .. }) => {
                Some(VmOutboxMember::single(VmOutboxSide::Host, member))
            }
            _ => None,
        },
        _ => None,
    }
}
