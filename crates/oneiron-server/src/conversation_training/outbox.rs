//! The outbox directory as the engine's training transport: three protocol
//! subdirectories and the vault's scopes file under one lock, written whole.
//!
//! An offer is staged in `offers/` under hidden names (`.<file>.staged`,
//! never a protocol file), each synced. Publishing renames the chunks in
//! first and the manifest last, then syncs the directory, so a manifest the
//! consumer sees always has its chunks. A purge removes the manifest first.
//! Controls are written whole into `controls/`; receipts are read from
//! `receipts/` against each scope's own cursor and removed once the engine
//! applied them, and a receipt for a scope the vault does not list is never
//! removed here. The scopes file (`training-scopes.v2.json`) is rewritten
//! whole when the engine's list of scopes or a cursor differs from it.
//! Nothing here decides what is staged, published or purged.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use oneiron::feedback::{
    PublisherTrainingLifecycle, ReceiptCursor, ReceivedTrainingReceipt, SealedTrainingOffer,
    SignedTrainingControl, TrainingQueued, TrainingReceiptPage, TrainingSubmissionId,
};
use oneiron_vault_contract::conversation_training::{
    CONTROLS_DIR, OFFERS_DIR, RECEIPTS_DIR, TRAINING_SCHEMA_VERSION, TRAINING_SCOPES_FILE,
    TRAINING_SCOPES_TYPE, TrainingFileName, TrainingScopeCursorV2, TrainingScopesV2,
    decode_training_receipt, parse_training_file_name, spool_training_file,
};

/// Held for a tick, so two vault processes never share the directory.
const LOCK_FILE: &str = ".lock";
/// The suffix of a staged offer file.
const STAGED_SUFFIX: &str = ".staged";

/// The outbox, locked for one tick.
pub(super) struct Outbox {
    root: PathBuf,
    offers: PathBuf,
    controls: PathBuf,
    receipts: PathBuf,
    /// The directory's lock, released when the tick drops the outbox.
    _lock: File,
}

impl Outbox {
    /// The outbox at `root`, its subdirectories made owner-only where
    /// missing, under its lock; `None` while another process holds it.
    pub(super) fn open(root: &Path) -> anyhow::Result<Option<Self>> {
        let offers = root.join(OFFERS_DIR);
        let controls = root.join(CONTROLS_DIR);
        let receipts = root.join(RECEIPTS_DIR);
        for dir in [
            root,
            offers.as_path(),
            controls.as_path(),
            receipts.as_path(),
        ] {
            ensure_directory(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let path = root.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let lock = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        match lock.try_lock() {
            Ok(()) => Ok(Some(Self {
                root: root.to_path_buf(),
                offers,
                controls,
                receipts,
                _lock: lock,
            })),
            Err(fs::TryLockError::WouldBlock) => {
                tracing::debug!(
                    dir = %root.display(),
                    "another process holds the publisher training outbox; this tick waits"
                );
                Ok(None)
            }
            Err(fs::TryLockError::Error(error)) => {
                Err(anyhow::Error::new(error).context(format!("lock {}", path.display())))
            }
        }
    }

    /// Where a protocol file of `offers/` is staged.
    fn staged(&self, name: &str) -> PathBuf {
        self.offers.join(format!(".{name}{STAGED_SUFFIX}"))
    }

    /// The protocol names of `submission`'s files in `offers/`: those
    /// published, and those staged.
    fn offer_files(&self, submission: &str) -> io::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut published = BTreeSet::new();
        let mut staged = BTreeSet::new();
        for entry in fs::read_dir(&self.offers)? {
            let Ok(name) = entry?.file_name().into_string() else {
                continue;
            };
            let hidden = name
                .strip_prefix('.')
                .and_then(|rest| rest.strip_suffix(STAGED_SUFFIX))
                .map(str::to_owned);
            let (protocol, set) = match hidden {
                Some(protocol) => (protocol, &mut staged),
                None => (name, &mut published),
            };
            if names_submission(&protocol, submission) {
                set.insert(protocol);
            }
        }
        Ok((published, staged))
    }
}

impl PublisherTrainingLifecycle for Outbox {
    fn accept(&self, offer: &SealedTrainingOffer) -> oneiron::Result<TrainingQueued> {
        for (name, bytes) in offer.chunks.iter().chain(std::iter::once(&offer.manifest)) {
            write_synced(&self.staged(name), bytes).map_err(oneiron::Error::Io)?;
        }
        Ok(TrainingQueued {
            id: offer.submission.0,
            scope: offer.scope,
            event_seq: offer.event_seq,
        })
    }

    fn publish(&self, queued: &TrainingQueued) -> oneiron::Result<()> {
        let submission = TrainingSubmissionId(queued.id).to_hex();
        let (_, staged) = self.offer_files(&submission).map_err(oneiron::Error::Io)?;
        let (manifests, chunks): (Vec<String>, Vec<String>) =
            staged.into_iter().partition(|name| {
                matches!(
                    parse_training_file_name(name),
                    Some(TrainingFileName::OfferManifest { .. })
                )
            });
        if manifests.is_empty() {
            return Err(oneiron::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "a released training offer has no staged manifest",
            )));
        }
        for name in chunks.iter().chain(&manifests) {
            fs::rename(self.staged(name), self.offers.join(name)).map_err(oneiron::Error::Io)?;
        }
        sync_dir(&self.offers).map_err(oneiron::Error::Io)
    }

    fn purge(&self, submission: TrainingSubmissionId) -> oneiron::Result<()> {
        let submission = submission.to_hex();
        let (published, staged) = self.offer_files(&submission).map_err(oneiron::Error::Io)?;
        // The manifest first: a consumer never meets one whose chunks went.
        let mut ordered: Vec<&String> = published.iter().collect();
        ordered.sort_by_key(|name| {
            !matches!(
                parse_training_file_name(name),
                Some(TrainingFileName::OfferManifest { .. })
            )
        });
        for name in ordered {
            remove_if_present(&self.offers.join(name)).map_err(oneiron::Error::Io)?;
        }
        for name in &staged {
            remove_if_present(&self.staged(name)).map_err(oneiron::Error::Io)?;
        }
        sync_dir(&self.offers).map_err(oneiron::Error::Io)
    }

    fn control(&self, control: &SignedTrainingControl) -> oneiron::Result<TrainingQueued> {
        // A file already there is this control: its name holds its id.
        if fs::symlink_metadata(self.controls.join(&control.file)).is_err() {
            spool_training_file(&self.controls, &control.file, &control.bytes)
                .map_err(|error| oneiron::Error::Io(io::Error::other(format!("{error:#}"))))?;
        }
        Ok(TrainingQueued {
            id: control.control.0,
            scope: control.scope,
            event_seq: control.event_seq,
        })
    }

    fn receipts(&self, after: &[ReceiptCursor]) -> oneiron::Result<TrainingReceiptPage> {
        let mut page = TrainingReceiptPage::default();
        for entry in fs::read_dir(&self.receipts).map_err(oneiron::Error::Io)? {
            let entry = entry.map_err(oneiron::Error::Io)?;
            let Ok(file) = entry.file_name().into_string() else {
                continue;
            };
            let receipt_file = matches!(
                parse_training_file_name(&file),
                Some(TrainingFileName::Receipt { .. })
            );
            if !receipt_file || !matches!(entry.file_type(), Ok(kind) if kind.is_file()) {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(oneiron::Error::Io)?;
            let receipt = match decode_training_receipt(&bytes) {
                Ok(receipt) => receipt,
                Err(error) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        %file,
                        "a publisher training receipt is malformed; it applies nothing"
                    );
                    continue;
                }
            };
            // Each scope's cursor reads its own receipts only; one for a
            // scope `after` does not name goes to the engine, which refuses
            // it unapplied and leaves it where it is.
            let applied = after
                .iter()
                .find(|cursor| cursor.scope.to_hex() == receipt.body.scope)
                .is_some_and(|cursor| receipt.body.publisher_sequence <= cursor.sequence);
            if applied {
                page.stale.push(file);
            } else {
                page.receipts
                    .push(ReceivedTrainingReceipt { file, receipt });
            }
        }
        Ok(page)
    }

    fn scopes(&self, scopes: &[ReceiptCursor]) -> oneiron::Result<()> {
        let file = TrainingScopesV2 {
            schema_version: TRAINING_SCHEMA_VERSION,
            file_type: TRAINING_SCOPES_TYPE.to_owned(),
            scopes: scopes
                .iter()
                .map(|cursor| TrainingScopeCursorV2 {
                    scope: cursor.scope.to_hex(),
                    receipt_cursor: cursor.sequence,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|error| {
            oneiron::Error::Io(io::Error::other(format!(
                "the training scopes file does not encode: {error}"
            )))
        })?;
        // Rewritten whole only when it differs: the list or a cursor moved.
        if fs::read(self.root.join(TRAINING_SCOPES_FILE)).is_ok_and(|held| held == bytes) {
            return Ok(());
        }
        spool_training_file(&self.root, TRAINING_SCOPES_FILE, &bytes)
            .map_err(|error| oneiron::Error::Io(io::Error::other(format!("{error:#}"))))?;
        Ok(())
    }

    fn retire_receipt(&self, file: &str) -> oneiron::Result<()> {
        if !matches!(
            parse_training_file_name(file),
            Some(TrainingFileName::Receipt { .. })
        ) {
            return Ok(());
        }
        remove_if_present(&self.receipts.join(file)).map_err(oneiron::Error::Io)?;
        sync_dir(&self.receipts).map_err(oneiron::Error::Io)
    }
}

/// Whether protocol file `name` is one of `submission`'s offer files.
fn names_submission(name: &str, submission: &str) -> bool {
    match parse_training_file_name(name) {
        Some(
            TrainingFileName::OfferManifest { submission: named }
            | TrainingFileName::OfferChunk {
                submission: named, ..
            },
        ) => named == submission,
        _ => false,
    }
}

/// Writes `bytes` to `path`, owner-only, and syncs it.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    remove_if_present(path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn ensure_directory(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}
