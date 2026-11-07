//! A skill body a code-run call's answer carries, witnessed where a native
//! producer made the answer (FIX 3608). Two producers hand a run a skill's
//! stored files after its first step: the skill library's view
//! (`vault.skills.get`, and the list, archive and restore answers made of
//! it), whose files are the package's exact bytes, and the leader's pattern
//! load (`self.leader.pattern`), whose files are text. Each witnesses the
//! entity it read, its revision as `skill_id@version`, and every file its
//! answer carries exactly: the file's path, the byte extent of it the
//! answer carries and the BLAKE3 of those bytes. A file an answer decodes
//! lossily is no span: the answer does not hold its bytes.
//!
//! A witness is made from what the producer returned. It is never inferred
//! from the rows an answer was served from, nor from a stored value's
//! sources: neither proves that the answer holds a skill's bytes. Beside the
//! bodies it binds the BLAKE3 of the producer's answer as JSON
//! ([`WitnessedAnswer`]): a verb hook's redaction inside the verb's door,
//! or any other change on the way to the run, leaves the answer the run got
//! another one, which delivers nothing. The run's host keeps a witness as a
//! delivery only for the answer the producer made, once its guest read it
//! (`engine_executor` host, FIX 3608).

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::verbs::{SkillLibraryPage, SkillLibraryRestoreReceipt, SkillLibraryView};

/// One stored file of a skill that an answer carries exactly: its path in
/// the skill's package, the byte extent of its bytes the answer carries,
/// `start..end`, and the BLAKE3 of those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SkillFileSpan {
    pub(crate) path: String,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) digest: [u8; 32],
}

impl SkillFileSpan {
    /// All of `content`, the file at `path`.
    pub(crate) fn whole(path: &str, content: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            start: 0,
            end: content.len() as u64,
            digest: *blake3::hash(content).as_bytes(),
        }
    }
}

/// A skill body one answer carries, as its producer made the answer: the
/// entity whose body it read, its revision as `skill_id@version`, and each
/// file of it the answer carries exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SkillBodyWitness {
    pub(crate) entity: EntityId,
    pub(crate) revision: String,
    pub(crate) files: Vec<SkillFileSpan>,
}

impl SkillBodyWitness {
    /// The witness of `files`, the files of `entity` at `skill_id@version`
    /// an answer carries exactly; `None` when it carries none.
    pub(crate) fn of_files(
        entity: EntityId,
        skill_id: &str,
        version: &str,
        files: Vec<SkillFileSpan>,
    ) -> Option<Self> {
        (!files.is_empty()).then(|| Self {
            entity,
            revision: format!("{skill_id}@{version}"),
            files,
        })
    }

    /// The skill library's view of one skill: every file of the package the
    /// view read, whole, as the view carries its bytes.
    fn of_library_view(view: &SkillLibraryView) -> Option<Self> {
        let files = view
            .files
            .iter()
            .flatten()
            .map(|file| SkillFileSpan::whole(&file.path, &file.content))
            .collect();
        Self::of_files(view.entity, &view.skill_id, &view.version, files)
    }
}

/// What one producer witnessed of the answer it made (FIX 3608): the BLAKE3
/// of the answer as JSON ([`answer_digest`]), and each skill body the answer
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessedAnswer {
    pub(crate) answer: [u8; 32],
    pub(crate) bodies: Vec<SkillBodyWitness>,
}

/// The BLAKE3 of `json`, an answer's JSON bytes: what a witness binds and
/// what the run's host checks the answer it got against.
pub(crate) fn answer_digest(json: &[u8]) -> [u8; 32] {
    *blake3::hash(json).as_bytes()
}

/// An answer a native producer made that carries skill bodies (FIX 3608).
pub(crate) trait CarriesSkillBodies {
    /// Each skill body the answer carries, as its producer made it.
    fn skill_bodies(&self) -> Vec<SkillBodyWitness>;
}

impl CarriesSkillBodies for SkillLibraryView {
    fn skill_bodies(&self) -> Vec<SkillBodyWitness> {
        SkillBodyWitness::of_library_view(self)
            .into_iter()
            .collect()
    }
}

impl CarriesSkillBodies for SkillLibraryPage {
    fn skill_bodies(&self) -> Vec<SkillBodyWitness> {
        self.skills
            .iter()
            .filter_map(SkillBodyWitness::of_library_view)
            .collect()
    }
}

impl CarriesSkillBodies for SkillLibraryRestoreReceipt {
    fn skill_bodies(&self) -> Vec<SkillBodyWitness> {
        match self {
            Self::Restored { skill, .. } => skill.skill_bodies(),
            Self::PendingAdmission { .. } | Self::Refused { .. } => Vec::new(),
        }
    }
}

/// Where one code-run call's producer puts what it witnessed of its answer
/// (FIX 3608): shared by the call's write origin and the run's dispatcher,
/// and closed once the dispatcher takes it, so nothing a producer witnesses
/// later joins the call's. A call's producer answers once; a second witness
/// in one call leaves the call with none.
#[derive(Debug, Clone, Default)]
pub(crate) struct SkillBodyCapture(Arc<Mutex<SkillBodyState>>);

#[derive(Debug, Default)]
struct SkillBodyState {
    witnessed: Option<WitnessedAnswer>,
    closed: bool,
}

impl PartialEq for SkillBodyCapture {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl SkillBodyCapture {
    /// Keeps `witnessed`, what the call's producer witnessed of its answer,
    /// while the capture is open; a second witness closes it with none.
    pub(crate) fn witness(&self, witnessed: WitnessedAnswer) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if state.closed {
            return;
        }
        if state.witnessed.is_some() {
            state.witnessed = None;
            state.closed = true;
            return;
        }
        state.witnessed = Some(witnessed);
    }

    /// Closes the capture and takes what it kept; none when its lock was
    /// poisoned, so no delivery is kept for the call.
    pub(crate) fn finish(&self) -> Option<WitnessedAnswer> {
        let mut state = self.0.lock().ok()?;
        state.closed = true;
        state.witnessed.take()
    }
}
