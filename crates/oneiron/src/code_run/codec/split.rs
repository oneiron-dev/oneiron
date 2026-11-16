//! The replay record's split form: a head row and one item row per family
//! element. The whole encoding stays the canonical form; split cuts it and
//! join rebuilds it byte for byte.

use rmpv::Value;

use crate::side_table::CodecError;
use crate::{EntityId, Error};

use super::super::replay::{
    CODE_RUN_REPLAY_HASH_LEN, CodeRunReplayGeneration, CodeRunReplayRecord,
};
use super::super::support::{fixed_binary, invalid_code_run_replay, u64_value};
use super::held::{array_len, key_index, map_len, read, skip_values, walk};

/// One of the four families whose elements live in item rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayFamily {
    /// The run's bridge calls, top-level key 3.
    BridgeCalls,
    /// The run's step checkpoints, top-level key 4.
    StepCheckpoints,
    /// The run's outputs, top-level key 5.
    Outputs,
    /// The run's result bindings, top-level key 7.
    Bindings,
}

impl ReplayFamily {
    /// Every family in item-key order.
    pub(crate) const ALL: [Self; 4] = [
        Self::BridgeCalls,
        Self::StepCheckpoints,
        Self::Outputs,
        Self::Bindings,
    ];

    /// The family's one-byte item-key tag.
    #[must_use]
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::BridgeCalls => 0,
            Self::StepCheckpoints => 1,
            Self::Outputs => 2,
            Self::Bindings => 3,
        }
    }

    /// The family for an item-key tag, if any.
    #[must_use]
    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::BridgeCalls),
            1 => Some(Self::StepCheckpoints),
            2 => Some(Self::Outputs),
            3 => Some(Self::Bindings),
            _ => None,
        }
    }

    /// The family's top-level key index in the record map.
    #[must_use]
    pub(crate) const fn key_index(self) -> usize {
        match self {
            Self::BridgeCalls => 3,
            Self::StepCheckpoints => 4,
            Self::Outputs => 5,
            Self::Bindings => 7,
        }
    }

    /// The family for a top-level key index, if it names one.
    const fn from_key_index(index: usize) -> Option<Self> {
        match index {
            3 => Some(Self::BridgeCalls),
            4 => Some(Self::StepCheckpoints),
            5 => Some(Self::Outputs),
            7 => Some(Self::Bindings),
            _ => None,
        }
    }

    /// The family's slot in the four-family arrays, in [`Self::ALL`] order.
    pub(crate) const fn slot(self) -> usize {
        match self {
            Self::BridgeCalls => 0,
            Self::StepCheckpoints => 1,
            Self::Outputs => 2,
            Self::Bindings => 3,
        }
    }
}

/// The bytes `cursor` consumed since it held `before` bytes of `whole`.
fn consumed<'a>(whole: &'a [u8], before: usize, cursor: &[u8]) -> &'a [u8] {
    let after = cursor.len();
    let start = whole.len().saturating_sub(before);
    let end = whole.len().saturating_sub(after);
    &whole[start..end]
}

/// The whole record's shell and its four families' element bytes. The shell
/// copies every byte verbatim except each family's array value, which becomes
/// empty; each element is its exact bytes cut by framing.
pub(crate) fn split_canonical(
    whole: &[u8],
) -> std::result::Result<(Vec<u8>, [Vec<Vec<u8>>; 4]), CodecError> {
    let mut cursor = whole;
    let before = cursor.len();
    let entries = map_len(&mut cursor)?;
    let mut shell = Vec::with_capacity(whole.len());
    shell.extend_from_slice(consumed(whole, before, cursor));
    let mut families: [Vec<Vec<u8>>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut seen = [false; super::CODE_RUN_REPLAY_RECORD_KEYS.len()];
    for _ in 0..entries {
        let before = cursor.len();
        let index = key_index(&mut cursor)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(invalid_code_run_replay("duplicate map key").into());
        }
        shell.extend_from_slice(consumed(whole, before, cursor));
        if let Some(family) = ReplayFamily::from_key_index(index) {
            let len = array_len(&mut cursor)?;
            for _ in 0..len {
                let before = cursor.len();
                skip_values(&mut cursor, 1)?;
                families[family.slot()].push(consumed(whole, before, cursor).to_vec());
            }
            shell.push(0x90);
        } else {
            let before = cursor.len();
            skip_values(&mut cursor, 1)?;
            shell.extend_from_slice(consumed(whole, before, cursor));
        }
    }
    if !cursor.is_empty() {
        return Err(invalid_code_run_replay("trailing bytes after code-run replay record").into());
    }
    for family in ReplayFamily::ALL {
        if !seen[family.key_index()] {
            return Err(invalid_code_run_replay("missing replay record field").into());
        }
    }
    Ok((shell, families))
}

/// The whole record for a shell and its four families' element bytes. The
/// shell copies verbatim except at the four family keys, whose value must be
/// empty and is replaced by the minimal array header for that family's count
/// followed by the element slices verbatim.
pub(crate) fn join_canonical(
    shell: &[u8],
    families: [&[Vec<u8>]; 4],
) -> std::result::Result<Vec<u8>, CodecError> {
    let mut cursor = shell;
    let before = cursor.len();
    let entries = map_len(&mut cursor)?;
    let mut whole = Vec::with_capacity(shell.len());
    whole.extend_from_slice(consumed(shell, before, cursor));
    let mut seen = [false; super::CODE_RUN_REPLAY_RECORD_KEYS.len()];
    for _ in 0..entries {
        let before = cursor.len();
        let index = key_index(&mut cursor)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(invalid_code_run_replay("duplicate map key").into());
        }
        whole.extend_from_slice(consumed(shell, before, cursor));
        if let Some(family) = ReplayFamily::from_key_index(index) {
            if cursor.first() != Some(&0x90) {
                return Err(invalid_code_run_replay("replay shell family is not empty").into());
            }
            cursor = &cursor[1..];
            let items = families[family.slot()];
            let len = u32::try_from(items.len())
                .map_err(|_| invalid_code_run_replay("replay family exceeds its length range"))?;
            rmp::encode::write_array_len(&mut whole, len)
                .map_err(|_| invalid_code_run_replay("replay family header encoding"))?;
            for item in items {
                whole.extend_from_slice(item);
            }
        } else {
            let before = cursor.len();
            skip_values(&mut cursor, 1)?;
            whole.extend_from_slice(consumed(shell, before, cursor));
        }
    }
    if !cursor.is_empty() {
        return Err(invalid_code_run_replay("trailing bytes after code-run replay shell").into());
    }
    for family in ReplayFamily::ALL {
        if !seen[family.key_index()] {
            return Err(invalid_code_run_replay("missing replay shell field").into());
        }
    }
    Ok(whole)
}

/// One run's replay head: its four counts, its generation's hashes and its
/// shell. The run id and birth world live in the shell; the counts say how
/// many items each family holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayHead {
    /// The four families' counts in [`ReplayFamily::ALL`] order.
    pub(crate) counts: [u64; 4],
    /// The last checkpoint's state hash, zero with no checkpoints.
    pub(crate) last_state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The pending step's digest, zero with none pending.
    pub(crate) pending_digest: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The record map with empty families.
    pub(crate) shell: Vec<u8>,
}

impl ReplayHead {
    /// The head for `record`: counts from its lengths, hashes as its
    /// generation reads them, shell as its empty-family encoding.
    pub(crate) fn of(record: &CodeRunReplayRecord) -> crate::Result<Self> {
        let counts = [
            u64::try_from(record.bridge_calls.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run bridge call count"))?,
            u64::try_from(record.step_checkpoints.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run step checkpoint count"))?,
            u64::try_from(record.outputs.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run output count"))?,
            u64::try_from(record.bindings.len())
                .map_err(|_| Error::ArithmeticOverflow("code-run binding count"))?,
        ];
        let generation = CodeRunReplayGeneration::for_record(record)?;
        let shell = super::encode_code_run_replay_shell(record).map_err(|error| match error {
            CodecError::Value(error) => error,
            CodecError::Row(problem) => crate::side_table::CODE_RUN_REPLAY.row_error(problem),
        })?;
        Ok(Self {
            counts,
            last_state_hash: generation.last_state_hash,
            pending_digest: generation.pending_digest,
            shell,
        })
    }

    /// The head's generation, with no shell walk.
    #[must_use]
    pub(crate) fn generation(&self) -> CodeRunReplayGeneration {
        CodeRunReplayGeneration {
            bridge_call_count: self.counts[0],
            step_checkpoint_count: self.counts[1],
            output_count: self.counts[2],
            last_state_hash: self.last_state_hash,
            pending_digest: self.pending_digest,
        }
    }

    /// The head's run id, read from its shell.
    pub(crate) fn run_id(&self) -> crate::Result<EntityId> {
        Ok(walk(&self.shell, false)?.run_id)
    }

    /// The head's birth world, read from its shell.
    pub(crate) fn birth_world(&self) -> crate::Result<Option<EntityId>> {
        Ok(walk(&self.shell, false)?.birth_world)
    }

    /// Whether `fenced` appends to this head: same run, and each of its
    /// calls, checkpoints and outputs counts at least this head's. Bindings
    /// are diffed, any count. A head that does not walk never appends.
    #[must_use]
    pub(crate) fn appends_to(&self, fenced: &CodeRunReplayRecord) -> bool {
        let Ok(run_id) = self.run_id() else {
            return false;
        };
        if run_id != fenced.run_id {
            return false;
        }
        let Ok(calls) = u64::try_from(fenced.bridge_calls.len()) else {
            return false;
        };
        let Ok(checkpoints) = u64::try_from(fenced.step_checkpoints.len()) else {
            return false;
        };
        let Ok(outputs) = u64::try_from(fenced.outputs.len()) else {
            return false;
        };
        calls >= self.counts[0] && checkpoints >= self.counts[1] && outputs >= self.counts[2]
    }
}

/// The head row: a 4-entry array of the counts, the last state hash, the
/// pending digest and the shell. The shell sits inline as its own map, not
/// as bytes, so the side-row wall reads its fields as it read them in the
/// whole record (an ABI check's field words joined, a credential field by
/// its key) and masks them in place.
impl crate::side_table::RawValue for ReplayHead {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let context = "code-run replay head MessagePack encode failed";
        // 0x94: a fixarray of four entries; the shell's bytes are the fourth.
        let mut bytes = vec![0x94];
        for value in [
            Value::Array(self.counts.iter().copied().map(Value::from).collect()),
            Value::Binary(self.last_state_hash.to_vec()),
            Value::Binary(self.pending_digest.to_vec()),
        ] {
            bytes.extend(super::encode_value(&value, context)?);
        }
        bytes.extend_from_slice(&self.shell);
        Ok(bytes)
    }

    /// A head decodes only when its shell holds a valid record's own fields
    /// (each decoded and checked as the whole decode checks it, the pending
    /// step against the head's call count), so the wall refuses a masked copy
    /// whose ABI check no longer matches its layout hash.
    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let mut cursor = bytes;
        if array_len(&mut cursor)? != 4 {
            return Err(invalid_code_run_replay("replay head must be a 4-entry array").into());
        }
        let counts = read(&mut cursor)?;
        let last_state_hash = read(&mut cursor)?;
        let pending_digest = read(&mut cursor)?;
        let shell = cursor;
        let Value::Array(counts) = &counts else {
            return Err(invalid_code_run_replay("replay head counts must be an array").into());
        };
        let [bridge_calls, step_checkpoints, outputs, bindings] = counts.as_slice() else {
            return Err(invalid_code_run_replay("replay head counts must hold four counts").into());
        };
        let counts = [
            u64_value(bridge_calls)?,
            u64_value(step_checkpoints)?,
            u64_value(outputs)?,
            u64_value(bindings)?,
        ];
        let last_state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN] =
            fixed_binary(&last_state_hash, "replay head last state hash")?;
        let pending_digest: [u8; CODE_RUN_REPLAY_HASH_LEN] =
            fixed_binary(&pending_digest, "replay head pending digest")?;
        super::validate_code_run_replay_shell(shell, counts[0])?;
        Ok(Self {
            counts,
            last_state_hash,
            pending_digest,
            shell: shell.to_vec(),
        })
    }
}
