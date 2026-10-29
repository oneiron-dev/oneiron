//! A room's talk copy made without its vault refs (FIX 1199,
//! `CopyRefs::Omit`): the same turns, messages and text as the copy that
//! carries them, with no stretch or room named, each turn and speaker under
//! a copy-local `turn-<n>` or `speaker-<n>` label, and each result shown as
//! the copy showed it under a `result-<n>` label, with no run, occurrence,
//! path, content handle or read facets to reach its body by. The copy says
//! what it left out in its `copy` record. A copy that carries its refs is
//! today's, byte for byte, and has no such record.

use std::collections::BTreeMap;

use super::{
    OffRecordRoomCopyLoss, OffRecordRoomCopyResult, OffRecordRoomCopySlot,
    OffRecordRoomCopySlotHandling, OffRecordRoomExport, OffRecordRoomExportResult,
    OffRecordRoomExportTurn,
};
use crate::share_travel::CopyRefs;

impl OffRecordRoomExport {
    /// This copy as `refs` makes it: unchanged for `Preserve`, without its
    /// vault refs for `Omit`.
    #[must_use]
    pub fn with_refs(self, refs: CopyRefs) -> Self {
        match refs {
            CopyRefs::Preserve => self,
            CopyRefs::Omit => self.without_refs(),
        }
    }

    fn without_refs(self) -> Self {
        let mut speakers: BTreeMap<String, String> = BTreeMap::new();
        let mut labelled_speakers = 0;
        let mut results = 0;
        let turn_count = self.turns.len();
        let turns = self
            .turns
            .into_iter()
            .enumerate()
            .map(|(index, turn)| {
                let speaker = turn.speaker.map(|speaker| {
                    labelled_speakers += 1;
                    let next = speakers.len() + 1;
                    speakers
                        .entry(speaker)
                        .or_insert_with(|| format!("speaker-{next}"))
                        .clone()
                });
                let messages = turn
                    .messages
                    .into_iter()
                    .map(|mut message| {
                        message.result = message.result.map(|result| match result {
                            OffRecordRoomExportResult::Attached(attached) => {
                                results += 1;
                                OffRecordRoomExportResult::Labelled(OffRecordRoomCopyResult {
                                    label: format!("result-{results}"),
                                    bytes: attached.bytes,
                                    kind: attached.kind,
                                    lines: attached.lines,
                                    complete: attached.complete,
                                    preview: attached.preview,
                                    preview_truncated: attached.preview_truncated,
                                })
                            }
                            labelled @ OffRecordRoomExportResult::Labelled(_) => labelled,
                        });
                        message
                    })
                    .collect();
                OffRecordRoomExportTurn {
                    turn: format!("turn-{}", index + 1),
                    speaker,
                    occurred_at: turn.occurred_at,
                    saved: turn.saved,
                    messages,
                }
            })
            .collect();
        let slots = [
            (
                "session_ref",
                OffRecordRoomCopySlotHandling::Dropped,
                usize::from(self.session_ref.is_some()),
            ),
            (
                "room",
                OffRecordRoomCopySlotHandling::Dropped,
                usize::from(self.room.is_some()),
            ),
            (
                "turns[].turn",
                OffRecordRoomCopySlotHandling::Labelled,
                turn_count,
            ),
            (
                "turns[].speaker",
                OffRecordRoomCopySlotHandling::Labelled,
                labelled_speakers,
            ),
            (
                "turns[].messages[].result.source",
                OffRecordRoomCopySlotHandling::Dropped,
                results,
            ),
            (
                "turns[].messages[].result.handle",
                OffRecordRoomCopySlotHandling::Dropped,
                results,
            ),
            (
                "turns[].messages[].result.more",
                OffRecordRoomCopySlotHandling::Dropped,
                results,
            ),
        ]
        .into_iter()
        .filter(|(_, _, count)| *count > 0)
        .map(|(slot, handling, count)| OffRecordRoomCopySlot {
            slot: slot.to_owned(),
            handling,
            count,
        })
        .collect();
        Self {
            session_ref: None,
            room: None,
            exported_at: self.exported_at,
            turns,
            copy: Some(OffRecordRoomCopyLoss {
                refs: CopyRefs::Omit,
                slots,
            }),
        }
    }
}
