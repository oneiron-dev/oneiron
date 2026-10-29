//! Each physical model call of a native stage admitted on its own permit
//! (FIX 3765): the bridge names a unit before it runs it (VAD, full-file
//! diarization, ASR, one CTC alignment window, one cleanup group) and waits
//! for its answer; the unit runs while its permit, under the stage's run,
//! is started, and settles on what the bridge says it heard or counted.
//! Entry: `MeetingAudioSeats`, `CommandMeetingAudioHost::run_unit`.

use serde_json::Value;

use crate::llm::ModelLocality;
use crate::llm::media::{AiOperation, MediaPart, MediaUsage};
use crate::llm::run_admission::{WireCallError, WireSeat};

use super::process::{Frame, Session};
use super::{AudioResult, CommandMeetingAudioHost, PROTOCOL, host_error};

/// The rungs a native host's physical model calls are admitted on, one per
/// model: each call settles at its own rung's rates.
#[derive(Clone)]
pub struct MeetingAudioSeats {
    pub vad: WireSeat,
    pub diarization: WireSeat,
    pub asr: WireSeat,
    pub alignment: WireSeat,
    pub cleanup: WireSeat,
}

impl MeetingAudioSeats {
    /// Whether every rung runs on this device.
    pub(super) fn on_device(&self) -> bool {
        [
            &self.vad,
            &self.diarization,
            &self.asr,
            &self.alignment,
            &self.cleanup,
        ]
        .iter()
        .all(|seat| seat.locality() == ModelLocality::OnDevice)
    }

    fn seat(&self, kind: UnitKind) -> &WireSeat {
        match kind {
            UnitKind::Vad => &self.vad,
            UnitKind::Diarization => &self.diarization,
            UnitKind::Asr => &self.asr,
            UnitKind::AlignmentWindow => &self.alignment,
            UnitKind::CleanupGroup => &self.cleanup,
        }
    }
}

/// One physical model call a stage makes.
#[derive(Clone, Copy)]
enum UnitKind {
    Vad,
    Diarization,
    Asr,
    AlignmentWindow,
    CleanupGroup,
}

impl UnitKind {
    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "vad" => Self::Vad,
            "diarization" => Self::Diarization,
            "asr" => Self::Asr,
            "alignment_window" => Self::AlignmentWindow,
            "cleanup_group" => Self::CleanupGroup,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Vad => "vad",
            Self::Diarization => "diarization",
            Self::Asr => "asr",
            Self::AlignmentWindow => "alignment_window",
            Self::CleanupGroup => "cleanup_group",
        }
    }

    /// Audio in for every unit but a cleanup group, which reads turns' text.
    fn operation(self) -> AiOperation {
        match self {
            Self::CleanupGroup => AiOperation::Text,
            _ => AiOperation::Transcribe,
        }
    }
}

/// The event an event line from request `request_id` names; `None` for a
/// line from another protocol or request.
pub(super) fn event_name<'a>(event: &'a Value, request_id: &str) -> Option<&'a str> {
    if event["protocol"] != PROTOCOL || event["request_id"] != request_id {
        return None;
    }
    event["event"].as_str()
}

impl CommandMeetingAudioHost {
    /// Runs the unit `unit` the bridge named in `stage`'s process, on its own
    /// permit: the bridge is answered once the permit starts, and the permit
    /// settles on the unit's end. A refused unit is answered no, and the
    /// stage faults; so does a unit that ends without its end.
    pub(super) fn run_unit(
        &self,
        stage: &str,
        request_id: &str,
        session: &mut Session,
        unit: &Value,
    ) -> AudioResult<()> {
        let kind = unit["kind"]
            .as_str()
            .and_then(UnitKind::parse)
            .ok_or_else(|| host_error(stage, "InvalidUnit"))?;
        let audio_ms = unit["audio_ms"].as_u64().unwrap_or(0);
        let seat = self.seats.seat(kind);
        let parts = match kind {
            UnitKind::CleanupGroup => vec![MediaPart::Text {
                text: String::new(),
            }],
            _ => vec![MediaPart::Audio {
                media_type: "audio/pcm".into(),
                bytes: Vec::new(),
            }],
        };
        let mut call = seat.request(kind.operation(), parts, None);
        call.params.extend([
            ("stage".to_owned(), Value::from(stage)),
            ("unit".to_owned(), Value::from(kind.as_str())),
            ("unit_index".to_owned(), unit["index"].clone()),
            ("audio_ms".to_owned(), Value::from(audio_ms)),
        ]);
        let ran = seat.call(
            &call,
            || {
                session.answer(true)?;
                loop {
                    match session.next()? {
                        Frame::Event(event) => match event_name(&event, request_id) {
                            Some("progress") => {}
                            Some("unit_done") => return Ok(unit_usage(&event["usage"])),
                            _ => return Err("UnitInterrupted"),
                        },
                        Frame::Reply(_) => return Err("UnitInterrupted"),
                    }
                }
            },
            MediaUsage::clone,
        );
        match ran {
            Ok(_) => Ok(()),
            Err(WireCallError::Refused(_)) => {
                // The bridge ends the stage, refused; the stage faults here.
                let _ = session.answer(false);
                Err(host_error(stage, "RunAdmissionRefused"))
            }
            Err(WireCallError::Failed(code)) => Err(host_error(stage, code)),
        }
    }
}

/// What a unit's end says it heard or counted.
fn unit_usage(usage: &Value) -> MediaUsage {
    let count = |key: &str| usage[key].as_u64().unwrap_or(0);
    MediaUsage {
        audio_ms: count("audio_ms"),
        input_tokens: count("input_tokens"),
        output_tokens: count("output_tokens"),
        ..MediaUsage::default()
    }
}
