//! Synthetic callback fixtures only: no decoder or model runs in these tests.

use super::super::provenance::{COMMUNITY1_MODEL, pcm_sha256};
use super::super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    EmptyDecode,
    BackendUnavailable,
    NoSpeech,
    EmptyAsr,
    WrongRoute,
    RemoteRoute,
    WrongAsrHash,
    WrongAsrModel,
    InvalidConfidence,
    WordCrossesSeam,
    WrongGlobalHash,
    WrongGlobalModel,
    ReusedInvocation,
    OverlappingTracks,
    MissingTrack,
    InventedCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HostRequest {
    Decode,
    Vad {
        samples: usize,
        hash: String,
    },
    Route {
        role: AsrRole,
        preferred: ProcessingTier,
        local_only: bool,
        model: String,
    },
    Pack {
        id: String,
        samples: usize,
        hash: String,
        glossary: Vec<String>,
    },
    Global {
        samples: usize,
        hash: String,
    },
    Cleanup,
}

pub(super) struct FixtureHost {
    pub(super) duration_ms: u64,
    pub(super) spans: Vec<SpeechSpan>,
    pub(super) requests: Vec<HostRequest>,
    pub(super) fault: Fault,
}

pub(super) fn options() -> ProducerOptions {
    ProducerOptions {
        glossary: vec!["Ada".into(), "製品名".into()],
        batch_default: BatchDefault::Provisional {
            model_id: "fixture-asr".into(),
        },
        local_only: false,
    }
}

pub(super) fn file() -> AudioFile<'static> {
    AudioFile {
        // Intentionally not an mp4. Do not cite this fixture as decoder proof.
        bytes: b"synthetic audio source marker; no encoded media",
        source_name: "synthetic.fixture",
        capture_started_at: Some(1_000),
        language_hint: None,
    }
}

impl FixtureHost {
    pub(super) fn small(fault: Fault) -> Self {
        Self {
            duration_ms: 3_000,
            spans: vec![
                SpeechSpan {
                    start_ms: 500,
                    end_ms: 1_000,
                },
                SpeechSpan {
                    start_ms: 1_800,
                    end_ms: 2_300,
                },
            ],
            requests: Vec::new(),
            fault,
        }
    }

    pub(super) fn two_packs() -> Self {
        Self {
            duration_ms: 190_000,
            spans: vec![
                SpeechSpan {
                    start_ms: 1_000,
                    end_ms: 46_000,
                },
                SpeechSpan {
                    start_ms: 48_000,
                    end_ms: 93_000,
                },
                SpeechSpan {
                    start_ms: 95_000,
                    end_ms: 140_000,
                },
                SpeechSpan {
                    start_ms: 142_000,
                    end_ms: 187_000,
                },
            ],
            requests: Vec::new(),
            fault: Fault::None,
        }
    }
}

fn provenance(id: &str, model: &str, hash: &str) -> InferenceProvenance {
    InferenceProvenance {
        invocation_id: id.into(),
        model_id: model.into(),
        input_sha256: hash.into(),
        execution: InferenceExecution::Fixture,
    }
}

impl MeetingAudioHost for FixtureHost {
    fn preflight_artifact(&mut self) -> AudioResult<()> {
        if self.fault == Fault::BackendUnavailable {
            Err(AudioError::Host {
                stage: "capabilities".into(),
                code: "ArtifactBackendUnavailable".into(),
            })
        } else {
            Ok(())
        }
    }
    fn decode(&mut self, _file: &AudioFile<'_>) -> AudioResult<Pcm16> {
        self.requests.push(HostRequest::Decode);
        let count = if self.fault == Fault::EmptyDecode {
            0
        } else {
            self.duration_ms * 16
        };
        Ok(Pcm16 {
            samples: vec![3; usize::try_from(count).unwrap()],
        })
    }

    fn silero_vad(&mut self, audio: &Pcm16, hash: &str) -> AudioResult<VadOutput> {
        assert_eq!(pcm_sha256(audio), hash);
        self.requests.push(HostRequest::Vad {
            samples: audio.samples.len(),
            hash: hash.into(),
        });
        Ok(VadOutput {
            spans: if self.fault == Fault::NoSpeech {
                Vec::new()
            } else {
                self.spans.clone()
            },
            provenance: provenance("vad-call", "silero-vad-fixture", hash),
        })
    }

    fn route_batch_asr(&mut self, request: BatchAsrRequest<'_>) -> AudioResult<AsrRoute> {
        self.requests.push(HostRequest::Route {
            role: request.role,
            preferred: request.preferred_tier,
            local_only: request.local_only,
            model: request.batch_default.model_id().into(),
        });
        Ok(AsrRoute {
            role: request.role,
            model_id: if self.fault == Fault::WrongRoute {
                "wrong"
            } else {
                request.batch_default.model_id()
            }
            .into(),
            tier: if self.fault == Fault::RemoteRoute {
                ProcessingTier::Hosted
            } else {
                ProcessingTier::Local
            },
            route_receipt_ref: "fixture-of133-route".into(),
        })
    }

    fn transcribe_pack(&mut self, request: AsrPackRequest<'_>) -> AudioResult<AsrOutput> {
        assert_eq!(pcm_sha256(request.audio), request.audio_sha256);
        self.requests.push(HostRequest::Pack {
            id: request.pack.pack_id.clone(),
            samples: request.audio.samples.len(),
            hash: request.audio_sha256.into(),
            glossary: request.glossary.to_vec(),
        });
        let mut words = Vec::new();
        for source in &request.pack.source_spans {
            let (index, speech) = self
                .spans
                .iter()
                .enumerate()
                .find(|(_, span)| {
                    span.start_ms >= source.source_start_ms && span.end_ms <= source.source_end_ms
                })
                .unwrap();
            let start_ms = source.pack_start_ms + speech.start_ms - source.source_start_ms;
            words.push(AsrWord {
                start_ms,
                end_ms: start_ms + 100,
                text: if index % 2 == 0 { "hello" } else { "world" }.into(),
                confidence: Some(0.9),
            });
        }
        if self.fault == Fault::WordCrossesSeam {
            let seam = request.pack.source_spans[0].pack_end_ms;
            words[0].start_ms = seam - 1;
            words[0].end_ms = seam + 1;
        }
        if self.fault == Fault::InvalidConfidence {
            words[0].confidence = Some(f64::NAN);
        }
        if self.fault == Fault::EmptyAsr {
            words.clear();
        }
        Ok(AsrOutput {
            words,
            aligner_model: "fixture-aligner".into(),
            provenance: provenance(
                &format!("asr-{}", request.pack.pack_id),
                if self.fault == Fault::WrongAsrModel {
                    "wrong"
                } else {
                    &request.route.model_id
                },
                if self.fault == Fault::WrongAsrHash {
                    "wrong"
                } else {
                    request.audio_sha256
                },
            ),
        })
    }

    fn community1_exclusive_full_file(
        &mut self,
        audio: &Pcm16,
        hash: &str,
    ) -> AudioResult<GlobalDiarization> {
        assert_eq!(pcm_sha256(audio), hash);
        self.requests.push(HostRequest::Global {
            samples: audio.samples.len(),
            hash: hash.into(),
        });
        let mut tracks: Vec<_> = self
            .spans
            .iter()
            .enumerate()
            .map(|(index, span)| SpeakerTrack {
                start_ms: span.start_ms,
                end_ms: span.end_ms,
                speaker_cluster: if index % 2 == 0 {
                    "global-a"
                } else {
                    "global-b"
                }
                .into(),
            })
            .collect();
        if self.fault == Fault::OverlappingTracks {
            tracks[1].start_ms = tracks[0].end_ms - 1;
        }
        if self.fault == Fault::MissingTrack {
            tracks.pop();
        }
        Ok(GlobalDiarization {
            exclusive_tracks: tracks,
            provenance: provenance(
                if self.fault == Fault::ReusedInvocation {
                    "vad-call"
                } else {
                    "global-call"
                },
                if self.fault == Fault::WrongGlobalModel {
                    "pyannote/3.1"
                } else {
                    COMMUNITY1_MODEL
                },
                if self.fault == Fault::WrongGlobalHash {
                    "pack-hash-not-full-file"
                } else {
                    hash
                },
            ),
        })
    }

    fn cleanup_turns(&mut self, request: CleanupRequest<'_>) -> AudioResult<CleanupOutput> {
        self.requests.push(HostRequest::Cleanup);
        let mut texts: Vec<_> = request
            .turns
            .iter()
            .map(|turn| format!("{}.", turn.text))
            .collect();
        if self.fault == Fault::InventedCleanup {
            texts[0] = "Approved the budget.".into();
        }
        Ok(CleanupOutput {
            texts,
            provenance: provenance("cleanup-call", "fixture-cleanup", request.input_sha256),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum ConsentResponse {
    Allow,
    Missing,
    WrongScope,
    WrongHash,
    WrongTurns,
    BlankReceipt,
}

pub(super) struct Authorizer {
    pub(super) response: ConsentResponse,
    pub(super) requests: Vec<BulkImportBinding>,
}

impl BulkImportAuthorizer for Authorizer {
    fn vault_scope(&self) -> &str {
        "fixture-vault-owner"
    }

    fn authorize_import(
        &mut self,
        binding: &BulkImportBinding,
    ) -> AudioResult<Option<BulkImportReceipt>> {
        self.requests.push(binding.clone());
        let mut receipt = BulkImportReceipt {
            binding: binding.clone(),
            receipt_ref: "fixture-batch-approval".into(),
        };
        match self.response {
            ConsentResponse::Allow => {}
            ConsentResponse::Missing => return Ok(None),
            ConsentResponse::WrongScope => receipt.binding.vault_scope = "another-vault".into(),
            ConsentResponse::WrongHash => receipt.binding.artifact_sha256 = "wrong".into(),
            ConsentResponse::WrongTurns => {
                receipt.binding.source_record_ids.pop();
            }
            ConsentResponse::BlankReceipt => receipt.receipt_ref.clear(),
        }
        Ok(Some(receipt))
    }
}
