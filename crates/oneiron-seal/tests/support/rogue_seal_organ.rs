//! A hostile seal organ for the seal binding's checks (feature
//! `hostile-organ-tests`; never shipped). It names itself `seal`, speaks
//! protocol 1.1, serves `seal.pdf` at schema 2 and at the old schema 1 (one
//! PDF, bare prehash signing), so the same attacks run against the adapter
//! before the binding and after it, and `seal.verify` at schema 1. It does
//! what a seal organ compromised by a hostile PDF could. Its first argument
//! picks how:
//! - `forge-signs`: asks the key to sign an unrelated prehash under the
//!   call's operation (Astra's witness on #1379); then, on schema 1, the
//!   prehash of a second document's signed attributes, and on schema 2,
//!   bound asks for the call's first revision whose messageDigest is the
//!   unrelated digest, and the second document's;
//! - `unsigned`: returns the prepared PDF unsigned, with a forged verdict;
//! - `alter-prefix`: seals for real, then changes one byte of the prepared
//!   PDF;
//! - `append-update`: seals for real, then appends an update after the
//!   signed revision and still calls it B-B.
//!
//! Its `seal.verify` always passes.

#[cfg(unix)]
mod rogue {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread::{self, Thread};

    use async_trait::async_trait;
    use der::{Decode, Encode};
    use oneiron_organ_protocol::{
        Answer, Asker, ByteBuf, CallContext, ErrorCode, Organ, OrganError, OrganIdentity,
        OutputBytes, VerbSpec,
    };
    use oneiron_seal::{
        BackendError, BackendRejectCode, BackendSignature, FetchPolicy, NativeSealEngine,
        OfflineFetcher, PadesProfile, PreparedRevision, SealBackend, SealClock, SealConfig,
        SealRequest, SealResourceLimits, SignDigestRequest, SignRevisionRequest,
        SignatureAlgorithm, SigningIdentity,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const UNRELATED: &[u8] = b"astra-1379 synthetic unrelated message";

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Mode {
        ForgeSigns,
        Unsigned,
        AlterPrefix,
        AppendUpdate,
    }

    impl Mode {
        pub(super) fn from_args() -> Option<Self> {
            match std::env::args().nth(1)?.as_str() {
                "forge-signs" => Some(Self::ForgeSigns),
                "unsigned" => Some(Self::Unsigned),
                "alter-prefix" => Some(Self::AlterPrefix),
                "append-update" => Some(Self::AppendUpdate),
                _ => None,
            }
        }
    }

    pub(super) struct Rogue(pub(super) Mode);

    #[derive(Deserialize)]
    struct SealArgs {
        operation_id: String,
        profile: PadesProfile,
        now_ms: u64,
        config: ConfigArgs,
        #[serde(default)]
        signature_revisions: Vec<RevisionArgs>,
    }

    #[derive(Deserialize)]
    struct ConfigArgs {
        trust_anchors: Vec<ByteBuf>,
    }

    #[derive(Deserialize)]
    struct RevisionArgs {
        suffix_offset: u64,
        suffix_len: u64,
        byte_range: [u64; 4],
    }

    #[derive(Serialize)]
    struct Verdict {
        verdict: &'static str,
        reasons: Vec<String>,
        achieved: Option<PadesProfile>,
        self_verify_ok: bool,
        report_json: ByteBuf,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum SealReport {
        Sealed {
            evidence_sha256: ByteBuf,
            requested: PadesProfile,
            achieved: PadesProfile,
            degraded: Vec<()>,
            self_verify: Verdict,
        },
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum VerifyReport {
        Verified(Verdict),
    }

    #[derive(Serialize)]
    struct LegacySign {
        operation_id: String,
        digest_algorithm: &'static str,
        digest: ByteBuf,
    }

    #[derive(Serialize)]
    struct BoundSign {
        operation_id: String,
        revision_id: u32,
        byte_range: [u64; 4],
        signed_attributes_der: ByteBuf,
    }

    #[derive(Deserialize)]
    struct IdentityAnswer {
        algorithm: SignatureAlgorithm,
        signer_certificate: ByteBuf,
        #[serde(default)]
        chain: Vec<ByteBuf>,
    }

    #[derive(Deserialize)]
    struct SignAnswer {
        signature: ByteBuf,
    }

    /// A forged pass, of the given profile.
    fn passed(achieved: PadesProfile) -> Verdict {
        Verdict {
            verdict: "passed",
            reasons: Vec::new(),
            achieved: Some(achieved),
            self_verify_ok: true,
            report_json: ByteBuf::from(b"{}".to_vec()),
        }
    }

    impl Organ for Rogue {
        fn identity(&self) -> OrganIdentity {
            OrganIdentity {
                name: "seal".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }
        }

        fn verbs(&self) -> Vec<VerbSpec> {
            [("seal.pdf", 1), ("seal.pdf", 2), ("seal.verify", 1)]
                .map(|(name, schema)| VerbSpec {
                    name: name.into(),
                    schema,
                    kinds: Vec::new(),
                })
                .into()
        }

        fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
            if call.verb == "seal.verify" {
                return answer(
                    &VerifyReport::Verified(passed(PadesProfile::BaselineB)),
                    None,
                );
            }
            let args: SealArgs = from_value(call.args)?;
            let legacy = call.schema == 1;
            let (pdf, revisions) = match (legacy, call.inputs) {
                (true, [pdf]) => (pdf, Vec::new()),
                (false, [pdf, suffixes]) => (pdf, revisions_of(&args, suffixes)?),
                _ => return Err(bad("inputs")),
            };
            let sub_operation = format!("{}:0000000000000000:sign:65536", args.operation_id);
            let (bytes, achieved) = match self.0 {
                Mode::ForgeSigns => {
                    forge_signs(&call.asker(), &sub_operation, pdf, revisions.first())?;
                    return Err(OrganError::new(
                        ErrorCode::Internal,
                        "every forgery refused",
                    ));
                }
                Mode::Unsigned => (pdf.to_vec(), args.profile),
                Mode::AlterPrefix | Mode::AppendUpdate => {
                    let engine = NativeSealEngine::new(
                        SealConfig {
                            trust_anchors_der: args
                                .config
                                .trust_anchors
                                .into_iter()
                                .map(ByteBuf::into_vec)
                                .collect(),
                            timestamp_authorities: Vec::new(),
                            fetch_policy: FetchPolicy::default(),
                            resource_limits: SealResourceLimits::default(),
                        },
                        Arc::new(Backend {
                            asker: call.asker(),
                            identity: Mutex::new(None),
                            legacy,
                        }),
                        Arc::new(OfflineFetcher),
                        Arc::new(Clock(args.now_ms)),
                    )
                    .map_err(bad)?;
                    let request = SealRequest {
                        operation_id: args.operation_id,
                        target_profile: PadesProfile::BaselineB,
                    };
                    let sealed = if legacy {
                        block_on(engine.seal_pdf(pdf, &request))
                    } else {
                        block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions))
                    };
                    let mut bytes = sealed.map_err(bad)?.bytes;
                    if self.0 == Mode::AlterPrefix {
                        bytes[pdf.len() / 2] ^= 0x01;
                    } else {
                        bytes.extend_from_slice(
                            b"\n9999 0 obj\n<< /Type /Annot /Subtype /FreeText \
                              /Contents (paid in full) >>\nendobj\n",
                        );
                    }
                    (bytes, PadesProfile::BaselineB)
                }
            };
            let report = SealReport::Sealed {
                evidence_sha256: ByteBuf::from(Sha256::digest(&bytes).to_vec()),
                requested: args.profile,
                achieved,
                degraded: Vec::new(),
                self_verify: passed(achieved),
            };
            answer(&report, Some(bytes))
        }
    }

    /// The engine's revisions, as the call's args place them in its second
    /// input.
    fn revisions_of<'a>(
        args: &SealArgs,
        suffixes: &'a [u8],
    ) -> Result<Vec<PreparedRevision<'a>>, OrganError> {
        args.signature_revisions
            .iter()
            .map(|revision| {
                let start = usize::try_from(revision.suffix_offset).map_err(bad)?;
                let len = usize::try_from(revision.suffix_len).map_err(bad)?;
                Ok(PreparedRevision {
                    suffix: suffixes
                        .get(start..start + len)
                        .ok_or_else(|| bad("suffix"))?,
                    byte_range: revision.byte_range,
                })
            })
            .collect()
    }

    /// Astra's witness, an unrelated prehash under the call's operation.
    /// Then a second document: the prepared PDF with one byte of its first
    /// stream changed. On schema 1 the organ asks for the prehash of that
    /// document's signed attributes. On schema 2 it asks, for the call's
    /// first revision, with attributes whose messageDigest is the unrelated
    /// digest, then with the second document's, hashed over the same
    /// revision. Each must be refused before the key signs.
    fn forge_signs(
        asker: &Asker,
        operation: &str,
        pdf: &[u8],
        revision: Option<&PreparedRevision<'_>>,
    ) -> Result<(), OrganError> {
        let identity: IdentityAnswer = from_value(
            &asker
                .ask("seal.identity", rmpv::Value::Map(Vec::new()))
                .map_err(bad)?
                .value,
        )?;
        let cert = identity.signer_certificate.into_vec();
        let unrelated: [u8; 32] = Sha256::digest(UNRELATED).into();
        let mut second = pdf.to_vec();
        let at = pdf
            .windows(7)
            .position(|window| window == b"stream\n")
            .map_or(pdf.len() / 2, |at| at + 7);
        if let Some(byte) = second.get_mut(at) {
            *byte ^= 0x01;
        }
        let bare = |digest: [u8; 32]| -> Result<rmpv::Value, OrganError> {
            to_value(&LegacySign {
                operation_id: operation.to_owned(),
                digest_algorithm: "sha256",
                digest: ByteBuf::from(digest.to_vec()),
            })
        };
        // Refusals are the point: each is on the host's record.
        let _ = asker.ask("seal.sign", bare(unrelated)?);
        let Some(revision) = revision else {
            let mut set = signed_attributes(&cert, &Sha256::digest(&second).into())?;
            set[0] = 0x31;
            let _ = asker.ask("seal.sign", bare(Sha256::digest(&set).into())?);
            return Ok(());
        };
        let [_, open, close, _] = revision.byte_range;
        let open = usize::try_from(open).map_err(bad)?;
        let close = usize::try_from(close).map_err(bad)?;
        let (head, tail) = (
            revision.suffix.get(..open.saturating_sub(pdf.len())),
            revision.suffix.get(close.saturating_sub(pdf.len())..),
        );
        let (head, tail) = head.zip(tail).ok_or_else(|| bad("byte range"))?;
        let other: [u8; 32] = Sha256::new()
            .chain_update(&second)
            .chain_update(head)
            .chain_update(tail)
            .finalize()
            .into();
        for digest in [unrelated, other] {
            let bound = BoundSign {
                operation_id: operation.to_owned(),
                revision_id: 0,
                byte_range: revision.byte_range,
                signed_attributes_der: ByteBuf::from(signed_attributes(&cert, &digest)?),
            };
            let _ = asker.ask("seal.sign", to_value(&bound)?);
        }
        Ok(())
    }

    /// Well-formed signed attributes over `digest`, `[0] IMPLICIT`: content
    /// type id-data, messageDigest, signingCertificateV2 for `cert`.
    fn signed_attributes(cert: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, OrganError> {
        let parsed = x509_cert::Certificate::from_der(cert).map_err(bad)?;
        let issuer = parsed.tbs_certificate.issuer.to_der().map_err(bad)?;
        let serial = parsed.tbs_certificate.serial_number.to_der().map_err(bad)?;
        let oid = |dotted: &str| -> Result<Vec<u8>, OrganError> {
            Ok(tlv(
                0x06,
                const_oid::ObjectIdentifier::new(dotted)
                    .map_err(bad)?
                    .as_bytes(),
            ))
        };
        let attribute = |id: Vec<u8>, value: Vec<u8>| tlv(0x30, &[id, tlv(0x31, &value)].concat());
        let issuer_serial = tlv(0x30, &[tlv(0x30, &tlv(0xA4, &issuer)), serial].concat());
        let ess = tlv(
            0x30,
            &[tlv(0x04, &Sha256::digest(cert)), issuer_serial].concat(),
        );
        let mut attributes = [
            attribute(oid("1.2.840.113549.1.9.3")?, oid("1.2.840.113549.1.7.1")?),
            attribute(oid("1.2.840.113549.1.9.4")?, tlv(0x04, digest)),
            attribute(
                oid("1.2.840.113549.1.9.16.2.47")?,
                tlv(0x30, &tlv(0x30, &ess)),
            ),
        ];
        attributes.sort();
        Ok(tlv(0xA0, &attributes.concat()))
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let significant = &bytes[bytes.iter().take_while(|byte| **byte == 0).count()..];
            out.push(0x80 | significant.len() as u8);
            out.extend_from_slice(significant);
        }
        out.extend_from_slice(content);
        out
    }

    /// Signs as the real organ does: through the bound ask on schema 2,
    /// through the old bare prehash ask on schema 1.
    struct Backend {
        asker: Asker,
        identity: Mutex<Option<SigningIdentity>>,
        legacy: bool,
    }

    impl Backend {
        fn sign(
            &self,
            ask: Result<rmpv::Value, OrganError>,
        ) -> Result<BackendSignature, BackendError> {
            let algorithm = self.signing_identity()?.algorithm;
            let rejected = || BackendError::Rejected {
                code: BackendRejectCode::Unauthorized,
            };
            let reply = self
                .asker
                .ask("seal.sign", ask.map_err(|_| rejected())?)
                .map_err(|_| rejected())?;
            let answer: SignAnswer =
                from_value(&reply.value).map_err(|_| BackendError::MalformedSignature)?;
            let bytes = answer.signature.into_vec();
            Ok(match algorithm {
                SignatureAlgorithm::RsaPkcs1v15Sha256 => BackendSignature::RsaPkcs1v15 { bytes },
                SignatureAlgorithm::EcdsaP256Sha256 => BackendSignature::EcdsaP256Der { bytes },
            })
        }
    }

    #[async_trait]
    impl SealBackend for Backend {
        fn signing_identity(&self) -> Result<SigningIdentity, BackendError> {
            let mut held = self.identity.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(identity) = held.as_ref() {
                return Ok(identity.clone());
            }
            let rejected = || BackendError::Rejected {
                code: BackendRejectCode::IdentityUnavailable,
            };
            let reply = self
                .asker
                .ask("seal.identity", rmpv::Value::Map(Vec::new()))
                .map_err(|_| rejected())?;
            let answer: IdentityAnswer = from_value(&reply.value).map_err(|_| rejected())?;
            let identity = SigningIdentity {
                algorithm: answer.algorithm,
                signer_certificate_der: answer.signer_certificate.into_vec(),
                certificate_chain_der: answer.chain.into_iter().map(ByteBuf::into_vec).collect(),
            };
            *held = Some(identity.clone());
            Ok(identity)
        }

        async fn sign_digest(
            &self,
            request: SignDigestRequest,
        ) -> Result<BackendSignature, BackendError> {
            if !self.legacy {
                return Err(BackendError::Rejected {
                    code: BackendRejectCode::Unauthorized,
                });
            }
            self.sign(to_value(&LegacySign {
                operation_id: request.operation_id,
                digest_algorithm: "sha256",
                digest: ByteBuf::from(request.digest.to_vec()),
            }))
        }

        async fn sign_revision(
            &self,
            request: SignRevisionRequest,
        ) -> Result<BackendSignature, BackendError> {
            let Some(revision_id) = request.revision_id else {
                return Err(BackendError::Rejected {
                    code: BackendRejectCode::Unauthorized,
                });
            };
            self.sign(to_value(&BoundSign {
                operation_id: request.operation_id,
                revision_id,
                byte_range: request.byte_range,
                signed_attributes_der: ByteBuf::from(request.signed_attributes_der),
            }))
        }
    }

    struct Clock(u64);

    impl SealClock for Clock {
        fn unix_time_ms(&self) -> u64 {
            self.0
        }
    }

    fn answer<T: Serialize>(report: &T, pdf: Option<Vec<u8>>) -> Result<Answer, OrganError> {
        Ok(Answer {
            report: to_value(report)?,
            outputs: pdf
                .into_iter()
                .map(|bytes| OutputBytes {
                    name: "sealed.pdf".to_owned(),
                    media_type: "application/pdf".to_owned(),
                    bytes,
                })
                .collect(),
            ..Answer::default()
        })
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        struct Unpark(Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        loop {
            if let Poll::Ready(out) = future.as_mut().poll(&mut context) {
                return out;
            }
            thread::park();
        }
    }

    fn bad(err: impl std::fmt::Display) -> OrganError {
        OrganError::new(ErrorCode::BadRequest, err.to_string())
    }

    fn to_value<T: Serialize>(value: &T) -> Result<rmpv::Value, OrganError> {
        let bytes = rmp_serde::to_vec_named(value).map_err(bad)?;
        rmpv::decode::read_value(&mut bytes.as_slice()).map_err(bad)
    }

    fn from_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Result<T, OrganError> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).map_err(bad)?;
        rmp_serde::from_slice(&bytes).map_err(bad)
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match rogue::Mode::from_args() {
        Some(mode) => oneiron_organ_protocol::serve(rogue::Rogue(mode)),
        None => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(unix))]
fn main() {}
