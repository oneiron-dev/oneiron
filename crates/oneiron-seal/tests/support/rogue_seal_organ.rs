//! A hostile seal organ for the seal binding's checks (feature
//! `hostile-organ-tests`; never shipped). It names itself `seal`, speaks
//! protocol 1.1, and serves `seal.verify` at schema 1 and `seal.pdf` at
//! schema 2, or, with `schema-1` as its second argument, at the old schema
//! 1 (one PDF, bare prehash signing), so the same attacks run against the
//! adapter before the binding and after it. `seal.prepare` and `seal.inspect`
//! are the real organ's, so the engine's PDF work reaches the attacks. It does what a seal organ
//! compromised by a hostile PDF could. Its first argument picks how:
//! - `forge-signs`: asks the key to sign an unrelated prehash under the
//!   call's operation (Astra's witness on #1379), then the prehash of a
//!   second document's signature revision: on schema 1 a bare prehash, on
//!   schema 2 bound asks for the call's first revision whose messageDigest
//!   is the unrelated digest, then the second document's;
//! - `unsigned`: returns the prepared PDF unsigned, with a forged verdict;
//! - `alter-prefix`: seals for real, then changes one byte of the prepared
//!   PDF;
//! - `append-update`: seals for real, then appends an update after the
//!   signed revision and still calls it B-B;
//! - `drop-certs`: seals for real, then rebuilds the CMS in the hole
//!   without its certificates;
//! - `signed-data-v0`, `signer-info-v3`, `crls-empty`, `other-cert`,
//!   `sig-alg-null`, `leaf-only`, `extra-cert`: seals for real, then
//!   rebuilds the CMS in the hole with that one part of the envelope changed
//!   (`leaf-only` keeps the signer's certificate and drops its chain;
//!   `extra-cert` adds a copy of a certificate under another serial).
//!
//! Its `seal.verify` always passes.
//!
//! The evidence modes take an `EvidenceFixture` as their fourth argument
//! (after the schema): a timestamp authority the organ's fetcher mints tokens
//! from, and the anchor's CRL it serves, so the organ's own engine seals for
//! real at B-T and above with no network. Each then forges one thing, claims
//! the profile it names, and its `seal.verify` runs the real verification and
//! forges only the verdict: passed, self-verified, the claimed profile, every
//! signature passed, every later revision validation data or a document
//! timestamp. The host's own evidence checks are all that stand between
//! them and a commit (ARCH-0075 `#organ-host-design-seal-residual`):
//! - `dss-honest`: seals at the requested profile, honestly; its verify is
//!   the real one, unchanged;
//! - `dss-untrusted-crl`, `dss-untrusted-ocsp`, `dss-no-revocation`: seal at
//!   B-T, append a DSS revision holding the fixture's material (a CRL or an
//!   OCSP response no issuer signed, or certificates alone), and claim B-LT;
//! - `doc-timestamp-forged`: seals at B-LTA, then puts the signature's own
//!   CMS, which is no TSTInfo, in the document timestamp's hole; claims B-LTA;
//! - `timestamp-forged`: seals at B-T, then replaces the signature
//!   timestamp token with one an untrusted authority minted over the right
//!   imprint; claims B-T.

#[cfg(unix)]
#[path = "rogue_evidence.rs"]
mod rogue_evidence;

#[cfg(unix)]
mod rogue {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread::{self, Thread};

    use async_trait::async_trait;
    use der::{Decode, Encode};
    use oneiron_organ_protocol::seal::{SealModifications, SealRevisionClassification};
    use oneiron_organ_protocol::{
        Answer, Asker, ByteBuf, CallContext, ErrorCode, Organ, OrganError, OrganIdentity,
        OutputBytes, Value, VerbSpec,
    };
    use oneiron_seal::ActiveContentFacts;
    use oneiron_seal::organ::{
        INSPECT_SCHEMA, PREPARE_SCHEMA, SealOrgan, VERB_INSPECT, VERB_PREPARE,
    };
    use oneiron_seal::{
        AdmittedBytes, BackendError, BackendRejectCode, BackendSignature, DigestAlgorithm,
        FetchError, FetchPolicy, FetchPurpose, FetchRequest, FetchResponse, NativeSealEngine,
        OfflineFetcher, PadesProfile, PdfSealEngine, PreparedRevision, SealBackend, SealClock,
        SealConfig, SealFetcher, SealMemory, SealMemoryProvider, SealMemoryRefusal, SealRequest,
        SealResourceLimits, SignDigestRequest, SignRevisionRequest, SignatureAlgorithm,
        SigningIdentity, TsaEndpoint,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::rogue_evidence::EvidenceFixture;

    const UNRELATED: &[u8] = b"astra-1379 synthetic unrelated message";
    const ID_DATA: &str = "1.2.840.113549.1.7.1";
    const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    const ID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
    const ID_SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
    const ID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
    const ID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
    /// The policy every fixture token names.
    const FIXTURE_TSA_POLICY: &str = "1.3.6.1.4.1.99999.3";

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Mode {
        ForgeSigns,
        Unsigned,
        AlterPrefix,
        AppendUpdate,
        DropCerts,
        SignedDataV0,
        SignerInfoV3,
        CrlsEmpty,
        OtherCert,
        SignatureAlgorithmNull,
        LeafOnly,
        ExtraCert,
        DssHonest,
        DssUntrustedCrl,
        DssUntrustedOcsp,
        DssNoRevocation,
        DocTimestampForged,
        TimestampForged,
    }

    impl Mode {
        /// What an evidence mode has the organ's own engine seal at, for a
        /// request of `requested`, and the profile it then claims.
        fn evidence(self, requested: PadesProfile) -> Option<(PadesProfile, PadesProfile)> {
            match self {
                Self::DssHonest => Some((requested, requested)),
                Self::DssUntrustedCrl | Self::DssUntrustedOcsp | Self::DssNoRevocation => {
                    Some((PadesProfile::BaselineT, PadesProfile::BaselineLt))
                }
                Self::DocTimestampForged => {
                    Some((PadesProfile::BaselineLta, PadesProfile::BaselineLta))
                }
                Self::TimestampForged => Some((PadesProfile::BaselineT, PadesProfile::BaselineT)),
                _ => None,
            }
        }

        /// The profile a forging evidence mode's `seal.verify` claims.
        fn forged_claim(self) -> Option<PadesProfile> {
            match self {
                Self::DssHonest => None,
                mode => mode
                    .evidence(PadesProfile::BaselineB)
                    .map(|(_, claim)| claim),
            }
        }

        pub(super) fn from_args() -> Option<Self> {
            match std::env::args().nth(1)?.as_str() {
                "forge-signs" => Some(Self::ForgeSigns),
                "unsigned" => Some(Self::Unsigned),
                "alter-prefix" => Some(Self::AlterPrefix),
                "append-update" => Some(Self::AppendUpdate),
                "drop-certs" => Some(Self::DropCerts),
                "signed-data-v0" => Some(Self::SignedDataV0),
                "signer-info-v3" => Some(Self::SignerInfoV3),
                "crls-empty" => Some(Self::CrlsEmpty),
                "other-cert" => Some(Self::OtherCert),
                "sig-alg-null" => Some(Self::SignatureAlgorithmNull),
                "leaf-only" => Some(Self::LeafOnly),
                "extra-cert" => Some(Self::ExtraCert),
                "dss-honest" => Some(Self::DssHonest),
                "dss-untrusted-crl" => Some(Self::DssUntrustedCrl),
                "dss-untrusted-ocsp" => Some(Self::DssUntrustedOcsp),
                "dss-no-revocation" => Some(Self::DssNoRevocation),
                "doc-timestamp-forged" => Some(Self::DocTimestampForged),
                "timestamp-forged" => Some(Self::TimestampForged),
                _ => None,
            }
        }
    }

    /// The mode, the schema it serves `seal.pdf` at, and an evidence mode's
    /// fixture.
    pub(super) struct Rogue(
        pub(super) Mode,
        pub(super) u32,
        pub(super) Option<EvidenceFixture>,
    );

    impl Rogue {
        pub(super) fn from_args() -> Option<Self> {
            let mode = Mode::from_args()?;
            let schema = match std::env::args().nth(2).as_deref() {
                Some("schema-1") => 1,
                _ => 2,
            };
            let fixture = match std::env::args().nth(3) {
                Some(hex) => Some(fixture_from_hex(&hex)?),
                None => None,
            };
            Some(Self(mode, schema, fixture))
        }
    }

    /// The fixture a test passed: hex of its MessagePack.
    fn fixture_from_hex(hex: &str) -> Option<EvidenceFixture> {
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()?;
        rmp_serde::from_slice(&bytes).ok()
    }

    /// The real verification's reply, read back so an evidence mode can
    /// forge its verdict and keep the rest.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum RealVerifyReport {
        Verified(RealVerdict),
    }

    #[derive(Serialize, Deserialize)]
    struct RealVerdict {
        verdict: String,
        reasons: Vec<String>,
        achieved: Option<PadesProfile>,
        self_verify_ok: bool,
        report_json: ByteBuf,
        active_content: ActiveContentFacts,
        classification: SealRevisionClassification,
    }

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

    /// A verdict in today's wire shape, which also carries the active-content
    /// facts and the revision classification (#3372, 7de2f0302b4); the host
    /// refuses a reply without them before it reaches the binding.
    #[derive(Serialize)]
    struct Verdict {
        verdict: &'static str,
        reasons: Vec<String>,
        achieved: Option<PadesProfile>,
        self_verify_ok: bool,
        report_json: ByteBuf,
        active_content: ActiveContentFacts,
        classification: SealRevisionClassification,
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

    /// A forged pass of `pdf`, of the given profile. Its classification is
    /// well formed and proves nothing: no revision chain, no signature, nothing
    /// classified through.
    fn passed(achieved: PadesProfile, pdf: &[u8]) -> Verdict {
        Verdict {
            verdict: "passed",
            reasons: Vec::new(),
            achieved: Some(achieved),
            self_verify_ok: true,
            report_json: ByteBuf::from(b"{}".to_vec()),
            active_content: ActiveContentFacts::default(),
            classification: SealRevisionClassification {
                artifact_sha256: ByteBuf::from(Sha256::digest(pdf).to_vec()),
                classified_through: None,
                modifications: SealModifications::NotRun,
                revisions: Vec::new(),
                signatures: Vec::new(),
            },
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
            [
                ("seal.pdf", self.1),
                ("seal.verify", 1),
                (VERB_INSPECT, INSPECT_SCHEMA),
                (VERB_PREPARE, PREPARE_SCHEMA),
            ]
            .map(|(name, schema)| VerbSpec {
                name: name.into(),
                schema,
                kinds: Vec::new(),
            })
            .into()
        }

        fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
            // The engine prepares and inspects the PDF before it seals
            // (seal.prepare, seal.inspect; the install spec requires every PDF
            // work verb, 13080826f10): the real organ's own code serves both, so
            // every attack below starts from the input an honest organ would
            // have prepared.
            if call.verb == VERB_PREPARE || call.verb == VERB_INSPECT {
                return SealOrgan.call(call);
            }
            if call.verb == "seal.verify" {
                let [pdf] = call.inputs else {
                    return Err(bad("inputs"));
                };
                if self.0 == Mode::DssHonest {
                    return SealOrgan.call(call);
                }
                if let Some(claim) = self.0.forged_claim() {
                    return forged_verification(call, pdf, claim);
                }
                return answer(
                    &VerifyReport::Verified(passed(PadesProfile::BaselineB, pdf)),
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
                    let asker = call.asker();
                    let witness = Witness {
                        asker: &asker,
                        operation: &sub_operation,
                        anchors: &args.config.trust_anchors,
                        now_ms: args.now_ms,
                    };
                    witness.forge_signs(pdf, revisions.first())?;
                    return Err(OrganError::new(
                        ErrorCode::Internal,
                        "every forgery refused",
                    ));
                }
                Mode::Unsigned => (pdf.to_vec(), args.profile),
                Mode::AlterPrefix
                | Mode::AppendUpdate
                | Mode::DropCerts
                | Mode::SignedDataV0
                | Mode::SignerInfoV3
                | Mode::CrlsEmpty
                | Mode::OtherCert
                | Mode::SignatureAlgorithmNull
                | Mode::LeafOnly
                | Mode::ExtraCert => {
                    let backend = Backend {
                        asker: call.asker(),
                        identity: Mutex::new(None),
                        legacy,
                    };
                    let engine = native(
                        &args.config.trust_anchors,
                        args.now_ms,
                        Arc::new(backend),
                        None,
                    )?;
                    let request = SealRequest {
                        operation_id: args.operation_id,
                        target_profile: PadesProfile::BaselineB,
                    };
                    let sealed = if legacy {
                        block_on(engine.seal_pdf(pdf, &request))
                    } else {
                        block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions))
                    };
                    let mut bytes = sealed.map_err(bad)?.bytes.to_vec();
                    match self.0 {
                        Mode::AlterPrefix => bytes[pdf.len() / 2] ^= 0x01,
                        Mode::AppendUpdate => bytes.extend_from_slice(
                            b"\n9999 0 obj\n<< /Type /Annot /Subtype /FreeText \
                              /Contents (paid in full) >>\nendobj\n",
                        ),
                        mode => rebuild_cms(&mut bytes, pdf.len(), &revisions, |signed| {
                            reshape(mode, signed)
                        })?,
                    }
                    (bytes, PadesProfile::BaselineB)
                }
                Mode::DssHonest
                | Mode::DssUntrustedCrl
                | Mode::DssUntrustedOcsp
                | Mode::DssNoRevocation
                | Mode::DocTimestampForged
                | Mode::TimestampForged => {
                    let fixture = self.2.as_ref().ok_or_else(|| bad("no evidence fixture"))?;
                    let (target, claim) = self
                        .0
                        .evidence(args.profile)
                        .ok_or_else(|| bad("not an evidence mode"))?;
                    let backend = Backend {
                        asker: call.asker(),
                        identity: Mutex::new(None),
                        legacy: false,
                    };
                    let engine = native(
                        &args.config.trust_anchors,
                        args.now_ms,
                        Arc::new(backend),
                        Some(fixture),
                    )?;
                    let request = SealRequest {
                        operation_id: args.operation_id,
                        target_profile: target,
                    };
                    let sealed =
                        block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions))
                            .map_err(bad)?;
                    // Each mode forges one thing over an honest seal: a
                    // fixture its own engine would not take is the test's
                    // error, never a refusal to credit to the host.
                    if sealed.achieved_profile != target {
                        return Err(bad(format!(
                            "the fixture sealed at {:?}, not {target:?}",
                            sealed.achieved_profile
                        )));
                    }
                    let mut bytes = sealed.bytes.to_vec();
                    match self.0 {
                        Mode::DssUntrustedCrl | Mode::DssUntrustedOcsp | Mode::DssNoRevocation => {
                            bytes = append_dss(&bytes, fixture)?;
                        }
                        Mode::DocTimestampForged => {
                            forge_document_timestamp(&mut bytes, pdf.len(), &revisions)?;
                        }
                        Mode::TimestampForged => {
                            let key = signing_key(&fixture.untrusted_tsa_key)?;
                            let certificate = fixture.untrusted_tsa_certificate.to_vec();
                            let now = args.now_ms / 1000;
                            rebuild_cms(&mut bytes, pdf.len(), &revisions, |signed| {
                                replace_signature_timestamp(signed, &key, &certificate, now)
                            })?;
                        }
                        _ => {}
                    }
                    (bytes, claim)
                }
            };
            let report = SealReport::Sealed {
                evidence_sha256: ByteBuf::from(Sha256::digest(&bytes).to_vec()),
                requested: args.profile,
                achieved,
                degraded: Vec::new(),
                self_verify: passed(achieved, &bytes),
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

    /// Grants every reservation and holds nothing. A native engine refuses
    /// to start without a memory service (FIX 7654); the real organ asks its
    /// host through `memory.grow`, and a hostile organ's own accounting is
    /// nothing the binding relies on. (A bin target cannot include the
    /// dev-dependency fixtures in `tests/support/mod.rs`.)
    struct GrantAllMemory;

    impl SealMemory for GrantAllMemory {
        fn reserve(&self, _bytes: u64) -> Result<Box<dyn Send>, SealMemoryRefusal> {
            Ok(Box::new(()))
        }
    }

    /// The organ's own seal engine over `backend`, as the real organ builds
    /// it for a call.
    /// With `fixture`, it has one timestamp authority, which the
    /// `FixtureFetcher` answers, and every CRL fetch gets the fixture's.
    fn native(
        anchors: &[ByteBuf],
        now_ms: u64,
        backend: Arc<dyn SealBackend>,
        fixture: Option<&EvidenceFixture>,
    ) -> Result<NativeSealEngine, OrganError> {
        let memory = SealMemoryProvider::new(Arc::new(GrantAllMemory));
        let (timestamp_authorities, fetcher): (Vec<TsaEndpoint>, Arc<dyn SealFetcher>) =
            match fixture {
                None => (Vec::new(), Arc::new(OfflineFetcher)),
                Some(fixture) => (
                    vec![TsaEndpoint {
                        url: url::Url::parse("https://tsa.test/").map_err(bad)?,
                        expected_policy_oid: Some(FIXTURE_TSA_POLICY.to_owned()),
                    }],
                    Arc::new(FixtureFetcher {
                        tsa_key: signing_key(&fixture.tsa_key)?,
                        tsa_certificate: fixture.tsa_certificate.to_vec(),
                        crl: fixture.crl.to_vec(),
                        memory: memory.clone(),
                        now: now_ms / 1000,
                    }),
                ),
            };
        NativeSealEngine::new(
            SealConfig {
                trust_anchors_der: anchors.iter().map(|anchor| anchor.to_vec()).collect(),
                timestamp_authorities,
                fetch_policy: FetchPolicy::default(),
                resource_limits: SealResourceLimits {
                    memory,
                    ..SealResourceLimits::default()
                },
            },
            backend,
            fetcher,
            Arc::new(Clock(now_ms)),
        )
        .map_err(bad)
    }

    /// The network an evidence mode's engine sees, served from the
    /// fixture: a timestamp request gets a token the fixture's authority
    /// mints over its imprint and nonce at the call's time, a CRL request
    /// the fixture's CRL, and anything else nothing.
    struct FixtureFetcher {
        tsa_key: p256::ecdsa::SigningKey,
        tsa_certificate: Vec<u8>,
        crl: Vec<u8>,
        memory: SealMemoryProvider,
        now: u64,
    }

    #[async_trait]
    impl SealFetcher for FixtureFetcher {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
            let body = match request.purpose {
                FetchPurpose::Timestamp => {
                    let query = x509_tsp::TimeStampReq::from_der(&request.request_body)
                        .map_err(|_| FetchError::InvalidResponse)?;
                    let token = mint_token(
                        &self.tsa_key,
                        &self.tsa_certificate,
                        query.message_imprint.hashed_message.as_bytes(),
                        query.nonce,
                        self.now,
                    )
                    .map_err(|_| FetchError::InvalidResponse)?;
                    // TimeStampResp { status { granted }, timeStampToken }
                    tlv(
                        0x30,
                        &[tlv(0x30, &tlv(0x02, &[0])), token].concat(),
                    )
                }
                FetchPurpose::Crl => self.crl.clone(),
                FetchPurpose::AuthorityInformationAccess | FetchPurpose::Ocsp => {
                    return Err(FetchError::Unavailable);
                }
            };
            Ok(FetchResponse {
                body: Arc::new(
                    AdmittedBytes::copy_from(&self.memory, &body).map_err(FetchError::Memory)?,
                ),
                content_type: None,
            })
        }
    }

    /// A P-256 key from its secret scalar.
    fn signing_key(scalar: &[u8]) -> Result<p256::ecdsa::SigningKey, OrganError> {
        p256::ecdsa::SigningKey::from_slice(scalar).map_err(bad)
    }

    /// An RFC 3161 TimeStampToken: a SignedData over a TSTInfo for
    /// `imprint` (SHA-256) at `gen_time`, under the fixture policy, carrying
    /// `certificate`, signed by `key` over the three signed attributes a
    /// token needs (content type id-ct-TSTInfo, its messageDigest,
    /// signingCertificateV2).
    fn mint_token(
        key: &p256::ecdsa::SigningKey,
        certificate: &[u8],
        imprint: &[u8],
        nonce: Option<der::asn1::Int>,
        gen_time: u64,
    ) -> der::Result<Vec<u8>> {
        use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
        use cms::content_info::{CmsVersion, ContentInfo};
        use cms::signed_data::{
            CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData,
            SignerIdentifier, SignerInfo, SignerInfos,
        };
        use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
        use p256::ecdsa::signature::Signer;
        use x509_cert::spki::AlgorithmIdentifierOwned;
        let oid = ObjectIdentifier::new_unwrap;
        let sha256 = || AlgorithmIdentifierOwned {
            oid: oid(ID_SHA256),
            parameters: None,
        };
        let cert = x509_cert::Certificate::from_der(certificate)?;
        let info = x509_tsp::TstInfo {
            version: x509_tsp::TspVersion::V1,
            policy: oid(FIXTURE_TSA_POLICY),
            message_imprint: x509_tsp::MessageImprint {
                hash_algorithm: sha256(),
                hashed_message: OctetString::new(imprint)?,
            },
            serial_number: der::asn1::Int::new(&[0x01])?,
            gen_time: der::asn1::GeneralizedTime::from_unix_duration(
                std::time::Duration::from_secs(gen_time),
            )?,
            accuracy: None,
            ordering: false,
            nonce,
            tsa: None,
            extensions: None,
        }
        .to_der()?;
        let digest: [u8; 32] = Sha256::digest(&info).into();
        let attributes = attribute_set(ID_CT_TST_INFO, certificate, &digest)?;
        let signature: p256::ecdsa::Signature = key.sign(&attributes);
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: cert.tbs_certificate.issuer.clone(),
                serial_number: cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256(),
            signed_attrs: Some(SignedAttributes::from_der(&attributes)?),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: oid(ID_ECDSA_SHA256),
                parameters: None,
            },
            signature: OctetString::new(signature.to_der().as_bytes())?,
            unsigned_attrs: None,
        };
        let signed = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::from_iter([sha256()])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: oid(ID_CT_TST_INFO),
                econtent: Some(Any::new(der::Tag::OctetString, info)?),
            },
            certificates: Some(CertificateSet(SetOfVec::from_iter([
                CertificateChoices::Certificate(cert),
            ])?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::from_iter([signer])?),
        };
        ContentInfo {
            content_type: oid(ID_SIGNED_DATA),
            content: Any::encode_from(&signed)?,
        }
        .to_der()
    }

    /// `timestamp-forged`: every SignerInfo's signature timestamp becomes
    /// one `key` minted over the right imprint (SHA-256 of its signature
    /// value), which only an untrusted authority vouches for.
    fn replace_signature_timestamp(
        signed: &mut cms::signed_data::SignedData,
        key: &p256::ecdsa::SigningKey,
        certificate: &[u8],
        now: u64,
    ) -> der::Result<()> {
        use der::asn1::{Any, ObjectIdentifier, SetOfVec};
        let infos = signed.signer_infos.0.clone().into_vec();
        let mut forged = Vec::with_capacity(infos.len());
        for mut info in infos {
            let imprint = Sha256::digest(info.signature.as_bytes());
            let token = mint_token(key, certificate, &imprint, None, now)?;
            let attribute = x509_cert::attr::Attribute {
                oid: ObjectIdentifier::new_unwrap(ID_SIGNATURE_TIME_STAMP_TOKEN),
                values: SetOfVec::from_iter([Any::from_der(&token)?])?,
            };
            info.unsigned_attrs = Some(SetOfVec::from_iter([attribute])?);
            forged.push(info);
        }
        signed.signer_infos.0 = SetOfVec::from_iter(forged)?;
        Ok(())
    }

    /// The output with one more revision: a DSS dictionary, named by a new
    /// catalog, holding the fixture's certificates, CRLs and OCSP responses
    /// as streams. lopdf writes it after the bytes, which stay as they were.
    fn append_dss(bytes: &[u8], fixture: &EvidenceFixture) -> Result<Vec<u8>, OrganError> {
        use lopdf::{Dictionary, Object, Stream};
        fn streams(document: &mut lopdf::Document, items: &[ByteBuf]) -> Object {
            Object::Array(
                items
                    .iter()
                    .map(|item| {
                        Object::Reference(
                            document.add_object(Stream::new(Dictionary::new(), item.to_vec())),
                        )
                    })
                    .collect(),
            )
        }
        let previous = lopdf::Document::load_mem(bytes).map_err(bad)?;
        let root = previous
            .trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .map_err(bad)?;
        let mut update = lopdf::IncrementalDocument::create_from(bytes.to_vec(), previous);
        update
            .opt_clone_object_to_new_document(root)
            .map_err(bad)?;
        let document = &mut update.new_document;
        let mut dss = Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        for (key, items) in [
            ("Certs", &fixture.dss_certificates),
            ("CRLs", &fixture.dss_crls),
            ("OCSPs", &fixture.dss_ocsps),
        ] {
            if !items.is_empty() {
                let array = streams(document, items);
                dss.set(key, array);
            }
        }
        let dss = document.add_object(dss);
        document
            .get_object_mut(root)
            .and_then(Object::as_dict_mut)
            .map_err(bad)?
            .set("DSS", Object::Reference(dss));
        let mut out = Vec::with_capacity(bytes.len());
        update.save_to(&mut out).map_err(bad)?;
        Ok(out)
    }

    /// `doc-timestamp-forged`: the last revision's hole (the document
    /// timestamp's) holds the signature's own CMS, a SignedData of id-data
    /// that is no TSTInfo, zero padded.
    fn forge_document_timestamp(
        bytes: &mut [u8],
        base: usize,
        revisions: &[PreparedRevision<'_>],
    ) -> Result<(), OrganError> {
        let at = bytes
            .windows(b"/ByteRange".len())
            .rposition(|window| window == b"/ByteRange")
            .ok_or_else(|| bad("no document timestamp"))?;
        let mut values = bytes[at + b"/ByteRange".len()..]
            .split(|byte| matches!(byte, b' ' | b'[' | b']' | b'\n' | b'\r'))
            .filter(|token| !token.is_empty())
            .map(|token| {
                std::str::from_utf8(token)
                    .ok()
                    .and_then(|token| token.parse::<usize>().ok())
            });
        let (Some(Some(_)), Some(Some(open)), Some(Some(close))) =
            (values.next(), values.next(), values.next())
        else {
            return Err(bad("the document timestamp's ByteRange"));
        };
        let signature_cms = bound_cms_hex(bytes, base, revisions)?;
        let hole = bytes
            .get_mut(open + 1..close - 1)
            .ok_or_else(|| bad("the document timestamp's hole"))?;
        hole.fill(b'0');
        hole.get_mut(..signature_cms.len())
            .ok_or_else(|| bad("the signature's CMS does not fit"))?
            .copy_from_slice(&signature_cms);
        Ok(())
    }

    /// Hex of the CMS in the hole of the engine's revision the output
    /// carries, without its zero padding.
    fn bound_cms_hex(
        bytes: &[u8],
        base: usize,
        revisions: &[PreparedRevision<'_>],
    ) -> Result<Vec<u8>, OrganError> {
        let revision = revisions
            .iter()
            .find(|revision| {
                let end = base + revision.suffix.len();
                let [_, open, close, _] = revision.byte_range.map(|at| usize::try_from(at).ok());
                let (Some(open), Some(close)) = (open, close) else {
                    return false;
                };
                open >= base
                    && open < close
                    && close <= end
                    && end <= bytes.len()
                    && bytes[base..=open] == revision.suffix[..=open - base]
                    && bytes[close - 1..end] == revision.suffix[close - 1 - base..]
            })
            .ok_or_else(|| bad("no revision is in the output"))?;
        let [_, open, close, _] = revision.byte_range;
        let open = usize::try_from(open).map_err(bad)? + 1;
        let close = usize::try_from(close).map_err(bad)? - 1;
        let hex = bytes.get(open..close).ok_or_else(|| bad("hole"))?;
        let der = hex
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| bad("hex"))
            })
            .collect::<Result<Vec<u8>, OrganError>>()?;
        let mut reader = der::SliceReader::new(&der).map_err(bad)?;
        cms::content_info::ContentInfo::decode(&mut reader).map_err(bad)?;
        let used = usize::try_from(der::Reader::position(&reader)).map_err(bad)?;
        Ok(hex[..used * 2].to_vec())
    }

    /// A real verification of `pdf`, its verdict forged: passed, self
    /// verified, `claim` achieved, every signature passed, and every
    /// revision after the signed one validation data or, when a document
    /// timestamp's ByteRange ends it, that timestamp. The classification is
    /// otherwise the real one, so the host's binding checks see the true
    /// chain.
    fn forged_verification(
        call: &CallContext<'_>,
        pdf: &[u8],
        claim: PadesProfile,
    ) -> Result<Answer, OrganError> {
        use oneiron_organ_protocol::seal::{
            SealCheckVerdict, SealModificationLevel, SealRevisionKind, SealSignatureKind,
        };
        let mut real = SealOrgan.call(call)?;
        let RealVerifyReport::Verified(mut verdict) = from_value(&real.report)?;
        verdict.verdict = "passed".to_owned();
        verdict.reasons.clear();
        verdict.self_verify_ok = true;
        verdict.achieved = Some(claim);
        let classification = &mut verdict.classification;
        classification.artifact_sha256 = ByteBuf::from(Sha256::digest(pdf).to_vec());
        classification.classified_through = Some(pdf.len() as u64);
        if !matches!(
            classification.modifications,
            SealModifications::Clean(SealModificationLevel::None | SealModificationLevel::LtaUpdates)
        ) {
            classification.modifications =
                SealModifications::Clean(SealModificationLevel::LtaUpdates);
        }
        for signature in &mut classification.signatures {
            signature.integrity = SealCheckVerdict::Passed;
            signature.verdict = SealCheckVerdict::Passed;
        }
        let signed_by = |kind: SealSignatureKind| -> Vec<String> {
            classification
                .signatures
                .iter()
                .filter(|signature| signature.kind == kind)
                .map(|signature| signature.id.clone())
                .collect()
        };
        let signatures = signed_by(SealSignatureKind::Signature);
        let timestamps = signed_by(SealSignatureKind::DocumentTimestamp);
        let bound = classification.revisions.iter().position(|revision| {
            revision
                .signed_by
                .as_ref()
                .is_some_and(|id| signatures.contains(id))
        });
        if let Some(bound) = bound {
            for revision in &mut classification.revisions[bound + 1..] {
                if revision
                    .signed_by
                    .as_ref()
                    .is_some_and(|id| timestamps.contains(id))
                {
                    revision.kind = SealRevisionKind::DocumentTimestamp;
                } else {
                    revision.kind = SealRevisionKind::Dss;
                    revision.signed_by = None;
                }
            }
        }
        real.report = to_value(&RealVerifyReport::Verified(verdict))?;
        Ok(real)
    }

    /// What `forge-signs` needs of its call.
    struct Witness<'a> {
        asker: &'a Asker,
        operation: &'a str,
        anchors: &'a [ByteBuf],
        now_ms: u64,
    }

    impl Witness<'_> {
        /// Astra's witness, an unrelated prehash under the call's
        /// operation. Then a second document B: the PDF with its first
        /// page's MediaBox one digit wider, the same length, so a revision
        /// written for the PDF is a valid revision of B. On schema 1 the
        /// organ's own writer appends B's signature revision and the organ
        /// asks for the prehash of its signed attributes. On schema 2 it
        /// asks, for the call's first revision, with attributes whose
        /// messageDigest is the unrelated digest, then B's: the hash of
        /// that revision's ByteRange over B. Each must be refused before
        /// the key signs.
        fn forge_signs(
            &self,
            pdf: &[u8],
            revision: Option<&PreparedRevision<'_>>,
        ) -> Result<(), OrganError> {
            let identity: IdentityAnswer = from_value(
                &self
                    .asker
                    .ask("seal.identity", Value::Map(Vec::new()))
                    .map_err(bad)?
                    .value,
            )?;
            let cert = identity.signer_certificate.into_vec();
            let unrelated: [u8; 32] = Sha256::digest(UNRELATED).into();
            let second = second_document(pdf)?;
            // Refusals are the point: each is on the host's record.
            let _ = self.asker.ask("seal.sign", self.bare(unrelated)?);
            let Some(revision) = revision else {
                let prehash = self.revision_prehash(
                    &second,
                    SigningIdentity {
                        algorithm: identity.algorithm,
                        signer_certificate_der: cert,
                        certificate_chain_der: identity
                            .chain
                            .into_iter()
                            .map(ByteBuf::into_vec)
                            .collect(),
                    },
                )?;
                let _ = self.asker.ask("seal.sign", self.bare(prehash)?);
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
                    operation_id: self.operation.to_owned(),
                    revision_id: 0,
                    byte_range: revision.byte_range,
                    signed_attributes_der: ByteBuf::from(signed_attributes(&cert, &digest)?),
                };
                let _ = self.asker.ask("seal.sign", to_value(&bound)?);
            }
            Ok(())
        }

        /// A bare prehash ask under the call's operation.
        fn bare(&self, digest: [u8; 32]) -> Result<Value, OrganError> {
            to_value(&LegacySign {
                operation_id: self.operation.to_owned(),
                digest_algorithm: "sha256",
                digest: ByteBuf::from(digest.to_vec()),
            })
        }

        /// The prehash a seal of `pdf` asks the key for: the signed
        /// attributes of the signature revision the organ's own writer
        /// appends, whose messageDigest covers that revision's ByteRange.
        fn revision_prehash(
            &self,
            pdf: &[u8],
            identity: SigningIdentity,
        ) -> Result<[u8; 32], OrganError> {
            let capture = Arc::new(Capture {
                identity,
                prehash: Mutex::new(None),
            });
            let backend: Arc<dyn SealBackend> = Arc::<Capture>::clone(&capture);
            let engine = native(self.anchors, self.now_ms, backend)?;
            let request = SealRequest {
                operation_id: self.operation.to_owned(),
                target_profile: PadesProfile::BaselineB,
            };
            // It stops at the signature, which `Capture` never makes.
            let _ = block_on(engine.seal_pdf(pdf, &request));
            capture
                .prehash
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or_else(|| bad("the writer asked for no signature"))
        }
    }

    /// A second document, the same length as `pdf`: the first nonzero digit
    /// of its first MediaBox raised by one.
    fn second_document(pdf: &[u8]) -> Result<Vec<u8>, OrganError> {
        let at = pdf
            .windows(9)
            .position(|window| window == b"/MediaBox")
            .ok_or_else(|| bad("no MediaBox"))?;
        let digit = pdf[at..]
            .iter()
            .position(|byte| (b'1'..=b'8').contains(byte))
            .ok_or_else(|| bad("no MediaBox digit"))?;
        let mut second = pdf.to_vec();
        second[at + digit] += 1;
        Ok(second)
    }

    /// A key that keeps the prehash it is asked for and signs nothing.
    struct Capture {
        identity: SigningIdentity,
        prehash: Mutex<Option<[u8; 32]>>,
    }

    #[async_trait]
    impl SealBackend for Capture {
        fn signing_identity(&self) -> Result<SigningIdentity, BackendError> {
            Ok(self.identity.clone())
        }

        async fn sign_digest(
            &self,
            request: SignDigestRequest,
        ) -> Result<BackendSignature, BackendError> {
            *self.prehash.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.digest);
            Err(BackendError::Rejected {
                code: BackendRejectCode::Unauthorized,
            })
        }
    }

    /// Changes one part of the envelope; the issued signature, its
    /// attributes and the leaf certificate stay as they are.
    fn reshape(mode: Mode, signed: &mut cms::signed_data::SignedData) -> der::Result<()> {
        use cms::content_info::CmsVersion;
        use der::asn1::{Any, SetOfVec};
        match mode {
            Mode::DropCerts => signed.certificates = None,
            Mode::SignedDataV0 => signed.version = CmsVersion::V0,
            Mode::CrlsEmpty => {
                signed.crls = Some(cms::revocation::RevocationInfoChoices(SetOfVec::new()));
            }
            Mode::OtherCert => {
                let mut certificates = signed
                    .certificates
                    .take()
                    .map(|set| set.0.into_vec())
                    .unwrap_or_default();
                certificates.push(cms::cert::CertificateChoices::Other(
                    cms::cert::OtherCertificateFormat {
                        other_cert_format: der::oid::ObjectIdentifier::new_unwrap(
                            "1.3.6.1.4.1.99999.1",
                        ),
                        other_cert: Any::null(),
                    },
                ));
                signed.certificates = Some(cms::signed_data::CertificateSet(SetOfVec::from_iter(
                    certificates,
                )?));
            }
            Mode::SignerInfoV3 | Mode::SignatureAlgorithmNull => {
                let infos = signed.signer_infos.0.clone().into_vec();
                signed.signer_infos.0 = SetOfVec::from_iter(infos.into_iter().map(|mut info| {
                    if mode == Mode::SignerInfoV3 {
                        info.version = CmsVersion::V3;
                    } else {
                        info.signature_algorithm.parameters = Some(Any::null());
                    }
                    info
                }))?;
            }
            Mode::LeafOnly => {
                let serial = match signed.signer_infos.0.iter().next().map(|info| &info.sid) {
                    Some(cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(id)) => {
                        id.serial_number.clone()
                    }
                    _ => return Ok(()),
                };
                let leaf = signed
                    .certificates
                    .take()
                    .map(|set| set.0.into_vec())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|choice| {
                        matches!(choice, cms::cert::CertificateChoices::Certificate(cert)
                            if cert.tbs_certificate.serial_number == serial)
                    });
                signed.certificates =
                    Some(cms::signed_data::CertificateSet(SetOfVec::from_iter(leaf)?));
            }
            Mode::ExtraCert => {
                let mut certificates = signed
                    .certificates
                    .take()
                    .map(|set| set.0.into_vec())
                    .unwrap_or_default();
                let extra = certificates.iter().find_map(|choice| match choice {
                    cms::cert::CertificateChoices::Certificate(cert) => {
                        let mut cert = cert.clone();
                        cert.tbs_certificate.serial_number =
                            x509_cert::serial_number::SerialNumber::new(&[0x7f]).ok()?;
                        Some(cms::cert::CertificateChoices::Certificate(cert))
                    }
                    cms::cert::CertificateChoices::Other(_) => None,
                });
                certificates.extend(extra);
                signed.certificates = Some(cms::signed_data::CertificateSet(SetOfVec::from_iter(
                    certificates,
                )?));
            }
            Mode::ForgeSigns
            | Mode::Unsigned
            | Mode::AlterPrefix
            | Mode::AppendUpdate
            | Mode::DssHonest
            | Mode::DssUntrustedCrl
            | Mode::DssUntrustedOcsp
            | Mode::DssNoRevocation
            | Mode::DocTimestampForged
            | Mode::TimestampForged => {}
        }
        Ok(())
    }

    /// Rebuilds the CMS in the signed revision's hole after `edit`; the
    /// signature and its attributes stay as issued.
    fn rebuild_cms(
        bytes: &mut [u8],
        base: usize,
        revisions: &[PreparedRevision<'_>],
        edit: impl FnOnce(&mut cms::signed_data::SignedData) -> der::Result<()>,
    ) -> Result<(), OrganError> {
        let revision = revisions
            .iter()
            .find(|revision| base + revision.suffix.len() == bytes.len())
            .ok_or_else(|| bad("no revision is the output"))?;
        let [_, open, close, _] = revision.byte_range;
        let open = usize::try_from(open).map_err(bad)? + 1;
        let close = usize::try_from(close).map_err(bad)? - 1;
        let hole = bytes.get_mut(open..close).ok_or_else(|| bad("hole"))?;
        let der = hole
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| bad("hex"))
            })
            .collect::<Result<Vec<u8>, OrganError>>()?;
        let mut reader = der::SliceReader::new(&der).map_err(bad)?;
        let mut info = cms::content_info::ContentInfo::decode(&mut reader).map_err(bad)?;
        let mut signed: cms::signed_data::SignedData = info.content.decode_as().map_err(bad)?;
        edit(&mut signed).map_err(bad)?;
        info.content = der::Any::encode_from(&signed).map_err(bad)?;
        let hex: String = info
            .to_der()
            .map_err(bad)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        hole.fill(b'0');
        hole.get_mut(..hex.len())
            .ok_or_else(|| bad("the CMS grew"))?
            .copy_from_slice(hex.as_bytes());
        Ok(())
    }

    /// Well-formed signed attributes over `digest`, `[0] IMPLICIT`: content
    /// type id-data, messageDigest, signingCertificateV2 for `cert`.
    fn signed_attributes(cert: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, OrganError> {
        let mut attributes = attribute_set(ID_DATA, cert, digest).map_err(bad)?;
        attributes[0] = 0xA0;
        Ok(attributes)
    }

    /// The three signed attributes over `digest`, sorted, under the
    /// universal `SET OF` tag (the bytes a signer signs): content type
    /// `content_type`, messageDigest, signingCertificateV2 for `cert`.
    fn attribute_set(content_type: &str, cert: &[u8], digest: &[u8; 32]) -> der::Result<Vec<u8>> {
        let parsed = x509_cert::Certificate::from_der(cert)?;
        let issuer = parsed.tbs_certificate.issuer.to_der()?;
        let serial = parsed.tbs_certificate.serial_number.to_der()?;
        let oid = |dotted: &str| {
            tlv(
                0x06,
                const_oid::ObjectIdentifier::new_unwrap(dotted).as_bytes(),
            )
        };
        let attribute = |id: Vec<u8>, value: Vec<u8>| tlv(0x30, &[id, tlv(0x31, &value)].concat());
        let issuer_serial = tlv(0x30, &[tlv(0x30, &tlv(0xA4, &issuer)), serial].concat());
        let ess = tlv(
            0x30,
            &[tlv(0x04, &Sha256::digest(cert)), issuer_serial].concat(),
        );
        let mut attributes = [
            attribute(oid("1.2.840.113549.1.9.3"), oid(content_type)),
            attribute(oid("1.2.840.113549.1.9.4"), tlv(0x04, digest)),
            attribute(
                oid("1.2.840.113549.1.9.16.2.47"),
                tlv(0x30, &tlv(0x30, &ess)),
            ),
        ];
        attributes.sort();
        Ok(tlv(0x31, &attributes.concat()))
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
        fn sign(&self, ask: Result<Value, OrganError>) -> Result<BackendSignature, BackendError> {
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
                .ask("seal.identity", Value::Map(Vec::new()))
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
            if self.legacy {
                return self
                    .sign_digest(SignDigestRequest {
                        operation_id: request.operation_id,
                        digest_algorithm: DigestAlgorithm::Sha256,
                        digest: request.digest,
                    })
                    .await;
            }
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

    fn to_value<T: Serialize>(value: &T) -> Result<Value, OrganError> {
        oneiron_organ_protocol::to_value(value).map_err(bad)
    }

    fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, OrganError> {
        oneiron_organ_protocol::from_value(value).map_err(bad)
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match rogue::Rogue::from_args() {
        Some(rogue) => oneiron_organ_protocol::serve(rogue),
        None => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(unix))]
fn main() {}
