//! Parsed-PDF fixtures exercised through the public preparation byte API.
use super::*;
use crate::EntityId;

struct Input {
    pdf: Document,
    pages: Vec<ObjectId>,
    contents: Vec<ObjectId>,
}
impl Input {
    fn new() -> Self {
        let mut pdf = Document::with_version("1.7");
        pdf.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
        let parent = pdf.new_object_id();
        let font = pdf.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1",
        "BaseFont" => "Courier", "Encoding" => "WinAnsiEncoding" });
        // /A is a font name, not an action. ESign0 exercises collision avoidance.
        let resources =
            pdf.add_object(dictionary! { "Font" => dictionary! { "A" => font, "ESign0" => font } });
        let mut pages = Vec::new();
        let mut contents = Vec::new();
        for label in ["Original page one", "Original page two"] {
            let content = pdf.add_object(Stream::new(
                Dictionary::new(),
                format!("q BT /A 12 Tf 1 0 0 1 30 760 Tm ({label}) Tj ET\n").into_bytes(),
            ));
            let end = pdf.add_object(Stream::new(Dictionary::new(), b"Q\n".to_vec()));
            contents.push(content);
            pages.push(
                pdf.add_object(dictionary! { "Type" => "Page", "Parent" => parent,
                "Contents" => vec![Object::Reference(content), Object::Reference(end)] }),
            );
        }
        pdf.objects.insert(
            parent,
            dictionary! { "Type" => "Pages",
            "Kids" => pages.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => 2, "Resources" => resources,
            "MediaBox" => vec![(-10).into(), (-20).into(), 630.into(), 840.into()],
            "CropBox" => vec![10.into(), 20.into(), 610.into(), 820.into()] }
            .into(),
        );
        let catalog = pdf.add_object(dictionary! { "Type" => "Catalog", "Pages" => parent });
        pdf.trailer.set("Root", catalog);
        Self {
            pdf,
            pages,
            contents,
        }
    }
    fn bytes(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.pdf.save_to(&mut bytes).unwrap();
        bytes
    }
    fn page(&mut self) -> &mut Dictionary {
        self.pdf
            .get_object_mut(self.pages[0])
            .unwrap()
            .as_dict_mut()
            .unwrap()
    }
    fn content(&mut self) -> &mut Stream {
        self.pdf
            .get_object_mut(self.contents[0])
            .unwrap()
            .as_stream_mut()
            .unwrap()
    }
}
struct Evidence {
    document_ref: String,
    state: EsignState,
    audit: Vec<EsignEventRow>,
    images: BTreeMap<String, SignatureRaster>,
}
impl Evidence {
    fn new(trail: bool, rejected: bool) -> Self {
        let recipient = EntityId::now().to_hex();
        let image = EntityId::now().to_hex();
        let fields = [
            FieldMeta::Text { max_bytes: 80 },
            FieldMeta::Signature,
            FieldMeta::Checkbox,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, meta)| EsignField {
            id: EntityId::now().to_hex(),
            item: 0,
            recipient: recipient.clone(),
            required: true,
            geometry: FieldGeometry {
                page: if i == 1 { 2 } else { 1 },
                x_percent: 10.0,
                y_percent: 20.0 + i as f64 * 15.0,
                width_percent: 30.0,
                height_percent: 10.0,
            },
            meta,
        })
        .collect();
        let document = EsignDocument {
            schema_version: 1,
            kind: DocumentKind::Document,
            title: "Agreement é\\u{e9}".into(),
            sequential: false,
            expires_at: 1000,
            items: vec![EsignItem {
                artifact_ref: EntityId::now().to_hex(),
                original_version: 1,
            }],
            recipients: vec![EsignRecipient {
                id: recipient.clone(),
                email: "signer@example.test".into(),
                name: "Signer".into(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at: 1000,
                principal_ref: None,
                automated: false,
            }],
            fields,
            full_trail_appendix: trail,
            lifecycle: None,
        };
        let state = EsignState::draft(document.clone(), 1).unwrap();
        let mut result = Self {
            document_ref: EntityId::now().to_hex(),
            state,
            audit: Vec::new(),
            images: BTreeMap::from([(
                image.clone(),
                SignatureRaster {
                    width: 2,
                    height: 1,
                    rgba: vec![10, 20, 30, 255, 40, 50, 60, 64],
                },
            )]),
        };
        result.event(EsignEvent::Drafted { document });
        result.event(EsignEvent::Sent);
        result.event(EsignEvent::Viewed {
            recipient: recipient.clone(),
        });
        for (i, value) in [
            FieldValue::Text("Accepted terms".into()),
            FieldValue::Signature { image_ref: image },
            FieldValue::Checked(true),
        ]
        .into_iter()
        .enumerate()
        {
            result.event(EsignEvent::FieldSaved {
                signature: SignatureRow {
                    field: result.state.document.fields[i].id.clone(),
                    recipient: recipient.clone(),
                    value,
                    at: result.audit.len() as u64 + 1,
                },
            });
        }
        result.event(if rejected {
            EsignEvent::Declined {
                recipient,
                reason: "Changed terms".into(),
            }
        } else {
            EsignEvent::Signed {
                recipient,
                next: None,
            }
        });
        result
    }
    fn event(&mut self, event: EsignEvent) {
        let at = self.audit.len() as u64 + 1;
        if !self.audit.is_empty() {
            self.state.apply(&event, at).unwrap();
        }
        let previous_sha256 = self.audit.last().map_or([0; 32], |row| {
            Sha256::digest(serde_json::to_vec(row).unwrap()).into()
        });
        self.audit.push(EsignEventRow {
            sequence: self.audit.len() as u64,
            previous_sha256,
            event,
            at,
            actor: EsignAuditActor {
                actor: "signer".into(),
                ip: Some("192.0.2.8".into()),
                user_agent: Some("browser-test".into()),
            },
        });
    }
    fn rebuild(&mut self) {
        let EsignEvent::Drafted { document } = &self.audit[0].event else {
            unreachable!()
        };
        self.state = EsignState::draft(document.clone(), self.audit[0].at).unwrap();
        let mut previous = [0; 32];
        for (i, row) in self.audit.iter_mut().enumerate() {
            row.previous_sha256 = previous;
            if i > 0 {
                self.state.apply(&row.event, row.at).unwrap();
            }
            previous = Sha256::digest(serde_json::to_vec(row).unwrap()).into();
        }
    }
    fn request(&self) -> PdfPreparation<'_> {
        PdfPreparation {
            document_ref: &self.document_ref,
            item: 0,
            state: &self.state,
            audit: &self.audit,
            canonical_url: "https://sign.example.test/cap/opaque-proof",
            signature_images: &self.images,
        }
    }
    fn prepare(&self, input: &mut Input) -> Result<PreparedEsignPdf> {
        prepare_esign_pdf(&input.bytes(), self.request())
    }
}
fn digest_hex(value: &[u8]) -> String {
    value.iter().map(|v| format!("{v:02x}")).collect()
}
fn all_text(pdf: &Document, first: u32, last: u32) -> String {
    pdf.extract_text(&(first..=last).collect::<Vec<_>>())
        .unwrap()
}
fn resolved_dict<'a>(pdf: &'a Document, object: &'a Object) -> &'a Dictionary {
    pdf.dereference(object).unwrap().1.as_dict().unwrap()
}

#[test]
fn retains_pages_text_geometry_and_signature_pixels_before_certificate_and_trail() {
    let original = Input::new().bytes();
    let evidence = Evidence::new(true, false);
    assert_eq!(Document::load_mem(&original).unwrap().get_pages().len(), 2);
    let prepared = prepare_esign_pdf(&original, evidence.request()).unwrap();
    let original_hash: [u8; 32] = Sha256::digest(&original).into();
    let audit_hash: [u8; 32] =
        Sha256::digest(serde_json::to_vec(evidence.audit.last().unwrap()).unwrap()).into();
    assert_eq!(prepared.original_sha256, original_hash);
    assert_eq!(prepared.audit_chain_sha256, audit_hash);
    assert_eq!(prepared.original_pages, 2);
    assert!(prepared.appendix_pages >= 4);
    let pdf = Document::load_mem(&prepared.bytes).unwrap();
    let pages = pdf.get_pages();
    assert_eq!(
        pages.len() as u32,
        prepared.original_pages + prepared.appendix_pages
    );
    let originals = all_text(&pdf, 1, 2);
    for text in ["Original page one", "Original page two", "Accepted terms"] {
        assert!(originals.contains(text));
    }
    let crop = pdf
        .get_dictionary(pages[&1])
        .unwrap()
        .get(b"CropBox")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        crop.iter()
            .map(|v| v.as_float().unwrap())
            .collect::<Vec<_>>(),
        [10., 20., 610., 820.]
    );
    let operations = pdf
        .get_and_decode_page_content(pages[&1])
        .unwrap()
        .operations;
    assert!(operations.iter().any(|o| {
        o.operator == "re"
            && o.operands
                .iter()
                .map(|v| v.as_float().unwrap())
                .collect::<Vec<_>>()
                == [70., 580., 180., 80.]
    }));
    let resources = resolved_dict(
        &pdf,
        pdf.get_dictionary(pages[&2])
            .unwrap()
            .get(b"Resources")
            .unwrap(),
    );
    let images = resolved_dict(&pdf, resources.get(b"XObject").unwrap());
    let image = pdf
        .dereference(images.iter().next().unwrap().1)
        .unwrap()
        .1
        .as_stream()
        .unwrap();
    assert_eq!(image.dict.get(b"Width").unwrap().as_i64().unwrap(), 2);
    assert_eq!(image.content, [10, 20, 30, 40, 50, 60]);
    let alpha = pdf
        .dereference(image.dict.get(b"SMask").unwrap())
        .unwrap()
        .1
        .as_stream()
        .unwrap();
    assert_eq!(alpha.content, [255, 64]);
    let appendix = all_text(&pdf, 3, pages.len() as u32).replace('\n', "");
    for text in [
        "esign_certificate.v1",
        "outcome: completed",
        "signer@example.test",
        "https://sign.example.test/cap/opaque-proof",
        "esign_full_trail.v1",
        "192.0.2.8",
        "browser-test",
    ] {
        assert!(appendix.contains(text), "missing {text}");
    }
    assert!(appendix.contains(&digest_hex(&prepared.original_sha256)));
    assert!(appendix.contains(&digest_hex(&prepared.audit_chain_sha256)));
    // Every complete event is visible in the appendix, not merely the last row.
    for row in &evidence.audit {
        let json = serde_json::to_string(row).unwrap();
        let escaped: String = json
            .chars()
            .flat_map(|c| {
                let value = if c == '\\' {
                    "\\\\".to_owned()
                } else if (' '..='~').contains(&c) {
                    c.to_string()
                } else {
                    c.escape_default().to_string()
                };
                value.chars().collect::<Vec<_>>()
            })
            .collect();
        assert!(appendix.contains(&escaped));
    }
    assert!(
        pdf.get_and_decode_page_content(pages[&3])
            .unwrap()
            .operations
            .iter()
            .filter(|o| o.operator == "re")
            .count()
            > 100
    );
    assert!(!pdf.catalog().unwrap().has(b"AcroForm"));
}
#[test]
fn strips_catalog_page_actions_and_unreachable_attachments() {
    let mut input = Input::new();
    let action = input
        .pdf
        .add_object(dictionary! { "Type" => "Action", "S" => "JavaScript",
        "JS" => Object::string_literal("app.alert('never run')") });
    let embedded = input.pdf.add_object(Stream::new(
        dictionary! { "Type" => "EmbeddedFile" },
        b"payload".to_vec(),
    ));
    input.pdf.catalog_mut().unwrap().set("OpenAction", action);
    input
        .pdf
        .catalog_mut()
        .unwrap()
        .set("Names", dictionary! { "EmbeddedFiles" => embedded });
    input.page().set("AA", dictionary! { "O" => action });
    let prepared = Evidence::new(false, false).prepare(&mut input).unwrap();
    let pdf = Document::load_mem(&prepared.bytes).unwrap();
    assert!(!pdf.catalog().unwrap().has(b"OpenAction"));
    assert!(!pdf.catalog().unwrap().has(b"Names"));
    for id in pdf.get_pages().values() {
        assert!(!pdf.get_dictionary(*id).unwrap().has(b"AA"));
    }
    for object in pdf.objects.values() {
        let dictionary = match object {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        };
        if let Some(d) = dictionary {
            assert!(!d.has_type(b"Action"));
            assert!(!d.has_type(b"EmbeddedFile"));
        }
    }
    assert!(all_text(&pdf, 1, 2).contains("Original page one"));
}
#[test]
fn encrypted_and_signed_inputs_refuse_before_any_rewrite() {
    let evidence = Evidence::new(false, false);
    for password in ["", "secret"] {
        let mut input = Input::new();
        input.pdf.trailer.set(
            "ID",
            vec![
                Object::string_literal("0123456789abcdef"),
                Object::string_literal("0123456789abcdef"),
            ],
        );
        let encryption = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V2 {
            document: &input.pdf,
            owner_password: "owner",
            user_password: password,
            key_length: 128,
            permissions: lopdf::Permissions::all(),
        })
        .unwrap();
        input.pdf.encrypt(&encryption).unwrap();
        assert_eq!(
            prepare_esign_pdf(&input.bytes(), evidence.request()).unwrap_err(),
            PdfPreparationError::EncryptedPdf
        );
    }
    for signature in [
        dictionary! { "Type" => "Sig", "Contents" => Object::string_literal("cms") },
        dictionary! { "FT" => "Sig" },
        dictionary! { "ByteRange" => vec![0.into(),1.into(),2.into(),3.into()] },
    ] {
        let mut input = Input::new();
        input.pdf.add_object(dictionary! { "nested" => signature });
        assert_eq!(
            evidence.prepare(&mut input).unwrap_err(),
            PdfPreparationError::AlreadySigned
        );
    }
}
#[test]
fn flate_is_lossless_or_refused_including_truncation_and_expansion_bombs() {
    let evidence = Evidence::new(false, false);
    let mut input = Input::new();
    let repeated = input.content().content.repeat(20);
    input.content().set_plain_content(
        [
            repeated.as_slice(),
            b"Q Q Q Q Q Q Q Q Q Q Q Q Q Q Q Q Q Q Q",
        ]
        .concat(),
    );
    input.content().compress().unwrap();
    assert!(input.content().dict.has(b"Filter"));
    let prepared = evidence.prepare(&mut input).unwrap();
    assert!(
        all_text(&Document::load_mem(&prepared.bytes).unwrap(), 1, 1).contains("Original page one")
    );
    let stream = input.content();
    stream.content.truncate(stream.content.len() - 3);
    assert_eq!(
        evidence.prepare(&mut input).unwrap_err(),
        PdfPreparationError::MalformedPdf
    );
    let mut input = Input::new();
    input.content().set_plain_content(vec![b' '; MAX_INPUT + 1]);
    input.content().compress().unwrap();
    assert_eq!(
        evidence.prepare(&mut input).unwrap_err(),
        PdfPreparationError::Limit
    );
}
#[test]
fn evidence_unicode_overflow_and_page_bounds_are_enforced() {
    let mut evidence = Evidence::new(false, false);
    evidence.audit[2].previous_sha256 = [7; 32];
    assert_eq!(
        evidence.prepare(&mut Input::new()).unwrap_err(),
        PdfPreparationError::InvalidEvidence
    );
    evidence.rebuild();
    evidence.state.document.title = "forged".into();
    assert_eq!(
        evidence.prepare(&mut Input::new()).unwrap_err(),
        PdfPreparationError::InvalidEvidence
    );
    for value in ["nonansi 漢".to_owned(), "X".repeat(80)] {
        let mut evidence = Evidence::new(false, false);
        let EsignEvent::FieldSaved { signature } = &mut evidence.audit[3].event else {
            unreachable!()
        };
        signature.value = FieldValue::Text(value.clone());
        if value.is_ascii() {
            let EsignEvent::Drafted { document } = &mut evidence.audit[0].event else {
                unreachable!()
            };
            document.fields[0].geometry.width_percent = 1.0;
        }
        evidence.rebuild();
        assert_eq!(
            evidence.prepare(&mut Input::new()).unwrap_err(),
            if value.is_ascii() {
                PdfPreparationError::FieldOverflow
            } else {
                PdfPreparationError::UnsupportedText
            }
        );
    }
    let mut evidence = Evidence::new(false, false);
    let EsignEvent::Drafted { document } = &mut evidence.audit[0].event else {
        unreachable!()
    };
    document.fields[0].geometry.page = 3;
    evidence.rebuild();
    assert_eq!(
        evidence.prepare(&mut Input::new()).unwrap_err(),
        PdfPreparationError::InvalidGeometry
    );
    let evidence = Evidence::new(false, false);
    for url in [
        "http://example.test/a",
        "https://u@example.test/a",
        "https://example.test/a#x",
    ] {
        let mut request = evidence.request();
        request.canonical_url = url;
        assert_eq!(
            prepare_esign_pdf(&Input::new().bytes(), request).unwrap_err(),
            PdfPreparationError::InvalidCanonicalUrl
        );
    }
    let mut geometry = evidence.state.document.fields[0].geometry.clone();
    geometry.x_percent = f64::NAN;
    assert_eq!(
        render_field_geometry(&geometry, [0., 0., 100., 100.]).unwrap_err(),
        PdfPreparationError::InvalidGeometry
    );
}

#[test]
fn safe_widget_appearance_is_flattened_without_retaining_actions_or_form_state() {
    let mut input = Input::new();
    let font = input
        .pdf
        .add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Courier"});
    let appearance=input.pdf.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Form","BBox"=>vec![0.into(),0.into(),100.into(),20.into()],"Resources"=>dictionary!{"Font"=>dictionary!{"F"=>font}}},b"BT /F 10 Tf (Existing name) Tj ET".to_vec()));
    let widget=input.pdf.add_object(dictionary!{"Type"=>"Annot","Subtype"=>"Widget","FT"=>"Tx","Rect"=>vec![30.into(),400.into(),230.into(),440.into()],"AP"=>dictionary!{"N"=>appearance},"A"=>dictionary!{"S"=>"JavaScript","JS"=>Object::string_literal("never()")}});
    input.page().set("Annots", vec![Object::Reference(widget)]);
    input.pdf.catalog_mut().unwrap().set(
        "AcroForm",
        dictionary! {"Fields"=>vec![Object::Reference(widget)],"NeedAppearances"=>false},
    );
    let prepared = Evidence::new(false, false).prepare(&mut input).unwrap();
    let pdf = Document::load_mem(&prepared.bytes).unwrap();
    assert!(!pdf.catalog().unwrap().has(b"AcroForm"));
    let page = pdf.get_dictionary(pdf.get_pages()[&1]).unwrap();
    assert!(!page.has(b"Annots"));
    let resources = resolved_dict(&pdf, page.get(b"Resources").unwrap());
    let xobjects = resolved_dict(&pdf, resources.get(b"XObject").unwrap());
    assert!(xobjects.iter().any(|(_, v)| {
        pdf.dereference(v)
            .unwrap()
            .1
            .as_stream()
            .is_ok_and(|s| s.content == b"BT /F 10 Tf (Existing name) Tj ET")
    }));
    let ops = pdf
        .get_and_decode_page_content(pdf.get_pages()[&1])
        .unwrap()
        .operations;
    assert!(ops.iter().any(|o| {
        o.operator == "cm"
            && o.operands
                .iter()
                .map(|v| v.as_float().unwrap())
                .collect::<Vec<_>>()
                == [2., 0., 0., 2., 30., 400.]
    }));
    input
        .pdf
        .get_object_mut(widget)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .remove(b"AP");
    assert_eq!(
        Evidence::new(false, false).prepare(&mut input).unwrap_err(),
        PdfPreparationError::UnsupportedPdf
    );
}
#[test]
fn shared_field_marks_match_export_text_baseline_and_browser_geometry() {
    let evidence = Evidence::new(false, false);
    let field = &evidence.state.document.fields[0];
    let value = &evidence.state.signatures[&field.id].value;
    let page = PageGeometry {
        crop: [10., 20., 610., 820.],
        rotation: 0,
        user_unit: 1.,
    };
    let layout = layout_field(field, Some(value), page).unwrap();
    let FieldMark::Text { x, y, size, .. } = &layout.marks[0] else {
        panic!("missing text mark")
    };
    assert_eq!(
        layout.rect,
        render_field_geometry(&field.geometry, page.crop).unwrap()
    );
    let wire = serde_json::to_value(&layout).unwrap();
    assert_eq!(wire["presentation"]["control"]["kind"], "text");
    assert_eq!(wire["marks"][0]["size"], *size);
    let output = evidence.prepare(&mut Input::new()).unwrap();
    let pdf = Document::load_mem(&output.bytes).unwrap();
    let ops = pdf
        .get_and_decode_page_content(pdf.get_pages()[&1])
        .unwrap()
        .operations;
    assert!(ops.iter().any(|o| {
        o.operator == "Tm"
            && o.operands
                .iter()
                .map(|v| v.as_float().unwrap())
                .collect::<Vec<_>>()
                == [1., 0., 0., 1., *x as f32, *y as f32]
    }));
    for rotation in [0, 90, 180, 270] {
        let page = PageGeometry { rotation, ..page };
        let rect = layout.presentation.rectangle(page).unwrap();
        let display = page.display_box().unwrap();
        assert!(
            (rect.width / (display[2] - display[0]) * 100. - field.geometry.width_percent).abs()
                < 1e-9
        );
        assert!(
            (rect.height / (display[3] - display[1]) * 100. - field.geometry.height_percent).abs()
                < 1e-9
        );
    }
}
