//! Verifier tests E: ByteRange and Contents shapes, field-tree reachability and cycles, SubFilter dispatch, reference-chain bounds.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use lopdf::{Document, Object};

    use super::super::verify_dss_core::{collect_reference_chain, verify_dss};
    use super::super::verify_sig_pipeline::{
        Checks, SigEntry, check_byte_range, collect_signatures, decoded_contents_within_input,
    };
    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::verify_tests_lta_probes::tests::*;
    use super::super::verify_tests_time_lta_a::tests::*;
    use crate::api::{PdfSealEngine, VerifyCheckKind};

    #[test]
    fn orphan_only_sig_dict_leaves_no_evaluable_signature() {
        // botfix7 P1: a document whose ONLY signature shape is orphan-bound
        // has no evaluable CAdES signature — collect_signatures yields no
        // evaluable candidates and the document fails verification (the
        // pin is at the collection boundary the seal-side verdict reads).
        let mut doc = Document::with_version("1.4");
        let mut orphan = lopdf::Dictionary::new();
        orphan.set("Type", Object::Name(b"Sig".to_vec()));
        orphan.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
        orphan.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        orphan.set(
            "Contents",
            Object::String(vec![0xAB], lopdf::StringFormat::Hexadecimal),
        );
        doc.add_object(Object::Dictionary(orphan));
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        let found = collect_signatures(&doc).unwrap();
        assert!(
            found.is_empty(),
            "an orphan signature-shaped dict is never evaluated"
        );
    }

    #[test]
    fn partial_signature_shape_is_malformed_never_skipped() {
        // /ByteRange WITHOUT /Contents (or vice versa) is malformed input,
        // never a silent skip.
        let mut doc = Document::with_version("1.4");
        let mut d = lopdf::Dictionary::new();
        d.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        doc.add_object(Object::Dictionary(d));
        assert!(collect_signatures(&doc).is_err());
    }

    #[test]
    fn whitespace_padded_contents_verifies() {
        // PDF permits whitespace inside hex strings: a /Contents value
        // padded with spaces must verify, with the length check counting
        // only hex digits.
        let (bytes, signer) = crafted_sig_revision("ws-sig", true, true);
        let engine = verify_engine(vec![signer.cert_der], VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert!(
            report.valid,
            "whitespace-padded /Contents must verify: {report:?}"
        );
    }

    #[test]
    fn byte_range_hex_length_counts_digits_not_whitespace() {
        // Direct mutation probe on the gate: "<AB CD>" decodes to two
        // bytes; a one-byte /Contents claim must still FAIL (whitespace is
        // stripped, not counted as content).
        let bytes = b"xx<AB CD>yy";
        let ok = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB, 0xCD],
        };
        assert!(check_byte_range(bytes, &ok));
        let short = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB],
        };
        assert!(!check_byte_range(bytes, &short));
        let long = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB, 0xCD, 0xEF],
        };
        assert!(!check_byte_range(bytes, &long));
    }

    #[test]
    fn byte_range_rejects_oversized_decoded_contents() {
        // botfix7 P3: the post-whitespace-strip decoded /Contents count is
        // capped at the input size — a /Contents claim larger than the
        // document it lives inside is structurally impossible, and must
        // fail the gate before any hex-length comparison.
        let bytes = b"xx<AB CD>yy";
        let oversized = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0u8; bytes.len() + 1],
        };
        assert!(
            !check_byte_range(bytes, &oversized),
            "decoded /Contents past the input size must be rejected"
        );
        // Composition pin: the cap helper itself rejects decoded_len > input
        // (the hex-digit gate alone cannot observe an oversized claim when
        // it also fails the digit count, so the helper is probed directly).
        assert!(!decoded_contents_within_input(bytes.len() + 1, bytes.len()));
        assert!(decoded_contents_within_input(bytes.len(), bytes.len()));
    }

    // --- bot-fix leg 4 pins -------------------------------------------------

    /// Field-anchored reachability for the leg-3b orphan-scan pins: the
    /// added dictionaries stay reachable (the document keeps its catalog /
    /// AcroForm /Fields path) but the added dicts themselves are never
    /// named by any field `/V`, so they are never evaluated. Returns the
    /// document plus the id of every added (orphan) object.
    fn doc_with_orphans(dicts: Vec<lopdf::Dictionary>) -> (Document, Vec<lopdf::ObjectId>) {
        let mut doc = Document::with_version("1.4");
        let field_id = doc.add_object(Object::Dictionary(lopdf::Dictionary::new()));
        let mut af = lopdf::Dictionary::new();
        af.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
        let af_id = doc.add_object(Object::Dictionary(af));
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Reference(af_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        let ids = dicts
            .into_iter()
            .map(|d| doc.add_object(Object::Dictionary(d)))
            .collect();
        (doc, ids)
    }

    #[test]
    fn contents_without_byte_range_is_never_a_signature_candidate() {
        // P1-1: ordinary /Page dictionaries carry /Contents (the page
        // content stream) without /ByteRange — typeless candidacy requires
        // /ByteRange, so these must be IGNORED, never rejected as malformed
        // (leg 3b's XOR gate false-rejected every non-blank page). Neither
        // dictionary is a field /V: both are orphaned, hence unexamined.
        let mut page = lopdf::Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Contents", Object::Reference((42, 0)));
        let mut bare = lopdf::Dictionary::new();
        bare.set("Contents", Object::string_literal(b"BT ET".to_vec()));
        let (doc, _) = doc_with_orphans(vec![page, bare]);
        let found = collect_signatures(&doc).unwrap();
        assert!(found.is_empty(), "page /Contents is not a signature");
    }

    #[test]
    fn byte_range_without_contents_stays_malformed() {
        // P1-1 rejection pin: a /ByteRange dictionary with no /Contents is
        // a partial signature shape — malformed, never a silent skip. The
        // signature shape must be REACHABLE to be judged (botfix7 P1): it
        // rides a field /V, so the malformed gate binds it.
        let mut partial = lopdf::Dictionary::new();
        partial.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(partial));
        let mut field = lopdf::Dictionary::new();
        field.set("FT", Object::Name(b"Sig".to_vec()));
        field.set("V", Object::Reference(sig_id));
        let field_id = doc.add_object(Object::Dictionary(field));
        let mut af = lopdf::Dictionary::new();
        af.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
        let af_id = doc.add_object(Object::Dictionary(af));
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Reference(af_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        assert!(collect_signatures(&doc).is_err());
    }

    // --- bot-fix leg 8 pins: AcroForm field TREE ---------------------------

    /// A well-formed CAdES signature dictionary (typed, correct SubFilter,
    /// four-element /ByteRange, hex /Contents) for the field-tree rows.
    fn tree_sig_dict() -> lopdf::Dictionary {
        let mut d = lopdf::Dictionary::new();
        d.set("Type", Object::Name(b"Sig".to_vec()));
        d.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
        d.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        d.set(
            "Contents",
            Object::String(vec![0u8; 2], lopdf::StringFormat::Hexadecimal),
        );
        d
    }

    /// Wrap `fields` as the catalog's `/AcroForm /Fields` array.
    fn doc_with_fields(doc: &mut Document, fields: Vec<Object>) {
        let mut af = lopdf::Dictionary::new();
        af.set("Fields", Object::Array(fields));
        let af_id = doc.add_object(Object::Dictionary(af));
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Reference(af_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
    }

    #[test]
    fn nested_signature_field_with_inherited_ft_is_reachable() {
        // botfix8 F3 REGRESSION: the honest PAdES hierarchy — /Fields holds
        // a NON-TERMINAL field carrying /FT /Sig and /T, whose /Kids holds
        // the terminal field carrying only /V. /FT is inheritable
        // (ISO 32000 §12.7.3.2), so the terminal field IS a signature
        // field. botfix-7's flat walk read the top-level dict, saw no /V,
        // and dropped the signature — an honest document failing with "no
        // evaluable signature". verify_rs 0.6+ and pyHanko 0.35+ emit this.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        let mut terminal = lopdf::Dictionary::new();
        terminal.set("T", Object::string_literal("child".to_string()));
        terminal.set("V", Object::Reference(sig_id));
        let terminal_id = doc.add_object(Object::Dictionary(terminal));
        let mut parent = lopdf::Dictionary::new();
        parent.set("FT", Object::Name(b"Sig".to_vec()));
        parent.set("T", Object::string_literal("parent".to_string()));
        parent.set("Kids", Object::Array(vec![Object::Reference(terminal_id)]));
        let parent_id = doc.add_object(Object::Dictionary(parent));
        doc_with_fields(&mut doc, vec![Object::Reference(parent_id)]);
        let found = collect_signatures(&doc).expect("tree walk must succeed");
        assert_eq!(
            found.len(),
            1,
            "the nested signature field must be discovered through /Kids \
             with /FT inherited from the parent"
        );
        assert!(!found[0].is_doc_ts);
    }

    #[test]
    fn kids_cycle_terminates_without_hanging() {
        // A hostile /Kids self-cycle must not spin: the visited-set stops
        // re-descent, so discovery terminates. The reachable signature on
        // the cycle is still found exactly once.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        // Reserve the parent id so the child can point back at it.
        let parent_id = doc.add_object(Object::Null);
        let mut child = lopdf::Dictionary::new();
        child.set("V", Object::Reference(sig_id));
        // The child's /Kids points BACK at its parent: a 2-cycle.
        child.set("Kids", Object::Array(vec![Object::Reference(parent_id)]));
        let child_id = doc.add_object(Object::Dictionary(child));
        let mut parent = lopdf::Dictionary::new();
        parent.set("FT", Object::Name(b"Sig".to_vec()));
        parent.set("Kids", Object::Array(vec![Object::Reference(child_id)]));
        doc.objects
            .insert(parent_id, Object::Dictionary(parent.clone()));
        doc_with_fields(&mut doc, vec![Object::Reference(parent_id)]);
        let found = collect_signatures(&doc).expect("cycle must terminate, not hang");
        assert_eq!(found.len(), 1, "the signature is collected exactly once");
    }

    #[test]
    fn self_referential_kids_terminates() {
        // The degenerate case: a field whose /Kids names itself.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        let field_id = doc.add_object(Object::Null);
        let mut field = lopdf::Dictionary::new();
        field.set("FT", Object::Name(b"Sig".to_vec()));
        field.set("V", Object::Reference(sig_id));
        field.set("Kids", Object::Array(vec![Object::Reference(field_id)]));
        doc.objects.insert(field_id, Object::Dictionary(field));
        doc_with_fields(&mut doc, vec![Object::Reference(field_id)]);
        let found = collect_signatures(&doc).expect("self-cycle must terminate");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn non_signature_parent_does_not_inherit_sig_ft_to_kids() {
        // Inheritance carries the parent's ACTUAL /FT: a /Tx parent must not
        // make its kids signature fields, and a kid's own /FT overrides the
        // inherited one. Neither field here is a signature field, so the
        // signature-shaped /V of the text field is never evaluated — the
        // fail-closed posture botfix-7 established stays intact.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        let mut terminal = lopdf::Dictionary::new();
        terminal.set("V", Object::Reference(sig_id));
        let terminal_id = doc.add_object(Object::Dictionary(terminal));
        let mut parent = lopdf::Dictionary::new();
        parent.set("FT", Object::Name(b"Tx".to_vec()));
        parent.set("Kids", Object::Array(vec![Object::Reference(terminal_id)]));
        let parent_id = doc.add_object(Object::Dictionary(parent));
        doc_with_fields(&mut doc, vec![Object::Reference(parent_id)]);
        let found = collect_signatures(&doc).expect("walk succeeds");
        assert!(
            found.is_empty(),
            "a /Tx subtree yields no signature candidates"
        );

        // Same tree, but the terminal field overrides with its own /FT /Sig.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        let mut terminal = lopdf::Dictionary::new();
        terminal.set("FT", Object::Name(b"Sig".to_vec()));
        terminal.set("V", Object::Reference(sig_id));
        let terminal_id = doc.add_object(Object::Dictionary(terminal));
        let mut parent = lopdf::Dictionary::new();
        parent.set("FT", Object::Name(b"Tx".to_vec()));
        parent.set("Kids", Object::Array(vec![Object::Reference(terminal_id)]));
        let parent_id = doc.add_object(Object::Dictionary(parent));
        doc_with_fields(&mut doc, vec![Object::Reference(parent_id)]);
        assert_eq!(
            collect_signatures(&doc).expect("walk succeeds").len(),
            1,
            "a kid's own /FT overrides the inherited one"
        );
    }

    #[test]
    fn terminal_field_with_widget_kids_is_still_evaluated() {
        // This crate's own writer emits `/FT /Sig /T .. /V n 0 R /Kids
        // [widget]` (pdf.rs build_objects): a TERMINAL field whose /Kids
        // holds widget annotations, not child fields. Descent must not
        // consume the node's own /V — /Kids and /V are not exclusive.
        let mut doc = Document::with_version("1.4");
        let sig_id = doc.add_object(Object::Dictionary(tree_sig_dict()));
        let mut widget = lopdf::Dictionary::new();
        widget.set("Type", Object::Name(b"Annot".to_vec()));
        widget.set("Subtype", Object::Name(b"Widget".to_vec()));
        let widget_id = doc.add_object(Object::Dictionary(widget));
        let mut field = lopdf::Dictionary::new();
        field.set("FT", Object::Name(b"Sig".to_vec()));
        field.set("V", Object::Reference(sig_id));
        field.set("Kids", Object::Array(vec![Object::Reference(widget_id)]));
        let field_id = doc.add_object(Object::Dictionary(field));
        doc_with_fields(&mut doc, vec![Object::Reference(field_id)]);
        assert_eq!(
            collect_signatures(&doc).expect("walk succeeds").len(),
            1,
            "a terminal field with widget /Kids keeps its own /V evaluated"
        );
    }

    #[test]
    fn subfilter_dispatch_is_fail_closed() {
        // A candidate is evaluated ONLY under the handler its /SubFilter
        // names; absent/foreign SubFilter on a typed dict is skipped, never
        // evaluated as CAdES.
        fn doc_with(type_name: Option<&[u8]>, subfilter: Option<&[u8]>) -> Document {
            // Each dictionary rides a field /V so every row REACHES the
            // dispatch (botfix7 P1); /SubFilter discriminates with the
            // signature shape already satisfied.
            let mut doc = Document::with_version("1.4");
            let mut d = lopdf::Dictionary::new();
            if let Some(t) = type_name {
                d.set("Type", Object::Name(t.to_vec()));
            }
            if let Some(sf) = subfilter {
                d.set("SubFilter", Object::Name(sf.to_vec()));
            }
            d.set(
                "ByteRange",
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(1),
                    Object::Integer(2),
                    Object::Integer(3),
                ]),
            );
            d.set(
                "Contents",
                Object::String(vec![0u8; 2], lopdf::StringFormat::Hexadecimal),
            );
            let sig_id = doc.add_object(Object::Dictionary(d));
            let mut field = lopdf::Dictionary::new();
            field.set("FT", Object::Name(b"Sig".to_vec()));
            field.set("V", Object::Reference(sig_id));
            let field_id = doc.add_object(Object::Dictionary(field));
            let mut af = lopdf::Dictionary::new();
            af.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
            let af_id = doc.add_object(Object::Dictionary(af));
            let mut pages = lopdf::Dictionary::new();
            pages.set("Type", Object::Name(b"Pages".to_vec()));
            pages.set("Kids", Object::Array(vec![]));
            pages.set("Count", Object::Integer(0));
            let pages_id = doc.add_object(Object::Dictionary(pages));
            let mut catalog = lopdf::Dictionary::new();
            catalog.set("Type", Object::Name(b"Catalog".to_vec()));
            catalog.set("Pages", Object::Reference(pages_id));
            catalog.set("AcroForm", Object::Reference(af_id));
            let cat_id = doc.add_object(Object::Dictionary(catalog));
            doc.trailer.set("Root", Object::Reference(cat_id));
            doc
        }
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let rfc3161: &[u8] = b"ETSI.RFC3161";
        // The finding's shape: /Sig with /adbe.pkcs7.detached is NOT CAdES.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), Some(b"adbe.pkcs7.detached")))
                .unwrap()
                .is_empty()
        );
        // Typed dicts with ABSENT SubFilter are skipped too.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), None))
                .unwrap()
                .is_empty()
        );
        assert!(
            collect_signatures(&doc_with(Some(b"DocTimeStamp"), None))
                .unwrap()
                .is_empty()
        );
        // Wrong handler for the type: an RFC3161-subfiltered /Sig and a
        // CAdES-subfiltered DocTimeStamp are both skipped.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), Some(rfc3161)))
                .unwrap()
                .is_empty()
        );
        assert!(
            collect_signatures(&doc_with(Some(b"DocTimeStamp"), Some(cades)))
                .unwrap()
                .is_empty()
        );
        // Correct handler per type is collected.
        let found = collect_signatures(&doc_with(Some(b"Sig"), Some(cades))).unwrap();
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_doc_ts);
        let found = collect_signatures(&doc_with(Some(b"DocTimeStamp"), Some(rfc3161))).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_doc_ts);
        // Typeless interop: absent SubFilter tolerated, foreign one skipped.
        let found = collect_signatures(&doc_with(None, None)).unwrap();
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_doc_ts);
        assert!(
            collect_signatures(&doc_with(None, Some(b"adbe.pkcs7.detached")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn present_unrecognized_type_is_never_a_candidate() {
        // The typeless interop allowance applies only when /Type is ABSENT:
        // a present-but-unrecognized (or malformed) /Type on a
        // /ByteRange + /Contents dictionary is skipped, never evaluated as
        // CAdES through the typeless path.
        fn doc_with_type_obj(type_obj: Option<Object>, subfilter: Option<&[u8]>) -> Document {
            // Each dictionary rides a field /V so the row reaches the /Type
            // dispatch (botfix7 P1).
            let mut doc = Document::with_version("1.4");
            let mut d = lopdf::Dictionary::new();
            if let Some(t) = type_obj {
                d.set("Type", t);
            }
            if let Some(sf) = subfilter {
                d.set("SubFilter", Object::Name(sf.to_vec()));
            }
            d.set(
                "ByteRange",
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(1),
                    Object::Integer(2),
                    Object::Integer(3),
                ]),
            );
            d.set(
                "Contents",
                Object::String(vec![0u8; 2], lopdf::StringFormat::Hexadecimal),
            );
            let sig_id = doc.add_object(Object::Dictionary(d));
            let mut field = lopdf::Dictionary::new();
            field.set("FT", Object::Name(b"Sig".to_vec()));
            field.set("V", Object::Reference(sig_id));
            let field_id = doc.add_object(Object::Dictionary(field));
            let mut af = lopdf::Dictionary::new();
            af.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
            let af_id = doc.add_object(Object::Dictionary(af));
            let mut pages = lopdf::Dictionary::new();
            pages.set("Type", Object::Name(b"Pages".to_vec()));
            pages.set("Kids", Object::Array(vec![]));
            pages.set("Count", Object::Integer(0));
            let pages_id = doc.add_object(Object::Dictionary(pages));
            let mut catalog = lopdf::Dictionary::new();
            catalog.set("Type", Object::Name(b"Catalog".to_vec()));
            catalog.set("Pages", Object::Reference(pages_id));
            catalog.set("AcroForm", Object::Reference(af_id));
            let cat_id = doc.add_object(Object::Dictionary(catalog));
            doc.trailer.set("Root", Object::Reference(cat_id));
            doc
        }
        // /Type /Foo with the interop shape (absent SubFilter): skipped.
        assert!(
            collect_signatures(&doc_with_type_obj(
                Some(Object::Name(b"Foo".to_vec())),
                None
            ))
            .unwrap()
            .is_empty(),
            "present-but-unrecognized /Type must not ride the typeless path"
        );
        // /Type /Foo even with the CAdES SubFilter named: not a handler's
        // type, still skipped.
        assert!(
            collect_signatures(&doc_with_type_obj(
                Some(Object::Name(b"Foo".to_vec())),
                Some(b"ETSI.CAdES.detached")
            ))
            .unwrap()
            .is_empty()
        );
        // Malformed /Type (not a name object): skipped, never candidacy.
        assert!(
            collect_signatures(&doc_with_type_obj(Some(Object::Integer(1)), None))
                .unwrap()
                .is_empty(),
            "malformed /Type must not ride the typeless path"
        );
        // Control: the ABSENT-/Type interop row still collects.
        let found = collect_signatures(&doc_with_type_obj(None, None)).unwrap();
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_doc_ts);
    }

    /// A chain of `hops` reference-linked objects ending in a terminal
    /// dictionary; returns the document and the chain's head id.
    fn reference_chain_doc(hops: usize) -> (Document, lopdf::ObjectId) {
        assert!(hops >= 1);
        let mut doc = Document::with_version("1.4");
        let terminal = doc.add_object(Object::Dictionary(lopdf::Dictionary::new()));
        let mut head = terminal;
        for _ in 1..hops {
            head = doc.add_object(Object::Reference(head));
        }
        (doc, head)
    }

    #[test]
    fn reference_chain_repetition_stays_bounded_by_unique_set() {
        // P1-2: N repetitions of one deep chain (one per DSS array
        // occurrence) must collapse into the chain's UNIQUE object set —
        // the id collection can never expand to 128*N.
        let (doc, head) = reference_chain_doc(128);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        for _ in 0..128 {
            collect_reference_chain(&doc, head, &mut ids, &mut work).unwrap();
        }
        assert_eq!(ids.len(), 128, "only unique objects are collected");
        assert_eq!(work, 128 * 128, "work counts hops across all chains");
        // The global budget fails closed past the cap: the 129th full
        // traversal would exceed MAX_REFERENCE_WORK.
        assert!(collect_reference_chain(&doc, head, &mut ids, &mut work).is_none());
    }

    #[test]
    fn reference_chain_cycle_and_over_limit_stay_fail_closed() {
        // P1-2: a reference cycle fails closed (the per-chain 128-hop bound
        // is kept), as does a 129-hop chain; a 128-hop chain still
        // resolves (the bound mirrors lopdf's dereference limit).
        let mut doc = Document::with_version("1.4");
        let a = doc.add_object(Object::Null);
        let b = doc.add_object(Object::Null);
        doc.objects.insert(a, Object::Reference(b));
        doc.objects.insert(b, Object::Reference(a));
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, a, &mut ids, &mut work).is_none());

        let (doc, head_129) = reference_chain_doc(129);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, head_129, &mut ids, &mut work).is_none());

        let (doc, head_128) = reference_chain_doc(128);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, head_128, &mut ids, &mut work).is_some());
        assert_eq!(ids.len(), 128);
    }

    #[test]
    fn dss_decode_budget_is_cumulative_across_entries() {
        // P1-3: two FlateDecode DSS streams each individually under the cap
        // but cumulatively over it must fail ValidationMaterial — the
        // budget is ONE shared remaining across every DSS entry, not a
        // per-stream allowance.
        let ca = test_ca("budget-dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), zlib_store(&crl));
        let covered = covered_of(&[&ca.cert_der]);
        let total = ca.cert_der.len() + crl.len();
        // Control: a budget covering both entries validates (the streams
        // are individually and cumulatively fine).
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, AT_UNIX, total, &mut checks);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "cumulative-fitting evidence must validate"
        );
        // One byte short cumulatively: the /Certs entry still decodes (it
        // fits the full cap alone), but the shared remainder is one byte
        // too small for the FlateDecode-wrapped CRL — the material fails
        // WITHOUT decoding beyond the shared limit. The pre-fix per-stream
        // cap decoded both and validated.
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, AT_UNIX, total - 1, &mut checks);
        assert_material_fails(&checks);
    }
}
