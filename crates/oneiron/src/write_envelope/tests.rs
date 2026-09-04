//! ONE-1314 · the source-lineage axis on the write envelope.
//!
//! What is pinned here is the TYPE and its identity law: lineage is a set, the
//! auto-permit question is a fail-closed OR over it, and a 4-arity envelope is
//! byte-for-byte the envelope that existed before the axis did.

use super::*;

fn actor() -> WriteActor {
    WriteActor::new(
        EntityId::from_bytes([0x31; 16]).expect("actor id"),
        EdgeActorClass::Agent,
    )
}

fn provenance() -> WriteProvenance {
    WriteProvenance::new(Value::from("one-1314-test")).expect("provenance")
}

const ALL_SOURCES: [ClaimSource; 6] = [
    ClaimSource::UserStated,
    ClaimSource::Observed,
    ClaimSource::Inferred,
    ClaimSource::Imported,
    ClaimSource::ToolOutput,
    ClaimSource::Generated,
];

#[test]
fn source_lineage_is_a_set_of_claim_sources() {
    let lineage = SourceLineage::of(ClaimSource::Generated)
        .with(ClaimSource::ToolOutput)
        .with(ClaimSource::Generated);

    assert!(lineage.contains(ClaimSource::Generated));
    assert!(lineage.contains(ClaimSource::ToolOutput));
    assert!(!lineage.contains(ClaimSource::UserStated));

    // Set semantics: re-adding a member changes nothing, and membership is
    // order-independent, so the same history always compares equal.
    assert_eq!(lineage.iter().count(), 2);
    assert_eq!(
        lineage,
        SourceLineage::of(ClaimSource::ToolOutput).with(ClaimSource::Generated)
    );
    assert_eq!(
        SourceLineage::of(ClaimSource::Generated).with(ClaimSource::Generated),
        SourceLineage::of(ClaimSource::Generated)
    );
}

#[test]
fn source_lineage_requires_explicit_auto_permit_is_a_fail_closed_or() {
    for source in ALL_SOURCES {
        assert_eq!(
            SourceLineage::of(source).requires_explicit_auto_permit(),
            source.requires_explicit_auto_permit(),
            "a one-member lineage answers exactly what its member answers ({source:?})"
        );
    }

    // ANY member that requires an explicit permit carries the whole set: a
    // clean member can never vouch for a tainted one.
    assert!(!SourceLineage::of(ClaimSource::UserStated).requires_explicit_auto_permit());
    assert!(
        SourceLineage::of(ClaimSource::UserStated)
            .with(ClaimSource::ToolOutput)
            .requires_explicit_auto_permit()
    );
    assert!(
        SourceLineage::of(ClaimSource::Generated)
            .with(ClaimSource::UserStated)
            .requires_explicit_auto_permit()
    );
}

#[test]
fn four_arity_constructors_produce_trivial_lineage() {
    for source in ALL_SOURCES {
        let envelope =
            WriteEnvelope::new(actor(), source, provenance(), ClaimApprovalStatus::Proposed);
        assert_eq!(envelope.lineage(), &SourceLineage::of(source));

        let via_try_new = WriteEnvelope::try_new(
            Some(actor()),
            Some(source),
            Some(provenance()),
            Some(ClaimApprovalStatus::Proposed),
        )
        .expect("try_new envelope");
        assert_eq!(via_try_new.lineage(), &SourceLineage::of(source));
        assert_eq!(envelope, via_try_new);
    }
}

#[test]
fn effective_auto_permit_is_declared_or_lineage() {
    // Declared axis alone, trivial lineage: exactly the pre-lineage answer.
    for source in ALL_SOURCES {
        let envelope = WriteEnvelope::new(actor(), source, provenance(), ClaimApprovalStatus::Auto);
        assert_eq!(
            envelope.effective_requires_explicit_auto_permit(),
            source.requires_explicit_auto_permit(),
            "trivial lineage cannot move the declared verdict ({source:?})"
        );
    }

    // The whole point of the ticket: a clean DECLARATION over a tool-output
    // history still requires the explicit permit.
    let restamped = WriteEnvelope::with_lineage(
        actor(),
        ClaimSource::UserStated,
        provenance(),
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::UserStated).with(ClaimSource::ToolOutput),
    );
    assert!(!ClaimSource::UserStated.requires_explicit_auto_permit());
    assert!(restamped.effective_requires_explicit_auto_permit());
}

#[test]
fn trivial_lineage_stamps_byte_identical_evidence() {
    let candidate_evidence = Value::Map(vec![(Value::from("note"), Value::from("kept"))]);
    for source in ALL_SOURCES {
        let envelope =
            WriteEnvelope::new(actor(), source, provenance(), ClaimApprovalStatus::Proposed);
        let with_trivial_lineage = WriteEnvelope::with_lineage(
            actor(),
            source,
            provenance(),
            ClaimApprovalStatus::Proposed,
            SourceLineage::of(source),
        );

        for candidate in [None, Some(candidate_evidence.clone())] {
            let evidence = write_envelope_evidence(&envelope, candidate.clone());
            assert_eq!(
                evidence,
                write_envelope_evidence(&with_trivial_lineage, candidate),
                "the trivial constructor and the explicit trivial lineage agree ({source:?})"
            );
            let Value::Map(entries) = evidence else {
                panic!("expected evidence map");
            };
            assert!(
                !entries
                    .iter()
                    .any(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY)),
                "a trivial lineage adds NO evidence key ({source:?})"
            );
        }
    }
}

#[test]
fn non_trivial_lineage_stamps_one_additive_evidence_entry() {
    let envelope = WriteEnvelope::with_lineage(
        actor(),
        ClaimSource::Generated,
        provenance(),
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(ClaimSource::ToolOutput),
    );
    let trivial = WriteEnvelope::new(
        actor(),
        ClaimSource::Generated,
        provenance(),
        ClaimApprovalStatus::Proposed,
    );

    let Value::Map(entries) = write_envelope_evidence(&envelope, None) else {
        panic!("expected evidence map");
    };
    let Value::Map(trivial_entries) = write_envelope_evidence(&trivial, None) else {
        panic!("expected evidence map");
    };

    // Additive: every pre-existing entry survives unchanged, in order.
    assert_eq!(entries.len(), trivial_entries.len() + 1);
    for (existing, added) in trivial_entries.iter().zip(entries.iter()) {
        assert_eq!(existing, added);
    }

    let lineage = entries
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY)).then_some(value)
        })
        .expect("lineage evidence entry");
    let Value::Array(members) = lineage else {
        panic!("expected lineage array");
    };
    let members: Vec<&str> = members.iter().filter_map(rmpv::Value::as_str).collect();
    assert!(members.contains(&ClaimSource::Generated.as_str()));
    assert!(members.contains(&ClaimSource::ToolOutput.as_str()));
    assert_eq!(members.len(), 2);
}

/// `lineage_tamper_rejected`, API-surface arm: there is no public path that
/// accepts a lineage value.
///
/// This is a COMPILE-SURFACE test. `with_lineage` is `pub(crate)`, so a
/// downstream caller cannot name it at all; inside the crate the only other
/// constructors are the 4-arity pair, which take no lineage argument and can
/// only produce the trivial value. The body below is the exhaustive list of
/// ways an envelope can be built, and every one of them is checked to yield a
/// lineage the caller did not choose.
#[test]
fn no_caller_supplied_lineage_reaches_a_public_constructor() {
    let built = WriteEnvelope::new(
        actor(),
        ClaimSource::UserStated,
        provenance(),
        ClaimApprovalStatus::Auto,
    );
    let attempted = WriteEnvelope::try_new(
        Some(actor()),
        Some(ClaimSource::UserStated),
        Some(provenance()),
        Some(ClaimApprovalStatus::Auto),
    )
    .expect("try_new envelope");
    let tagged = WriteEnvelope::new(
        actor(),
        ClaimSource::UserStated,
        provenance(),
        ClaimApprovalStatus::Auto,
    )
    .with_session_tag("session-1314");

    for envelope in [built, attempted, tagged] {
        assert_eq!(
            envelope.lineage(),
            &SourceLineage::of(ClaimSource::UserStated),
            "a public constructor can only mint the trivial lineage"
        );
    }
}

#[test]
fn session_tag_is_untouched_by_the_lineage_axis() {
    let envelope = WriteEnvelope::with_lineage(
        actor(),
        ClaimSource::Generated,
        provenance(),
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(ClaimSource::ToolOutput),
    )
    .with_session_tag("session-1314");

    assert_eq!(envelope.session_tag.as_deref(), Some("session-1314"));
    assert!(envelope.lineage().contains(ClaimSource::ToolOutput));
}
