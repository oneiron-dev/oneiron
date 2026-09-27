"""Evidence-bearing, three-way coverage outcomes for the seal reader harness."""
from dataclasses import dataclass, asdict
from io import BytesIO
from typing import Union

from pdf_source import EnvelopeKind, SignatureSource, SourceSpan


@dataclass(frozen=True)
class CoverageEvidence:
    source: SignatureSource
    gap: SourceSpan
    signed_revision_end: int
    final_file_length: int
    observed_contents: bytes
    parsed_startxref: int

    def __post_init__(self):
        a, b, c, d = self.source.byte_range
        if (a != 0 or b <= 0 or c <= b or d <= 0
                or self.source.contents_span != self.gap
                or self.gap != SourceSpan(b, c)
                or c + d != self.signed_revision_end
                or self.signed_revision_end > self.final_file_length
                or self.observed_contents != self.source.contents
                or self.parsed_startxref != self.source.revision_startxref
                or self.source.revision_xref_end > self.signed_revision_end):
            raise ValueError("coverage evidence has no exact signed contents span")

    def to_json(self):
        return {"source": self.source.identity, "source_provider": "pyhanko-source",
                "gap": asdict(self.gap), "signed_revision_end": self.signed_revision_end,
                "final_file_length": self.final_file_length,
                "final_document_coverage": self.signed_revision_end == self.final_file_length}


@dataclass(frozen=True)
class Established:
    evidence: CoverageEvidence
    state: str = "established"

    def to_json(self):
        return {"state": self.state, "evidence": self.evidence.to_json()}


@dataclass(frozen=True)
class Rejected:
    reason: str
    state: str = "rejected"

    def to_json(self):
        return {"state": self.state, "reason": self.reason}


@dataclass(frozen=True)
class NotEstablished:
    reason: str
    state: str = "not_established"

    def to_json(self):
        return {"state": self.state, "reason": self.reason}


CoverageResult = Union[Established, Rejected, NotEstablished]


def evaluate_coverage(source: SignatureSource | None, observed_range: tuple[int, ...],
                      observed_contents: bytes | None, pdf: bytes) -> CoverageResult:
    if len(observed_range) != 4:
        return Rejected("signature ByteRange has no four spans")
    a, b, c, d = observed_range
    end = c + d
    if a != 0 or b <= 0 or c <= b or d <= 0 or end > len(pdf):
        return Rejected("signature ByteRange has empty, unordered or out-of-file spans")
    if source is None:
        return NotEstablished("no uniquely matching parsed signature source")
    if source.byte_range != observed_range or source.contents != observed_contents:
        return NotEstablished("PDFium and source parser disagree on signature")
    if source.contents_span is None:
        return NotEstablished(source.source_reason or "signature contents source span unavailable")
    if source.contents_span != SourceSpan(b, c):
        return Rejected("ByteRange gap does not exclude this signature's contents value")
    if end != source.revision_end or source.revision_xref_end > end:
        return Rejected("ByteRange ends before the parsed signed revision")
    # pyHanko's xref cache identifies the revision. Its EOF parser checks that
    # this endpoint actually closes that revision rather than just a prefix.
    from pyhanko.pdf_utils.reader import process_data_at_eof
    if not pdf[:end].rstrip(b"\x00\t\n\f\r ").endswith(b"%%EOF"):
        return Rejected("signed revision does not end at PDF EOF")
    try:
        prefix = BytesIO(pdf[:end])
        prefix.seek(end - 1)
        parsed_startxref = process_data_at_eof(prefix)
    except Exception:
        return NotEstablished("signed revision boundary could not be parsed")
    if parsed_startxref != source.revision_startxref:
        return Rejected("signed revision does not end at its parsed xref")
    try:
        evidence = CoverageEvidence(source, source.contents_span, end, len(pdf),
                                    observed_contents or b"", parsed_startxref)
    except ValueError as exc:
        return Rejected(str(exc))
    return Established(evidence)
