"""Exact source spans of parsed signature dictionary values (pinned pyHanko)."""
from dataclasses import dataclass
from enum import Enum
from io import BytesIO


class EnvelopeKind(str, Enum):
    SIGNATURE = "Signature"
    DOCUMENT_TIMESTAMP = "DocumentTimestamp"

    @classmethod
    def from_pdf_type(cls, value):
        if str(value) == "/Sig":
            return cls.SIGNATURE
        if str(value) == "/DocTimeStamp":
            return cls.DOCUMENT_TIMESTAMP
        raise ValueError(f"unsupported envelope kind: {value}")


@dataclass(frozen=True)
class SourceSpan:
    start: int
    end: int


@dataclass(frozen=True)
class SignatureSource:
    object_number: int
    generation: int
    revision: int
    revision_end: int
    byte_range: tuple[int, ...]
    contents: bytes
    contents_span: SourceSpan | None
    source_reason: str | None
    revision_startxref: int
    revision_xref_end: int
    kind: EnvelopeKind

    @property
    def identity(self):
        return {"object_number": self.object_number, "generation": self.generation,
                "revision": self.revision, "kind": self.kind.value}


def _direct_contents_span(stream, ref, offset, revision_end, expected_contents):
    """Record parser positions for the xref-selected object's direct value.

    NameObject/read_object own PDF grammar here: comments, name escapes,
    strings, references, arrays and nested dictionaries are not scanned anew.
    """
    from pyhanko.pdf_utils.generic import NameObject, ByteStringObject, read_object
    from pyhanko.pdf_utils.misc import read_non_whitespace
    from pyhanko.pdf_utils.xref import read_object_header

    if not isinstance(offset, int) or not 0 <= offset < revision_end:
        return None, "signature object has no direct source offset"
    stream.seek(offset)
    try:
        if read_object_header(stream, strict=True) != (ref.idnum, ref.generation):
            return None, "xref signature object header differs"
        read_non_whitespace(stream, seek_back=True)
        if stream.read(2) != b"<<":
            return None, "signature source is not a direct dictionary"
        found = []
        while True:
            read_non_whitespace(stream, seek_back=True)
            if stream.read(2) == b">>":
                break
            stream.seek(-2, 1)
            key = NameObject.read_from_stream(stream)
            read_non_whitespace(stream, seek_back=True)
            start = stream.tell()
            value = read_object(stream, ref)
            end = stream.tell()
            if key == "/Contents":
                found.append((SourceSpan(start, end), value))
            if end >= revision_end:
                return None, "signature dictionary exceeds signed revision"
        read_non_whitespace(stream, seek_back=True)
        if stream.read(6) != b"endobj" or len(found) != 1:
            return None, "signature source has no unique direct contents"
        span, value = found[0]
        if not isinstance(value, ByteStringObject) or bytes(value) != expected_contents:
            return None, "xref signature contents differ from parsed envelope"
        stream.seek(span.start)
        if (not isinstance(value, ByteStringObject) or span.end > revision_end
                or stream.read(1) != b"<"):
            return None, "signature contents are not direct hex"
        stream.seek(span.end - 1)
        if stream.read(1) != b">":
            return None, "signature contents hex span not established"
        return span, None
    except (ValueError, TypeError, IndexError, KeyError, OSError, EOFError) as exc:
        return None, f"signature source parse failed: {type(exc).__name__}"
    except Exception as exc:
        # An unsupported parser representation cannot become coverage evidence.
        return None, f"signature source parse failed: {type(exc).__name__}"


def signature_sources(data: bytes) -> list[SignatureSource]:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.generic import ByteStringObject

    stream = BytesIO(data)
    reader = PdfFileReader(stream, strict=True)
    sources = []
    for signature in reader.embedded_signatures:
        ref = signature.sig_object.container_ref
        if ref is None:
            continue
        revision = signature.signed_revision
        byte_range = tuple(map(int, signature.byte_range))
        revision_end = byte_range[2] + byte_range[3] if len(byte_range) == 4 else 0
        offset = reader.xrefs.get_historical_ref(ref, revision)
        value = signature.sig_object.raw_get("/Contents")
        span, reason = _direct_contents_span(
            stream, ref, offset, revision_end,
            bytes(value) if isinstance(value, ByteStringObject) else b"",
        )
        if not isinstance(value, ByteStringObject):
            span, reason = None, "signature contents are not direct bytes"
        sources.append(SignatureSource(
            ref.idnum, ref.generation, revision, revision_end, byte_range,
            bytes(value) if isinstance(value, ByteStringObject) else b"",
            span, reason, reader.xrefs.get_startxref_for_revision(revision),
            reader.xrefs.get_xref_container_info(revision).end_location,
            EnvelopeKind.from_pdf_type(signature.sig_object_type),
        ))
    return sources
