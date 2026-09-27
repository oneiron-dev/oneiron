#!/usr/bin/env python3
"""PDFium signature-object parse with separate, source-backed coverage evidence.

No CMS cryptography, later-change policy or certificate trust check is performed.
"""
import ctypes
import importlib.metadata
import json
import sys

from pdf_source import signature_sources
from reader_result import Established, NotEstablished, Rejected, evaluate_coverage


def emit(version, status, detail, code, **extra):
    print(json.dumps({"reader": "pdfium", "version": version, "mode": "parse",
                      "status": status, "detail": detail, **extra}))
    return code


def pdfium_contents(raw, sig, file_length):
    size = raw.FPDFSignatureObj_GetContents(sig, None, 0)
    if not 0 < size <= file_length:
        return None
    buf = (ctypes.c_ubyte * size)()
    if raw.FPDFSignatureObj_GetContents(sig, buf, size) != size:
        return None
    return bytes(buf)


def pdfium_range(raw, sig):
    values = (ctypes.c_int * 4)()
    length = raw.FPDFSignatureObj_GetByteRange(sig, values, 4)
    # Some generated ctypes bindings return void; the filled array is the ABI.
    if isinstance(length, int) and length not in (0, 4):
        return None
    return tuple(map(int, values))


def prefix_contains_range(pdfium, raw, data, byte_range):
    end = byte_range[2] + byte_range[3]
    try:
        prefix = pdfium.PdfDocument(data[:end])
        try:
            for index in range(int(raw.FPDF_GetSignatureCount(prefix.raw))):
                obj = raw.FPDF_GetSignatureObject(prefix.raw, index)
                if obj and pdfium_range(raw, obj) == byte_range:
                    return True
        finally:
            prefix.close()
    except Exception:
        return False
    return False


def main(path):
    try:
        import pypdfium2 as pdfium
    except ModuleNotFoundError as exc:
        return emit("unavailable", "unavailable", str(exc), 77)
    version = importlib.metadata.version("pypdfium2")
    raw = pdfium.raw
    required = ("FPDF_GetSignatureCount", "FPDF_GetSignatureObject",
                "FPDFSignatureObj_GetByteRange", "FPDFSignatureObj_GetContents")
    missing = [name for name in required if not hasattr(raw, name)]
    if missing:
        return emit(version, "unavailable", "signature API unavailable: " + ", ".join(missing), 77)
    try:
        with open(path, "rb") as stream:
            data = stream.read()
        document = pdfium.PdfDocument(path)
        try:
            count = int(raw.FPDF_GetSignatureCount(document.raw))
            if count < 1:
                return emit(version, "fail", "PDFium found no signature objects", 1)
            source_error = None
            try:
                sources = signature_sources(data)
            except Exception as exc:
                sources = []
                source_error = f"source parser unavailable: {type(exc).__name__}: {exc}"
            outcomes = []
            for index in range(count):
                sig = raw.FPDF_GetSignatureObject(document.raw, index)
                if not sig:
                    outcome = Rejected("PDFium signature object cannot be read")
                else:
                    byte_range = pdfium_range(raw, sig)
                    if byte_range is None:
                        outcome = NotEstablished("PDFium ByteRange API unavailable")
                    else:
                        contents = pdfium_contents(raw, sig, len(data))
                        candidates = [source for source in sources
                                      if source.byte_range == byte_range
                                      and source.contents == contents]
                        source = candidates[0] if len(candidates) == 1 else None
                        outcome = evaluate_coverage(source, byte_range, contents, data)
                        if isinstance(outcome, Established) and not prefix_contains_range(
                                pdfium, raw, data, byte_range):
                            outcome = Rejected("PDFium cannot parse the signed revision")
                        if isinstance(outcome, NotEstablished) and source_error:
                            outcome = NotEstablished(source_error)
                outcomes.append({"index": index + 1, "coverage": outcome.to_json()})
            if any(item["coverage"]["state"] == "rejected" for item in outcomes):
                status, code = "fail", 1
            elif any(item["coverage"]["state"] == "not_established" for item in outcomes):
                status, code = "unavailable", 77
            else:
                status, code = "pass", 0
            established = [item["coverage"]["evidence"] for item in outcomes
                           if item["coverage"]["state"] == "established"]
            coverage_outcome = ("established" if status == "pass" else
                                "rejected" if status == "fail" else "not_established")
            final_coverage = (str(any(item["final_document_coverage"] for item in established))
                              .lower() if status == "pass" else "not_established")
            detail = (f"pages={len(document)}; signature_objects={count}; signatures={count}; "
                      f"signed_revision_coverage={coverage_outcome}; "
                      f"final_document_coverage={final_coverage}; "
                      "source_provider=pyhanko; later revisions are not a permitted-change "
                      "assessment; no CMS cryptography or certificate trust check")
            return emit(version, status, detail, code, coverage_outcome=coverage_outcome,
                        signature_results=outcomes, source_provider="pyhanko-source")
        finally:
            document.close()
    except Exception as exc:
        return emit(version, "fail", f"{type(exc).__name__}: {exc}", 1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: seal-pdfium PDF", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
