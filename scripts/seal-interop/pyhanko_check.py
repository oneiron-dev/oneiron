#!/usr/bin/env python3
"""Pinned pyHanko signature checker wrapper; JSON contract for oracle tests."""
import importlib.metadata, json, sys
from reader_result import EnvelopeKind

def main(path):
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import ValidationContext, validate_pdf_signature, validate_pdf_timestamp
        from pyhanko.sign.validation.settings import KeyUsageConstraints
        version = importlib.metadata.version("pyhanko")
        with open(path, "rb") as f:
            reader = PdfFileReader(f, strict=True)
            sigs = reader.embedded_signatures
            if not sigs:
                result = {"reader":"pyhanko", "version":version, "mode":"verify", "status":"fail", "detail":"no embedded signature"}
                print(json.dumps(result)); return 1
            outcomes = []
            ku = KeyUsageConstraints(key_usage=set(), extd_key_usage=None)
            for index, sig in enumerate(sigs, 1):
                kind_name = str(sig.sig_object_type)
                try:
                    kind = EnvelopeKind.from_pdf_type(kind_name)
                    cms_certs = list(sig.signed_data["certificates"])
                    roots = [c.chosen for c in cms_certs if c.name == "certificate"] or [sig.signer_cert]
                    vc = ValidationContext(trust_roots=roots, allow_fetching=False)
                    if kind is EnvelopeKind.SIGNATURE:
                        status = validate_pdf_signature(sig, signer_validation_context=vc,
                                                        key_usage_settings=ku)
                        valid = bool(status.bottom_line)
                    elif kind is EnvelopeKind.DOCUMENT_TIMESTAMP:
                        status = validate_pdf_timestamp(sig, validation_context=vc)
                        valid = bool(status.valid and status.intact and status.trusted)
                    outcomes.append({"index": index, "kind": kind.value,
                                     "valid": valid, "cryptographic_valid": bool(status.valid),
                                     "intact": bool(status.intact), "trusted": bool(status.trusted)})
                except Exception as exc:
                    outcomes.append({"index": index, "kind": kind_name, "valid": False,
                                     "error": f"{type(exc).__name__}: {exc}"})
            valid = all(item["valid"] for item in outcomes)
            result = {"reader":"pyhanko", "version":version, "mode":"verify", "status":"pass" if valid else "fail",
                      "signatures_checked": len(outcomes), "signature_results": outcomes,
                      "detail":f"signatures_checked={len(outcomes)}; signature_valid={valid}; trust override: embedded CMS signer certificate is treated as a local anchor; no production trust claim"}
            print(json.dumps(result)); return 0 if valid else 1
    except ModuleNotFoundError as e:
        print(json.dumps({"reader":"pyhanko","version":"unavailable","mode":"verify","status":"unavailable","detail":str(e)})); return 77
    except Exception as e:
        print(json.dumps({"reader":"pyhanko","version":safe_version(),"mode":"verify","status":"fail","detail":f"{type(e).__name__}: {e}"})); return 1

def safe_version():
    try: return importlib.metadata.version("pyhanko")
    except Exception: return "unknown"

if __name__ == "__main__":
    if len(sys.argv) != 2: print("usage: seal-pyhanko PDF", file=sys.stderr); raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
