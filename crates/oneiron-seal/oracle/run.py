#!/usr/bin/env python3
"""CI-only pyHanko differential oracle for oneiron-seal.

Usage: run.py validate <sealed.pdf>

Prints one normalized JSON line: {"valid": bool, "validator": "pyhanko",
"version": "<pyhanko version>"}. No credential references, no fetch URLs,
no sealed bytes are written anywhere.
"""

import json
import sys


def validate(path: str) -> dict:
    from pyhanko import __version__
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.validation.settings import KeyUsageConstraints

    with open(path, "rb") as fh:
        reader = PdfFileReader(fh, strict=True)
        # embedded_signatures is the tolerant discovery path: a document
        # without /AcroForm (or with an unusual field layout) must not
        # crash the oracle with a KeyError traceback.
        sigs = reader.embedded_signatures
        if not sigs:
            return {"valid": False, "validator": "pyhanko", "version": __version__}
        # EKU None = unrestricted; an empty set rejects every EKU.
        ku = KeyUsageConstraints(key_usage=set(), extd_key_usage=None)
        status = validate_pdf_signature(sigs[0], key_usage_settings=ku)
        return {
            "valid": bool(status.bottom_line),
            "validator": "pyhanko",
            "version": __version__,
        }


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "validate":
        print(__doc__, file=sys.stderr)
        return 2
    result = validate(sys.argv[2])
    json.dump(result, sys.stdout)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
