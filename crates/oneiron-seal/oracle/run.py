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
        sig_fields = reader.root["/AcroForm"]["/Fields"]
        sigs = [
            f.get_object()["/V"].get_object()
            for f in sig_fields
            if f.get_object().get("/FT") == "/Sig"
        ]
        if not sigs:
            return {"valid": False, "validator": "pyhanko", "version": __version__}
        ku = KeyUsageConstraints(key_usage=set(), extd_key_usage=set())
        status = validate_pdf_signature(
            reader.embedded_signatures[0],
            key_usage_settings=ku,
        )
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
