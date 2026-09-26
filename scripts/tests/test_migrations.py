"""Contract check for the GA preflight migration register."""

import re
import unittest
from pathlib import Path


REGISTER = Path(__file__).resolve().parents[2] / "MIGRATIONS.md"
BREAKS = ("ONE-1645", "ONE-1631", "ONE-1637", "ONE-1633", "ONE-1103", "ONE-1122")


def preflight_sections(register: str) -> list[tuple[str, str]]:
    """Extract the bounded register entries, not unrelated historical mentions."""
    start = register.index("## GA preflight / ONE-1938:")
    end = register.index("\n## ", start + 3)
    preflight = register[start:end]
    sections = re.split(r"(?m)^### ", preflight)[1:]
    return [(title, body) for title, _, body in (section.partition("\n") for section in sections)]


class MigrationRegisterTests(unittest.TestCase):
    def test_every_preflight_break_has_a_disposition_and_named_population(self):
        sections = preflight_sections(REGISTER.read_text())
        for ticket in BREAKS:
            matches = [body for title, body in sections if title.startswith(ticket + ":")]
            with self.subTest(ticket=ticket):
                self.assertEqual(len(matches), 1)
                body = matches[0]
                self.assertIn("**Ruling:", body)
                self.assertIn("population", body.lower())
                if ticket == "ONE-1633":
                    self.assertIn("migration", body.split("**Ruling:", 1)[1].split("**", 1)[0])
                else:
                    self.assertIn("**Ruling: no-op. Discarded population:**", body)

    def test_unregistered_abi_history_names_the_discarded_vaults(self):
        register = REGISTER.read_text()
        history = register.split("## Pre-GA ABI v4–v15 catch-up (ONE-1938)", 1)[1].split(
            "\n## OF-326 / ONE-1732:", 1
        )[0]
        for old_abi in range(3, 15):
            with self.subTest(abi=old_abi):
                self.assertIn(f"ABI-{old_abi} development vaults", history)
                self.assertIn(f"| v{old_abi}→v{old_abi + 1} ", history)
        for title in (
            "OF-494: byte-space v3.1 family reflow",
            "Wave 7 stored meanings and facets",
            "Pairing and proof replay rows",
        ):
            with self.subTest(title=title):
                section = register.split("### " + title, 1)[1].split("\n### ", 1)[0]
                self.assertIn("**Ruling:", section)
                self.assertIn("development vault", section)


if __name__ == "__main__":
    unittest.main()
