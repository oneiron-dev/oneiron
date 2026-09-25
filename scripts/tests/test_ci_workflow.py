"""Pin both featureless library process models in the CI test lanes."""

from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


def test_featureless_tier_runs_under_cargo_test_and_nextest_on_both_lanes():
    lines = WORKFLOW.read_text().splitlines()
    for job in ("test", "test-linux"):
        start = lines.index(f"  {job}:") + 1
        end = next(
            (i for i in range(start, len(lines)) if lines[i].startswith("  ")
             and not lines[i].startswith("    ") and lines[i].strip()),
            len(lines),
        )
        steps = []
        for line in lines[start:end]:
            if line.startswith("      - name: "):
                steps.append({"name": line.removeprefix("      - name: ")})
            elif steps and line.startswith("        ") and not line.startswith("          "):
                key, _, value = line.strip().partition(": ")
                if key in ("run", "if"):
                    steps[-1][key] = value

        one_process = next(s for s in steps if s["name"] == "Featureless oneiron library tests")
        per_test = next(s for s in steps if s["name"] == "Featureless oneiron library tests (nextest, no retries)")
        assert one_process["run"] == "cargo test -p oneiron --lib --no-default-features", job
        assert per_test["run"] == (
            "cargo nextest run -p oneiron --lib --no-default-features "
            "--profile featureless --no-fail-fast"
        ), job
        assert steps.index(per_test) == steps.index(one_process) + 1, job
        assert per_test.get("if") == one_process.get("if"), job
