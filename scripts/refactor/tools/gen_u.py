#!/usr/bin/env python3
"""U (types.rs #[path] un-mount) generator, TS D4.1 + D9.5 row 6. No item moves:
delete the two #[path] mounts + pub-use blocks in types.rs, re-point the lib.rs
flat groups (companion -> crate::companion, psych -> crate::psych_profile), fix
super:: in the two child files, re-point all crate::types::(companion|psych|flat)
consumers, and add the U-gap use line to types.rs."""
import os
import re
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
BASE = os.environ.get("BASE_REV", "b2437d700")
OUT = os.path.join(ROOT, "scripts/refactor/moves")


def show(path):
    p = subprocess.run(["git", "-C", ROOT, "show", f"{BASE}:{path}"], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def use_names(head):
    return [x.strip() for x in head[head.index("{") + 1:head.rindex("}")].split(",")]


def norm_use(mod, names):
    return R.norm_head(f"pub use crate :: {mod} :: {{ {' , '.join(sorted(names))} }}")


def norm_rel(mod, names):
    return R.norm_head(f"pub use {mod} :: {{ {' , '.join(sorted(names))} }}")


def main():
    types = R.Doc(show("crates/oneiron/src/types.rs"))
    lib = R.Doc(show("crates/oneiron/src/lib.rs"))
    # types.rs relative pub use companion/psych (the re-exported name sets)
    comp42 = psych9 = None
    for it in R.enumerate_items(types):
        if it["kind"] == "use" and it["vis"] == "pub":
            h = R.logical_head(types, it["sig_line"])
            if h.startswith("pub use companion ::"):
                comp42 = use_names(h)
            elif h.startswith("pub use psych_profile ::"):
                psych9 = use_names(h)
    # lib.rs crate::types groups (572 native+companion, 602 psych)
    lib572 = lib602 = None
    for it in R.enumerate_items(lib):
        if it["kind"] == "use" and it["vis"] == "pub":
            h = R.logical_head(lib, it["sig_line"])
            if "crate :: types ::" in h and "{" in h:
                names = use_names(h)
                if any(n in psych9 for n in names):
                    lib602 = names
                else:
                    lib572 = names
    comp_set, psych_set = set(comp42), set(psych9)
    flat_comp = [n for n in lib572 if n in comp_set]     # 38 flat companion
    native = [n for n in lib572 if n not in comp_set]    # 71 native

    decl = []
    decl.append("- " + norm_rel("companion", comp42))
    decl.append("- " + norm_rel("psych_profile", psych9))
    decl.append("- " + norm_use("types", lib572))
    decl.append("- " + norm_use("types", lib602))
    decl.append("+ " + norm_use("types", native))
    decl.append("+ " + norm_use("companion", flat_comp))
    decl.append("+ " + norm_use("psych_profile", psych9))

    # consumer sweeps ------------------------------------------------------
    edits = []
    allow = set()
    flat_all = comp_set | psych_set

    def add_edit(path, s, new):
        if new != s and path not in ("crates/oneiron/src/lib.rs", "crates/oneiron/src/types.rs"):
            edits.append((path, s, new))
        if path not in ("crates/oneiron/src/lib.rs",):
            allow.add(path)

    # 1) nested paths crate::types::companion:: / ::psych_profile::  (in/cross crate)
    p = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "-E",
                        r"(crate|oneiron)::types::(companion|psych_profile)::", BASE, "--", "*.rs"],
                       capture_output=True, text=True)
    for ln in p.stdout.splitlines():
        try:
            _, path, no, content = ln.split(":", 3)
        except ValueError:
            continue
        s = content.strip()
        # un-mount collapses (crate|oneiron)::types::companion -> ::companion
        new = re.sub(r"(crate|oneiron)::types::(companion|psych_profile)",
                     lambda m: f"{m.group(1)}::{m.group(2)}", s)
        add_edit(path, s, new)

    # 2) direct flat refs crate::types::<flat companion/psych name> (in + cross crate)
    p = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "-E",
                        r"(crate|oneiron)::types::[A-Za-z_]", BASE, "--", "*.rs"],
                       capture_output=True, text=True)
    occ = re.compile(r"(crate|oneiron)::types::([A-Za-z_][A-Za-z0-9_]*)")
    for ln in p.stdout.splitlines():
        try:
            _, path, no, content = ln.split(":", 3)
        except ValueError:
            continue
        names = [n for n in occ.findall(content)]
        hit = [(pre, n) for (pre, n) in names if n in flat_all]
        if not hit:
            continue
        s = content.strip()

        def sub(m):
            pre, n = m.group(1), m.group(2)
            if n in comp_set:
                return f"{pre}::companion::{n}"
            if n in psych_set:
                return f"{pre}::psych_profile::{n}"
            return m.group(0)
        new = occ.sub(sub, s)
        add_edit(path, s, new)

    # 3) super:: fixes in the two child files -> crate::types::
    for child in ("crates/oneiron/src/companion.rs", "crates/oneiron/src/psych_profile.rs"):
        cp = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "super::", BASE, "--", child],
                            capture_output=True, text=True)
        for ln in cp.stdout.splitlines():
            try:
                _, path, no, content = ln.split(":", 3)
            except ValueError:
                continue
            s = content.strip()
            new = re.sub(r"\bsuper::", "crate::types::", s)
            add_edit(path, s, new)

    allow |= {"crates/oneiron/src/types.rs", "crates/oneiron/src/lib.rs",
              "crates/oneiron/src/companion.rs", "crates/oneiron/src/psych_profile.rs"}

    # U-gap use line (types.rs) is a private `use` -> not in inventory; it lands via
    # check C exemption. Record as an add for documentation only.
    ugap = "use crate::companion::{COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER};"

    with open(os.path.join(OUT, "U.tsv"), "w") as f:
        f.write("# U: types.rs #[path] un-mount — no item moves (edits + lib re-point only)\n")
    with open(os.path.join(OUT, "U.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n## flat-name-check\nyes\n\n")
        f.write("## allowed\n" + "".join(a + "\n" for a in sorted(allow)) + "\n")
        f.write("## consumer-exempt\ncrates/oneiron/src/types.rs\ncrates/oneiron/src/companion.rs\n"
                "crates/oneiron/src/psych_profile.rs\n\n")
        f.write("## decl\n" + "".join(d + "\n" for d in sorted(decl)) + "\n")
        f.write("## edit\n" + "".join(f"{e[0]}\t{e[1]}\t{e[2]}\n" for e in sorted(set(edits))))
        f.write("\n## add\ncrates/oneiron/src/types.rs\t" + ugap + "\n")
    print(f"U: comp42={len(comp42)} psych9={len(psych9)} lib572={len(lib572)} "
          f"flat_comp={len(flat_comp)} native={len(native)}; {len(set(edits))} consumer edits, "
          f"{len(allow)} allowed files")


if __name__ == "__main__":
    main()
