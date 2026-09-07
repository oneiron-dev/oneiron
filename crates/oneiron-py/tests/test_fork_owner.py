"""Dropping an inherited SDK client must not release the live parent's lease."""

import os
import subprocess
import sys
import textwrap

import pytest


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is Unix-only")
def test_child_drop_keeps_parent_lease_and_constructor_refuses(tmp_path):
    probe = r"""
        import gc
        import os
        import subprocess
        import sys
        from oneiron import Oneiron, OneironError

        path = sys.argv[1]
        memory = Oneiron.open(path)
        pid = os.fork()
        if pid == 0:
            try:
                Oneiron.open(path)
            except OneironError as error:
                if error.code != "VAULT_LOCKED_SINGLE_WRITER":
                    os._exit(2)
            else:
                os._exit(3)
            del memory
            gc.collect()  # Run the native client's destructor BEFORE _exit.
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        assert status == 0, status
        challenge = "\n".join([
            "import sys",
            "from oneiron import Oneiron, OneironError",
            "try:",
            "    Oneiron.open(sys.argv[1])",
            "except OneironError as error:",
            "    assert error.code == 'VAULT_LOCKED_SINGLE_WRITER', error.code",
            "else:",
            "    raise AssertionError('child drop unlocked the live parent')",
        ])
        challenger = subprocess.run(
            [sys.executable, "-c", challenge, path],
            capture_output=True, text=True, timeout=30,
        )
        assert challenger.returncode == 0, challenger.stderr
        assert isinstance(memory.receipts(1), list)
    """
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(probe), str(tmp_path / "vault")],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
