"""oneiron.shared_env — original-value shared invitation acceptance and bootstrap.

The successful HTTPS acceptance as its native value, never a decoded receipt.
Keep the object :meth:`oneiron.Oneiron.accept_shared_invitation_https` returns
for :meth:`oneiron.engine.EmbeddedEngine.bootstrap_shared_env`; a receipt record
cannot supply its provenance.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from . import _translate

if TYPE_CHECKING:
    from . import Oneiron

__all__ = ["SharedAcceptance", "SharedEnvBootstrapOutcome"]


class SharedAcceptance:
    """A successful acceptance on the connected HTTPS home, kept as the native value."""

    def __init__(self, native: Any) -> None:
        """Internal-only wrapper seam; use :meth:`oneiron.Oneiron.accept_shared_invitation_https`."""
        self._native = native

    def home_url(self) -> str:
        """The normalized HTTPS home the acceptance selected."""
        return self._native.home_url()

    def acceptance_url(self) -> str:
        """The exact facade URL the original acceptance used."""
        return self._native.acceptance_url()

    def request(self) -> dict[str, Any]:
        """The original request; reading it does not create another acceptance."""
        return json.loads(_translate(lambda: self._native.request()))

    def reply(self) -> dict[str, Any]:
        """The complete original receipt and member credential, available even after member-client creation or native bootstrap fails."""
        return json.loads(_translate(lambda: self._native.reply()))

    def member_client(self) -> Oneiron:
        """A remote member handle on the same HTTPS home and original HTTP wire.

        Each request still passes the home's ordinary admission checks.
        """
        from . import Oneiron

        return Oneiron(_translate(lambda: self._native.member_client()))


class SharedEnvBootstrapOutcome:
    """The native import result and committed flag, retained independently."""

    def __init__(self, native: Any) -> None:
        """Internal-only wrapper seam; use :meth:`oneiron.engine.EmbeddedEngine.bootstrap_shared_env`."""
        self._native = native

    @property
    def committed(self) -> bool:
        """The native publication flag, including when a later step failed."""
        return self._native.committed()

    def vault_path(self) -> str:
        """The actual registry-held vault's path on success.

        A failed import, credential update or insertion raises its native error
        instead; it never returns an empty or fabricated successful path.
        """
        return _translate(lambda: self._native.vault_path())
