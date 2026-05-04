"""Integration-test isolation: skip the whole tree on Windows.

These tests drive the real CLI through long-lived subprocesses against
an in-process mock HTTPS gateway. On Linux / macOS GitHub Actions
runners they're solid; on the Windows runner they flake intermittently
because of slower TIME_WAIT recycling on ephemeral ports, the
mock-gateway thread shutdown timing, and ``subprocess.communicate``
TimeoutExpired on cold runs. Two consecutive identical CI runs on the
same commit have shown one green and one red, which is flake by
definition.

The integration suite isn't Windows-targeted anyway — ``openconnect``
isn't installed and the auth flow is exercised at the unit level for
that platform — so skip the whole directory on ``win32`` rather than
chase the flake. Linux + macOS runners still cover it, plus the unit
tests themselves run on Windows.
"""

from __future__ import annotations

import sys

import pytest

collect_ignore_glob = ["test_*.py"] if sys.platform == "win32" else []

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Integration tests use long-lived subprocess+sockets that flake on Windows runners",
)
