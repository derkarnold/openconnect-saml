"""Tests for openconnect_saml.app helper functions.

Targets the small leaf functions that don't need an event loop or
the full ``_run`` orchestrator: validators, hook handlers, helpers.
Improves the app.py coverage from ~35% upward.
"""

from __future__ import annotations

import logging
import subprocess
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------- _validate_hook_command


class TestValidateHookCommand:
    def test_empty_command_is_valid(self):
        from openconnect_saml.app import _validate_hook_command

        assert _validate_hook_command("") is True
        assert _validate_hook_command(None) is True

    def test_simple_command_is_valid(self):
        from openconnect_saml.app import _validate_hook_command

        assert _validate_hook_command("/usr/local/bin/notify-up") is True
        assert _validate_hook_command("echo hello world") is True

    @pytest.mark.parametrize(
        "metachar",
        ["`", "$(", "${", "||", "&&", ";", "\n", "|"],
    )
    def test_shell_metacharacters_rejected(self, metachar):
        """Each of the suspicious patterns aborts validation so a
        config-injected hook can't escape into a subshell."""
        from openconnect_saml.app import _validate_hook_command

        assert _validate_hook_command(f"echo a{metachar}b") is False


# ---------------------------------------------------------------- handle_connect / handle_disconnect / handle_error


class TestHandleConnect:
    def test_no_command_is_noop(self):
        from openconnect_saml.app import handle_connect

        # Returns None (function exits without running anything).
        assert handle_connect("") is None
        assert handle_connect(None) is None

    @patch("openconnect_saml.app.subprocess.run")
    def test_valid_command_runs(self, mock_run):
        from openconnect_saml.app import handle_connect

        mock_run.return_value = MagicMock(returncode=0)
        assert handle_connect("/bin/true") == 0
        # Was called with shell=False (no shell injection).
        assert mock_run.call_args.kwargs.get("shell") is False

    def test_command_with_metacharacter_refused_with_rc1(self):
        from openconnect_saml.app import handle_connect

        # Returns 1, doesn't shell out at all.
        with patch("openconnect_saml.app.subprocess.run") as mock_run:
            assert handle_connect("rm -rf /; touch x") == 1
            mock_run.assert_not_called()

    @patch(
        "openconnect_saml.app.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="x", timeout=30),
    )
    def test_command_timeout_returns_1(self, mock_run):
        from openconnect_saml.app import handle_connect

        assert handle_connect("/bin/sleep 60") == 1

    @patch("openconnect_saml.app.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_binary_returns_1(self, mock_run):
        from openconnect_saml.app import handle_connect

        assert handle_connect("/no/such/binary") == 1


class TestHandleDisconnect:
    @patch("openconnect_saml.app.subprocess.run")
    def test_runs_and_returns_exit_code(self, mock_run):
        from openconnect_saml.app import handle_disconnect

        mock_run.return_value = MagicMock(returncode=0)
        assert handle_disconnect("/bin/true") == 0


class TestHandleError:
    @patch("openconnect_saml.app.subprocess.run")
    def test_passes_exit_code_via_env(self, mock_run):
        from openconnect_saml.app import handle_error

        mock_run.return_value = MagicMock(returncode=0)
        handle_error("/usr/local/bin/notify-fail", exit_code=42)
        env = mock_run.call_args.kwargs.get("env", {})
        assert env.get("RC") == "42"

    def test_no_command_is_noop(self):
        from openconnect_saml.app import handle_error

        # Should not raise.
        handle_error("", exit_code=1)


# ---------------------------------------------------------------- configure_logger


class TestConfigureLogger:
    def test_sets_level_on_root_logger(self):
        from openconnect_saml.app import configure_logger

        root = logging.getLogger()
        original = root.level
        try:
            configure_logger(root, "WARNING")
            assert root.level == logging.WARNING
            configure_logger(root, "DEBUG")
            assert root.level == logging.DEBUG
        finally:
            root.level = original


# ---------------------------------------------------------------- _wait_for_tunnel


class TestWaitForTunnel:
    def test_returns_true_when_interface_appears(self):
        from openconnect_saml.app import _wait_for_tunnel

        # Patch the lazy-imported _get_vpn_interface so we don't shell out.
        with patch("openconnect_saml.tui._get_vpn_interface", return_value="tun0"):
            assert _wait_for_tunnel(deadline_seconds=1.0) is True

    def test_returns_false_on_timeout(self):
        from openconnect_saml.app import _wait_for_tunnel

        with patch("openconnect_saml.tui._get_vpn_interface", return_value=None):
            assert _wait_for_tunnel(deadline_seconds=0.05) is False

    def test_swallows_exceptions_and_keeps_polling(self):
        from openconnect_saml.app import _wait_for_tunnel

        # First call raises, second returns interface — we should
        # still see True.
        attempts = {"n": 0}

        def flaky():
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OSError("transient")
            return "tun0"

        with patch("openconnect_saml.tui._get_vpn_interface", side_effect=flaky):
            assert _wait_for_tunnel(deadline_seconds=1.0) is True
        assert attempts["n"] >= 2


# ---------------------------------------------------------------- _read_password


class TestReadPassword:
    def test_tty_uses_getpass(self, monkeypatch):
        from openconnect_saml import app

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("openconnect_saml.app.getpass.getpass", return_value="pwd-from-tty"),
        ):
            assert app._read_password("Password: ") == "pwd-from-tty"

    def test_pipe_reads_from_stdin(self, monkeypatch, capsys):
        from openconnect_saml import app

        with (
            patch("sys.stdin.isatty", return_value=False),
            patch("sys.stdin.readline", return_value="pwd-from-pipe\n"),
        ):
            assert app._read_password("Password: ") == "pwd-from-pipe"

    def test_pipe_with_eof_returns_empty(self):
        from openconnect_saml import app

        with (
            patch("sys.stdin.isatty", return_value=False),
            patch("sys.stdin.readline", return_value=""),
        ):
            assert app._read_password("Password: ") == ""
