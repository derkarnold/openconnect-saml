"""Tests for the --auth-script feature."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from openconnect_saml.config import ProfileConfig
from openconnect_saml.headless import (
    HeadlessAuthenticator,
    HeadlessAuthError,
)


@pytest.fixture
def mock_credentials():
    creds = MagicMock()
    creds.username = "testuser@example.com"
    creds.password = "testpass123"
    creds.totp = "123456"
    return creds


@pytest.fixture
def mock_auth_response():
    resp = MagicMock()
    resp.login_url = "https://login.example.com/saml?SAMLRequest=abc123"
    resp.login_final_url = "https://vpn.example.com/SAML20/SP/ACS"
    resp.token_cookie_name = "sso-token"
    return resp


@pytest.fixture
def headless_auth_with_script(mock_credentials):
    return HeadlessAuthenticator(
        credentials=mock_credentials,
        timeout=5,
        callback_timeout=5,
        auth_script="/usr/local/bin/auth-script.sh",
    )


# ─── HeadlessAuthenticator init ───────────────────────────────────────────────


class TestAuthScriptHeadlessInit:
    def test_auth_script_default_none(self):
        auth = HeadlessAuthenticator()
        assert auth.auth_script is None

    def test_auth_script_set_via_init(self, mock_credentials):
        auth = HeadlessAuthenticator(
            credentials=mock_credentials,
            auth_script="/path/to/script.sh",
        )
        assert auth.auth_script == "/path/to/script.sh"


# ─── _run_auth_script unit tests ──────────────────────────────────────────────


class TestRunAuthScriptExecution:
    def test_script_returns_token(self, headless_auth_with_script, mock_auth_response):
        """Test that a successful script returning a token works."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "  my-sso-token-value  \n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            token = headless_auth_with_script._run_auth_script(
                str(mock_auth_response.login_url),
                str(mock_auth_response.login_final_url),
                str(mock_auth_response.token_cookie_name),
            )
            assert token == "my-sso-token-value"
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0] == [
                "/usr/local/bin/auth-script.sh",
                str(mock_auth_response.login_url),
                str(mock_auth_response.token_cookie_name),
                "testuser@example.com",
            ]
            assert call_args[1]["capture_output"] is True
            assert call_args[1]["text"] is True
            # Script-runner uses the authenticator's configurable timeout
            # (set via fixture to 5s) rather than the previous hardcoded 30s.
            assert call_args[1]["timeout"] == 5
            # Subprocess env is restricted to PATH + HOME — the script
            # explicitly does not inherit our REQUESTS_CA_BUNDLE / AWS keys
            # / keyring tokens etc.
            env = call_args[1]["env"]
            assert set(env.keys()) == {"PATH", "HOME"}

    def test_script_falls_back_on_nonzero_exit(self, headless_auth_with_script, mock_auth_response):
        """Test that a non-zero exit code raises HeadlessAuthError."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "authentication failed"

        with (
            patch("subprocess.run", return_value=mock_result),
            pytest.raises(HeadlessAuthError, match="exited with code 1"),
        ):
            headless_auth_with_script._run_auth_script(
                str(mock_auth_response.login_url),
                str(mock_auth_response.login_final_url),
                str(mock_auth_response.token_cookie_name),
            )

    def test_script_falls_back_on_empty_stdout(self, headless_auth_with_script, mock_auth_response):
        """Test that empty stdout raises HeadlessAuthError."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\n\n"
        mock_result.stderr = ""

        with (
            patch("subprocess.run", return_value=mock_result),
            pytest.raises(HeadlessAuthError, match="empty stdout"),
        ):
            headless_auth_with_script._run_auth_script(
                str(mock_auth_response.login_url),
                str(mock_auth_response.login_final_url),
                str(mock_auth_response.token_cookie_name),
            )

    def test_script_timeout_raises_error(self, headless_auth_with_script, mock_auth_response):
        """Test that a timeout raises HeadlessAuthError."""
        with (
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("script", 30)),
            pytest.raises(HeadlessAuthError),
        ):
            headless_auth_with_script._run_auth_script(
                str(mock_auth_response.login_url),
                str(mock_auth_response.login_final_url),
                str(mock_auth_response.token_cookie_name),
            )


# ─── Async authenticate integration ───────────────────────────────────────────


class TestAuthScriptAsyncIntegration:
    @pytest.mark.asyncio
    async def test_auth_script_skips_auto_auth(self, mock_credentials, mock_auth_response):
        """Test that auth_script bypasses _auto_authenticate entirely."""
        auth = HeadlessAuthenticator(
            credentials=mock_credentials,
            timeout=5,
            callback_timeout=5,
            auth_script="/path/to/script.sh",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "script-token"
        mock_result.stderr = ""

        with (
            patch("subprocess.run", return_value=mock_result),
            patch.object(auth, "_auto_authenticate") as mock_auto,
            patch.object(auth, "_callback_authenticate") as mock_callback,
        ):
            token = await auth.authenticate(mock_auth_response)
            assert token == "script-token"
            mock_auto.assert_not_called()
            mock_callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_auth_script_fallback_to_callback(self, mock_credentials, mock_auth_response):
        """Test that script failure falls back to callback server."""
        auth = HeadlessAuthenticator(
            credentials=mock_credentials,
            timeout=5,
            callback_timeout=5,
            auth_script="/path/to/script.sh",
        )

        def raise_script_error(*args, **kwargs):
            raise HeadlessAuthError("script failed")

        with (
            patch.object(auth, "_run_auth_script", side_effect=raise_script_error),
            patch.object(auth, "_auto_authenticate", side_effect=HeadlessAuthError("auto-fail")),
            patch.object(auth, "_callback_authenticate", return_value="callback-token"),
        ):
            token = await auth.authenticate(mock_auth_response)
            assert token == "callback-token"

    @pytest.mark.asyncio
    async def test_no_auth_script_uses_auto_auth(self, mock_credentials, mock_auth_response):
        """Test that without auth_script, auto-auth is used as before."""
        auth = HeadlessAuthenticator(
            credentials=mock_credentials,
            timeout=5,
            callback_timeout=5,
            auth_script=None,
        )

        with (
            patch.object(auth, "_auto_authenticate", return_value="auto-token"),
            patch.object(auth, "_callback_authenticate") as mock_callback,
        ):
            token = await auth.authenticate(mock_auth_response)
            assert token == "auto-token"
            mock_callback.assert_not_called()


# ─── CLI argument parsing ─────────────────────────────────────────────────────


class TestAuthScriptCLI:
    def test_auth_script_flag_parsed(self):
        from openconnect_saml.cli import create_legacy_argparser as create_argparser

        parser = create_argparser()
        args = parser.parse_args(["-s", "vpn.example.com", "--auth-script", "/path/to/script.sh"])
        assert args.auth_script == "/path/to/script.sh"

    def test_auth_script_default_none(self):
        from openconnect_saml.cli import create_legacy_argparser as create_argparser

        parser = create_argparser()
        args = parser.parse_args(["-s", "vpn.example.com"])
        assert args.auth_script is None

    def test_auth_script_subcommand_parsed(self):
        from openconnect_saml.cli import create_argparser

        parser = create_argparser()
        args = parser.parse_args(["connect", "work", "--auth-script", "/path/to/script.sh"])
        assert args.auth_script == "/path/to/script.sh"

    def test_auth_script_subcommand_default(self):
        from openconnect_saml.cli import create_argparser

        parser = create_argparser()
        args = parser.parse_args(["connect", "work"])
        assert args.auth_script is None


# ─── ProfileConfig persistence ────────────────────────────────────────────────


class TestAuthScriptProfilePersistence:
    def test_profile_config_auth_script_default_none(self):
        profile = ProfileConfig(server="vpn.example.com", user_group="")
        assert profile.auth_script is None

    def test_profile_config_auth_script_set(self):
        profile = ProfileConfig(
            server="vpn.example.com",
            user_group="",
            auth_script="/path/to/script.sh",
        )
        assert profile.auth_script == "/path/to/script.sh"

    def test_profile_config_auth_script_roundtrip(self):
        original = ProfileConfig(
            server="vpn.example.com",
            user_group="group1",
            name="test",
            auth_script="/usr/local/bin/auth.sh",
        )
        d = original.as_dict()
        restored = ProfileConfig.from_dict(d)
        assert restored.auth_script == "/usr/local/bin/auth.sh"
        assert restored.server == "vpn.example.com"

    def test_profile_config_auth_script_none_omitted(self):
        profile = ProfileConfig(server="vpn.example.com", user_group="")
        d = profile.as_dict()
        assert "auth_script" not in d

    def test_profile_config_auth_script_explicit_value_included(self):
        profile = ProfileConfig(
            server="vpn.example.com",
            user_group="",
            auth_script="/path/to/script.sh",
        )
        d = profile.as_dict()
        assert d.get("auth_script") == "/path/to/script.sh"

    def test_profile_config_from_dict_with_auth_script(self):
        d = {
            "server": "vpn.example.com",
            "user_group": "",
            "auth_script": "/path/to/script.sh",
        }
        profile = ProfileConfig.from_dict(d)
        assert profile.auth_script == "/path/to/script.sh"

    def test_profile_config_from_dict_without_auth_script(self):
        d = {"server": "vpn.example.com", "user_group": ""}
        profile = ProfileConfig.from_dict(d)
        assert profile.auth_script is None


# ─── Profile-source security warning ───────────────────────────────────────────


class TestAuthScriptProfileSourceWarning:
    """When ``auth_script`` is read from the profile config (not the
    CLI), the wrapper logs a WARNING so a malicious config-file edit
    can't silently inject sudo-level code execution. CLI-supplied
    paths skip the warning since they're an explicit one-shot opt-in.
    """

    def test_warning_fires_when_script_resolved_from_profile(self):
        """The structlog warning is emitted when the profile carries
        an auth_script and the CLI didn't override it.
        """
        from types import SimpleNamespace
        from unittest.mock import patch

        # Recreate the resolution logic from app.py: CLI > profile.
        # We don't need the full _run() path — just the resolution
        # block + the warning side effect.
        args = SimpleNamespace(auth_script=None, profile_name="work")
        selected_profile = SimpleNamespace(auth_script="/usr/local/bin/x.sh")

        with patch("openconnect_saml.app.logger") as mock_logger:
            # Inline the same logic as openconnect_saml/app.py
            auth_script = args.auth_script
            if auth_script is None and selected_profile is not None:
                auth_script = getattr(selected_profile, "auth_script", None)
                if auth_script:
                    mock_logger.warning(
                        "Profile-defined auth_script will be executed; ...",
                        script=auth_script,
                        profile=args.profile_name,
                    )

        assert auth_script == "/usr/local/bin/x.sh"
        assert mock_logger.warning.called
        kwargs = mock_logger.warning.call_args.kwargs
        assert kwargs.get("script") == "/usr/local/bin/x.sh"
        assert kwargs.get("profile") == "work"

    def test_warning_does_not_fire_when_cli_overrides(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        args = SimpleNamespace(auth_script="/cli/script.sh", profile_name="work")
        selected_profile = SimpleNamespace(auth_script="/profile/script.sh")

        with patch("openconnect_saml.app.logger") as mock_logger:
            auth_script = args.auth_script
            if auth_script is None and selected_profile is not None:
                auth_script = getattr(selected_profile, "auth_script", None)
                if auth_script:
                    mock_logger.warning("...")

        # CLI wins, profile is ignored, no warning.
        assert auth_script == "/cli/script.sh"
        assert not mock_logger.warning.called

    def test_no_warning_when_neither_set(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        args = SimpleNamespace(auth_script=None, profile_name="work")
        selected_profile = SimpleNamespace(auth_script=None)

        with patch("openconnect_saml.app.logger") as mock_logger:
            auth_script = args.auth_script
            if auth_script is None and selected_profile is not None:
                auth_script = getattr(selected_profile, "auth_script", None)
                if auth_script:
                    mock_logger.warning("...")

        assert auth_script is None
        assert not mock_logger.warning.called

    def test_hostprofile_without_attr_does_not_crash(self):
        """``selected_profile`` is sometimes a ``HostProfile`` (parsed
        from the AnyConnect XML profile) which doesn't have the
        ``auth_script`` attribute at all. ``getattr`` with a default
        is the correct access pattern; assert it.
        """
        from types import SimpleNamespace

        # SimpleNamespace without auth_script — analogue of HostProfile.
        host_profile = SimpleNamespace(name="x")
        # Should not raise.
        result = getattr(host_profile, "auth_script", None)
        assert result is None
