"""Tests for the KeePassXC TOTP provider."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from openconnect_saml.totp_providers import KeePassXCProvider


def _result(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


# ---------------------------------------------------------------- happy path


class TestKeePassXCHappyPath:
    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_returns_otp_from_stdout(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "vault-pwd")
        mock_run.return_value = _result(stdout="123456\n")
        p = KeePassXCProvider(database="/tmp/v.kdbx", entry="VPN/Work")
        assert p.get_totp() == "123456"
        # Password came in via stdin, not argv (avoids ps leak).
        kw = mock_run.call_args.kwargs
        assert kw["input"] == "vault-pwd"
        assert "vault-pwd" not in mock_run.call_args.args[0]

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_strips_padding_and_picks_last_line(self, mock_run, mock_which, monkeypatch):
        """Some keepassxc-cli versions emit a header line + the value."""
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        mock_run.return_value = _result(stdout="TOTP:    \n  654321  \n")
        p = KeePassXCProvider(database="/tmp/v.kdbx", entry="x")
        assert p.get_totp() == "654321"

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_keyfile_appended_to_argv(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        mock_run.return_value = _result(stdout="000000\n")
        p = KeePassXCProvider(database="/tmp/v.kdbx", entry="x", keyfile="/tmp/key")
        p.get_totp()
        argv = mock_run.call_args.args[0]
        assert "--key-file" in argv
        assert "/tmp/key" in argv


# ---------------------------------------------------------------- error paths


class TestKeePassXCErrors:
    @patch("openconnect_saml.totp_providers.shutil.which", return_value=None)
    def test_missing_cli_returns_none(self, mock_which):
        p = KeePassXCProvider(database="x", entry="x")
        assert p.get_totp() is None

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch(
        "openconnect_saml.totp_providers.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="keepassxc-cli", timeout=15),
    )
    def test_timeout_returns_none(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        p = KeePassXCProvider(database="x", entry="x")
        assert p.get_totp() is None

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_wrong_password_returns_none(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "wrong")
        mock_run.return_value = _result(stderr="invalid credentials provided", returncode=1)
        p = KeePassXCProvider(database="x", entry="x")
        assert p.get_totp() is None

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_missing_entry_returns_none(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        mock_run.return_value = _result(stderr="Could not find entry", returncode=1)
        p = KeePassXCProvider(database="x", entry="missing")
        assert p.get_totp() is None

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_no_totp_secret_returns_none(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        mock_run.return_value = _result(stderr="entry has no TOTP", returncode=1)
        p = KeePassXCProvider(database="x", entry="x")
        assert p.get_totp() is None

    @patch("openconnect_saml.totp_providers.shutil.which", return_value="/usr/bin/keepassxc-cli")
    @patch("openconnect_saml.totp_providers.subprocess.run")
    def test_empty_stdout_returns_none(self, mock_run, mock_which, monkeypatch):
        monkeypatch.setenv("KEEPASSXC_DB_PASSWORD", "x")
        mock_run.return_value = _result(stdout="\n\n")
        p = KeePassXCProvider(database="x", entry="x")
        assert p.get_totp() is None


# ---------------------------------------------------------------- CLI + config wiring


class TestKeePassXCWiring:
    def test_choice_accepted_by_argparser(self):
        from openconnect_saml.cli import create_argparser

        parser = create_argparser()
        # Both forms should parse without an argparse SystemExit.
        args = parser.parse_args(
            [
                "connect",
                "work",
                "--totp-source",
                "keepassxc",
                "--keepassxc-db",
                "/tmp/v.kdbx",
                "--keepassxc-entry",
                "VPN/Work",
                "--keepassxc-keyfile",
                "/tmp/k",
            ]
        )
        assert args.totp_source == "keepassxc"
        assert args.keepassxc_db == "/tmp/v.kdbx"
        assert args.keepassxc_entry == "VPN/Work"
        assert args.keepassxc_keyfile == "/tmp/k"

    def test_configure_totp_provider_keepassxc_requires_db_and_entry(self):
        from openconnect_saml.app import configure_totp_provider
        from openconnect_saml.config import Config, Credentials

        cfg = Config()
        creds = Credentials("u@x.test")
        # Build SimpleNamespace mimicking the parsed args, only the
        # bits configure_totp_provider looks at.
        from types import SimpleNamespace

        args = SimpleNamespace(
            no_totp=False,
            totp_source="keepassxc",
            keepassxc_db=None,
            keepassxc_entry=None,
            keepassxc_keyfile=None,
            twofauth_url=None,
            twofauth_token=None,
            twofauth_account_id=None,
            bw_item_id=None,
            op_item=None,
            op_vault=None,
            op_account=None,
            pass_entry=None,
        )
        with pytest.raises(ValueError) as exc:
            configure_totp_provider(args, cfg, creds)
        # Exit code 25 is the new bucket dedicated to KeePassXC config errors.
        assert exc.value.args[1] == 25

    def test_configure_totp_provider_keepassxc_persists_to_config(self, monkeypatch):
        from openconnect_saml.app import configure_totp_provider
        from openconnect_saml.config import Config, Credentials, KeePassXCConfig

        # Stub the provider so we don't actually shell out.
        called = {}

        class FakeProvider:
            def __init__(self, database, entry, keyfile=None):
                called["database"] = database
                called["entry"] = entry
                called["keyfile"] = keyfile

        monkeypatch.setattr("openconnect_saml.app.KeePassXCProvider", FakeProvider)

        cfg = Config()
        creds = Credentials("u@x.test")
        from types import SimpleNamespace

        args = SimpleNamespace(
            no_totp=False,
            totp_source="keepassxc",
            keepassxc_db="/v.kdbx",
            keepassxc_entry="VPN/Work",
            keepassxc_keyfile="/key",
            twofauth_url=None,
            twofauth_token=None,
            twofauth_account_id=None,
            bw_item_id=None,
            op_item=None,
            op_vault=None,
            op_account=None,
            pass_entry=None,
        )
        configure_totp_provider(args, cfg, creds)
        assert called == {"database": "/v.kdbx", "entry": "VPN/Work", "keyfile": "/key"}
        assert isinstance(cfg.keepassxc, KeePassXCConfig)
        assert cfg.keepassxc.database == "/v.kdbx"
        assert creds.totp_source == "keepassxc"
