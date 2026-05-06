"""Tests for openconnect_saml.killswitch helper functions.

Targets the small platform / resolve / privilege-tool helpers
that don't need a real iptables / pf running. Improves the
killswitch.py coverage from ~64% upward. The full-pipeline
tests (apply / teardown of actual iptables rules) live in
``test_killswitch.py`` and are skipped off Linux.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------- _platform_check


class TestPlatformCheck:
    @patch("openconnect_saml.killswitch.platform.system", return_value="Linux")
    def test_linux_passes(self, mock_system):
        from openconnect_saml.killswitch import _platform_check

        # Should not raise.
        _platform_check()

    @patch("openconnect_saml.killswitch.platform.system", return_value="Darwin")
    def test_macos_passes(self, mock_system):
        from openconnect_saml.killswitch import _platform_check

        _platform_check()

    @patch("openconnect_saml.killswitch.platform.system", return_value="Windows")
    def test_windows_raises(self, mock_system):
        from openconnect_saml.killswitch import KillSwitchNotSupported, _platform_check

        with pytest.raises(KillSwitchNotSupported, match="only supported on Linux"):
            _platform_check()

    @patch("openconnect_saml.killswitch.platform.system", return_value="FreeBSD")
    def test_unknown_platform_raises(self, mock_system):
        from openconnect_saml.killswitch import KillSwitchNotSupported, _platform_check

        with pytest.raises(KillSwitchNotSupported):
            _platform_check()


# ---------------------------------------------------------------- _backend_name


class TestBackendName:
    @patch("openconnect_saml.killswitch.platform.system", return_value="Linux")
    def test_linux_uses_iptables(self, mock_system):
        from openconnect_saml.killswitch import _backend_name

        assert _backend_name() == "iptables"

    @patch("openconnect_saml.killswitch.platform.system", return_value="Darwin")
    def test_macos_uses_pf(self, mock_system):
        from openconnect_saml.killswitch import _backend_name

        assert _backend_name() == "pf"


# ---------------------------------------------------------------- _find_privilege_tool


class TestFindPrivilegeTool:
    def test_explicit_empty_string_means_no_escalation(self):
        from openconnect_saml.killswitch import _find_privilege_tool

        assert _find_privilege_tool("") is None

    @patch("openconnect_saml.killswitch.shutil.which", return_value="/usr/bin/sudo")
    def test_explicit_value_resolved_via_path(self, mock_which):
        from openconnect_saml.killswitch import _find_privilege_tool

        assert _find_privilege_tool("sudo") == "/usr/bin/sudo"
        mock_which.assert_called_once_with("sudo")

    @patch("openconnect_saml.killswitch.shutil.which", return_value=None)
    def test_explicit_value_missing_raises(self, mock_which):
        from openconnect_saml.killswitch import KillSwitchError, _find_privilege_tool

        with pytest.raises(KillSwitchError, match="not found in PATH"):
            _find_privilege_tool("doas-not-installed")

    def test_autodetect_prefers_doas_over_sudo(self):
        from openconnect_saml.killswitch import _find_privilege_tool

        def fake_which(name):
            return f"/usr/bin/{name}" if name in ("doas", "sudo") else None

        with patch("openconnect_saml.killswitch.shutil.which", side_effect=fake_which):
            assert _find_privilege_tool(None) == "/usr/bin/doas"

    def test_autodetect_falls_back_to_sudo_when_no_doas(self):
        from openconnect_saml.killswitch import _find_privilege_tool

        def fake_which(name):
            return "/usr/bin/sudo" if name == "sudo" else None

        with patch("openconnect_saml.killswitch.shutil.which", side_effect=fake_which):
            assert _find_privilege_tool(None) == "/usr/bin/sudo"

    @patch("openconnect_saml.killswitch.shutil.which", return_value=None)
    def test_autodetect_returns_none_when_neither_found(self, mock_which):
        from openconnect_saml.killswitch import _find_privilege_tool

        # Container / minimal env without sudo or doas.
        assert _find_privilege_tool(None) is None


# ---------------------------------------------------------------- _resolve_server_ips


class TestResolveServerIps:
    @patch("openconnect_saml.killswitch.socket.getaddrinfo")
    def test_url_form_strips_scheme(self, mock_gai):
        from openconnect_saml.killswitch import _resolve_server_ips

        mock_gai.return_value = [
            (socket.AF_INET, 0, 0, "", ("203.0.113.5", 0)),
        ]
        ips = _resolve_server_ips("https://vpn.example.com:443/foo")
        assert ips == ["203.0.113.5"]
        mock_gai.assert_called_once_with("vpn.example.com", None)

    @patch("openconnect_saml.killswitch.socket.getaddrinfo")
    def test_bare_host(self, mock_gai):
        from openconnect_saml.killswitch import _resolve_server_ips

        mock_gai.return_value = [
            (socket.AF_INET, 0, 0, "", ("203.0.113.10", 0)),
        ]
        assert _resolve_server_ips("vpn.example.com") == ["203.0.113.10"]

    @patch("openconnect_saml.killswitch.socket.getaddrinfo")
    def test_dual_stack_dedupes_and_sorts(self, mock_gai):
        from openconnect_saml.killswitch import _resolve_server_ips

        # getaddrinfo can return duplicates (one per protocol/socket type).
        mock_gai.return_value = [
            (socket.AF_INET, 0, 0, "", ("203.0.113.5", 0)),
            (socket.AF_INET, 0, 0, "", ("203.0.113.5", 0)),  # dupe
            (socket.AF_INET6, 0, 0, "", ("2001:db8::1", 0, 0, 0)),
        ]
        ips = _resolve_server_ips("vpn.example.com")
        assert ips == sorted({"203.0.113.5", "2001:db8::1"})

    @patch(
        "openconnect_saml.killswitch.socket.getaddrinfo",
        side_effect=socket.gaierror("nodename nor servname provided"),
    )
    def test_dns_failure_raises_with_useful_message(self, mock_gai):
        from openconnect_saml.killswitch import KillSwitchError, _resolve_server_ips

        with pytest.raises(KillSwitchError, match="Cannot resolve VPN server"):
            _resolve_server_ips("nope.example.invalid")


# ---------------------------------------------------------------- _is_ipv6


class TestIsIpv6:
    def test_ipv4_is_not_v6(self):
        from openconnect_saml.killswitch import _is_ipv6

        assert _is_ipv6("203.0.113.5") is False

    def test_ipv6_is_v6(self):
        from openconnect_saml.killswitch import _is_ipv6

        assert _is_ipv6("2001:db8::1") is True

    def test_invalid_input_is_not_v6(self):
        from openconnect_saml.killswitch import _is_ipv6

        # ipaddress raises on garbage; the helper should return False
        # rather than propagate.
        assert _is_ipv6("not-an-ip") is False
